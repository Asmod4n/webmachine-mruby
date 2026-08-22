#include "server.hpp"

#include <mruby/chrono.hpp>
#include <mruby/class.h>
#include <mruby/presym.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <memory>
#include <vector>

#include "application.hpp"
#include "assets.hpp"
#include "http1.hpp"
#include "ring.hpp"

namespace webmachine {
namespace {

// ONE server per process, like there is one ring and one VM. Built on
// first use - by the tool, or by the app file itself if it called run
// or tick inside `main`.
ServerOptions opts_;
std::vector<AppSpec*> specs_;
std::vector<std::vector<const Resource*>> resources_;
Assets assets_;
std::unique_ptr<Http1> http_;
std::unique_ptr<Ring<Http1>> ring_;
bool built_ = false;
bool entered_ = false;

// The listener table, straight out of the registry: registration order
// IS listener order, and the listener index is what a connection
// carries (#116 slice 2).
bool build_listeners(RingConfig& cfg, char* err, size_t errlen) {
  cfg.nlisteners = static_cast<uint32_t>(specs_.size());
  cfg.stop_fd = opts_.stop_fd;
  const bool cli = opts_.cli_unix != nullptr || opts_.cli_port != 0;
  if (cli && specs_.size() > 1) {
    std::snprintf(err, errlen,
                  "--unix/--port names one listener and this file registered %zu "
                  "applications - drop the override and let each app's conf speak",
                  specs_.size());
    return false;
  }
  if (opts_.cli_unix != nullptr) {
    cfg.listeners[0].unix_path = opts_.cli_unix;
    return true;
  }
  if (opts_.cli_port != 0) {
    cfg.listeners[0].port = opts_.cli_port;
    return true;
  }
  for (size_t i = 0; i < specs_.size(); i++) {
    switch (specs_[i]->form) {
      case AppSpec::Form::kUnix:
        cfg.listeners[i].unix_path = specs_[i]->unix_path.c_str();
        break;
      case AppSpec::Form::kPort:
      case AppSpec::Form::kUrl: cfg.listeners[i].port = specs_[i]->port; break;
      case AppSpec::Form::kNone:
        std::snprintf(err, errlen,
                      "application %zu has no listener - its configure block names one "
                      "(conf.port / conf.unix_path / conf.url), or pass --port/--unix for "
                      "a file with a single app",
                      i);
        return false;
    }
  }
  return true;
}

}  // namespace

bool server_backend_ok(bool have_uring, char* err, size_t errlen) {
#ifdef SLIPSTREAM_IO
  (void)have_uring;
  (void)err;
  (void)errlen;
  std::fprintf(stderr,
               "webmachine: ================================================================\n"
               "webmachine: == IO: slipstreamIO - the ring API over select(2)\n"
               "webmachine: == why: this build found no liburing to compile against\n"
               "webmachine: == cost: CORRECT, NOT FAST. Every operation is readiness plus\n"
               "webmachine: ==   a classic syscall; recv bundles do not exist (one buffer\n"
               "webmachine: ==   per completion)\n");
#ifdef IO_URING_FD_CEILING
  std::fprintf(stderr,
               "webmachine: == cap: descriptors must stay below %llu - the API says so, and\n"
               "webmachine: ==   a connection is a process fd here\n",
               static_cast<unsigned long long>(IO_URING_FD_CEILING));
#endif
  std::fprintf(stderr,
               "webmachine: == fix: build on Linux >= 6.11 against liburing\n"
               "webmachine: ================================================================\n");
  return true;
#else
  if (!have_uring) {
    std::snprintf(err, errlen,
                  "io_uring is not usable here (URING_AVAILABLE is false: the kernel is too "
                  "old, or a seccomp profile or sysctl blocks it). This binary was built "
                  "against liburing and carries no other implementation. Build against "
                  "slipstreamIO to run anyway");
    return false;
  }
  return true;
#endif
}

namespace {

// Everything between "main returned" and "the first accept", once.
bool build(mrb_state* mrb, char* err, size_t errlen) {
  if (built_) return true;
  if (!server_backend_ok(opts_.have_uring, err, errlen)) return false;

  if (!app_registered_all(specs_, kMaxListeners, err, errlen)) return false;
  RingConfig cfg;
  if (!build_listeners(cfg, err, errlen)) return false;

  // The asset table is built ONCE, before any listener exists; a bad
  // archive refuses the start by name (#170).
  if (opts_.assets_path != nullptr && !assets_.open(opts_.assets_path, err, errlen)) {
    return false;
  }

  // ONE Http1 for the whole process: every route of every app built
  // here, once. The resource pointers are gathered per app and KEPT -
  // AppInput borrows the arrays only for the constructor's duration,
  // but keeping them costs one vector per app and no thought.
  resources_.resize(specs_.size());
  std::vector<Http1::AppInput> inputs(specs_.size());
  for (size_t i = 0; i < specs_.size(); i++) {
    resources_[i].reserve(specs_[i]->resources.size());
    for (const auto& r : specs_[i]->resources) resources_[i].push_back(r.get());
    inputs[i] = Http1::AppInput{&specs_[i]->table, resources_[i].data(), resources_[i].size()};
  }
  http_.reset(new Http1(inputs.data(), inputs.size(),
                        opts_.assets_path != nullptr ? &assets_ : nullptr));

  ring_.reset(new Ring<Http1>(*http_));
  if (!ring_->init(cfg, err, errlen)) {
    ring_.reset();
    return false;
  }

  // THE BINDS HAVE HAPPENED, in listener order. Each app's conf.url now
  // reads back where ITS listener really is, and its ready hook runs:
  // after the bind, before the first accept, exactly once, in the order
  // the apps registered. A raise there stops the start.
  for (size_t i = 0; i < specs_.size(); i++) {
    app_mark_bound(*specs_[i], cfg.listeners[i].unix_path, cfg.listeners[i].port);
    if (!app_ready_run(mrb, *specs_[i], err, errlen)) {
      ring_.reset();
      return false;
    }
  }

  std::fprintf(stderr, "webmachine: http/1.1 up, pid %d, %u listener(s)\n", getpid(),
               cfg.nlisteners);
  for (uint32_t i = 0; i < cfg.nlisteners; i++) {
    if (cfg.listeners[i].unix_path != nullptr) {
      std::fprintf(stderr, "webmachine:   [%u] unix %s\n", i, cfg.listeners[i].unix_path);
    } else {
      std::fprintf(stderr, "webmachine:   [%u] tcp port %d\n", i, cfg.listeners[i].port);
    }
  }
  built_ = true;
  return true;
}

// The Ruby doors all need the server standing; a failure to build is
// this machine refusing this configuration, so it raises with the
// reason rather than answering nil.
void ensure(mrb_state* mrb) {
  char err[512] = "";
  if (!build(mrb, err, sizeof(err))) mrb_raisef(mrb, E_RUNTIME_ERROR, "webmachine: %s", err);
  entered_ = true;
}

mrb_value wm_run(mrb_state* mrb, mrb_value self) {
  ensure(mrb);
  ring_->run();
  return self;
}

mrb_value wm_tick(mrb_state* mrb, mrb_value) {
  mrb_value budget = mrb_nil_value();
  mrb_get_args(mrb, "|o", &budget);
  ensure(mrb);
  if (mrb_nil_p(budget)) return mrb_bool_value(ring_->tick(nullptr));
  // EVERY duration crossing this boundary goes through mruby-chrono,
  // once, at the edge - there is no second seconds convention in this
  // tree (the date patch in http1 is wall-clock, not a duration, and
  // stays plain C).
  const auto ns = mrb_chrono::as<std::chrono::nanoseconds>(mrb, budget);
  if (ns.count() < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Webmachine.tick wants a duration, not a negative one");
  }
  struct __kernel_timespec ts {ns.count() / 1000000000, ns.count() % 1000000000};
  return mrb_bool_value(ring_->tick(&ts));
}

mrb_value wm_fd(mrb_state* mrb, mrb_value) {
  ensure(mrb);
  const int fd = ring_->fd();
  if (fd < 0) {
    // A backend whose completions are not a descriptor cannot be
    // polled, and pretending otherwise would hand the embedder a
    // number that never becomes readable.
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "this io backend has no pollable descriptor - drive it with "
              "Webmachine.tick(budget) instead of waiting on an fd");
  }
  return mrb_fixnum_value(fd);
}

mrb_value wm_stopped(mrb_state* mrb, mrb_value) {
  ensure(mrb);
  return mrb_bool_value(ring_->stopped());
}

}  // namespace

void server_options(const ServerOptions& opts) { opts_ = opts; }

bool server_entered() { return entered_; }

void server_init(mrb_state* mrb, struct RClass* wm) {
  mrb_define_module_function_id(mrb, wm, MRB_SYM(run), wm_run, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, wm, MRB_SYM(tick), wm_tick, MRB_ARGS_OPT(1));
  mrb_define_module_function_id(mrb, wm, MRB_SYM(fd), wm_fd, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, wm, MRB_SYM_Q(stopped), wm_stopped, MRB_ARGS_NONE());
}

int server_run(mrb_state* mrb, char* err, size_t errlen) {
  if (!build(mrb, err, errlen)) return 1;
  entered_ = true;
  ring_->run();
  // The ring's destructor is what unlinks a unix path again, so it has
  // to run BEFORE the process leaves - not at exit, when nothing is
  // ordered any more.
  ring_.reset();
  return 0;
}

}  // namespace webmachine
