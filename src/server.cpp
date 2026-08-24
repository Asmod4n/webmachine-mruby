#include "webmachine.hpp"

#include <cstring>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <mruby/chrono.hpp>
#include <mruby/class.h>
#include <mruby/presym.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <memory>
#include <vector>


namespace webmachine {
namespace {

// ONE server per process, like there is one ring and one VM. Built on
// first use - by the tool, or by the app file itself if it called run
// or tick inside `main`.
ServerOptions opts_;
std::vector<AppSpec*> specs_;
std::vector<std::vector<const Resource*>> resources_;
std::vector<std::vector<const WsResource*>> ws_resources_;
std::vector<std::vector<const SseResource*>> sse_resources_;
int log_fd_ = -1;
int err_fd_ = -1;
Assets assets_;
MimeDb mime_;
std::unique_ptr<Http1> http_;
std::unique_ptr<Ring<Http1>> ring_;
bool built_ = false;
bool entered_ = false;

// Fork one webmachine-logd over a socketpair and hand back OUR end.
// The daemon is spawned BEFORE the ring exists, so the child inherits
// none of it. Two streams take this road, and everything on it is 1:1
// identical between them - the socketpair, where the binary lives, the
// fork, the reaped-child signal - so it is written once and the mode
// word is the argument. Returns -1 with a named reason in err: a
// server told to log that cannot log is already breaking its one rule.
int spawn_logd(const char* mode, const char* path, const char* privacy, char* err, size_t errlen) {
  int sp[2];
  if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
    std::snprintf(err, errlen, "--%s log socketpair: %s", mode, std::strerror(errno));
    return -1;
  }
  // The daemon lives next to this binary; argv0-relative, resolved
  // through /proc/self/exe so a PATH-relative start still finds it.
  char self[4096];
  const ssize_t sl = ::readlink("/proc/self/exe", self, sizeof(self) - 1);
  std::string logd = "webmachine-logd";
  if (sl > 0) {
    self[sl] = '\0';
    if (char* slash = std::strrchr(self, '/')) {
      *slash = '\0';
      logd = std::string(self) + "/webmachine-logd";
    }
  }
  // The ceiling, spelled once here so both daemons get the same words.
  char cap[24];
  std::snprintf(cap, sizeof cap, "%llu", opts_.log_max_bytes);
  const pid_t pid = ::fork();
  if (pid < 0) {
    std::snprintf(err, errlen, "--%s log fork: %s", mode, std::strerror(errno));
    ::close(sp[0]);
    ::close(sp[1]);
    return -1;
  }
  if (pid == 0) {
    ::dup2(sp[0], 0);
    ::close(sp[0]);
    ::close(sp[1]);
    // A null privacy IS the argument list's end - execl stops at the
    // first null, so the error daemon is exec'd with four words and
    // the access daemon with five. One call, two shapes, no branch.
    ::execl(logd.c_str(), "webmachine-logd", mode, path, cap, privacy, (char*)nullptr);
    std::fprintf(stderr, "webmachine: exec %s: %s\n", logd.c_str(), std::strerror(errno));
    ::_exit(127);
  }
  ::close(sp[0]);
  // A logd that dies must surface as the write's -EPIPE (a named
  // refusal), never as a zombie in the process table.
  ::signal(SIGCHLD, SIG_IGN);
  return sp[1];
}

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
#ifdef SLIPSTREAM_IO_ONLY
               "webmachine: == why: the `portable` target - built without liburing on\n"
               "webmachine: ==   purpose, so a host that forbids io_uring to this process\n"
               "webmachine: ==   (kernel.io_uring_disabled, seccomp, an LSM) still serves\n"
#else
               "webmachine: == why: this build found no liburing to compile against\n"
#endif
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
#ifdef SLIPSTREAM_IO_ONLY
               "webmachine: == fast: the unnamed build, on a host that allows io_uring\n"
#else
               "webmachine: == fix: build on Linux >= 6.11 against liburing\n"
#endif
               "webmachine: ================================================================\n");
  return true;
#else
  if (!have_uring) {
    // Say WHICH of the reasons it is, when the machine will tell us.
    // kernel.io_uring_disabled (Linux >= 6.6, and what a hardened
    // Debian/Ubuntu ships) is the one an operator can act on: 1 means
    // only members of kernel.io_uring_group may, 2 means nobody may.
    // Anything else - an old kernel, seccomp, an LSM - leaves the
    // file absent or at 0, and then the general sentence is the
    // honest one.
    char why[192] = "the kernel is too old, or a seccomp profile or an LSM blocks it";
    char buf[32] = "";
    const int fd = ::open("/proc/sys/kernel/io_uring_disabled", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
      const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
      ::close(fd);
      if (n > 0) {
        buf[n] = '\0';
        if (buf[0] == '2') {
          std::snprintf(why, sizeof(why),
                        "sysctl kernel.io_uring_disabled=2 - io_uring is off for every "
                        "process on this machine");
        } else if (buf[0] == '1') {
          char grp[32] = "";
          const int g = ::open("/proc/sys/kernel/io_uring_group", O_RDONLY | O_CLOEXEC);
          if (g >= 0) {
            const ssize_t m = ::read(g, grp, sizeof(grp) - 1);
            ::close(g);
            if (m > 0) grp[m] = '\0';
          }
          std::snprintf(why, sizeof(why),
                        "sysctl kernel.io_uring_disabled=1 - only members of group %s "
                        "(kernel.io_uring_group) may, and this process is not one",
                        grp[0] != '\0' ? grp : "?");
        }
      }
    }
    std::snprintf(err, errlen,
                  "io_uring is not usable here: %s. This binary was built against liburing "
                  "and carries no other implementation - the `portable` target "
                  "(build_config.rb) is the one that runs anyway, on select(2)",
                  why);
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
  cfg.sq_entries = opts_.sq_entries;  // 0 stays "the ring's default"
  cfg.backlog = opts_.backlog;
  cfg.to_header = opts_.to_header;
  cfg.to_send = opts_.to_send;
  cfg.to_idle = opts_.to_idle;
  if (!build_listeners(cfg, err, errlen)) return false;

  // The asset table is built ONCE, before any listener exists; a bad
  // archive refuses the start by name (#170). The media types come
  // first, because every entry's Content-Type is decided while that
  // table is built - and they come off the MACHINE, so the startup
  // says which database answered rather than reaching into a file
  // nobody expected.
  if (opts_.assets_path != nullptr) {
    if (!mime_.load(opts_.mime_path, err, errlen)) return false;
    std::fprintf(stderr, "webmachine: media types from %s (%zu extensions)\n",
                 mime_.source().c_str(), mime_.size());
    if (!assets_.open(opts_.assets_path, mime_, err, errlen)) return false;
  }

  // The access log (opt-in, accesslog.hpp's head says why the shape
  // is two processes): --log forks webmachine-logd over a socketpair,
  // BEFORE the ring exists so the child inherits none of it. This
  // core ships records; the sibling formats and writes the file. A
  // daemon that cannot start refuses the start by name - a server
  // told to log that cannot is already breaking its one rule.
  if (opts_.log_path != nullptr) {
    // The level names the amount of PRIVACY, so `none` means full
    // client addresses on disk - personal data under the GDPR (art.
    // 4(1); ECJ C-582/14 said so even for dynamic IPs). That is a
    // legal choice, not a technical one, so the server says out loud
    // what the operator just took on. Precisely: no cookie banner is
    // forced by a server log (that duty is ePrivacy, about the
    // client's DEVICE) - what full addresses need is an art. 6 basis
    // and disclosure. Default: anon, which the authorities treat as
    // no longer personal.
    if (opts_.log_privacy != nullptr && std::strcmp(opts_.log_privacy, "none") == 0) {
      std::fprintf(stderr,
                   "webmachine: --log-privacy none writes FULL client addresses to the log.\n"
                   "webmachine: an IP address is personal data (GDPR art. 4(1)); logging it\n"
                   "webmachine: needs a legal basis (art. 6). Security logging with short\n"
                   "webmachine: retention usually rides legitimate interest plus a privacy\n"
                   "webmachine: notice; using the addresses beyond that (analytics, tracking)\n"
                   "webmachine: needs consent. DNT/Sec-GPC peers are capped to anon either way.\n");
    }
    log_fd_ = spawn_logd("access", opts_.log_path,
                         opts_.log_privacy != nullptr ? opts_.log_privacy : "anon", err, errlen);
    if (log_fd_ < 0) return false;
    cfg.log_fd = log_fd_;
  }
  // The second stream, and a second process for it: --error-log. Same
  // machinery, a different daemon, a different file. It carries no
  // privacy switch - the daemon spells an error's peer at anon and
  // that is the whole of its choice (its head says why).
  if (opts_.error_log_path != nullptr) {
    err_fd_ = spawn_logd("error", opts_.error_log_path, nullptr, err, errlen);
    if (err_fd_ < 0) return false;
    cfg.err_fd = err_fd_;
  }

  // ONE Http1 for the whole process: every route of every app built
  // here, once. The resource pointers are gathered per app and KEPT -
  // AppInput borrows the arrays only for the constructor's duration,
  // but keeping them costs one vector per app and no thought.
  resources_.resize(specs_.size());
  ws_resources_.resize(specs_.size());
  sse_resources_.resize(specs_.size());
  std::vector<Http1::AppInput> inputs(specs_.size());
  for (size_t i = 0; i < specs_.size(); i++) {
    resources_[i].reserve(specs_[i]->resources.size());
    for (const auto& r : specs_[i]->resources) resources_[i].push_back(r.get());
    ws_resources_[i].reserve(specs_[i]->ws_resources.size());
    for (const auto& r : specs_[i]->ws_resources) ws_resources_[i].push_back(r.get());
    sse_resources_[i].reserve(specs_[i]->sse_resources.size());
    for (const auto& r : specs_[i]->sse_resources) sse_resources_[i].push_back(r.get());
    inputs[i] = Http1::AppInput{&specs_[i]->table,
                                resources_[i].data(),
                                resources_[i].size(),
                                &specs_[i]->ws_table,
                                ws_resources_[i].data(),
                                ws_resources_[i].size(),
                                &specs_[i]->sse_table,
                                sse_resources_[i].data(),
                                sse_resources_[i].size()};
  }
  http_.reset(new Http1(inputs.data(), inputs.size(),
                        opts_.assets_path != nullptr ? &assets_ : nullptr));
  if (opts_.log_path != nullptr) http_->enable_access_log();
  if (opts_.error_log_path != nullptr) http_->enable_error_log();

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
    // The RING's port, not the spec's: a conf asking for port 0 gets
    // the kernel's pick here, which is the whole point of asking.
    app_mark_bound(*specs_[i], cfg.listeners[i].unix_path,
                   ring_->bound_port(static_cast<uint32_t>(i)));
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
      std::fprintf(stderr, "webmachine:   [%u] tcp port %d\n", i, ring_->bound_port(i));
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

// DRAIN, THEN FORGET (#116 slice 5). The listeners close at once, and
// the loop turns until the last accepted connection is gone or the
// grace runs out - whichever comes first. No argument = stop now.
//
// This is process-wide, and the name says as much: there is ONE ring
// and ONE loop, so a second application's connections stop with the
// first's. Application#stop is this same method under webmachine-ruby's
// spelling, not a second, narrower one - a per-app stop would have to
// mean a listener closing while the loop kept turning, which nothing
// has asked for and which this would only pretend to do.
mrb_value wm_stop(mrb_state* mrb, mrb_value self) {
  mrb_value grace = mrb_nil_value();
  mrb_get_args(mrb, "|o", &grace);
  // Never BUILDS the server: stopping one that was never started is
  // not an error, it is a no-op with nothing to drain.
  if (!built_) return self;
  int64_t ns = 0;
  if (!mrb_nil_p(grace)) {
    ns = mrb_chrono::as<std::chrono::nanoseconds>(mrb, grace).count();
    if (ns < 0) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "Webmachine.stop wants a grace, not a negative one");
    }
  }
  ring_->drain(ns);
  return self;
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
  mrb_define_module_function_id(mrb, wm, MRB_SYM(stop), wm_stop, MRB_ARGS_OPT(1));
  // webmachine-ruby's own spelling, the same method: an application
  // object is where a Ruby program has the server in its hand.
  struct RClass* app = mrb_class_get_under_id(mrb, wm, MRB_SYM(Application));
  mrb_define_method_id(mrb, app, MRB_SYM(stop), wm_stop, MRB_ARGS_OPT(1));
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
