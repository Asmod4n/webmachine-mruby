// The server binary: the CLI picks an App and hands it to the Ring.
// --echo mounts the byte-proof Echo app (the bintest's mirror);
// otherwise the HTTP/1.1 app runs. The Ring itself knows only bytes.
//
// SINCE #116 the app file defines `main` and nothing else: this tool
// loads the bytecode, calls `main`, and the Webmachine::Application the
// block registered says where to listen and what to route. There is no
// `run` in Ruby yet - serve() below IS the serve loop, cut as its own
// function precisely so slice 3 can expose it as Webmachine.run (and
// its wait as Webmachine.tick) without moving a line of it.
#include <mruby.h>
#include <mruby/variable.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <sys/uio.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "../../src/application.hpp"
#include "../../src/assets.hpp"
#include "../../src/http1.hpp"
#include "../../src/resource.hpp"
#include "../../src/ring.hpp"

namespace {

// The byte proof: what arrived goes back, nothing else. Lives here
// because it is a test fixture, not a protocol.
struct Echo {
  struct Conn {
    void reset(uint8_t, bool) {}
  };
  struct Plan {  // echo hands over no pointers; the shape is the Ring's
    struct iovec iov[4] = {};
    unsigned niov = 0;
    size_t iov_len = 0;
  };
  bool feed(Conn&, const char* data, size_t len, std::string& sink) {
    sink.append(data, len);
    return true;
  }
  bool more(Conn&, std::string&, Plan&) { return true; }  // owes nothing between feeds
  bool pending(const Conn&) const { return false; }  // nothing is ever owed
  void on_tick() {}
};

// Does io_uring exist on THIS machine? Not asked here - ANSWERED
// here, by reading the answer the process already has. mruby-io_uring
// probes in its gem_init during mrb_open() and publishes the result as
// URING_AVAILABLE on Object; it is a hard dependency of this tree
// (mrbgem.rake), so the constant is always there and always current.
// Asking again with a probe of our own would create a second answer
// that can disagree with the first - the point of the gem exporting a
// signal is that there is exactly one.
//
// This is a RUNTIME question and stays one even though WHICH
// implementation of the API got compiled in is settled at build time
// (see slipstreamIO): a binary built against the real liburing can
// still land on a kernel too old for the ring ops, or under a seccomp
// profile or sysctl that blocks them.
bool uring_present(mrb_state* mrb) {
  const mrb_sym k = mrb_intern_lit(mrb, "URING_AVAILABLE");
  const mrb_value obj = mrb_obj_value(mrb->object_class);
  if (!mrb_const_defined(mrb, obj, k)) return false;  // a build without the gem
  return mrb_bool(mrb_const_get(mrb, obj, k));
}

// ONE path (#171). The Ring calls io_uring_* and never learns which
// implementation answers - there is no template parameter, no function
// table and no `if (have_uring)` anywhere below this line. Which one
// got linked was decided when the tree was built, by whoever put a
// liburing.h on the include path; SLIPSTREAM_IO says it landed on the
// select implementation, and that is worth SAYING - loudly, once, at
// startup - because it is correct and not fast.
//
// SAYING is all the name is good for. The numbers in that banner are
// read from the PROPERTY the header states (IO_URING_FD_CEILING), not
// from the name: a limit derived from a name is a limit every later
// implementation inherits whether or not it has one.
//
// When the real ring is in and the machine cannot run it, this refuses
// BY NAME and stops. There is no second backend in the binary to fall
// back to, and inventing a slow one at that moment would be a
// performance cliff wearing a startup message.
template <class App>
int serve(const webmachine::RingConfig& cfg, App& app, const char* label, bool have_uring,
          mrb_state* mrb = nullptr,
          const std::vector<webmachine::AppSpec*>& specs = {}) {
#ifdef SLIPSTREAM_IO
  (void)have_uring;
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
#else
  if (!have_uring) {
    std::fprintf(stderr,
                 "webmachine: io_uring is not usable here (URING_AVAILABLE is false: the\n"
                 "webmachine: kernel is too old, or a seccomp profile or sysctl blocks it).\n"
                 "webmachine: This binary was built against liburing and carries no other\n"
                 "webmachine: implementation. Build against slipstreamIO to run anyway.\n");
    return 1;
  }
#endif
  webmachine::Ring<App> ring(app);
  char err[256] = "";
  if (!ring.init(cfg, err, sizeof(err))) {
    std::fprintf(stderr, "webmachine: %s\n", err);
    return 1;
  }
  // THE BIND HAS HAPPENED - all of them, in listener order. Each app's
  // conf.url now reads back where ITS listener really is, and its ready
  // hook runs: after the bind, before the first accept, exactly once,
  // in the order the apps registered. A raise there stops the start.
  for (size_t i = 0; i < specs.size(); i++) {
    webmachine::app_mark_bound(*specs[i], cfg.listeners[i].unix_path, cfg.listeners[i].port);
    char rerr[256] = "";
    if (!webmachine::app_ready_run(mrb, *specs[i], rerr, sizeof(rerr))) {
      std::fprintf(stderr, "webmachine: %s\n", rerr);
      return 1;
    }
  }
  std::fprintf(stderr, "webmachine: %s up, pid %d, %u listener(s)\n", label, getpid(),
               cfg.nlisteners);
  for (uint32_t i = 0; i < cfg.nlisteners; i++) {
    if (cfg.listeners[i].unix_path != nullptr) {
      std::fprintf(stderr, "webmachine:   [%u] unix %s\n", i, cfg.listeners[i].unix_path);
    } else {
      std::fprintf(stderr, "webmachine:   [%u] tcp port %d\n", i, cfg.listeners[i].port);
    }
  }
  ring.run();
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  webmachine::RingConfig cfg;
  cfg.nlisteners = 1;
  bool echo = false;
  const char* app_path = nullptr;
  const char* assets_path = nullptr;
  const char* cli_unix = nullptr;
  int cli_port = 0;
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--unix") == 0 && i + 1 < argc) {
      cli_unix = argv[++i];
    } else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      cli_port = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--app") == 0 && i + 1 < argc) {
      app_path = argv[++i];
    } else if (std::strcmp(argv[i], "--assets") == 0 && i + 1 < argc) {
      assets_path = argv[++i];
    } else if (std::strcmp(argv[i], "--echo") == 0) {
      echo = true;
    } else {
      std::fprintf(stderr,
                   "usage: %s [--unix PATH | --port N] [--app FILE.mrb] [--assets FILE.zip] "
                   "[--echo]\n"
                   "  --unix/--port OVERRIDE the listener the app's conf named; without an\n"
                   "  app (or without a conf listener) one of them is required.\n",
                   argv[0]);
      return 2;
    }
  }
  if (cli_unix != nullptr && cli_port != 0) {
    std::fprintf(stderr, "at most one of --unix or --port\n");
    return 2;
  }

  // TERM/INT are blocked and land in a signalfd the ring polls: the
  // stop arrives as a CQE, so it cannot race the ring wait the way a
  // handler flag would (flag checked, signal lands, wait blocks forever).
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigprocmask(SIG_BLOCK, &mask, nullptr);
  cfg.stop_fd = signalfd(-1, &mask, SFD_CLOEXEC);

  // The VM boots with the process and holds the resources. Class
  // methods are asked ONCE at route.add and become constants; instance
  // methods are the runtime tier, asked through the VM on every request
  // (the budgeted entry - the copy floor prices one at ~0.1-0.3us).
  mrb_state* mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "webmachine: mrb_open failed\n");
    return 1;
  }

  // EVERY application main registered, in registration order (#116
  // slice 2). That order is the listener order and the listener index
  // is what a connection carries, so this one vector decides both the
  // ring's setup chain and which routes a request walks.
  std::vector<webmachine::AppSpec*> specs;
  if (app_path != nullptr) {
    char err[512];
    if (!webmachine::app_load(mrb, app_path, err, sizeof(err))) {
      std::fprintf(stderr, "webmachine: %s: %s\n", app_path, err);
      mrb_close(mrb);
      return 1;
    }
    if (!webmachine::app_registered_all(specs, webmachine::kMaxListeners, err, sizeof(err))) {
      std::fprintf(stderr, "webmachine: %s: %s\n", app_path, err);
      mrb_close(mrb);
      return 1;
    }
  } else {
    // No app: one splat route on webmachine-ruby's unbound resource -
    // what this server answered everywhere before routes existed.
    specs.push_back(webmachine::app_default());
  }

  // The CLI overrides conf: a spec's listener is what the app WANTS,
  // --unix/--port is what this invocation gets (bintests and bench runs
  // live on that override). It names ONE socket, so it can only speak
  // for a file that registered ONE app - with several, the override has
  // no way to say which, and refusing is the only honest answer.
  cfg.nlisteners = static_cast<uint32_t>(specs.size());
  const bool cli_listener = cli_unix != nullptr || cli_port != 0;
  if (cli_listener && specs.size() > 1) {
    std::fprintf(stderr,
                 "webmachine: --unix/--port names one listener and %s registered %zu "
                 "applications - drop the override and let each app's conf speak\n",
                 app_path, specs.size());
    mrb_close(mrb);
    return 2;
  }
  if (cli_unix != nullptr) {
    cfg.listeners[0].unix_path = cli_unix;
  } else if (cli_port != 0) {
    cfg.listeners[0].port = cli_port;
  } else {
    for (size_t i = 0; i < specs.size(); i++) {
      switch (specs[i]->form) {
        case webmachine::AppSpec::Form::kUnix:
          cfg.listeners[i].unix_path = specs[i]->unix_path.c_str();
          break;
        case webmachine::AppSpec::Form::kPort:
        case webmachine::AppSpec::Form::kUrl: cfg.listeners[i].port = specs[i]->port; break;
        case webmachine::AppSpec::Form::kNone:
          std::fprintf(stderr,
                       "webmachine: application %zu has no listener - its configure block "
                       "names one (conf.port / conf.unix_path / conf.url), or pass "
                       "--port/--unix for a file with a single app\n",
                       i);
          mrb_close(mrb);
          return 2;
      }
    }
  }

  // The asset table is built ONCE, before any listener exists; a bad
  // archive refuses the start by name (#170).
  webmachine::Assets assets;
  if (assets_path != nullptr) {
    char err[512];
    if (!assets.open(assets_path, err, sizeof(err))) {
      std::fprintf(stderr, "webmachine: assets: %s\n", err);
      mrb_close(mrb);
      return 1;
    }
  }

  const bool have_uring = uring_present(mrb);

  int rc = 0;
  if (echo) {
    Echo app;
    rc = serve(cfg, app, "echo floor", have_uring);
  } else {
    // ONE Http1 for the whole process: every route of every app built
    // here, once, and the connection's listener plus the router pick
    // between them per request. The resource pointers are gathered per
    // app into one vector each, kept alive until the constructor has
    // copied what it needs.
    std::vector<std::vector<const webmachine::Resource*>> resources(specs.size());
    std::vector<webmachine::Http1::AppInput> inputs(specs.size());
    for (size_t i = 0; i < specs.size(); i++) {
      resources[i].reserve(specs[i]->resources.size());
      for (const auto& r : specs[i]->resources) resources[i].push_back(r.get());
      inputs[i] = webmachine::Http1::AppInput{&specs[i]->table, resources[i].data(),
                                              resources[i].size()};
    }
    webmachine::Http1 app(inputs.data(), inputs.size(),
                          assets_path != nullptr ? &assets : nullptr);
    rc = serve(cfg, app, "http/1.1", have_uring, mrb, specs);
  }
  mrb_close(mrb);
  return rc;
}
