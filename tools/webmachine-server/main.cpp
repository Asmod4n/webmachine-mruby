// The server binary: the CLI states what this INVOCATION decides, the
// app file's `main` states what is served, and the loop belongs to
// neither - src/server.cpp owns it, and this tool enters it through the
// same door Ruby does (#116 slice 3: Webmachine.run / .tick / .fd).
// --echo mounts the byte-proof Echo app, which is a fixture and has no
// applications, so it keeps a serve loop of its own here.
#include <mruby.h>
#include <mruby/variable.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <sys/uio.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../../src/application.hpp"
#include "../../src/ring.hpp"
#include "../../src/server.hpp"

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

// The echo floor's own loop. The HTTP server has none here any more:
// src/server.cpp holds it, so Ruby and this tool cannot drift apart.
int serve_echo(const webmachine::RingConfig& cfg, bool have_uring) {
  char err[512] = "";
  if (!webmachine::server_backend_ok(have_uring, err, sizeof(err))) {
    std::fprintf(stderr, "webmachine: %s\n", err);
    return 1;
  }
  Echo app;
  webmachine::Ring<Echo> ring(app);
  if (!ring.init(cfg, err, sizeof(err))) {
    std::fprintf(stderr, "webmachine: %s\n", err);
    return 1;
  }
  std::fprintf(stderr, "webmachine: echo floor up, pid %d, %s\n", getpid(),
               cfg.listeners[0].unix_path != nullptr ? cfg.listeners[0].unix_path : "tcp");
  ring.run();
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  bool echo = false;
  webmachine::ServerOptions opts;
  const char* cli_unix = nullptr;
  int cli_port = 0;
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--unix") == 0 && i + 1 < argc) {
      cli_unix = argv[++i];
    } else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      cli_port = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--app") == 0 && i + 1 < argc) {
      opts.app_path = argv[++i];
    } else if (std::strcmp(argv[i], "--assets") == 0 && i + 1 < argc) {
      opts.assets_path = argv[++i];
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
  opts.cli_unix = cli_unix;
  opts.cli_port = cli_port;

  // TERM/INT are blocked and land in a signalfd the ring polls: the
  // stop arrives as a CQE, so it cannot race the ring wait the way a
  // handler flag would (flag checked, signal lands, wait blocks forever).
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigprocmask(SIG_BLOCK, &mask, nullptr);
  opts.stop_fd = signalfd(-1, &mask, SFD_CLOEXEC);

  // The VM boots with the process and holds the resources. Class
  // methods are asked ONCE at route.add and become constants; instance
  // methods are the runtime tier, asked through the VM on every request
  // (the budgeted entry - the copy floor prices one at ~0.1-0.3us).
  mrb_state* mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "webmachine: mrb_open failed\n");
    return 1;
  }
  opts.have_uring = uring_present(mrb);

  if (echo) {
    webmachine::RingConfig cfg;
    cfg.nlisteners = 1;
    cfg.stop_fd = opts.stop_fd;
    if (cli_unix != nullptr) {
      cfg.listeners[0].unix_path = cli_unix;
    } else if (cli_port != 0) {
      cfg.listeners[0].port = cli_port;
    } else {
      std::fprintf(stderr, "webmachine: --echo needs --unix or --port\n");
      mrb_close(mrb);
      return 2;
    }
    const int rc = serve_echo(cfg, opts.have_uring);
    mrb_close(mrb);
    return rc;
  }

  // The INVOCATION speaks first, and once: an app file that could
  // rewrite the command line would make the command line a suggestion.
  webmachine::server_options(opts);

  if (opts.app_path != nullptr) {
    char err[512];
    if (!webmachine::app_load(mrb, opts.app_path, err, sizeof(err))) {
      std::fprintf(stderr, "webmachine: %s: %s\n", opts.app_path, err);
      mrb_close(mrb);
      return 1;
    }
  } else {
    // No app: one splat route on webmachine-ruby's unbound resource -
    // what this server answered everywhere before routes existed.
    webmachine::app_default();
  }

  int rc = 0;
  // `main` may have served already - it can call Webmachine.run, or
  // tick in a loop of its own; that is what slice 3 is for. Then there
  // is nothing left here to do: the stop that ended its loop ends this
  // process too.
  if (!webmachine::server_entered()) {
    char err[512] = "";
    rc = webmachine::server_run(mrb, err, sizeof(err));
    if (rc != 0) std::fprintf(stderr, "webmachine: %s\n", err);
  }
  mrb_close(mrb);
  return rc;
}
