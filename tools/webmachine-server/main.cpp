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
#include "../../src/config.hpp"
#include "../../src/ring.hpp"
#include "../../src/server.hpp"

namespace {

// The byte proof: what arrived goes back, nothing else. Lives here
// because it is a test fixture, not a protocol.
struct Echo {
  struct Conn {
    const void* peer = nullptr;   // the Ring fills these when a log is
    uint8_t peer_len = 0;         // on; echo has no log and no reader
    void reset(uint8_t, bool) {}
  };
  struct Plan {  // echo hands over no segments; the shape is the Ring's
    struct Seg {
      const char* base;
      size_t off;
      size_t len;
    };
    static constexpr unsigned kSegs = 1;
    Seg seg[kSegs] = {};
    unsigned nseg = 0;
    size_t iov_len = 0;
    size_t byte_cap = 0;
  };
  bool feed(Conn&, const char* data, size_t len, std::string& sink, Plan*) {
    sink.append(data, len);
    return true;
  }
  bool more(Conn&, std::string&, Plan&) { return true; }  // owes nothing between feeds
  webmachine::AccessLog* access_log() { return nullptr; }  // echo logs nothing
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
  const char* pidfile = nullptr;
  webmachine::ServerOptions opts;
  const char* cli_unix = nullptr;
  const char* log_path = nullptr;
  const char* log_privacy = nullptr;
  const char* config_path = nullptr;
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
    } else if (std::strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
      log_path = argv[++i];
    } else if (std::strcmp(argv[i], "--log-privacy") == 0 && i + 1 < argc) {
      log_privacy = argv[++i];
    } else if (std::strcmp(argv[i], "--pidfile") == 0 && i + 1 < argc) {
      pidfile = argv[++i];
    } else if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config_path = argv[++i];
    } else if (std::strcmp(argv[i], "--echo") == 0) {
      echo = true;
    } else {
      std::fprintf(stderr,
                   "usage: %s [--config FILE.toml] [--unix PATH | --port N] [--app FILE.mrb] "
                   "[--assets FILE.zip] [--log FILE [--log-privacy none|anon|full]] "
                   "[--pidfile PATH] [--echo]\n"
                   "  --config reads the same choices from a TOML file; typed flags beat it,\n"
                   "  and both beat the app's conf. Without --config, a ./webmachine.toml is\n"
                   "  used when present (and announced).\n"
                   "  --unix/--port OVERRIDE the listener the app's conf named; without an\n"
                   "  app (or without a conf listener) one of them is required.\n"
                   "  --pidfile writes this process's pid and removes the file on the way out.\n",
                   argv[0]);
      return 2;
    }
  }
  if (cli_unix != nullptr && cli_port != 0) {
    std::fprintf(stderr, "at most one of --unix or --port\n");
    return 2;
  }

  // The VM boots with the process and holds the resources. Class
  // methods are asked ONCE at route.add and become constants; instance
  // methods are the runtime tier, asked through the VM on every request
  // (the budgeted entry - the copy floor prices one at ~0.1-0.3us).
  // Booted BEFORE the config file: mruby-toml parses it through this
  // same VM (config is once-per-start, no hot path, no second parser).
  mrb_state* mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "webmachine: mrb_open failed\n");
    return 1;
  }

  // The file speaks after the flags (config.hpp's head owns the
  // precedence sentence). An explicit --config that cannot be read is
  // a refusal; without one, ./webmachine.toml is used when present -
  // and ANNOUNCED, so an invisible file never silently steers a
  // server. `fc` owns the strings for the whole run.
  webmachine::Config fc;
  if (config_path == nullptr && ::access("webmachine.toml", R_OK) == 0) {
    config_path = "webmachine.toml";
  }
  if (config_path != nullptr) {
    char cerr[512];
    if (!webmachine::config_load(mrb, config_path, fc, cerr, sizeof(cerr))) {
      std::fprintf(stderr, "webmachine: %s\n", cerr);
      mrb_close(mrb);
      return 2;
    }
    std::fprintf(stderr, "webmachine: config %s\n", config_path);
    if (cli_unix == nullptr && cli_port == 0) {
      if (!fc.unix_path.empty()) cli_unix = fc.unix_path.c_str();
      else if (fc.port != 0) cli_port = fc.port;
    }
    if (opts.app_path == nullptr && !fc.app.empty()) opts.app_path = fc.app.c_str();
    if (opts.assets_path == nullptr && !fc.assets.empty()) opts.assets_path = fc.assets.c_str();
    if (log_path == nullptr && !fc.log_file.empty()) log_path = fc.log_file.c_str();
    if (log_privacy == nullptr && !fc.log_privacy.empty()) log_privacy = fc.log_privacy.c_str();
    if (pidfile == nullptr && !fc.pidfile.empty()) pidfile = fc.pidfile.c_str();
    opts.sq_entries = fc.sq_entries;  // no CLI twin; 0 = default
    opts.backlog = fc.backlog;
  }

  opts.cli_unix = cli_unix;
  opts.cli_port = cli_port;

  // The pid, for whoever started this process and has to find it again
  // - a supervisor, a test harness, a bench script. Written BEFORE
  // anything can fail, so a file that exists names a process that at
  // least got this far, and removed on the way out (the stop signal
  // lands in the signalfd below, so the normal exit path runs).
  //
  // Pattern-matching the process table is the alternative, and it is
  // worse than it looks: `pkill -f webmachine-server` also matches the
  // shell that typed the command, which is how an afternoon gets spent.
  if (pidfile != nullptr) {
    FILE* pf = std::fopen(pidfile, "we");
    if (pf == nullptr) {
      std::fprintf(stderr, "webmachine: cannot write pidfile %s\n", pidfile);
      mrb_close(mrb);
      return 1;
    }
    std::fprintf(pf, "%d\n", getpid());
    std::fclose(pf);
  }

  // TERM/INT are blocked and land in a signalfd the ring polls: the
  // stop arrives as a CQE, so it cannot race the ring wait the way a
  // handler flag would (flag checked, signal lands, wait blocks forever).
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigprocmask(SIG_BLOCK, &mask, nullptr);
  opts.stop_fd = signalfd(-1, &mask, SFD_CLOEXEC);

  opts.log_path = log_path;
  opts.log_privacy = log_privacy;
  opts.have_uring = uring_present(mrb);

  if (echo) {
    webmachine::RingConfig cfg;
    cfg.nlisteners = 1;
    cfg.stop_fd = opts.stop_fd;
    cfg.sq_entries = opts.sq_entries;  // [tune] reaches the floor too
    cfg.backlog = opts.backlog;
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
  if (pidfile != nullptr) ::unlink(pidfile);
  return rc;
}
