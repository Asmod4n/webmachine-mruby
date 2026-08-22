// The server binary: the CLI picks an App and hands it to the Ring.
// --echo mounts the byte-proof Echo app (the bintest's mirror);
// otherwise the HTTP/1.1 app runs. The Ring itself knows only bytes.
#include <mruby.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "../../src/assets.hpp"
#include "../../src/http1.hpp"
#include "../../src/resource.hpp"
#include "../../src/ring.hpp"

namespace {

// The byte proof: what arrived goes back, nothing else. Lives here
// because it is a test fixture, not a protocol.
struct Echo {
  struct Conn {
    void reset(uint8_t) {}
  };
  struct Splice {
    size_t off = 0;
    size_t len = 0;
  };
  bool feed(Conn&, const char* data, size_t len, std::string& sink) {
    sink.append(data, len);
    return true;
  }
  // echo owes nothing between feeds and never splices
  bool more(Conn&, std::string&, Splice&, bool) { return true; }
  void on_tick() {}
};

template <class App>
int serve(const webmachine::RingConfig& cfg, App& app, const char* label) {
  webmachine::Ring<App> ring(app);
  char err[256] = "";
  if (!ring.init(cfg, err, sizeof(err))) {
    std::fprintf(stderr, "webmachine: %s\n", err);
    return 1;
  }
  std::fprintf(stderr, "webmachine: %s up, pid %d, %s\n", label, getpid(),
               cfg.listeners[0].unix_path != nullptr ? cfg.listeners[0].unix_path : "tcp");
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
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--unix") == 0 && i + 1 < argc) {
      cfg.listeners[0].unix_path = argv[++i];
    } else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      cfg.listeners[0].port = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--app") == 0 && i + 1 < argc) {
      app_path = argv[++i];
    } else if (std::strcmp(argv[i], "--assets") == 0 && i + 1 < argc) {
      assets_path = argv[++i];
    } else if (std::strcmp(argv[i], "--pipes") == 0 && i + 1 < argc) {
      // 0 = pure-iovec baseline (the A/B splice is judged against);
      // unset = derived from pipe-user-pages-soft (#168).
      cfg.pipes = std::atol(argv[++i]);
    } else if (std::strcmp(argv[i], "--echo") == 0) {
      echo = true;
    } else {
      std::fprintf(stderr,
                   "usage: %s (--unix PATH | --port N) [--app FILE.rb] [--assets FILE.zip] "
                   "[--pipes N] [--echo]\n",
                   argv[0]);
      return 2;
    }
  }
  if ((cfg.listeners[0].unix_path == nullptr) == (cfg.listeners[0].port == 0)) {
    std::fprintf(stderr, "exactly one of --unix or --port\n");
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

  // The VM boots with the process and holds the resource. Class
  // methods are asked ONCE here and become constants; instance methods
  // are the runtime tier, asked through the VM on every request (the
  // budgeted entry - the copy floor prices one at ~0.1-0.3us).
  mrb_state* mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "webmachine: mrb_open failed\n");
    return 1;
  }

  webmachine::Resource res;  // webmachine-ruby's defaults unbound
  if (app_path != nullptr) {
    char err[512];
    if (!webmachine::resource_setup(mrb, app_path, res, err, sizeof(err))) {
      std::fprintf(stderr, "webmachine: %s: %s\n", app_path, err);
      mrb_close(mrb);
      return 1;
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
    // The ZIP is the splice source (#168): the ring registers it and
    // moves its byte ranges file->pipe->socket where that pays.
    cfg.splice_src_fd = assets.fd();
  }

  int rc = 0;
  if (echo) {
    Echo app;
    rc = serve(cfg, app, "echo floor");
  } else {
    webmachine::Http1 app(res.konst, &res, res.dynamic != 0, res.dynamic_body,
                          assets_path != nullptr ? &assets : nullptr);
    rc = serve(cfg, app, "http/1.1");
  }
  mrb_close(mrb);
  return rc;
}
