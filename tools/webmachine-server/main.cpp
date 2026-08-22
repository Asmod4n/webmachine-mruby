// The server binary: the CLI picks an App and hands it to the Ring.
// --echo mounts the byte-proof Echo app (the bintest's mirror);
// otherwise the HTTP/1.1 app runs. The Ring itself knows only bytes.
#include <mruby.h>
#include <mruby/variable.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <sys/uio.h>

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
int serve(const webmachine::RingConfig& cfg, App& app, const char* label, bool have_uring) {
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
    } else if (std::strcmp(argv[i], "--echo") == 0) {
      echo = true;
    } else {
      std::fprintf(stderr,
                   "usage: %s (--unix PATH | --port N) [--app FILE.mrb] [--assets FILE.zip] "
                   "[--echo]\n",
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
  }

  const bool have_uring = uring_present(mrb);

  int rc = 0;
  if (echo) {
    Echo app;
    rc = serve(cfg, app, "echo floor", have_uring);
  } else {
    webmachine::Http1 app(res.konst, &res, res.dynamic != 0, res.dynamic_body,
                          assets_path != nullptr ? &assets : nullptr);
    rc = serve(cfg, app, "http/1.1", have_uring);
  }
  mrb_close(mrb);
  return rc;
}
