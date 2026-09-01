// The second binary (#206). Same sources as the server, same reactor,
// same ring - only the entry point differs: libFuzzer calls in here
// instead of a CLI parsing argv.
//
// WHAT MAKES THIS FAITHFUL, and the reason it is not the method-level
// harness that used to live in test/fuzz: the payload does NOT get
// handed to a parser. A real client socket connects to the server's
// real listener, writes the bytes, and the REACTOR picks them up -
// accept, recv completion, the answer, the send. The only thing that is
// unusual is that both ends live in one address space, which is what
// lets libFuzzer see the coverage it steers by.
//
// Ring::tick is what makes that possible: prep from wherever, one tick,
// and everything that was queued runs. No second thread, no run() loop
// to escape from.
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <mruby.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include "../../src/webmachine.hpp"

namespace {

const char* kSock = "/tmp/wm-libfuzzer.sock";

mrb_state* g_mrb = nullptr;
struct RClass* g_wm = nullptr;

// Connections deliberately left open across runs, so slot reuse under
// the generation counters, the idle deadline and the header deadline are
// things this campaign actually reaches - the same reason the socket
// driver lingers on a share of its connections.
std::vector<int> g_open;
constexpr size_t kMaxOpen = 32;
uint64_t g_runs = 0;

void tick() {
  if (g_mrb == nullptr) return;
  mrb_funcall_id(g_mrb, mrb_obj_value(g_wm), MRB_SYM(tick), 0);
  if (g_mrb->exc != nullptr) {
    // A raise from the reactor is a FINDING, not noise: since the ring
    // stopped ending the process itself, Webmachine::Error is how it
    // says it cannot go on.
    mrb_value s = mrb_funcall_id(g_mrb, mrb_obj_value(g_mrb->exc), MRB_SYM(message), 0);
    std::fprintf(stderr, "webmachine-fuzz: reactor raised: %s\n",
                 mrb_string_p(s) ? RSTRING_PTR(s) : "?");
    std::abort();
  }
}

void setup() {
  ::unlink(kSock);
  g_mrb = mrb_open();
  if (g_mrb == nullptr) std::abort();
  g_wm = mrb_module_get_id(g_mrb, MRB_SYM(Webmachine));

  webmachine::ServerOptions opts;
  opts.cli_unix = kSock;
  // An app makes the flow engine reachable; without one the server is
  // the bare floor and only the framing gets fuzzed. Compiled bytecode
  // only (#100), so the runner hands the path in.
  if (const char* app = std::getenv("WM_FUZZ_APP")) opts.app_path = app;
  webmachine::server_options(opts);

  if (opts.app_path != nullptr) {
    char err[512] = "";
    if (!webmachine::app_load(g_mrb, opts.app_path, err, sizeof(err))) {
      std::fprintf(stderr, "webmachine-fuzz: %s: %s\n", opts.app_path, err);
      std::exit(1);
    }
  }
  tick();  // builds the ring and the listener, then runs one round
}

int dial() {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (fd < 0) return -1;
  struct sockaddr_un sa {};
  sa.sun_family = AF_UNIX;
  std::snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", kSock);
  if (::connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0 &&
      errno != EINPROGRESS) {
    ::close(fd);
    return -1;
  }
  return fd;
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  setup();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0 || size > 65536) return 0;
  const int fd = dial();
  if (fd < 0) return 0;
  tick();  // let the accept land

  ::send(fd, data, size, MSG_NOSIGNAL);
  tick();  // and the recv, the answer, the send

  // Every payload gets its own connection; a share of them are LEFT
  // OPEN, unread, and reaped later - a peer that stops reading is one
  // the server has to survive.
  if ((g_runs & 3) == 0 && g_open.size() < kMaxOpen) {
    g_open.push_back(fd);
  } else {
    char sink[4096];
    while (::recv(fd, sink, sizeof sink, MSG_DONTWAIT) > 0) {
    }
    ::close(fd);
  }
  if (g_open.size() >= kMaxOpen) {
    for (int old : g_open) ::close(old);
    g_open.clear();
    tick();
  }
  g_runs++;
  return 0;
}
