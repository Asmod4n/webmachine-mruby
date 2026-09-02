// The dynamic-body A/B, driven through the REAL reactor.
//
// vm_floor.cpp's BM_wire_copy_send / BM_wire_register_sendmsg answered
// "copy out of the VM, or freeze+register and hand the VM's own buffer
// to the kernel?" against BLOCKING send()/sendmsg(). That is not the
// shape the server has: everything goes through webmachine::Ring<App>,
// whose io_uring_submit_and_wait carries several SQEs per enter and
// reaps several CQEs per return. Batching amortises exactly the fixed
// per-call cost that made the two paths look equal below 32KB, so the
// crossover measured against bare syscalls need not be the real one.
//
// This driver rebuilds the same A/B on top of the real Ring: real
// multishot accept, real buffer-ring recv, real take_plan, real
// arm_send, real send completions. Nothing about the reactor is
// reimplemented here - only a minimal App is, because Http1 is far more
// surface than the question needs.
//
//   (a) copy-first  - fresh mrb String, bytes copied into the sink,
//                     delivered as a sink-relative Seg{nullptr,off,len}
//                     (today's shape: resource.cpp's run_body->assign).
//   (b) zero-copy   - same fresh String, frozen + gc_registered, its
//                     RSTRING_PTR handed in as an external Seg{base,0,len},
//                     exactly mirroring the mmap'd-asset precedent in
//                     http1.cpp (Assets::wire_iov -> plan->seg[...]).
//
// Both shapes emit TWO segments (header from the sink, body), so both
// end up in one sendmsg with two iovecs: the only variable left between
// them is the body memcpy against freeze/register/unregister.
//
// One process = one (variant, size) measurement, by design - a shared
// 4-vCPU box wants many short isolated runs and a median, not one long
// run and a mean. bench/vm/ring_body.sh drives the repetitions.

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/string.h>

#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "../../src/webmachine.hpp"

namespace {

// ---------------------------------------------------------------- config

bool g_zero_copy = false;   // (b) when set, (a) otherwise
// Two knobs, not one - because the first profiled reading showed the
// difference between the variants was NOT the memcpy (144ns at 8KB, as
// an 8KB memcpy should be) but mrb_str_new running several times slower
// in the copy variant. Delivery and lifetime therefore have to be
// separable, or the benchmark cannot say which of the two it measured.
//   deliver: copy into the sink, or hand over an external pointer
//   hold:    freeze + gc_register for the in-flight window, or not
// copy+nohold is today's shape, extern+hold is the proposal, and
// copy+hold is the control that tells the two effects apart.
bool g_hold = false;
size_t g_body = 0;          // body bytes per response
std::string g_src;          // what the "callback" builds its String from
std::string g_header;       // response head, identical in both variants
mrb_state* mrb = nullptr;

// Timing phases, flipped by the client thread, sampled by the ring
// thread from on_tick() - the one App callback the reactor makes on
// every single step.
enum : int { kWarm = 0, kMeasure = 1, kDone = 2 };
std::atomic<int> g_phase{kWarm};

int64_t g_cpu_start_ns = 0;
int64_t g_cpu_ns = 0;

// Reactor steps inside the measured window. One step is one
// io_uring_submit_and_wait, i.e. one io_uring_enter - so requests/steps
// IS the batching depth this run actually achieved, which is the whole
// reason the blocking-syscall answer was suspect.
int64_t g_steps = 0;
int64_t g_steps_start = 0;
int64_t g_steps_total = 0;

// --profile: where the App-side time actually goes. Off by default -
// four clock reads per request is ~1% on a 10us request, which is fine
// for attribution and not fine for a headline number. This exists
// because the first honest reading of the 8KB result was "the copy
// variant burns 6us more CPU per request", and an 8KB memcpy is not
// 6us: something had to be attributed before anything could be claimed.
bool g_profile = false;
int64_t g_n_emit = 0;      // responses emitted in the measured window
int64_t g_str_ns = 0;      // mrb_str_new: the callback's fresh String
int64_t g_move_ns = 0;     // (a) sink.append   (b) freeze + gc_register
int64_t g_rel_ns = 0;      // (b) gc_unregister + unfreeze; (a) nothing
int64_t g_emit_ns = 0;     // the whole of emit()

// Registrations outstanding. A body that reaches the wire and is never
// released is a VM object that never dies - the exact failure mode the
// zero-copy shape risks - so the harness counts rather than trusts. It
// must be 0 once every connection is gone.
int64_t g_held_live = 0;

int64_t thread_cpu_ns() {
  struct rusage ru {};
  ::getrusage(RUSAGE_THREAD, &ru);
  return (static_cast<int64_t>(ru.ru_utime.tv_sec) + ru.ru_stime.tv_sec) * 1000000000 +
         (static_cast<int64_t>(ru.ru_utime.tv_usec) + ru.ru_stime.tv_usec) * 1000;
}

// Optional, off by default: on a shared box, pinning removes migration
// noise but also removes the scheduler's ability to dodge a busy
// neighbour. Which of the two wins is an empirical question, so it is a
// flag rather than a decision baked into the harness.
void pin_to(int cpu) {
  if (cpu < 0) return;
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu, &set);
  (void)::pthread_setaffinity_np(::pthread_self(), sizeof set, &set);
}

int64_t mono_ns() {
  struct timespec ts {};
  ::clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<int64_t>(ts.tv_sec) * 1000000000 + ts.tv_nsec;
}

std::string make_header(size_t n) {
  char buf[256];
  const int k = std::snprintf(buf, sizeof buf,
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: text/html; charset=utf-8\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: keep-alive\r\n"
                              "\r\n",
                              n);
  return std::string(buf, static_cast<size_t>(k));
}

// ------------------------------------------------------------------ App

// The smallest thing that satisfies what Ring<App> asks for. The
// protocol is deliberately not HTTP on the way IN: one request byte,
// one response. Parsing is not what is being weighed here.
class BodyApp {
 public:
  struct Conn {
    // The in-flight registration for variant (b). At most one, because
    // the driver is strictly lockstep per connection - see the abort in
    // emit() if that ever stops being true.
    mrb_value held{};
    bool has_held = false;
    unsigned owed = 0;  // requests received, response not yet emitted

    // Ring's on_peer writes these; they must exist even though this
    // bench never enables a log.
    const void* peer = nullptr;
    uint8_t peer_len = 0;

    // The Ring resets a slot on accept - which is also the only signal
    // an App gets that a connection died and came back, so it doubles
    // as the begin_close() release path (see release()).
    void reset(uint8_t, bool) {
      release();
      owed = 0;
      peer = nullptr;
      peer_len = 0;
    }
    ~Conn() { release(); }

    // Release the VM's hold on the body: unregister so the next GC may
    // collect it, and lift the freeze we imposed. The freeze was ours,
    // for our in-flight window only - Ruby has no #unfreeze, so we
    // clear the RBasic bit directly rather than leave app-visible state
    // behind. mruby's GC never moves objects, so the pointer the kernel
    // read was stable; the freeze is what kept mrb_str_modify from
    // reallocating it out from under the send.
    void release() {
      if (!has_held) return;
      const int64_t t0 = g_profile ? mono_ns() : 0;
      mrb_gc_unregister(mrb, held);
      mrb_basic_ptr(held)->frozen = 0;
      has_held = false;
      g_held_live--;
      if (g_profile && g_phase.load(std::memory_order_relaxed) == kMeasure) {
        g_rel_ns += mono_ns() - t0;
      }
    }
  };

  struct Plan {
    struct Seg {
      const char* base;
      size_t off;
      size_t len;
    };
    static constexpr unsigned kSegs = 1023;
    Seg seg[kSegs];
    unsigned nseg = 0;
    size_t iov_len = 0;
    size_t byte_cap = 0;
  };

  // Wire bytes in: one byte is one request. A chunk that is not the last
  // of its CQE arrives with plan == nullptr and can only be counted.
  struct Sink {
    std::string& bytes;
    Plan* plan;
  };

  bool feed(Conn& st, std::string_view in, Sink out) {
    st.owed += static_cast<unsigned>(in.size());
    if (out.plan != nullptr && st.owed != 0) emit(st, out.bytes, *out.plan);
    return true;
  }

  // THE RELEASE POINT. more() is reached only through continue_conn(),
  // which on_send() calls exactly when the whole round has drained
  // (c.sent >= offered, sink cleared, niov cleared). That is the
  // granularity the plan was built at - header seg plus body seg, one
  // completion - so releasing here releases neither too early nor too
  // late. Released BEFORE the next body is built, so a connection never
  // holds two.
  bool more(Conn& st, std::string& sink, Plan& plan) {
    st.release();
    if (st.owed != 0) emit(st, sink, plan);
    return true;
  }

  bool pending(const Conn& st) const { return st.owed != 0; }
  bool timed(const Conn&) const { return false; }

  // Called once per reactor step; the phase samples ride along on it
  // rather than needing a clock of their own.
  void on_tick() {
    g_steps++;
    const int p = g_phase.load(std::memory_order_relaxed);
    if (p == kMeasure && g_cpu_start_ns == 0) {
      g_cpu_start_ns = thread_cpu_ns();
      g_steps_start = g_steps;
    }
    if (p == kDone && g_cpu_ns == 0 && g_cpu_start_ns != 0) {
      g_cpu_ns = thread_cpu_ns() - g_cpu_start_ns;
      g_steps_total = g_steps - g_steps_start;
    }
  }

  // No logs: the Ring checks for null and skips both streams.
  webmachine::Logger* access_log() { return nullptr; }
  webmachine::Logger* error_log() { return nullptr; }

 private:
  // One response: the head into the sink, the body either copied in
  // behind it (a) or handed over as an external pointer (b).
  void emit(Conn& st, std::string& sink, Plan& plan) {
    if (st.has_held) {
      // A second body while the first is still on the wire would mean
      // the lockstep assumption broke and one registration is about to
      // be lost. Never silently: the numbers would be measuring a leak.
      std::fprintf(stderr, "ring_body: two bodies in flight on one conn - lockstep broken\n");
      std::abort();
    }
    st.owed--;
    const bool prof = g_profile && g_phase.load(std::memory_order_relaxed) == kMeasure;
    const int64_t t_emit = prof ? mono_ns() : 0;

    const size_t hoff = sink.size();
    sink.append(g_header);
    plan.seg[plan.nseg++] = Plan::Seg{nullptr, hoff, g_header.size()};
    plan.iov_len += g_header.size();

    const int ai = mrb_gc_arena_save(mrb);
    // What a resource's to_html-style callback hands back: a fresh
    // Ruby String, allocated inside the VM, per request.
    const int64_t t_str = prof ? mono_ns() : 0;
    mrb_value v = mrb_str_new(mrb, g_src.data(), static_cast<mrb_int>(g_body));
    const size_t blen = static_cast<size_t>(RSTRING_LEN(v));
    const int64_t t_move = prof ? mono_ns() : 0;
    if (prof) g_str_ns += t_move - t_str;
    if (g_hold) {
      mrb_obj_freeze(mrb, v);
      mrb_gc_register(mrb, v);
      st.held = v;
      st.has_held = true;
      g_held_live++;
    }
    if (g_zero_copy) {
      // External pointer, resolved as-is by take_plan - the same door
      // an mmap'd asset walks through in http1.cpp. Only legal because
      // the hold above pins the buffer for the whole in-flight window.
      plan.seg[plan.nseg++] = Plan::Seg{RSTRING_PTR(v), 0, blen};
    } else {
      // resource.cpp's run_body->assign(RSTRING_PTR(v), RSTRING_LEN(v)),
      // one hop later: the bytes land in the connection's own sink and
      // the String is garbage before a single byte is sent.
      const size_t boff = sink.size();
      sink.append(RSTRING_PTR(v), blen);
      // Offset, not pointer: append may reallocate, and take_plan is
      // the first moment the address is final.
      plan.seg[plan.nseg++] = Plan::Seg{nullptr, boff, blen};
    }
    plan.iov_len += blen;
    if (prof) {
      const int64_t now = mono_ns();
      g_move_ns += now - t_move;
      g_emit_ns += now - t_emit;
      g_n_emit++;
    }
    mrb_gc_arena_restore(mrb, ai);
  }
};

// --------------------------------------------------------------- client

// Plain blocking sockets - the client is not what is being measured.
// Several connections at once on purpose: a single lockstep connection
// gives the ring one SQE per enter, which is the blocking case wearing
// a costume. Concurrency is what makes submit_and_wait actually batch.
struct Client {
  std::string path;
  int nconns = 0;
  int64_t rounds = 0;
  int64_t warm = 0;
  int stop_fd = -1;
  int pin = -1;

  int64_t wall_ns = 0;
  bool ok = false;

  void run() {
    pin_to(pin);
    std::vector<int> fds(static_cast<size_t>(nconns), -1);
    struct sockaddr_un sa {};
    sa.sun_family = AF_UNIX;
    std::snprintf(sa.sun_path, sizeof sa.sun_path, "%s", path.c_str());
    for (int i = 0; i < nconns; i++) {
      int fd = -1;
      for (int tries = 0; tries < 2000; tries++) {
        fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) break;
        if (::connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof sa) == 0) break;
        ::close(fd);
        fd = -1;
        struct timespec ts {0, 1000000};
        ::nanosleep(&ts, nullptr);
      }
      if (fd < 0) {
        std::fprintf(stderr, "ring_body: connect(%s) failed: %s\n", path.c_str(),
                     std::strerror(errno));
        finish();
        return;
      }
      fds[static_cast<size_t>(i)] = fd;
    }

    const size_t want = g_header.size() + g_body;
    std::vector<char> buf(want);

    // The warm rounds are also the CHECK: a wrong external pointer in
    // variant (b) would still be the right LENGTH, so a benchmark that
    // only counted bytes would happily time garbage. Verified outside
    // the timed window so it costs the measurement nothing.
    for (int64_t r = 0; r < warm; r++) {
      if (!round(fds, buf, want, r == 0)) { finish(); return; }
    }

    g_phase.store(kMeasure, std::memory_order_relaxed);
    const int64_t t0 = mono_ns();
    for (int64_t r = 0; r < rounds; r++) {
      if (!round(fds, buf, want, false)) { finish(); return; }
    }
    wall_ns = mono_ns() - t0;
    g_phase.store(kDone, std::memory_order_relaxed);
    ok = true;

    for (int fd : fds) if (fd >= 0) ::close(fd);
    finish();
  }

  // One round: a request byte down every connection, then every
  // response drained in turn. The requests go out first so the reactor
  // has several connections' work to batch into one enter.
  bool round(std::vector<int>& fds, std::vector<char>& buf, size_t want, bool verify) {
    const char req = 'R';
    for (int fd : fds) {
      if (::send(fd, &req, 1, MSG_NOSIGNAL) != 1) {
        std::fprintf(stderr, "ring_body: request send failed: %s\n", std::strerror(errno));
        return false;
      }
    }
    for (int fd : fds) {
      size_t got = 0;
      while (got < want) {
        const ssize_t n = ::recv(fd, buf.data() + got, want - got, 0);
        if (n <= 0) {
          std::fprintf(stderr, "ring_body: short response (%zu/%zu): %s\n", got, want,
                       n < 0 ? std::strerror(errno) : "eof");
          return false;
        }
        got += static_cast<size_t>(n);
      }
      if (verify) {
        if (std::memcmp(buf.data(), g_header.data(), g_header.size()) != 0) {
          std::fprintf(stderr, "ring_body: response head mismatch\n");
          return false;
        }
        for (size_t i = g_header.size(); i < want; i++) {
          if (buf[i] != 'x') {
            std::fprintf(stderr, "ring_body: body byte %zu is 0x%02x, not 'x' - the "
                                 "external segment pointed at the wrong bytes\n",
                         i - g_header.size(), static_cast<unsigned>(buf[i]) & 0xffu);
            return false;
          }
        }
      }
    }
    return true;
  }

  void finish() {
    g_phase.store(kDone, std::memory_order_relaxed);
    const char b = 1;
    if (stop_fd >= 0) (void)!::write(stop_fd, &b, 1);
  }
};

void usage() {
  std::fprintf(stderr,
               "usage: ring_body --variant copy|zero --size BYTES [--requests N]\n"
               "                 [--conns N] [--warm N] [--sock PATH]\n"
               "                 [--pin-ring CPU] [--pin-client CPU]\n");
}

}  // namespace

int main(int argc, char** argv) {
  const char* variant = nullptr;
  int64_t requests = 0;
  int nconns = 8;
  int64_t warm_requests = 0;
  std::string sock;
  int pin_ring = -1;
  int pin_client = -1;
  int hold_opt = -1;

  for (int i = 1; i < argc; i++) {
    const auto val = [&](const char* what) -> const char* {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "ring_body: %s needs a value\n", what);
        std::exit(2);
      }
      return argv[++i];
    };
    if (std::strcmp(argv[i], "--variant") == 0) variant = val("--variant");
    else if (std::strcmp(argv[i], "--size") == 0) g_body = std::strtoull(val("--size"), nullptr, 10);
    else if (std::strcmp(argv[i], "--requests") == 0) requests = std::strtoll(val("--requests"), nullptr, 10);
    else if (std::strcmp(argv[i], "--conns") == 0) nconns = std::atoi(val("--conns"));
    else if (std::strcmp(argv[i], "--warm") == 0) warm_requests = std::strtoll(val("--warm"), nullptr, 10);
    else if (std::strcmp(argv[i], "--sock") == 0) sock = val("--sock");
    else if (std::strcmp(argv[i], "--profile") == 0) g_profile = true;
    else if (std::strcmp(argv[i], "--hold") == 0) hold_opt = std::atoi(val("--hold"));
    else if (std::strcmp(argv[i], "--pin-ring") == 0) pin_ring = std::atoi(val("--pin-ring"));
    else if (std::strcmp(argv[i], "--pin-client") == 0) pin_client = std::atoi(val("--pin-client"));
    else { usage(); return 2; }
  }
  if (variant == nullptr || g_body == 0) { usage(); return 2; }
  if (std::strcmp(variant, "zero") == 0) g_zero_copy = true;
  else if (std::strcmp(variant, "copy") != 0) { usage(); return 2; }
  // Default each variant to its real-world lifetime; --hold overrides it
  // only so the control cell (copy+hold) can be measured.
  g_hold = hold_opt < 0 ? g_zero_copy : hold_opt != 0;
  if (g_zero_copy && !g_hold) {
    std::fprintf(stderr, "ring_body: --variant zero --hold 0 hands the kernel a pointer "
                         "nothing roots; refusing to measure a use-after-free\n");
    return 2;
  }
  if (nconns < 1) nconns = 1;
  if (requests <= 0) requests = 2000;
  if (warm_requests <= 0) warm_requests = requests / 10 < 64 ? 64 : requests / 10;
  if (sock.empty()) {
    char p[128];
    std::snprintf(p, sizeof p, "/tmp/wm-ring-body-%d.sock", static_cast<int>(::getpid()));
    sock = p;
  }
  ::unlink(sock.c_str());

  const int64_t rounds = (requests + nconns - 1) / nconns;
  const int64_t warm_rounds = (warm_requests + nconns - 1) / nconns;
  const int64_t did = rounds * nconns;

  g_src.assign(g_body, 'x');
  g_header = make_header(g_body);

  mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "ring_body: mrb_open failed\n");
    return 1;
  }

  int stop_pipe[2] = {-1, -1};
  if (::pipe(stop_pipe) != 0) {
    std::fprintf(stderr, "ring_body: pipe: %s\n", std::strerror(errno));
    return 1;
  }

  int rc = 0;
  {
    pin_to(pin_ring);
    BodyApp app;
    webmachine::Ring<BodyApp> ring(app);
    webmachine::RingConfig cfg;
    cfg.listeners[0].unix_path = sock.c_str();
    cfg.nlisteners = 1;
    cfg.stop_fd = stop_pipe[0];
    // Generous, so a slow neighbour cannot reap a live connection
    // mid-measurement and turn a timeout into a "result".
    cfg.to_header = 600;
    cfg.to_send = 600;
    cfg.to_idle = 600;
    char err[256];
    if (!ring.init(cfg, err, sizeof err)) {
      std::fprintf(stderr, "ring_body: ring init: %s\n", err);
      mrb_close(mrb);
      return 1;
    }

    Client cl;
    cl.path = sock;
    cl.nconns = nconns;
    cl.rounds = rounds;
    cl.warm = warm_rounds;
    cl.stop_fd = stop_pipe[1];
    cl.pin = pin_client;
    std::thread th([&cl] { cl.run(); });

    ring.run();
    th.join();

    if (!cl.ok || cl.wall_ns <= 0) {
      std::fprintf(stderr, "ring_body: client did not complete\n");
      rc = 1;
    } else {
      const double reqs = static_cast<double>(did);
      const double wall_per = static_cast<double>(cl.wall_ns) / reqs;
      const double cpu_per = static_cast<double>(g_cpu_ns) / reqs;
      const double mbps = (static_cast<double>(g_body) * reqs) /
                          (static_cast<double>(cl.wall_ns) / 1e9) / (1024.0 * 1024.0);
      // One machine-readable line per process, for ring_body.sh to fold.
      const double per_step = g_steps_total > 0 ? reqs / static_cast<double>(g_steps_total) : 0.0;
      std::printf("RESULT variant=%s size=%zu conns=%d requests=%" PRId64
                  " wall_ns_per_req=%.1f ring_cpu_ns_per_req=%.1f body_MiBps=%.1f"
                  " ring_steps=%" PRId64 " reqs_per_enter=%.2f\n",
                  g_hold && !g_zero_copy ? "copyhold" : variant,
                  g_body, nconns, did, wall_per, cpu_per, mbps, g_steps_total,
                  per_step);
      if (g_profile && g_n_emit > 0) {
        const double e = static_cast<double>(g_n_emit);
        // emit_ns is the App's whole share; the rest of ring_cpu is the
        // reactor and the kernel.
        std::printf("PROFILE variant=%s size=%zu emits=%" PRId64
                    " emit_ns=%.0f str_new_ns=%.0f move_ns=%.0f release_ns=%.0f\n",
                    g_hold && !g_zero_copy ? "copyhold" : variant,
                    g_body, g_n_emit, g_emit_ns / e, g_str_ns / e,
                    g_move_ns / e, g_rel_ns / e);
      }
      std::fflush(stdout);
    }
  }

  // The Ring is gone, so every Conn has been destroyed and every
  // in-flight body released - including any that were still on the wire
  // when the run ended. Anything left here would be a leak, not a
  // rounding error, so it is loud and it fails the run.
  if (g_held_live != 0) {
    std::fprintf(stderr, "ring_body: %" PRId64 " registration(s) outstanding after teardown "
                         "- the release path leaks\n", g_held_live);
    rc = 1;
  }
  ::close(stop_pipe[0]);
  ::close(stop_pipe[1]);
  mrb_close(mrb);
  ::unlink(sock.c_str());
  return rc;
}
