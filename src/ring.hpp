// The reactor: one thread, one io_uring, and every piece of state hung
// off one instance - no globals, so N instances could exist someday,
// though no line here knows about threads.
//
// The Ring knows NOTHING but bytes: bytes arrive, it hands them to its
// App; whatever the App appends to the sink goes back out. HTTP, Ruby,
// echo - all of that lives in an App type, bound at compile time
// (template, zero indirection, no std::function, no virtual).
//
// An App provides:
//   struct Conn { void reset(uint8_t listener); };    per-connection state
//                 (reset carries which listener accepted - the App's
//                  key to "whose connection is this")
//   bool feed(Conn&, const char*, size_t, std::string& sink);
//        false = close this connection once the sink has drained
//   void on_tick();                                   once per reactor wake
//
// EVERYTHING goes through the ring. The listener is born as a direct
// descriptor (io_uring_prep_socket_direct), bound and set listening by
// ring ops (IORING_OP_BIND/LISTEN, kernel 6.11+ - probed at init, named
// error if absent, no POSIX fallback: one implementation, one path).
// The only classic syscall left is mmap, which is memory, not IO.
#ifndef WEBMACHINE_RING_HPP
#define WEBMACHINE_RING_HPP

#include <arpa/inet.h>
#include <liburing.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// Prediction hints ONLY where the taken side is terminal - an exit, a
// raise, a connection's death, an invariant violation. A branch that
// swings naturally at runtime (workload-dependent) carries NO hint: a
// static hint on a swinging branch is a systematic mispredict.
#define WM_LIKELY(x) __builtin_expect(!!(x), 1)
#define WM_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace webmachine {

// Slot count == the sparse direct-descriptor table size: a connection's
// id IS its direct descriptor index, so lookup is an array index. The
// listeners live in the slots behind the connections: listener i sits
// at kListenerBase + i ("more than one app per thread" = more than one
// listener on the one ring).
inline constexpr uint32_t kMaxConns = 4096;
inline constexpr uint32_t kListenerBase = kMaxConns;
inline constexpr uint32_t kMaxListeners = 16;
// Pool geometry measured in the old tree as not moving the profile
// (2048 x 4096 vs ladders: null result), so the simple shape stays.
inline constexpr uint32_t kBufCount = 2048;
inline constexpr uint32_t kBufSize = 4096;
inline constexpr uint16_t kBufGroup = 0;
static_assert((kBufCount & (kBufCount - 1)) == 0, "buffer walk wraps by mask");
static_assert(static_cast<size_t>(kBufCount) <= SIZE_MAX / kBufSize,
              "pool size arithmetic must not overflow");

// One listener: exactly one of unix_path / port.
struct ListenerSpec {
  const char* unix_path = nullptr;
  int port = 0;
};

struct RingConfig {
  ListenerSpec listeners[kMaxListeners] = {};
  uint32_t nlisteners = 0;
  // A signalfd main owns (signals blocked, so they land there). The
  // ring polls it: the stop signal arrives as a CQE like everything
  // else - a handler flag would race the wait (checked, then the signal
  // lands, then the wait blocks forever with the flag set).
  int stop_fd = -1;
};

namespace detail {

// user_data: kind(8) | gen(16) | idx(32). gen guards a reused slot
// against CQEs of the connection that owned it before.
enum : uint8_t {
  kAccept = 1, kRecv = 2, kSend = 3, kClose = 4, kSetup = 5, kStop = 6, kShutdown = 7
};

inline uint64_t tag(uint8_t kind, uint16_t gen, uint32_t idx) {
  return (static_cast<uint64_t>(kind) << 56) | (static_cast<uint64_t>(gen) << 32) | idx;
}

// The setup chain's stages, carried in the idx half of the tag so a
// failing CQE can name what failed.
enum : uint32_t { kStSocket = 1, kStSockopt = 2, kStBind = 3, kStListen = 4 };

inline const char* stage_name(uint32_t st) {
  switch (st) {
    case kStSocket: return "socket";
    case kStSockopt: return "setsockopt";
    case kStBind: return "bind";
    case kStListen: return "listen";
  }
  return "?";
}

}  // namespace detail

template <class App>
class Ring {
 public:
  explicit Ring(App& app) : app_(app) {}
  Ring(const Ring&) = delete;
  Ring& operator=(const Ring&) = delete;

  ~Ring() {
    if (ring_up_) {
      // The listeners leave through the ring like everything else did,
      // and a unix listener takes its path with it - waited on, because
      // queue_exit would race the unlink.
      unsigned n = 0;
      for (uint32_t i = 0; i < nlisteners_; i++) {
        struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
        if (s == nullptr) break;
        io_uring_prep_close_direct(s, kListenerBase + i);
        io_uring_sqe_set_data64(s, detail::tag(detail::kClose, 0, kListenerBase + i));
        n++;
      }
      for (const std::string& path : unix_paths_) {
        struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
        if (s == nullptr) break;
        io_uring_prep_unlink(s, path.c_str(), 0);
        io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, 0));
        n++;
      }
      if (n != 0) io_uring_submit_and_wait(&ring_, n);
    }
    if (buf_ring_ != nullptr) io_uring_free_buf_ring(&ring_, buf_ring_, kBufCount, kBufGroup);
    if (pool_ != nullptr) ::munmap(pool_, static_cast<size_t>(kBufCount) * kBufSize);
    if (ring_up_) io_uring_queue_exit(&ring_);
  }

  // False leaves the reason - naming the failed setup stage - in err.
  // Reads WM_BUNDLE, the one env knob left and only ever narrowing:
  // recv bundles default to the kernel's feature bit, and one
  // known-broken kernel (container 6.18.5-fc) violates the dense-fill
  // contract and needs WM_BUNDLE=0. It earns its place by answering a
  // correctness question no build-time check can.
  bool init(const RingConfig& cfg, char* err, size_t errlen) {
    struct io_uring_params p {};
    p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
    int rc = io_uring_queue_init_params(1024, &ring_, &p);
    if (rc != 0) {
      std::snprintf(err, errlen, "io_uring_queue_init: %s", std::strerror(-rc));
      return false;
    }
    ring_up_ = true;
    // One fewer fd-table lookup per enter(2); nothing else shares this fd.
    io_uring_register_ring_fd(&ring_);

    // IORING_OP_BIND/LISTEN are 6.11; the setup below has exactly one
    // path, so their absence is a named refusal, not a fallback.
    {
      struct io_uring_probe* probe = io_uring_get_probe_ring(&ring_);
      const bool ok = probe != nullptr && io_uring_opcode_supported(probe, IORING_OP_BIND) &&
                      io_uring_opcode_supported(probe, IORING_OP_LISTEN);
      if (probe != nullptr) io_uring_free_probe(probe);
      if (!ok) {
        std::snprintf(err, errlen, "kernel lacks IORING_OP_BIND/LISTEN (needs 6.11+)");
        return false;
      }
    }

    rc = io_uring_register_files_sparse(&ring_, kMaxConns + kMaxListeners);  // + listener slots
    if (rc != 0) {
      std::snprintf(err, errlen, "register_files_sparse: %s", std::strerror(-rc));
      return false;
    }
    // The direct-descriptor allocator's cursor continues past the last
    // slot it touched - after the listeners land at kListenerBase+ the
    // next accept would be handed a LISTENER slot (measured: res=4097).
    // Confine allocation to the connection slots; listeners are placed,
    // never allocated.
    rc = io_uring_register_file_alloc_range(&ring_, 0, kMaxConns);
    if (rc != 0) {
      std::snprintf(err, errlen, "register_file_alloc_range: %s", std::strerror(-rc));
      return false;
    }

    const size_t pool_bytes = static_cast<size_t>(kBufCount) * kBufSize;  // static_assert-bounded
    void* mem =
        ::mmap(nullptr, pool_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
      std::snprintf(err, errlen, "mmap pool: %s", std::strerror(errno));
      return false;
    }
    pool_ = static_cast<char*>(mem);

    int bre = 0;
    buf_ring_ = io_uring_setup_buf_ring(&ring_, kBufCount, kBufGroup, 0, &bre);
    if (buf_ring_ == nullptr) {
      std::snprintf(err, errlen, "setup_buf_ring: %s", std::strerror(-bre));
      return false;
    }
    // Written once. Replenish is advance-only: the kernel consumes entries
    // strictly in ring order, so re-exposing a slot re-exposes the buffer
    // it has always named.
    const int mask = io_uring_buf_ring_mask(kBufCount);
    for (uint32_t i = 0; i < kBufCount; i++) {
      io_uring_buf_ring_add(buf_ring_, pool_ + static_cast<size_t>(i) * kBufSize, kBufSize,
                            static_cast<uint16_t>(i), mask, static_cast<int>(i));
    }
    io_uring_buf_ring_advance(buf_ring_, kBufCount);

    // Default: the kernel's own feature bit. WM_BUNDLE=0 narrows, for the
    // one kernel caught violating the dense-fill contract (6.18.5-fc:
    // res spanned buffers each holding only its own small segment).
    bundles_ = (ring_.features & IORING_FEAT_RECVSEND_BUNDLE) != 0;
    if (const char* e = std::getenv("WM_BUNDLE")) {
      if (e[0] == '0') bundles_ = false;
    }

    if (cfg.nlisteners == 0 || cfg.nlisteners > kMaxListeners) {
      std::snprintf(err, errlen, "listener count %u out of range (1..%u)", cfg.nlisteners,
                    kMaxListeners);
      return false;
    }
    for (uint32_t li = 0; li < cfg.nlisteners; li++) {
      if (!setup_listener(li, cfg.listeners[li], err, errlen)) return false;
    }
    nlisteners_ = cfg.nlisteners;

    conns_.resize(kMaxConns);
    rearm_.reserve(64);

    if (cfg.stop_fd >= 0) {
      struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
      if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
      io_uring_prep_poll_add(s, cfg.stop_fd, POLLIN);
      io_uring_sqe_set_data64(s, detail::tag(detail::kStop, 0, 0));
    }

    for (uint32_t li = 0; li < nlisteners_; li++) arm_accept(li);
    return true;
  }

  // Loops until the stop_fd CQE lands, then returns so the destructor
  // runs: that is what removes the unix socket path again.
  void run() {
    while (!stop_) tick();
  }

 private:
  // One listener, made entirely of ring ops: a stale unix path goes
  // first and UNLINKED from the chain (a linked op that fails - ENOENT
  // is normal - would cancel everything behind it), then socket ->
  // (setsockopt) -> bind -> listen as one linked chain, one submit,
  // every CQE checked, a failure naming its stage.
  bool setup_listener(uint32_t li, const ListenerSpec& spec, char* err, size_t errlen) {
    const uint32_t slot = kListenerBase + li;
    const bool is_unix = spec.unix_path != nullptr;
    struct sockaddr_un sun {};
    struct sockaddr_in sin {};
    struct sockaddr* sa = nullptr;
    socklen_t salen = 0;
    if (is_unix) {
      sun.sun_family = AF_UNIX;
      const size_t plen = std::strlen(spec.unix_path);
      if (plen >= sizeof(sun.sun_path)) {
        std::snprintf(err, errlen, "listener %u: unix path too long (%zu)", li, plen);
        return false;
      }
      std::memcpy(sun.sun_path, spec.unix_path, plen + 1);
      sa = reinterpret_cast<struct sockaddr*>(&sun);
      salen = sizeof(sun);

      struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
      if (s == nullptr) {
        std::snprintf(err, errlen, "SQ empty at setup");
        return false;
      }
      io_uring_prep_unlink(s, spec.unix_path, 0);
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, 0));
      io_uring_submit_and_wait(&ring_, 1);
      struct io_uring_cqe* cqe = nullptr;
      if (io_uring_peek_cqe(&ring_, &cqe) == 0) {
        // Only ENOENT is ordinary; anything else on the path is a refusal.
        if (cqe->res < 0 && cqe->res != -ENOENT) {
          std::snprintf(err, errlen, "unlink %s: %s", spec.unix_path, std::strerror(-cqe->res));
          return false;
        }
        io_uring_cqe_seen(&ring_, cqe);
      }
    } else {
      if (spec.port <= 0 || spec.port > 65535) {
        std::snprintf(err, errlen, "listener %u: port %d out of range", li, spec.port);
        return false;
      }
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = htonl(INADDR_ANY);
      sin.sin_port = htons(static_cast<uint16_t>(spec.port));
      sa = reinterpret_cast<struct sockaddr*>(&sin);
      salen = sizeof(sin);
    }

    // The addresses live on this frame; init blocks until the chain's
    // CQEs, so the borrow ends before the frame does.
    static const int kOne = 1;  // static: SO_REUSEADDR optval, borrowed by the ring op
    unsigned chain = 0;
    {
      struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
      if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
      io_uring_prep_socket_direct(s, is_unix ? AF_UNIX : AF_INET, SOCK_STREAM, 0, slot, 0);
      s->flags |= IOSQE_IO_LINK;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStSocket));
      chain++;

      if (!is_unix) {
        s = io_uring_get_sqe(&ring_);
        if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
        io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, slot, SOL_SOCKET, SO_REUSEADDR,
                               const_cast<int*>(&kOne), sizeof(kOne));
        s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
        io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStSockopt));
        chain++;
      }

      s = io_uring_get_sqe(&ring_);
      if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
      io_uring_prep_bind(s, slot, sa, salen);
      s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStBind));
      chain++;

      s = io_uring_get_sqe(&ring_);
      if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
      io_uring_prep_listen(s, slot, 511);
      s->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, 0, detail::kStListen));
      chain++;
    }
    io_uring_submit_and_wait(&ring_, chain);
    {
      bool failed = false;
      struct io_uring_cqe* cqe = nullptr;
      unsigned head = 0;
      unsigned seen = 0;
      io_uring_for_each_cqe(&ring_, head, cqe) {
        seen++;
        if (cqe->res < 0 && !failed) {
          // -ECANCELED names the victim of an earlier failure, not a cause.
          if (cqe->res != -ECANCELED) {
            const uint32_t st = static_cast<uint32_t>(io_uring_cqe_get_data64(cqe));
            std::snprintf(err, errlen, "listener %u %s: %s", li, detail::stage_name(st),
                          std::strerror(-cqe->res));
            failed = true;
          } else if (err[0] == '\0') {
            std::snprintf(err, errlen, "listener %u: setup chain canceled", li);
            failed = true;
          }
        }
      }
      io_uring_cq_advance(&ring_, seen);
      if (failed) return false;
    }
    // Only a bind that happened leaves a path to remove again.
    if (is_unix) unix_paths_.emplace_back(spec.unix_path);
    return true;
  }

  struct Conn {
    // Read on every event before anything else.
    bool live = false;
    bool sending = false;          // `out` is borrowed by the kernel
    bool close_after_send = false;
    uint16_t gen = 0;  // stale-CQE guard: slot reuse bumps it, old ops miss
    size_t sent = 0;   // bytes of `out` the kernel has taken so far

    // Two buffers, not one: `out` is BORROWED by an in-flight send (its
    // pointer is in the SQE), so nothing may append to or clear it until
    // the send's CQE - appends land in `next`, the swap happens when the
    // send drains. Capacity survives clear(); a warm slot allocates
    // nothing.
    std::string out;
    std::string next;

    // The App's per-connection state; the Ring only resets it.
    typename App::Conn app;
  };

  // Never returns null: a full SQ is submitted and retried once, and a
  // ring that cannot take an SQE after that is a broken ring - checked,
  // reported on stderr, process exits (there is no connection to blame).
  struct io_uring_sqe* sqe() {
    struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
    if (WM_LIKELY(s != nullptr)) return s;
    io_uring_submit(&ring_);
    s = io_uring_get_sqe(&ring_);
    if (WM_UNLIKELY(s == nullptr)) {
      std::fprintf(stderr, "webmachine: SQ stuck after submit; ring is broken\n");
      std::exit(1);
    }
    return s;
  }

  void arm_accept(uint32_t li) {
    struct io_uring_sqe* s = sqe();
    io_uring_prep_multishot_accept_direct(s, kListenerBase + li, nullptr, nullptr, 0);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kAccept, 0, li));
  }

  void arm_recv(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    io_uring_prep_recv_multishot(s, static_cast<int>(idx), nullptr, 0, 0);
    s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
    s->buf_group = kBufGroup;
    if (bundles_) s->ioprio |= IORING_RECVSEND_BUNDLE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kRecv, c.gen, idx));
  }

  void arm_send(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    io_uring_prep_send(s, static_cast<int>(idx), c.out.data() + c.sent, c.out.size() - c.sent,
                       MSG_NOSIGNAL);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kSend, c.gen, idx));
    c.sending = true;
  }

  void begin_close(uint32_t idx) {
    Conn& c = conns_[idx];
    if (!c.live) return;
    // An in-flight send borrows c.out; the slot may not be reset (and the
    // descriptor not closed) until its CQE lands - on_send finishes the
    // close then.
    if (c.sending) {
      c.close_after_send = true;
      return;
    }
    c.live = false;
    // The armed multishot recv holds a file reference: close_direct alone
    // only clears the table slot, the socket stays open and the peer
    // never sees FIN (three bintests hung exactly there). shutdown forces
    // the FIN out first; the link keeps the order. Both SQEs must ride
    // the same submission or the link breaks.
    if (io_uring_sq_space_left(&ring_) < 2) io_uring_submit(&ring_);
    struct io_uring_sqe* s = sqe();
    io_uring_prep_shutdown(s, static_cast<int>(idx), SHUT_RDWR);
    s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, detail::tag(detail::kShutdown, c.gen, idx));
    s = sqe();
    io_uring_prep_close_direct(s, idx);
    io_uring_sqe_set_data64(s, detail::tag(detail::kClose, c.gen, idx));
  }

  void on_accept(uint32_t li, struct io_uring_cqe* cqe) {
    if (!(cqe->flags & IORING_CQE_F_MORE)) arm_accept(li);
    if (cqe->res < 0) return;  // transient (EMFILE and friends); multishot may carry on
    const uint32_t idx = static_cast<uint32_t>(cqe->res);
    if (WM_UNLIKELY(idx >= kMaxConns)) return;  // the kernel named a slot we never registered
    Conn& c = conns_[idx];
    c.gen++;
    c.live = true;
    c.sending = false;
    c.close_after_send = false;
    c.sent = 0;
    c.out.clear();  // capacity survives: a warm slot allocates nothing
    c.next.clear();
    c.app.reset(static_cast<uint8_t>(li));  // whose listener, whose app
    arm_recv(idx);
  }

  void on_recv(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= kMaxConns)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen) return;  // a previous tenant's completion

    if (WM_UNLIKELY(cqe->res <= 0)) {
      if (cqe->res == -ENOBUFS) {
        // Reachable by arithmetic: kMaxConns (4096) > kBufCount (2048),
        // and every completion consumes at least one whole buffer no
        // matter how few bytes it carries. Under DEFER_TASKRUN all
        // completions of a wait window are produced before userspace runs
        // again, and buffers only return at the NEXT tick's advance - so
        // >2048 readable connections in one window (or one bundle burst
        // past 8 MiB) drain the pool and the rest post ENOBUFS. Without
        // this re-arm their multishot is dead and the connection hangs.
        rearm_.push_back(idx);
        return;
      }
      // 0 = EOF; everything else ends the connection the same way.
      begin_close(idx);
      return;
    }

    if (WM_UNLIKELY(!(cqe->flags & IORING_CQE_F_BUFFER))) {
      begin_close(idx);
      return;
    }
    const uint32_t bid0 = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    const size_t total = static_cast<size_t>(cqe->res);
    // Kernel-supplied values, checked before use: an id or length past the
    // pool would hand out someone else's memory.
    if (WM_UNLIKELY(bid0 >= kBufCount || total > static_cast<size_t>(kBufCount) * kBufSize)) {
      begin_close(idx);
      return;
    }

    // A connection already condemned (close_after_send) reads nothing
    // more; its buffers still go back to the pool.
    if (WM_UNLIKELY(c.close_after_send)) {
      replenish_ += static_cast<unsigned>((total + kBufSize - 1) / kBufSize);
      return;
    }

    // Walk the bundle: consecutive ids from bid0, every buffer full
    // except the last (dense-fill contract, io_uring_prep_recv(3)).
    std::string& sink = c.sending ? c.next : c.out;
    bool closing = false;
    size_t left = total;
    uint32_t bid = bid0;
    while (left > 0) {
      const size_t n = left < kBufSize ? left : kBufSize;
      size_t off = 0;
      if (WM_UNLIKELY(__builtin_mul_overflow(static_cast<size_t>(bid),
                                             static_cast<size_t>(kBufSize), &off))) {
        begin_close(idx);
        return;
      }
      if (!closing) closing = !app_.feed(c.app, pool_ + off, n, sink);
      left -= n;
      bid = (bid + 1) & (kBufCount - 1);
      replenish_++;
    }

    if (!c.sending && !c.out.empty()) arm_send(idx);
    if (WM_UNLIKELY(closing)) {
      // Everything queued still drains; on_send finishes the close.
      if (c.sending) c.close_after_send = true;
      else begin_close(idx);
      return;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) rearm_.push_back(idx);
  }

  void on_send(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= kMaxConns)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    c.sending = false;

    if (WM_UNLIKELY(cqe->res < 0)) {
      begin_close(idx);
      return;
    }
    const size_t took = static_cast<size_t>(cqe->res);
    size_t new_sent = 0;
    // The kernel cannot have taken more than it was offered, and the sum
    // must not wrap - both are one check each, before anything uses them.
    if (WM_UNLIKELY(took > c.out.size() - c.sent ||
                    __builtin_add_overflow(c.sent, took, &new_sent))) {
      begin_close(idx);
      return;
    }
    c.sent = new_sent;
    if (c.sent < c.out.size()) {
      arm_send(idx);
      return;
    }
    c.out.clear();
    c.sent = 0;
    // next drains BEFORE a pending close: an error response queued behind
    // an in-flight send must still reach the wire (RFC 9112 §9.6).
    if (!c.next.empty()) {
      c.out.swap(c.next);
      arm_send(idx);
      return;
    }
    if (c.close_after_send) {
      c.close_after_send = false;
      begin_close(idx);
    }
  }

  void handle(struct io_uring_cqe* cqe) {
    const uint64_t ud = io_uring_cqe_get_data64(cqe);
    const uint8_t kind = static_cast<uint8_t>(ud >> 56);
    const uint16_t gen = static_cast<uint16_t>(ud >> 32);
    const uint32_t idx = static_cast<uint32_t>(ud);
    switch (kind) {
      case detail::kAccept: on_accept(idx, cqe); break;
      case detail::kRecv: on_recv(idx, gen, cqe); break;
      case detail::kSend: on_send(idx, gen, cqe); break;
      case detail::kClose:
        if (WM_UNLIKELY(cqe->res == -ECANCELED)) {
          // The linked shutdown failed (peer reset first); the close is
          // still owed or the direct slot leaks.
          struct io_uring_sqe* s = sqe();
          io_uring_prep_close_direct(s, idx);
          io_uring_sqe_set_data64(s, detail::tag(detail::kClose, gen, idx));
        }
        break;
      case detail::kShutdown: break;  // best effort; the linked close is the contract
      case detail::kStop: stop_ = true; break;
      default: break;
    }
  }

  void tick() {
    if (replenish_ != 0) {
      io_uring_buf_ring_advance(buf_ring_, static_cast<int>(replenish_));
      replenish_ = 0;
    }
    io_uring_submit_and_wait(&ring_, 1);
    // Once per wake, never per request; the Ring does not know or care
    // what the App keeps fresh.
    app_.on_tick();
    struct io_uring_cqe* cqe = nullptr;
    unsigned head = 0;
    unsigned seen = 0;
    io_uring_for_each_cqe(&ring_, head, cqe) {
      seen++;
      handle(cqe);
    }
    if (seen != 0) io_uring_cq_advance(&ring_, seen);
    if (!rearm_.empty()) {
      for (uint32_t idx : rearm_) {
        Conn& c = conns_[idx];
        // A condemned connection gets no new read; its close is in flight.
        if (c.live && !c.close_after_send) arm_recv(idx);
      }
      rearm_.clear();
    }
  }

  App& app_;
  struct io_uring ring_ {};
  bool ring_up_ = false;
  bool stop_ = false;
  bool bundles_ = false;
  std::vector<std::string> unix_paths_;  // owned copies: the destructor unlinks them
  uint32_t nlisteners_ = 0;
  char* pool_ = nullptr;   // kBufCount * kBufSize, mmap'd once
  struct io_uring_buf_ring* buf_ring_ = nullptr;
  // Buffers consumed this tick, handed back (advance-only: the ring
  // entries were written once and consumption strictly rotates) at the
  // top of the NEXT tick - a Read's bytes stay valid until then.
  unsigned replenish_ = 0;
  std::vector<Conn> conns_;
  // Connections whose multishot recv ended this tick and must be
  // re-armed after the batch (their prep would race the buffer advance).
  std::vector<uint32_t> rearm_;
};

}  // namespace webmachine

#endif
