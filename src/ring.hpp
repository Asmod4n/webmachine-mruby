// The reactor: one thread, one io backend (#171: io_uring, or the
// select shim where io_uring cannot be had), every piece of state hung
// off one instance - no globals, so N instances could exist someday,
// though no line here knows about threads.
//
// The Ring knows NOTHING but bytes: bytes arrive, it hands them to its
// App; whatever the App appends to the sink goes back out. HTTP, Ruby,
// echo - all of that lives in an App type, bound at compile time
// (template, zero indirection, no std::function, no virtual).
//
// An App provides:
//   struct Conn { void reset(uint8_t listener, bool packetized); };
//                 per-connection state (reset carries which listener
//                 accepted - the App's key to "whose connection is
//                 this" - and whether that listener is TCP, #147: a
//                 unix listener sits behind a proxy and is never
//                 packetized on this hop)
//   bool feed(Conn&, const char*, size_t, std::string& sink, Plan*);
//        false = close this connection once the sink has drained. The
//        Plan is nullable: the Ring passes one only when it could arm
//        it in this very round (no send in flight, last segment of a
//        recv bundle) - then feed may hand bytes over as segments the
//        same way more() does, and they leave WITH the sink in one
//        sendmsg. A null plan asks for the classic copy/park shape.
//   bool pending(const Conn&) const;
//        does this connection still owe bytes the App has not handed
//        over? Asked before each send: true makes it carry MSG_MORE,
//        so a small head does not go out alone and wait out the peer's
//        delayed ACK.
//   struct Plan { struct Seg { const char* base; size_t off, len; };
//                 static constexpr unsigned kSegs; Seg seg[kSegs];
//                 unsigned nseg; size_t iov_len; };
//   bool more(Conn&, std::string& sink, Plan&);
//        the delivery continuation (#168): called when the sink has
//        fully drained. The App either appends to the sink, or fills
//        the Plan with SEGMENTS - `base` names bytes that already
//        exist somewhere durable (a mapping, a table built at
//        add_route), a null `base` names a RANGE OF THE SINK at `off`,
//        for a round that has to spell some bytes itself and interleave
//        them with the pointed-at ones (h2's DATA frame headers). An
//        offset, not a pointer, because the sink is still being
//        appended to while the plan is built. The whole round leaves in
//        ONE sendmsg, without a body byte passing through this process.
//        Same close contract as feed. An App without sources appends
//        nothing and returns true.
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
#include <fcntl.h>

#include <liburing.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
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
// at listener_base_ + i ("more than one app per thread" = more than one
// listener on the one ring).
//
// The COUNT is derived, never guessed (#169): the backend owns
// RLIMIT_NOFILE - it raises soft to hard at init (unprivileged, allowed
// for every process; systemd default is soft 1024 / hard 524288, the
// ceiling for the raise is /proc/sys/fs/nr_open) and takes everything
// the final limit allows, minus a reserve. The kernel checks the sparse
// table size against RLIMIT_NOFILE (measured: limit 1024 -> 1023 slots
// ok, 4096 EMFILE), which is why the raise must come first.
inline constexpr uint32_t kMaxListeners = 16;
// Classic fds the process keeps NEXT TO the fixed table: stdio, the
// ring fd, the stop signalfd, the asset ZIP (#170), and foreign
// in-process code (mruby-c-ares sockets). Connections consume NO fd
// numbers here - multishot_accept_direct lands them in the fixed table
// only - so this is headroom, not arithmetic necessity; under a shim
// backend (#171), where connections ARE process fds, the SAME formula
// holds and the reserve becomes load-bearing. One arithmetic, every
// backend: max_conns = final_limit - kFdReserve - kMaxListeners.
inline constexpr uint32_t kFdReserve = 128;
// The kernel's own cap on a fixed-file table (io_uring/rsrc.c,
// IORING_MAX_FIXED_FILES) - a limit above it must not size the table.
inline constexpr uint32_t kFixedTableKernelMax = 1u << 20;

// The one arithmetic with two consumers: the server sizes itself with
// it here; tools/webmachine-tune.sh (#167) only PRINTS it. extra_slots
// = fixed-table slots something other than connections and listeners
// claims; nothing does today. 0 = the limit leaves no room, a named
// refusal for the caller to spell out.
// The OTHER limit a ring is charged against: its SQ/CQ pages are
// locked memory, accounted per USER. Soft to hard, once, before the
// ring exists - #169's shape for RLIMIT_NOFILE applied here. Failure
// is deliberately silent: not being allowed to raise it is no reason
// not to start, it only means the ring below settles smaller.
inline void raise_memlock() {
  struct rlimit rl {};
  if (::getrlimit(RLIMIT_MEMLOCK, &rl) != 0) return;
  if (rl.rlim_cur == rl.rlim_max) return;
  struct rlimit want {rl.rlim_max, rl.rlim_max};
  (void)::setrlimit(RLIMIT_MEMLOCK, &want);
}

inline uint32_t derive_max_conns(uint64_t nofile_limit, uint32_t extra_slots = 0) {
  const uint64_t taken = static_cast<uint64_t>(kFdReserve) + kMaxListeners + extra_slots;
  if (nofile_limit <= taken) return 0;
  uint64_t n = nofile_limit - taken;
  if (n + kMaxListeners + extra_slots > kFixedTableKernelMax) {
    n = kFixedTableKernelMax - kMaxListeners - extra_slots;
  }
  return static_cast<uint32_t>(n);
}

// NEVER PIN THIS PROCESS. It was measured twice and lost twice - the
// older tree deleted every taskset it had ("handing the scheduler one
// core was slower than letting it choose"; a client mask widened
// 2 -> 15 -> 30 cpus raised throughput monotonically in the MEDIAN).
// And whenever io_uring hands work to an io-wq worker, that worker
// INHERITS the issuing thread's affinity: pinning locks the pool that
// exists to use OTHER cores onto the core the loop already occupies.
// Measured here at its worst, back when file bodies went through
// splice: 0.07x under `taskset -c 0`, the system at 49.3% sy against
// 10.3% us.
//
// Pool geometry measured in the old tree as not moving the profile
// (2048 x 4096 vs ladders: null result), so the simple shape stays.
inline constexpr uint32_t kBufCount = 2048;
inline constexpr uint32_t kBufSize = 4096;
inline constexpr uint16_t kBufGroup = 0;
static_assert((kBufCount & (kBufCount - 1)) == 0, "buffer walk wraps by mask");
static_assert(static_cast<size_t>(kBufCount) <= SIZE_MAX / kBufSize,
              "pool size arithmetic must not overflow");

// #169's raise: soft to hard, ceiling fs.nr_open - done ONCE at init,
// and the capacity falls out of whatever finally stands.
//
// Which of the two paths below runs is decided by a PROPERTY the
// liburing.h on this include path states, never by which
// implementation it is (#171). IO_URING_FD_CEILING means "every
// descriptor handed to these functions must stay strictly below this
// number"; its ABSENCE means the API imposes no ceiling and the
// process rlimits are the only bound. Asking WHO answered instead
// would hand select's FD_SETSIZE to every implementation that comes
// later - an IOCP build has no fd_set at all - so this file never
// learns a name.
inline uint64_t raise_nofile() {
  struct rlimit rl {};
  if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
#ifdef IO_URING_FD_CEILING
  // The API states a ceiling, so descriptors are what it counts: here a
  // connection IS a process fd, and the rlimit is the only thing that
  // keeps fd numbers under that roof - for this process AND for every
  // neighbour holding an fd_set, mruby-c-ares being the concrete one.
  // The soft limit is moved TO that roof - down where it stood higher,
  // up where it stood lower - so the two agree, once, at init.
  rlim_t target = static_cast<rlim_t>(IO_URING_FD_CEILING - 1);
  if (target > rl.rlim_max) target = rl.rlim_max;
  if (rl.rlim_cur != target) {
    struct rlimit want {target, rl.rlim_max};
    (void)::setrlimit(RLIMIT_NOFILE, &want);
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
  }
  const uint64_t cur = static_cast<uint64_t>(rl.rlim_cur);
  return cur < IO_URING_FD_CEILING ? cur : IO_URING_FD_CEILING - 1;
#else
  // No ceiling stated: nothing but the rlimits bounds this. With the
  // real ring, connections live in the fixed-file table and consume no
  // fd numbers, so take everything the hard limit allows, ceiling
  // fs.nr_open. #169 measured why a cap would only cost here.
  rlim_t target = rl.rlim_max;
  if (target == RLIM_INFINITY) {
    uint64_t nr_open = 1u << 20;  // kernel default; used only if /proc is unreadable
    if (std::FILE* f = std::fopen("/proc/sys/fs/nr_open", "re")) {
      unsigned long long v = 0;
      if (std::fscanf(f, "%llu", &v) == 1 && v > 0) nr_open = v;
      std::fclose(f);
    }
    target = static_cast<rlim_t>(nr_open);
  }
  if (rl.rlim_cur < target) {
    struct rlimit want {target, rl.rlim_max};
    (void)::setrlimit(RLIMIT_NOFILE, &want);
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
  }
  return static_cast<uint64_t>(rl.rlim_cur);
#endif
}

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

// Io picks the backend (#171): UringIo by default, SelectIo as the
// portable/lazy path - two instantiations, zero indirection in
// either, the one branch point living in main at init.
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
      close_listeners();
      unsigned n = 0;
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
  // EVERY failure here is this machine refusing this configuration - a
  // taken port, an fd limit that leaves no room. Which io_uring answers
  // these calls was settled at BUILD time (src/uring.hpp), so nothing
  // in here is a reason to go looking for another one: a bind clash
  // that silently demoted the server to a slower path would be a
  // performance cliff wearing a startup message.
  bool init(const RingConfig& cfg, char* err, size_t errlen) {
    int rc = 0;
    // The SQ is a SHARED, fixed resource - every in-flight operation of
    // every connection sits in it, and one response can claim many
    // (a body split into frames is one SQE per segment). 32768 is the
    // kernel's own ceiling, IORING_MAX_ENTRIES; the SQ array costs
    // 64 bytes an entry and the CQ 16 at twice the count, so the full
    // ask is ~3 MiB once per process.
    //
    // A machine that will not give that gets less, not a refusal: a
    // smaller ring is smaller HEADROOM, not a wrong ring, and the same
    // rule already governs max_conns_ ("the capacity falls out of
    // whatever finally stands", #169). Halve until one takes; the
    // floor is what stood here before this loop existed, so this can
    // only ever end at least as well as it used to.
    raise_memlock();
    constexpr unsigned kSqWanted = 32768;
    constexpr unsigned kSqFloor = 1024;
    constexpr unsigned kSetupFlags =
        IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
    struct io_uring_params p {};
    for (sq_entries_ = kSqWanted;; sq_entries_ /= 2) {
      // queue_init_params WRITES its result into p (sq/cq entries,
      // features), so a retry starts from a clean one.
      p = io_uring_params{};
      p.flags = kSetupFlags;
      rc = io_uring_queue_init_params(sq_entries_, &ring_, &p);
      if (rc == 0) {
        sq_entries_ = p.sq_entries;  // what the KERNEL gave, not what was asked
        break;
      }
      if (sq_entries_ <= kSqFloor) {
        std::snprintf(err, errlen, "io_uring_queue_init(%u): %s", sq_entries_,
                      std::strerror(-rc));
        return false;
      }
    }
    // One fewer fd-table lookup per enter(2); nothing else shares this fd.
    io_uring_register_ring_fd(&ring_);
    ring_up_ = true;

    // The limit is set ONCE, here, and never touched again. The
    // capacity falls out of whatever finally stands.
    const uint64_t nofile = raise_nofile();
    max_conns_ = derive_max_conns(nofile);
    if (max_conns_ == 0) {
      std::snprintf(err, errlen,
                    "RLIMIT_NOFILE %llu leaves no room for connections "
                    "(reserve %u + listeners %u)",
                    static_cast<unsigned long long>(nofile), kFdReserve, kMaxListeners);
      return false;
    }
    listener_base_ = max_conns_;

    rc = io_uring_register_files_sparse(&ring_, max_conns_ + kMaxListeners);
    if (rc != 0) {
      std::snprintf(err, errlen, "register_files_sparse(%u): %s",
                    max_conns_ + kMaxListeners, std::strerror(-rc));
      return false;
    }
    // The direct-descriptor allocator's cursor continues past the last
    // slot it touched - after the listeners land at listener_base_+ the
    // next accept would be handed a LISTENER slot (measured: res=4097).
    // Confine allocation to the connection slots; listeners are placed,
    // never allocated.
    rc = io_uring_register_file_alloc_range(&ring_, 0, max_conns_);
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

    // One allocation at init, sized by the derived capacity - memory now
    // scales with the limit (a half-million-fd host pays tens of MB
    // here). Deliberate: no guessed cap anywhere; #166 makes it
    // overridable, and an override ABOVE the derivation is refused by
    // name there, never silently clamped.
    conns_.resize(max_conns_);
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
    while (!stop_) tick(nullptr);
  }

  // ONE bounded step (#116 slice 3, Gebot 18 as an API): with a budget
  // the WAIT is at most that long AND the batch is interrupted between
  // completions once it is spent - what is left stays in the CQ and the
  // next tick continues it. Without one this is the loop's own step:
  // block until at least one completion, then drain the batch.
  // True = work was processed.
  bool tick(const struct __kernel_timespec* budget) {
    if (budget == nullptr) return step(nullptr, false);
    // The deadline is read ONCE here and compared between completions
    // against the coarse monotonic clock - a vDSO read, no syscall.
    struct timespec now {};
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
    int64_t deadline = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
    deadline += budget->tv_sec * 1000000000 + budget->tv_nsec;
    return step(&deadline, true);
  }

  // The descriptor an embedder polls (#116 slice 3): readable exactly
  // when this ring has completions to hand over, so an idle server
  // costs its host nothing. -1 before init.
  int fd() const { return ring_up_ ? ring_.ring_fd : -1; }

  // Did the stop signal's completion land? The bounded tick's caller
  // owns its own loop and has to be able to ask.
  bool stopped() const { return stop_; }

  // DRAIN, THEN FORGET (#116 slice 5). The listeners close at once -
  // nothing new is taken - and the loop keeps turning until either the
  // last accepted connection is gone or the grace runs out, whichever
  // comes first. Grace 0 means the second condition is already true,
  // which is the immediate stop.
  //
  // The connections that survive the grace are FORGOTTEN, not waited
  // on: an idle keep-alive peer that says nothing would otherwise hold
  // the process open forever, and it is the destructor's ring exit that
  // ends them - one place, the same place a signal's stop uses.
  void drain(int64_t grace_ns) {
    if (draining_) return;
    draining_ = true;
    close_listeners();
    struct timespec now {};
    ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
    drain_deadline_ = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec + grace_ns;
    if (live_ == 0 || grace_ns <= 0) stop_ = true;
  }

  // How many accepted connections are still being served. The drain
  // watches it; a caller with its own loop can too.
  uint32_t live_conns() const { return live_; }

  // The derived capacity - what the machine actually allows, the "thing
  // that says what max is". tools/webmachine-tune.sh prints the same
  // arithmetic without running a server.
  uint32_t max_conns() const { return max_conns_; }

 private:
  // One listener, made entirely of ring ops: a stale unix path goes
  // first and UNLINKED from the chain (a linked op that fails - ENOENT
  // is normal - would cancel everything behind it), then socket ->
  // (setsockopt) -> bind -> listen as one linked chain, one submit,
  // every CQE checked, a failure naming its stage.
  bool setup_listener(uint32_t li, const ListenerSpec& spec, char* err, size_t errlen) {
    const uint32_t slot = listener_base_ + li;
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
      while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
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
        io_uring_cqe_seen(&ring_, cqe);
      }
      if (failed) return false;
    }
    // Only a bind that happened leaves a path to remove again.
    if (is_unix) unix_paths_.emplace_back(spec.unix_path);
    // TCP-only settings (TCP_NODELAY, SO_SNDBUF) are asked per accept;
    // a connection remembers which listener took it.
    unix_listener_[li] = is_unix;
    return true;
  }

  struct Conn {
    // Read on every event before anything else.
    bool live = false;
    bool sending = false;          // `out` is borrowed by the kernel
    bool close_after_send = false;
    uint8_t li = 0;    // which listener accepted - the App's key
    uint16_t gen = 0;  // stale-CQE guard: slot reuse bumps it, old ops miss
    size_t sent = 0;   // bytes of `out` the kernel has taken so far

    // Two buffers, not one: `out` is BORROWED by an in-flight send (its
    // pointer is in the SQE), so nothing may append to or clear it until
    // the send's CQE - appends land in `next`, the swap happens when the
    // send drains. Capacity survives clear(); a warm slot allocates
    // nothing.
    std::string out;
    std::string next;

    // One MORE than the plan can hold: a plan of pure pointers leaves
    // the sink to be sent ahead of it, and that prepend must always
    // have somewhere to go. Truncating instead would drop bytes off
    // the wire silently, which is the one failure this model must not
    // be able to have.
    static constexpr unsigned kIov = App::Plan::kSegs + 1;
    unsigned niov = 0;    // 0 = plain send of `out`
    size_t plan_len = 0;  // total bytes across iov
    struct msghdr msg {};

    // The App's per-connection state; the Ring only resets it.
    typename App::Conn app;

    // The App's PLAN for one round (#168), resolved: pointers into a
    // mapping or into a table built at add_route, interleaved with
    // ranges of `out` where the round had to spell bytes itself (h2's
    // DATA frame headers). One sendmsg puts the whole round on the
    // wire without a single body byte passing through this process.
    // They must live until the CQE, which is why they sit here and not
    // on a stack frame. msg_iov is what the in-flight sendmsg actually
    // points at - iov minus whatever a partial send consumed - kept
    // separate so the plan stays intact across retries.
    //
    // LAST in the struct, DELIBERATELY, and with no initializer: at
    // 128 segments these two arrays are 4 KB of a ~4.7 KB Conn, and
    // conns_ holds max_conns_ of them (derived from RLIMIT_NOFILE -
    // easily a million). Placed last and never written by the
    // constructor, their pages stay zero-backed until a connection
    // actually transfers something; only then does its slot's memory
    // become real. Putting anything the constructor touches after them
    // would fault every page of every slot at startup.
    struct iovec iov[kIov];
    struct iovec msg_iov[kIov];
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
      std::fprintf(stderr, "webmachine: SQ (%u entries) stuck after submit; ring is broken\n",
                   sq_entries_);
      std::exit(1);
    }
    return s;
  }

  // The listeners leave through the ring, like everything else. Called
  // by drain and by the destructor, which is why it is idempotent -
  // closing a slot twice would take a slot a later accept was given.
  void close_listeners() {
    if (listeners_closed_) return;
    listeners_closed_ = true;
    for (uint32_t i = 0; i < nlisteners_; i++) {
      struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
      if (s == nullptr) break;
      io_uring_prep_close_direct(s, listener_base_ + i);
      io_uring_sqe_set_data64(s, detail::tag(detail::kClose, 0, listener_base_ + i));
    }
    io_uring_submit(&ring_);
  }

  void arm_accept(uint32_t li) {
    if (draining_) return;  // nothing new is taken once the drain began
    struct io_uring_sqe* s = sqe();
    io_uring_prep_multishot_accept_direct(s, listener_base_ + li, nullptr, nullptr, 0);
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

  // MSG_MORE when the App still owes bytes behind this segment: a
  // response is head-then-body, and a lone small head goes out and
  // then WAITS for the peer's delayed ACK before the body may follow
  // (measured in the previous tree: 44.30ms average, 1,118 req/s ->
  // 31,077 once fixed). MSG_MORE rather than TCP_CORK deliberately -
  // cork is connection state that needs an uncork afterwards, so a
  // response failing between head and body would leave the connection
  // corked; MSG_MORE is an argument to this one send and cannot
  // outlive it.
  void arm_send(uint32_t idx) {
    Conn& c = conns_[idx];
    struct io_uring_sqe* s = sqe();
    const int flags = MSG_NOSIGNAL | (app_.pending(c.app) ? MSG_MORE : 0);
    if (c.niov == 0) {
      io_uring_prep_send(s, static_cast<int>(idx), c.out.data() + c.sent,
                         c.out.size() - c.sent, flags);
    } else {
      // A PLAN: head plus pointers into the mapping, one operation, no
      // copy in this process. The iovecs are rebuilt from `sent` each
      // time because a partial send may have consumed whole segments
      // and part of the next - the kernel takes what the socket has
      // room for and says how much.
      //
      // MSG_SPLICE_PAGES WAS TRIED HERE AND DOES NOTHING (measured,
      // 6.18, io_uring): it is an MSG_INTERNAL_SENDMSG_FLAGS bit meant
      // for in-kernel callers whose iterators are already bvec/kvec; a
      // userspace iovec does not qualify. 2 GiB in 256 KiB chunks over
      // loopback, flag on against flag off, three rounds each: 2001 /
      // 2025 / 2147 MB/s against 2158 / 2064 / 2080, with system time
      // equal to three decimals - no saved copy, in either direction.
      // A second probe confirms it from the other side: clobbering the
      // source buffer immediately after io_uring_submit still puts the
      // ORIGINAL bytes on the wire, i.e. the copy already happened.
      // Which is also the standing rule for every send here - anything
      // that fits in the sndbuf (3.76 MiB on loopback TCP, 208 KiB on
      // AF_UNIX) is the kernel's the moment submit returns.
      //
      // That leaves ONE kernel copy per body and nothing to remove.
      // The alternatives both cost more than they save and are closed:
      // splice needs a pipe, a second operation and an io-wq hop
      // (measured 0.63x-0.79x at 256 KiB / 1 MiB); SEND_ZC buys the
      // copy back with a ubuf_info and a SECOND completion per send,
      // and caps in-flight bytes at the RLIMIT_MEMLOCK account (~8 MB)
      // - a great deal of bookkeeping around a small window.
      unsigned n = 0;
      size_t skip = c.sent;
      for (unsigned i = 0; i < c.niov; i++) {
        if (skip >= c.iov[i].iov_len) {
          skip -= c.iov[i].iov_len;
          continue;
        }
        c.msg_iov[n].iov_base = static_cast<char*>(c.iov[i].iov_base) + skip;
        c.msg_iov[n].iov_len = c.iov[i].iov_len - skip;
        skip = 0;
        n++;
      }
      c.msg = msghdr{};
      c.msg.msg_iov = c.msg_iov;
      c.msg.msg_iovlen = n;
      io_uring_prep_sendmsg(s, static_cast<int>(idx), &c.msg, flags);
    }
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, detail::tag(detail::kSend, c.gen, idx));
    c.sending = true;
  }

  void begin_close(uint32_t idx) {
    Conn& c = conns_[idx];
    if (!c.live) return;
    // An in-flight send borrows c.out and the plan's pointers; the slot
    // may not be reset (and the descriptor not closed) until its CQE
    // lands - on_send finishes the close.
    if (c.sending) {
      c.close_after_send = true;
      return;
    }
    c.live = false;
    if (live_ != 0) live_--;
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
    if (WM_UNLIKELY(idx >= max_conns_)) return;  // the kernel named a slot we never registered
    Conn& c = conns_[idx];
    c.gen++;
    c.live = true;
    live_++;
    c.sending = false;
    c.close_after_send = false;
    c.li = static_cast<uint8_t>(li);
    c.sent = 0;
    c.out.clear();  // capacity survives: a warm slot allocates nothing
    c.next.clear();
    c.app.reset(static_cast<uint8_t>(li), !unix_listener_[li]);  // whose listener, whose app, packetized?
    // A server that writes complete responses has nothing for Nagle to
    // coalesce - only stalls to offer. Found the hard way (#168): a
    // response whose tail went out as its own small segment waited
    // ~43ms for the peer's delayed ACK, once per response. Best effort
    // through the ring; the CQE is ignored (kSetup has no handler arm,
    // deliberately).
    if (!unix_listener_[li]) {
      static const int kOne = 1;
      struct io_uring_sqe* s = sqe();
      io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx),
                             IPPROTO_TCP, TCP_NODELAY, const_cast<int*>(&kOne), sizeof(kOne));
      s->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, c.gen, idx));
      // TCP_MAXSEG once lived here too (#147), queried per connection
      // to gate gzip on the real segment size. Retired (Nutzer-Entscheid
      // 2026-08-22, #147 Tor 1 revision): io_uring_cmd_getsockopt
      // (io_uring/cmd_net.c) hard-refuses every level but SOL_SOCKET -
      // TCP_MAXSEG is IPPROTO_TCP, so it was structurally unreachable
      // through the ring by any op, confirmed live as -EOPNOTSUPP. The
      // only bridge was IORING_OP_FIXED_FD_INSTALL + getsockopt(2) +
      // close(2), linked ahead of the first recv so the query always
      // landed before a response could be built - a whole extra ring
      // round-trip of latency on every TCP accept, paid before the
      // connection had said a word. http1.hpp's kCompressFloor replaces
      // the query with a fixed floor (1280B, the IPv6 minimum MTU) that
      // needs nothing from the kernel at accept time.
    }
    arm_recv(idx);
  }

  void on_recv(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen) return;  // a previous tenant's completion

    if (WM_UNLIKELY(cqe->res <= 0)) {
      if (cqe->res == -ENOBUFS) {
        // Reachable by arithmetic: max_conns_ (derived; in practice far
        // above kBufCount's 2048 since #169), and every completion
        // consumes at least one whole buffer no
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
    // The plan is offered on the LAST feed of the bundle alone, and
    // only when nothing is in flight (an in-flight sendmsg owns the
    // iovec arrays, and a plan against `next` would resolve against
    // the wrong string). Earlier segments park; the last one's flush
    // delivers everything parked by the whole bundle - so nothing is
    // lost to the split, it only rides one call later.
    typename App::Plan req;
    while (left > 0) {
      const size_t n = left < kBufSize ? left : kBufSize;
      size_t off = 0;
      if (WM_UNLIKELY(__builtin_mul_overflow(static_cast<size_t>(bid),
                                             static_cast<size_t>(kBufSize), &off))) {
        begin_close(idx);
        return;
      }
      const bool last = left <= kBufSize;
      typename App::Plan* plan = (last && !c.sending) ? &req : nullptr;
      if (!closing) closing = !app_.feed(c.app, pool_ + off, n, sink, plan);
      left -= n;
      bid = (bid + 1) & (kBufCount - 1);
      replenish_++;
    }

    if (!c.sending) {
      if (req.nseg != 0) {
        take_plan(c, req);
        arm_send(idx);
      } else if (!c.out.empty()) {
        arm_send(idx);
      }
    }
    if (WM_UNLIKELY(closing)) {
      // Everything queued still drains; on_send finishes the close.
      if (c.sending) c.close_after_send = true;
      else begin_close(idx);
      return;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) rearm_.push_back(idx);
  }

  void on_send(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (c.gen != gen) return;
    c.sending = false;

    if (WM_UNLIKELY(cqe->res < 0)) {
      begin_close(idx);
      return;
    }
    const size_t took = static_cast<size_t>(cqe->res);
    // What was offered: the plan's total when there is one, `out`
    // alone otherwise.
    const size_t offered = c.niov != 0 ? c.plan_len : c.out.size();
    size_t new_sent = 0;
    // The kernel cannot have taken more than it was offered, and the sum
    // must not wrap - both are one check each, before anything uses them.
    if (WM_UNLIKELY(took > offered - c.sent ||
                    __builtin_add_overflow(c.sent, took, &new_sent))) {
      begin_close(idx);
      return;
    }
    c.sent = new_sent;
    if (c.sent < offered) {
      arm_send(idx);  // partial: the rebuilt iovecs skip what already went
      return;
    }
    c.out.clear();
    c.sent = 0;
    c.niov = 0;  // the plan is spent; its pointers are nobody's business now
    c.plan_len = 0;
    // next drains BEFORE a pending close: an error response queued behind
    // an in-flight send must still reach the wire (RFC 9112 §9.6).
    if (!c.next.empty()) {
      c.out.swap(c.next);
      arm_send(idx);
      return;
    }
    continue_conn(idx);
  }

  // RESOLVE a plan into the connection's iovecs. A sink segment could
  // not carry a pointer while the plan was built - `out` was still
  // being appended to and every append may move it - so it carried an
  // offset, and this is the first moment the address is final. A plan
  // that names any sink range describes the round's sink COMPLETELY;
  // one of pure pointers (h1's transfer out of more()) leaves the sink
  // to be sent ahead of it - the prepend shifts the array by one, and
  // Conn::kIov reserves the slot.
  void take_plan(Conn& c, const typename App::Plan& req) {
    c.niov = 0;
    c.plan_len = 0;
    bool sink_covered = false;
    for (unsigned i = 0; i < req.nseg; i++) {
      const typename App::Plan::Seg& sg = req.seg[i];
      if (sg.base != nullptr) {
        c.iov[c.niov].iov_base = const_cast<char*>(sg.base);
      } else {
        c.iov[c.niov].iov_base = c.out.data() + sg.off;
        sink_covered = true;
      }
      c.iov[c.niov].iov_len = sg.len;
      c.plan_len += sg.len;
      c.niov++;
    }
    if (!sink_covered && !c.out.empty()) {
      for (unsigned i = c.niov; i > 0; i--) c.iov[i] = c.iov[i - 1];
      c.iov[0].iov_base = c.out.data();
      c.iov[0].iov_len = c.out.size();
      c.plan_len += c.out.size();
      c.niov++;
    }
    c.sent = 0;
  }

  // The delivery continuation (#168): a fully drained sink is the one
  // signal every protocol produces. Backlog first - bytes queued in
  // `out` while a chain flew belong to EARLIER wire order than any new
  // round. Then the App speaks: bytes into `out`, or a PLAN - pointers
  // to bytes that already exist, which leave with the sink in one
  // sendmsg. Runs BEFORE a pending close is honored: a closing
  // response still delivers its source to the end.
  void continue_conn(uint32_t idx) {
    Conn& c = conns_[idx];
    if (!c.out.empty()) {
      arm_send(idx);
      return;
    }
    // Default-init, NOT value-init: Plan's array is deliberately left
    // indeterminate (only [0, nseg) is ever read), because this runs
    // after EVERY drained send - hello pays it as often as a transfer.
    typename App::Plan req;
    if (!app_.more(c.app, c.out, req)) c.close_after_send = true;
    if (req.nseg != 0) {
      take_plan(c, req);
      arm_send(idx);
      return;
    }
    if (!c.out.empty()) {
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

  // deadline: CLOCK_MONOTONIC_COARSE nanoseconds, or null for "no
  // bound". Everything the two callers share lives here; the ONLY
  // difference is the wait and where the batch may stop.
  bool step(const int64_t* deadline, bool bounded) {
    if (replenish_ != 0) {
      io_uring_buf_ring_advance(buf_ring_, static_cast<int>(replenish_));
      replenish_ = 0;
    }
    if (bounded) {
      // The rest of the budget is what the WAIT may take. Already
      // spent: submit and take whatever is there, waiting for nothing.
      struct timespec now {};
      ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
      const int64_t left =
          *deadline - (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec);
      struct io_uring_cqe* first = nullptr;
      if (left <= 0) {
        io_uring_submit(&ring_);
      } else {
        struct __kernel_timespec ts {left / 1000000000, left % 1000000000};
        // -ETIME is the budget doing its job, not a failure.
        io_uring_submit_and_wait_timeout(&ring_, &first, 1, &ts, nullptr);
      }
    } else {
      io_uring_submit_and_wait(&ring_, 1);
    }
    // Once per wake, never per request; the Ring does not know or care
    // what the App keeps fresh.
    app_.on_tick();
    bool worked = false;
    struct io_uring_cqe* cqe = nullptr;
    while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
      handle(cqe);
      io_uring_cqe_seen(&ring_, cqe);
      worked = true;
      if (bounded) {
        // Between completions, never inside one: a half-handled CQE
        // has no resumable state. What is left stays in the CQ - the
        // advance above only ever released what was HANDLED, so the
        // next tick reads it as if nothing had happened.
        struct timespec now {};
        ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
        if (static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec >= *deadline) break;
      }
    }
    if (!rearm_.empty()) {
      for (uint32_t idx : rearm_) {
        Conn& c = conns_[idx];
        // A condemned connection gets no new read; its close is in flight.
        if (c.live && !c.close_after_send) arm_recv(idx);
      }
      rearm_.clear();
    }
    if (WM_UNLIKELY(draining_) && !stop_) {
      struct timespec now {};
      ::clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
      const int64_t at = static_cast<int64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
      if (live_ == 0 || at >= drain_deadline_) stop_ = true;
    }
    return worked;
  }

  App& app_;
  struct io_uring ring_ {};
  bool ring_up_ = false;
  bool stop_ = false;
  bool bundles_ = false;
  // Derived at init from the raised RLIMIT_NOFILE (#169); 0 only
  // before init. listener_base_ = max_conns_: the listeners sit behind
  // the connection slots.
  unsigned sq_entries_ = 0;  // what the SQ finally settled at
  uint32_t max_conns_ = 0;
  uint32_t listener_base_ = 0;
  bool unix_listener_[kMaxListeners] = {};
  std::vector<std::string> unix_paths_;  // owned copies: the destructor unlinks them
  uint32_t nlisteners_ = 0;
  bool listeners_closed_ = false;
  // The drain (#116 slice 5): set once, never cleared - a server that
  // began stopping does not start again.
  bool draining_ = false;
  int64_t drain_deadline_ = 0;
  uint32_t live_ = 0;  // accepted connections still being served
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
