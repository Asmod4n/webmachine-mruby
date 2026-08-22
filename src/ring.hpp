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
//   struct Conn { void reset(uint8_t listener); };    per-connection state
//                 (reset carries which listener accepted - the App's
//                  key to "whose connection is this")
//   bool feed(Conn&, const char*, size_t, std::string& sink);
//        false = close this connection once the sink has drained
//   bool pending(const Conn&) const;
//        does this connection still owe bytes the App has not handed
//        over? Asked before each send: true makes it carry MSG_MORE,
//        so a small head does not go out alone and wait out the peer's
//        delayed ACK.
//   struct Plan { struct iovec iov[4]; unsigned niov; size_t iov_len; };
//   bool more(Conn&, std::string& sink, Plan&);
//        the delivery continuation (#168): called when the sink has
//        fully drained. The App either appends to the sink, or fills
//        the Plan with POINTERS to bytes that already exist somewhere
//        (a mapping, a table built at add_route) - those leave with
//        the sink in ONE sendmsg, without a copy in this process.
//        Same close contract as feed. An App without sources appends
//        nothing and returns true.
//   void on_tick();                                   once per reactor wake
//   void set_mss(uint32_t mss);
//        the TCP_MAXSEG queried once at accept (#147), 0 if unknown
//        (a unix listener never queries it - see on_accept). An App
//        with nothing to gate on segment size takes the value and
//        does nothing with it.
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
  kAccept = 1, kRecv = 2, kSend = 3, kClose = 4, kSetup = 5, kStop = 6, kShutdown = 7,
  kSetupTcp = 8
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
      unsigned n = 0;
      for (uint32_t i = 0; i < nlisteners_; i++) {
        struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
        if (s == nullptr) break;
        io_uring_prep_close_direct(s, listener_base_ + i);
        io_uring_sqe_set_data64(s, detail::tag(detail::kClose, 0, listener_base_ + i));
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
  // EVERY failure here is this machine refusing this configuration - a
  // taken port, an fd limit that leaves no room. Which io_uring answers
  // these calls was settled at BUILD time (src/uring.hpp), so nothing
  // in here is a reason to go looking for another one: a bind clash
  // that silently demoted the server to a slower path would be a
  // performance cliff wearing a startup message.
  bool init(const RingConfig& cfg, char* err, size_t errlen) {
    int rc = 0;
    struct io_uring_params p {};
    p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
    rc = io_uring_queue_init_params(1024, &ring_, &p);
    if (rc != 0) {
      std::snprintf(err, errlen, "io_uring_queue_init: %s", std::strerror(-rc));
      return false;
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
    while (!stop_) tick();
  }

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

    // The App's PLAN for the bytes that do not live in `out` (#168):
    // pointers into a mapping or into a table built at add_route,
    // never copies. iov[0] is always `out` itself (the prebuilt head),
    // so one sendmsg puts head and body on the wire together without a
    // single byte passing through this process. They must live until
    // the CQE, which is why they sit here and not on a stack frame.
    struct iovec iov[5];
    unsigned niov = 0;    // 0 = plain send of `out`
    size_t plan_len = 0;  // total bytes across iov, `out` included
    // What the in-flight sendmsg actually points at: iov minus whatever
    // an earlier partial send already consumed. Separate from iov so
    // the plan itself stays intact across retries.
    struct iovec msg_iov[5];
    struct msghdr msg {};

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
    c.sending = false;
    c.close_after_send = false;
    c.li = static_cast<uint8_t>(li);
    c.sent = 0;
    c.out.clear();  // capacity survives: a warm slot allocates nothing
    c.next.clear();
    c.app.reset(static_cast<uint8_t>(li));  // whose listener, whose app
    // A server that writes complete responses has nothing for Nagle to
    // coalesce - only stalls to offer. Found the hard way (#168): a
    // response whose tail went out as its own small segment waited
    // ~43ms for the peer's delayed ACK, once per response. Best effort
    // through the ring; the CQE is ignored (kSetup has no handler arm,
    // deliberately) - unlike the MSS query below, nothing depends on
    // TCP_NODELAY landing before the first byte is read.
    if (!unix_listener_[li]) {
      static const int kOne = 1;
      struct io_uring_sqe* s = sqe();
      io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(idx),
                             IPPROTO_TCP, TCP_NODELAY, const_cast<int*>(&kOne), sizeof(kOne));
      s->flags |= IOSQE_FIXED_FILE;
      io_uring_sqe_set_data64(s, detail::tag(detail::kSetup, c.gen, idx));

      // TCP_MAXSEG, ASKED not guessed (#147) - but NOT through
      // SOCKET_URING_OP_GETSOCKOPT, unlike the SETSOCKOPT above.
      // Verified against the kernel's own source
      // (io_uring/cmd_net.c, io_uring_cmd_getsockopt): it hard-refuses
      // every level but SOL_SOCKET -
      //
      //   level = READ_ONCE(sqe->level);
      //   if (level != SOL_SOCKET)
      //           return -EOPNOTSUPP;
      //
      // - unconditionally, with no protocol-level escape hatch
      // anywhere in io_uring_cmd_sock's whole op switch (SIOCINQ,
      // SIOCOUTQ, GETSOCKOPT, SETSOCKOPT, TX_TIMESTAMP, GETSOCKNAME -
      // nothing else exists). Confirmed live against this exact
      // kernel, not just read: SOCKET_URING_OP_GETSOCKOPT with
      // IPPROTO_TCP/TCP_MAXSEG returns cqe->res == -EOPNOTSUPP every
      // time. SETSOCKOPT above has no such restriction
      // (do_sock_setsockopt takes any level) - which is why
      // TCP_NODELAY works and this does not; the asymmetry is the
      // kernel's, not this file's.
      //
      // A direct descriptor is not a process fd, so no classic
      // getsockopt(2) can name it either - IORING_OP_FIXED_FD_INSTALL
      // is the bridge: it installs a REGULAR fd into the process
      // table that refers to the SAME socket, without touching the
      // fixed slot connections otherwise live in. This is this file's
      // SECOND exception to "everything through the ring, no classic
      // syscalls" (mmap in Assets::open is the first, for the same
      // reason: no ring op exists for what is needed). The syscall
      // pair that follows (on_setup_mss) is getsockopt(2) itself -
      // a bounded socket-state read, not a blocking network wait, the
      // category "no classic syscalls" exists to keep off this
      // thread - plus close(2) on the borrowed fd, which drops one of
      // two references to the socket and returns immediately; the
      // fixed-table reference is what keeps the connection alive.
      //
      // LINKED to the recv armed right after (IOSQE_IO_LINK: the next
      // SQE submitted does not start until this one completes) -
      // required, not a nicety. Measured without a link on the
      // now-abandoned GETSOCKOPT attempt: a client that writes its
      // request immediately after connect() routinely has its bytes
      // ready before this op's CQE is even processed, so an unlinked
      // recv could complete (and a response be built) before set_mss
      // ever ran - not a rare window but the common case on loopback.
      // The link makes "queried before answered" true by construction.
      // A unix listener has no MSS at all and never reaches this
      // branch - the App's set_mss is simply never called there, and
      // its default (0) reads as "never compress", the same answer a
      // failed query gives.
      struct io_uring_sqe* sm = sqe();
      io_uring_prep_fixed_fd_install(sm, static_cast<int>(idx), 0);
      sm->flags |= IOSQE_IO_LINK;
      io_uring_sqe_set_data64(sm, detail::tag(detail::kSetupTcp, c.gen, idx));
      arm_recv(idx);  // the link's dependent SQE - must be the very next one submitted
    } else {
      arm_recv(idx);
    }
  }

  // The installed regular fd's landing (#147): cqe->res is the new fd
  // on success (io_uring_prep_fixed_fd_install's own contract) - named
  // borrowed because it names the SAME socket as the fixed slot and
  // is given back (closed) before this function returns; it is never
  // stored anywhere. A stale CQE (slot reused since) or any failure
  // leaves the App's mss at its reset() default (0, "unknown") rather
  // than guessing - #147 requires querying, not guessing, and 0
  // already reads as "never compress" everywhere it is checked.
  void on_setup_mss(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
    if (WM_UNLIKELY(idx >= max_conns_)) return;
    Conn& c = conns_[idx];
    if (!c.live || c.gen != gen) return;
    if (cqe->res < 0) return;  // install failed: mss stays 0 ("unknown")
    const int borrowed_fd = cqe->res;
    int mss = 0;
    socklen_t mss_len = sizeof(mss);
    if (::getsockopt(borrowed_fd, IPPROTO_TCP, TCP_MAXSEG, &mss, &mss_len) == 0 && mss > 0) {
      c.app.set_mss(static_cast<uint32_t>(mss));
    }
    ::close(borrowed_fd);
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
    typename App::Plan req{};
    if (!app_.more(c.app, c.out, req)) c.close_after_send = true;
    if (req.niov != 0) {
      // Take the plan: iov[0] is whatever the round also put in the
      // sink (usually nothing here - the head left with an earlier
      // round), then the source's own pointers.
      c.niov = 0;
      c.plan_len = 0;
      if (!c.out.empty()) {
        c.iov[c.niov].iov_base = c.out.data();
        c.iov[c.niov].iov_len = c.out.size();
        c.plan_len += c.out.size();
        c.niov++;
      }
      for (unsigned i = 0; i < req.niov && c.niov < 5; i++) {
        c.iov[c.niov++] = req.iov[i];
        c.plan_len += req.iov[i].iov_len;
      }
      c.sent = 0;
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
      case detail::kSetupTcp: on_setup_mss(idx, gen, cqe); break;
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
    while (io_uring_peek_cqe(&ring_, &cqe) == 0) {
      handle(cqe);
      io_uring_cqe_seen(&ring_, cqe);
    }
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
  // Derived at init from the raised RLIMIT_NOFILE (#169); 0 only
  // before init. listener_base_ = max_conns_: the listeners sit behind
  // the connection slots.
  uint32_t max_conns_ = 0;
  uint32_t listener_base_ = 0;
  bool unix_listener_[kMaxListeners] = {};
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
