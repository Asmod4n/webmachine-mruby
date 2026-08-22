// The io backend (#171): the Ring speaks ONE API - the liburing subset
// it actually uses - and two providers implement it. UringIo is a
// header-only inline pass-through onto the real liburing, optimized
// away without residue (the http.hpp precedent: sharing proven free).
// SelectIo is the portable path: it REUSES liburing's SQE/CQE structs
// as a pure data format (io_uring_prep_* are userspace struct writers,
// no syscall in any of them) and interprets the opcodes over select(2).
//
// WHY select AND NOT poll/kqueue/epoll (user decision): macOS' poll is
// permanently broken on several fd types, WSAPoll does not report
// failed connections (acknowledged by Microsoft, never fixed), kqueue
// is BSD-only, epoll Linux-only. select is the one readiness primitive
// that exists everywhere AND has been debugged everywhere - and one
// primitive means ONE implementation instead of three backends with
// three test matrices.
//
// THE SHIM IS NOT A FALLBACK, IT IS A BACKEND. There is never an
// `if (have_uring)` at runtime - the Ring is instantiated per backend
// (template, zero indirection), and the ONE branch point is at init,
// in main: io_uring sets up, or the select backend starts and SCREAMS
// (the fat stderr warning main owns).
//
// DESIGN GOAL, explicit: the select path is CORRECT, not fast.
// Laziness is the declared motive. Nobody optimizes it later.
//   - every operation is readiness + a classic syscall
//   - file IO under select is never non-blocking (select on a regular
//     file always says ready); it would run synchronously and block
//     the reactor - which is why splice does not exist here at all:
//     kSupportsSplice = false, the Ring never builds the pipe pool,
//     every body goes iovec.
//   - recv bundles do not exist (has_bundles = false); one buffer per
//     completion, the dense-fill contract holds trivially.
#ifndef WEBMACHINE_IO_BACKEND_HPP
#define WEBMACHINE_IO_BACKEND_HPP

#include <liburing.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <vector>

namespace webmachine {

// ---- UringIo: the real thing, inlined away --------------------------

struct UringIo {
  using State = struct io_uring;
  using BufRing = struct io_uring_buf_ring;
  static constexpr bool kSupportsSplice = true;
  static constexpr const char* kName = "io_uring";

  // queue init + ring-fd registration + the load-bearing probe:
  // IORING_OP_BIND/LISTEN are 6.11, and their absence is what flips
  // main to the select backend (a NAMED reason, carried out in err).
  static bool setup(State* st, char* err, size_t errlen) {
    struct io_uring_params p {};
    p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
    const int rc = io_uring_queue_init_params(1024, st, &p);
    if (rc != 0) {
      std::snprintf(err, errlen, "io_uring_queue_init: %s", std::strerror(-rc));
      return false;
    }
    // One fewer fd-table lookup per enter(2); nothing else shares this fd.
    io_uring_register_ring_fd(st);
    struct io_uring_probe* probe = io_uring_get_probe_ring(st);
    const bool ok = probe != nullptr && io_uring_opcode_supported(probe, IORING_OP_BIND) &&
                    io_uring_opcode_supported(probe, IORING_OP_LISTEN);
    if (probe != nullptr) io_uring_free_probe(probe);
    if (!ok) {
      io_uring_queue_exit(st);
      std::snprintf(err, errlen, "kernel lacks IORING_OP_BIND/LISTEN (needs 6.11+)");
      return false;
    }
    return true;
  }
  static void queue_exit(State* st) { io_uring_queue_exit(st); }

  static bool has_op_pipe(State* st) {
    struct io_uring_probe* probe = io_uring_get_probe_ring(st);
    const bool ok = probe != nullptr && io_uring_opcode_supported(probe, IORING_OP_PIPE);
    if (probe != nullptr) io_uring_free_probe(probe);
    return ok;
  }
  static bool has_bundles(State* st) {
    return (st->features & IORING_FEAT_RECVSEND_BUNDLE) != 0;
  }

  // #169's raise: soft to hard, ceiling fs.nr_open. Lives with the
  // backend because only the backend knows what it can index.
  static uint64_t raise_nofile() {
    struct rlimit rl {};
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
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
  }

  static int register_files_sparse(State* st, unsigned n) {
    return io_uring_register_files_sparse(st, n);
  }
  static int register_file_alloc_range(State* st, unsigned lo, unsigned n) {
    return io_uring_register_file_alloc_range(st, lo, n);
  }
  static int register_files_update(State* st, unsigned off, int* fds, unsigned n) {
    return io_uring_register_files_update(st, off, fds, n);
  }

  static BufRing* setup_buf_ring(State* st, unsigned count, int group, unsigned flags,
                                 int* errp) {
    return io_uring_setup_buf_ring(st, count, group, flags, errp);
  }
  static void buf_ring_add(BufRing* br, void* addr, unsigned len, uint16_t bid, int mask,
                           int off) {
    io_uring_buf_ring_add(br, addr, len, bid, mask, off);
  }
  static void buf_ring_advance(BufRing* br, int n) { io_uring_buf_ring_advance(br, n); }
  static int buf_ring_mask(unsigned count) { return io_uring_buf_ring_mask(count); }
  static void free_buf_ring(State* st, BufRing* br, unsigned count, int group) {
    io_uring_free_buf_ring(st, br, count, group);
  }

  static struct io_uring_sqe* get_sqe(State* st) { return io_uring_get_sqe(st); }
  static int submit(State* st) { return io_uring_submit(st); }
  static int submit_and_wait(State* st, unsigned n) { return io_uring_submit_and_wait(st, n); }
  static unsigned sq_space_left(State* st) { return io_uring_sq_space_left(st); }
  static int peek_cqe(State* st, struct io_uring_cqe** cqe) {
    return io_uring_peek_cqe(st, cqe);
  }
  static void cqe_seen(State* st, struct io_uring_cqe* cqe) { io_uring_cqe_seen(st, cqe); }
};

// ---- SelectIo: the portable interpreter -----------------------------

struct SelectIo {
  static constexpr bool kSupportsSplice = false;
  static constexpr const char* kName = "select";

  struct BufRing {
    struct Ent {
      void* addr = nullptr;
      unsigned len = 0;
      uint16_t bid = 0;
    };
    std::vector<Ent> ents;
    uint32_t mask = 0;
    // Free-running cursors, exactly the kernel's shape: the provider
    // advances tail, consumption walks head strictly in ring order -
    // the advance-only replenish contract the Ring relies on.
    uint32_t head = 0;
    uint32_t tail = 0;
  };

  struct State {
    std::vector<struct io_uring_sqe> sq;  // filled by the real io_uring_prep_* writers
    std::deque<struct io_uring_cqe> cq;
    std::vector<int> files;               // slot -> fd; the direct table, spelled out
    std::vector<uint32_t> free_slots;     // the alloc range's free list
    uint32_t alloc_lo = 0, alloc_n = 0;
    std::vector<struct io_uring_sqe> waiting;  // armed ops awaiting readiness
    BufRing bufring;
    ~State() {
      for (int fd : files) {
        if (fd >= 0) ::close(fd);
      }
    }
  };

  static bool setup(State*, char*, size_t) { return true; }
  static void queue_exit(State*) {}  // the State destructor closes what remains
  static bool has_op_pipe(State*) { return false; }
  static bool has_bundles(State*) { return false; }

  // THE RLIMIT RULE (user decision, this backend only): the soft limit
  // may only be raised to FD_SETSIZE - 1. Under this backend
  // connections ARE process fds and would otherwise climb past every
  // stock fd_set in the process (mruby-c-ares is the concrete
  // neighbor). The io_uring path deliberately has no such cap - #169
  // measured why it would only cost there.
  static uint64_t raise_nofile() {
    struct rlimit rl {};
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
    rlim_t target = static_cast<rlim_t>(FD_SETSIZE - 1);
    if (target > rl.rlim_max) target = rl.rlim_max;
    if (rl.rlim_cur != target) {
      struct rlimit want {target, rl.rlim_max};
      (void)::setrlimit(RLIMIT_NOFILE, &want);
      if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return 0;
    }
    const uint64_t cur = static_cast<uint64_t>(rl.rlim_cur);
    return cur < FD_SETSIZE ? cur : FD_SETSIZE - 1;
  }

  static int register_files_sparse(State* st, unsigned n) {
    st->files.assign(n, -1);
    return 0;
  }
  static int register_file_alloc_range(State* st, unsigned lo, unsigned n) {
    st->alloc_lo = lo;
    st->alloc_n = n;
    st->free_slots.clear();
    st->free_slots.reserve(n);
    // Descending, so allocation hands out low slots first (cosmetic
    // parity with the kernel; the Ring only checks the bound).
    for (unsigned i = n; i-- > 0;) st->free_slots.push_back(lo + i);
    return 0;
  }
  static int register_files_update(State* st, unsigned off, int* fds, unsigned n) {
    for (unsigned i = 0; i < n; i++) {
      if (off + i >= st->files.size()) return -EINVAL;
      // dup: the caller may close its copy after registering, exactly
      // like the kernel's table taking its own reference.
      st->files[off + i] = ::dup(fds[i]);
    }
    return static_cast<int>(n);
  }

  static BufRing* setup_buf_ring(State* st, unsigned count, int, unsigned, int*) {
    st->bufring.ents.assign(count, {});
    st->bufring.mask = count - 1;
    st->bufring.head = st->bufring.tail = 0;
    return &st->bufring;
  }
  static void buf_ring_add(BufRing* br, void* addr, unsigned len, uint16_t bid, int mask,
                           int off) {
    BufRing::Ent& e = br->ents[(br->tail + static_cast<uint32_t>(off)) & static_cast<uint32_t>(mask)];
    e.addr = addr;
    e.len = len;
    e.bid = bid;
  }
  static void buf_ring_advance(BufRing* br, int n) { br->tail += static_cast<uint32_t>(n); }
  static int buf_ring_mask(unsigned count) { return static_cast<int>(count - 1); }
  static void free_buf_ring(State*, BufRing*, unsigned, int) {}

  static struct io_uring_sqe* get_sqe(State* st) {
    if (st->sq.size() >= 1024) return nullptr;  // the caller submits and retries
    st->sq.emplace_back();
    struct io_uring_sqe* s = &st->sq.back();
    std::memset(s, 0, sizeof(*s));
    return s;
  }
  static unsigned sq_space_left(State* st) {
    return static_cast<unsigned>(1024 - st->sq.size());
  }

  static int peek_cqe(State* st, struct io_uring_cqe** cqe) {
    if (st->cq.empty()) return -EAGAIN;
    *cqe = &st->cq.front();
    return 0;
  }
  static void cqe_seen(State* st, struct io_uring_cqe*) { st->cq.pop_front(); }

  static int submit(State* st) {
    // Immediate ops execute now, in order, with link semantics: a
    // failing IOSQE_IO_LINK member cancels the rest of its chain
    // (-ECANCELED), which the Ring's setup chains and shutdown+close
    // pair rely on. Readiness ops park in `waiting`.
    bool chain_failed = false;
    const int n = static_cast<int>(st->sq.size());
    for (struct io_uring_sqe& s : st->sq) {
      const bool linked = (s.flags & IOSQE_IO_LINK) != 0;
      if (chain_failed) {
        push_cqe(st, s.user_data, -ECANCELED, 0);
        if (!linked) chain_failed = false;
        continue;
      }
      int res = 0;
      if (deferred(s.opcode)) {
        st->waiting.push_back(s);
        continue;
      }
      res = execute(st, s);
      push_cqe(st, s.user_data, res, 0);
      if (linked && res < 0) chain_failed = true;
    }
    st->sq.clear();
    return n;
  }

  static int submit_and_wait(State* st, unsigned wait_nr) {
    const int n = submit(st);
    while (st->cq.size() < wait_nr) {
      if (!wait_ready(st)) break;  // nothing armed and nothing done: do not spin
    }
    return n;
  }

 private:
  static void push_cqe(State* st, uint64_t ud, int32_t res, uint32_t flags) {
    struct io_uring_cqe c {};
    c.user_data = ud;
    c.res = res;
    c.flags = flags;
    st->cq.push_back(c);
  }

  static bool deferred(uint8_t op) {
    return op == IORING_OP_ACCEPT || op == IORING_OP_RECV || op == IORING_OP_SEND ||
           op == IORING_OP_POLL_ADD;
  }

  static int resolve_fd(State* st, const struct io_uring_sqe& s) {
    if (s.flags & IOSQE_FIXED_FILE) {
      const uint32_t slot = static_cast<uint32_t>(s.fd);
      if (slot >= st->files.size()) return -1;
      return st->files[slot];
    }
    return s.fd;
  }

  // The immediate ops - each decoded by the field layout the real
  // io_uring_prep_* wrote (liburing.h is the codec spec here).
  static int execute(State* st, struct io_uring_sqe& s) {
    switch (s.opcode) {
      case IORING_OP_UNLINKAT: {
        const char* path = reinterpret_cast<const char*>(static_cast<uintptr_t>(s.addr));
        return ::unlinkat(s.fd, path, static_cast<int>(s.unlink_flags)) == 0 ? 0 : -errno;
      }
      case IORING_OP_SOCKET: {
        // prep_socket_direct: domain=fd, type=off, protocol=len, slot=file_index-1
        const int fd = ::socket(s.fd, static_cast<int>(s.off) | SOCK_NONBLOCK | SOCK_CLOEXEC,
                                static_cast<int>(s.len));
        if (fd < 0) return -errno;
        if (fd >= FD_SETSIZE) {  // the assertion that can structurally never fire
          ::close(fd);
          return -EMFILE;
        }
        const uint32_t slot = s.file_index - 1;
        if (slot >= st->files.size()) {
          ::close(fd);
          return -EINVAL;
        }
        st->files[slot] = fd;
        return 0;
      }
      case IORING_OP_URING_CMD: {
        if (s.cmd_op != SOCKET_URING_OP_SETSOCKOPT) return -EOPNOTSUPP;
        const int fd = resolve_fd(st, s);
        if (fd < 0) return -EBADF;
        const void* val = reinterpret_cast<const void*>(static_cast<uintptr_t>(s.optval));
        return ::setsockopt(fd, static_cast<int>(s.level), static_cast<int>(s.optname), val,
                            s.optlen) == 0
                   ? 0
                   : -errno;
      }
      case IORING_OP_BIND: {
        const int fd = resolve_fd(st, s);
        if (fd < 0) return -EBADF;
        const struct sockaddr* sa =
            reinterpret_cast<const struct sockaddr*>(static_cast<uintptr_t>(s.addr));
        return ::bind(fd, sa, static_cast<socklen_t>(s.off)) == 0 ? 0 : -errno;
      }
      case IORING_OP_LISTEN: {
        const int fd = resolve_fd(st, s);
        if (fd < 0) return -EBADF;
        return ::listen(fd, static_cast<int>(s.len)) == 0 ? 0 : -errno;
      }
      case IORING_OP_SHUTDOWN: {
        const int fd = resolve_fd(st, s);
        if (fd < 0) return -EBADF;
        return ::shutdown(fd, static_cast<int>(s.len)) == 0 ? 0 : -errno;
      }
      case IORING_OP_CLOSE: {
        // close_direct: the slot is file_index-1. Closing also cancels
        // (silently drops) whatever was armed on that fd - the kernel
        // would post -ECANCELED, but the Ring's gen guard ignores those
        // anyway; not existing is as good as being ignored.
        const uint32_t slot = s.file_index - 1;
        if (slot >= st->files.size() || st->files[slot] < 0) return -EBADF;
        purge_waiting_on_slot(st, slot);
        ::close(st->files[slot]);
        st->files[slot] = -1;
        if (slot >= st->alloc_lo && slot < st->alloc_lo + st->alloc_n) {
          st->free_slots.push_back(slot);
        }
        return 0;
      }
      default:
        return -EOPNOTSUPP;
    }
  }

  static void purge_waiting_on_slot(State* st, uint32_t slot) {
    for (size_t i = 0; i < st->waiting.size();) {
      const struct io_uring_sqe& w = st->waiting[i];
      if ((w.flags & IOSQE_FIXED_FILE) != 0 && static_cast<uint32_t>(w.fd) == slot) {
        st->waiting[i] = st->waiting.back();
        st->waiting.pop_back();
      } else {
        i++;
      }
    }
  }

  // One blocking select over everything armed, then run what is ready.
  // Returns false when nothing is armed (the caller must not spin).
  // The fd_set is bounded structurally: raise_nofile capped the limit
  // at FD_SETSIZE-1, so no fd can reach FD_SETSIZE - checked anyway,
  // as the assertion it is (an out-of-range FD_SET writes past the
  // buffer on POSIX).
  static bool wait_ready(State* st) {
    if (st->waiting.empty()) return false;
    fd_set rset, wset;
    FD_ZERO(&rset);
    FD_ZERO(&wset);
    int nfds = 0;
    for (const struct io_uring_sqe& w : st->waiting) {
      const int fd = resolve_fd(st, w);
      if (fd < 0 || fd >= FD_SETSIZE) continue;
      if (w.opcode == IORING_OP_SEND) FD_SET(fd, &wset);
      else FD_SET(fd, &rset);
      if (fd + 1 > nfds) nfds = fd + 1;
    }
    if (nfds == 0) return false;
    const int rc = ::select(nfds, &rset, &wset, nullptr, nullptr);
    if (rc <= 0) return true;  // EINTR and friends: try again from the top

    for (size_t i = 0; i < st->waiting.size();) {
      struct io_uring_sqe& w = st->waiting[i];
      const int fd = resolve_fd(st, w);
      bool remove = false;
      if (fd >= 0 && fd < FD_SETSIZE) {
        if (w.opcode == IORING_OP_SEND && FD_ISSET(fd, &wset)) {
          const void* buf = reinterpret_cast<const void*>(static_cast<uintptr_t>(w.addr));
          const ssize_t r =
              ::send(fd, buf, w.len, static_cast<int>(w.msg_flags) | MSG_NOSIGNAL);
          push_cqe(st, w.user_data, r >= 0 ? static_cast<int>(r) : -errno, 0);
          remove = true;
        } else if (w.opcode == IORING_OP_ACCEPT && FD_ISSET(fd, &rset)) {
          const int nf = ::accept4(fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
          if (nf >= 0) {
            if (nf >= FD_SETSIZE || st->free_slots.empty()) {
              ::close(nf);
              push_cqe(st, w.user_data, -ENFILE, 0);  // no MORE: the Ring re-arms
              remove = true;
            } else {
              const uint32_t slot = st->free_slots.back();
              st->free_slots.pop_back();
              st->files[slot] = nf;
              push_cqe(st, w.user_data, static_cast<int>(slot), IORING_CQE_F_MORE);
            }
          } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            push_cqe(st, w.user_data, -errno, IORING_CQE_F_MORE);  // transient, stays armed
          }
        } else if (w.opcode == IORING_OP_RECV && FD_ISSET(fd, &rset)) {
          BufRing& br = st->bufring;
          if (br.tail == br.head) {
            push_cqe(st, w.user_data, -ENOBUFS, 0);  // no MORE: the Ring re-arms
            remove = true;
          } else {
            const BufRing::Ent& e = br.ents[br.head & br.mask];
            const ssize_t r = ::recv(fd, e.addr, e.len, 0);
            if (r > 0) {
              br.head++;  // consumed strictly in ring order
              push_cqe(st, w.user_data, static_cast<int>(r),
                       IORING_CQE_F_MORE | IORING_CQE_F_BUFFER |
                           (static_cast<uint32_t>(e.bid) << IORING_CQE_BUFFER_SHIFT));
            } else if (r == 0) {
              push_cqe(st, w.user_data, 0, 0);  // EOF ends the multishot, no buffer used
              remove = true;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
              push_cqe(st, w.user_data, -errno, 0);
              remove = true;
            }
          }
        } else if (w.opcode == IORING_OP_POLL_ADD && FD_ISSET(fd, &rset)) {
          push_cqe(st, w.user_data, POLLIN, 0);
          remove = true;
        }
      } else {
        push_cqe(st, w.user_data, -EBADF, 0);
        remove = true;
      }
      if (remove) {
        st->waiting[i] = st->waiting.back();
        st->waiting.pop_back();
      } else {
        i++;
      }
    }
    return true;
  }
};

}  // namespace webmachine

#endif
