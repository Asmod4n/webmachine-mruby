#include "ring.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace webmachine {
namespace {

// Fixed until the HTTP layer exists: one 200 per receive completion.
constexpr char kResponse[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
constexpr size_t kResponseLen = sizeof(kResponse) - 1;

// user_data: kind(8) | gen(16) | idx(32). gen guards a reused slot
// against CQEs of the connection that owned it before.
enum : uint8_t { kAccept = 1, kRecv = 2, kSend = 3, kClose = 4, kSetup = 5 };

uint64_t tag(uint8_t kind, uint16_t gen, uint32_t idx) {
  return (static_cast<uint64_t>(kind) << 56) | (static_cast<uint64_t>(gen) << 32) | idx;
}

// The setup chain's stages, carried in the idx half of the tag so a
// failing CQE can name what failed.
enum : uint32_t { kStSocket = 1, kStSockopt = 2, kStBind = 3, kStListen = 4 };

const char* stage_name(uint32_t st) {
  switch (st) {
    case kStSocket: return "socket";
    case kStSockopt: return "setsockopt";
    case kStBind: return "bind";
    case kStListen: return "listen";
  }
  return "?";
}

}  // namespace

Ring::~Ring() {
  if (ring_up_) {
    // The listener leaves through the ring like everything else did,
    // and a unix listener takes its path with it - waited on, because
    // queue_exit would race the unlink.
    unsigned n = 0;
    struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
    if (s != nullptr) {
      io_uring_prep_close_direct(s, kListenerSlot);
      io_uring_sqe_set_data64(s, tag(kClose, 0, kListenerSlot));
      n++;
    }
    if (!unix_path_.empty()) {
      s = io_uring_get_sqe(&ring_);
      if (s != nullptr) {
        io_uring_prep_unlink(s, unix_path_.c_str(), 0);
        io_uring_sqe_set_data64(s, tag(kSetup, 0, 0));
        n++;
      }
    }
    if (n != 0) io_uring_submit_and_wait(&ring_, n);
  }
  if (buf_ring_ != nullptr) io_uring_free_buf_ring(&ring_, buf_ring_, kBufCount, kBufGroup);
  if (pool_ != nullptr) ::munmap(pool_, static_cast<size_t>(kBufCount) * kBufSize);
  if (ring_up_) io_uring_queue_exit(&ring_);
}

bool Ring::init(const RingConfig& cfg, char* err, size_t errlen) {
  echo_ = cfg.echo;

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

  rc = io_uring_register_files_sparse(&ring_, kMaxConns + 1);  // +1: the listener's slot
  if (rc != 0) {
    std::snprintf(err, errlen, "register_files_sparse: %s", std::strerror(-rc));
    return false;
  }

  const size_t pool_bytes = static_cast<size_t>(kBufCount) * kBufSize;  // static_assert-bounded
  void* mem = ::mmap(nullptr, pool_bytes, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

  // --- the listener, made entirely of ring ops -----------------------
  //
  // A stale unix path goes first and UNLINKED from the chain: a linked
  // op that fails (ENOENT is normal here) would cancel everything
  // behind it.
  const bool is_unix = cfg.unix_path != nullptr;
  struct sockaddr_un sun {};
  struct sockaddr_in sin {};
  struct sockaddr* sa = nullptr;
  socklen_t salen = 0;
  if (is_unix) {
    sun.sun_family = AF_UNIX;
    const size_t plen = std::strlen(cfg.unix_path);
    if (plen >= sizeof(sun.sun_path)) {
      std::snprintf(err, errlen, "unix path too long (%zu)", plen);
      return false;
    }
    std::memcpy(sun.sun_path, cfg.unix_path, plen + 1);
    sa = reinterpret_cast<struct sockaddr*>(&sun);
    salen = sizeof(sun);

    struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
    if (s == nullptr) {
      std::snprintf(err, errlen, "SQ empty at setup");
      return false;
    }
    io_uring_prep_unlink(s, cfg.unix_path, 0);
    io_uring_sqe_set_data64(s, tag(kSetup, 0, 0));
    io_uring_submit_and_wait(&ring_, 1);
    struct io_uring_cqe* cqe = nullptr;
    if (io_uring_peek_cqe(&ring_, &cqe) == 0) {
      // Only ENOENT is ordinary; anything else on the path is a refusal.
      if (cqe->res < 0 && cqe->res != -ENOENT) {
        std::snprintf(err, errlen, "unlink %s: %s", cfg.unix_path, std::strerror(-cqe->res));
        return false;
      }
      io_uring_cqe_seen(&ring_, cqe);
    }
  } else {
    if (cfg.port <= 0 || cfg.port > 65535) {
      std::snprintf(err, errlen, "port %d out of range", cfg.port);
      return false;
    }
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(static_cast<uint16_t>(cfg.port));
    sa = reinterpret_cast<struct sockaddr*>(&sin);
    salen = sizeof(sin);
  }

  // socket -> (setsockopt) -> bind -> listen, one linked chain, one
  // submit. The addresses live on this frame; init blocks until the
  // chain's CQEs, so the borrow ends before the frame does.
  static const int kOne = 1;  // static: SO_REUSEADDR optval, borrowed by the ring op
  unsigned chain = 0;
  {
    struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
    if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
    io_uring_prep_socket_direct(s, is_unix ? AF_UNIX : AF_INET, SOCK_STREAM, 0, kListenerSlot, 0);
    s->flags |= IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, tag(kSetup, 0, kStSocket));
    chain++;

    if (!is_unix) {
      s = io_uring_get_sqe(&ring_);
      if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
      io_uring_prep_cmd_sock(s, SOCKET_URING_OP_SETSOCKOPT, kListenerSlot, SOL_SOCKET,
                             SO_REUSEADDR, const_cast<int*>(&kOne), sizeof(kOne));
      s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
      io_uring_sqe_set_data64(s, tag(kSetup, 0, kStSockopt));
      chain++;
    }

    s = io_uring_get_sqe(&ring_);
    if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
    io_uring_prep_bind(s, kListenerSlot, sa, salen);
    s->flags |= IOSQE_FIXED_FILE | IOSQE_IO_LINK;
    io_uring_sqe_set_data64(s, tag(kSetup, 0, kStBind));
    chain++;

    s = io_uring_get_sqe(&ring_);
    if (s == nullptr) { std::snprintf(err, errlen, "SQ empty at setup"); return false; }
    io_uring_prep_listen(s, kListenerSlot, 511);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, tag(kSetup, 0, kStListen));
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
          std::snprintf(err, errlen, "%s: %s", stage_name(st), std::strerror(-cqe->res));
          failed = true;
        } else if (err[0] == '\0') {
          std::snprintf(err, errlen, "setup chain canceled");
          failed = true;
        }
      }
    }
    io_uring_cq_advance(&ring_, seen);
    if (failed) return false;
  }
  // Only a bind that happened leaves a path to remove again.
  if (is_unix) unix_path_.assign(cfg.unix_path);

  conns_.resize(kMaxConns);
  rearm_.reserve(64);

  arm_accept();
  return true;
}

struct io_uring_sqe* Ring::sqe() {
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

void Ring::arm_accept() {
  struct io_uring_sqe* s = sqe();
  io_uring_prep_multishot_accept_direct(s, kListenerSlot, nullptr, nullptr, 0);
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_sqe_set_data64(s, tag(kAccept, 0, 0));
}

void Ring::arm_recv(uint32_t idx) {
  Conn& c = conns_[idx];
  struct io_uring_sqe* s = sqe();
  io_uring_prep_recv_multishot(s, static_cast<int>(idx), nullptr, 0, 0);
  s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
  s->buf_group = kBufGroup;
  if (bundles_) s->ioprio |= IORING_RECVSEND_BUNDLE;
  io_uring_sqe_set_data64(s, tag(kRecv, c.gen, idx));
}

void Ring::arm_send(uint32_t idx) {
  Conn& c = conns_[idx];
  struct io_uring_sqe* s = sqe();
  io_uring_prep_send(s, static_cast<int>(idx), c.out.data() + c.sent, c.out.size() - c.sent,
                     MSG_NOSIGNAL);
  s->flags |= IOSQE_FIXED_FILE;
  io_uring_sqe_set_data64(s, tag(kSend, c.gen, idx));
  c.sending = true;
}

void Ring::begin_close(uint32_t idx) {
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
  struct io_uring_sqe* s = sqe();
  io_uring_prep_close_direct(s, idx);
  io_uring_sqe_set_data64(s, tag(kClose, c.gen, idx));
}

void Ring::on_accept(struct io_uring_cqe* cqe) {
  if (!(cqe->flags & IORING_CQE_F_MORE)) arm_accept();
  if (cqe->res < 0) return;  // transient (EMFILE and friends); multishot may carry on  // transient (EMFILE and friends); multishot carries on
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
  arm_recv(idx);
}

void Ring::on_recv(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
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

  std::string& sink = c.sending ? c.next : c.out;
  if (!echo_) {
    // Production path: no per-buffer walk at all. The bundle's buffer
    // count is arithmetic (dense-fill contract, io_uring_prep_recv(3)):
    // every buffer full except the last.
    replenish_ += static_cast<unsigned>((total + kBufSize - 1) / kBufSize);
    // One answer per receive completion - the floor's whole protocol.
    sink.append(kResponse, kResponseLen);
  } else {
    // Echo (the bintest's byte-proof): walk the bundle, consecutive ids
    // from bid0, and give back exactly what arrived.
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
      sink.append(pool_ + off, n);
      left -= n;
      bid = (bid + 1) & (kBufCount - 1);
      replenish_++;
    }
  }

  if (!c.sending && !c.out.empty()) arm_send(idx);
  if (!(cqe->flags & IORING_CQE_F_MORE)) rearm_.push_back(idx);
}

void Ring::on_send(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
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
  if (WM_UNLIKELY(took > c.out.size() - c.sent || __builtin_add_overflow(c.sent, took, &new_sent))) {
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
  if (c.close_after_send) {
    c.close_after_send = false;
    begin_close(idx);
    return;
  }
  if (!c.next.empty()) {
    c.out.swap(c.next);
    arm_send(idx);
  }
}

void Ring::handle(struct io_uring_cqe* cqe) {
  const uint64_t ud = io_uring_cqe_get_data64(cqe);
  const uint8_t kind = static_cast<uint8_t>(ud >> 56);
  const uint16_t gen = static_cast<uint16_t>(ud >> 32);
  const uint32_t idx = static_cast<uint32_t>(ud);
  switch (kind) {
    case kAccept: on_accept(cqe); break;
    case kRecv: on_recv(idx, gen, cqe); break;
    case kSend: on_send(idx, gen, cqe); break;
    case kClose: break;  // the slot freed itself; nothing is owed
    default: break;
  }
}

void Ring::tick() {
  if (replenish_ != 0) {
    io_uring_buf_ring_advance(buf_ring_, static_cast<int>(replenish_));
    replenish_ = 0;
  }
  io_uring_submit_and_wait(&ring_, 1);
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
      if (c.live) arm_recv(idx);
    }
    rearm_.clear();
  }
}

void Ring::run(const volatile std::sig_atomic_t* stop) {
  while (!*stop) tick();
}

}  // namespace webmachine
