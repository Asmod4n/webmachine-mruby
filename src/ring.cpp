#include "ring.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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
enum : uint8_t { kAccept = 1, kRecv = 2, kSend = 3, kClose = 4 };

uint64_t tag(uint8_t kind, uint16_t gen, uint32_t idx) {
  return (static_cast<uint64_t>(kind) << 56) | (static_cast<uint64_t>(gen) << 32) | idx;
}

int make_listener(const RingConfig& cfg, char* err, size_t errlen) {
  int fd = -1;
  if (cfg.unix_path != nullptr) {
    struct sockaddr_un sa {};
    sa.sun_family = AF_UNIX;
    const size_t plen = std::strlen(cfg.unix_path);
    if (plen >= sizeof(sa.sun_path)) {
      std::snprintf(err, errlen, "unix path too long (%zu)", plen);
      return -1;
    }
    std::memcpy(sa.sun_path, cfg.unix_path, plen + 1);
    ::unlink(cfg.unix_path);
    fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || ::bind(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
      std::snprintf(err, errlen, "unix bind %s: %s", cfg.unix_path, std::strerror(errno));
      if (fd >= 0) ::close(fd);
      return -1;
    }
  } else {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      std::snprintf(err, errlen, "socket: %s", std::strerror(errno));
      return -1;
    }
    const int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa {};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(static_cast<uint16_t>(cfg.port));
    if (::bind(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
      std::snprintf(err, errlen, "bind port %d: %s", cfg.port, std::strerror(errno));
      ::close(fd);
      return -1;
    }
  }
  if (::listen(fd, 511) != 0) {
    std::snprintf(err, errlen, "listen: %s", std::strerror(errno));
    ::close(fd);
    return -1;
  }
  return fd;
}

}  // namespace

Ring::~Ring() {
  if (buf_ring_ != nullptr) io_uring_free_buf_ring(&ring_, buf_ring_, kBufCount, kBufGroup);
  if (pool_ != nullptr) ::munmap(pool_, static_cast<size_t>(kBufCount) * kBufSize);
  if (ring_up_) io_uring_queue_exit(&ring_);
  if (listen_fd_ >= 0) ::close(listen_fd_);
}

bool Ring::init(const RingConfig& cfg, char* err, size_t errlen) {
  echo_ = cfg.echo;

  listen_fd_ = make_listener(cfg, err, errlen);
  if (listen_fd_ < 0) return false;

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

  rc = io_uring_register_files_sparse(&ring_, kMaxConns);
  if (rc != 0) {
    std::snprintf(err, errlen, "register_files_sparse: %s", std::strerror(-rc));
    return false;
  }

  const size_t pool_bytes = static_cast<size_t>(kBufCount) * kBufSize;
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

  conns_.resize(kMaxConns);
  rearm_.reserve(64);

  arm_accept();
  return true;
}

struct io_uring_sqe* Ring::sqe() {
  struct io_uring_sqe* s = io_uring_get_sqe(&ring_);
  if (s != nullptr) return s;
  io_uring_submit(&ring_);
  s = io_uring_get_sqe(&ring_);
  if (s == nullptr) {
    std::fprintf(stderr, "webmachine: SQ stuck after submit; ring is broken\n");
    std::exit(1);
  }
  return s;
}

void Ring::arm_accept() {
  struct io_uring_sqe* s = sqe();
  io_uring_prep_multishot_accept_direct(s, listen_fd_, nullptr, nullptr, 0);
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
  if (cqe->res < 0) return;  // transient (EMFILE and friends); multishot carries on
  const uint32_t idx = static_cast<uint32_t>(cqe->res);
  if (idx >= kMaxConns) return;  // the kernel named a slot we never registered
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
  if (idx >= kMaxConns) return;
  Conn& c = conns_[idx];
  if (!c.live || c.gen != gen) return;  // a previous tenant's completion

  if (cqe->res <= 0) {
    if (cqe->res == -ENOBUFS) {
      // Pool ran dry mid-tick; buffers come back at the next tick's
      // advance, so the re-arm waits behind it.
      rearm_.push_back(idx);
      return;
    }
    // 0 = EOF; everything else ends the connection the same way.
    begin_close(idx);
    return;
  }

  if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
    begin_close(idx);
    return;
  }
  const uint32_t bid0 = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
  const size_t total = static_cast<size_t>(cqe->res);
  // Kernel-supplied values, checked before use: an id or length past the
  // pool would hand out someone else's memory.
  if (bid0 >= kBufCount || total > static_cast<size_t>(kBufCount) * kBufSize) {
    begin_close(idx);
    return;
  }

  // Bundle reconstruction, the documented contract (io_uring_prep_recv(3),
  // examples/proxy.c): consecutive ids from bid0, each buffer filled
  // completely except the last.
  std::string& sink = c.sending ? c.next : c.out;
  size_t left = total;
  uint32_t bid = bid0;
  while (left > 0) {
    const size_t n = left < kBufSize ? left : kBufSize;
    const char* p = pool_ + static_cast<size_t>(bid) * kBufSize;
    if (echo_) sink.append(p, n);
    left -= n;
    bid = (bid + 1) & (kBufCount - 1);
    replenish_++;
  }
  if (!echo_) {
    // One answer per receive completion - the floor's whole protocol.
    sink.append(kResponse, kResponseLen);
    served_++;
  }

  if (!c.sending && !c.out.empty()) arm_send(idx);
  if (!(cqe->flags & IORING_CQE_F_MORE)) rearm_.push_back(idx);
}

void Ring::on_send(uint32_t idx, uint16_t gen, struct io_uring_cqe* cqe) {
  if (idx >= kMaxConns) return;
  Conn& c = conns_[idx];
  if (c.gen != gen) return;
  c.sending = false;

  if (cqe->res < 0) {
    begin_close(idx);
    return;
  }
  c.sent += static_cast<size_t>(cqe->res);
  if (c.sent > c.out.size()) {  // the kernel cannot have taken more than offered
    begin_close(idx);
    return;
  }
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

void Ring::run() {
  for (;;) tick();
}

}  // namespace webmachine
