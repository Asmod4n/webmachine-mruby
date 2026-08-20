// The echo probe: what does the RING itself cost against plain
// recv/send, with everything else stripped away? One unix socket, one
// connection, ping-pong - no HTTP, no mruby, no pools, no multishot.
// The uring path uses the reactor's own setup flags (SINGLE_ISSUER |
// DEFER_TASKRUN | COOP_TASKRUN, see src/ring.hpp) so the number prices
// the submission model the server actually runs, not a generic ring.
//
// Roles and modes compose freely:
//   echo_bench --server sys|uring|uring-ms --sock PATH
//   echo_bench --client sys|uring --sock PATH [--size N] [--seconds S]
//
// uring-ms is the reactor's own receive shape: multishot recv armed
// once, one submit_and_wait per exchange. Plain uring (one-shot
// recv + send, two enters per exchange) is the strawman a naive port
// would write - kept as the middle rung of the ladder.
//
// The server echoes one connection until EOF, then exits. The client
// ping-pongs SIZE-byte messages for SECONDS, then reports round trips
// per second and RTT p50/p99 from per-iteration samples. Setup
// (socket/bind/listen/accept/connect) is plain syscalls in both modes:
// this probe prices the DATA path, not the setup path.

#include <liburing.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>

namespace {

[[noreturn]] void die(const char* what) {
  perror(what);
  exit(1);
}

// One submission, one completion, ping-pong deep - the shape a single
// echo exchange has. submit_and_wait is the reactor's own wait.
struct Uring {
  struct io_uring ring;
  void init() {
    struct io_uring_params p;
    std::memset(&p, 0, sizeof(p));
    p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN |
              IORING_SETUP_COOP_TASKRUN;
    const int rc = io_uring_queue_init_params(64, &ring, &p);
    if (rc < 0) {
      std::fprintf(stderr, "io_uring_queue_init: %s\n", std::strerror(-rc));
      exit(1);
    }
  }
  ssize_t op(bool is_recv, int fd, void* buf, size_t n) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    if (sqe == nullptr) die("get_sqe");
    if (is_recv) io_uring_prep_recv(sqe, fd, buf, n, 0);
    else io_uring_prep_send(sqe, fd, buf, n, 0);
    const int rc = io_uring_submit_and_wait(&ring, 1);
    if (rc < 0) {
      std::fprintf(stderr, "submit_and_wait: %s\n", std::strerror(-rc));
      exit(1);
    }
    struct io_uring_cqe* cqe;
    if (io_uring_peek_cqe(&ring, &cqe) != 0) die("peek_cqe");
    const ssize_t res = cqe->res;
    io_uring_cqe_seen(&ring, cqe);
    return res;
  }
};

// The two data paths behind one shape: mode 0 = syscalls, 1 = uring.
struct Io {
  int mode = 0;
  Uring u;
  void init(int m) {
    mode = m;
    if (mode == 1) u.init();
  }
  ssize_t rx(int fd, void* b, size_t n) {
    return mode == 1 ? u.op(true, fd, b, n) : ::recv(fd, b, n, 0);
  }
  ssize_t tx(int fd, void* b, size_t n) {
    return mode == 1 ? u.op(false, fd, b, n) : ::send(fd, b, n, 0);
  }
  bool tx_all(int fd, const char* b, size_t n) {
    size_t off = 0;
    while (off < n) {
      const ssize_t r = tx(fd, const_cast<char*>(b) + off, n - off);
      if (r <= 0) return false;
      off += static_cast<size_t>(r);
    }
    return true;
  }
  bool rx_all(int fd, char* b, size_t n) {
    size_t off = 0;
    while (off < n) {
      const ssize_t r = rx(fd, b + off, n - off);
      if (r <= 0) return false;
      off += static_cast<size_t>(r);
    }
    return true;
  }
};

// The reactor's actual receive shape (src/ring.hpp): multishot recv
// over a provided-buffer ring, armed ONCE; per exchange the loop pays
// ONE io_uring_enter - the send submits and the wait counts the
// in-flight send's completion alongside the next request's arrival
// (wait_nr = 2). The plain uring mode above is the strawman a naive
// port would write - two enters per exchange, kept as the middle rung.
int run_server_multishot(int fd) {
  Uring u;
  u.init();
  constexpr unsigned kBufs = 8;
  constexpr size_t kBufSz = 1u << 16;
  std::vector<char> mem(kBufs * kBufSz);
  int rc = 0;
  struct io_uring_buf_ring* br = io_uring_setup_buf_ring(&u.ring, kBufs, 0, 0, &rc);
  if (br == nullptr) {
    std::fprintf(stderr, "setup_buf_ring: %s\n", std::strerror(-rc));
    exit(1);
  }
  const int mask = io_uring_buf_ring_mask(kBufs);
  for (unsigned i = 0; i < kBufs; i++) {
    io_uring_buf_ring_add(br, mem.data() + i * kBufSz, kBufSz, static_cast<unsigned short>(i),
                          mask, static_cast<int>(i));
  }
  io_uring_buf_ring_advance(br, kBufs);

  const auto arm = [&] {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&u.ring);
    if (sqe == nullptr) die("get_sqe");
    io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = 0;
    sqe->user_data = 1;
  };
  arm();
  bool send_pending = false;
  for (;;) {
    rc = io_uring_submit_and_wait(&u.ring, send_pending ? 2u : 1u);
    if (rc < 0) die("submit_and_wait");
    struct io_uring_cqe* cqe;
    unsigned head, seen = 0;
    ssize_t got = -1;
    unsigned short bid = 0;
    bool rearm = false, dead = false;
    io_uring_for_each_cqe(&u.ring, head, cqe) {
      seen++;
      if (cqe->user_data == 1) {  // recv: the payload sits in buffer bid
        if (cqe->res <= 0) {
          dead = true;
        } else {
          got = cqe->res;
          bid = static_cast<unsigned short>(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
        }
        if (!(cqe->flags & IORING_CQE_F_MORE)) rearm = true;
      } else {  // send done: its buffer goes back to the ring
        send_pending = false;
        if (cqe->res <= 0) dead = true;
        const unsigned short done = static_cast<unsigned short>(cqe->user_data >> 8);
        io_uring_buf_ring_add(br, mem.data() + done * kBufSz, kBufSz, done, mask, 0);
        io_uring_buf_ring_advance(br, 1);
      }
    }
    io_uring_cq_advance(&u.ring, seen);
    if (dead) break;
    if (rearm) arm();
    if (got > 0) {
      // Echo straight out of the selected buffer; it is re-provided
      // when the send completes. Short sends do not happen at these
      // sizes on a unix socket - the probe asserts rather than
      // degrades (dead above).
      struct io_uring_sqe* sqe = io_uring_get_sqe(&u.ring);
      if (sqe == nullptr) die("get_sqe");
      io_uring_prep_send(sqe, fd, mem.data() + bid * kBufSz, static_cast<size_t>(got), 0);
      sqe->user_data = 2 | (static_cast<uint64_t>(bid) << 8);
      send_pending = true;
    }
  }
  return 0;
}

int run_server(int mode, const char* path) {
  ::unlink(path);
  const int ls = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (ls < 0) die("socket");
  struct sockaddr_un sa;
  std::memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  std::strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
  if (::bind(ls, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) die("bind");
  if (::listen(ls, 1) < 0) die("listen");
  const int fd = ::accept(ls, nullptr, nullptr);
  if (fd < 0) die("accept");

  if (mode == 2) {
    run_server_multishot(fd);
  } else {
    Io io;
    io.init(mode);
    std::vector<char> buf(1u << 16);
    for (;;) {
      const ssize_t n = io.rx(fd, buf.data(), buf.size());
      if (n <= 0) break;  // EOF ends the probe; errors end it the same way
      if (!io.tx_all(fd, buf.data(), static_cast<size_t>(n))) break;
    }
  }
  ::close(fd);
  ::close(ls);
  ::unlink(path);
  return 0;
}

uint64_t now_ns() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<uint64_t>(ts.tv_nsec);
}

int run_client(int mode, const char* path, size_t size, unsigned seconds) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) die("socket");
  struct sockaddr_un sa;
  std::memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  std::strncpy(sa.sun_path, path, sizeof(sa.sun_path) - 1);
  if (::connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) < 0) die("connect");

  Io io;
  io.init(mode);
  std::vector<char> out(size, 'x');
  std::vector<char> in(size);

  for (int i = 0; i < 1000; i++) {  // warm: pages, branch state, sk buffers
    if (!io.tx_all(fd, out.data(), size) || !io.rx_all(fd, in.data(), size)) die("warmup");
  }

  std::vector<uint32_t> rtt;
  rtt.reserve(4u << 20);
  const uint64_t end = now_ns() + static_cast<uint64_t>(seconds) * 1000000000ull;
  uint64_t t = now_ns();
  while (t < end) {
    if (!io.tx_all(fd, out.data(), size) || !io.rx_all(fd, in.data(), size)) die("exchange");
    const uint64_t t2 = now_ns();
    rtt.push_back(static_cast<uint32_t>(t2 - t));
    t = t2;
  }
  ::close(fd);

  const size_t n = rtt.size();
  std::sort(rtt.begin(), rtt.end());
  const double secs = 0;
  (void)secs;
  double total_ns = 0;
  for (uint32_t v : rtt) total_ns += v;
  std::printf("size=%zu %zu rt in %.2fs = %.0f rt/s, rtt p50=%.2fus p99=%.2fus\n", size, n,
              total_ns / 1e9, n / (total_ns / 1e9), rtt[n / 2] / 1000.0,
              rtt[(n * 99) / 100] / 1000.0);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  const char* role = nullptr;
  int mode = -1;
  const char* sock = nullptr;
  size_t size = 16;
  unsigned seconds = 5;
  for (int i = 1; i < argc; i++) {
    const auto is = [&](const char* s) { return std::strcmp(argv[i], s) == 0; };
    if ((is("--server") || is("--client")) && i + 1 < argc) {
      role = argv[i] + 2;
      const char* m = argv[++i];
      mode = std::strcmp(m, "uring") == 0      ? 1
             : std::strcmp(m, "sys") == 0      ? 0
             : std::strcmp(m, "uring-ms") == 0 ? 2
                                               : -1;
    } else if (is("--sock") && i + 1 < argc) {
      sock = argv[++i];
    } else if (is("--size") && i + 1 < argc) {
      size = static_cast<size_t>(std::strtoul(argv[++i], nullptr, 10));
    } else if (is("--seconds") && i + 1 < argc) {
      seconds = static_cast<unsigned>(std::strtoul(argv[++i], nullptr, 10));
    }
  }
  if (role == nullptr || mode < 0 || sock == nullptr || size == 0 || size > (1u << 16)) {
    std::fprintf(stderr,
                 "usage: echo_bench --server sys|uring --sock PATH\n"
                 "       echo_bench --client sys|uring --sock PATH [--size N<=65536] "
                 "[--seconds S]\n");
    return 2;
  }
  return std::strcmp(role, "server") == 0 ? run_server(mode, sock)
                                          : run_client(mode, sock, size, seconds);
}
