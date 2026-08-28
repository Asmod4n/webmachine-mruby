// The load generator (#196). Not a wrk clone: the SAME loop the reactor
// runs, with the roles swapped - connect instead of accept, multishot recv
// out of a provided buffer ring, bundles where the kernel offers them, one
// enter carrying hundreds of completions. wrk costs about three times as
// much per request as the server does, so on a fast host the client, not
// webmachine, is what bench/floor.sh ends up measuring; its own REFUSED
// rule then blocks the run and raising THREADS stops helping.
//
//   load --sock PATH [--conns N] [--seconds S] [--path P] [--host H]
//   load --host 127.0.0.1 --port 8123 [...]
//
// Prints one line of counts. wrk stays the ORACLE: a number from here
// means nothing until wrk says the same thing on the same box, because
// this client SHARES phr, the framing assumptions and the ring patterns
// with the server - a shared misunderstanding would not show up.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>

#include "liburing.h"

extern "C" {
#include "picohttpparser.h"
}

namespace {

// The reactor's own geometry, so the two ends are priced the same way.
constexpr unsigned kBufCount = 2048;
constexpr unsigned kBufSize = 4096;
constexpr unsigned kBufGroup = 1;
constexpr unsigned kSqEntries = 16384;

enum : uint8_t { kOpRecv = 1, kOpSend = 2 };

inline uint64_t tag(uint8_t op, uint32_t idx) {
  return (static_cast<uint64_t>(op) << 56) | idx;
}

int64_t now_ns() {
  struct timespec t {};
  ::clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<int64_t>(t.tv_sec) * 1000000000 + t.tv_nsec;
}

// One connection: what it still owes of the response it is reading, and a
// carry for the rare head that a buffer boundary split.
struct Conn {
  int fd = -1;
  size_t body_left = 0;   // RFC 9110 8.6: content still to arrive
  bool in_body = false;
  std::string carry;      // only used when a HEAD spans two buffers
  uint64_t done = 0;
};

struct Load {
  struct io_uring ring {};
  struct io_uring_buf_ring* br = nullptr;
  char* pool = nullptr;
  std::vector<Conn> conns;
  std::vector<int> fds;
  std::string request;
  bool bundles = false;
  unsigned replenish = 0;
  uint64_t responses = 0;
  uint64_t bad = 0;
  std::vector<uint32_t> to_send;

  struct io_uring_sqe* sqe() {
    struct io_uring_sqe* s = io_uring_get_sqe(&ring);
    if (s != nullptr) return s;
    io_uring_submit(&ring);
    s = io_uring_get_sqe(&ring);
    if (s == nullptr) {
      std::fprintf(stderr, "load: SQ stuck after submit\n");
      std::exit(1);
    }
    return s;
  }

  void arm_recv(uint32_t idx) {
    struct io_uring_sqe* s = sqe();
    io_uring_prep_recv_multishot(s, static_cast<int>(idx), nullptr, 0, 0);
    s->flags |= IOSQE_BUFFER_SELECT | IOSQE_FIXED_FILE;
    s->buf_group = kBufGroup;
    if (bundles) s->ioprio |= IORING_RECVSEND_BUNDLE;
    io_uring_sqe_set_data64(s, tag(kOpRecv, idx));
  }

  void arm_send(uint32_t idx) {
    struct io_uring_sqe* s = sqe();
    io_uring_prep_send(s, static_cast<int>(idx), request.data(), request.size(), MSG_NOSIGNAL);
    s->flags |= IOSQE_FIXED_FILE;
    io_uring_sqe_set_data64(s, tag(kOpSend, idx));
  }

  // RFC 9112 3: count RESPONSES, not bytes - a head, then exactly the
  // content its Content-Length promised, then the next request goes out.
  void feed(uint32_t idx, const char* p, size_t n) {
    Conn& c = conns[idx];
    while (n != 0) {
      if (c.in_body) {
        const size_t take = n < c.body_left ? n : c.body_left;
        c.body_left -= take;
        p += take;
        n -= take;
        if (c.body_left == 0) {
          c.in_body = false;
          c.done++;
          responses++;
          to_send.push_back(idx);
        }
        continue;
      }
      const char* head = p;
      size_t head_len = n;
      if (!c.carry.empty()) {
        c.carry.append(p, n);
        head = c.carry.data();
        head_len = c.carry.size();
      }
      int minor = 0, status = 0;
      const char* msg = nullptr;
      size_t msg_len = 0;
      struct phr_header hdr[64];
      size_t nhdr = sizeof(hdr) / sizeof(hdr[0]);
      const int r = phr_parse_response(head, head_len, &minor, &status, &msg, &msg_len, hdr,
                                       &nhdr, 0);
      if (r == -2) {
        if (c.carry.empty()) c.carry.assign(p, n);
        return;
      }
      if (r < 0) {
        bad++;
        c.carry.clear();
        return;
      }
      size_t clen = 0;
      for (size_t i = 0; i < nhdr; i++) {
        if (hdr[i].name_len == 14 && strncasecmp(hdr[i].name, "Content-Length", 14) == 0) {
          clen = static_cast<size_t>(std::strtoull(std::string(hdr[i].value, hdr[i].value_len)
                                                       .c_str(),
                                                   nullptr, 10));
        }
      }
      const size_t consumed = static_cast<size_t>(r);
      const size_t rest = head_len - consumed;
      c.in_body = true;
      c.body_left = clen;
      if (!c.carry.empty()) {
        // The carry held the split head; what follows it is the content.
        std::string tail(head + consumed, rest);
        c.carry.clear();
        if (!tail.empty()) feed(idx, tail.data(), tail.size());
        else if (clen == 0) {
          c.in_body = false;
          c.done++;
          responses++;
          to_send.push_back(idx);
        }
        return;
      }
      p += consumed;
      n -= consumed;
      if (clen == 0) {
        c.in_body = false;
        c.done++;
        responses++;
        to_send.push_back(idx);
      }
    }
  }

  void on_recv(uint32_t idx, struct io_uring_cqe* cqe) {
    if (cqe->res <= 0) {
      if (cqe->res == -ENOBUFS) {
        arm_recv(idx);
        return;
      }
      return;
    }
    if (!(cqe->flags & IORING_CQE_F_BUFFER)) return;
    uint32_t bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    size_t left = static_cast<size_t>(cqe->res);
    while (left != 0) {
      const size_t take = left < kBufSize ? left : kBufSize;
      feed(idx, pool + static_cast<size_t>(bid) * kBufSize, take);
      left -= take;
      bid = (bid + 1) & (kBufCount - 1);
      replenish++;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) arm_recv(idx);
  }
};

int connect_unix(const char* path) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  struct sockaddr_un sa {};
  sa.sun_family = AF_UNIX;
  std::snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
  if (::connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

int connect_tcp(const char* host, int port) {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  int one = 1;
  ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  struct sockaddr_in sa {};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(static_cast<uint16_t>(port));
  if (::inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
    ::close(fd);
    return -1;
  }
  if (::connect(fd, reinterpret_cast<struct sockaddr*>(&sa), sizeof(sa)) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

}  // namespace

int main(int argc, char** argv) {
  const char* sock = nullptr;
  const char* host = nullptr;
  const char* hdr_host = "localhost";
  const char* path = "/";
  int port = 0;
  int conns = 64;
  double seconds = 5.0;
  for (int i = 1; i < argc; i++) {
    const auto next = [&]() -> const char* { return i + 1 < argc ? argv[++i] : nullptr; };
    if (std::strcmp(argv[i], "--sock") == 0) sock = next();
    else if (std::strcmp(argv[i], "--host") == 0) host = next();
    else if (std::strcmp(argv[i], "--port") == 0) port = std::atoi(next());
    else if (std::strcmp(argv[i], "--conns") == 0) conns = std::atoi(next());
    else if (std::strcmp(argv[i], "--seconds") == 0) seconds = std::atof(next());
    else if (std::strcmp(argv[i], "--path") == 0) path = next();
    else if (std::strcmp(argv[i], "--host-header") == 0) hdr_host = next();
    else {
      std::fprintf(stderr, "load: unknown argument %s\n", argv[i]);
      return 2;
    }
  }
  if ((sock == nullptr) == (host == nullptr)) {
    std::fprintf(stderr, "load: exactly one of --sock PATH or --host H --port P\n");
    return 2;
  }
  if (conns <= 0 || conns > 4096) {
    std::fprintf(stderr, "load: --conns must be 1..4096\n");
    return 2;
  }

  Load L;
  L.request.assign("GET ").append(path).append(" HTTP/1.1\r\nHost: ").append(hdr_host).append(
      "\r\n\r\n");
  L.conns.resize(static_cast<size_t>(conns));
  L.fds.resize(static_cast<size_t>(conns));
  for (int i = 0; i < conns; i++) {
    const int fd = sock != nullptr ? connect_unix(sock) : connect_tcp(host, port);
    if (fd < 0) {
      std::fprintf(stderr, "load: connect %d/%d failed: %s\n", i + 1, conns,
                   std::strerror(errno));
      return 1;
    }
    L.conns[static_cast<size_t>(i)].fd = fd;
    L.fds[static_cast<size_t>(i)] = fd;
  }

  struct io_uring_params p {};
  p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_COOP_TASKRUN;
  int rc = io_uring_queue_init_params(kSqEntries, &L.ring, &p);
  if (rc != 0) {
    std::fprintf(stderr, "load: queue_init: %s\n", std::strerror(-rc));
    return 1;
  }
  io_uring_register_ring_fd(&L.ring);
  rc = io_uring_register_files(&L.ring, L.fds.data(), static_cast<unsigned>(conns));
  if (rc != 0) {
    std::fprintf(stderr, "load: register_files: %s\n", std::strerror(-rc));
    return 1;
  }
  void* mem = ::mmap(nullptr, static_cast<size_t>(kBufCount) * kBufSize,
                     PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mem == MAP_FAILED) {
    std::fprintf(stderr, "load: mmap pool: %s\n", std::strerror(errno));
    return 1;
  }
  L.pool = static_cast<char*>(mem);
  int bre = 0;
  L.br = io_uring_setup_buf_ring(&L.ring, kBufCount, kBufGroup, 0, &bre);
  if (L.br == nullptr) {
    std::fprintf(stderr, "load: setup_buf_ring: %s\n", std::strerror(-bre));
    return 1;
  }
  const int mask = io_uring_buf_ring_mask(kBufCount);
  for (uint32_t i = 0; i < kBufCount; i++) {
    io_uring_buf_ring_add(L.br, L.pool + static_cast<size_t>(i) * kBufSize, kBufSize,
                          static_cast<uint16_t>(i), mask, static_cast<int>(i));
  }
  io_uring_buf_ring_advance(L.br, kBufCount);
  L.bundles = (L.ring.features & IORING_FEAT_RECVSEND_BUNDLE) != 0;
  if (const char* e = std::getenv("WM_BUNDLE")) {
    if (e[0] == '0') L.bundles = false;
  }

  for (int i = 0; i < conns; i++) {
    L.arm_recv(static_cast<uint32_t>(i));
    L.arm_send(static_cast<uint32_t>(i));
  }

  const int64_t t0 = now_ns();
  const int64_t deadline = t0 + static_cast<int64_t>(seconds * 1e9);
  for (;;) {
    const int64_t left = deadline - now_ns();
    if (left <= 0) break;
    struct __kernel_timespec ts {left / 1000000000, left % 1000000000};
    struct io_uring_cqe* first = nullptr;
    io_uring_submit_and_wait_timeout(&L.ring, &first, 1, &ts, nullptr);

    unsigned head = 0;
    struct io_uring_cqe* cqe = nullptr;
    unsigned seen = 0;
    io_uring_for_each_cqe(&L.ring, head, cqe) {
      const uint64_t d = io_uring_cqe_get_data64(cqe);
      const uint8_t op = static_cast<uint8_t>(d >> 56);
      const uint32_t idx = static_cast<uint32_t>(d & 0xffffffffu);
      if (op == kOpRecv) L.on_recv(idx, cqe);
      seen++;
    }
    io_uring_cq_advance(&L.ring, seen);
    if (L.replenish != 0) {
      io_uring_buf_ring_advance(L.br, static_cast<int>(L.replenish));
      L.replenish = 0;
    }
    for (uint32_t idx : L.to_send) L.arm_send(idx);
    L.to_send.clear();
  }
  const double elapsed = static_cast<double>(now_ns() - t0) / 1e9;

  std::printf("responses=%llu bad=%llu seconds=%.3f rps=%.0f conns=%d bundles=%d\n",
              static_cast<unsigned long long>(L.responses),
              static_cast<unsigned long long>(L.bad), elapsed,
              static_cast<double>(L.responses) / elapsed, conns, L.bundles ? 1 : 0);
  return 0;
}
