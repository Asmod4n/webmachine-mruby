#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {
#define WM_UNLIKELY(x) __builtin_expect(!!(x), 0)

constexpr char kResponse[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
constexpr size_t kResponseLen = sizeof(kResponse) - 1;

struct Conn {
  bool live = false;
  bool want_out = false;
  size_t sent = 0;
  std::string out;
};

struct Floor {
  int ep = -1;
  int lfd = -1;
  bool echo = false;
  std::vector<Conn> conns;

  // The measuring stick's connection table.
  // .DESIGN.md #floor "The floor binary"
  Conn& conn(int fd) {
    if (static_cast<size_t>(fd) >= conns.size()) conns.resize(static_cast<size_t>(fd) + 1);
    return conns[static_cast<size_t>(fd)];
  }

  // The measuring stick: close and forget.
  // .DESIGN.md #floor "The floor binary"
  void drop(int fd) {
    Conn& c = conns[static_cast<size_t>(fd)];
    c.live = false;
    c.want_out = false;
    c.sent = 0;
    c.out.clear();
    ::epoll_ctl(ep, EPOLL_CTL_DEL, fd, nullptr);
    ::close(fd);
  }

  // The measuring stick: push `out`; what it refuses waits for EPOLLOUT.
  // .DESIGN.md #floor "The floor binary"
  void flush(int fd) {
    Conn& c = conns[static_cast<size_t>(fd)];
    while (c.sent < c.out.size()) {
      const ssize_t n = ::send(fd, c.out.data() + c.sent, c.out.size() - c.sent,
                               MSG_NOSIGNAL | MSG_DONTWAIT);
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          if (!c.want_out) {
            struct epoll_event ev {};
            ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
            ev.data.fd = fd;
            ::epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev);
            c.want_out = true;
          }
          return;
        }
        if (errno == EINTR) continue;
        drop(fd);
        return;
      }
      size_t new_sent = 0;
      if (WM_UNLIKELY(__builtin_add_overflow(c.sent, static_cast<size_t>(n), &new_sent))) {
        drop(fd);
        return;
      }
      c.sent = new_sent;
    }
    c.out.clear();
    c.sent = 0;
    if (c.want_out) {
      struct epoll_event ev {};
      ev.events = EPOLLIN | EPOLLET;
      ev.data.fd = fd;
      ::epoll_ctl(ep, EPOLL_CTL_MOD, fd, &ev);
      c.want_out = false;
    }
  }

  // The measuring stick: edge-triggered, read until EAGAIN or the edge is lost.
  // .DESIGN.md #floor "The floor binary"
  void on_readable(int fd) {
    Conn& c = conn(fd);
    char buf[65536];
    for (;;) {
      const ssize_t n = ::recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
      if (n > 0) {
        if (echo) c.out.append(buf, static_cast<size_t>(n));
        else c.out.append(kResponse, kResponseLen);
        continue;
      }
      if (n == 0) {
        drop(fd);
        return;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      if (errno == EINTR) continue;
      drop(fd);
      return;
    }
    if (!c.out.empty()) flush(fd);
  }

  // The measuring stick: accept4 until EAGAIN.
  // .DESIGN.md #floor "The floor binary"
  void on_accept() {
    for (;;) {
      const int fd = ::accept4(lfd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
      if (fd < 0) return;
      Conn& c = conn(fd);
      c.live = true;
      c.want_out = false;
      c.sent = 0;
      c.out.clear();
      struct epoll_event ev {};
      ev.events = EPOLLIN | EPOLLET;
      ev.data.fd = fd;
      ::epoll_ctl(ep, EPOLL_CTL_ADD, fd, &ev);
    }
  }
};
}

// The measuring stick, not a product: the same floor protocol on epoll(7).
// The distance to the ring floor IS what io_uring buys on this hardware.
// .DESIGN.md #floor "The floor binary"
int main(int argc, char** argv) {
  const char* unix_path = nullptr;
  int port = 0;
  Floor f;
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--unix") == 0 && i + 1 < argc) {
      unix_path = argv[++i];
    } else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      port = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--echo") == 0) {
      f.echo = true;
    } else {
      std::fprintf(stderr, "usage: %s (--unix PATH | --port N) [--echo]\n", argv[0]);
      return 2;
    }
  }
  if ((unix_path == nullptr) == (port == 0)) {
    std::fprintf(stderr, "exactly one of --unix or --port\n");
    return 2;
  }

  struct sockaddr_un sun {};
  struct sockaddr_in sin {};
  struct sockaddr* sa = nullptr;
  socklen_t salen = 0;
  if (unix_path != nullptr) {
    const size_t plen = std::strlen(unix_path);
    if (plen >= sizeof(sun.sun_path)) {
      std::fprintf(stderr, "unix path too long (%zu)\n", plen);
      return 1;
    }
    sun.sun_family = AF_UNIX;
    std::memcpy(sun.sun_path, unix_path, plen + 1);
    sa = reinterpret_cast<struct sockaddr*>(&sun);
    salen = sizeof(sun);
    ::unlink(unix_path);
  } else {
    if (port <= 0 || port > 65535) {
      std::fprintf(stderr, "port %d out of range\n", port);
      return 1;
    }
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(static_cast<uint16_t>(port));
    sa = reinterpret_cast<struct sockaddr*>(&sin);
    salen = sizeof(sin);
  }

  f.lfd = ::socket(unix_path != nullptr ? AF_UNIX : AF_INET,
                   SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (f.lfd < 0) { std::perror("socket"); return 1; }
  if (unix_path == nullptr) {
    const int one = 1;
    ::setsockopt(f.lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  }
  if (::bind(f.lfd, sa, salen) != 0) { std::perror("bind"); return 1; }
  if (::listen(f.lfd, 511) != 0) { std::perror("listen"); return 1; }

  f.ep = ::epoll_create1(EPOLL_CLOEXEC);
  if (f.ep < 0) { std::perror("epoll_create1"); return 1; }
  {
    struct epoll_event ev {};
    ev.events = EPOLLIN;
    ev.data.fd = f.lfd;
    ::epoll_ctl(f.ep, EPOLL_CTL_ADD, f.lfd, &ev);
  }

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigprocmask(SIG_BLOCK, &mask, nullptr);
  const int stop_fd = signalfd(-1, &mask, SFD_CLOEXEC);
  {
    struct epoll_event ev {};
    ev.events = EPOLLIN;
    ev.data.fd = stop_fd;
    ::epoll_ctl(f.ep, EPOLL_CTL_ADD, stop_fd, &ev);
  }

  std::fprintf(stderr, "webmachine: epoll floor up, pid %d, %s%s\n", getpid(),
               unix_path != nullptr ? unix_path : "tcp", f.echo ? ", echo" : "");

  struct epoll_event evs[512];
  bool stop = false;
  while (!stop) {
    const int n = ::epoll_wait(f.ep, evs, 512, -1);
    if (n < 0) continue;
    for (int i = 0; i < n; i++) {
      const int fd = evs[i].data.fd;
      if (fd == stop_fd) {
        stop = true;
        continue;
      }
      if (fd == f.lfd) {
        f.on_accept();
        continue;
      }
      if (evs[i].events & (EPOLLHUP | EPOLLERR)) {
        f.drop(fd);
        continue;
      }
      if (evs[i].events & EPOLLIN) f.on_readable(fd);
      if ((evs[i].events & EPOLLOUT) && f.conns[static_cast<size_t>(fd)].live) f.flush(fd);
    }
  }

  ::close(f.lfd);
  if (unix_path != nullptr) ::unlink(unix_path);
  return 0;
}
