// webmachine-logd: the access log's prose half. Reads LogRec records
// (accesslog.hpp, the wire contract) from fd 0 - the socketpair the
// server forked us with - formats Combined Log Format, and batches to
// the file named in argv[1]. Lives on its own core, dies on the
// socket's EOF after draining everything, and NEVER drops a record:
// a write error is a named refusal with a nonzero exit the server's
// operator can see.
//
// Deliberately dumb: blocking reads, write(2) per filled batch, no
// ring, no threads. Its budget is enormous next to its load - the
// formatting it took off the serving core measured 71.5ns/line, and
// batched write(2) moves 3.8M lines/s in the slowest container this
// tree benches on.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "../../src/accesslog.hpp"

using webmachine::LogRec;
using webmachine::kLogH2;
using webmachine::kLogNoTrack;
using webmachine::kLogRecVersion;

static std::string out;
static int log_fd = -1;

static void flush_out() {
  size_t off = 0;
  while (off < out.size()) {
    const ssize_t n = ::write(log_fd, out.data() + off, out.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      std::fprintf(stderr, "webmachine-logd: write: %s - refusing to drop lines\n",
                   std::strerror(errno));
      std::exit(1);
    }
    off += static_cast<size_t>(n);
  }
  out.clear();
}

// "[23/Aug/2026:14:30:00 +0000]" - cached per second; records arrive
// in near-time order, so this hits almost always.
static int64_t ts_sec = -1;
// 28 bytes are ever read (the append below says so); the size gives
// snprintf its worst case - a five-digit year would truncate inside
// 29, and gcc rightly refuses to promise it cannot happen.
static char ts[40];
static void spell_ts(int64_t sec) {
  if (sec == ts_sec) return;
  ts_sec = sec;
  time_t t = static_cast<time_t>(sec);
  struct tm g;
  gmtime_r(&t, &g);
  static const char kMon[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  std::snprintf(ts, sizeof ts, "[%02d/%s/%04d:%02d:%02d:%02d +0000]", g.tm_mday,
                kMon[g.tm_mon], g.tm_year + 1900, g.tm_hour, g.tm_min, g.tm_sec);
}

// Quotes, backslashes and control bytes in request-controlled fields
// are escaped HERE - an attacker's header must not forge log columns,
// and the serving core no longer pays the scan.
static void esc(const char* p, size_t n) {
  for (size_t i = 0; i < n; i++) {
    const unsigned char c = static_cast<unsigned char>(p[i]);
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(char(c));
    } else if (c < 0x20 || c == 0x7f) {
      static const char hex[] = "0123456789abcdef";
      out.append("\\x", 2);
      out.push_back(hex[c >> 4]);
      out.push_back(hex[c & 15]);
    } else {
      out.push_back(char(c));
    }
  }
}

static void spell_num(size_t v) {
  char tmp[20];
  size_t k = 0;
  do { tmp[k++] = char('0' + v % 10); v /= 10; } while (v != 0);
  while (k != 0) out.push_back(tmp[--k]);
}

// %h from the record's RAW sockaddr. The level names the amount of
// PRIVACY the peer gets, not the amount of address the operator gets:
//   none  no privacy - the address as-is. A full IP is personal data
//         under the GDPR; the server warns at startup that logging it
//         needs a legal basis (consent banner / privacy notice).
//   anon  IPv4 with the last octet zeroed, IPv6 cut to its /48 - the
//         common GDPR anonymization the apache/nginx modules apply
//   full  full privacy - every host spells "-"
// The SERVER never sees a spelled address; the raw bytes exist only in
// transit and, at anon/full, never reach the disk at all.
enum class Privacy { kNone, kAnon, kFull };
static Privacy privacy = Privacy::kAnon;

// no_track: the record carries the peer's own "do not track" ask
// (DNT/Sec-GPC) - it caps the level at anon whatever the operator
// chose. It can only ever ADD privacy, never remove it.
static void spell_peer(const char* sa, size_t salen, bool no_track) {
  Privacy level = privacy;
  if (no_track && level == Privacy::kNone) level = Privacy::kAnon;
  if (level == Privacy::kFull || salen < 2) { out.push_back('-'); return; }
  const uint16_t fam = static_cast<uint16_t>(static_cast<unsigned char>(sa[0]) |
                                             (static_cast<unsigned char>(sa[1]) << 8));
  char txt[INET6_ADDRSTRLEN] = {};
  if (fam == AF_INET && salen >= sizeof(struct sockaddr_in)) {
    struct sockaddr_in v4;
    std::memcpy(&v4, sa, sizeof v4);
    if (level == Privacy::kAnon) {
      v4.sin_addr.s_addr &= htonl(0xffffff00u);
    }
    inet_ntop(AF_INET, &v4.sin_addr, txt, sizeof txt);
  } else if (fam == AF_INET6 && salen >= sizeof(struct sockaddr_in6)) {
    struct sockaddr_in6 v6;
    std::memcpy(&v6, sa, sizeof v6);
    if (level == Privacy::kAnon) {
      std::memset(v6.sin6_addr.s6_addr + 6, 0, 10);  // keep the /48
    }
    inet_ntop(AF_INET6, &v6.sin6_addr, txt, sizeof txt);
  } else {
    out.push_back('-');
    return;
  }
  if (txt[0] == '\0') { out.push_back('-'); return; }
  out.append(txt);
}

int main(int argc, char** argv) {
  if (argc < 2 || argc > 3) {
    std::fprintf(stderr, "usage: webmachine-logd FILE [full|anon|none]  (records on fd 0)\n");
    return 2;
  }
  if (argc == 3) {
    if (std::strcmp(argv[2], "anon") == 0) privacy = Privacy::kAnon;
    else if (std::strcmp(argv[2], "none") == 0) privacy = Privacy::kNone;
    else if (std::strcmp(argv[2], "full") == 0) privacy = Privacy::kFull;
    else {
      std::fprintf(stderr, "webmachine-logd: privacy '%s'? none, anon or full\n", argv[2]);
      return 2;
    }
  }
  log_fd = ::open(argv[1], O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (log_fd < 0) {
    std::fprintf(stderr, "webmachine-logd: %s: %s\n", argv[1], std::strerror(errno));
    return 1;
  }

  std::string in;
  char rbuf[256 * 1024];
  out.reserve(1u << 20);
  for (;;) {
    const ssize_t n = ::read(0, rbuf, sizeof rbuf);
    if (n < 0) {
      if (errno == EINTR) continue;
      std::fprintf(stderr, "webmachine-logd: read: %s\n", std::strerror(errno));
      flush_out();
      return 1;
    }
    if (n == 0) {  // the server is gone; everything received still lands
      flush_out();
      return 0;
    }
    in.append(rbuf, static_cast<size_t>(n));

    size_t off = 0;
    while (in.size() - off >= sizeof(LogRec)) {
      LogRec r;
      std::memcpy(&r, in.data() + off, sizeof r);
      if (r.version != kLogRecVersion) {
        std::fprintf(stderr, "webmachine-logd: record version %u, built for %u - refusing\n",
                     r.version, kLogRecVersion);
        flush_out();
        return 1;
      }
      const size_t need = sizeof(LogRec) + r.mlen + r.plen + r.tlen + r.rlen + r.ulen;
      if (in.size() - off < need) break;
      const char* p = in.data() + off + sizeof(LogRec);
      const char* method = p;               p += r.mlen;
      const char* peer = p;                 p += r.plen;
      const char* target = p;               p += r.tlen;
      const char* ref = p;                  p += r.rlen;
      const char* ua = p;

      spell_ts(r.sec);
      if (r.plen != 0) spell_peer(peer, r.plen, (r.flags & kLogNoTrack) != 0);
      else out.push_back('-');
      out.append(" - - ", 5);
      out.append(ts, 28);
      out.append(" \"", 2);
      if (r.mlen != 0) esc(method, r.mlen); else out.push_back('-');
      out.push_back(' ');
      esc(target, r.tlen);
      const bool h2 = (r.flags & kLogH2) != 0;
      out.append(h2 ? " HTTP/2\" " : " HTTP/1.1\" ", h2 ? 9 : 11);
      out.push_back(char('0' + r.status / 100));
      out.push_back(char('0' + r.status / 10 % 10));
      out.push_back(char('0' + r.status % 10));
      out.push_back(' ');
      if (r.bytes == 0) out.push_back('-'); else spell_num(r.bytes);
      out.append(" \"", 2);
      if (r.rlen != 0) esc(ref, r.rlen); else out.push_back('-');
      out.append("\" \"", 3);
      if (r.ulen != 0) esc(ua, r.ulen); else out.push_back('-');
      out.append("\"\n", 2);

      off += need;
      if (out.size() >= (1u << 20)) flush_out();
    }
    in.erase(0, off);
  }
}
