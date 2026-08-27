// Design decisions live in .DESIGN.md, filed under what each comment names.
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

#include "../../src/webmachine.hpp"

using webmachine::ErrRec;
using webmachine::LogRec;
using webmachine::kErrRecVersion;
using webmachine::kLogH2;
using webmachine::kLogNoTrack;
using webmachine::kLogRecVersion;

static std::string out;
static int log_fd = -1;
static size_t max_bytes = 0;
static size_t on_disk = 0;

// The hard ceiling: keep the NEWEST bytes, drop the oldest, in place.
// The cut lands on a whole ENTRY, never mid-record.
static void enforce_cap() {
  if (max_bytes == 0 || on_disk <= max_bytes) return;
  const size_t keep = max_bytes / 2;
  std::string tail;
  tail.resize(keep);
  const off_t from = static_cast<off_t>(on_disk - keep);
  size_t got = 0;
  while (got < keep) {
    const ssize_t n = ::pread(log_fd, &tail[got], keep - got, from + static_cast<off_t>(got));
    if (n < 0) {
      if (errno == EINTR) continue;
      std::fprintf(stderr, "webmachine-logd: pread while capping: %s\n", std::strerror(errno));
      std::exit(1);
    }
    if (n == 0) break;
    got += static_cast<size_t>(n);
  }
  tail.resize(got);
  const size_t nl = tail.find('\n');
  size_t start = nl == std::string::npos ? 0 : nl + 1;
  while (start < tail.size() && tail[start] == '\t') {
    const size_t next = tail.find('\n', start);
    if (next == std::string::npos) { start = tail.size(); break; }
    start = next + 1;
  }
  const size_t len = tail.size() - start;
  size_t off = 0;
  while (off < len) {
    const ssize_t n = ::pwrite(log_fd, tail.data() + start + off, len - off,
                               static_cast<off_t>(off));
    if (n < 0) {
      if (errno == EINTR) continue;
      std::fprintf(stderr, "webmachine-logd: pwrite while capping: %s\n", std::strerror(errno));
      std::exit(1);
    }
    off += static_cast<size_t>(n);
  }
  if (::ftruncate(log_fd, static_cast<off_t>(len)) != 0) {
    std::fprintf(stderr, "webmachine-logd: ftruncate while capping: %s\n", std::strerror(errno));
    std::exit(1);
  }
  if (::lseek(log_fd, 0, SEEK_END) < 0) {
    std::fprintf(stderr, "webmachine-logd: lseek while capping: %s\n", std::strerror(errno));
    std::exit(1);
  }
  on_disk = len;
}

// One write(2) per filled batch. A write error is a named refusal.
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
  on_disk += out.size();
  out.clear();
  enforce_cap();
}

static int64_t ts_sec = -1;
static char ts[40];
// Combined Log Format: "[23/Aug/2026:14:30:00 +0000]", cached per second.
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

// Escaping happens HERE: an attacker's header must not forge log columns.
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

// Combined Log Format: %b, by hand.
static void spell_num(size_t v) {
  char tmp[20];
  size_t k = 0;
  do { tmp[k++] = char('0' + v % 10); v /= 10; } while (v != 0);
  while (k != 0) out.push_back(tmp[--k]);
}

enum class Privacy { kNone, kAnon, kFull };
static Privacy privacy = Privacy::kAnon;

// Combined Log Format %h, at the operator's PRIVACY level; DNT/Sec-GPC
// can only ever add privacy.
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
      std::memset(v6.sin6_addr.s6_addr + 6, 0, 10);
    }
    inet_ntop(AF_INET6, &v6.sin6_addr, txt, sizeof txt);
  } else {
    out.push_back('-');
    return;
  }
  if (txt[0] == '\0') { out.push_back('-'); return; }
  out.append(txt);
}

// Combined Log Format: one line per response, batched.
static void run_access() {
  std::string in;
  char rbuf[256 * 1024];
  out.reserve(1u << 20);
  for (;;) {
    const ssize_t n = ::read(0, rbuf, sizeof rbuf);
    if (n < 0) {
      if (errno == EINTR) continue;
      std::fprintf(stderr, "webmachine-logd: read: %s\n", std::strerror(errno));
      flush_out();
      std::exit(1);
    }
    if (n == 0) {
      flush_out();
      std::exit(0);
    }
    in.append(rbuf, static_cast<size_t>(n));

    size_t off = 0;
    while (in.size() - off >= sizeof(LogRec)) {
      LogRec r;
      std::memcpy(&r, in.data() + off, sizeof r);
      if (r.version != kLogRecVersion) {
        std::fprintf(stderr, "webmachine-logd: access record version %u, built for %u - refusing\n",
                     r.version, kLogRecVersion);
        flush_out();
        std::exit(1);
      }
      const size_t need = sizeof(LogRec) + r.method_token_len + r.peer_len + r.request_target_len +
                          r.referer_len + r.user_agent_len;
      if (in.size() - off < need) break;
      const char* p = in.data() + off + sizeof(LogRec);
      const char* method_token = p;         p += r.method_token_len;
      const char* peer = p;                 p += r.peer_len;
      const char* request_target = p;       p += r.request_target_len;
      const char* referer = p;              p += r.referer_len;
      const char* user_agent = p;

      spell_ts(r.unix_seconds);
      if (r.peer_len != 0) spell_peer(peer, r.peer_len, (r.flags & kLogNoTrack) != 0);
      else out.push_back('-');
      out.append(" - - ", 5);
      out.append(ts, 28);
      out.append(" \"", 2);
      if (r.method_token_len != 0) esc(method_token, r.method_token_len);
      else out.push_back('-');
      out.push_back(' ');
      esc(request_target, r.request_target_len);
      const bool h2 = (r.flags & kLogH2) != 0;
      out.append(h2 ? " HTTP/2\" " : " HTTP/1.1\" ", h2 ? 9 : 11);
      out.push_back(char('0' + r.status_code / 100));
      out.push_back(char('0' + r.status_code / 10 % 10));
      out.push_back(char('0' + r.status_code % 10));
      out.push_back(' ');
      if (r.content_length == 0) out.push_back('-'); else spell_num(r.content_length);
      out.append(" \"", 2);
      if (r.referer_len != 0) esc(referer, r.referer_len); else out.push_back('-');
      out.append("\" \"", 3);
      if (r.user_agent_len != 0) esc(user_agent, r.user_agent_len); else out.push_back('-');
      out.append("\"\n", 2);

      off += need;
      if (out.size() >= (1u << 20)) flush_out();
    }
    in.erase(0, off);
  }
}

// One block per raise: a header line, then one indented line per frame.
static void run_error() {
  std::string in;
  char rbuf[64 * 1024];
  out.reserve(1u << 16);
  for (;;) {
    const ssize_t n = ::read(0, rbuf, sizeof rbuf);
    if (n < 0) {
      if (errno == EINTR) continue;
      std::fprintf(stderr, "webmachine-logd: read: %s\n", std::strerror(errno));
      flush_out();
      std::exit(1);
    }
    if (n == 0) {
      flush_out();
      std::exit(0);
    }
    in.append(rbuf, static_cast<size_t>(n));

    size_t off = 0;
    while (in.size() - off >= sizeof(ErrRec)) {
      ErrRec r;
      std::memcpy(&r, in.data() + off, sizeof r);
      if (r.version != kErrRecVersion) {
        std::fprintf(stderr, "webmachine-logd: error record version %u, built for %u - refusing\n",
                     r.version, kErrRecVersion);
        flush_out();
        std::exit(1);
      }
      const size_t parts = size_t(r.peer_len) + r.exception_class_len + r.request_target_len +
                           r.message_len + r.backtrace_len;
      if (parts != r.dynamic_len) {
        std::fprintf(stderr, "webmachine-logd: error record says %u dynamic bytes, its fields add "
                             "up to %zu - stream desynced, refusing\n", r.dynamic_len, parts);
        flush_out();
        std::exit(1);
      }
      const size_t need = sizeof(ErrRec) + r.dynamic_len;
      if (in.size() - off < need) break;
      const char* p = in.data() + off + sizeof(ErrRec);
      const char* peer = p;                 p += r.peer_len;
      const char* exception_class = p;      p += r.exception_class_len;
      const char* request_target = p;       p += r.request_target_len;
      const char* message = p;              p += r.message_len;
      const char* backtrace = p;

      spell_ts(r.unix_seconds);
      out.append(ts, 28);
      out.push_back(' ');
      if (r.peer_len != 0) spell_peer(peer, r.peer_len, false); else out.push_back('-');
      out.push_back(' ');
      if (r.status_code != 0) {
        out.push_back(char('0' + r.status_code / 100));
        out.push_back(char('0' + r.status_code / 10 % 10));
        out.push_back(char('0' + r.status_code % 10));
      } else {
        out.push_back('-');
      }
      out.push_back(' ');
      if (r.request_target_len != 0) esc(request_target, r.request_target_len);
      else out.push_back('-');
      out.push_back(' ');
      if (r.exception_class_len != 0) esc(exception_class, r.exception_class_len);
      else out.push_back('-');
      out.append(": ", 2);
      if (r.message_len != 0) esc(message, r.message_len); else out.push_back('-');
      out.push_back('\n');
      for (size_t i = 0; i < r.backtrace_len;) {
        size_t j = i;
        while (j < r.backtrace_len && backtrace[j] != '\n') j++;
        out.append("\tfrom ", 6);
        esc(backtrace + i, j - i);
        out.push_back('\n');
        i = j + 1;
      }

      off += need;
      flush_out();
    }
    in.erase(0, off);
  }
}

// Two modes, two streams: access FILE MAXBYTES [privacy] | error FILE MAXBYTES.
int main(int argc, char** argv) {
  if (argc < 4) {
    std::fprintf(stderr,
                 "usage: webmachine-logd access FILE MAXBYTES [full|anon|none]  (records on fd 0)\n"
                 "       webmachine-logd error  FILE MAXBYTES\n");
    return 2;
  }
  const bool err_mode = std::strcmp(argv[1], "error") == 0;
  if (!err_mode && std::strcmp(argv[1], "access") != 0) {
    std::fprintf(stderr, "webmachine-logd: mode '%s'? access or error\n", argv[1]);
    return 2;
  }
  if (err_mode ? argc != 4 : argc > 5) {
    std::fprintf(stderr, "webmachine-logd: %s takes FILE MAXBYTES%s\n", argv[1],
                 err_mode ? "" : " [full|anon|none]");
    return 2;
  }
  {
    char* end = nullptr;
    errno = 0;
    const unsigned long long v = std::strtoull(argv[3], &end, 10);
    if (errno != 0 || end == argv[3] || *end != '\0') {
      std::fprintf(stderr, "webmachine-logd: MAXBYTES '%s'? a byte count, 0 for no ceiling\n",
                   argv[3]);
      return 2;
    }
    max_bytes = static_cast<size_t>(v);
  }
  if (argc == 5) {
    if (std::strcmp(argv[4], "anon") == 0) privacy = Privacy::kAnon;
    else if (std::strcmp(argv[4], "none") == 0) privacy = Privacy::kNone;
    else if (std::strcmp(argv[4], "full") == 0) privacy = Privacy::kFull;
    else {
      std::fprintf(stderr, "webmachine-logd: privacy '%s'? none, anon or full\n", argv[4]);
      return 2;
    }
  }
  log_fd = ::open(argv[2], O_RDWR | O_CREAT | O_CLOEXEC, 0644);
  if (log_fd < 0) {
    std::fprintf(stderr, "webmachine-logd: %s: %s\n", argv[2], std::strerror(errno));
    return 1;
  }
  const off_t at = ::lseek(log_fd, 0, SEEK_END);
  if (at < 0) {
    std::fprintf(stderr, "webmachine-logd: %s: %s\n", argv[2], std::strerror(errno));
    return 1;
  }
  on_disk = static_cast<size_t>(at);

  if (err_mode) run_error(); else run_access();
  return 0;
}
