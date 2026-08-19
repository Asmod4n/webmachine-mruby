#include "http1.hpp"

#include <picohttpparser.h>

#include <cstring>

// Prediction hints only where the taken side is terminal (see ring.hpp).
#define WM_H1_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace webmachine {
namespace {

// Case-insensitive equality against a lowercase literal (header names
// are case-insensitive, RFC 9110 §5.1).
bool tok_eq(const char* s, size_t n, const char* lit, size_t litn) {
  if (n != litn) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    if (c != lit[i]) return false;
  }
  return true;
}

// Connection is a comma-separated token list (RFC 9110 §7.6.1); a
// substring match would accept e.g. "not-close".
bool conn_has(const char* v, size_t n, const char* lit, size_t litn) {
  size_t i = 0;
  while (i < n) {
    while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
    const size_t start = i;
    while (i < n && v[i] != ',' && v[i] != ' ' && v[i] != '\t') i++;
    if (tok_eq(v + start, i - start, lit, litn)) return true;
  }
  return false;
}

// The date field's fixed shape; refresh patches exactly these 29 bytes.
constexpr char kDatePlaceholder[] = "Sun, 00 Jan 1970 00:00:00 GMT";
constexpr size_t kDateLen = sizeof(kDatePlaceholder) - 1;

}  // namespace

Http1::Http1() {
  // Built ONCE; from here on only the 29 date bytes ever change.
  const auto build = [](Resp& r, const char* status, const char* conn, const char* tail) {
    r.bytes.clear();
    r.bytes.append("HTTP/1.1 ").append(status).append("\r\nDate: ");
    r.date_off = r.bytes.size();
    r.bytes.append(kDatePlaceholder).append("\r\n").append(conn).append(tail);
  };
  build(ok_plain_, "200 OK", "", "Content-Length: 2\r\n\r\nOK");
  build(ok_keep_, "200 OK", "Connection: keep-alive\r\n", "Content-Length: 2\r\n\r\nOK");
  build(ok_close_, "200 OK", "Connection: close\r\n", "Content-Length: 2\r\n\r\nOK");
  build(r400_, "400 Bad Request", "Connection: close\r\n", "Content-Length: 0\r\n\r\n");
  build(r411_, "411 Length Required", "Connection: close\r\n", "Content-Length: 0\r\n\r\n");
  build(r413_, "413 Content Too Large", "Connection: close\r\n", "Content-Length: 0\r\n\r\n");
  build(r431_, "431 Request Header Fields Too Large", "Connection: close\r\n",
        "Content-Length: 0\r\n\r\n");
  sec_ = 0;
  on_tick();
}

void Http1::on_tick() {
  const time_t now = ::time(nullptr);
  if (now == sec_) return;
  sec_ = now;
  struct tm tm;
  gmtime_r(&now, &tm);
  // IMF-fixdate by hand (RFC 9110 §5.6.7): strftime's %a/%b obey the
  // process locale and would emit German day names under LC_TIME=de_DE.
  static const char kDay[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char kMon[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  char core[kDateLen];
  //                    0123456789012345678901234567 8
  //                    Sun, 00 Jan 1970 00:00:00 GMT
  const auto two = [&](size_t at, int v) {
    core[at] = static_cast<char>('0' + v / 10);
    core[at + 1] = static_cast<char>('0' + v % 10);
  };
  std::memcpy(core, kDay[tm.tm_wday], 3);
  core[3] = ',';
  core[4] = ' ';
  two(5, tm.tm_mday);
  core[7] = ' ';
  std::memcpy(core + 8, kMon[tm.tm_mon], 3);
  core[11] = ' ';
  const int year = tm.tm_year + 1900;
  two(12, year / 100);
  two(14, year % 100);
  core[16] = ' ';
  two(17, tm.tm_hour);
  core[19] = ':';
  two(20, tm.tm_min);
  core[22] = ':';
  two(23, tm.tm_sec);
  core[25] = ' ';
  std::memcpy(core + 26, "GMT", 3);

  Resp* all[] = {&ok_plain_, &ok_keep_, &ok_close_, &r400_, &r411_, &r413_, &r431_};
  for (Resp* r : all) std::memcpy(r->bytes.data() + r->date_off, core, kDateLen);
}

bool Http1::fail(Conn& st, const Resp& resp, std::string& sink) {
  sink.append(resp.bytes);
  st.reset();
  return false;
}

bool Http1::feed(Conn& st, const char* data, size_t len, std::string& sink) {
  // Body bytes a previous receive left owing are consumed first -
  // skipped, this layer has no consumer, but the framing must hold or
  // keep-alive would parse body bytes as the next head.
  if (st.body_skip != 0) {
    const size_t take = st.body_skip < len ? st.body_skip : len;
    st.body_skip -= take;
    data += take;
    len -= take;
    if (len == 0) return true;
  }

  // The hot path parses the receive buffer in place; only a head split
  // across receives pays for the carry copy.
  const bool in_place = st.carry.empty();
  const char* view = data;
  size_t viewlen = len;
  if (!in_place) {
    size_t grown = 0;
    if (WM_H1_UNLIKELY(__builtin_add_overflow(st.carry.size(), len, &grown))) {
      return fail(st, r431_, sink);
    }
    st.carry.append(data, len);
    view = st.carry.data();
    viewlen = st.carry.size();
  }

  size_t off = 0;
  while (off < viewlen) {  // pipelining: every complete head in the view answers
    const char* method;
    size_t method_len;
    const char* path;
    size_t path_len;
    int minor;
    struct phr_header headers[kMaxHeaders];
    size_t num_headers = kMaxHeaders;
    const int ret = phr_parse_request(view + off, viewlen - off, &method, &method_len, &path,
                                      &path_len, &minor, headers, &num_headers, 0);
    if (ret == -2) {  // incomplete head: carry it (bytes die with the pool buffer)
      const size_t rest = viewlen - off;
      if (WM_H1_UNLIKELY(rest > kMaxHead)) return fail(st, r431_, sink);  // RFC 6585 §5
      if (in_place) st.carry.assign(view + off, rest);
      else st.carry.erase(0, off);
      return true;
    }
    if (WM_H1_UNLIKELY(ret <= 0)) return fail(st, r400_, sink);  // RFC 9112 §2.2
    // The cap holds for complete heads too, or one receive containing a
    // whole oversized head would sail past the -2 path's check.
    if (WM_H1_UNLIKELY(static_cast<size_t>(ret) > kMaxHead)) return fail(st, r431_, sink);

    size_t content_length = 0;
    bool have_cl = false, have_te = false, have_host = false;
    bool conn_close = false, conn_keep = false;
    for (size_t i = 0; i < num_headers; i++) {
      const struct phr_header& h = headers[i];
      // The four interesting names have four distinct lengths: one jump
      // on the length, one comparison behind it, every other header
      // costs exactly the length check.
      switch (h.name_len) {
        case 14:
          if (tok_eq(h.name, h.name_len, "content-length", 14)) {
            // A second Content-Length is a smuggling shape (RFC 9112 §6.3).
            if (WM_H1_UNLIKELY(have_cl || h.value_len == 0)) return fail(st, r400_, sink);
            have_cl = true;
            size_t v = 0;
            for (size_t j = 0; j < h.value_len; j++) {
              const char ch = h.value[j];
              if (WM_H1_UNLIKELY(ch < '0' || ch > '9')) {
                return fail(st, r400_, sink);  // 1*DIGIT, §6.2
              }
              size_t t = 0;
              if (WM_H1_UNLIKELY(__builtin_mul_overflow(v, static_cast<size_t>(10), &t) ||
                                 __builtin_add_overflow(t, static_cast<size_t>(ch - '0'), &v))) {
                return fail(st, r413_, sink);
              }
            }
            content_length = v;
          }
          break;
        case 17:
          if (tok_eq(h.name, h.name_len, "transfer-encoding", 17)) have_te = true;
          break;
        case 4:
          if (tok_eq(h.name, h.name_len, "host", 4)) {
            if (WM_H1_UNLIKELY(have_host)) return fail(st, r400_, sink);  // RFC 9112 §3.2: one
            have_host = true;
          }
          break;
        case 10:
          if (tok_eq(h.name, h.name_len, "connection", 10)) {
            if (conn_has(h.value, h.value_len, "close", 5)) conn_close = true;
            else if (conn_has(h.value, h.value_len, "keep-alive", 10)) conn_keep = true;
          }
          break;
        default:
          break;
      }
    }
    // Transfer-Encoding alongside Content-Length is the classic
    // smuggling vector (RFC 9112 §6.3.3); chunked alone is refused with
    // 411 as §6.1 sanctions until a body consumer exists.
    if (WM_H1_UNLIKELY(have_te)) return fail(st, have_cl ? r400_ : r411_, sink);
    if (WM_H1_UNLIKELY(minor >= 1 && !have_host)) return fail(st, r400_, sink);  // RFC 9112 §3.2
    if (WM_H1_UNLIKELY(content_length > kMaxBody)) return fail(st, r413_, sink);

    // RFC 9112 §9.3: 1.1 persists unless close; 1.0 closes unless it
    // asked (§C.2.2), and the asked-for keep-alive is echoed.
    const bool persist = minor >= 1 ? !conn_close : conn_keep;
    sink.append(minor >= 1 ? (persist ? ok_plain_.bytes : ok_close_.bytes)
                           : (persist ? ok_keep_.bytes : ok_close_.bytes));

    off += static_cast<size_t>(ret);
    if (content_length != 0) {
      const size_t avail = viewlen - off;
      const size_t skip = content_length < avail ? content_length : avail;
      off += skip;
      st.body_skip = content_length - skip;
    }
    if (!persist) {
      // Bytes pipelined behind a closing request die with the
      // connection (RFC 9112 §9.6: the close ends the exchange).
      st.reset();
      return false;
    }
  }
  if (!in_place) st.carry.clear();
  return true;
}

}  // namespace webmachine
