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

// If-Match / If-None-Match spell "any" as * (RFC 9110 §13.1.1/13.1.2);
// a quoted "*" arrives from some clients and means the same.
bool star_value(const char* v, size_t n) {
  if (n == 1 && v[0] == '*') return true;
  return n == 3 && v[0] == '"' && v[1] == '*' && v[2] == '"';
}

// Methods are case-sensitive tokens (RFC 9110 §9.1).
flow::Method parse_method(const char* m, size_t n) {
  switch (n) {
    case 3:
      if (std::memcmp(m, "GET", 3) == 0) return flow::Method::kGet;
      if (std::memcmp(m, "PUT", 3) == 0) return flow::Method::kPut;
      break;
    case 4:
      if (std::memcmp(m, "HEAD", 4) == 0) return flow::Method::kHead;
      if (std::memcmp(m, "POST", 4) == 0) return flow::Method::kPost;
      break;
    case 6:
      if (std::memcmp(m, "DELETE", 6) == 0) return flow::Method::kDelete;
      break;
    case 7:
      if (std::memcmp(m, "OPTIONS", 7) == 0) return flow::Method::kOptions;
      break;
    default:
      break;
  }
  return flow::Method::kOther;
}

const char* reason(uint16_t status) {
  switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 300: return "Multiple Choices";
    case 301: return "Moved Permanently";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 409: return "Conflict";
    case 410: return "Gone";
    case 411: return "Length Required";
    case 412: return "Precondition Failed";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 415: return "Unsupported Media Type";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
  }
  return "Response";
}

// The date field's fixed shape; on_tick patches exactly these 29 bytes.
constexpr char kDatePlaceholder[] = "Sun, 00 Jan 1970 00:00:00 GMT";
constexpr size_t kDateLen = sizeof(kDatePlaceholder) - 1;

}  // namespace

void Http1::build_status(uint16_t status, const char* extra, const char* body) {
  const auto build = [&](Resp& r, const char* conn) {
    r.bytes.clear();
    char line[16];
    line[0] = static_cast<char>('0' + status / 100);
    line[1] = static_cast<char>('0' + (status / 10) % 10);
    line[2] = static_cast<char>('0' + status % 10);
    line[3] = '\0';
    r.bytes.append("HTTP/1.1 ").append(line).append(" ").append(reason(status));
    r.bytes.append("\r\nDate: ");
    r.date_off = r.bytes.size();
    r.bytes.append(kDatePlaceholder).append("\r\n").append(conn).append(extra).append(body);
  };
  Variants v;
  build(v.plain, "");
  build(v.keep, "Connection: keep-alive\r\n");
  build(v.close, "Connection: close\r\n");
  index_[status] = static_cast<uint8_t>(store_.size());
  store_.push_back(std::move(v));
}

Http1::Http1(const flow::KonstSet& ks, const Resource* res, bool dynamic_nodes,
             bool dynamic_body)
    : konst_(ks),
      res_(res),
      dynamic_nodes_(dynamic_nodes),
      dynamic_body_(dynamic_body),
      bound_(res != nullptr && (dynamic_nodes || dynamic_body)) {
  // Every status the flow's halt edges can speak, plus the framer's own
  // wire refusals - collected from the table, built ONCE. From here on
  // only the 29 date bytes ever change.
  store_.reserve(32);
  const std::string allow = "Allow: " + konst_.allow + "\r\n";
  // 200 carries the resource's rendered representation (RFC 9110 8.3:
  // a body announces its Content-Type).
  std::string ok_extra;
  if (!konst_.content_type.empty()) {
    ok_extra = "Content-Type: " + konst_.content_type + "\r\n";
  }
  const std::string ok_tail =
      "Content-Length: " + std::to_string(konst_.body.size()) + "\r\n\r\n" + konst_.body;
  bool have[600] = {};
  const auto add = [&](uint16_t s) {
    if (have[s]) return;
    have[s] = true;
    // 204/304 are defined bodyless (RFC 9110 15.3.5/15.4.5): no
    // Content-Length, no body. 405 names what IS allowed (10.2.1),
    // from the resource's list.
    if (s == 204 || s == 304) build_status(s, "", "\r\n");
    else if (s == 405) build_status(s, allow.c_str(), "Content-Length: 0\r\n\r\n");
    else if (s == 200) build_status(s, ok_extra.c_str(), ok_tail.c_str());
    else build_status(s, "", "Content-Length: 0\r\n\r\n");
  };
  for (const auto& f : flow::kFlow) {
    if (f.on_true.status != 0) add(f.on_true.status);
    if (f.on_false.status != 0) add(f.on_false.status);
  }
  add(400);
  add(411);
  add(413);
  add(431);

  // HEAD answers with 200's head and no body bytes (RFC 9110 9.3.2).
  {
    const Variants& ok = variants(200);
    const size_t blen = konst_.body.size();
    const auto strip = [&](const Resp& src, Resp& dst) {
      dst.bytes.assign(src.bytes, 0, src.bytes.size() - blen);
      dst.date_off = src.date_off;
    };
    strip(ok.plain, ok_head_.plain);
    strip(ok.keep, ok_head_.keep);
    strip(ok.close, ok_head_.close);
  }
  // A per-request body assembles onto 200's head cut before
  // Content-Length: prefix + "Content-Length: N\r\n\r\n" + body.
  if (dynamic_body_) {
    const Variants& ok = variants(200);
    const size_t cut = ok_tail.size();  // ok's bytes end with the whole tail
    const auto prefix = [&](const Resp& src, Resp& dst) {
      dst.bytes.assign(src.bytes, 0, src.bytes.size() - cut);
      dst.date_off = src.date_off;
    };
    prefix(ok.plain, ok_prefix_.plain);
    prefix(ok.keep, ok_prefix_.keep);
    prefix(ok.close, ok_prefix_.close);
  }
  // Exceptions answer as the negotiated type: a 500 head open for a
  // per-request body carrying the reason.
  if (bound_) {
    const auto build = [&](Resp& r, const char* conn) {
      r.bytes.clear();
      r.bytes.append("HTTP/1.1 500 Internal Server Error\r\nDate: ");
      r.date_off = r.bytes.size();
      r.bytes.append(kDatePlaceholder).append("\r\n").append(conn).append(ok_extra);
    };
    build(err_prefix_.plain, "");
    build(err_prefix_.keep, "Connection: keep-alive\r\n");
    build(err_prefix_.close, "Connection: close\r\n");
  }

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

  for (Variants& v : store_) {
    std::memcpy(v.plain.bytes.data() + v.plain.date_off, core, kDateLen);
    std::memcpy(v.keep.bytes.data() + v.keep.date_off, core, kDateLen);
    std::memcpy(v.close.bytes.data() + v.close.date_off, core, kDateLen);
  }
  std::memcpy(ok_head_.plain.bytes.data() + ok_head_.plain.date_off, core, kDateLen);
  std::memcpy(ok_head_.keep.bytes.data() + ok_head_.keep.date_off, core, kDateLen);
  std::memcpy(ok_head_.close.bytes.data() + ok_head_.close.date_off, core, kDateLen);
  if (dynamic_body_) {
    std::memcpy(ok_prefix_.plain.bytes.data() + ok_prefix_.plain.date_off, core, kDateLen);
    std::memcpy(ok_prefix_.keep.bytes.data() + ok_prefix_.keep.date_off, core, kDateLen);
    std::memcpy(ok_prefix_.close.bytes.data() + ok_prefix_.close.date_off, core, kDateLen);
  }
  if (bound_) {
    std::memcpy(err_prefix_.plain.bytes.data() + err_prefix_.plain.date_off, core, kDateLen);
    std::memcpy(err_prefix_.keep.bytes.data() + err_prefix_.keep.date_off, core, kDateLen);
    std::memcpy(err_prefix_.close.bytes.data() + err_prefix_.close.date_off, core, kDateLen);
  }
}

void Http1::assemble(std::string& sink, const Resp& prefix, const char* body, size_t len,
                     bool head_only) {
  sink.append(prefix.bytes);
  // Content-Length spelled by hand: printf machinery has no business
  // on the request path.
  char cl[40] = "Content-Length: ";
  size_t at = 16;
  char digits[20];
  size_t d = 0;
  size_t v = len;
  do {
    digits[d++] = static_cast<char>('0' + v % 10);
    v /= 10;
  } while (v != 0);
  while (d != 0) cl[at++] = digits[--d];
  cl[at++] = '\r';
  cl[at++] = '\n';
  cl[at++] = '\r';
  cl[at++] = '\n';
  sink.append(cl, at);
  if (!head_only) sink.append(body, len);
}

bool Http1::fail(Conn& st, uint16_t status, std::string& sink) {
  // Wire invalidity: framing trust is gone, the connection always ends.
  sink.append(variants(status).close.bytes);
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
      return fail(st, 431, sink);
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
      if (WM_H1_UNLIKELY(rest > kMaxHead)) return fail(st, 431, sink);  // RFC 6585 §5
      if (in_place) st.carry.assign(view + off, rest);
      else st.carry.erase(0, off);
      return true;
    }
    if (WM_H1_UNLIKELY(ret <= 0)) return fail(st, 400, sink);  // RFC 9112 §2.2
    // The cap holds for complete heads too, or one receive containing a
    // whole oversized head would sail past the -2 path's check.
    if (WM_H1_UNLIKELY(static_cast<size_t>(ret) > kMaxHead)) return fail(st, 431, sink);

    size_t content_length = 0;
    bool have_cl = false, have_te = false, have_host = false;
    bool conn_close = false, conn_keep = false;
    flow::ReqFacts facts;
    facts.method = parse_method(method, method_len);
    for (size_t i = 0; i < num_headers; i++) {
      const struct phr_header& h = headers[i];
      // One jump on the length, one or two comparisons behind it; every
      // foreign header costs exactly the length check.
      switch (h.name_len) {
        case 14:
          if (tok_eq(h.name, h.name_len, "content-length", 14)) {
            // A second Content-Length is a smuggling shape (RFC 9112 §6.3).
            if (WM_H1_UNLIKELY(have_cl || h.value_len == 0)) return fail(st, 400, sink);
            have_cl = true;
            size_t v = 0;
            for (size_t j = 0; j < h.value_len; j++) {
              const char ch = h.value[j];
              if (WM_H1_UNLIKELY(ch < '0' || ch > '9')) {
                return fail(st, 400, sink);  // 1*DIGIT, §6.2
              }
              size_t t = 0;
              if (WM_H1_UNLIKELY(__builtin_mul_overflow(v, static_cast<size_t>(10), &t) ||
                                 __builtin_add_overflow(t, static_cast<size_t>(ch - '0'), &v))) {
                return fail(st, 413, sink);
              }
            }
            content_length = v;
          } else if (tok_eq(h.name, h.name_len, "accept-charset", 14)) {
            facts.has_accept_charset = true;
          }
          break;
        case 17:
          if (tok_eq(h.name, h.name_len, "transfer-encoding", 17)) have_te = true;
          else if (tok_eq(h.name, h.name_len, "if-modified-since", 17)) {
            // Date parsing is a later tier; an unparsed date reads as
            // invalid, which flow.rb's rescue path also ignores (L14).
            facts.has_if_modified_since = true;
          }
          break;
        case 4:
          if (tok_eq(h.name, h.name_len, "host", 4)) {
            if (WM_H1_UNLIKELY(have_host)) return fail(st, 400, sink);  // RFC 9112 §3.2: one
            have_host = true;
          }
          break;
        case 10:
          if (tok_eq(h.name, h.name_len, "connection", 10)) {
            if (conn_has(h.value, h.value_len, "close", 5)) conn_close = true;
            else if (conn_has(h.value, h.value_len, "keep-alive", 10)) conn_keep = true;
          }
          break;
        case 6:
          if (tok_eq(h.name, h.name_len, "accept", 6)) facts.has_accept = true;
          break;
        case 15:
          if (tok_eq(h.name, h.name_len, "accept-language", 15)) facts.has_accept_language = true;
          else if (tok_eq(h.name, h.name_len, "accept-encoding", 15)) facts.has_accept_encoding = true;
          break;
        case 8:
          if (tok_eq(h.name, h.name_len, "if-match", 8)) {
            facts.has_if_match = true;
            facts.if_match_star = star_value(h.value, h.value_len);
          }
          break;
        case 13:
          if (tok_eq(h.name, h.name_len, "if-none-match", 13)) {
            facts.has_if_none_match = true;
            facts.inm_star = star_value(h.value, h.value_len);
          }
          break;
        case 19:
          if (tok_eq(h.name, h.name_len, "if-unmodified-since", 19)) {
            facts.has_if_unmodified_since = true;  // date tier pending, like IMS
          }
          break;
        case 11:
          if (tok_eq(h.name, h.name_len, "content-md5", 11)) facts.has_content_md5 = true;
          break;
        default:
          break;
      }
    }
    // Transfer-Encoding alongside Content-Length is the classic
    // smuggling vector (RFC 9112 §6.3.3); chunked alone is refused with
    // 411 as §6.1 sanctions until a body consumer exists.
    if (WM_H1_UNLIKELY(have_te)) return fail(st, have_cl ? 400 : 411, sink);
    if (WM_H1_UNLIKELY(minor >= 1 && !have_host)) return fail(st, 400, sink);  // RFC 9112 §3.2
    if (WM_H1_UNLIKELY(content_length > kMaxBody)) return fail(st, 413, sink);

    // The wire is valid; from here the FLOW decides the status. Konst
    // answers are compiled into the method's vector; dynamic nodes -
    // instance methods, by declaration - are asked through the VM per
    // request (this branch is deployment-stable: no hint).
    uint16_t status =
        dynamic_nodes_ ? resource_decide(*res_, facts)
                       : flow::walk(facts, konst_.per_method[static_cast<size_t>(facts.method)]);

    // RFC 9112 §9.3: 1.1 persists unless close; 1.0 closes unless it
    // asked (§C.2.2), and the asked-for keep-alive is echoed.
    const bool persist = minor >= 1 ? !conn_close : conn_keep;
    const bool head_only = facts.method == flow::Method::kHead;
    bool answered = false;
    if (dynamic_body_ && status == 200) {
      // The per-request representation: rendered in the VM, its bytes
      // BORROWED until render_end and copied exactly once, straight
      // into the sink. HEAD renders too - its Content-Length must be
      // the GET's - but sends no body bytes (RFC 9110 9.3.2).
      const char* bp = nullptr;
      size_t blen = 0;
      int arena = 0;
      if (WM_H1_UNLIKELY(!resource_render_begin(*res_, &bp, &blen, &arena))) {
        status = 500;  // the handler raised; the connection outlives it
      } else {
        assemble(sink, minor >= 1 ? (persist ? ok_prefix_.plain : ok_prefix_.close)
                                  : (persist ? ok_prefix_.keep : ok_prefix_.close),
                 bp, blen, head_only);
        resource_render_end(*res_, arena);
        answered = true;
      }
    }
    if (WM_H1_UNLIKELY(!answered && status == 500 && bound_)) {
      // A raising callback answers in the negotiated type, the reason
      // as body - the exception was left pending for exactly this.
      const char* bp = nullptr;
      size_t blen = 0;
      int arena = 0;
      if (resource_exception_begin(*res_, &bp, &blen, &arena)) {
        assemble(sink, minor >= 1 ? (persist ? err_prefix_.plain : err_prefix_.close)
                                  : (persist ? err_prefix_.keep : err_prefix_.close),
                 bp, blen, head_only);
        resource_render_end(*res_, arena);
        answered = true;
      }
    }
    if (!answered) {
      const Variants& sv = (head_only && status == 200) ? ok_head_ : variants(status);
      sink.append(minor >= 1 ? (persist ? sv.plain.bytes : sv.close.bytes)
                             : (persist ? sv.keep.bytes : sv.close.bytes));
    }

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
