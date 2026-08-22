// The version-free HTTP layer: RFC 9110 semantics as pure inline
// functions and data. No state, no wire syntax - status lines,
// Connection handling, chunked framing and phr are 9112 property and
// stay in http1 (9113's frames will stay in http2). Sharing happens
// at zero cost: everything here inlines into its caller, so the
// machine code is identical to the copy it replaced.
#ifndef WEBMACHINE_HTTP_HPP
#define WEBMACHINE_HTTP_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>

#include "flow_walk.hpp"

namespace webmachine::http {

// Case-insensitive equality against a lowercase literal (header names
// are case-insensitive, RFC 9110 §5.1).
constexpr bool tok_eq(const char* s, size_t n, const char* lit, size_t litn) {
  if (n != litn) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
    if (c != lit[i]) return false;
  }
  return true;
}

// If-Match / If-None-Match spell "any" as * (RFC 9110 §13.1.1/13.1.2);
// a quoted "*" arrives from some clients and means the same.
constexpr bool star_value(const char* v, size_t n) {
  if (n == 1 && v[0] == '*') return true;
  return n == 3 && v[0] == '"' && v[1] == '*' && v[2] == '"';
}

// Methods are case-sensitive tokens (RFC 9110 §9.1).
inline flow::Method parse_method(const char* m, size_t n) {
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

// text/* with no parameters gets "; charset=utf-8" appended - a
// statement of fact, not a guess: mruby produces UTF-8 or bytes,
// nothing else exists in this VM, and a text/plain response without a
// charset decodes by the BROWSER'S locale default (windows-1252 in
// Western locales). text/* only: application/json's registration has
// no charset parameter (RFC 8259, JSON is UTF-8), adding one is noise.
// A type already carrying parameters is left alone - a resource that
// spelled its own charset wins. Setup-only; never runs per request.
// EVERY writer goes through here (#146: this tree once shipped two
// serializers that drifted): Http1's konst head + h2 blocks, and the
// asset tier's extension table.
inline std::string with_charset(const std::string& type) {
  if (type.size() < 5 || !tok_eq(type.data(), 5, "text/", 5)) return type;
  if (type.find(';') != std::string::npos) return type;
  return type + "; charset=utf-8";
}

// #147's media-type table: worth compressing a dynamic body of this
// Content-Type? Decided ONCE per resource at Http1's setup (the "8%
// rule" - a media type this narrow gate lets through is the minority,
// so a resource outside it costs no branch at answer time, only this
// one bool). Structural, not a guess: text/* always compresses;
// anything ending +json or +xml is a registered structured-syntax
// suffix (RFC 6839) and inherits its base type's compressibility; a
// short named list covers the common textual types that are neither -
// application/json, application/javascript, application/xml,
// application/wasm (a binary format, but one deflate reliably shrinks:
// it is mostly small integer opcodes and LEB128, not entropy), and
// image/svg+xml (XML, mislabeled as an image/ type by history).
// EVERYTHING ELSE, including anything this table has never heard of,
// answers false - conservative downward, because a wrong "yes" spends
// CPU compressing bytes that gain nothing (already-compressed media:
// image/png, video/*, application/zip, ...) while a wrong "no" only
// ever costs bytes on the wire, never correctness. Any parameters
// (";...", most commonly a charset) are ignored - the media type
// itself answers the question, not what follows the semicolon.
constexpr size_t clen(const char* s) {
  size_t n = 0;
  while (s[n] != '\0') n++;
  return n;
}
constexpr bool compressible_media_type(const char* v, size_t n) {
  size_t tn = 0;
  while (tn < n && v[tn] != ';') tn++;
  if (tn >= 5 && tok_eq(v, 5, "text/", 5)) return true;
  if (tn >= 5 && tok_eq(v + tn - 5, 5, "+json", 5)) return true;  // RFC 6839
  if (tn >= 4 && tok_eq(v + tn - 4, 4, "+xml", 4)) return true;   // RFC 6839
  constexpr const char* kExact[] = {
      "application/json", "application/javascript", "application/xml",
      "application/wasm", "image/svg+xml",
  };
  for (const char* lit : kExact) {
    if (tok_eq(v, tn, lit, clen(lit))) return true;
  }
  return false;
}
inline bool compressible_media_type(const std::string& v) {
  return compressible_media_type(v.data(), v.size());
}
namespace proof {
constexpr bool ct(const char* s) { return compressible_media_type(s, clen(s)); }
static_assert(ct("text/html"), "text/* compresses");
static_assert(ct("text/html; charset=utf-8"), "a parameter does not hide the media type");
static_assert(ct("application/json"));
static_assert(ct("application/javascript"));
static_assert(ct("application/xml"));
static_assert(ct("application/wasm"));
static_assert(ct("image/svg+xml"));
static_assert(ct("application/vnd.api+json"), "RFC 6839 +json suffix");
static_assert(ct("application/rss+xml"), "RFC 6839 +xml suffix");
static_assert(!ct("image/png"), "already-compressed media stays no");
static_assert(!ct("application/octet-stream"), "unknown is conservative no");
static_assert(!ct(""), "empty is no, not a crash");
}  // namespace proof

// The status names of RFC 9110 §15.
constexpr const char* reason(uint16_t status) {
  switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 206: return "Partial Content";
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
    case 416: return "Range Not Satisfiable";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
  }
  return "Response";
}

// The Date field value's fixed shape (RFC 9110 §5.6.7 IMF-fixdate);
// writers may prebuild with the placeholder and patch exactly these
// 29 bytes per second.
inline constexpr char kDatePlaceholder[] = "Sun, 00 Jan 1970 00:00:00 GMT";
inline constexpr size_t kDateLen = sizeof(kDatePlaceholder) - 1;

// IMF-fixdate by hand: strftime's %a/%b obey the process locale and
// would emit German day names under LC_TIME=de_DE.
inline void date_core(char out[kDateLen], const struct tm& tm) {
  static const char kDay[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char kMon[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  const auto two = [&](size_t at, int v) {
    out[at] = static_cast<char>('0' + v / 10);
    out[at + 1] = static_cast<char>('0' + v % 10);
  };
  std::memcpy(out, kDay[tm.tm_wday], 3);
  out[3] = ',';
  out[4] = ' ';
  two(5, tm.tm_mday);
  out[7] = ' ';
  std::memcpy(out + 8, kMon[tm.tm_mon], 3);
  out[11] = ' ';
  const int year = tm.tm_year + 1900;
  two(12, year / 100);
  two(14, year % 100);
  out[16] = ' ';
  two(17, tm.tm_hour);
  out[19] = ':';
  two(20, tm.tm_min);
  out[22] = ':';
  two(23, tm.tm_sec);
  out[25] = ' ';
  std::memcpy(out + 26, "GMT", 3);
}

// "Content-Length: N\r\n\r\n" spelled by hand (RFC 9110 §8.6): printf
// machinery has no business on the request path. Returns the length.
inline size_t spell_content_length(char (&buf)[40], size_t len) {
  std::memcpy(buf, "Content-Length: ", 16);
  size_t at = 16;
  char digits[20];
  size_t d = 0;
  size_t v = len;
  do {
    digits[d++] = static_cast<char>('0' + v % 10);
    v /= 10;
  } while (v != 0);
  while (d != 0) buf[at++] = digits[--d];
  buf[at++] = '\r';
  buf[at++] = '\n';
  buf[at++] = '\r';
  buf[at++] = '\n';
  return at;
}

// Content-Length is 1*DIGIT (RFC 9110 §8.6). kOk fills *out; kBad is
// a syntax violation (the caller's 400), kOverflow exceeds size_t
// (the caller's refusal bound, 413).
enum class ClStatus : uint8_t { kOk, kBad, kOverflow };
inline ClStatus parse_content_length(const char* s, size_t n, size_t* out) {
  if (n == 0) return ClStatus::kBad;
  size_t v = 0;
  for (size_t j = 0; j < n; j++) {
    const char ch = s[j];
    if (ch < '0' || ch > '9') return ClStatus::kBad;
    size_t t = 0;
    if (__builtin_mul_overflow(v, static_cast<size_t>(10), &t) ||
        __builtin_add_overflow(t, static_cast<size_t>(ch - '0'), &v)) {
      return ClStatus::kOverflow;
    }
  }
  *out = v;
  return ClStatus::kOk;
}

// The value tier's first residents (#165, first customer #170): the
// header VALUES negotiation reads. The pointers BORROW the receive
// buffer (h1) or the decode buffer (h2) and die with the dispatch that
// filled them - presence lives in ReqFacts' has_* flags, these only
// say where the bytes are while the answer is being made.
struct ReqValues {
  const char* accept_encoding = nullptr;
  size_t accept_encoding_len = 0;
  const char* if_match = nullptr;
  size_t if_match_len = 0;
  const char* if_none_match = nullptr;
  size_t if_none_match_len = 0;
  // Range/If-Range never touch the graph (webmachine has no range
  // node - a representation concern, not a decision one), so they set
  // no fact and leave `plain` alone; only the asset tier reads them.
  const char* range = nullptr;
  size_t range_len = 0;
  const char* if_range = nullptr;
  size_t if_range_len = 0;
};

// Range: bytes=first-last | first- | -suffix, ONE range only (RFC 9110
// §14.1.2). kNone = act as if the field were absent - a server MAY
// ignore Range entirely (§14.2), so a multi-range request, a foreign
// unit or a malformed value degrades to the full 200, stated here
// rather than discovered. kUnsat = 416 (§15.5.17). `complete` counts
// the SELECTED representation's octets - for a Content-Encoding: gzip
// response that is the compressed stream (§14.1.2; ranging the
// uncompressed bytes under a gzip coding would be silent corruption).
enum class RangeParse : uint8_t { kNone, kOne, kUnsat };
inline RangeParse parse_range(const char* v, size_t n, size_t complete, size_t* first,
                              size_t* last) {
  if (n < 7 || !tok_eq(v, 6, "bytes=", 6)) return RangeParse::kNone;
  size_t i = 6;
  while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
  const auto digits = [&](size_t* out) -> bool {  // 1*DIGIT, overflow-checked
    bool any = false;
    size_t val = 0;
    while (i < n && v[i] >= '0' && v[i] <= '9') {
      size_t t = 0;
      if (__builtin_mul_overflow(val, static_cast<size_t>(10), &t) ||
          __builtin_add_overflow(t, static_cast<size_t>(v[i] - '0'), &val)) {
        return false;
      }
      any = true;
      i++;
    }
    *out = val;
    return any;
  };
  size_t a = 0, b = 0;
  const bool have_a = digits(&a);
  if (i >= n || v[i] != '-') return RangeParse::kNone;
  i++;
  const bool have_b = digits(&b);
  while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
  if (i != n) return RangeParse::kNone;  // a second range or trailing junk: ignore
  if (!have_a && !have_b) return RangeParse::kNone;
  if (complete == 0) return RangeParse::kUnsat;  // no byte satisfies any range
  if (!have_a) {  // -suffix: the final b octets
    if (b == 0) return RangeParse::kUnsat;
    *first = b >= complete ? 0 : complete - b;
    *last = complete - 1;
    return RangeParse::kOne;
  }
  if (have_b && b < a) return RangeParse::kNone;  // malformed: ignore
  if (a >= complete) return RangeParse::kUnsat;
  *first = a;
  *last = have_b ? (b < complete - 1 ? b : complete - 1) : complete - 1;
  return RangeParse::kOne;
}

// If-Range holds ONE validator (RFC 9110 §14.2): an entity-tag,
// compared STRONGLY (a weak tag can never match), or an HTTP-date -
// unparsed here, and an unmatched validator lawfully serves the full
// 200, so a date reads as "no match" and stays correct.
inline bool if_range_matches(const char* v, size_t n, const char* tag, size_t taglen) {
  size_t i = 0;
  while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
  size_t e = n;
  while (e > i && (v[e - 1] == ' ' || v[e - 1] == '\t')) e--;
  return e - i == taglen && std::memcmp(v + i, tag, taglen) == 0;
}

// Accept-Encoding, asked the one question this tree has: may gzip be
// sent? (RFC 9110 §12.5.3.) Most specific wins: an explicit gzip (or
// its x-gzip alias, §12.5.3) decides by its own q; otherwise * decides;
// otherwise - the field is present but names neither - gzip is not
// acceptable. An empty value means "no codings": also not acceptable.
// Callers only ask when the field EXISTS; a missing field means any
// coding is acceptable and never reaches this parse.
inline bool gzip_acceptable(const char* v, size_t n) {
  bool gz_seen = false, gz_ok = false, star_seen = false, star_ok = false;
  size_t i = 0;
  while (i < n) {
    while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
    const size_t ts = i;
    while (i < n && v[i] != ',' && v[i] != ';' && v[i] != ' ' && v[i] != '\t') i++;
    const size_t tl = i - ts;
    // Parameters up to the next element; q's digits decide (weight is
    // 0[.000]..1[.000], so "any nonzero digit" IS "q > 0").
    bool q_nonzero = true;
    while (i < n && v[i] != ',') {
      if (v[i] != ';') {
        i++;
        continue;
      }
      i++;
      while (i < n && (v[i] == ' ' || v[i] == '\t')) i++;
      if (i < n && (v[i] == 'q' || v[i] == 'Q')) {
        size_t j = i + 1;
        while (j < n && (v[j] == ' ' || v[j] == '\t')) j++;
        if (j < n && v[j] == '=') {
          j++;
          q_nonzero = false;
          while (j < n && v[j] != ',' && v[j] != ';') {
            if (v[j] >= '1' && v[j] <= '9') q_nonzero = true;
            j++;
          }
          i = j;
        }
      }
    }
    if (tl != 0) {
      if (tok_eq(v + ts, tl, "gzip", 4) || tok_eq(v + ts, tl, "x-gzip", 6)) {
        gz_seen = true;
        gz_ok = q_nonzero;
      } else if (tl == 1 && v[ts] == '*') {
        star_seen = true;
        star_ok = q_nonzero;
      }
    }
  }
  if (gz_seen) return gz_ok;
  if (star_seen) return star_ok;
  return false;
}

// Does an If-Match/If-None-Match list contain `tag` (the full quoted
// form)? If-None-Match compares weakly - a W/ prefix is stripped and
// ignored (RFC 9110 §13.1.2); If-Match compares strongly, so a weak
// member can never match there (§13.1.1). The * form never reaches
// this parse - ReqFacts carries it as a fact.
inline bool etag_list_match(const char* v, size_t n, const char* tag, size_t taglen,
                            bool weak) {
  size_t i = 0;
  while (i < n) {
    while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
    if (i >= n) break;
    bool member_weak = false;
    if (i + 1 < n && v[i] == 'W' && v[i + 1] == '/') {
      member_weak = true;
      i += 2;
    }
    if (i >= n || v[i] != '"') {
      // Not an entity-tag; skip to the next element rather than trust
      // the rest of a malformed list.
      while (i < n && v[i] != ',') i++;
      continue;
    }
    const size_t start = i;
    i++;
    while (i < n && v[i] != '"') i++;
    if (i >= n) break;  // unterminated: nothing more to compare
    i++;
    const size_t mlen = i - start;
    if ((weak || !member_weak) && mlen == taglen &&
        std::memcmp(v + start, tag, taglen) == 0) {
      return true;
    }
  }
  return false;
}

// One length-switch per header - the hot-path shape stays ONE dispatch.
// The 9110 facts (conneg, preconditions, content-md5) are filled here;
// every name this layer does not own falls through to the framer's
// functor (9112 owns host/connection/transfer-encoding/content-length;
// 9113 owns none of them, §8.2.2). The functor inlines at each call
// site, where the case's length is a known constant - the compiler
// folds its checks to exactly the arms the old fused switch had.
template <class OnWire>
inline void header_switch(const char* name, size_t nlen, const char* value, size_t vlen,
                          flow::ReqFacts& facts, ReqValues& vals, OnWire&& wire) {
  switch (nlen) {
    case 5:
      if (tok_eq(name, nlen, "range", 5)) {
        vals.range = value;  // no fact, no plain: the graph has no range node
        vals.range_len = vlen;
        return;
      }
      break;
    case 6:
      if (tok_eq(name, nlen, "accept", 6)) {
        facts.has_accept = true;
        facts.plain = false;
        return;
      }
      break;
    case 8:
      if (tok_eq(name, nlen, "if-range", 8)) {
        vals.if_range = value;  // like range: representation-level only
        vals.if_range_len = vlen;
        return;
      }
      if (tok_eq(name, nlen, "if-match", 8)) {
        facts.has_if_match = true;
        facts.plain = false;
        facts.if_match_star = star_value(value, vlen);
        vals.if_match = value;
        vals.if_match_len = vlen;
        return;
      }
      break;
    case 11:
      if (tok_eq(name, nlen, "content-md5", 11)) {
        facts.has_content_md5 = true;
        facts.plain = false;
        return;
      }
      break;
    case 13:
      if (tok_eq(name, nlen, "if-none-match", 13)) {
        facts.has_if_none_match = true;
        facts.plain = false;
        facts.inm_star = star_value(value, vlen);
        vals.if_none_match = value;
        vals.if_none_match_len = vlen;
        return;
      }
      break;
    case 14:
      if (tok_eq(name, nlen, "accept-charset", 14)) {
        facts.has_accept_charset = true;
        facts.plain = false;
        return;
      }
      break;
    case 15:
      if (tok_eq(name, nlen, "accept-language", 15)) {
        facts.has_accept_language = true;
        facts.plain = false;
        return;
      }
      if (tok_eq(name, nlen, "accept-encoding", 15)) {
        facts.has_accept_encoding = true;
        facts.plain = false;
        vals.accept_encoding = value;
        vals.accept_encoding_len = vlen;
        return;
      }
      break;
    case 17:
      if (tok_eq(name, nlen, "if-modified-since", 17)) {
        // Date parsing is a later tier; an unparsed date reads as
        // invalid, which flow.rb's rescue path also ignores (L14).
        facts.has_if_modified_since = true;
        facts.plain = false;
        return;
      }
      break;
    case 19:
      if (tok_eq(name, nlen, "if-unmodified-since", 19)) {
        facts.has_if_unmodified_since = true;  // date tier pending, like IMS
        facts.plain = false;
        return;
      }
      break;
    default:
      break;
  }
  wire(name, nlen, value, vlen);
}

}  // namespace webmachine::http

#endif
