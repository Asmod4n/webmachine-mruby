#include "http1.hpp"

#include <picohttpparser.h>

#include <cstdlib>
#include <cstring>

#include "assets.hpp"
#include "gzip.hpp"
#include "h2.hpp"
#include "http.hpp"
#include "request.hpp"
#include "resource.hpp"

// Prediction hints only where the taken side is terminal (see ring.hpp).
#define WM_H1_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace webmachine {
namespace {

// The version-free HTTP semantics live in http.hpp (RFC 9110); this
// anonymous namespace holds only 9112 wire property.

// Connection is a comma-separated token list (RFC 9110 §7.6.1); a
// substring match would accept e.g. "not-close". The header itself is
// 9112 property - h2 forbids it (RFC 9113 §8.2.2).
bool conn_has(const char* v, size_t n, const char* lit, size_t litn) {
  size_t i = 0;
  while (i < n) {
    while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) i++;
    const size_t start = i;
    while (i < n && v[i] != ',' && v[i] != ' ' && v[i] != '\t') i++;
    if (http::tok_eq(v + start, i - start, lit, litn)) return true;
  }
  return false;
}

using http::kDateLen;
using http::kDatePlaceholder;

}  // namespace

void Http1::build_variants(Variants& v, uint16_t status, const char* extra, const char* body,
                           const char* date) {
  const auto build = [&](Resp& r, const char* conn) {
    r.bytes.clear();
    char line[16];
    line[0] = static_cast<char>('0' + status / 100);
    line[1] = static_cast<char>('0' + (status / 10) % 10);
    line[2] = static_cast<char>('0' + status % 10);
    line[3] = '\0';
    r.bytes.append("HTTP/1.1 ").append(line).append(" ").append(http::reason(status));
    r.bytes.append("\r\nDate: ");
    r.date_off = r.bytes.size();
    r.bytes.append(date).append("\r\n").append(conn).append(extra).append(body);
  };
  build(v.plain, "");
  build(v.keep, "Connection: keep-alive\r\n");
  build(v.close, "Connection: close\r\n");
}

void Http1::build_status(uint16_t status, const char* extra, const char* body) {
  Variants v;
  build_variants(v, status, extra, body, kDatePlaceholder);
  index_[status] = static_cast<uint16_t>(store_.size());
  store_.push_back(std::move(v));
}

void Http1::patch_date(Variants& v, const char* core) {
  std::memcpy(v.plain.bytes.data() + v.plain.date_off, core, kDateLen);
  std::memcpy(v.keep.bytes.data() + v.keep.date_off, core, kDateLen);
  std::memcpy(v.close.bytes.data() + v.close.date_off, core, kDateLen);
}

// ONE route's whole voice, built once (#116). Everything here used to
// be a member of Http1 itself, when an app had exactly one resource;
// the code is the same code, the owner is the route.
void Http1::build_bundle(Bundle& b, const Resource* res) {
  b.res = res;
  b.konst = res->konst;
  b.dynamic_body = res->dynamic_body;
  b.bound = res->dynamic != 0 || res->dynamic_body;
  // One transformation, at the ONE point every writer reads from:
  // ok_extra, the h2 blocks and the exception head all spell whatever
  // stands here (#146). The resource's own copy is untouched -
  // negotiation never string-compares this.
  b.konst.content_type = http::with_charset(b.konst.content_type);
  // Start from the generic table, then point the two statuses that
  // carry a resource's own voice at this route's own entries.
  b.index = index_;
  // 200 carries the resource's rendered representation (RFC 9110 8.3:
  // a body announces its Content-Type).
  std::string ok_extra;
  if (!b.konst.content_type.empty()) {
    ok_extra = "Content-Type: " + b.konst.content_type + "\r\n";
  }
  const std::string ok_tail =
      "Content-Length: " + std::to_string(b.konst.body.size()) + "\r\n\r\n" + b.konst.body;
  Variants ok;
  build_variants(ok, 200, ok_extra.c_str(), ok_tail.c_str(), kDatePlaceholder);
  // 405 names what IS allowed (RFC 9110 10.2.1), from THIS resource's
  // list - which is the whole reason 405 needs a per-route entry.
  const std::string allow = "Allow: " + b.konst.allow + "\r\n";
  Variants m405;
  build_variants(m405, 405, allow.c_str(), "Content-Length: 0\r\n\r\n", kDatePlaceholder);

  // The fast lane's DATA half, whole and precomputed: valid only when
  // the body never varies at all - !bound means status 200 always
  // sends konst.body verbatim, forever. stream id is patched per
  // response at its fixed offset (h2_patch_stream_id); END_STREAM is
  // baked in because h2_answer only ever reaches for this buffer when
  // it has already proven it will be the sole, last frame.
  if (!b.bound) {
    unsigned char fh[kH2FrameHeaderLen];
    h2_put_frame_header(fh, static_cast<uint32_t>(b.konst.body.size()), kH2Data,
                        kH2FlagEndStream, 0);
    b.h2_data200.assign(reinterpret_cast<const char*>(fh), sizeof(fh));
    b.h2_data200.append(b.konst.body);
  }

  // HEAD answers with 200's head and no body bytes (RFC 9110 9.3.2).
  {
    const size_t blen = b.konst.body.size();
    const auto strip = [&](const Resp& src, Resp& dst) {
      dst.bytes.assign(src.bytes, 0, src.bytes.size() - blen);
      dst.date_off = src.date_off;
    };
    strip(ok.plain, b.ok_head.plain);
    strip(ok.keep, b.ok_head.keep);
    strip(ok.close, b.ok_head.close);
  }
  // A per-request body assembles onto 200's head cut before
  // Content-Length: prefix + "Content-Length: N\r\n\r\n" + body.
  if (b.dynamic_body) {
    const size_t cut = ok_tail.size();  // ok's bytes end with the whole tail
    const auto prefix = [&](const Resp& src, Resp& dst) {
      dst.bytes.assign(src.bytes, 0, src.bytes.size() - cut);
      dst.date_off = src.date_off;
    };
    prefix(ok.plain, b.ok_prefix.plain);
    prefix(ok.keep, b.ok_prefix.keep);
    prefix(ok.close, b.ok_prefix.close);
  }
  // Into the shared store, one slot each; on_tick patches them with
  // every other prebuilt status and never walks a per-route list.
  b.index[200] = static_cast<uint16_t>(store_.size());
  store_.push_back(std::move(ok));
  {
    H2Block hb;
    h2_build_block(hb, 200, &b.konst.content_type, nullptr);
    h2_store_.push_back(std::move(hb));
  }
  b.index[405] = static_cast<uint16_t>(store_.size());
  store_.push_back(std::move(m405));
  {
    H2Block hb;
    h2_build_block(hb, 405, nullptr, &b.konst.allow);
    h2_store_.push_back(std::move(hb));
  }
  // #147: this resource's own answer to TOR 2 (media-type table) and
  // "encodings_provided says gzip" - decided ONCE, here, never again.
  // A resource that fails either test costs no branch beyond this bool
  // at answer time. Built directly rather than sliced from b.ok the
  // way ok_prefix is above, because these carry headers (Vary,
  // Content-Encoding) the konst 200 head never has.
  b.gzip_ok = b.dynamic_body && res->gzip_offered &&
              http::compressible_media_type(b.konst.content_type);
  if (b.gzip_ok) {
    const auto buildv = [&](Resp& r, const char* conn, const char* enc) {
      r.bytes.clear();
      r.bytes.append("HTTP/1.1 200 OK\r\nDate: ");
      r.date_off = r.bytes.size();
      r.bytes.append(kDatePlaceholder).append("\r\n").append(conn).append(ok_extra).append(enc);
    };
    buildv(b.ok_prefix_vary.plain, "", "Vary: Accept-Encoding\r\n");
    buildv(b.ok_prefix_vary.keep, "Connection: keep-alive\r\n", "Vary: Accept-Encoding\r\n");
    buildv(b.ok_prefix_vary.close, "Connection: close\r\n", "Vary: Accept-Encoding\r\n");
    buildv(b.ok_prefix_gzip.plain, "", "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n");
    buildv(b.ok_prefix_gzip.keep, "Connection: keep-alive\r\n",
           "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n");
    buildv(b.ok_prefix_gzip.close, "Connection: close\r\n",
           "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n");
  }
  // Exceptions answer as the negotiated type: a 500 head open for a
  // per-request body carrying the reason.
  if (b.bound) {
    const auto build = [&](Resp& r, const char* conn) {
      r.bytes.clear();
      r.bytes.append("HTTP/1.1 500 Internal Server Error\r\nDate: ");
      r.date_off = r.bytes.size();
      r.bytes.append(kDatePlaceholder).append("\r\n").append(conn).append(ok_extra);
    };
    build(b.err_prefix.plain, "");
    build(b.err_prefix.keep, "Connection: keep-alive\r\n");
    build(b.err_prefix.close, "Connection: close\r\n");
    // h2's exception answer: 500 in the negotiated type.
    h2_build_block(b.h2_err, 500, &b.konst.content_type, nullptr);
  }
}

Http1::Http1(const RouteTable& table, const Resource* const* resources, size_t nroutes,
             Assets* assets)
    : assets_(assets) {
  const AppInput one{&table, resources, nroutes};
  build(&one, 1);
}

Http1::Http1(const AppInput* apps, size_t napps, Assets* assets) : assets_(assets) {
  build(apps, napps);
}

void Http1::build(const AppInput* apps, size_t napps) {
  // Every status the flow's halt edges can speak, plus the framer's own
  // wire refusals - collected from the table, built ONCE. The 200 and
  // 405 slots are built NEUTRALLY here (no content type, no Allow):
  // they exist so index_ stays total for any status the tables name,
  // and a matched route never reads them - its bundle owns those two.
  store_.reserve(32);
  bool have[600] = {};
  const auto add = [&](uint16_t s) {
    if (have[s]) return;
    have[s] = true;
    // 204/304 are defined bodyless (RFC 9110 15.3.5/15.4.5): no
    // Content-Length, no body.
    if (s == 204 || s == 304) build_status(s, "", "\r\n");
    else build_status(s, "", "Content-Length: 0\r\n\r\n");
    // The same status precomputed as h2's header block (same slot as
    // store_ via index_).
    H2Block b;
    h2_build_block(b, s, nullptr, nullptr);
    h2_store_.push_back(std::move(b));
  };
  for (const auto& f : flow::kFlow) {
    if (f.on_true.status != 0) add(f.on_true.status);
    if (f.on_false.status != 0) add(f.on_false.status);
  }
  add(400);
  add(411);
  add(413);
  add(431);
  // The router's own answer: a path no route claims is 404, built here
  // like every other prebuilt status (the flow tables already name it,
  // so this is a no-op the day they stop).
  add(404);

  // Every app's routes go into ONE bundle vector, back to back; the
  // app's slot remembers where its own start. A request therefore
  // still indexes once (base + the router's verdict), and the date
  // patch above stays one loop for the whole process.
  size_t total = 0;
  for (size_t a = 0; a < napps; a++) total += apps[a].nroutes;
  bundles_.resize(total);
  apps_.resize(napps);
  size_t at = 0;
  for (size_t a = 0; a < napps; a++) {
    apps_[a].table = apps[a].table;
    apps_[a].base = static_cast<uint16_t>(at);
    apps_[a].count = static_cast<uint16_t>(apps[a].nroutes);
    for (size_t i = 0; i < apps[a].nroutes; i++) {
      build_bundle(bundles_[at + i], apps[a].resources[i]);
    }
    at += apps[a].nroutes;
  }

  // The warm budget, read once (see kWarmBudgetDefault for the
  // measurement behind the number). 0 is legal and means "never copy,
  // always deliver" - it is one end of the sweep.
  if (const char* w = std::getenv("WM_WARM_BUDGET")) {
    char* end = nullptr;
    const unsigned long v = std::strtoul(w, &end, 10);
    if (end != w) warm_budget_ = static_cast<size_t>(v);
  }

  // The asset tier's h2 blocks (#170): per entry once, at setup, plus
  // the shared 405/406. The h1 heads were prebuilt by Assets::open.
  if (assets_ != nullptr) {
    h2_build_asset_shared();
    for (AssetEntry& e : assets_->entries()) h2_build_asset_blocks(e);
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
  http::date_core(date_, tm);
  const char* core = date_;

  for (Variants& v : store_) patch_date(v, core);
  // Per route, only the shapes that route actually built. This is the
  // one place the multi-resource cut costs work proportional to the
  // number of routes, and it is per SECOND, never per request.
  for (Bundle& b : bundles_) {
    patch_date(b.ok_head, core);
    if (b.dynamic_body) patch_date(b.ok_prefix, core);
    if (b.gzip_ok) {
      patch_date(b.ok_prefix_vary, core);
      patch_date(b.ok_prefix_gzip, core);
    }
    if (b.bound) patch_date(b.err_prefix, core);
  }
  // The h2 blocks carry no date - it changes, so it rides the encoder
  // lane per response, reading date_ directly.
}

void Http1::assemble(std::string& sink, const Resp& prefix, const char* body, size_t len,
                     bool head_only) {
  sink.append(prefix.bytes);
  char cl[40];
  sink.append(cl, http::spell_content_length(cl, len));
  if (!head_only) sink.append(body, len);
}

// #147: called only when the route's gzip_ok - the caller already paid
// the one branch that costs every other resource nothing.
void Http1::assemble_dynamic(const Conn& st, const flow::ReqFacts& facts,
                             const http::ReqValues& vals, const Resp& prefix_id,
                             const Resp& prefix_gz, bool head_only, std::string& sink) {
  // RFC 9110 12.5.3: a missing Accept-Encoding accepts anything: the
  // asset tier (#170) reads the SAME field the same way - the rule is
  // pulled out, not duplicated, only in that http::gzip_acceptable is
  // the shared code and "was the field even sent" is each caller's own
  // one-line gate around it (h1 here, http/2 has no separate copy to
  // duplicate against - it goes through this same function).
  const bool accept_gzip =
      !facts.has_accept_encoding || http::gzip_acceptable(vals.accept_encoding,
                                                           vals.accept_encoding_len);
  bool use_gzip = false;
  // TOR 1, revised (Nutzer-Entscheid 2026-08-22): packetized (TCP, not
  // unix behind a proxy - #147) is the first gate, kCompressFloor the
  // second, replacing the per-connection MSS query this tree used to
  // make at accept (see kCompressFloor's comment in http1.hpp for the
  // full reasoning and the kernel finding that forced the retreat).
  if (accept_gzip && st.packetized) {
    char cl[40];
    const size_t cl_len = http::spell_content_length(cl, body_.size());
    // The UNCOMPRESSED answer's total size - head (already carrying
    // Vary) plus Content-Length line plus body - against the floor.
    // Below it: identity, compression could not have saved a packet
    // even on the narrowest legal path (#147 Tor 1).
    if (prefix_id.bytes.size() + cl_len + body_.size() >= kCompressFloor) {
      use_gzip = gzip::compress(body_, gz_body_);  // false: fall back to identity, never fail
    }
  }
  if (use_gzip) assemble(sink, prefix_gz, gz_body_.data(), gz_body_.size(), head_only);
  else assemble(sink, prefix_id, body_.data(), body_.size(), head_only);
}

bool Http1::fail(Conn& st, uint16_t status, std::string& sink) {
  // Wire invalidity: framing trust is gone, the connection always ends.
  sink.append(variants(status).close.bytes);
  st.carry.clear();
  st.body_skip = 0;
  return false;
}

bool Http1::feed(Conn& st, const char* data, size_t len, std::string& sink) {
  // A connection that spoke the client preface routes its bytes to the
  // frame layer forever after (RFC 9113 3.4); everything below is h1.
  if (st.h2 != nullptr) return h2_feed(st, data, len, sink);
  if (st.fresh) {
    // Decided on the first bytes: GET diverges at byte 0, POST/PUT at
    // byte 1 - the h1 path pays for this compare exactly once per
    // connection, never per request.
    const size_t seen = st.carry.size();  // a partial preface carried over
    size_t i = 0;
    while (i < len && seen + i < kH2PrefaceLen && data[i] == kH2Preface[seen + i]) i++;
    if (seen + i == kH2PrefaceLen) {  // the full preface: h2 from here on
      st.fresh = false;
      st.carry.clear();
      if (!h2_begin(st, sink)) return false;
      return h2_feed(st, data + i, len - i, sink);
    }
    if (i == len) {  // every byte so far matches: wait for the verdict
      st.carry.append(data, len);
      return true;
    }
    // Mismatch: h1 forever. Any stashed preface prefix doubles as a
    // partial h1 head; the carry path below already handles it.
    st.fresh = false;
  }
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

  // An active transfer owns the wire order (#168): responses to
  // anything pipelined behind it would overtake its remaining chunks.
  // The bytes wait in the carry; more() resumes parsing them when the
  // source is exhausted. One head's budget bounds the wait - a peer
  // stuffing more than that behind a running transfer wants buffer,
  // not service (RFC 6585 §5 sanctions the refusal).
  if (WM_H1_UNLIKELY(st.xfer != nullptr)) {
    if (WM_H1_UNLIKELY(st.carry.size() + len > kMaxHead)) {
      // Mid-body no status can be spoken (the bytes would land inside
      // the transfer's Content-Length); the connection just ends.
      st.carry.clear();
      st.body_skip = 0;
      st.xfer = nullptr;
      return false;
    }
    st.carry.append(data, len);
    return true;
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
    uint16_t wire_err = 0;  // first wire violation wins; the loop is bounded
    flow::ReqFacts facts;
    http::ReqValues vals;  // value borrows die with this request's answer
    facts.method = http::parse_method(method, method_len);
    for (size_t i = 0; i < num_headers; i++) {
      const struct phr_header& h = headers[i];
      // The 9110 facts fill in http.hpp's length-switch; the functor
      // carries the 9112 wire names. It inlines per case arm, where
      // the length is a known constant - the compiled result is the
      // ONE fused switch this loop always was.
      http::header_switch(
          h.name, h.name_len, h.value, h.value_len, facts, vals,
          [&](const char* n, size_t nl, const char* v, size_t vl) {
            if (wire_err != 0) return;
            switch (nl) {
              case 14:
                if (http::tok_eq(n, nl, "content-length", 14)) {
                  // A second Content-Length is a smuggling shape (RFC 9112 §6.3).
                  if (WM_H1_UNLIKELY(have_cl)) {
                    wire_err = 400;
                    return;
                  }
                  have_cl = true;
                  switch (http::parse_content_length(v, vl, &content_length)) {
                    case http::ClStatus::kOk: break;
                    case http::ClStatus::kBad: wire_err = 400; break;  // 1*DIGIT, §6.2
                    case http::ClStatus::kOverflow: wire_err = 413; break;
                  }
                }
                break;
              case 17:
                if (http::tok_eq(n, nl, "transfer-encoding", 17)) have_te = true;
                break;
              case 4:
                if (http::tok_eq(n, nl, "host", 4)) {
                  if (WM_H1_UNLIKELY(have_host)) wire_err = 400;  // RFC 9112 §3.2: one
                  have_host = true;
                }
                break;
              case 10:
                if (http::tok_eq(n, nl, "connection", 10)) {
                  if (conn_has(v, vl, "close", 5)) conn_close = true;
                  else if (conn_has(v, vl, "keep-alive", 10)) conn_keep = true;
                }
                break;
              default:
                break;
            }
          });
    }
    if (WM_H1_UNLIKELY(wire_err != 0)) return fail(st, wire_err, sink);
    // Transfer-Encoding alongside Content-Length is the classic
    // smuggling vector (RFC 9112 §6.3.3); chunked alone is refused with
    // 411 as §6.1 sanctions until a body consumer exists.
    if (WM_H1_UNLIKELY(have_te)) return fail(st, have_cl ? 400 : 411, sink);
    if (WM_H1_UNLIKELY(minor >= 1 && !have_host)) return fail(st, 400, sink);  // RFC 9112 §3.2
    if (WM_H1_UNLIKELY(content_length > kMaxBody)) return fail(st, 413, sink);

    // RFC 9112 §9.3: 1.1 persists unless close; 1.0 closes unless it
    // asked (§C.2.2), and the asked-for keep-alive is echoed.
    const bool persist = minor >= 1 ? !conn_close : conn_keep;
    const bool head_only = facts.method == flow::Method::kHead;

    // The asset tier (#170): a path naming a ZIP entry answers from
    // the table, before the flow - the first thing in this tree that
    // reads the request-target at all. A miss falls through to the app
    // resource unchanged (the general router is #116's).
    if (assets_ != nullptr) {
      if (AssetEntry* ae = assets_->find(path, path_len)) {
        const uint16_t as = assets_->verdict(*ae, facts.method, facts, vals);
        bool started_xfer = false;
        if (as == 412 || as == 501) {
          // Nothing asset-specific in these; the shared store answers.
          const Variants& sv = variants(as);
          sink.append(minor >= 1 ? (persist ? sv.plain.bytes : sv.close.bytes)
                                 : (persist ? sv.keep.bytes : sv.close.bytes));
        } else {
          const Assets::Variant av = minor >= 1 ? (persist ? Assets::kPlain : Assets::kClose)
                                                : (persist ? Assets::kKeep : Assets::kClose);
          // Range (#148): defined for GET alone (RFC 9110 14.2 - a
          // HEAD carrying Range answers the plain 200 head), on the
          // 200 verdict alone, and only past a matching If-Range (an
          // unmatched or date-form validator lawfully serves the full
          // 200). The window counts WIRE-body octets - a range over a
          // gzip response ranges the encoded stream, structurally.
          uint16_t rs = 0;
          size_t rf = 0, rl = 0;
          if (as == 200 && !head_only && facts.method == flow::Method::kGet &&
              vals.range != nullptr &&
              (vals.if_range == nullptr ||
               http::if_range_matches(vals.if_range, vals.if_range_len, ae->etag,
                                      sizeof(ae->etag)))) {
            switch (http::parse_range(vals.range, vals.range_len, Assets::wire_len(*ae),
                                      &rf, &rl)) {
              case http::RangeParse::kOne: rs = 206; break;
              case http::RangeParse::kUnsat: rs = 416; break;
              case http::RangeParse::kNone: break;  // ignored: the full 200
            }
          }
          if (rs == 416) {
            assets_->answer_416_head(*ae, av, date_, sink);
          } else if (rs == 206) {
            assets_->answer_206_head(*ae, av, rf, rl, date_, sink);
            const size_t rlen = rl - rf + 1;
            if (rlen <= warm_budget_) {
              Assets::copy_wire(*ae, rf, rlen, sink);
            } else {
              st.xfer = ae;
              st.xfer_off = rf;
              st.xfer_end = rl + 1;
              started_xfer = true;
            }
          } else {
            assets_->answer_head(*ae, as, av, date_, sec_, sink);
            if (as == 200 && !head_only) {
              // Delivery (#168): a body within the WARM BUDGET is
              // copied and leaves with its head in one append - the
              // degenerate case of the model, and the fast path. Above
              // it the entry becomes the connection's source and every
              // body round goes through more(), which hands the Ring
              // pointers instead of bytes; only the head leaves here.
              const size_t wlen = Assets::wire_len(*ae);
              if (wlen <= warm_budget_) {
                Assets::copy_wire(*ae, 0, wlen, sink);
              } else {
                st.xfer = ae;
                st.xfer_off = 0;
                st.xfer_end = wlen;
                started_xfer = true;
              }
            }
          }
        }
        off += static_cast<size_t>(ret);
        if (content_length != 0) {
          const size_t avail = viewlen - off;
          const size_t skip = content_length < avail ? content_length : avail;
          off += skip;
          st.body_skip = content_length - skip;
        }
        if (!persist) {
          st.carry.clear();
          st.body_skip = 0;
          return false;  // false still delivers: more() drains the source first
        }
        if (started_xfer) {
          // The transfer owns the wire order: the rest of this view is
          // pipelined behind it and waits in the carry (more() resumes
          // parsing when the source is exhausted).
          const size_t rest = viewlen - off;
          if (in_place) st.carry.assign(view + off, rest);
          else st.carry.erase(0, off);
          return true;
        }
        continue;
      }
    }

    // THE ROUTER (#116). One walk of the app's constant table decides
    // which resource answers - literals by memcmp, symbols and :*
    // captured as spans nothing reads yet (router.hpp says why they
    // are captured anyway). A MISS answers the prebuilt 404 and stops
    // here: before B13, therefore before any method test, so POST on
    // an unknown path is 404 and never 405.
    // WHOSE table: the listener the Ring wrote into this connection at
    // accept (#116 slice 2). One indexed load, no search, no branch -
    // a one-app process reads slot 0 every time.
    const AppSlot& slot = apps_[st.listener];
    RouteSpans spans;
    const int route = slot.table->match(path, path_len, spans);
    const Bundle* b = nullptr;
    // Which status table answers, settled INSIDE the branch that was
    // going to be taken anyway - so the writer below stays one indexed
    // load with no test of its own.
    const std::array<uint16_t, 600>* idx = &index_;
    uint16_t status;
    bool have_body = false;
    if (WM_H1_UNLIKELY(route < 0)) {
      status = 404;
    } else {
      b = &bundles_[slot.base + static_cast<size_t>(route)];
      idx = &b->index;
      // The wire is valid; from here the FLOW decides the status. Konst
      // answers are compiled into the method's vector; dynamic nodes -
      // instance methods, by declaration - are asked through the VM per
      // request. Konst resources never see the VM; anything dynamic
      // runs the whole flow inside ONE VM frame (this branch is
      // deployment-stable: no hint).
      if (b->bound) {
        // The request the callbacks may ask about (#116 slice 4). Built
        // on THIS frame out of what the framer and the router already
        // held - the spans the match captured, the target bytes still
        // in the receive buffer - and nothing in it is materialised
        // until a callback asks.
        ReqView rv;
        rv.target = path;
        rv.target_len = path_len;
        rv.path_len = http::path_only(path, path_len);
        rv.method = facts.method;
        rv.method_p = method;
        rv.method_n = method_len;
        rv.table = slot.table;
        rv.route = route;
        rv.spans = spans;
        status = resource_run(*b->res, facts, &rv, &body_, &have_body);
      } else {
        status = flow::answer(facts, b->konst.per_method[static_cast<size_t>(facts.method)],
                             b->konst.shortcut[static_cast<size_t>(facts.method)]);
      }
    }

    bool answered = false;
    if (have_body && status == 200) {
      // Rendered inside the run frame, copied there while the frame
      // rooted it; HEAD renders too - its Content-Length must be the
      // GET's - but sends no body bytes (RFC 9110 9.3.2).
      if (b->gzip_ok) {
        // #147: deployment-stable like bound above - a resource either
        // declared gzip or it never did, so no hint (see WM_H1_UNLIKELY's
        // own rule: only for a branch that swings per request).
        assemble_dynamic(
            st, facts, vals,
            minor >= 1 ? (persist ? b->ok_prefix_vary.plain : b->ok_prefix_vary.close)
                       : (persist ? b->ok_prefix_vary.keep : b->ok_prefix_vary.close),
            minor >= 1 ? (persist ? b->ok_prefix_gzip.plain : b->ok_prefix_gzip.close)
                       : (persist ? b->ok_prefix_gzip.keep : b->ok_prefix_gzip.close),
            head_only, sink);
      } else {
        assemble(sink, minor >= 1 ? (persist ? b->ok_prefix.plain : b->ok_prefix.close)
                                  : (persist ? b->ok_prefix.keep : b->ok_prefix.close),
                 body_.data(), body_.size(), head_only);
      }
      answered = true;
    }
    if (WM_H1_UNLIKELY(!answered && status == 500 && b != nullptr && b->bound)) {
      // A raising callback answers in the negotiated type, the reason
      // as body - the exception was left pending for exactly this.
      // Copied before any mruby call can run.
      const char* bp = nullptr;
      size_t blen = 0;
      if (resource_exception_begin(*b->res, &bp, &blen)) {
        assemble(sink, minor >= 1 ? (persist ? b->err_prefix.plain : b->err_prefix.close)
                                  : (persist ? b->err_prefix.keep : b->err_prefix.close),
               bp, blen, head_only);
        answered = true;
      }
    }
    if (!answered) {
      // The route's own table for a matched request (its 200 and 405
      // sit in the shared store like everything else, at slots only
      // its index names), the generic one for a router miss. The shape
      // is one indexed load either way - exactly what a single-resource
      // app paid.
      const Variants& sv =
          (head_only && status == 200) ? b->ok_head : store_[(*idx)[status]];
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
      st.carry.clear();
      st.body_skip = 0;
      return false;
    }
  }
  if (!in_place) st.carry.clear();
  return true;
}

}  // namespace webmachine
