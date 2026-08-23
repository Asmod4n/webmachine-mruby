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
#include "websocket.hpp"
#include "wsdeflate.hpp"

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
  size_t ws_at = 0;
  for (size_t a = 0; a < napps; a++) {
    apps_[a].table = apps[a].table;
    apps_[a].base = static_cast<uint16_t>(at);
    apps_[a].count = static_cast<uint16_t>(apps[a].nroutes);
    for (size_t i = 0; i < apps[a].nroutes; i++) {
      build_bundle(bundles_[at + i], apps[a].resources[i]);
    }
    at += apps[a].nroutes;
    // The websocket routes (#175): a second table, walked only when a
    // head asks for an upgrade, and nothing built for it here - a
    // websocket has no prebuilt status to speak.
    apps_[a].ws_table = apps[a].ws_nroutes != 0 ? apps[a].ws_table : nullptr;
    apps_[a].ws_base = static_cast<uint16_t>(ws_at);
    for (size_t i = 0; i < apps[a].ws_nroutes; i++) {
      ws_res_.push_back(apps[a].ws_resources[i]);
    }
    ws_at += apps[a].ws_nroutes;
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
  alog_.sec = static_cast<int64_t>(now);
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

bool Http1::fail(Conn& st, uint16_t status, std::string& sink, uint8_t log_flags) {
  // Wire invalidity: framing trust is gone, the connection always ends.
  // The log line has no request to describe - most callers never got a
  // parsed head - so every request field spells "-"; the status is the
  // story. Callers past the header loop pass the peer's no-track ask.
  if (alog_.enabled) {
    alog_.line(st.peer, st.peer_len, nullptr, 0, "-", 1, log_flags, status, 0, nullptr, 0,
               nullptr, 0);
  }
  sink.append(variants(status).close.bytes);
  st.carry.clear();
  st.body_skip = 0;
  return false;
}

bool Http1::feed(Conn& st, const char* data, size_t len, std::string& sink, Plan* plan) {
  // A connection that spoke the client preface routes its bytes to the
  // frame layer forever after (RFC 9113 3.4); everything below is h1.
  if (st.h2 != nullptr) return h2_feed(st, data, len, sink, plan);
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
      return h2_feed(st, data + i, len - i, sink, plan);
    }
    if (i == len) {  // every byte so far matches: wait for the verdict
      st.carry.append(data, len);
      return true;
    }
    // WHERE the mismatch fell decides who the peer is, and that is the
    // whole of RFC 9113 3.4's advice: "an invalid preface indicates
    // that the peer is not using HTTP/2".
    //
    // Past the announcement half - the 18 bytes "PRI * HTTP/2.0" CRLF
    // CRLF, which no HTTP/1 request line can be a prefix of - the peer
    // HAS named itself an h2 client and then fumbled the rest. It is
    // waiting for a frame and cannot read a status line, so it gets
    // the frame 3.4 names: GOAWAY, PROTOCOL_ERROR, last-stream-id 0
    // (none was ever opened), then the connection ends.
    //
    // Before it, the peer never said "PRI" at all, so by 3.4's own
    // sentence it is not an h2 client - and this listener also speaks
    // HTTP/1.1, so it gets the HTTP/1.1 answer to a request line that
    // does not parse: 400, Connection: close (RFC 9112 2.2). That is
    // the ONE h2spec case this tree does not pass (3.5/2, "Sends
    // invalid connection preface" - h2spec sends "INVALID CONNECTION
    // PREFACE" CRLF CRLF and reads our status line as a frame header).
    // Named, not accidental: h2spec measures an h2-ONLY endpoint, the
    // connection dies either way as 3.4 requires, and the alternative
    // - closing a fresh connection mute - would take the 400 away from
    // every real HTTP/1 client that mistypes its first request line.
    if (seen + i >= kH2PrefaceAnnounce) {
      static const unsigned char kGoaway[kH2FrameHeaderLen + 8] = {
          0, 0, 8, kH2Goaway, 0, 0, 0, 0, 0,  // length 8, stream 0
          0, 0, 0, 0,                         // last stream id: none was opened
          0, 0, 0, kH2ProtocolError};
      sink.append(reinterpret_cast<const char*>(kGoaway), sizeof(kGoaway));
      return false;
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

  // Past the 101 this connection is not HTTP any more (#175): every
  // byte belongs to the websocket half, which keeps its own carry.
  if (WM_H1_UNLIKELY(st.ws != nullptr)) return ws_feed(st.ws, data, len, sink);

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
    // The upgrade's four facts (RFC 6455 4.2.1), read in the same one
    // switch every other wire name is read in - a head that asks for
    // nothing costs the compare its length already implied.
    bool up_ws = false, conn_upgrade = false;
    const char* ws_key = nullptr;
    size_t ws_key_len = 0;
    int ws_version = 0;
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
                else if (http::tok_eq(n, nl, "sec-websocket-key", 17)) {
                  ws_key = v;
                  ws_key_len = vl;
                }
                break;

              case 4:
                if (http::tok_eq(n, nl, "host", 4)) {
                  if (WM_H1_UNLIKELY(have_host)) wire_err = 400;  // RFC 9112 §3.2: one
                  have_host = true;
                }
                break;
              case 10:
                if (http::tok_eq(n, nl, "user-agent", 10)) {
                  vals.log_ua = v;
                  vals.log_ua_len = vl;
                } else if (http::tok_eq(n, nl, "connection", 10)) {
                  if (conn_has(v, vl, "close", 5)) conn_close = true;
                  else if (conn_has(v, vl, "keep-alive", 10)) conn_keep = true;
                  // RFC 9110 7.8: Connection is a token LIST, and a
                  // browser sends "keep-alive, Upgrade" - so this is a
                  // third test on the same list, not an else.
                  if (conn_has(v, vl, "upgrade", 7)) conn_upgrade = true;
                }
                break;
              case 7:
                if (http::tok_eq(n, nl, "referer", 7)) {
                  vals.log_ref = v;
                  vals.log_ref_len = vl;
                  break;
                }
                // RFC 6455 4.2.1 step 3: "websocket", case-insensitive.
                if (http::tok_eq(n, nl, "upgrade", 7)) {
                  up_ws = http::tok_eq(v, vl, "websocket", 9);
                }
                break;

              case 21:
                if (http::tok_eq(n, nl, "sec-websocket-version", 21)) {
                  ws_version = 0;
                  for (size_t j = 0; j < vl; j++) {
                    if (v[j] < '0' || v[j] > '9') { ws_version = -1; break; }
                    ws_version = ws_version * 10 + (v[j] - '0');
                    if (ws_version > 999) { ws_version = -1; break; }
                  }
                }
                break;
              default:
                break;
            }
          });
    }
    // The head parsed, so the peer's "do not track" ask is known -
    // every log line below this point carries it, refusals included.
    const uint8_t lflags = facts.no_track ? kLogNoTrack : 0;
    if (WM_H1_UNLIKELY(wire_err != 0)) return fail(st, wire_err, sink, lflags);
    // Transfer-Encoding alongside Content-Length is the classic
    // smuggling vector (RFC 9112 §6.3.3); chunked alone is refused with
    // 411 as §6.1 sanctions until a body consumer exists.
    if (WM_H1_UNLIKELY(have_te)) return fail(st, have_cl ? 400 : 411, sink, lflags);
    if (WM_H1_UNLIKELY(minor >= 1 && !have_host)) return fail(st, 400, sink, lflags);  // §3.2
    if (WM_H1_UNLIKELY(content_length > kMaxBody)) return fail(st, 413, sink, lflags);

    // RFC 9112 §9.3: 1.1 persists unless close; 1.0 closes unless it
    // asked (§C.2.2), and the asked-for keep-alive is echoed.
    const bool persist = minor >= 1 ? !conn_close : conn_keep;
    const bool head_only = facts.method == flow::Method::kHead;

    // THE UPGRADE (#175). RFC 6455 4.2.1: Upgrade: websocket AND
    // upgrade in the Connection list. A path no websocket route claims
    // falls straight through to the ordinary request path - RFC 9110
    // 7.8 lets a server ignore an upgrade it does not offer, and that
    // is exactly what happens then.
    if (WM_H1_UNLIKELY(up_ws && conn_upgrade)) {
      const AppSlot& wslot = apps_[st.listener];
      RouteSpans wspans;
      const int wr =
          wslot.ws_table != nullptr ? wslot.ws_table->match(path, path_len, wspans) : -1;
      if (wr >= 0) {
        // 4.4: the version this endpoint speaks is 13, and a peer that
        // asked for another one is told WHICH - that is what makes 426
        // useful instead of merely negative.
        if (ws_version != 13) {
          sink.append("HTTP/1.1 426 Upgrade Required\r\nDate: ");
          sink.append(date_, http::kDateLen);
          sink.append(
              "\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\n"
              "Content-Length: 0\r\n\r\n");
          return false;
        }
        // 4.1: the handshake is a GET, and it carries a key.
        if (facts.method != flow::Method::kGet || ws_key == nullptr) {
          return fail(st, 400, sink, lflags);
        }
        const char* rest = view + off + static_cast<size_t>(ret);
        const size_t rest_len = viewlen - off - static_cast<size_t>(ret);
        return ws_upgrade(st, wslot, wr, path, path_len, wspans, ws_key, ws_key_len, headers,
                          num_headers, rest, rest_len, sink);
      }
    }

    // The asset tier (#170): a path naming a ZIP entry answers from
    // the table, before the flow - the first thing in this tree that
    // reads the request-target at all. A miss falls through to the app
    // resource unchanged (the general router is #116's).
    if (assets_ != nullptr) {
      if (AssetEntry* ae = assets_->find(path, path_len)) {
        const uint16_t as = assets_->verdict(*ae, facts.method, facts, vals);
        bool started_xfer = false;
        uint16_t alog_st = as;
        size_t alog_by = 0;
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
            alog_st = 416;
            assets_->answer_416_head(*ae, av, date_, sink);
          } else if (rs == 206) {
            alog_st = 206;
            assets_->answer_206_head(*ae, av, rf, rl, date_, sink);
            const size_t rlen = rl - rf + 1;
            alog_by = rlen;
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
              alog_by = Assets::wire_len(*ae);
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
        if (alog_.enabled) {
          alog_.line(st.peer, st.peer_len, method, method_len, path, path_len, lflags, alog_st,
                     alog_by, vals.log_ref, vals.log_ref_len, vals.log_ua, vals.log_ua_len);
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
          // When the Ring handed a plan in, the transfer leaves WITH
          // its head in this very round: the sink (head + everything
          // before it) is one leading segment, the wire body follows
          // as pointers, and the head-only round this used to cost is
          // gone. Without a plan (a send in flight) the park stands
          // and more() delivers, as before.
          if (plan != nullptr) {
            // The head counts against the round's byte bound too - it
            // rides the same sendmsg. No room past it: plan nothing,
            // the head goes as a plain send and the park stands.
            const size_t room = plan->byte_cap == 0 ? st.xfer_end - st.xfer_off
                                : plan->byte_cap > sink.size() ? plan->byte_cap - sink.size()
                                                               : 0;
            size_t take = st.xfer_end - st.xfer_off;
            if (take > room) take = room;
            if (take > 0) {
              plan->seg[plan->nseg++] = Plan::Seg{nullptr, 0, sink.size()};
              plan->iov_len += sink.size();
              struct iovec iv[3];
              const unsigned k = Assets::wire_iov(*st.xfer, st.xfer_off, take, iv);
              for (unsigned i = 0; i < k; i++) {
                plan->seg[plan->nseg++] =
                    Plan::Seg{static_cast<const char*>(iv[i].iov_base), 0, iv[i].iov_len};
              }
              plan->iov_len += take;
              st.xfer_off += take;
              if (st.xfer_off == st.xfer_end) {
                st.xfer = nullptr;
                st.xfer_off = 0;
                st.xfer_end = 0;
              }
            }
          }
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
        // The head itself, lent off this frame: two stores, and only
        // in the branch that was going to run a resource anyway.
        rv.hdrs = headers;
        rv.nhdr = num_headers;
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
    if (alog_.enabled) {
      // %b for the dynamic 200 is the identity length - the gzip arm's
      // wire size is conneg's secret, and re-deciding it here for a
      // log column would be work per line. Prebuilt-store answers log
      // "-": their body lengths were baked into bytes at build.
      alog_.line(st.peer, st.peer_len, method, method_len, path, path_len, lflags, status,
                 (answered && !head_only) ? body_.size() : 0, vals.log_ref, vals.log_ref_len,
                 vals.log_ua, vals.log_ua_len);
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

// THE HANDSHAKE'S ANSWER (#175, RFC 6455 4.2.2). Everything that could
// be decided from the wire was decided by feed; what is left is the
// resource's own say and 129 bytes of head.
bool Http1::ws_upgrade(Conn& st, const AppSlot& slot, int route, const char* path,
                       size_t path_len, const RouteSpans& spans, const char* key,
                       size_t key_len, const void* hdrs, size_t nhdr, const char* rest,
                       size_t rest_len, std::string& sink) {
  char accept[28];
  // 4.2.1 step 5.4: the key is 16 bytes base64'd. A key that is not
  // that is the one thing the client half must get right.
  if (!ws::accept_key(key, key_len, accept)) return fail(st, 400, sink);

  const WsResource* res = ws_res_[slot.ws_base + static_cast<size_t>(route)];

  // The resource's own say, with the handshake's head still LIVE: this
  // is where a subprotocol is chosen, an Origin refused, a token in the
  // query checked (#175's whole reason for request.headers).
  ReqView rv;
  rv.target = path;
  rv.target_len = path_len;
  rv.path_len = http::path_only(path, path_len);
  rv.method = flow::Method::kGet;
  rv.table = slot.ws_table;
  rv.route = route;
  rv.spans = spans;
  rv.hdrs = hdrs;
  rv.nhdr = nhdr;
  request_bind(&rv);
  std::string proto;
  uint16_t refuse_status = 0;
  // The peer's own resource is built here and its initialize decides
  // (#181); what comes back IS this peer's connection, owning that
  // object until ws_free.
  WsConn* wsc = ws_admit(res, proto, refuse_status);
  request_bind(nullptr);
  if (wsc == nullptr) {
    // The resource said no. It answers as HTTP, because nothing was
    // upgraded - and it closes, because a refused handshake has
    // nothing more to say on this connection.
    return fail(st, refuse_status == 0 ? 403 : refuse_status, sink);
  }

  // permessage-deflate (#175 round two, RFC 7692), and only for a route
  // that said it wants it: the offer list is walked here, where the
  // parsed head still lies, so the extension costs a route that
  // declined it exactly one bool. A field may appear more than once
  // (RFC 9110 5.3 makes a list one field or many); the FIRST offer
  // anywhere in them that this endpoint can accept wins, which is
  // 7692 5.1's "the server selects one".
  wsdeflate::Params dparams;
  std::string ext_answer;
  if (ws_wants_deflate(res)) {
    const struct phr_header* hs = static_cast<const struct phr_header*>(hdrs);
    for (size_t i = 0; i < nhdr && !dparams.on; i++) {
      if (!http::tok_eq(hs[i].name, hs[i].name_len, "sec-websocket-extensions", 24)) continue;
      wsdeflate::negotiate(hs[i].value, hs[i].value_len, dparams, ext_answer);
    }
  }

  sink.append("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: "
              "Upgrade\r\nSec-WebSocket-Accept: ");
  sink.append(accept, sizeof(accept));
  if (!proto.empty()) {
    // 4.2.2 step 5.5: at most one, and only one the client offered -
    // which the resource read out of the head itself.
    sink.append("\r\nSec-WebSocket-Protocol: ").append(proto);
  }
  if (dparams.on) sink.append("\r\nSec-WebSocket-Extensions: ").append(ext_answer);
  sink.append("\r\n\r\n");

  ws_open(wsc, dparams);
  st.ws = wsc;
  st.carry.clear();     // the head is answered; nothing HTTP waits any more
  st.body_skip = 0;
  // Frames the client sent in the SAME receive as its handshake - a
  // peer that does not wait for the 101 is not made to wait for
  // another packet.
  if (rest_len != 0) return ws_feed(st.ws, rest, rest_len, sink);
  return true;
}

}  // namespace webmachine
