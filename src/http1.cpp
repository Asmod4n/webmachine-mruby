#include "http1.hpp"

#include <picohttpparser.h>

#include <cstring>

#include "assets.hpp"
#include "h2.hpp"
#include "http.hpp"

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

void Http1::build_status(uint16_t status, const char* extra, const char* body) {
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
             bool dynamic_body, Assets* assets)
    : konst_(ks),
      res_(res),
      dynamic_nodes_(dynamic_nodes),
      dynamic_body_(dynamic_body),
      bound_(res != nullptr && (dynamic_nodes || dynamic_body)),
      assets_(assets) {
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
    // The same status precomputed as h2's header block (same slot as
    // store_ via index_); bodies ride DATA frames, so ONE 200 block
    // serves konst and dynamic alike.
    H2Block b;
    h2_build_block(b, s, s == 200 ? &konst_.content_type : nullptr,
                   s == 405 ? &konst_.allow : nullptr);
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

  // The fast lane's DATA half, whole and precomputed: valid only when
  // the body never varies at all - !bound_ means status 200 always
  // sends konst_.body verbatim, forever. stream id is patched per
  // response at its fixed offset (h2_patch_stream_id); END_STREAM is
  // baked in because h2_answer only ever reaches for this buffer when
  // it has already proven it will be the sole, last frame.
  if (!bound_) {
    unsigned char fh[kH2FrameHeaderLen];
    h2_put_frame_header(fh, static_cast<uint32_t>(konst_.body.size()), kH2Data,
                        kH2FlagEndStream, 0);
    h2_data200_.assign(reinterpret_cast<const char*>(fh), sizeof(fh));
    h2_data200_.append(konst_.body);
  }

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
    // h2's exception answer: 500 in the negotiated type.
    h2_build_block(h2_err_, 500, &konst_.content_type, nullptr);
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
        if (as == 412 || as == 501) {
          // Nothing asset-specific in these; the shared store answers.
          const Variants& sv = variants(as);
          sink.append(minor >= 1 ? (persist ? sv.plain.bytes : sv.close.bytes)
                                 : (persist ? sv.keep.bytes : sv.close.bytes));
        } else {
          const Assets::Variant av = minor >= 1 ? (persist ? Assets::kPlain : Assets::kClose)
                                                : (persist ? Assets::kKeep : Assets::kClose);
          assets_->answer_h1(*ae, as, av, head_only, date_, sec_, sink);
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
          return false;
        }
        continue;
      }
    }

    // The wire is valid; from here the FLOW decides the status. Konst
    // answers are compiled into the method's vector; dynamic nodes -
    // instance methods, by declaration - are asked through the VM per
    // request (this branch is deployment-stable: no hint).
    // Konst resources never see the VM; anything dynamic runs the whole
    // flow inside ONE VM frame (this branch is deployment-stable: no
    // hint).
    uint16_t status;
    bool have_body = false;
    if (bound_) {
      status = resource_run(*res_, facts, &body_, &have_body);
    } else {
      status = flow::answer(facts, konst_.per_method[static_cast<size_t>(facts.method)],
                           konst_.shortcut[static_cast<size_t>(facts.method)]);
    }

    bool answered = false;
    if (have_body && status == 200) {
      // Rendered inside the run frame, copied there while the frame
      // rooted it; HEAD renders too - its Content-Length must be the
      // GET's - but sends no body bytes (RFC 9110 9.3.2).
      assemble(sink, minor >= 1 ? (persist ? ok_prefix_.plain : ok_prefix_.close)
                                : (persist ? ok_prefix_.keep : ok_prefix_.close),
               body_.data(), body_.size(), head_only);
      answered = true;
    }
    if (WM_H1_UNLIKELY(!answered && status == 500 && bound_)) {
      // A raising callback answers in the negotiated type, the reason
      // as body - the exception was left pending for exactly this.
      // Copied before any mruby call can run.
      const char* bp = nullptr;
      size_t blen = 0;
      if (resource_exception_begin(*res_, &bp, &blen)) {
        assemble(sink, minor >= 1 ? (persist ? err_prefix_.plain : err_prefix_.close)
                                  : (persist ? err_prefix_.keep : err_prefix_.close),
               bp, blen, head_only);
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
      st.carry.clear();
      st.body_skip = 0;
      return false;
    }
  }
  if (!in_place) st.carry.clear();
  return true;
}

}  // namespace webmachine
