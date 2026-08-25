// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <picohttpparser.h>

#include <cstdlib>
#include <cstring>

#define WM_H1_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace webmachine {
namespace {
// RFC 9110 7.6.1: Connection is a token LIST - a substring match would
// accept "not-close".
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

// RFC 9112 3/9.3: the head ONE bound run spelled for itself - status line,
// Date, its own field lines, the framing this connection asked for. No
// prebuilt head can take this shape, so it is spelled byte by byte.
void spell_head(std::string& sink, uint16_t status, const char* date, const std::string& ctype,
                const std::string& rhdrs, int minor, bool persist, bool bodyless, size_t len) {
  char line[4];
  line[0] = static_cast<char>('0' + status / 100);
  line[1] = static_cast<char>('0' + (status / 10) % 10);
  line[2] = static_cast<char>('0' + status % 10);
  line[3] = '\0';
  sink.append("HTTP/1.1 ").append(line).append(" ").append(http::reason(status));
  sink.append("\r\nDate: ").append(date, kDateLen).append("\r\n");
  if (!ctype.empty()) sink.append("Content-Type: ").append(ctype).append("\r\n");
  sink.append(rhdrs);
  if (!persist) sink.append("Connection: close\r\n");
  else if (minor < 1) sink.append("Connection: keep-alive\r\n");
  if (bodyless) {
    sink.append("\r\n");
    return;
  }
  char cl[40];
  sink.append(cl, http::spell_content_length(cl, len));
}
}

// RFC 9112 9.3: one status prebuilt in all three connection spellings.
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

// RFC 9110 15: one status into the shared store, date offset kept.
void Http1::build_status(uint16_t status, const char* extra, const char* body) {
  Variants v;
  build_variants(v, status, extra, body, kDatePlaceholder);
  index_[status] = static_cast<uint16_t>(store_.size());
  store_.push_back(std::move(v));
}

// RFC 9110 5.6.7: the 29 date bytes, once a second, in place.
void Http1::patch_date(Variants& v, const char* core) {
  std::memcpy(v.plain.bytes.data() + v.plain.date_off, core, kDateLen);
  std::memcpy(v.keep.bytes.data() + v.keep.date_off, core, kDateLen);
  std::memcpy(v.close.bytes.data() + v.close.date_off, core, kDateLen);
}

// RFC 9110: ONE route's whole voice - its 200 in every shape, its Allow
// (10.2.1), its negotiated type (8.3), its gzip decision, its h2 blocks.
void Http1::build_bundle(Bundle& b, const Resource* res) {
  b.res = res;
  b.konst = res->konst;
  b.dynamic_body = res->dynamic_body;
  b.bound = res->dynamic != 0 || res->dynamic_body;
  b.konst.content_type = http::with_charset(b.konst.content_type);
  b.index = index_;
  std::string ok_extra;
  if (!b.konst.content_type.empty()) {
    ok_extra = "Content-Type: " + b.konst.content_type + "\r\n";
  }
  const std::string ok_tail =
      "Content-Length: " + std::to_string(b.konst.body.size()) + "\r\n\r\n" + b.konst.body;
  Variants ok;
  build_variants(ok, 200, ok_extra.c_str(), ok_tail.c_str(), kDatePlaceholder);
  const std::string allow = "Allow: " + b.konst.allow + "\r\n";
  Variants m405;
  build_variants(m405, 405, allow.c_str(), "Content-Length: 0\r\n\r\n", kDatePlaceholder);

  if (!b.bound) {
    unsigned char fh[kH2FrameHeaderLen];
    h2_put_frame_header(fh, static_cast<uint32_t>(b.konst.body.size()), kH2Data,
                        kH2FlagEndStream, 0);
    b.h2_data200.assign(reinterpret_cast<const char*>(fh), sizeof(fh));
    b.h2_data200.append(b.konst.body);
  }

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
  if (b.dynamic_body) {
    const size_t cut = ok_tail.size();
    const auto prefix = [&](const Resp& src, Resp& dst) {
      dst.bytes.assign(src.bytes, 0, src.bytes.size() - cut);
      dst.date_off = src.date_off;
    };
    prefix(ok.plain, b.ok_prefix.plain);
    prefix(ok.keep, b.ok_prefix.keep);
    prefix(ok.close, b.ok_prefix.close);
  }
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
    h2_build_block(b.h2_err, 500, &b.konst.content_type, nullptr);
  }
}

// One app, one listener - the shape everything but a multi-app file has.
Http1::Http1(const RouteTable& table, const Resource* const* resources, size_t nroutes,
             Assets* assets)
    : assets_(assets) {
  const AppInput one{&table, resources, nroutes};
  build(&one, 1);
}

// Every response every route of every app can speak, built once.
Http1::Http1(const AppInput* apps, size_t napps, Assets* assets) : assets_(assets) {
  build(apps, napps);
}

// RFC 9110 15: the status supply, the bundles and the asset blocks, at setup.
void Http1::build(const AppInput* apps, size_t napps) {
  store_.reserve(32);
  bool have[600] = {};
  const auto add = [&](uint16_t s) {
    if (have[s]) return;
    have[s] = true;
    if (s == 204 || s == 304) build_status(s, "", "\r\n");
    else build_status(s, "", "Content-Length: 0\r\n\r\n");
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
  add(404);

  size_t total = 0;
  for (size_t a = 0; a < napps; a++) total += apps[a].nroutes;
  bundles_.resize(total);
  apps_.resize(napps);
  size_t at = 0;
  size_t ws_at = 0;
  size_t sse_at = 0;
  for (size_t a = 0; a < napps; a++) {
    apps_[a].table = apps[a].table;
    apps_[a].base = static_cast<uint16_t>(at);
    apps_[a].count = static_cast<uint16_t>(apps[a].nroutes);
    for (size_t i = 0; i < apps[a].nroutes; i++) {
      build_bundle(bundles_[at + i], apps[a].resources[i]);
    }
    at += apps[a].nroutes;
    apps_[a].ws_table = apps[a].ws_nroutes != 0 ? apps[a].ws_table : nullptr;
    apps_[a].ws_base = static_cast<uint16_t>(ws_at);
    for (size_t i = 0; i < apps[a].ws_nroutes; i++) {
      ws_res_.push_back(apps[a].ws_resources[i]);
    }
    ws_at += apps[a].ws_nroutes;
    apps_[a].sse_table = apps[a].sse_nroutes != 0 ? apps[a].sse_table : nullptr;
    apps_[a].sse_base = static_cast<uint16_t>(sse_at);
    for (size_t i = 0; i < apps[a].sse_nroutes; i++) {
      sse_res_.push_back(apps[a].sse_resources[i]);
    }
    sse_at += apps[a].sse_nroutes;
  }

  if (const char* w = std::getenv("WM_WARM_BUDGET")) {
    char* end = nullptr;
    const unsigned long v = std::strtoul(w, &end, 10);
    if (end != w) warm_budget_ = static_cast<size_t>(v);
  }

  if (assets_ != nullptr) {
    h2_build_asset_shared();
    for (AssetEntry& e : assets_->entries()) h2_build_asset_blocks(e);
  }

  sec_ = 0;
  on_tick();
}

// RFC 9110 5.6.7: the wall-clock second changed - patch every prebuilt date.
void Http1::on_tick() {
  const time_t now = ::time(nullptr);
  if (now == sec_) return;
  sec_ = now;
  struct tm tm;
  gmtime_r(&now, &tm);
  http::date_core(date_, tm);
  alog_.sec = static_cast<int64_t>(now);
  elog_.sec = static_cast<int64_t>(now);
  const char* core = date_;

  for (Variants& v : store_) patch_date(v, core);
  for (Bundle& b : bundles_) {
    patch_date(b.ok_head, core);
    if (b.dynamic_body) patch_date(b.ok_prefix, core);
    if (b.gzip_ok) {
      patch_date(b.ok_prefix_vary, core);
      patch_date(b.ok_prefix_gzip, core);
    }
    if (b.bound) patch_date(b.err_prefix, core);
  }
}

// RFC 9110 8.6: prefix + hand-spelled Content-Length + (unless HEAD) the body.
void Http1::assemble(std::string& sink, const Resp& prefix, const char* body, size_t len,
                     bool head_only) {
  sink.append(prefix.bytes);
  char cl[40];
  sink.append(cl, http::spell_content_length(cl, len));
  if (!head_only) sink.append(body, len);
}

// RFC 9110 12.5.3/12.5.5: identity or gzip for a dynamic 200, and the Vary
// that says the resource varies either way.
void Http1::assemble_dynamic(const Conn& st, const flow::ReqFacts& facts,
                             const http::ReqValues& vals, const Resp& prefix_id,
                             const Resp& prefix_gz, bool head_only, std::string& sink) {
  const bool accept_gzip =
      !facts.has_accept_encoding || http::gzip_acceptable(vals.accept_encoding,
                                                           vals.accept_encoding_len);
  bool use_gzip = false;
  if (accept_gzip && st.packetized) {
    char cl[40];
    const size_t cl_len = http::spell_content_length(cl, body_.size());
    if (prefix_id.bytes.size() + cl_len + body_.size() >= kCompressFloor) {
      use_gzip = gzip::compress(body_, gz_body_);
    }
  }
  if (use_gzip) assemble(sink, prefix_gz, gz_body_.data(), gz_body_.size(), head_only);
  else assemble(sink, prefix_id, body_.data(), body_.size(), head_only);
}

// RFC 9112: wire invalidity - framing trust is gone, the connection ends.
bool Http1::fail(Conn& st, uint16_t status, std::string& sink, uint8_t log_flags) {
  if (alog_.enabled) {
    log_access(alog_, st.peer, st.peer_len, nullptr, 0, "-", 1, log_flags, status, 0, nullptr, 0,
               nullptr, 0);
  }
  sink.append(variants(status).close.bytes);
  st.carry.clear();
  st.body_skip = 0;
  st.body_need = 0;
  return false;
}

// A lent body splits the sink, so whatever the parse appended after it
// still has to be claimed - and it returns down a dozen paths, so the plan
// is closed HERE, once, on all of them.
bool Http1::feed(Conn& st, const char* data, size_t len, std::string& sink, Plan* plan) {
  const bool ok = feed_parse(st, data, len, sink, plan);
  if (WM_H1_UNLIKELY(st.zc_split) && plan != nullptr && sink.size() > st.zc_covered) {
    const size_t rest = sink.size() - st.zc_covered;
    plan->seg[plan->nseg++] = Plan::Seg{nullptr, st.zc_covered, rest};
    plan->iov_len += rest;
    st.zc_covered = sink.size();
  }
  return ok;
}

// RFC 9110 8.6: the body the run LENT, delivered as an external segment
// over its own frozen String - the door http1's mmap'd assets already use.
// The sink bytes it splits are claimed on either side of it by offset.
void Http1::lend_body(Conn& st, std::string& sink, const char* body, size_t len, Plan& plan) {
  if (sink.size() > st.zc_covered) {
    const size_t head = sink.size() - st.zc_covered;
    plan.seg[plan.nseg++] = Plan::Seg{nullptr, st.zc_covered, head};
    plan.iov_len += head;
  }
  st.zc_covered = sink.size();
  plan.seg[plan.nseg++] = Plan::Seg{body, 0, len};
  plan.iov_len += len;
  st.zc_split = true;
}

// RFC 9112: THE framer. phr on the wire bytes, the carry only when a head
// splits; RFC 9113 3.4 decides h2 on the first bytes; the flow decides
// every status.
bool Http1::feed_parse(Conn& st, const char* data, size_t len, std::string& sink, Plan* plan) {
  if (st.h2 != nullptr) return h2_feed(st, data, len, sink, plan);
  if (st.fresh) {
    st.body_need = 0;
    const size_t seen = st.carry.size();
    size_t i = 0;
    while (i < len && seen + i < kH2PrefaceLen && data[i] == kH2Preface[seen + i]) i++;
    if (seen + i == kH2PrefaceLen) {
      st.fresh = false;
      st.carry.clear();
      if (!h2_begin(st, sink)) return false;
      return h2_feed(st, data + i, len - i, sink, plan);
    }
    if (i == len) {
      st.carry.append(data, len);
      return true;
    }
    if (seen + i >= kH2PrefaceAnnounce) {
      static const unsigned char kGoaway[kH2FrameHeaderLen + 8] = {
          0, 0, 8, kH2Goaway, 0, 0, 0, 0, 0,
          0, 0, 0, 0,
          0, 0, 0, kH2ProtocolError};
      sink.append(reinterpret_cast<const char*>(kGoaway), sizeof(kGoaway));
      return false;
    }
    st.fresh = false;
  }
  if (st.body_skip != 0) {
    const size_t take = st.body_skip < len ? st.body_skip : len;
    st.body_skip -= take;
    data += take;
    len -= take;
    if (len == 0) return true;
  }

  // RFC 9110 6.4: a bound route's head waits in the carry until the whole
  // body is here - the run READS the body, so it cannot answer before the
  // last byte. Nothing is parsed again until body_need is paid off.
  if (WM_H1_UNLIKELY(st.body_need != 0)) {
    if (len < st.body_need) {
      st.body_need -= len;
      st.carry.append(data, len);
      return true;
    }
    st.body_need = 0;
  }

  if (WM_H1_UNLIKELY(st.xfer != nullptr)) {
    if (WM_H1_UNLIKELY(st.carry.size() + len > kMaxHead)) {
      st.carry.clear();
      st.body_skip = 0;
      st.xfer = nullptr;
      return false;
    }
    st.carry.append(data, len);
    return true;
  }

  if (WM_H1_UNLIKELY(st.ws != nullptr)) return ws_feed(st.ws, data, len, sink);
  if (WM_H1_UNLIKELY(st.sse != nullptr)) return true;

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
  while (off < viewlen) {
    const char* method;
    size_t method_len;
    const char* path;
    size_t path_len;
    int minor;
    struct phr_header headers[kMaxHeaders];
    size_t num_headers = kMaxHeaders;
    const int ret = phr_parse_request(view + off, viewlen - off, &method, &method_len, &path,
                                      &path_len, &minor, headers, &num_headers, 0);
    if (ret == -2) {
      const size_t rest = viewlen - off;
      if (WM_H1_UNLIKELY(rest > kMaxHead)) return fail(st, 431, sink);
      if (in_place) st.carry.assign(view + off, rest);
      else st.carry.erase(0, off);
      return true;
    }
    if (WM_H1_UNLIKELY(ret <= 0)) return fail(st, 400, sink);
    if (WM_H1_UNLIKELY(static_cast<size_t>(ret) > kMaxHead)) return fail(st, 431, sink);

    size_t content_length = 0;
    bool have_cl = false, have_te = false, have_host = false;
    bool conn_close = false, conn_keep = false;
    bool up_ws = false, conn_upgrade = false;
    const char* ws_key = nullptr;
    size_t ws_key_len = 0;
    int ws_version = 0;
    uint16_t wire_err = 0;
    flow::ReqFacts facts;
    http::ReqValues vals;
    facts.method = http::parse_method(method, method_len);
    for (size_t i = 0; i < num_headers; i++) {
      const struct phr_header& h = headers[i];
      http::header_switch(
          h.name, h.name_len, h.value, h.value_len, facts, vals,
          [&](const char* n, size_t nl, const char* v, size_t vl) {
            if (wire_err != 0) return;
            switch (nl) {
              case 14:
                if (http::tok_eq(n, nl, "content-length", 14)) {
                  if (WM_H1_UNLIKELY(have_cl)) {
                    wire_err = 400;
                    return;
                  }
                  have_cl = true;
                  switch (http::parse_content_length(v, vl, &content_length)) {
                    case http::ClStatus::kOk: break;
                    case http::ClStatus::kBad: wire_err = 400; break;
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
                  if (WM_H1_UNLIKELY(have_host)) wire_err = 400;
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
                  if (conn_has(v, vl, "upgrade", 7)) conn_upgrade = true;
                }
                break;
              case 7:
                if (http::tok_eq(n, nl, "referer", 7)) {
                  vals.log_ref = v;
                  vals.log_ref_len = vl;
                  break;
                }
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
    const uint8_t lflags = facts.no_track ? kLogNoTrack : 0;
    if (WM_H1_UNLIKELY(wire_err != 0)) return fail(st, wire_err, sink, lflags);
    if (WM_H1_UNLIKELY(have_te)) return fail(st, have_cl ? 400 : 411, sink, lflags);
    if (WM_H1_UNLIKELY(minor >= 1 && !have_host)) return fail(st, 400, sink, lflags);
    if (WM_H1_UNLIKELY(content_length > kMaxBody)) return fail(st, 413, sink, lflags);

    const bool persist = minor >= 1 ? !conn_close : conn_keep;
    const bool head_only = facts.method == flow::Method::kHead;

    if (WM_H1_UNLIKELY(up_ws && conn_upgrade)) {
      const AppSlot& wslot = apps_[st.listener];
      RouteSpans wspans;
      const int wr =
          wslot.ws_table != nullptr ? wslot.ws_table->match(path, path_len, wspans) : -1;
      if (wr >= 0) {
        if (ws_version != 13) {
          sink.append("HTTP/1.1 426 Upgrade Required\r\nDate: ");
          sink.append(date_, http::kDateLen);
          sink.append(
              "\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\n"
              "Content-Length: 0\r\n\r\n");
          return false;
        }
        if (facts.method != flow::Method::kGet || ws_key == nullptr) {
          return fail(st, 400, sink, lflags);
        }
        const char* rest = view + off + static_cast<size_t>(ret);
        const size_t rest_len = viewlen - off - static_cast<size_t>(ret);
        return ws_upgrade(st, wslot, wr, path, path_len, wspans, ws_key, ws_key_len, headers,
                          num_headers, rest, rest_len, sink);
      }
    }

    if (WM_H1_UNLIKELY(apps_[st.listener].sse_table != nullptr)) {
      const AppSlot& sslot = apps_[st.listener];
      RouteSpans sspans;
      const int sr = sslot.sse_table->match(path, path_len, sspans);
      if (sr >= 0) {
        return sse_begin(st, sslot, sr, method, method_len, path, path_len, sspans, headers,
                         num_headers, minor, facts.method, vals, lflags, sink);
      }
    }

    if (assets_ != nullptr) {
      if (AssetEntry* ae = assets_->find(path, path_len)) {
        const uint16_t as = assets_->verdict(*ae, facts.method, facts, vals);
        bool started_xfer = false;
        uint16_t alog_st = as;
        size_t alog_by = 0;
        if (as == 412 || as == 501) {
          const Variants& sv = variants(as);
          sink.append(minor >= 1 ? (persist ? sv.plain.bytes : sv.close.bytes)
                                 : (persist ? sv.keep.bytes : sv.close.bytes));
        } else {
          const Assets::Variant av = minor >= 1 ? (persist ? Assets::kPlain : Assets::kClose)
                                                : (persist ? Assets::kKeep : Assets::kClose);
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
              case http::RangeParse::kNone: break;
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
          log_access(alog_, st.peer, st.peer_len, method, method_len, path, path_len, lflags, alog_st,
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
          return false;
        }
        if (started_xfer) {
          const size_t rest = viewlen - off;
          if (in_place) st.carry.assign(view + off, rest);
          else st.carry.erase(0, off);
          if (plan != nullptr) {
            const size_t room = plan->byte_cap == 0 ? st.xfer_end - st.xfer_off
                                : plan->byte_cap > sink.size() ? plan->byte_cap - sink.size()
                                                               : 0;
            size_t take = st.xfer_end - st.xfer_off;
            if (take > room) take = room;
            if (take > 0) {
              const size_t head = sink.size() - st.zc_covered;
              plan->seg[plan->nseg++] = Plan::Seg{nullptr, st.zc_covered, head};
              plan->iov_len += head;
              st.zc_covered = sink.size();
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

    const AppSlot& slot = apps_[st.listener];
    RouteSpans spans;
    const int route = slot.table->match(path, path_len, spans);
    const Bundle* b = nullptr;
    const std::array<uint16_t, 600>* idx = &index_;
    uint16_t status;
    bool have_body = false;
    bool answered = false;
    const char* lent = nullptr;
    size_t lent_len = 0;
    if (WM_H1_UNLIKELY(route < 0)) {
      status = 404;
    } else {
      b = &bundles_[slot.base + static_cast<size_t>(route)];
      idx = &b->index;
      if (b->bound) {
        const size_t head_len = static_cast<size_t>(ret);
        if (content_length != 0 && viewlen - off - head_len < content_length) {
          st.body_need = content_length - (viewlen - off - head_len);
          const size_t rest = viewlen - off;
          if (in_place) st.carry.assign(view + off, rest);
          else st.carry.erase(0, off);
          return true;
        }
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
        rv.hdrs = headers;
        rv.nhdr = num_headers;
        if (content_length != 0) {
          rv.body = view + off + head_len;
          rv.body_len = content_length;
        }
        // A run may LEND its body only where nothing downstream touches the
        // bytes anyway: HEAD sends none, gzip copies them, one connection
        // holds one lend, and an external segment fits through a plan only.
        const bool gz_now =
            b->gzip_ok && st.packetized &&
            (!facts.has_accept_encoding ||
             http::gzip_acceptable(vals.accept_encoding, vals.accept_encoding_len));
        const size_t zc_min = (zc_min_ != 0 && plan != nullptr && !st.zc_have && !head_only &&
                               !gz_now)
                                  ? zc_min_
                                  : 0;
        status = resource_run(*b->res, facts, &vals, &rv, &body_, &have_body, &rhdrs_, zc_min);
        if (WM_H1_UNLIKELY(resource_body_lent(*b->res, &st.zc, &lent, &lent_len))) {
          st.zc_mrb = b->res->mrb;
          st.zc_have = true;
        }
        // RFC 9110 6.3: field lines or a conneg no prebuilt head can hold -
        // this run spells its own. 500 stays on the exception path below.
        if (WM_H1_UNLIKELY((b->res->run_head_dynamic || !rhdrs_.empty()) && status != 500)) {
          const bool bodyless = status == 204 || status == 304;
          if (bodyless || !have_body) {
            body_.clear();
            st.zc_release();
            lent = nullptr;
            lent_len = 0;
          }
          std::string ctype;
          if (!bodyless) {
            if (!b->res->run_ctype.empty()) ctype = http::with_charset(b->res->run_ctype);
            else if (have_body) ctype = b->konst.content_type;
          }
          spell_head(sink, status, date_, ctype, rhdrs_, minor, persist, bodyless,
                     lent != nullptr ? lent_len : body_.size());
          if (!bodyless && !head_only) {
            if (lent != nullptr) lend_body(st, sink, lent, lent_len, *plan);
            else sink.append(body_);
          }
          have_body = false;
          answered = true;
        }
      } else {
        status = flow::answer(facts, b->konst.per_method[static_cast<size_t>(facts.method)],
                             b->konst.shortcut[static_cast<size_t>(facts.method)]);
      }
    }

    if (have_body && status == 200) {
      if (lent != nullptr) {
        const Variants& pv = b->gzip_ok ? b->ok_prefix_vary : b->ok_prefix;
        const Resp& pfx = minor >= 1 ? (persist ? pv.plain : pv.close)
                                     : (persist ? pv.keep : pv.close);
        sink.append(pfx.bytes);
        char cl[40];
        sink.append(cl, http::spell_content_length(cl, lent_len));
        lend_body(st, sink, lent, lent_len, *plan);
      } else if (b->gzip_ok) {
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
      if (elog_.enabled) {
        log_exception(elog_, b->res->mrb, st.peer, st.peer_len, path, path_len, 500);
      }
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
      const Variants& sv =
          (head_only && status == 200) ? b->ok_head : store_[(*idx)[status]];
      sink.append(minor >= 1 ? (persist ? sv.plain.bytes : sv.close.bytes)
                             : (persist ? sv.keep.bytes : sv.close.bytes));
    }
    if (alog_.enabled) {
      const size_t blen = lent != nullptr ? lent_len : body_.size();
      log_access(alog_, st.peer, st.peer_len, method, method_len, path, path_len, lflags, status,
                 (answered && !head_only) ? blen : 0, vals.log_ref, vals.log_ref_len,
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
      st.carry.clear();
      st.body_skip = 0;
      return false;
    }
  }
  if (!in_place) st.carry.clear();
  return true;
}

// RFC 6455 4.2.2: the handshake's answer, 101 or the refusal the route earned.
bool Http1::ws_upgrade(Conn& st, const AppSlot& slot, int route, const char* path,
                       size_t path_len, const RouteSpans& spans, const char* key,
                       size_t key_len, const void* hdrs, size_t nhdr, const char* rest,
                       size_t rest_len, std::string& sink) {
  char accept[28];
  if (!ws::accept_key(key, key_len, accept)) return fail(st, 400, sink);

  const WsResource* res = ws_res_[slot.ws_base + static_cast<size_t>(route)];

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
  WsConn* wsc = ws_admit(res, elog_.enabled ? &elog_ : nullptr, proto, refuse_status);
  request_bind(nullptr);
  if (wsc == nullptr) {
    return fail(st, refuse_status == 0 ? 403 : refuse_status, sink);
  }

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
    sink.append("\r\nSec-WebSocket-Protocol: ").append(proto);
  }
  if (dparams.on) sink.append("\r\nSec-WebSocket-Extensions: ").append(ext_answer);
  sink.append("\r\n\r\n");

  ws_open(wsc, dparams);
  st.ws = wsc;
  st.carry.clear();
  st.body_skip = 0;
  if (rest_len != 0) return ws_feed(st.ws, rest, rest_len, sink);
  return true;
}

// WHATWG HTML: the event stream's head - RFC 9112 7.1 chunked, RFC 9111
// 5.2.2.5 no-store, and this connection never reads another head.
bool Http1::sse_begin(Conn& st, const AppSlot& slot, int route, const char* method,
                      size_t method_len, const char* path, size_t path_len,
                      const RouteSpans& spans, const void* hdrs, size_t nhdr, int minor,
                      flow::Method m, const http::ReqValues& vals, uint8_t lflags,
                      std::string& sink) {
  const auto log = [&](uint16_t status) {
    if (alog_.enabled) {
      log_access(alog_, st.peer, st.peer_len, method, method_len, path, path_len, lflags, status, 0,
                 vals.log_ref, vals.log_ref_len, vals.log_ua, vals.log_ua_len);
    }
  };
  if (WM_H1_UNLIKELY(m != flow::Method::kGet)) {
    log(405);
    sink.append("HTTP/1.1 405 Method Not Allowed\r\nDate: ");
    sink.append(date_, http::kDateLen);
    sink.append("\r\nAllow: GET\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    return false;
  }
  if (WM_H1_UNLIKELY(minor < 1)) {
    log(505);
    sink.append("HTTP/1.1 505 HTTP Version Not Supported\r\nDate: ");
    sink.append(date_, http::kDateLen);
    sink.append("\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    return false;
  }

  ReqView rv;
  rv.target = path;
  rv.target_len = path_len;
  rv.path_len = http::path_only(path, path_len);
  rv.method = flow::Method::kGet;
  rv.table = slot.sse_table;
  rv.route = route;
  rv.spans = spans;
  rv.hdrs = hdrs;
  rv.nhdr = nhdr;
  request_bind(&rv);
  uint16_t refused = 0;
  SseStream* s = sse_open(sse_res_[slot.sse_base + static_cast<size_t>(route)],
                        elog_.enabled ? &elog_ : nullptr, refused);
  request_bind(nullptr);
  if (s == nullptr) {
    log(refused == 0 ? 403 : refused);
    return fail(st, refused == 0 ? 403 : refused, sink, lflags);
  }

  log(200);
  sink.append("HTTP/1.1 200 OK\r\nDate: ");
  sink.append(date_, http::kDateLen);
  sink.append(
      "\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n"
      "Transfer-Encoding: chunked\r\n\r\n");
  st.sse = s;
  st.carry.clear();
  st.body_skip = 0;
  return true;
}
}
