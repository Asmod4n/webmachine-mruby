// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <picohttpparser.h>

#include <cstdlib>
#include <cstring>

#define WM_H1_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define WM_H1_LIKELY(x) __builtin_expect(!!(x), 1)

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
    if (http::tok_eq({v + start, i - start}, {lit, litn})) return true;
  }
  return false;
}

using http::kDateLen;
using http::kDatePlaceholder;

// RFC 9112: what the FRAMER reads out of the head - the fields 9110's
// header_switch hands back because their meaning is the connection's,
// not the resource's.
struct WireFacts {
  size_t content_length = 0;
  const char* ws_key = nullptr;
  size_t ws_key_len = 0;
  int ws_version = 0;
  uint16_t err = 0;
  bool have_cl = false;
  bool have_te = false;
  bool have_host = false;
  bool conn_close = false;
  bool conn_keep = false;
  bool up_ws = false;
  bool conn_upgrade = false;
};

// RFC 9112 / RFC 6455: host(4) referer/upgrade(7) connection/user-agent(10)
// content-length(14) sec-websocket-key/transfer-encoding(17)
// sec-websocket-version(21).
constexpr size_t kWireLengths[] = {4, 7, 10, 14, 17, 21};
constexpr uint32_t kWireLengthMask =
    http::lengths_mask(kWireLengths, sizeof(kWireLengths) / sizeof(kWireLengths[0]));

// Where one request's FRAMING facts are being filled: the facts, the
// values that point back into the head, and the index of the field being
// read - the same shape http::FactSink has for the 9110 facts.
struct WireSink {
  WireFacts& w;
  http::ReqValues& vals;
  size_t at;
};

// RFC 9112 6.1/6.3, 7.6.1, RFC 6455 4.1: one such field.
void read_wire_header(WireSink into, http::Field f) {
  WireFacts& w = into.w;
  http::ReqValues& vals = into.vals;
  const size_t at = into.at;
  const char* const n = f.name.data();
  const size_t nl = f.name.size();
  const char* const v = f.value.data();
  const size_t vl = f.value.size();
  if (w.err != 0 || !http::length_is_one_of(nl, kWireLengthMask)) return;
  switch (nl) {
    case 14:
      if (http::tok_eq({n, nl}, "content-length")) {
        if (WM_H1_UNLIKELY(w.have_cl)) {
          w.err = 400;
          return;
        }
        w.have_cl = true;
        vals.named.note(http::NamedField::kContentLength, at);
        switch (http::parse_content_length({v, vl}, &w.content_length)) {
          case http::ClStatus::kOk: break;
          case http::ClStatus::kBad: w.err = 400; break;
          case http::ClStatus::kOverflow: w.err = 413; break;
        }
      }
      break;
    case 17:
      if (http::tok_eq({n, nl}, "transfer-encoding")) w.have_te = true;
      else if (http::tok_eq({n, nl}, "sec-websocket-key")) {
        w.ws_key = v;
        w.ws_key_len = vl;
      }
      break;
    case 4:
      if (http::tok_eq({n, nl}, "host")) {
        if (WM_H1_UNLIKELY(w.have_host)) w.err = 400;
        w.have_host = true;
      }
      break;
    case 10:
      if (http::tok_eq({n, nl}, "user-agent")) {
        vals.log_ua = v;
        vals.log_ua_len = vl;
      } else if (http::tok_eq({n, nl}, "connection")) {
        if (conn_has(v, vl, "close", 5)) w.conn_close = true;
        else if (conn_has(v, vl, "keep-alive", 10)) w.conn_keep = true;
        if (conn_has(v, vl, "upgrade", 7)) w.conn_upgrade = true;
      }
      break;
    case 7:
      if (http::tok_eq({n, nl}, "referer")) {
        vals.log_ref = v;
        vals.log_ref_len = vl;
        break;
      }
      if (http::tok_eq({n, nl}, "upgrade")) {
        w.up_ws = http::tok_eq({v, vl}, "websocket");
      }
      break;
    case 21:
      if (http::tok_eq({n, nl}, "sec-websocket-version")) {
        w.ws_version = 0;
        for (size_t j = 0; j < vl; j++) {
          if (v[j] < '0' || v[j] > '9') { w.ws_version = -1; break; }
          w.ws_version = w.ws_version * 10 + (v[j] - '0');
          if (w.ws_version > 999) { w.ws_version = -1; break; }
        }
      }
      break;
    default:
      break;
  }
}

// RFC 9112 3/9.3: the head ONE bound run spelled for itself - the status
// it carries, the Date line for this second, its own Content-Type and
// field lines, the framing this connection asked for, and the length it
// declares where it declares one. No prebuilt head can take this shape.
struct SpelledHead {
  uint16_t status;
  const char* date;
  std::string_view ctype;
  std::string_view rhdrs;
  int minor;
  bool persist;
  bool bodyless;
  size_t len;
};

// And here it is spelled, byte by byte.
void spell_head(std::string& sink, const SpelledHead& head) {
  const uint16_t status = head.status;
  char line[4];
  line[0] = static_cast<char>('0' + status / 100);
  line[1] = static_cast<char>('0' + (status / 10) % 10);
  line[2] = static_cast<char>('0' + status % 10);
  line[3] = '\0';
  sink.append("HTTP/1.1 ").append(line).append(" ").append(http::reason(status));
  sink.append("\r\nDate: ").append(head.date, kDateLen).append("\r\n");
  if (!head.ctype.empty()) sink.append("Content-Type: ").append(head.ctype).append("\r\n");
  sink.append(head.rhdrs);
  if (!head.persist) sink.append("Connection: close\r\n");
  else if (head.minor < 1) sink.append("Connection: keep-alive\r\n");
  if (head.bodyless) {
    sink.append("\r\n");
    return;
  }
  char cl[40];
  sink.append(cl, http::spell_content_length(cl, head.len));
}
}

// One of build_variants' three spellings, its date offset noted.
void Http1::build_one_variant(Resp& r, Prebuilt p) {
  r.bytes.clear();
  char line[16];
  line[0] = static_cast<char>('0' + p.status / 100);
  line[1] = static_cast<char>('0' + (p.status / 10) % 10);
  line[2] = static_cast<char>('0' + p.status % 10);
  line[3] = '\0';
  r.bytes.append("HTTP/1.1 ").append(line).append(" ").append(http::reason(p.status));
  r.bytes.append("\r\nDate: ");
  r.date_off = r.bytes.size();
  r.bytes.append(p.date).append("\r\n").append(p.conn).append(p.extra).append(p.body);
}

// One prebuilt head with its trailing `cut` bytes left off.
void Http1::copy_without_tail(const Resp& src, Resp& dst, size_t cut) {
  dst.bytes.assign(src.bytes, 0, src.bytes.size() - cut);
  dst.date_off = src.date_off;
}

// A 200 or 500 head that stops before Content-Length, for a body the run
// has yet to produce. `enc` carries whatever Vary/Content-Encoding applies.
void Http1::build_open_prefix(Resp& r, OpenPrefix p) {
  r.bytes.clear();
  r.bytes.append(p.status_line).append("\r\nDate: ");
  r.date_off = r.bytes.size();
  r.bytes.append(kDatePlaceholder).append("\r\n").append(p.conn).append(p.extra).append(p.enc);
}

// RFC 9112 9.3: one status prebuilt in all three connection spellings.
void Http1::build_variants(Variants& v, Prebuilt p) {
  p.conn = "";
  build_one_variant(v.plain, p);
  p.conn = "Connection: keep-alive\r\n";
  build_one_variant(v.keep, p);
  p.conn = "Connection: close\r\n";
  build_one_variant(v.close, p);
}

// And the same head, open, in the same three.
void Http1::build_open_prefixes(Variants& v, OpenPrefix p) {
  p.conn = "";
  build_open_prefix(v.plain, p);
  p.conn = "Connection: keep-alive\r\n";
  build_open_prefix(v.keep, p);
  p.conn = "Connection: close\r\n";
  build_open_prefix(v.close, p);
}

// RFC 9110 15: one status into the shared store, date offset kept - and
// beside it the same answer WITHOUT `body`, which is where an error that
// has a page to show puts its own Content-Type and Content-Length (#210).
void Http1::build_status(uint16_t status, StatusText t) {
  Variants v;
  build_variants(v, {status, t.extra, t.body, kDatePlaceholder});
  Variants p;
  build_variants(p, {status, t.extra, "", kDatePlaceholder});
  index_[status] = static_cast<uint16_t>(store_.size());
  store_.push_back(std::move(v));
  store_prefix_.push_back(std::move(p));
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
  b.accept_type = b.konst.content_type;
  b.konst.content_type = http::with_charset(b.konst.content_type);
  b.index = index_;
  std::string ok_extra;
  if (!b.konst.content_type.empty()) {
    ok_extra = "Content-Type: " + b.konst.content_type + "\r\n";
  }
  const std::string ok_tail =
      "Content-Length: " + std::to_string(b.konst.body.size()) + "\r\n\r\n" + b.konst.body;
  Variants ok;
  build_variants(ok, {200, ok_extra.c_str(), ok_tail.c_str(), kDatePlaceholder});
  const std::string allow = "Allow: " + b.konst.allow + "\r\n";
  Variants m405;
  build_variants(m405, {405, allow.c_str(), "Content-Length: 0\r\n\r\n", kDatePlaceholder});

  if (!b.bound) {
    unsigned char fh[kH2FrameHeaderLen];
    h2_put_frame_header(
        fh, {static_cast<uint32_t>(b.konst.body.size()), kH2Data, kH2FlagEndStream, 0});
    b.h2_data200.assign(reinterpret_cast<const char*>(fh), sizeof(fh));
    b.h2_data200.append(b.konst.body);
  }

  const size_t blen = b.konst.body.size();
  copy_without_tail(ok.plain, b.ok_head.plain, blen);
  copy_without_tail(ok.keep, b.ok_head.keep, blen);
  copy_without_tail(ok.close, b.ok_head.close, blen);
  if (b.dynamic_body) {
    const size_t cut = ok_tail.size();
    copy_without_tail(ok.plain, b.ok_prefix.plain, cut);
    copy_without_tail(ok.keep, b.ok_prefix.keep, cut);
    copy_without_tail(ok.close, b.ok_prefix.close, cut);
  }
  b.index[200] = static_cast<uint16_t>(store_.size());
  {
    // The twin of every store_ push: store_prefix_ is addressed by the
    // same index, so the two vectors have to grow together (#210).
    Variants p200;
    build_variants(p200, {200, ok_extra.c_str(), "", kDatePlaceholder});
    store_prefix_.push_back(std::move(p200));
  }
  store_.push_back(std::move(ok));
  {
    H2Block hb;
    h2_build_block(hb, {200, &b.konst.content_type});
    h2_store_.push_back(std::move(hb));
  }
  b.index[405] = static_cast<uint16_t>(store_.size());
  {
    // RFC 9110 15.5.6: the 405 page keeps its Allow, and adds the page's
    // own Content-Type behind it.
    Variants p405;
    build_variants(p405, {405, allow.c_str(), "", kDatePlaceholder});
    store_prefix_.push_back(std::move(p405));
  }
  store_.push_back(std::move(m405));
  {
    H2Block hb;
    h2_build_block(hb, {405, nullptr, &b.konst.allow});
    h2_store_.push_back(std::move(hb));
  }
  b.gzip_ok = b.dynamic_body && res->gzip_offered &&
              http::compressible_media_type(b.konst.content_type);
  if (b.gzip_ok) {
    static const char kOk[] = "HTTP/1.1 200 OK";
    static const char kVary[] = "Vary: Accept-Encoding\r\n";
    static const char kGzip[] = "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n";
    build_open_prefixes(b.ok_prefix_vary, {kOk, ok_extra, kVary});
    build_open_prefixes(b.ok_prefix_gzip, {kOk, ok_extra, kGzip});
  }
  if (b.bound) {
    static const char kErr[] = "HTTP/1.1 500 Internal Server Error";
    build_open_prefixes(b.err_prefix, {kErr, ok_extra, ""});
    h2_build_block(b.h2_err, {500, &b.konst.content_type});
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

// RFC 9110 15: one status' h1 spellings and its h2 block, the first time
// the flow graph or a framer names it.
void Http1::stock_status(bool have[600], uint16_t s) {
  if (have[s]) return;
  have[s] = true;
  if (s == 204 || s == 304) build_status(s, {"", "\r\n"});
  else build_status(s, {"", "Content-Length: 0\r\n\r\n"});
  H2Block b;
  h2_build_block(b, {s});
  h2_store_.push_back(std::move(b));
}

// RFC 9110 15: the status supply, the bundles and the asset blocks, at setup.
void Http1::build(const AppInput* apps, size_t napps) {
  store_.reserve(32);
  bool have[600] = {};
  for (const auto& f : flow::kFlow) {
    if (f.on_true.status != 0) stock_status(have, f.on_true.status);
    if (f.on_false.status != 0) stock_status(have, f.on_false.status);
  }
  stock_status(have, 400);
  stock_status(have, 411);
  stock_status(have, 413);
  stock_status(have, 431);
  stock_status(have, 404);
  // response.file answers out of this store too, and index_ defaults to slot
  // 0 - an absent status would quietly spell whatever lives there.
  stock_status(have, 500);
  stock_status(have, 304);

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
  alog_.unix_seconds = static_cast<int64_t>(now);
  elog_.unix_seconds = static_cast<int64_t>(now);
  const char* core = date_;

  for (Variants& v : store_) patch_date(v, core);
  for (Variants& v : store_prefix_) patch_date(v, core);
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
void Http1::assemble(std::string& sink, const Assembled& a) {
  sink.append(a.prefix.bytes);
  char cl[40];
  sink.append(cl, http::spell_content_length(cl, a.body.size()));
  if (!a.head_only) sink.append(a.body);
}

// RFC 9110 12.5.3/12.5.5: identity or gzip for a dynamic 200, and the Vary
// that says the resource varies either way.
void Http1::assemble_dynamic(const DynamicBody& d, std::string& sink) {
  bool use_gzip = false;
  if (d.may_gzip) {
    char cl[40];
    const size_t cl_len = http::spell_content_length(cl, body_.size());
    if (d.prefix_id.bytes.size() + cl_len + body_.size() >= kCompressFloor) {
      use_gzip = gzip::compress(body_, gz_body_);
    }
  }
  if (use_gzip) assemble(sink, {d.prefix_gz, gz_body_, d.head_only});
  else assemble(sink, {d.prefix_id, body_, d.head_only});
}

// RFC 9112: wire invalidity - framing trust is gone, the connection ends.
// #210: the error pages render in a VM this layer does not own. Called
// once, after the bundles exist; a caller that never calls it keeps the
// bodyless statuses (#173: bytes in, bytes out, no VM required).
void Http1::open_error_assets(mrb_state* mrb, Assets* error_assets) {
  error_assets_ = error_assets;
  err_pages_.open(mrb, error_assets);
}

// RFC 9110 15: the error answer - the prebuilt status line and Date, then
// the page rendered for THIS request. RFC 9110 9.3.2: a HEAD carries the
// Content-Length a GET would have sent, and no body.
void Http1::spell_error(const ErrorAnswer& e, std::string& sink) {
  std::string body;
  size_t dlen = 0;
  const char* data = err_pages_.body_for({e.status, e.media, e.fields}, body, &dlen);
  if (data == nullptr) {
    sink.append(e.bodyless.bytes);
    return;
  }
  sink.append(e.prefix.bytes);
  sink.append("Content-Type: ").append(err_pages_.media_type(e.media)).append("\r\n");
  char cl[40];
  sink.append(cl, http::spell_content_length(cl, dlen));
  if (!e.head_only) sink.append(data, dlen);
}

// RFC 9110 6.3 / RFC 9111: a mounted archive answers this target on its
// own - conditional requests, ranges and refusals included - without the
// flow or the VM. /error_assets/ is resolved against the error archive,
// which is always mounted; everything else against --assets.
Http1::Took Http1::answer_from_assets(Round& r, std::string& sink, Plan* plan) {
  Assets* tier = assets_;
  const char* apath = r.path;
  size_t alen = r.path_len;
  char abuf[kMaxHead];
  if (error_assets_ != nullptr && r.path_len > kErrorAssetsPrefixLen &&
      std::memcmp(r.path, kErrorAssetsPrefix, kErrorAssetsPrefixLen) == 0) {
    const size_t rest = r.path_len - kErrorAssetsPrefixLen;
    if (rest + 1 < sizeof(abuf)) {
      abuf[0] = '/';
      std::memcpy(abuf + 1, r.path + kErrorAssetsPrefixLen, rest);
      tier = error_assets_;
      apath = abuf;
      alen = rest + 1;
    }
  }
  if (tier == nullptr) return Took::kNo;
  AssetEntry* ae = tier->find(apath, alen);
  if (ae == nullptr) return Took::kNo;
  const uint16_t as = tier->verdict(*ae, {r.facts, r.vals});
  const AssetStep step =
      asset_step(*ae, {as, r.head_only, r.facts.method, r.vals, warm_budget_});
  const Assets::ConnectionOption conn =
      r.minor >= 1 ? (r.persist ? Assets::kNoConnectionField : Assets::kConnClose)
                   : (r.persist ? Assets::kKeepAlive : Assets::kConnClose);
  // #210: a refusal this tier owns is a 4xx like any other, and a 4xx
  // explains itself. The page is the one every 4xx sends; what differs is
  // what the tier spells around it - a 405's Allow, a 406's Vary, a 416's
  // Content-Range - so the tier writes the head and is handed the body to
  // declare in it.
  std::string epage;
  size_t eblen = 0;
  const char* ebody = nullptr;
  const char* ectype = nullptr;
  if (step.status_code >= 400 && step.head != AssetStep::HeadKind::kRefusal) {
    const int em = err_pages_.media_for(step.status_code, r.vals.accept, r.vals.accept_len);
    const ErrorPages::Fields none;
    ebody = err_pages_.body_for({step.status_code, em, none}, epage, &eblen);
    if (ebody != nullptr) ectype = err_pages_.media_type(em);
    else eblen = 0;
  }
  Assets::HeadAsk head{*ae};
  head.status_code = step.status_code;
  head.conn = conn;
  head.date = date_;
  head.unix_seconds = sec_;
  head.first_byte_pos = step.first_byte_pos;
  head.last_byte_pos = step.first_byte_pos + step.content_length - 1;
  head.body_type = ectype;
  head.body_len = eblen;
  switch (step.head) {
    case AssetStep::HeadKind::kRefusal: {
      // 412 and 501 carry no field of this tier's own, so they are spelled
      // the way every other status of theirs is.
      const Variants& pv = prefixes(step.status_code);
      const Variants& sv = variants(step.status_code);
      const bool plain = r.minor >= 1;
      const ErrorPages::Fields none;
      const Resp& prefix =
          plain ? (r.persist ? pv.plain : pv.close) : (r.persist ? pv.keep : pv.close);
      const Resp& bodyless =
          plain ? (r.persist ? sv.plain : sv.close) : (r.persist ? sv.keep : sv.close);
      spell_error({prefix, bodyless, step.status_code,
                   err_pages_.media_for(step.status_code, r.vals.accept, r.vals.accept_len),
                   none, r.head_only},
                  sink);
      break;
    }
    case AssetStep::HeadKind::kUnsatisfiable: tier->answer_416_head(head, sink); break;
    case AssetStep::HeadKind::kRange: tier->answer_206_head(head, sink); break;
    case AssetStep::HeadKind::kNormal: tier->answer_head(head, sink); break;
  }
  const bool sent_page = ebody != nullptr && !r.head_only;
  if (sent_page) sink.append(ebody, eblen);
  bool started_xfer = false;
  if (step.sends_content) {
    if (step.copy_content) {
      Assets::copy_wire(*ae, {step.first_byte_pos, step.content_length}, sink);
    } else {
      r.st.asset = ae;
      r.st.asset_off = step.first_byte_pos;
      r.st.asset_end = step.first_byte_pos + step.content_length;
      started_xfer = true;
    }
  }
  if (alog_.enabled) {
    log_access(alog_, {{static_cast<const char*>(r.st.peer), r.st.peer_len},
                       {r.method, r.method_len},
                       {r.path, r.path_len},
                       {r.vals.log_ref, r.vals.log_ref_len},
                       {r.vals.log_ua, r.vals.log_ua_len},
                       step.sends_content ? step.content_length : (sent_page ? eblen : 0),
                       step.status_code,
                       r.lflags});
  }
  // The head this answered is consumed here, not by the caller -
  // the caller only learns r.off once the round is taken.
  r.off += r.head_len;
  if (r.content_length != 0) {
    const size_t avail = r.viewlen - r.off;
    const size_t skip = r.content_length < avail ? r.content_length : avail;
    r.off += skip;
    r.st.content_skip = r.content_length - skip;
  }
  if (!r.persist) {
    r.st.carry.clear();
    r.st.content_skip = 0;
    return Took::kClose;
  }
  if (started_xfer) {
    const size_t rest = r.viewlen - r.off;
    if (r.in_place) r.st.carry.assign(r.view + r.off, rest);
    else r.st.carry.erase(0, r.off);
    if (plan != nullptr) {
      const size_t room = plan->byte_cap == 0 ? r.st.asset_end - r.st.asset_off
                          : plan->byte_cap > sink.size() ? plan->byte_cap - sink.size()
                                                         : 0;
      size_t take = r.st.asset_end - r.st.asset_off;
      if (take > room) take = room;
      if (take > 0) {
        claim_sink(r.st, sink, *plan);
        struct iovec iv[3];
        const unsigned k = Assets::wire_iov(*r.st.asset, {r.st.asset_off, take}, iv);
        for (unsigned i = 0; i < k; i++) {
          plan->iov[plan->iovlen++] =
              Plan::Seg{static_cast<const char*>(iv[i].iov_base), 0, iv[i].iov_len};
        }
        plan->byte_total += take;
        r.st.asset_off += take;
        if (r.st.asset_off == r.st.asset_end) {
          r.st.asset = nullptr;
          r.st.asset_off = 0;
          r.st.asset_end = 0;
        }
      }
    }
    return Took::kOwed;
  }
  return Took::kNextRequest;
}

// RFC 9110 6.3: the run named a file rather than spelling a body, and
// opening one is disk work that does not belong in a reactor step. The
// framing is copied onto the connection, the reactor drives openat2/
// statx/read through the ring, and `more` puts the result on the wire.
// A name this process already refused takes the same 404 the kernel's
// own refusal would, spelled here since no ring trip is owed.
bool Http1::answer_from_file(Round& r, uint16_t status) {
  WantedFile wanted;
  if (!resource_file_wanted(*r.b->res, wanted) || status != 200) return false;

  Conn& st = r.st;
  // resource_run never lends a body a run also named a file for (see the
  // O18 body handler), so nothing is lent here - zc_release() still runs,
  // for its h2-backlog drain.
  st.zc_release();
  if (st.file == nullptr) st.file = new Conn::FileXfer();
  st.file->pathname.assign(wanted.name);
  st.file->field_lines = rhdrs_;
  st.file->content_type = !r.b->res->run_content_type.empty()
                              ? http::with_charset(r.b->res->run_content_type)
                              : r.b->konst.content_type;
  st.file->minor = r.minor;
  st.file->persist = r.persist;
  st.file->head_only = r.head_only;
  st.file->if_modified_since_valid =
      r.facts.has_if_modified_since && r.facts.if_modified_since_valid;
  st.file->if_modified_since = r.vals.if_modified_since_epoch;
  st.file->log_flags = r.lflags;
  st.file->method_token.assign(r.method, r.method_len);
  st.file->request_target.assign(r.path, r.path_len);
  st.file->referer.assign(r.vals.log_ref != nullptr ? r.vals.log_ref : "", r.vals.log_ref_len);
  st.file->user_agent.assign(r.vals.log_ua != nullptr ? r.vals.log_ua : "", r.vals.log_ua_len);
  st.file->stage = FileStage::kNamed;
  if (wanted.bad) file_reject(st);

  size_t off = r.off;
  if (r.content_length != 0) {
    const size_t avail = r.viewlen - off;
    const size_t skip = r.content_length < avail ? r.content_length : avail;
    off += skip;
    st.content_skip = r.content_length - skip;
  }
  if (!r.persist) {
    st.carry.clear();
    st.content_skip = 0;
  } else if (r.in_place) {
    st.carry.assign(r.view + off, r.viewlen - off);
  } else {
    st.carry.erase(0, off);
  }
  return true;
}

bool Http1::fail(Conn& st, uint16_t code, std::string& out, uint8_t log) {
  if (alog_.enabled) {
    log_access(alog_, {{static_cast<const char*>(st.peer), st.peer_len},
                       {}, "-", {}, {}, 0, code, log});
  }
  // Nothing is parsed on this path, so there is no Accept to weigh and no
  // target to name: the page for the status, and that is all it can say.
  const ErrorPages::Fields f;
  spell_error({prefixes(code).close, variants(code).close, code,
               err_pages_.media_for(code, nullptr, 0), f, false},
              out);
  st.carry.clear();
  st.content_skip = 0;
  st.content_need = 0;
  return false;
}

// The sink's uncovered tail since the last claim, as one external segment -
// every site that splices something else into the plan claims this head
// first, so what follows lands at the right offset on the wire.
void Http1::claim_sink(Conn& st, const std::string& sink, Plan& plan) {
  if (sink.size() > st.zc_covered) {
    const size_t head = sink.size() - st.zc_covered;
    plan.iov[plan.iovlen++] = Plan::Seg{nullptr, st.zc_covered, head};
    plan.byte_total += head;
  }
  st.zc_covered = sink.size();
}

// A lent body splits the sink, so whatever the parse appended after it
// still has to be claimed - and it returns down a dozen paths, so the plan
// is closed HERE, once, on all of them.
bool Http1::feed(Conn& st, std::string_view data, Sink out) {
  std::string& sink = out.bytes;
  Plan* const plan = out.plan;
  const bool ok = feed_parse(st, data, out);
  if (WM_H1_UNLIKELY(st.zc_split) && plan != nullptr) claim_sink(st, sink, *plan);
  return ok;
}

// RFC 9110 8.6: the body the run LENT, delivered as an external segment
// over its own frozen String - the door http1's mmap'd assets already use.
// The sink bytes it splits are claimed on either side of it by offset.
void Http1::lend_body(Conn& st, std::string& sink, Lending lend) {
  Plan& plan = lend.plan;
  claim_sink(st, sink, plan);
  plan.iov[plan.iovlen++] = Plan::Seg{lend.body.data(), 0, lend.body.size()};
  plan.byte_total += lend.body.size();
  st.zc_split = true;
}

// RFC 9112 9.3: a file answer that carries nothing of its own - the status
// straight out of the shared store, in this connection's spelling.
void Http1::file_prebuilt(Conn& st, uint16_t status_code) {
  const Variants& sv = variants(status_code);
  st.file->head = st.file->minor >= 1 ? (st.file->persist ? sv.plain.bytes : sv.close.bytes)
                                      : (st.file->persist ? sv.keep.bytes : sv.close.bytes);
  st.file->status_code = status_code;
  st.file->buf_filled = 0;
  st.file->stage = FileStage::kDeliver;
}

// RFC 9112 3: the head a served file wears. No prebuilt head can hold a
// per-file Content-Length and Last-Modified, so it is spelled byte by byte -
// spell_head's own job, with the run's field lines still in front.
void Http1::file_spell(Conn& st, FileHead head_of) {
  const uint16_t status_code = head_of.status;
  const size_t content_length = head_of.content_length;
  const bool bodyless = head_of.bodyless;
  st.file->head.clear();
  const SpelledHead head = {status_code,
                           date_,
                           bodyless ? std::string_view() : st.file->content_type,
                           st.file->field_lines,
                           st.file->minor,
                           st.file->persist,
                           bodyless,
                           content_length};
  spell_head(st.file->head, head);
  st.file->status_code = status_code;
  st.file->buf_filled = bodyless || st.file->head_only ? 0 : content_length;
  st.file->stage = FileStage::kDeliver;
}

// response.file: the reactor is taking the open. The name has to stay put -
// the SQE points straight at these bytes - so nothing clears it until the
// answer is spelled.
const char* Http1::file_take(Conn& st) {
  if (st.file == nullptr || st.file->stage != FileStage::kNamed) return nullptr;
  st.file->stage = FileStage::kRing;
  return st.file->pathname.c_str();
}

// ONE answer for every refusal: a name that was never there, a directory, a
// "..", a symlink out of the docroot, a /proc magic-link. Same status, same
// bytes, same shape - so an attacker cannot tell a caught escape from a
// miss and probe the filesystem through the difference.
void Http1::file_reject(Conn& st) { file_prebuilt(st, 404); }

// The server's own fault: named in the error log, never in the answer.
void Http1::file_error(Conn& st, const char* why) {
  log_internal_error(elog_, {{static_cast<const char*>(st.peer), st.peer_len},
                             st.file->request_target,
                             why,
                             500});
  // Once a window has gone out the answer is committed: the head named a
  // Content-Length this body can no longer reach, so a 500 spelled here
  // would land BEHIND those bytes and the client would wait forever for the
  // rest. RFC 9112 6.3: the only way left to say "this is not the whole
  // representation" is to close the connection under it.
  if (st.file->content_sent != 0) {
    st.file->content_length = st.file->content_sent;
    st.file->buf_filled = 0;
    st.file->persist = false;
    st.file->stage = FileStage::kDeliver;
    return;
  }
  file_prebuilt(st, 500);
}

// statx on the opened fd. Only a regular file within the ceiling earns a
// read; everything else is answered here and the fd goes straight back.
// True = the bytes are still owed.
bool Http1::file_stat(Conn& st, const struct statx& stx, size_t* want) {
  if (!S_ISREG(stx.stx_mode)) {
    // A directory, a fifo, a device: not a representation, and saying WHICH
    // would be the distinguishable answer this whole path avoids.
    file_reject(st);
    return false;
  }
  const size_t len = static_cast<size_t>(stx.stx_size);

  // RFC 9110 8.8.2: Last-Modified, whole seconds, in front of whatever field
  // lines the run itself spelled.
  const int64_t mtime = static_cast<int64_t>(stx.stx_mtime.tv_sec);
  char lm[http::kDateLen];
  {
    const time_t t = static_cast<time_t>(mtime);
    struct tm tm;
    gmtime_r(&t, &tm);
    http::date_core(lm, tm);
  }
  st.file->field_lines.append("Last-Modified: ").append(lm, http::kDateLen).append("\r\n");

  // RFC 9110 13.1.3 / 15.4.5: no newer than what the client already holds.
  if (st.file->if_modified_since_valid && mtime <= st.file->if_modified_since) {
    file_spell(st, {304, 0, true});
    return false;
  }
  if (st.file->head_only || len == 0) {
    // The head still states the real length; HEAD just sends no bytes.
    file_spell(st, {200, len, false});
    return false;
  }
  file_spell(st, {200, len, false});
  st.file->stage = FileStage::kRing;  // the head stands, the bytes are owed
  st.file->content_length = len;
  st.file->content_sent = 0;
  // [tune] file_map_threshold: 0 is "never map", so it is not a plain >=.
  st.file->map_wanted = map_min_ != 0 && len >= map_min_;
  // ONE meaning: what a READ may take. The mapping's length is a separate
  // question with a separate answer (file_map_len) - the two used to share
  // this variable, and the read path then asked for the whole file.
  *want = len < kResponseFileWindow ? len : kResponseFileWindow;
  return true;
}

// Where the ring reads the bytes. Only ever called with no read in flight.
char* Http1::file_buffer(Conn& st, size_t n) {
  if (st.file->buf.size() < n) st.file->buf.resize(n);
  return &st.file->buf[0];
}

// The whole file, mapped. No read happened and none will: more() lends the
// mapping to one send and zc_release() gives it back when that round drains.
void Http1::file_mapped(Conn& st, const char* p, size_t n) {
  // A mapping still installed here belongs to no round: nothing lent it,
  // so nothing will hand it back.
  st.map_release();
  st.file->map_addr = p;
  st.file->map_length = n;
  st.file->buf_filled = n;
  st.file->content_length = n;
  st.file->content_sent = 0;
  st.file->stage = FileStage::kDeliver;
}

// The ONE place a transfer's state changes as a round goes out. Everything
// it does was decided by file_step over a snapshot; nothing is decided here.
void Http1::file_apply(Conn& st, const FileStep& step) {
  if (st.file == nullptr) return;
  st.file->content_sent = step.sent_after;
  st.file->stage = step.next;
  if (step.head) st.file->head.clear();  // the head rides the first round
  if (step.log) file_log(st);            // before file_clear takes the strings
  if (step.release_map) st.map_release();
  if (step.clear) st.file_clear();
}

// RFC 9110: ONE access line per request, with the bytes that really left.
// A transfer that ends in sixteen windows is one request, not sixteen.
void Http1::file_log(Conn& st) {
  if (!alog_.enabled || st.file == nullptr) return;
  const Conn::FileXfer& x = *st.file;
  log_access(alog_, {{static_cast<const char*>(st.peer), st.peer_len},
                     x.method_token, x.request_target, x.referer, x.user_agent,
                     x.content_sent, x.status_code, x.log_flags});
}

// A connection dying under a transfer still owes its line - that event is
// exactly what an operator wants to see. The stage is the guard: a transfer
// that reached kNone has already written its line and cannot write a second.
void Http1::file_abandon(Conn& st) {
  if (st.file == nullptr || st.file->stage == FileStage::kNone) return;
  file_log(st);
  st.file->stage = FileStage::kNone;
}

// The bytes are in. `more` is what puts head and body on the wire.
void Http1::file_ready_now(Conn& st, size_t n) {
  st.file->buf_filled = n;
  st.file->stage = FileStage::kDeliver;
}

// RFC 9112: THE framer. phr on the wire bytes, the carry only when a head
// splits; RFC 9113 3.4 decides h2 on the first bytes; the flow decides
// every status.
bool Http1::feed_parse(Conn& st, std::string_view in, Sink out) {
  const char* data = in.data();
  size_t len = in.size();
  std::string& sink = out.bytes;
  Plan* const plan = out.plan;
  if (st.h2 != nullptr) return h2_feed(st, in, out);
  if (st.fresh) {
    st.content_need = 0;
    const size_t seen = st.carry.size();
    size_t i = 0;
    while (i < len && seen + i < kH2PrefaceLen && data[i] == kH2Preface[seen + i]) i++;
    if (seen + i == kH2PrefaceLen) {
      st.fresh = false;
      st.carry.clear();
      if (!h2_begin(st, sink)) return false;
      return h2_feed(st, {data + i, len - i}, out);
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
  if (st.content_skip != 0) {
    const size_t take = st.content_skip < len ? st.content_skip : len;
    st.content_skip -= take;
    data += take;
    len -= take;
    if (len == 0) return true;
  }

  // RFC 9110 6.4: a bound route's head waits in the carry until the whole
  // body is here - the run READS the body, so it cannot answer before the
  // last byte. Nothing is parsed again until body_need is paid off.
  if (WM_H1_UNLIKELY(st.content_need != 0)) {
    if (len < st.content_need) {
      st.content_need -= len;
      st.carry.append(data, len);
      return true;
    }
    st.content_need = 0;
  }

  if (WM_H1_UNLIKELY(st.asset != nullptr)) {
    if (WM_H1_UNLIKELY(st.carry.size() + len > kMaxHead)) {
      st.carry.clear();
      st.content_skip = 0;
      st.asset = nullptr;
      return false;
    }
    st.carry.append(data, len);
    return true;
  }

  if (WM_H1_UNLIKELY(st.ws != nullptr)) return ws_feed(st.ws, in, sink);
  if (WM_H1_UNLIKELY(st.sse != nullptr)) return true;

  const bool in_place = st.carry.empty();
  const char* view = data;
  size_t viewlen = len;
  if (WM_H1_UNLIKELY(!in_place)) {
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
    if (WM_H1_UNLIKELY(ret == -2)) {
      const size_t rest = viewlen - off;
      if (WM_H1_UNLIKELY(rest > kMaxHead)) return fail(st, 431, sink);
      if (in_place) st.carry.assign(view + off, rest);
      else st.carry.erase(0, off);
      return true;
    }
    if (WM_H1_UNLIKELY(ret <= 0)) return fail(st, 400, sink);
    if (WM_H1_UNLIKELY(static_cast<size_t>(ret) > kMaxHead)) return fail(st, 431, sink);

    WireFacts w;
    flow::ReqFacts facts;
    http::ReqValues vals;
    facts.method = http::parse_method(method, method_len);
    for (size_t i = 0; i < num_headers; i++) {
      const struct phr_header& h = headers[i];
      if (http::header_switch({{h.name, h.name_len}, {h.value, h.value_len}},
                              {facts, vals, i})) {
        read_wire_header({w, vals, i}, {{h.name, h.name_len}, {h.value, h.value_len}});
      }
    }
    const uint8_t lflags = facts.no_track ? kLogNoTrack : 0;
    if (WM_H1_UNLIKELY(w.err != 0)) return fail(st, w.err, sink, lflags);
    if (WM_H1_UNLIKELY(w.have_te)) return fail(st, w.have_cl ? 400 : 411, sink, lflags);
    if (WM_H1_UNLIKELY(minor >= 1 && !w.have_host)) return fail(st, 400, sink, lflags);
    if (WM_H1_UNLIKELY(w.content_length > kMaxBody)) return fail(st, 413, sink, lflags);

    const bool persist = minor >= 1 ? !w.conn_close : w.conn_keep;
    const bool head_only = facts.method == flow::Method::kHead;

    if (WM_H1_UNLIKELY(w.up_ws && w.conn_upgrade)) {
      const AppSlot& wslot = apps_[st.listener];
      RouteSpans wspans;
      const int wr =
          wslot.ws_table != nullptr ? wslot.ws_table->match(path, path_len, wspans) : -1;
      if (wr >= 0) {
        if (w.ws_version != 13) {
          sink.append("HTTP/1.1 426 Upgrade Required\r\nDate: ");
          sink.append(date_, http::kDateLen);
          sink.append(
              "\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\n"
              "Content-Length: 0\r\n\r\n");
          return false;
        }
        if (facts.method != flow::Method::kGet || w.ws_key == nullptr) {
          return fail(st, 400, sink, lflags);
        }
        const char* rest = view + off + static_cast<size_t>(ret);
        const size_t rest_len = viewlen - off - static_cast<size_t>(ret);
        const WsUpgrade up{wslot,  wr,   {path, path_len},
                           wspans, {w.ws_key, w.ws_key_len},
                           headers, num_headers, vals, {rest, rest_len}};
        return ws_upgrade(st, up, sink);
      }
    }

    if (WM_H1_UNLIKELY(apps_[st.listener].sse_table != nullptr)) {
      const AppSlot& sslot = apps_[st.listener];
      RouteSpans sspans;
      const int sr = sslot.sse_table->match(path, path_len, sspans);
      if (sr >= 0) {
        const SseBegin req{sslot,   sr,          {method, method_len},
                           {path, path_len},    sspans,  headers,
                           num_headers, minor,  facts.method, vals, lflags};
        return sse_begin(st, req, sink);
      }
    }

    // #210: the error assets answer under one reserved prefix, always,
    // and without the operator mounting anything - a page that names a
    // picture has to be able to hand it over. Everything else belongs to
    // whoever passed --assets.
    {
      Round r{st,   nullptr, view, viewlen, off, static_cast<size_t>(ret),
              in_place, method, method_len, path, path_len, minor, persist, head_only,
              w.content_length, lflags, facts, vals};
      const Took took = answer_from_assets(r, sink, plan);
      if (WM_H1_UNLIKELY(took != Took::kNo)) {
        off = r.off;
        if (took == Took::kClose) return false;
        if (took == Took::kOwed) return true;
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
    // Read once, used by both the zero-copy eligibility gate below and
    // assemble_dynamic() further down - Accept-Encoding does not change
    // between the two.
    bool accept_gzip = false;
    if (WM_H1_UNLIKELY(route < 0)) {
      status = 404;
    } else {
      b = &bundles_[slot.base + static_cast<size_t>(route)];
      idx = &b->index;
      if (WM_H1_LIKELY(b->bound)) {
        const size_t head_len = static_cast<size_t>(ret);
        if (w.content_length != 0 && viewlen - off - head_len < w.content_length) {
          st.content_need = w.content_length - (viewlen - off - head_len);
          const size_t rest = viewlen - off;
          if (in_place) st.carry.assign(view + off, rest);
          else st.carry.erase(0, off);
          return true;
        }
        ReqView rv;
        rv.request_target = path;
        rv.request_target_len = path_len;
        rv.path_len = http::path_only(path, path_len);
        rv.method = facts.method;
        rv.method_token = method;
        rv.method_token_len = method_len;
        rv.table = slot.table;
        rv.route = route;
        rv.spans = spans;
        rv.fields = headers;
        rv.field_count = num_headers;
        rv.values = &vals;
        if (w.content_length != 0) {
          rv.content = view + off + head_len;
          rv.content_len = w.content_length;
        }
        accept_gzip = !facts.has_accept_encoding ||
                      http::gzip_acceptable(vals.accept_encoding, vals.accept_encoding_len);
        // A run may LEND its body only where nothing downstream touches the
        // bytes anyway: HEAD sends none, gzip copies them, one connection
        // holds one lend, and an external segment fits through a plan only.
        const bool gz_now = accept_gzip && b->gzip_ok && st.packetized;
        const size_t zc_min = (zc_min_ != 0 && plan != nullptr && !st.zc_lent && !head_only &&
                               !gz_now)
                                  ? zc_min_
                                  : 0;
        const RunAsk asked = {facts, &vals, &rv, zc_min};
        const RunAnswer answer = {&body_, &have_body, &rhdrs_};
        status = resource_run(*b->res, asked, answer);
        LentBody lent_body;
        if (WM_H1_UNLIKELY(resource_body_lent(*b->res, lent_body))) {
          st.zc_value = lent_body.value;
          lent = lent_body.bytes.data();
          lent_len = lent_body.bytes.size();
          st.zc_mrb = b->res->mrb;
          st.zc_lent = true;
        }
        // #210 response.error_asset: the run named an entry of the error
        // assets, and an entry goes on the wire the way the asset tier
        // already puts one there - through Assets' own accessors, which
        // are the one place that knows an entry's wire form. It lives in
        // a mapping that outlives every request, so nothing here is
        // rooted and nothing is released: a plan carries the segment
        // (wire_iov), and without one the bytes are copied (copy_wire).
        if (WM_H1_UNLIKELY(b->res->run_asset != nullptr)) {
          const AssetEntry& ae = *b->res->run_asset;
          const size_t n = Assets::wire_len(ae);
          if (plan != nullptr) {
            struct iovec iv[3];
            const unsigned k = Assets::wire_iov(ae, {0, n}, iv);
            // One segment for a stored entry; a deflated one would be
            // three, and response.error_asset refuses those - the head
            // spelled here carries no Content-Encoding to declare them.
            lent = k == 1 ? static_cast<const char*>(iv[0].iov_base) : nullptr;
            lent_len = k == 1 ? iv[0].iov_len : 0;
          }
          if (lent == nullptr) {
            body_.clear();
            Assets::copy_wire(ae, {0, n}, body_);
          }
        }
        // response.file: the run named a file instead of spelling a body,
        // and opening one is disk work that does not belong in a reactor
        // step. NOTHING is answered here - the framing this answer will need
        // is copied onto the connection, the reactor drives openat2/statx/
        // read through the ring, and `more` puts the result on the wire. A
        // name this process already refused takes the same 404 the kernel's
        // own refusal takes, spelled right here since no ring trip is owed.
        {
          Round r{st,   b,        view,      viewlen,  off + static_cast<size_t>(ret),
                  static_cast<size_t>(ret), in_place, method,   method_len,
                  path, path_len, minor,     persist,  head_only,
                  w.content_length, lflags,   facts,    vals};
          if (WM_H1_UNLIKELY(answer_from_file(r, status))) {
            body_.clear();
            have_body = false;
            return true;
          }
        }
        // RFC 9110 6.3: field lines or a conneg no prebuilt head can hold -
        // this run spells its own. 500 stays on the exception path below.
        if (WM_H1_UNLIKELY((!b->res->run_content_type.empty() || !rhdrs_.empty()) &&
                           status != 500)) {
          const bool bodyless = status == 204 || status == 304;
          if (bodyless || !have_body) {
            body_.clear();
            st.zc_release();
            lent = nullptr;
            lent_len = 0;
          }
          // helpers.rb encode_body: a `def self.to_html` renders at SETUP, so
          // a run that reaches o18 with one produces no body - the bundle's
          // prebuilt 200 carries it. That head is not the one being spelled
          // here, so the bake has to be named, or this answer goes out empty.
          const bool baked = !bodyless && !have_body && lent == nullptr && status == 200 &&
                             !b->dynamic_body && !b->konst.body.empty();
          std::string ctype;
          std::string epage;
          // RFC 9110 15: a 4xx or 5xx is owed the page its status carries,
          // and a run that wrote a field of its own - a 405's Allow, most
          // often - lands here instead of at spell_error. Without this it
          // goes out as the bare status: the same answer the prebuilt one
          // gives, minus the page the prebuilt one has.
          if (status >= 400 && !bodyless && !have_body && lent == nullptr) {
            const int em = err_pages_.media_for(status, vals.accept, vals.accept_len);
            size_t elen = 0;
            const ErrorPages::Fields none;
            const char* ep = err_pages_.body_for({status, em, none}, epage, &elen);
            if (ep != nullptr) {
              body_.assign(ep, elen);
              have_body = true;
              ctype = err_pages_.media_type(em);
            }
          }
          if (!bodyless && ctype.empty()) {
            if (!b->res->run_content_type.empty()) {
              ctype = http::with_charset(b->res->run_content_type);
            }
            else if (have_body || baked) ctype = b->konst.content_type;
          }
          const SpelledHead head = {
              status, date_, ctype, rhdrs_, minor, persist, bodyless,
              lent != nullptr ? lent_len : (baked ? b->konst.body.size() : body_.size())};
          spell_head(sink, head);
          if (!bodyless && !head_only) {
            if (lent != nullptr) lend_body(st, sink, {{lent, lent_len}, *plan});
            else sink.append(baked ? b->konst.body : body_);
          }
          have_body = false;
          answered = true;
        }
      } else {
        // RFC 9110 12.5.1: c4 belongs to the client. The fold left this
        // resource with exactly one media type (two would have bound it), so
        // the question is one match, asked here in C++ and never in the VM.
        if (WM_H1_UNLIKELY(facts.has_accept && vals.accept != nullptr)) {
          facts.accept_ok =
              http::choose_media_type({{&b->accept_type, 1}, {vals.accept, vals.accept_len}}) >= 0;
        }
        const size_t mi = static_cast<size_t>(facts.method);
        status = flow::answer(facts, {b->konst.per_method[mi], b->konst.shortcut[mi]});
      }
    }

    AnswerStep astep = answer_step({status, body_.size(), lent_len, answered, have_body,
                                    lent != nullptr, b != nullptr && b->gzip_ok,
                                    b != nullptr && b->bound});
    mrb_value exc_value = mrb_nil_value();
    // #210: what led here, gathered once - the record and the page carry
    // the same hash because they are taken over the same facts.
    ErrFacts ef;
    std::string ef_backtrace;
    std::string ef_steering;
    char ef_hash[kFingerprintLen] = {};
    if (WM_H1_UNLIKELY(astep.shape == AnswerStep::Shape::kException)) {
      ef.peer = st.peer;
      ef.peer_len = st.peer_len;
      ef.request_target = path;
      ef.request_target_len = path_len;
      ef.method = method;
      ef.method_len = method_len;
      spell_steering(&vals, ef_steering);
      ef.steering = ef_steering.data();
      ef.steering_len = ef_steering.size();
      // The request as the resource saw it: lent for this frame, which is
      // the frame still being answered.
      ef.body = b->res->run_req != nullptr ? b->res->run_req->content : nullptr;
      ef.body_len = b->res->run_req != nullptr ? b->res->run_req->content_len : 0;
      ef.body_full = ef.body_len;
      ef.status_code = 500;
      exception_facts(b->res->mrb, {ef, ef_backtrace});
      spell_fingerprint(ef_hash, fingerprint_of(ef));
      if (elog_.enabled) log_error(elog_, ef);
      // #210: handle_exception lives on the error resource and nowhere
      // else, so the exception object itself is what crosses over - not
      // a message some resource already made of it.
      if (resource_exception_take(*b->res, &exc_value)) astep.answered = true;
      else astep.shape = AnswerStep::Shape::kStatus;
    }
    switch (astep.shape) {
      case AnswerStep::Shape::kAlready:
        break;
      case AnswerStep::Shape::kLent: {
        const Variants& pv = b->gzip_ok ? b->ok_prefix_vary : b->ok_prefix;
        const Resp& pfx = minor >= 1 ? (persist ? pv.plain : pv.close)
                                     : (persist ? pv.keep : pv.close);
        sink.append(pfx.bytes);
        char cl[40];
        sink.append(cl, http::spell_content_length(cl, lent_len));
        lend_body(st, sink, {{lent, lent_len}, *plan});
        break;
      }
      case AnswerStep::Shape::kGzip: {
        const Resp& prefix_id =
            minor >= 1 ? (persist ? b->ok_prefix_vary.plain : b->ok_prefix_vary.close)
                       : (persist ? b->ok_prefix_vary.keep : b->ok_prefix_vary.close);
        const Resp& prefix_gz =
            minor >= 1 ? (persist ? b->ok_prefix_gzip.plain : b->ok_prefix_gzip.close)
                       : (persist ? b->ok_prefix_gzip.keep : b->ok_prefix_gzip.close);
        assemble_dynamic({prefix_id, prefix_gz, accept_gzip && st.packetized, head_only}, sink);
        break;
      }
      case AnswerStep::Shape::kPlain: {
        const Resp& prefix = minor >= 1 ? (persist ? b->ok_prefix.plain : b->ok_prefix.close)
                                        : (persist ? b->ok_prefix.keep : b->ok_prefix.close);
        assemble(sink, {prefix, body_, head_only});
        break;
      }
      case AnswerStep::Shape::kException: {
        std::string message;
        err_pages_.exception_text(exc_value, message);
        const Variants& pv = store_prefix_[(*idx)[500]];
        const Variants& bv = store_[(*idx)[500]];
        ErrorPages::Fields f;
        f.message = message.data();
        f.message_len = message.size();
        f.fingerprint = ef_hash;
        // A ship build says what was thrown and where the log has the rest; a
        // debug build is already telling you about itself, so the trace goes
        // on the page too.
        if (kDebugBuild) {
          f.backtrace = ef.backtrace;
          f.backtrace_len = ef.backtrace_len;
        }
        const Resp& prefix = minor >= 1 ? (persist ? pv.plain : pv.close)
                                        : (persist ? pv.keep : pv.close);
        const Resp& bodyless = minor >= 1 ? (persist ? bv.plain : bv.close)
                                          : (persist ? bv.keep : bv.close);
        spell_error({prefix, bodyless, 500,
                     err_pages_.media_for(500, vals.accept, vals.accept_len), f, head_only},
                    sink);
        break;
      }
      case AnswerStep::Shape::kStatus: {
        const Variants& sv =
            (head_only && status == 200) ? b->ok_head : store_[(*idx)[status]];
        const Resp& bodyless = minor >= 1 ? (persist ? sv.plain : sv.close)
                                          : (persist ? sv.keep : sv.close);
        // RFC 9110 15: only a 4xx or 5xx has something to explain. A 204,
        // a 304 or a redirect is an answer, and answers carry no page.
        if (status >= 400) {
          const Variants& pv = store_prefix_[(*idx)[status]];
          const ErrorPages::Fields f;
          const Resp& prefix = minor >= 1 ? (persist ? pv.plain : pv.close)
                                          : (persist ? pv.keep : pv.close);
          spell_error({prefix, bodyless, status,
                       err_pages_.media_for(status, vals.accept, vals.accept_len), f, head_only},
                      sink);
        } else {
          sink.append(bodyless.bytes);
        }
        break;
      }
    }
    if (alog_.enabled) {
      log_access(alog_, {{static_cast<const char*>(st.peer), st.peer_len},
                         {method, method_len},
                         {path, path_len},
                         {vals.log_ref, vals.log_ref_len},
                         {vals.log_ua, vals.log_ua_len},
                         (astep.answered && !head_only) ? astep.body_len : 0,
                         status,
                         lflags});
    }

    off += static_cast<size_t>(ret);
    if (w.content_length != 0) {
      const size_t avail = viewlen - off;
      const size_t skip = w.content_length < avail ? w.content_length : avail;
      off += skip;
      st.content_skip = w.content_length - skip;
    }
    if (WM_H1_UNLIKELY(!persist)) {
      st.carry.clear();
      st.content_skip = 0;
      return false;
    }
  }
  if (WM_H1_UNLIKELY(!in_place)) st.carry.clear();
  return true;
}

// RFC 6455 4.2.2: the handshake's answer, 101 or the refusal the route earned.
bool Http1::ws_upgrade(Conn& st, const WsUpgrade& up, std::string& sink) {
  const AppSlot& slot = up.slot;
  const int route = up.route;
  const std::string_view path = up.path;
  const RouteSpans& spans = up.spans;
  const void* hdrs = up.hdrs;
  const size_t nhdr = up.nhdr;
  const http::ReqValues& vals = up.vals;
  char accept[28];
  if (!ws::accept_key(up.key.data(), up.key.size(), accept)) return fail(st, 400, sink);

  const WsResource* res = ws_res_[slot.ws_base + static_cast<size_t>(route)];

  ReqView rv;
  rv.request_target = path.data();
  rv.request_target_len = path.size();
  rv.path_len = http::path_only(path.data(), path.size());
  rv.method = flow::Method::kGet;
  rv.table = slot.ws_table;
  rv.route = route;
  rv.spans = spans;
  rv.fields = hdrs;
  rv.field_count = nhdr;
  rv.values = &vals;
  request_bind(&rv);
  std::string proto;
  uint16_t refuse_status = 0;
  WsConn* wsc = ws_admit(res, elog_.enabled ? &elog_ : nullptr, {proto, refuse_status});
  request_bind(nullptr);
  if (wsc == nullptr) {
    return fail(st, refuse_status == 0 ? 403 : refuse_status, sink);
  }

  wsdeflate::Params dparams;
  std::string ext_answer;
  if (ws_wants_deflate(res)) {
    const struct phr_header* hs = static_cast<const struct phr_header*>(hdrs);
    for (size_t i = 0; i < nhdr && !dparams.on; i++) {
      if (!http::tok_eq({hs[i].name, hs[i].name_len}, "sec-websocket-extensions")) continue;
      wsdeflate::negotiate({hs[i].value, hs[i].value_len}, {dparams, ext_answer});
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
  st.content_skip = 0;
  if (!up.rest.empty()) return ws_feed(st.ws, up.rest, sink);
  return true;
}

// One line of the access log for an event stream that got an answer.
void Http1::log_sse(Logger& lg, const Conn& st, const SseLine& line) {
  if (!lg.enabled) return;
  const std::string_view method = line.method;
  const std::string_view path = line.path;
  const http::ReqValues& vals = line.vals;
  const uint8_t lflags = line.lflags;
  const uint16_t status = line.status;
  log_access(lg, {{static_cast<const char*>(st.peer), st.peer_len},
                  method,
                  path,
                  {vals.log_ref, vals.log_ref_len},
                  {vals.log_ua, vals.log_ua_len},
                  0, status, lflags});
}

// WHATWG HTML: the event stream's head - RFC 9112 7.1 chunked, RFC 9111
// 5.2.2.5 no-store, and this connection never reads another head.
bool Http1::sse_begin(Conn& st, const SseBegin& req, std::string& sink) {
  const AppSlot& slot = req.slot;
  const int route = req.route;
  const std::string_view method = req.method;
  const std::string_view path = req.path;
  const RouteSpans& spans = req.spans;
  const void* hdrs = req.hdrs;
  const size_t nhdr = req.nhdr;
  const int minor = req.minor;
  const flow::Method m = req.m;
  const http::ReqValues& vals = req.vals;
  const uint8_t lflags = req.lflags;
  if (WM_H1_UNLIKELY(m != flow::Method::kGet)) {
    log_sse(alog_, st, {method, path, vals, 405, lflags});
    sink.append("HTTP/1.1 405 Method Not Allowed\r\nDate: ");
    sink.append(date_, http::kDateLen);
    sink.append("\r\nAllow: GET\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    return false;
  }
  if (WM_H1_UNLIKELY(minor < 1)) {
    log_sse(alog_, st, {method, path, vals, 505, lflags});
    sink.append("HTTP/1.1 505 HTTP Version Not Supported\r\nDate: ");
    sink.append(date_, http::kDateLen);
    sink.append("\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    return false;
  }

  ReqView rv;
  rv.request_target = path.data();
  rv.request_target_len = path.size();
  rv.path_len = http::path_only(path.data(), path.size());
  rv.method = flow::Method::kGet;
  rv.table = slot.sse_table;
  rv.route = route;
  rv.spans = spans;
  rv.fields = hdrs;
  rv.field_count = nhdr;
  rv.values = &vals;
  request_bind(&rv);
  uint16_t refused = 0;
  SseStream* s = sse_open(sse_res_[slot.sse_base + static_cast<size_t>(route)],
                        elog_.enabled ? &elog_ : nullptr, refused);
  request_bind(nullptr);
  if (s == nullptr) {
    // RFC 9110 15.5.4: a stream the app would not open is a 403 unless the
    // app named a status of its own.
    const uint16_t status = refused == 0 ? 403 : refused;
    log_sse(alog_, st, {method, path, vals, status, lflags});
    return fail(st, status, sink, lflags);
  }

  log_sse(alog_, st, {method, path, vals, 200, lflags});
  sink.append("HTTP/1.1 200 OK\r\nDate: ");
  sink.append(date_, http::kDateLen);
  sink.append(
      "\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\n"
      "Transfer-Encoding: chunked\r\n\r\n");
  st.sse = s;
  st.carry.clear();
  st.content_skip = 0;
  return true;
}
}
