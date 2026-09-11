#include "webmachine.hpp"

#include "ring.hpp"

#include <picohttpparser.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>


namespace webmachine {
namespace {
// RFC 9110 7.6.1: Connection is a token list - a substring match would
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

// RFC 9112: what the framer reads out of the head - the fields 9110's
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
  bool te_chunked = false;
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

// Where one request's framing facts are being filled: the facts, the
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
        if (mrb_unlikely(w.have_cl)) {
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
      if (http::tok_eq({n, nl}, "transfer-encoding")) {
        w.have_te = true;
        // RFC 9112 6.1: chunked is the only coding this server reads,
        // and it has to be the last one. Anything else is 501.
        w.te_chunked = http::tok_eq({v, vl}, "chunked");
      }
      else if (http::tok_eq({n, nl}, "sec-websocket-key")) {
        w.ws_key = v;
        w.ws_key_len = vl;
      }
      break;
    case 4:
      if (http::tok_eq({n, nl}, "host")) {
        if (mrb_unlikely(w.have_host)) w.err = 400;
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

// RFC 9112 3/9.3: the head that one bound run spelled for itself. Its status,
// the Date line for this second, its own Content-Type and field lines,
// this connection's framing, and a length where it declares one. No
// prebuilt head can take that shape.
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
// beside it the same answer without `body`, which is where an error that
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

// RFC 9110: one route's whole voice - its 200 in every shape, its Allow
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
  // The 200 without its tail - no Content-Length, no body. A dynamic body
  // needs it because its length is not known until the run returns; a konst
  // body needs it because the prebuilt 200 carries the body inside the
  // buffer whose Date stamp_variants patches every second, and a body that
  // is lent rather than copied must not sit in bytes that move.
  {
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
    apps_[a].tls = apps[a].tls;
    apps_[a].max_body = apps[a].max_body;
    for (size_t i = 0; i < apps[a].sse_nroutes; i++) {
      sse_res_.push_back(apps[a].sse_resources[i]);
    }
    sse_at += apps[a].sse_nroutes;
  }

  if (assets_ != nullptr) {
    h2_build_asset_shared();
    for (AssetEntry& e : assets_->entries()) h2_build_asset_blocks(e);
  }

  sec_ = 0;
  on_tick();
}

// A pack built again while this one serves. The entries are new objects
// in a new mapping, so the h2 blocks are built for them the way the
// constructor built them for the pack this replaces.
void Http1::swap_assets(Assets* assets) {
  assets_ = assets;
  if (assets_ == nullptr) return;

  h2_build_asset_shared();
  for (AssetEntry& e : assets_->entries()) h2_build_asset_blocks(e);
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
    // RFC 9110 6.6.1: the Date is the time the message was made, so
    // Every head that goes on the wire is stamped - ok_prefix included,
    // which serves the konst body as well as a dynamic one.
    patch_date(b.ok_prefix, core);
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
    const size_t cl_len = http::spell_content_length(cl, d.body.size());
    if (d.prefix_id.bytes.size() + cl_len + d.body.size() >= kCompressFloor) {
      use_gzip = gzip::compress(d.body, gz_body_);
    }
  }
  if (use_gzip) assemble(sink, {d.prefix_gz, gz_body_, d.head_only});
  else assemble(sink, {d.prefix_id, d.body, d.head_only});
}

// RFC 9112: wire invalidity - framing trust is gone, the connection ends.
// #210: the error pages render in a VM this layer does not own. Called
// once, after the bundles exist; a caller that never calls it keeps the
// bodyless statuses (#173: bytes in, bytes out, no VM required).
void Http1::open_error_assets(mrb_state* mrb, Assets* error_assets) {
  error_assets_ = error_assets;
  err_pages_.open(mrb, error_assets, &elog_);
}

// RFC 9110 15: the error answer - the prebuilt status line and Date, then
// the page rendered for this request. RFC 9110 9.3.2: a HEAD carries the
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
      asset_step(*ae, {as, r.head_only, r.facts.method, r.vals});
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
    r.st.asset = ae;
    r.st.become(ConnMode::kAsset);
    r.st.asset_off = step.first_byte_pos;
    r.st.asset_end = step.first_byte_pos + step.content_length;
    started_xfer = true;
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
          r.st.become(ConnMode::kHead);
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
// statx/read through the ring, and `spell_next_round` puts the result on the wire.
// A name this process already refused takes the same 404 the kernel's
// own refusal would, spelled here since no ring trip is owed.
bool Http1::answer_from_file(Round& r, uint16_t status, const std::string& rhdrs) {
  WantedFile wanted;
  if (!resource_file_wanted(*r.b->res, wanted) || status != 200) return false;

  Conn& st = r.st;
  // resource_run never lends a body a run also named a file for (see the
  // O18 body handler), so nothing is lent here - zc_release() still runs,
  // for its h2-backlog drain.
  st.zc_release();
  if (st.file == nullptr) st.file = new Conn::FileXfer();
  st.file->pathname.assign(wanted.name);
  st.file->field_lines = rhdrs;
  st.file->content_type = !r.b->res->run.content_type.empty()
                              ? http::with_charset(r.b->res->run.content_type)
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
  // RFC 9110 12.5.1: which form a refusal takes is the caller's Accept,
  // and a refusal can land long after this round - so it is decided here,
  // while the request is still in hand.
  st.file->err_media = err_pages_.media_for(404, r.vals.accept, r.vals.accept_len);
  st.file->stage = FileStage::kNamed;
  if (wanted.bad) file_reject(st);
  file_named_tail(r);
  return true;
}

// What every named file owes the connection once the answer is the ring's:
// the request body this round will never read is skipped, and what the
// parse read past this request is carried to the next one.
void Http1::file_named_tail(Round& r) {
  Conn& st = r.st;
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
}

// RFC 9110 4.2.1: the target names a file under the docroot, and this is
// the tier that answers it - with no app, no route and no VM. The
// decision is the graph's, folded: GET and HEAD answer, anything else is
// 405, a directory takes its index.html, and what is not there is 404.
//
// It is the file machine underneath, the same one response.file drives:
// openat2 beneath the docroot fd, statx, If-Modified-Since, the head
// spelled per file. What this adds is the name and the media type.
Http1::Took Http1::answer_from_docroot(Round& r) {
  if (docroot_fd() < 0 || mime_ == nullptr) return Took::kNo;

  Conn& st = r.st;
  const bool readable =
      r.facts.method == flow::Method::kGet || r.facts.method == flow::Method::kHead;

  // The path a client wrote, without its leading slash and without a
  // query. A directory takes its own index.html, as the asset tier does.
  size_t len = r.path_len;
  for (size_t i = 0; i < len; i++) {
    if (r.path[i] == '?') {
      len = i;
      break;
    }
  }
  std::string name;
  if (len > 1) name.assign(r.path + 1, len - 1);
  if (name.empty() || name.back() == '/') name.append("index.html");

  // A name this process can refuse without asking the kernel. openat2
  // with RESOLVE_BENEATH would refuse the same ones, and a ring trip
  // that can only end in 404 is a ring trip nobody owes.
  bool bad = name.find('\0') != std::string::npos;
  for (size_t at = 0; !bad && at < name.size();) {
    const size_t end = name.find('/', at);
    const std::string_view seg(name.data() + at,
                               (end == std::string::npos ? name.size() : end) - at);
    if (seg.empty() || seg == "." || seg == "..") bad = true;
    if (end == std::string::npos) break;
    at = end + 1;
  }

  if (st.file == nullptr) st.file = new Conn::FileXfer();
  st.file->pathname.assign(name);
  st.file->field_lines.clear();
  st.file->content_type = http::with_charset(mime_->type_of(name));
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
  st.file->err_media = err_pages_.media_for(404, r.vals.accept, r.vals.accept_len);
  st.file->stage = FileStage::kNamed;
  if (!readable) file_prebuilt(st, r.facts.method == flow::Method::kOther ? 501 : 405);
  else if (bad) file_reject(st);
  file_named_tail(r);
  return Took::kOwed;
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
// is closed here, once, on all of them.
bool Http1::feed(Conn& st, std::string_view data, Sink out) {
  std::string& sink = out.bytes;
  Plan* const plan = out.plan;
  const bool ok = feed_parse(st, data, out);
  if (mrb_unlikely(st.zc_split) && plan != nullptr) claim_sink(st, sink, *plan);
  return ok;
}

// RFC 9110 8.6: the body the run lent, delivered as an external segment
// over its own frozen String - the door http1's mmap'd assets already use.
// The sink bytes it splits are claimed on either side of it by offset.
void Http1::lend_body(Conn& st, std::string& sink, Lending lend) {
  Plan& plan = lend.plan;
  claim_sink(st, sink, plan);
  plan.iov[plan.iovlen++] = Plan::Seg{lend.body.data(), 0, lend.body.size()};
  plan.byte_total += lend.body.size();
  st.zc_split = true;
}

// RFC 9112 9.3: a file answer of its own status, in this connection's
// spelling - and with the page that status has.
//
// Every refusal wears its page, whatever served it. The graph has one
// 404, and a file that is not there is that 404: the same body a
// resource answering g7 with false would send. This used to take the
// bodyless status out of the shared store, so a docroot miss answered
// Content-Length: 0 while the same miss on a pack answered a page.
void Http1::file_prebuilt(Conn& st, uint16_t status_code) {
  const Variants& sv = variants(status_code);
  const Resp& bodyless = st.file->minor >= 1 ? (st.file->persist ? sv.plain : sv.close)
                                             : (st.file->persist ? sv.keep : sv.close);
  st.file->head.clear();
  if (status_code >= 400) {
    const Variants& pv = prefixes(status_code);
    const Resp& prefix = st.file->minor >= 1 ? (st.file->persist ? pv.plain : pv.close)
                                             : (st.file->persist ? pv.keep : pv.close);
    const ErrorPages::Fields f;
    spell_error({prefix, bodyless, status_code, st.file->err_media, f, st.file->head_only},
                st.file->head);
  } else {
    st.file->head = bodyless.bytes;
  }
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

// One answer for every refusal: a name that was never there, a directory, a
// "..", a symlink out of the docroot, a /proc magic-link. Same status, same
// bytes, same shape - so an attacker cannot tell a caught escape from a
// miss and probe the filesystem through the difference.
void Http1::file_reject(Conn& st) { file_prebuilt(st, 404); }

// RFC 9110 6.4: what the ring answered for one spill write. The octets
// are in the file now, or the write failed and the body can never be
// read.
//
// The body being whole on the wire is not the same as the body being
// whole in its file, and a run reads the file. So this is where a run
// that stopped for its body learns that it may go on.
void Http1::spill_wrote(Conn& st, ssize_t res, const std::string& out) {
  BodySpill* sp = nullptr;
  if (st.spill.in_flight) {
    sp = &st.spill;
  } else if (st.h2 != nullptr) {
    for (H2Stream& s : st.h2->streams) {
      if (s.spill.in_flight) {
        sp = &s.spill;
        break;
      }
    }
  }
  if (sp == nullptr) return;
  sp->wrote(res, out);
  // The body is whole on the wire and whole in the file now, so the run
  // that stopped for it may walk on.
  if (sp == &st.spill && sp->ended && sp->drained() && st.run_wants_body) {
    Conn::Round* const r = st.park_at(st.parked.co ? st.parked.co.promise().park : -1);
    if (r != nullptr) r->answer_ready = true;
  }
  if (mrb_unlikely(sp->failed)) {
    // The file cannot hold this body, so the request cannot be
    // answered from it. h1 ends the connection; an h2 stream ends on
    // its own below, through the round the reactor spells.
    if (sp == &st.spill) {
      st.body_to = Conn::Body::kNone;
      st.content_need = 0;
      st.run_wants_body = false;
    }
    return;
  }
}

// The server's own fault: named in the error log, never in the answer.
void Http1::file_error(Conn& st, const char* why) {
  log_internal_error(elog_, {{static_cast<const char*>(st.peer), st.peer_len},
                             st.file->request_target,
                             why,
                             500});
  // Once a window has gone out the answer is committed: the head named a
  // Content-Length this body can no longer reach, so a 500 spelled here
  // would land behind those bytes and the client would wait forever for the
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
    // A directory, a fifo, a device: not a representation, and saying which
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
  // One meaning: what one read may take. How long the mapping is has its
  // own answer, in file_map_len.
  *want = len < kResponseFileWindow ? len : kResponseFileWindow;
  return true;
}

// Where the ring reads the bytes. Only ever called with no read in flight.
char* Http1::file_buffer(Conn& st, size_t n) {
  if (st.file->buf.size() < n) st.file->buf.resize(n);
  return &st.file->buf[0];
}

// The whole file, mapped. No read happened and none will: the next round lends the
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

// The one place a transfer's state changes as a round goes out. Everything
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

// RFC 9110: one access line per request, with the bytes that really left.
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

// The bytes are in. `spell_next_round` is what puts head and body on the wire.
void Http1::file_ready_now(Conn& st, size_t n) {
  st.file->buf_filled = n;
  st.file->stage = FileStage::kDeliver;
}

// RFC 9112: the framer. phr on the wire bytes, the carry only when a head
// splits; RFC 9113 3.4 decides h2 on the first bytes; the flow decides
// every status.
// #80: Held's out-of-line half. It is out of line because phr_header is
// incomplete in webmachine.hpp on purpose - the framer's header does not
// belong in this tree's one contract - and a unique_ptr<T[]> needs T
// complete exactly where these are defined.
Http1::Held::Held() = default;
Http1::Held::~Held() = default;
Http1::Held::Held(Held&&) noexcept = default;
Http1::Held& Http1::Held::operator=(Held&&) noexcept = default;

void Http1::Held::hold(const char* head_at, size_t head_len, const ReqView& from) {
  head.assign(head_at, head_len);
  const ptrdiff_t delta = head.data() - head_at;

  vals = *from.values;
  http::rebase(vals, delta);

  nfields = from.field_count;
  if (nfields != 0) {
    fields = std::make_unique<struct phr_header[]>(nfields);
    const auto* src = static_cast<const struct phr_header*>(from.fields);
    for (size_t i = 0; i < nfields; i++) {
      fields[i] = src[i];
      if (fields[i].name != nullptr) fields[i].name += delta;
      if (fields[i].value != nullptr) fields[i].value += delta;
    }
  }
  vals.named = from.values->named;

  // RouteSpans: only the ones nbind/has_splat say are readable. Past
  // nbind the array is uninitialised by contract, and moving those would
  // be reading it.
  if (from.spans != nullptr) {
    spans = *from.spans;
    for (uint8_t i = 0; i < spans.nbind; i++) {
      if (spans.bind[i].p != nullptr) spans.bind[i].p += delta;
    }
    if (spans.has_splat && spans.splat.p != nullptr) spans.splat.p += delta;
  }

  rv = from;
  if (rv.request_target != nullptr) rv.request_target += delta;
  if (rv.method_token != nullptr) rv.method_token += delta;
  rv.values = &vals;
  rv.fields = fields.get();
  rv.spans = from.spans != nullptr ? &spans : nullptr;
  // The body too: it lies in the same buffer as the head, and the run
  // reads request.body after it resumes. A body in a file needs none of
  // this - rv = from carried its descriptor, and the file outlives every
  // buffer the kernel takes back.
  if (from.content != nullptr && from.content_len != 0) {
    content.assign(from.content, from.content_len);
    rv.content = content.data();
  } else {
    rv.content = from.content;
  }
  rv.content_len = from.content_len;

  // The check the member table cannot do for itself. kReqValueSpans is a
  // list, and a list can be short by one - and the member it is short by
  // is a pointer still aimed at a buffer the kernel already has back. So
  // look at ReqValues as words and refuse any that still lands in the
  // source: a forgotten member is found here, on the first parked run in
  // a debug build, instead of in production on the rarest path there is.
  //
  // The epoch fields are words too and are read the same way. A date in
  // seconds cannot collide with a stack or heap address, so they cost
  // nothing but the loop.
  if constexpr (kDebugBuild) {
    const uintptr_t lo = reinterpret_cast<uintptr_t>(head_at);
    const uintptr_t hi = lo + head_len;
    const unsigned char* raw = reinterpret_cast<const unsigned char*>(&vals);
    for (size_t i = 0; i + sizeof(uintptr_t) <= sizeof(vals); i += sizeof(uintptr_t)) {
      uintptr_t w = 0;
      std::memcpy(&w, raw + i, sizeof(w));
      if (w >= lo && w < hi) {
        std::fprintf(stderr,
                     "webmachine: #80 hold() left a ReqValues word at offset %zu pointing "
                     "into the buffer it was supposed to leave - add the member to "
                     "kReqValueSpans\n",
                     i);
        std::abort();
      }
    }
  }
}


// #80: the bound answer, out of feed_parse's loop body. It is a function
// because a run that parks has to return out of it and re-enter later,
// and an inline block inside a loop body cannot be re-entered. What the
// loop held is in the Round and the BoundAsk beside it.

// #80: what happens to a bound run's answer after the walk - the lend,
// the error asset, response.file, and the head a run spells for itself.
// It is its own function because two callers reach it: the straight one
// above, and the coroutine that a promising resource is run through.
// Both arrive here with the same three facts, and out carries them in.

// #80: what the walk is handed, built once. Both entries need it - the
// straight one, and the coroutine a promising resource runs through -
// and neither may build it differently from the other.
void Http1::bound_prepare(Round& r, const BoundAsk& ask, BoundPrep& prep) {
  Conn& st = r.st;
  const Bundle* const b = r.b;
  const char* const view = r.view;
  const size_t off = r.off - r.head_len;
  const size_t head_len = r.head_len;
  const char* const method = r.method;
  const size_t method_len = r.method_len;
  const char* const path = r.path;
  const size_t path_len = r.path_len;
  const bool head_only = r.head_only;
  const flow::ReqFacts& facts = r.facts;
  const http::ReqValues& vals = r.vals;
  const struct phr_header* const headers = static_cast<const struct phr_header*>(ask.fields);
  const size_t num_headers = ask.nfields;
  const RouteSpans& spans = ask.spans;
  Plan* const plan = ask.plan;
  ReqView& rv = prep.rv;
  rv.request_target = path;
  rv.request_target_len = path_len;
  rv.path_len = http::path_only(path, path_len);
  rv.method = facts.method;
  rv.method_token = method;
  rv.method_token_len = method_len;
  rv.table = ask.table;
  rv.route = ask.route;
  rv.spans = &spans;
  rv.fields = headers;
  rv.field_count = num_headers;
  rv.values = &vals;
  // RFC 9110 6.4: the view carries a body only where a node of this
  // resource can read one. A resource without those callbacks never
  // waited for the body, so what sits behind the head is a part of it -
  // and request.body must answer nothing rather than that part.
  // RFC 9112 7.1: a chunked body declares nothing, so what it holds is
  // what has arrived. The count is the length the flow is told about.
  const bool chunked = st.body_to == Conn::Body::kChunkMem ||
                       st.body_to == Conn::Body::kChunkFile || st.body_count != 0;
  rv.declared_len = chunked ? st.body_count : r.content_length;
  if ((r.content_length != 0 || chunked) && b->res->takes_body) {
    // #36: is the whole body here? The walk reads this at kN11, kO14
    // and kP3 and stops there while octets are still coming. Every node
    // above them decided on the head alone.
    rv.content_ready = chunked ? st.body_to == Conn::Body::kNone : st.content_need == 0;
    if (!rv.content_ready) {
      // Nothing is bound while octets are still coming. The walk stops
      // at the first node that reads content, and the resume binds the
      // whole body - a part of one is never handed to a callback.
    } else if (st.spill.fd >= 0) {
      // RFC 9110 6.4: this body is a file. request.body reads it from
      // offset 0, and spill_written is how far the octets go.
      rv.content_fd = st.spill.fd;
      rv.content_len = st.spill.written;
      st.spill.bound = true;
    } else if (chunked) {
      // The reader wrote it into the hold, chunk by chunk, and the
      // framing octets are not in it.
      rv.content = st.body_hold.empty() ? nullptr : st.body_hold.data();
      rv.content_len = st.body_hold.size();
    } else {
      rv.content = view + off + head_len;
      rv.content_len = r.content_length;
    }
  }
  prep.accept_gzip = !facts.has_accept_encoding ||
                http::gzip_acceptable(vals.accept_encoding, vals.accept_encoding_len);
  // A run may lend its body only where nothing downstream touches the
  // bytes anyway: HEAD sends none, gzip copies them, one connection
  // holds one lend, and an external segment fits through a plan only.
  const bool gz_now = prep.accept_gzip && b->gzip_ok && st.packetized;
  prep.zc_min = (zc_min_ != 0 && plan != nullptr && !st.zc_lent && !head_only && !gz_now)
                    ? zc_min_
                    : 0;
}

Http1::Took Http1::bound_finish(Round& r, const BoundAsk& ask, BoundOut& out) {
  Conn& st = r.st;
  const Bundle* const b = r.b;
  const bool head_only = r.head_only;
  const int minor = r.minor;
  const bool persist = r.persist;
  const http::ReqValues& vals = r.vals;
  Plan* const plan = ask.plan;
  std::string& sink = ask.sink;
  uint16_t status = out.status;
  bool have_body = out.have_body;
  bool answered = false;
  const char* lent = nullptr;
  size_t lent_len = 0;
  LentBody lent_body;
  if (mrb_unlikely(resource_body_lent(*b->res, lent_body))) {
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
  if (mrb_unlikely(b->res->run.asset != nullptr)) {
    const AssetEntry& ae = *b->res->run.asset;
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
      ask.body.clear();
      Assets::copy_wire(ae, {0, n}, ask.body);
    }
  }
  // response.file: the run named a file instead of spelling a body,
  // and opening one is disk work that does not belong in a reactor
  // step. Nothing is answered here - the framing this answer will need
  // is copied onto the connection, the reactor drives openat2/statx/
  // read through the ring, and `spell_next_round` puts the result on the wire. A
  // name this process already refused takes the same 404 the kernel's
  // own refusal takes, spelled right here since no ring trip is owed.
  {
    if (mrb_unlikely(answer_from_file(r, status, ask.rhdrs))) {
      ask.body.clear();
      // accept_gzip came in with `out` and stays there: the caller read
      // Accept-Encoding once, and a file answer does not change what the
      // client will take.
      out.status = status;
      out.have_body = false;
      out.answered = false;
      out.lent = nullptr;
      out.lent_len = 0;
      return Took::kOwed;
    }
  }
  // RFC 9110 6.3: field lines or a conneg no prebuilt head can hold -
  // this run spells its own. 500 stays on the exception path below.
  if (mrb_unlikely((!b->res->run.content_type.empty() || !ask.rhdrs.empty()) &&
                     status != 500)) {
    const bool bodyless = status == 204 || status == 304;
    if (bodyless || !have_body) {
      ask.body.clear();
      st.zc_release();
      lent = nullptr;
      lent_len = 0;
    }
    // helpers.rb encode_body: a `def self.to_html` renders at setup, so
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
        ask.body.assign(ep, elen);
        have_body = true;
        ctype = err_pages_.media_type(em);
      }
    }
    if (!bodyless && ctype.empty()) {
      if (!b->res->run.content_type.empty()) {
        ctype = http::with_charset(b->res->run.content_type);
      }
      else if (have_body || baked) ctype = b->konst.content_type;
    }
    const SpelledHead head = {
        status, date_, ctype, ask.rhdrs, minor, persist, bodyless,
        lent != nullptr ? lent_len : (baked ? b->konst.body.size() : ask.body.size())};
    spell_head(sink, head);
    if (!bodyless && !head_only) {
      if (lent != nullptr) lend_body(st, sink, {{lent, lent_len}, *plan});
      else sink.append(baked ? b->konst.body : ask.body);
    }
    have_body = false;
    answered = true;
  }


  out.status = status;
  out.have_body = have_body;
  out.answered = answered;
  out.lent = lent;
  out.lent_len = lent_len;
  return Took::kNextRequest;
}


// #80: the bound answer for a resource that declared a compute task, in a
// frame that can stop. The whole reason this is a coroutine and not a
// stage on the connection: at the stop, `view`, `method`, `path` and
// every span in ReqValues point into a provided buffer, and on_recv
// hands that buffer back to the kernel before anything could resume.
// The bytes have to be copied either way; a frame the compiler manages
// is the copy that cannot be short by one member.
//
// A resource that never says `compute` never reaches this. Its answer
// goes through answer_bound, straight, with no frame.
// The compute round, out of line and out of feed_parse: everything here
// happens only for a resource that said `compute`, and feed_parse is
// walked by every request that did not.
Http1::ComputeRound Http1::start_compute_round(Conn& st, const BoundStart& s, std::string* sink,
                                               Plan* plan, size_t& off) {
  st.parked = run_parkable(st, {RunStart::Proto::kH1, s}, sink, plan);
  // The bookkeeping is done here either way, because the bytes it moves
  // belong to the buffer the parse was handed, and a stopped run
  // outlives it. BoundStart::off is already past the head, which is
  // what the parse has to carry on from.
  off = s.off;
  // #36: a run that waits for the body is not stepping over it - the
  // octets are in the connection's hold and the run reads them when the
  // last one lands. BoundStart::off is already past what arrived.
  if (s.content_length != 0 && !st.run_wants_body) {
    const size_t avail = s.viewlen - off;
    const size_t skip = s.content_length < avail ? s.content_length : avail;
    off += skip;
    st.content_skip = s.content_length - skip;
  }
  if (!st.parked.done()) {
    // Stopped. What is left in the buffer waits in the carry: RFC 9112
    // 9.3.2 puts the answers out in the order the requests came, so
    // nothing behind it may speak first.
    const size_t rest = s.viewlen - off;
    if (s.in_place) st.carry.assign(s.view + off, rest);
    else st.carry.erase(0, off);
    return ComputeRound::kParked;
  }
  const bool alive = st.parked.co.promise().persist;
  st.parked.destroy();
  if (!alive) {
    st.carry.clear();
    st.content_skip = 0;
    return ComputeRound::kClosed;
  }
  return ComputeRound::kNext;
}

Http1::Run Http1::run_parkable(Conn& st, RunStart start, std::string* sink, Plan* plan) {
  const bool h1 = start.proto == RunStart::Proto::kH1;
  BoundStart s = start.h1;
  // h2 asks for its own bundle after the walk; h1 was handed one.
  const Bundle* const b = h1 ? s.b : nullptr;

  // The frame's own scratch. A parked run may share none of it with the
  // next request on this connection: that one would write over what this
  // one still owes.
  std::string body;
  std::string rhdrs;
  Held held;
  bool have_body = false;

  // RFC 9112 9.3: the request decided this, and the caller reads it off
  // the frame - whether that caller is the parse that started the run or
  // the round that resumed it.
  Run::promise_type& me = co_await Self{};
  me.persist = h1 ? s.persist : true;

  {
    BoundPrep prep;
    H2Produced hp;
    // h2 answers from copies: the dispatch buffers die with the round
    // that read them, and a parked run answers after that. No Values
    // either - the bytes went with them.
    // Did this run stop? A stopped one logs its own answer from the
    // tail, because the caller logged nothing for it.
    bool stopped = false;
    const H2Request hq = {start.h2.stream_id, start.h2.facts, nullptr,
                          nullptr,            start.h2.target, start.h2.route,
                          start.h2.head_only};
    uint16_t status = 0;
    if (h1) {
      Round r{st,          b,           s.view,      s.viewlen,    s.off,
              s.head_len,  s.in_place,  s.method,    s.method_len, s.path,
              s.path_len,  s.minor,     s.persist,   s.head_only,  s.content_length,
              s.lflags,    s.facts,     s.vals};
      const BoundAsk ask = {s.fields, s.nfields, s.spans, s.table, s.route,
                            plan,     *sink,     body,    rhdrs};
      bound_prepare(r, ask, prep);

      // can_park: this frame is the thing that can hold a stopped run, so
      // the walk may stop in it. What answers the stop is a worker, and
      // the crossing to one is complete.
      const RunAsk asked = {s.facts, &s.vals, &prep.rv, prep.zc_min, true};
      const RunAnswer answer = {&body, &have_body, &rhdrs};
      status = resource_run(*b->res, asked, answer);
    } else {
      hp.body = &body;
      hp.rhdrs = &rhdrs;
      h2_produce(st, hq, true, hp);
      status = hp.status;
      have_body = hp.have_body;
    }
    // Which resource ran, if one did. A konst h2 route runs none, and
    // then nothing here can stop.
    const Bundle* const rb = h1 ? b : hp.b;
    const Resource* const ran = (rb != nullptr && rb->bound) ? rb->res : nullptr;

    // #30: what this run waits on, in the frame that holds the run. The
    // connection only learns its address, under a park slot, because a
    // completion carries a number and not a pointer.
    Conn::Round mine_round;
    int park = -1;
    while (mrb_unlikely(ran != nullptr && run_stopped(*ran))) {
      const Resource& res = *ran;
      // The head, copied, and everything re-pointed at the copy. After
      // this the provided buffer may go back to the kernel.
      //
      // #30: h1 only. An h2 run started from copies - RunStart::H2Start
      // carries the facts and the target - because the dispatch buffers
      // die with the round that read them.
      if (h1) {
        held.hold(s.head_at, s.head_len, prep.rv);
        // The view the run bound (res.run.req is &prep.rv) reads the copy
        // from here on, not the buffer the kernel has back.
        prep.rv = held.rv;
        s.view = held.head.data();
        s.viewlen = held.head.size();
        s.off = held.head.size();
        s.method = held.rv.method_token;
        s.path = held.rv.request_target;
        s.fields = held.fields.get();
        s.nfields = held.nfields;
        s.spans = held.spans;
        s.vals = held.vals;
      }

      // The crossing, before the state travels: the block becomes an id
      // and the arguments become CBOR while both the VM and the run's
      // own state are still to hand. One line later res.run is gone
      // from the resource, and neither could be read again.
      if (park < 0) {
        park = st.park_take(&mine_round);
        me.park = park;
      }
      // #36: a run waiting for the body owes nothing to a worker and
      // nothing to the ring. The connection is already taking the
      // octets, and the last one makes this round ready - so there is
      // no crossing to make and no descriptor to arm.
      if (mrb_unlikely(res.run.wants_body)) {
        mine_round.wants_body = true;
        mine_round.jobs_owed = 0;
      } else {
      compute_task_hand_over(st, mine_round, park, res);
      // #30: the same moment for a watcher. It is a value of the
      // reactor's VM and it must reach the connection's hash before the
      // frame takes res.run away - a watcher nobody roots is collected
      // while its descriptor is still in the ring. A connection that can
      // hold no more says so, and the run is answered rather than left
      // waiting for a poll nobody armed.
      if (res.run.watch_count != 0 && !watch_hand_over(st, mine_round, park, res)) {
        mine_round.answer_value[0] = mrb_nil_value();
        mine_round.jobs_owed = 0;
        mine_round.answer_ready = true;
      }
      }

      // The walk's own state travels with the frame. res.run belongs to
      // the route, and the next request on it would write over this.
      //
      // #30: this frame holds everything about the run it left, and a
      // watcher block of that run needs it back for as long as it
      // speaks. So each watcher is told where it is - a pointer into
      // this frame, which outlives every wait it started, and one per
      // run rather than one per connection.
      Resource::RunState mine = std::move(res.run);
      res.run = Resource::RunState{};
      watch_run_is(st, mine_round, &mine);
      // #80: if this frame is destroyed while the run waits - the peer
      // left, Conn::reset ran - the roots run_settle took and the
      // answers the round already holds are given back here. On the
      // way back the guard is disarmed: res.run owns them again.
      struct ParkedRoots {
        const Resource* res;
        Resource::RunState* state;
        Conn::Round* round;
        ~ParkedRoots() {
          if (res == nullptr) return;
          resource_abandon(*res, *state);
          for (mrb_value& a : round->answer_value) {
            if (!mrb_nil_p(a)) mrb_gc_unregister(res->mrb, a);
            a = mrb_nil_value();
          }
          for (int i = 0; i < Conn::kJobSlots; i++) {
            if (round->user_have[i]) mrb_gc_unregister(res->mrb, round->user_value[i]);
            round->user_have[i] = false;
          }
        }
      } parked_roots{&res, &mine, &mine_round};

      Run::promise_type& pr = co_await Park{};
      parked_roots.res = nullptr;
      stopped = true;

      // Back, into a round that is not the one that left. Only the wire
      // is the resumer's: the sink to write into and the plan a lend
      // rides out on, because the ones this run started with were
      // locals of a parse that has returned.
      //
      // RFC 9112 9.3: `persist` is not the resumer's. Whether the
      // connection lives past this answer was decided by the request
      // itself - its version and its Connection field - before the run
      // began. It travels in this frame, and `spell_next_round` reads it back out of
      // the promise_type once the run is done.
      sink = pr.sink;
      plan = pr.plan;
      pr.persist = s.persist;
      // What the resource holds now is another request's leftovers, and
      // its userdata root would be lost under the move.
      resource_forget_userdata(res);
      res.run = std::move(mine);
      // Back in the resource. Nothing may point at this frame's copy
      // any more - a watcher that outlived its answer would lend a
      // state that has moved.
      watch_run_is(st, mine_round, nullptr);
      // Three refusals, and they must not be confused: a full pool is
      // load and passes, a deadline the author got wrong does not, and
      // a handle that died may come back.
      // A refused run does not walk on - there is no answer to walk to.
      const ComputeRefusal refused = compute_task_refusal(mine_round);
      if (mrb_unlikely(refused.status != 0)) {
        // Nothing the run said still holds: it never reached an answer.
        // A content type, a file name, an error asset - all of them
        // belong to a walk that was refused, and the finish would try
        // to serve them. The status and the Retry-After are the whole
        // answer. The roots the wait took are given back with it.
        resource_abandon(res, res.run);
        status = refused.status;
        have_body = false;
        body.clear();
        rhdrs.assign(refused.retry_after);
      } else if (mrb_unlikely(mine_round.wants_body)) {
        // #36: the body is whole. Nothing answered for this run - it
        // waited on octets, not on a worker - so the round carries no
        // job and the walk runs the node itself, with the content in
        // reach. `content_seen` is already set, so it does not stop on
        // that node a second time.
        //
        // res.run.req points at prep.rv, which the hold re-pointed at
        // the copied head. So the body binds here, in the frame that
        // outlives the parse.
        if (st.spill.fd >= 0) {
          prep.rv.content_fd = st.spill.fd;
          prep.rv.content_len = st.spill.written;
          st.spill.bound = true;
        } else {
          prep.rv.content = st.body_hold.empty() ? nullptr : st.body_hold.data();
          prep.rv.content_len = st.body_hold.size();
        }
        prep.rv.content_ready = true;
        res.run.wants_body = false;
        mine_round.wants_body = false;
        st.run_wants_body = false;
        status = resource_resume(res, {&body, &have_body, &rhdrs},
                                 {mine_round.answer_value, mine_round.job_what,
                                  mine_round.user_value, mine_round.user_have, 0});
      } else {
        // #30: the whole round, in the order the stop handed it over.
        // A watcher and a single task are one entry of it.
        const uint8_t owed = mine_round.jobs_owed != 0 ? mine_round.jobs_owed : 1;
        status = resource_resume(res, {&body, &have_body, &rhdrs},
                                 {mine_round.answer_value, mine_round.job_what,
                                  mine_round.user_value, mine_round.user_have, owed});
      }
      // The answers were rooted while they waited - nothing on the VM's
      // stack named them. The round is read, so they are let go.
      for (mrb_value& a : mine_round.answer_value) {
        if (!mrb_nil_p(a)) {
          mrb_gc_unregister(res.mrb, a);
          a = mrb_nil_value();
        }
      }
      for (int i = 0; i < Conn::kJobSlots; i++) {
        if (!mine_round.user_have[i]) continue;
        mrb_gc_unregister(res.mrb, mine_round.user_value[i]);
        mine_round.user_value[i] = mrb_nil_value();
        mine_round.user_have[i] = false;
      }
    }

    // The run is done stopping. The slot goes back, and nothing in the
    // table names this frame any more.
    if (park >= 0) {
      st.park_drop(park);
      me.park = -1;
    }

    // #30: the h2 tail. The walk is over, so what it left can be read
    // now, and the frames go out through the same framer the straight
    // path uses.
    if (!h1) {
      // What the resumed walk answered is in this frame's locals, not in
      // what the walk said before it stopped.
      hp.have_body = have_body;
      // RFC 9113 5.1: the peer reset the stream while the run was
      // parked. Its entry is gone, and the answer goes to nobody.
      H2Stream* const entry = st.h2->find(hq.stream_id);
      if (stopped && entry == nullptr) co_return 1;
      if (entry != nullptr) entry->parked = false;
      h2_after_run(st, hq, hp, status);
      const bool sent = h2_frame(st, hq, *sink, hp);
      if (stopped) h2_log(st, {hq.facts, hq.target});
      co_return sent ? 1 : 0;
    }

    Round fr{st,          b,           s.view,      s.viewlen,    s.off,
             s.head_len,  s.in_place,  s.method,    s.method_len, s.path,
             s.path_len,  s.minor,     s.persist,   s.head_only,  s.content_length,
             s.lflags,    s.facts,     s.vals};
    const BoundAsk fask = {s.fields, s.nfields, s.spans, s.table, s.route,
                           plan,     *sink,     body,    rhdrs};
    BoundOut out;
    out.status = status;
    out.have_body = have_body;
    out.accept_gzip = prep.accept_gzip;
    if (mrb_unlikely(bound_finish(fr, fask, out) == Took::kOwed)) {
      // response.file: the reactor fetches it and spell_next_round puts
      // it on the wire. Nothing is spelled here.
      co_return 0;
    }
    const AnswerStep astep = spell_answer(
        fr, {*sink, plan, out.status, out.lent, out.lent_len, out.answered, out.have_body,
             out.accept_gzip, &b->index, body});
    // The access line is written here and not by the caller: a stopped
    // run answers long after the caller returned, and the line belongs
    // to the answer, not to the parse that started it.
    if (alog_.enabled) {
      log_access(alog_, {{static_cast<const char*>(st.peer), st.peer_len},
                         {s.method, s.method_len},
                         {s.path, s.path_len},
                         {s.vals.log_ref, s.vals.log_ref_len},
                         {s.vals.log_ua, s.vals.log_ua_len},
                         (astep.answered && !s.head_only) ? astep.body_len : 0,
                         out.status,
                         s.lflags});
    }
    // RFC 9112 9.3: the caller reads this out of the compute task, whether it
    // is the parse that started the run or the round that resumed it.
    co_return out.status;
  }
}

Http1::Took Http1::answer_bound(Round& r, const BoundAsk& ask, BoundOut& out) {
  // What this function reads. Spelling the answer belongs to
  // bound_finish and spell_answer.
  const Bundle* const b = r.b;
  const flow::ReqFacts& facts = r.facts;
  const http::ReqValues& vals = r.vals;
  uint16_t status = 0;
  bool have_body = false;
  bool accept_gzip = false;
  BoundPrep prep;
  bound_prepare(r, ask, prep);
  ReqView& rv = prep.rv;
  const size_t zc_min = prep.zc_min;
  accept_gzip = prep.accept_gzip;
  const RunAsk asked = {facts, &vals, &rv, zc_min};
  const RunAnswer answer = {&ask.body, &have_body, &ask.rhdrs};
  status = resource_run(*b->res, asked, answer);
  out.status = status;
  out.have_body = have_body;
  out.accept_gzip = accept_gzip;
  return bound_finish(r, ask, out);
}

// RFC 9113 3.4: the first bytes of a fresh connection decide the
// protocol. The preface is matched across receives; a connection that
// sent enough of it to be h2 and then diverged is refused with GOAWAY.
Http1::Preface Http1::h1_preface(Conn& st, const char* data, size_t len, std::string& sink,
                                 size_t* consumed) {
  st.content_need = 0;
  const size_t seen = st.carry.size();
  size_t i = 0;
  while (i < len && seen + i < kH2PrefaceLen && data[i] == kH2Preface[seen + i]) i++;
  if (seen + i == kH2PrefaceLen) {
    st.fresh = false;
    st.carry.clear();
    if (!h2_begin(st, sink)) return Preface::kRefused;
    *consumed = i;
    return Preface::kH2;
  }
  if (i == len) {
    st.carry.append(data, len);
    return Preface::kWait;
  }
  if (seen + i >= kH2PrefaceAnnounce) {
    static const unsigned char kGoaway[kH2FrameHeaderLen + 8] = {
        0, 0, 8, kH2Goaway, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, kH2ProtocolError};
    sink.append(reinterpret_cast<const char*>(kGoaway), sizeof(kGoaway));
    return Preface::kRefused;
  }
  st.fresh = false;
  return Preface::kH1;
}

// RFC 6455 4.2 and WHATWG HTML: a head that upgrades to a WebSocket, or
// names an event-stream route, leaves the request path here. Returns
// whether it was taken; `lives` then says whether the connection goes
// on. A head that is neither falls back to the tables.
bool Http1::h1_upgrade_or_stream(Conn& st, const H1Head& h, std::string& sink, bool* lives) {
  if (mrb_unlikely(h.wants_ws)) {
    const AppSlot& wslot = apps_[st.listener];
    RouteSpans wspans;
    const int wr = wslot.ws_table != nullptr
                       ? wslot.ws_table->match(h.path.data(), h.path.size(), wspans)
                       : -1;
    if (wr >= 0) {
      if (h.ws_version != 13) {
        sink.append("HTTP/1.1 426 Upgrade Required\r\nDate: ");
        sink.append(date_, http::kDateLen);
        sink.append(
            "\r\nSec-WebSocket-Version: 13\r\nConnection: close\r\n"
            "Content-Length: 0\r\n\r\n");
        *lives = false;
        return true;
      }
      if (h.facts.method != flow::Method::kGet || h.ws_key == nullptr) {
        *lives = fail(st, 400, sink, h.lflags);
        return true;
      }
      const WsUpgrade up{wslot,  wr,   h.path,
                         wspans, {h.ws_key, h.ws_key_len},
                         h.headers, h.num_headers, h.vals, {h.rest, h.rest_len}};
      *lives = ws_upgrade(st, up, sink);
      return true;
    }
  }
  if (mrb_unlikely(apps_[st.listener].sse_table != nullptr)) {
    const AppSlot& sslot = apps_[st.listener];
    RouteSpans sspans;
    const int sr = sslot.sse_table->match(h.path.data(), h.path.size(), sspans);
    if (sr >= 0) {
      const SseBegin req{sslot,   sr,          h.method,
                         h.path,  sspans,      h.headers,
                         h.num_headers, h.minor, h.facts.method, h.vals, h.lflags};
      *lives = sse_begin(st, req, sink);
      return true;
    }
  }
  return false;
}

bool Http1::feed_parse(Conn& st, std::string_view in, Sink out) {
  const char* data = in.data();
  size_t len = in.size();
  std::string& sink = out.bytes;
  Plan* const plan = out.plan;
  if (st.h2 != nullptr) return h2_feed(st, in, out);
  if (st.fresh) {
    size_t consumed = 0;
    switch (h1_preface(st, data, len, sink, &consumed)) {
      case Preface::kH2: return h2_feed(st, {data + consumed, len - consumed}, out);
      case Preface::kWait: return true;
      case Preface::kRefused: return false;
      case Preface::kH1: break;
    }
  }
  // The state and the pointers must say the same thing, and the parts
  // must stand to one another the way Conn::invariant_broken says. This
  // is the top of the feed on purpose: the paths below return as soon
  // as they have taken their octets, so a check under them would never
  // see a connection with a body in flight. The debug build is what
  // every test in this tree runs, so a drift fails the suite instead of
  // answering a request from a state nobody declared.
  if (kDebugBuild) {
    if (mrb_unlikely(!st.mode_agrees())) {
      std::fprintf(stderr, "webmachine: a connection says it is %s, and its pointers do not\n",
                   conn_mode_name(st.mode));
      std::abort();
    }
    if (const char* const broken = st.invariant_broken(); mrb_unlikely(broken != nullptr)) {
      std::fprintf(stderr, "webmachine: a connection that is %s broke a rule: %s\n",
                   conn_mode_name(st.mode), broken);
      std::abort();
    }
  }

  if (st.content_skip != 0) {
    const size_t take = st.content_skip < len ? st.content_skip : len;
    st.content_skip -= take;
    data += take;
    len -= take;
    if (len == 0) return true;
  }

  // RFC 9110 6.4: the octets of a body a run is waiting for. The run
  // already walked the head and stopped at kN11, kO14 or kP3; these go
  // where the head decided, and the last one makes its round ready.
  // Nothing behind them is parsed until content_need is paid off.
  //
  // One switch, and it is the question this function had to ask anyway:
  // are these octets a body or the head of a request. The two body arms
  // name a writer, and each writer's code holds no test about where the
  // octets go, because the head answered that before they arrived.
  // RFC 9110 8.3: the octets against the claim the head made. The first
  // 512 of them are kept aside - the body itself may be on its way to a
  // file - and the table reads them once. A contradiction is 415 at the
  // first buffer, so a half gigabyte behind a lie never arrives.
  if (mrb_unlikely(!st.sniff_type.empty() && !st.sniff_done && len != 0)) {
    const size_t want = sniff::bytes_wanted();
    if (st.sniff_head.size() < want) {
      const size_t room = want - st.sniff_head.size();
      st.sniff_head.append(data, len < room ? len : room);
    }
    const sniff::Verdict v = sniff::check(st.sniff_type, st.sniff_head);
    if (mrb_unlikely(v == sniff::Verdict::kContradicts)) {
      st.body_to = Conn::Body::kNone;
      st.content_need = 0;
      st.body_hold.clear();
      st.spill.close_file();
      st.run_wants_body = false;
      return fail(st, 415, sink);
    }
    if (v == sniff::Verdict::kAgrees || st.sniff_head.size() >= want) st.sniff_done = true;
  }

  BodyTake took = BodyTake::kNone;
  switch (st.body_to) {
    case Conn::Body::kNone: break;
    case Conn::Body::kMem: took = take_body(st, MemWriter{&st.body_hold}, data, len); break;
    case Conn::Body::kFile: took = take_body(st, FileWriter{&st.spill}, data, len); break;
    // RFC 9112 7.1: the same two writers, behind a reader that has to
    // find the octets first.
    case Conn::Body::kChunkMem:
      took = take_chunked(st, MemWriter{&st.body_hold}, data, len);
      break;
    case Conn::Body::kChunkFile:
      took = take_chunked(st, FileWriter{&st.spill}, data, len);
      break;
  }
  switch (took) {
    case BodyTake::kNone: break;
    case BodyTake::kFailed: return false;
    case BodyTake::kMore: return true;
    case BodyTake::kWhole:
      // RFC 9110 6.4: whole on the wire is not whole in the file. The
      // run reads the file, so the last write has to land first. The
      // reactor makes the round ready when it does - see spill_wrote.
      if (st.spill.fd >= 0) {
        st.spill.ended = true;
        if (!st.spill.drained()) break;
      }
      // #36: the body is whole. The run stopped on it owes nothing to a
      // worker, so this is what answers it: the round is ready, and
      // spell_next_round resumes the walk at the node it stopped on.
      if (mrb_unlikely(st.run_wants_body)) {
        Conn::Round* const r = st.park_at(st.parked.co ? st.parked.co.promise().park : -1);
        if (r != nullptr) r->answer_ready = true;
        // No return: what came behind the last octet is a pipelined
        // request, and the guard below puts it in the carry. RFC 9112
        // 9.3.2 answers in the order the requests came, so it may not
        // be parsed while this run is still stopped.
      }
      break;
  }

  if (mrb_unlikely(st.asset != nullptr)) {
    if (mrb_unlikely(st.carry.size() + len > kMaxHead)) {
      st.carry.clear();
      st.content_skip = 0;
      st.asset = nullptr;
      st.become(ConnMode::kHead);
      return false;
    }
    st.carry.append(data, len);
    return true;
  }

  if (mrb_unlikely(st.ws != nullptr)) return ws_feed(st.ws, in, sink);
  if (mrb_unlikely(st.sse != nullptr)) return true;

  // RFC 9112 9.3.2: a run that parked, or a file the ring still owes,
  // is the next answer on this connection. A request that arrives
  // behind it in a receive of its own waits in the carry, and the
  // round that spells that answer feeds the carry.
  if (mrb_unlikely(st.run_parked() ||
                   (st.file != nullptr && st.file->stage != FileStage::kNone))) {
    if (mrb_unlikely(st.carry.size() + len > kMaxHead)) return fail(st, 431, sink);
    st.carry.append(data, len);
    return true;
  }

  const bool in_place = st.carry.empty();
  const char* view = data;
  size_t viewlen = len;
  if (mrb_unlikely(!in_place)) {
    size_t grown = 0;
    if (mrb_unlikely(__builtin_add_overflow(st.carry.size(), len, &grown))) {
      return fail(st, 431, sink);
    }
    st.carry.append(data, len);
    view = st.carry.data();
    viewlen = st.carry.size();
  }

  size_t off = 0;
  while (off < viewlen) {
    // RFC 9110 6.4: the body file of the request that just finished goes
    // back here. This connection answers one request at a time - a run
    // that parks stops this loop until it is resumed - so a new head at
    // the top of the loop says the last body has been read for the last
    // time.
    //
    // Only a file a round already took: an unbound one is this request's
    // body still arriving, and the loop runs again for it once the last
    // octet lands.
    if (mrb_unlikely(st.spill.bound)) st.spill.close_file();
    const char* method;
    size_t method_len;
    const char* path;
    size_t path_len;
    int minor;
    struct phr_header headers[kMaxHeaders];
    size_t num_headers = kMaxHeaders;
    const int ret = phr_parse_request(view + off, viewlen - off, &method, &method_len, &path,
                                      &path_len, &minor, headers, &num_headers, 0);
    if (mrb_unlikely(ret == -2)) {
      const size_t rest = viewlen - off;
      if (mrb_unlikely(rest > kMaxHead)) return fail(st, 431, sink);
      if (in_place) st.carry.assign(view + off, rest);
      else st.carry.erase(0, off);
      return true;
    }
    if (mrb_unlikely(ret <= 0)) return fail(st, 400, sink);
    if (mrb_unlikely(static_cast<size_t>(ret) > kMaxHead)) return fail(st, 431, sink);

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
    if (mrb_unlikely(w.err != 0)) return fail(st, w.err, sink, lflags);
    // RFC 9112 6.1: a request that names both framings is a smuggling
    // attempt, and a coding this server cannot read is 501. Chunked
    // alone is read: the octets arrive without a length and the count
    // is what holds them to a limit.
    if (mrb_unlikely(w.have_te)) {
      if (mrb_unlikely(w.have_cl)) return fail(st, 400, sink, lflags);
      if (mrb_unlikely(!w.te_chunked)) return fail(st, 501, sink, lflags);
    }
    if (mrb_unlikely(minor >= 1 && !w.have_host)) return fail(st, 400, sink, lflags);
    bool persist = minor >= 1 ? !w.conn_close : w.conn_keep;
    const bool head_only = facts.method == flow::Method::kHead;
    // RFC 9112 6.6: this connection ends when the request carries
    // content that no node will read. The answer has to say so, and the
    // head is spelled from `persist`, so the decision belongs here -
    // ahead of every tier that can answer.
    //
    // Only a request with content pays for the extra match, and the
    // match is pure: the route table answers the same both times.
    bool body_read = w.content_length == 0 && !w.have_te;
    // The application's number, until the route names a nearer one.
    size_t limit = apps_[st.listener].max_body;
    // RFC 9112 7.1: what the chunked reader took out of this buffer,
    // framing and all. The cursor steps over it after the answer.
    size_t chunk_used = 0;
    if (mrb_unlikely(!body_read)) {
      // Only a request that carries content pays for this second
      // match, and the route table is pure: it answers the same both
      // times. Measured: out of line it cost 16 bytes more here and
      // another 515 of its own, so it stays where it is read.
      const AppSlot& probe_slot = apps_[st.listener];
      RouteSpans probe_spans;
      const int probe = probe_slot.table->match(path, path_len, probe_spans);
      if (probe >= 0) {
        const Bundle& pb = bundles_[probe_slot.base + static_cast<size_t>(probe)];
        body_read = pb.bound && pb.res->takes_body;
        // RFC 9110 15.5.14: the nearest limit answers. This route's
        // resource holds one when it said `def self.max_body`, and the
        // application's number answers for every route that did not.
        if (pb.bound && pb.res->max_body >= 0) {
          limit = static_cast<size_t>(pb.res->max_body);
        }
      }
      if (!body_read) persist = false;
    }
    // RFC 9110 15.5.14: a declared length above the limit is 413, and
    // no octet of the body is read. The check waits for the route
    // probe above, because the route is what can name a nearer limit.
    if (mrb_unlikely(w.content_length > limit)) {
      return fail(st, 413, sink, lflags);
    }
    // A chunked body declares nothing, so the limit has to travel with
    // the connection: the reader holds the count against it, buffer by
    // buffer.
    st.body_limit = limit;

    if (mrb_unlikely((w.up_ws && w.conn_upgrade) || apps_[st.listener].sse_table != nullptr)) {
      const H1Head head = {{method, method_len}, {path, path_len}, minor,   headers,
                           num_headers,          facts,            vals,    lflags,
                           w.up_ws && w.conn_upgrade, w.ws_version, w.ws_key, w.ws_key_len,
                           view + off + static_cast<size_t>(ret),
                           viewlen - off - static_cast<size_t>(ret)};
      bool lives = true;
      if (h1_upgrade_or_stream(st, head, sink, &lives)) return lives;
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
      if (mrb_unlikely(took != Took::kNo)) {
        off = r.off;
        if (took == Took::kClose) return false;
        if (took == Took::kOwed) return true;
        continue;
      }
      // The standalone tier: a docroot answers what the pack does not,
      // and there is no route table behind it to fall through to.
      if (mime_ != nullptr) {
        const Took from_disk = answer_from_docroot(r);
        if (from_disk != Took::kNo) {
          off = r.off;
          return from_disk != Took::kClose;
        }
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
    if (mrb_unlikely(route < 0)) {
      status = 404;
    } else {
      b = &bundles_[slot.base + static_cast<size_t>(route)];
      idx = &b->index;
      if (mrb_likely(b->bound)) {
        const size_t head_len = static_cast<size_t>(ret);
        const size_t body_here = viewlen - off - head_len;
        // What is already in hand: the octets behind the head, or - once
        // this body went to a file - what reached the file. The second
        // re-parse of a spilled request finds an empty carry behind the
        // head, and the body is complete all the same.
        const size_t body_have = st.spill.fd >= 0 ? st.spill.written : body_here;
        // RFC 9110 6.4: only three callbacks read a request body -
        // content_types_accepted, create_path and process_post. A
        // resource that declares none of them has no node that can ask
        // for one, so this connection waits for nothing and keeps
        // nothing: the octets are stepped over below.
        //
        // Before this, every bound route held the whole upload while
        // the flow walked, and a body of kBodySpill or more went to a
        // file first. A route that never reads a body could be made to
        // do both.
        // RFC 9110 8.3: this route asked for the octets of some types to
        // be checked against the claim. The claim is here, at the head;
        // the octets arrive after it. So the type is kept and the check
        // runs on the first buffer, in sniff_body below.
        if (mrb_unlikely(!b->res->sniff_types.empty()) && vals.content_type != nullptr) {
          const std::string_view claim{vals.content_type, vals.content_type_len};
          if (sniff::wants(b->res->sniff_types, claim)) {
            st.sniff_type.assign(claim);
            st.sniff_head.clear();
            st.sniff_done = false;
            // The first octets of a body usually arrive in the buffer
            // that carried the head, and those never pass the feed's
            // body switch. So the check starts here, on them.
            const size_t want = sniff::bytes_wanted();
            st.sniff_head.assign(view + off + head_len, body_here < want ? body_here : want);
            const sniff::Verdict v = sniff::check(st.sniff_type, st.sniff_head);
            if (mrb_unlikely(v == sniff::Verdict::kContradicts)) {
              return fail(st, 415, sink, lflags);
            }
            if (v == sniff::Verdict::kAgrees || st.sniff_head.size() >= want) {
              st.sniff_done = true;
            }
          }
        }
        // RFC 9112 7.1: a chunked body has no length to compare, so the
        // reader starts here and the octets behind the head are its
        // first buffer. It begins in memory and moves to a file when
        // the count says so - the head cannot know which it will be.
        if (mrb_unlikely(w.have_te) && mrb_likely(b->res->takes_body)) {
          st.chunk = {};
          // RFC 9112 7.1.2: the decoder reads the trailer section and
          // drops it. No node of this server reads a trailer field.
          st.chunk.consume_trailer = 1;
          st.body_count = 0;
          st.body_hold.clear();
          st.body_to = Conn::Body::kChunkMem;
          st.run_wants_body = true;
          const char* cp = view + off + head_len;
          size_t clen = body_here;
          const BodyTake got = take_chunked(st, MemWriter{&st.body_hold}, cp, clen);
          chunk_used = body_here - clen;
          if (mrb_unlikely(got == BodyTake::kFailed)) {
            st.body_to = Conn::Body::kNone;
            st.body_hold.clear();
            st.spill.close_file();
            return fail(st, 400, sink, lflags);
          }
          // What the reader did not read is a pipelined request, and it
          // waits behind a run that has not answered yet.
          st.run_wants_body = got != BodyTake::kWhole;
        } else if (w.content_length != 0 && body_have < w.content_length &&
            mrb_likely(b->res->takes_body)) {
          st.content_need = w.content_length - body_have;
          // RFC 9110 6.4: a large body goes to a file, so the connection
          // holds the head and not the upload. The length is declared -
          // this server refuses a chunked request body - so the choice
          // is made once, here, and never part way through.
          if (w.content_length >= kBodySpill) {
            if (mrb_unlikely(!st.spill.open_file())) return fail(st, 500, sink, lflags);
            if (mrb_unlikely(!st.spill.take(view + off + head_len, body_here))) {
              st.spill.close_file();
              return fail(st, 500, sink, lflags);
            }
            st.body_to = Conn::Body::kFile;
          } else {
            // #36: a body under kBodySpill waits in body_hold. It cannot
            // stay behind the head in the carry: the run is about to
            // read that head, and the carry is where a pipelined
            // request waits.
            //
            // The declared length is the whole size, so the buffer is
            // taken once and never grows again.
            st.body_hold.reserve(w.content_length);
            st.body_hold.assign(view + off + head_len, body_here);
            st.body_to = Conn::Body::kMem;
          }
          // #36: the walk starts now, on the head. It stops at kN11,
          // kO14 or kP3 - the three nodes that read content - and the
          // last octet of the body makes its round ready again.
          //
          // Before this the head waited in the carry until the whole
          // body had arrived, so is_authorized? and forbidden? were
          // asked after the upload rather than before it.
          st.run_wants_body = true;
        }
        // #80: a resource that declared a compute task is answered inside a
        // frame that can stop. The frame spells the whole answer,
        // including the access line, so nothing below is owed for it.
        // Measured, not chosen: giving this frame to every bound resource
        // breaks response.file - thirteen bintests, all of them a file
        // the run owes and the frame finishes differently. So the gate
        // stays what a resource declared, and a watcher needs a
        // declaration of its own before it can reach this path.
        // #30: a value round stops the run as much as a node does, and
        // a resource may declare only values.
        // #36: a run that waits for the body stops as much as a compute
        // task does, so it needs the same frame. Its BoundStart::off is
        // past the octets that already arrived - they are in the hold,
        // and nothing steps over them.
        if (mrb_unlikely(b->res->compute != 0 || b->res->watch != 0 ||
                           b->res->value_jobs != 0 || b->res->value_watch != 0 ||
                           st.run_wants_body)) {
          const size_t past = head_len + (st.run_wants_body ? body_here : chunk_used);
          const BoundStart start = {b,        view + off, view,       viewlen,
                                    off + past,           head_len,   method,
                                    method_len,           path,       path_len,
                                    w.content_length,     headers,    num_headers,
                                    spans,    slot.table, facts,      vals,
                                    route,    minor,      lflags,     in_place,
                                    persist,  head_only};
          const ComputeRound r = start_compute_round(st, start, &sink, plan, off);
          if (mrb_unlikely(r == ComputeRound::kParked)) return true;
          if (mrb_unlikely(r == ComputeRound::kClosed)) return false;
          continue;
        }
        Round br{st,   b,        view,      viewlen,  off + head_len,
                 head_len, in_place, method,   method_len,
                 path, path_len, minor,     persist,  head_only,
                 w.content_length, lflags,   facts,    vals};
        BoundOut bo;
        // body_ and rhdrs_ are this writer's own scratch, reused request
        // after request. The straight path hands them in; a parked run
        // will hand in a pair of its own.
        const BoundAsk basked = {headers, num_headers, spans,  slot.table,
                                 route,   plan,        sink,   body_,
                                 rhdrs_};
        if (mrb_unlikely(answer_bound(br, basked, bo) == Took::kOwed)) {
          have_body = false;
          return true;
        }
        status = bo.status;
        have_body = bo.have_body;
        answered = bo.answered;
        lent = bo.lent;
        lent_len = bo.lent_len;
        accept_gzip = bo.accept_gzip;
      } else {
        // RFC 9110 12.5.1: c4 belongs to the client. The fold left this
        // resource with exactly one media type (two would have bound it), so
        // the question is one match, asked here in C++ and never in the VM.
        if (mrb_unlikely(facts.has_accept && vals.accept != nullptr)) {
          if (http::accept_is_exact({vals.accept, vals.accept_len}, b->accept_type)) {
            // Asked and answered: this Accept names the one type offered,
            // so c3/c4 have nothing left to decide and the request is as
            // plain as one that never negotiated.
            facts.has_accept = false;
          } else {
            facts.plain = false;
            facts.accept_ok =
                http::choose_media_type({{&b->accept_type, 1}, {vals.accept, vals.accept_len}}) >= 0;
          }
        }
        const size_t mi = static_cast<size_t>(facts.method);
        status = flow::answer(facts, {b->konst.per_method[mi], b->konst.shortcut[mi]});
      }
    }

    Round ar{st,   b,        view,      viewlen,  off + static_cast<size_t>(ret),
             static_cast<size_t>(ret), in_place, method,   method_len,
             path, path_len, minor,     persist,  head_only,
             w.content_length, lflags,   facts,    vals};
    const AnswerStep astep = spell_answer(
        ar, {sink, plan, status, lent, lent_len, answered, have_body, accept_gzip, idx,
             body_});
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
    // RFC 9112 6.6: this request carried content and no node of the flow
    // asked for it. A route that does not exist, a method that is not
    // allowed, a resource that declares none of the three callbacks that
    // read a body - each answers before any node wants content.
    //
    // The answer is already in the sink and goes out. The connection
    // ends behind it, because reading the rest to stay alive would read
    // exactly what the flow refused. RFC 9110 9.3.1 names the risk:
    // content behind a request nobody parsed is where request smuggling
    // lives. A GET carries none of it - RFC 10008 QUERY is the method
    // for a safe request that needs content.
    if (mrb_unlikely(!body_read)) {
      st.carry.clear();
      st.content_skip = 0;
      st.content_need = 0;
      return false;
    }
    // RFC 9110 6.4: step over the body this round did not read. A body
    // that went to a file is already off the wire and out of the buffer,
    // so there is nothing here to step over - counting it again would
    // make the next request's head look like this request's body.
    if (w.content_length != 0 && st.spill.fd < 0) {
      const size_t avail = viewlen - off;
      const size_t skip = w.content_length < avail ? w.content_length : avail;
      off += skip;
      st.content_skip = w.content_length - skip;
    }
    // RFC 9112 7.1: the chunked reader took its own octets out of this
    // buffer, framing and all, so the cursor steps over exactly what it
    // read and the next head starts where the body ended.
    off += chunk_used;
    if (mrb_unlikely(!persist)) {
      st.carry.clear();
      st.content_skip = 0;
      return false;
    }
  }
  if (mrb_unlikely(!in_place)) st.carry.clear();
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
  rv.tls = apps_[st.listener].tls;
  rv.request_target = path.data();
  rv.request_target_len = path.size();
  rv.path_len = http::path_only(path.data(), path.size());
  rv.method = flow::Method::kGet;
  rv.table = slot.ws_table;
  rv.route = route;
  rv.spans = &spans;
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
  st.become(ConnMode::kWs);
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
  if (mrb_unlikely(m != flow::Method::kGet)) {
    log_sse(alog_, st, {method, path, vals, 405, lflags});
    sink.append("HTTP/1.1 405 Method Not Allowed\r\nDate: ");
    sink.append(date_, http::kDateLen);
    sink.append("\r\nAllow: GET\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    return false;
  }
  if (mrb_unlikely(minor < 1)) {
    log_sse(alog_, st, {method, path, vals, 505, lflags});
    sink.append("HTTP/1.1 505 HTTP Version Not Supported\r\nDate: ");
    sink.append(date_, http::kDateLen);
    sink.append("\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    return false;
  }

  ReqView rv;
  rv.tls = apps_[st.listener].tls;
  rv.request_target = path.data();
  rv.request_target_len = path.size();
  rv.path_len = http::path_only(path.data(), path.size());
  rv.method = flow::Method::kGet;
  rv.table = slot.sse_table;
  rv.route = route;
  rv.spans = &spans;
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
  st.become(ConnMode::kSse);
  st.carry.clear();
  st.content_skip = 0;
  return true;
}
}
