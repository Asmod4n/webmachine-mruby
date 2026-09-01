// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <picohttpparser.h>

#include <cstring>

namespace webmachine {
namespace {
constexpr size_t kH2MaxFields = kMaxHeaders + 8;
constexpr size_t kH2FragBudget = kMaxHead * 2;
constexpr size_t kH2MergeBody = 1024;

// RFC 9113 8.2.1: a field name carrying an uppercase letter is malformed.
// Eight bytes a word. Clearing every high bit first and re-setting it as
// a guard bit keeps each byte's subtraction inside its own lane, so no
// borrow can travel between bytes and forge (or hide) a letter; the last
// term drops bytes >= 0x80, whose low seven bits could otherwise spell
// one.
bool h2_has_upper(const char* s, size_t n) {
  constexpr uint64_t kOnes = 0x0101010101010101ULL;
  constexpr uint64_t kHigh = 0x8080808080808080ULL;
  size_t i = 0;
  for (; i + 8 <= n; i += 8) {
    uint64_t w;
    std::memcpy(&w, s + i, sizeof(w));
    const uint64_t g = (w & ~kHigh) | kHigh;
    const uint64_t ge_a = (g - kOnes * 'A') & kHigh;
    const uint64_t ge_z1 = (g - kOnes * ('Z' + 1)) & kHigh;
    if ((ge_a & ~ge_z1 & ~w & kHigh) != 0) return true;
  }
  for (; i < n; i++) {
    const unsigned c = static_cast<unsigned char>(s[i]);
    if (c - 'A' < 26u) return true;
  }
  return false;
}

// RFC 9113 4.1: a 32-bit field, network order.
void put_u32(unsigned char* p, uint32_t v) {
  p[0] = static_cast<unsigned char>(v >> 24);
  p[1] = static_cast<unsigned char>(v >> 16);
  p[2] = static_cast<unsigned char>(v >> 8);
  p[3] = static_cast<unsigned char>(v);
}

// RFC 9113 6: one control frame - its type, its flags, the stream it names
// (0 = the connection itself), and its fixed payload.
struct H2Control {
  uint8_t type;
  uint8_t flags;
  uint32_t stream;
  std::span<const unsigned char> payload;
};

// Header + payload, into the sink.
void emit_control(std::string& sink, const H2Control& c) {
  const uint32_t len = static_cast<uint32_t>(c.payload.size());
  unsigned char fh[kH2FrameHeaderLen];
  h2_put_frame_header(fh, {len, c.type, c.flags, c.stream});
  sink.append(reinterpret_cast<const char*>(fh), sizeof(fh));
  if (len != 0) sink.append(reinterpret_cast<const char*>(c.payload.data()), len);
}

// RFC 7541 5.2: a string length, 7-bit prefix, H bit 0 - no Huffman out.
void hp_len(std::string& out, size_t n) {
  if (n < 127) {
    out.push_back(static_cast<char>(n));
    return;
  }
  out.push_back(0x7f);
  n -= 127;
  while (n >= 128) {
    out.push_back(static_cast<char>(0x80 | (n & 0x7f)));
    n >>= 7;
  }
  out.push_back(static_cast<char>(n));
}

// RFC 7541 6.2.2: literal without indexing, indexed name, 4-bit prefix.
void hp_name_idx(std::string& out, uint32_t idx) {
  if (idx < 15) {
    out.push_back(static_cast<char>(idx));
    return;
  }
  out.push_back(0x0f);
  idx -= 15;
  while (idx >= 128) {
    out.push_back(static_cast<char>(0x80 | (idx & 0x7f)));
    idx >>= 7;
  }
  out.push_back(static_cast<char>(idx));
}
}

// RFC 9113: the connection's state dies with the connection.
void h2_free(H2State* h2) { delete h2; }

// RFC 9110 4.2.1: a PARKED request's view - its bytes are the stream's own
// copy, so the spans have to be captured again.
const ReqView* Http1::h2_parked_view(Conn& st0, const std::string& target, ReqView& out) {
  if (target.empty()) return nullptr;
  const AppSlot& slot = apps_[st0.listener];
  const int r = slot.table->match(target.data(), target.size(), out.spans);
  if (r < 0) return nullptr;
  out.request_target = target.data();
  out.request_target_len = target.size();
  out.path_len = http::path_only(target.data(), target.size());
  out.table = slot.table;
  out.route = r;
  return &out;
}

// RFC 7541 6.1/6.2.2: lane 1 - a precomputed block of what never changes.
void Http1::h2_build_block(H2Block& b, const H2BlockFields& f) {
  const uint16_t status = f.status;
  const std::string* const ctype = f.ctype;
  const std::string* const allow = f.allow;
  b.bytes.clear();
  switch (status) {
    case 200: b.bytes.push_back(static_cast<char>(0x88)); break;
    case 204: b.bytes.push_back(static_cast<char>(0x89)); break;
    case 206: b.bytes.push_back(static_cast<char>(0x8a)); break;
    case 304: b.bytes.push_back(static_cast<char>(0x8b)); break;
    case 400: b.bytes.push_back(static_cast<char>(0x8c)); break;
    case 404: b.bytes.push_back(static_cast<char>(0x8d)); break;
    case 500: b.bytes.push_back(static_cast<char>(0x8e)); break;
    default: {
      hp_name_idx(b.bytes, 8);
      char d[3];
      d[0] = static_cast<char>('0' + status / 100);
      d[1] = static_cast<char>('0' + (status / 10) % 10);
      d[2] = static_cast<char>('0' + status % 10);
      hp_len(b.bytes, 3);
      b.bytes.append(d, 3);
      break;
    }
  }
  if (ctype != nullptr && !ctype->empty()) {
    hp_name_idx(b.bytes, 31);
    hp_len(b.bytes, ctype->size());
    b.bytes.append(*ctype);
  }
  if (allow != nullptr && !allow->empty()) {
    b.bytes.push_back(0x00);
    hp_len(b.bytes, 5);
    b.bytes.append("allow", 5);
    hp_len(b.bytes, allow->size());
    b.bytes.append(*allow);
  }
}

// RFC 9113 3.4: this side's half of the preface, a SETTINGS frame.
bool Http1::h2_begin(Conn& st, std::string& sink) {
  st.h2 = new H2State();
  // The encoder allocates; without it there is no answer to send, so the
  // connection ends here rather than at the first field.
  if (!st.h2->hpack_ready) return false;
  unsigned char payload[6];
  payload[0] = 0;
  payload[1] = kH2SettingsMaxConcurrentStreams;
  put_u32(payload + 2, kH2MaxConcurrentStreams);
  emit_control(sink, {kH2Settings, 0, 0, payload});
  return true;
}

// RFC 9113 6.8: GOAWAY, and the connection is done.
bool Http1::h2_error(Conn& st, uint32_t code, std::string& sink) {
  H2State& h2 = *st.h2;
  st.carry.clear();
  if (!h2.goaway_sent) {
    unsigned char payload[8];
    put_u32(payload, h2.last_stream);
    put_u32(payload + 4, code);
    emit_control(sink, {kH2Goaway, 0, 0, payload});
    h2.goaway_sent = true;
  }
  return false;
}

// RFC 9113 5.1: an id above everything ever accepted is IDLE.
// RFC 9113 8.2.2: the connection-specific fields h2 forbids outright, and
// 8.1.1's content-length, which may be named once. False = malformed, and
// the stream is reset.
// RFC 9113 8.1.2: what a content-length field claimed, if one did - a
// second one is the protocol error this returns false for.
struct ClaimedLength {
  bool have = false;
  size_t value = 0;
};

bool h2_wire_header_ok(http::Field f, ClaimedLength& claimed) {
  const char* const n = f.name.data();
  const size_t nl = f.name.size();
  const char* const v = f.value.data();
  const size_t vl = f.value.size();
  // te(2) upgrade(7) connection/keep-alive(10) content-length(14)
  // transfer-encoding(17).
  static constexpr size_t kLengths[] = {2, 7, 10, 14, 17};
  static constexpr uint32_t kMask =
      http::lengths_mask(kLengths, sizeof(kLengths) / sizeof(kLengths[0]));
  if (!http::length_is_one_of(nl, kMask)) return true;
  switch (nl) {
    case 2:
      if (http::tok_eq(n, nl, "te", 2) && !(vl == 8 && http::tok_eq(v, vl, "trailers", 8))) {
        return false;
      }
      break;
    case 14:
      if (http::tok_eq(n, nl, "content-length", 14)) {
        if (claimed.have) return false;
        claimed.have = true;
        if (http::parse_content_length({v, vl}, &claimed.value) != http::ClStatus::kOk) {
          return false;
        }
      }
      break;
    case 10:
      if (http::tok_eq(n, nl, "connection", 10) || http::tok_eq(n, nl, "keep-alive", 10)) {
        return false;
      }
      break;
    case 17:
      if (http::tok_eq(n, nl, "transfer-encoding", 17)) return false;
      break;
    case 7:
      if (http::tok_eq(n, nl, "upgrade", 7)) return false;
      break;
    default:
      break;
  }
  return true;
}

static bool h2_is_idle(const H2State& h2, uint32_t id) { return id > h2.highest_opened; }

// RFC 9113 6.2: one whole HEADERS frame - the route's prebuilt block, the
// per-answer fields, and the date - laid down for the cache to replay.
void Http1::cache_headers(std::string& out, const CachedHead& head) {
  const size_t clen = head.fields.size();
  const size_t dlen = head.date.size();
  unsigned char fh[kH2FrameHeaderLen];
  h2_put_frame_header(fh, {static_cast<uint32_t>(head.block.bytes.size() + clen + dlen),
                           kH2Headers, kH2FlagEndHeaders, 0});
  out.assign(reinterpret_cast<const char*>(fh), sizeof(fh));
  out.append(head.block.bytes);
  if (clen != 0) out.append(reinterpret_cast<const char*>(head.fields.data()), clen);
  out.append(reinterpret_cast<const char*>(head.date.data()), dlen);
}

// RFC 9113 6.4: a stream error - the stream dies, the connection lives.
void Http1::h2_rst(Conn& st, uint32_t stream_id, uint32_t code, std::string& sink) {
  unsigned char payload[4];
  put_u32(payload, code);
  emit_control(sink, {kH2RstStream, 0, stream_id, payload});
  st.h2->close_stream(stream_id);
}

// #210 / #146: the page h1 spells for this status, framed for h2. False =
// there is nothing to say and the prebuilt bodyless block stands.
bool Http1::h2_error_page(const H2ErrorAsk& ask, H2ErrorPage& page, H2Answer& out) {
  const http::ReqValues* vals = ask.vals;
  const int m = err_pages_.media_for(ask.status, vals != nullptr ? vals->accept : nullptr,
                                     vals != nullptr ? vals->accept_len : 0);
  size_t plen = 0;
  const char* pbody =
      err_pages_.body_for({ask.status, m, ask.fields}, page.rendered, &plen);
  if (pbody == nullptr) return false;
  const std::string ctype(err_pages_.media_type(m));
  // RFC 9110 15.5.6: a 405 says which methods it WOULD take, and the page
  // it now carries must not cost it that field.
  const Bundle* b = ask.bundle;
  const std::string* allow =
      (ask.status == 405 && b != nullptr && !b->konst.allow.empty()) ? &b->konst.allow : nullptr;
  h2_build_block(page.block, {ask.status, &ctype, allow});
  // Lent where it lies, whether that is the picture in the mapping or the
  // page prepared at boot; a render lands in page.rendered, which
  // outlives the framing at the call site either way.
  out.body = pbody;
  out.blen = plen;
  out.blk = &page.block;
  return true;
}

// RFC 9113 8.1/8.2/8.3: decode the block, check the pseudo-fields, and
// either answer or park the facts on the stream.
bool Http1::h2_dispatch(Conn& st0, const H2Headers& h, std::string& sink) {
  const uint32_t stream_id = h.stream_id;
  const bool end_stream = h.end_stream;
  const unsigned char* const blk = h.block.data();
  const size_t blk_len = h.block.size();
  H2State& h2 = *st0.h2;

  uint32_t quads[4 * kH2MaxFields];
  size_t nq = 0;
  size_t used = 0;
  const unsigned char* p = blk;
  const unsigned char* end = p + blk_len;
  while (p < end) {
    if (nq + 4 > 4 * kH2MaxFields) return h2_error(st0, kH2EnhanceYourCalm, sink);
    if (used > kH2FragBudget) return h2_error(st0, kH2EnhanceYourCalm, sink);
    if (h2.hdrbuf.size() < used + 4096) h2.hdrbuf.resize(used + 4096);
    lsxpack_header_t xh;
    lsxpack_header_prepare_decode(&xh, &h2.hdrbuf[used], 0, 4096);
    if (lshpack_dec_decode(&h2.dec, &p, end, &xh) != 0) {
      return h2_error(st0, kH2CompressionError, sink);
    }
    quads[nq++] = static_cast<uint32_t>(used + xh.name_offset);
    quads[nq++] = xh.name_len;
    quads[nq++] = static_cast<uint32_t>(used + xh.val_offset);
    quads[nq++] = xh.val_len;
    // lshpack.h states what one decode writes into the buffer we lent:
    // name_len + val_len + lshpack_dec_extra_bytes(dec). Advancing by
    // val_offset + val_len is short by exactly those extra bytes (the
    // HTTP/1.x CRLF the decoder appends), so the NEXT field's window
    // began inside bytes this one had just written. Their number, not
    // ours.
    used += static_cast<size_t>(xh.name_len) + xh.val_len + lshpack_dec_extra_bytes(&h2.dec);
  }
  h2.frag.clear();

  H2Stream* existing = h2.find(stream_id);
  if (existing != nullptr && existing->end_headers) {
    if (!end_stream || existing->half_closed_remote) {
      return h2_error(st0, kH2ProtocolError, sink);
    }
    existing->half_closed_remote = true;
    const flow::ReqFacts facts = existing->facts;
    const bool head_only = existing->head_method;
    const AssetEntry* asset = existing->parked_asset;
    const uint16_t asset_status = existing->parked_status;
    const size_t asset_off = existing->parked_first;
    const size_t asset_end = existing->parked_end;
    const uint16_t route = existing->route;
    const std::string target = existing->request_target;
    if (asset != nullptr) {
      const H2Asset ask = {stream_id, *asset, asset_status, head_only, asset_off, asset_end};
      if (!h2_asset_answer(st0, ask, sink)) return false;
      h2_log(st0, {facts, target});
      return true;
    }
    std::string body;
    body.swap(existing->request_content);
    // The fields this stream copied when it parked, rebuilt over the
    // blob that outlived hdrbuf.
    struct phr_header hv[kH2MaxFields];
    size_t nh = existing->field_spans.size() / 4;
    if (nh > kH2MaxFields) nh = kH2MaxFields;
    for (size_t i = 0; i < nh; i++) {
      hv[i].name = existing->field_blob.data() + existing->field_spans[i * 4];
      hv[i].name_len = existing->field_spans[i * 4 + 1];
      hv[i].value = existing->field_blob.data() + existing->field_spans[i * 4 + 2];
      hv[i].value_len = existing->field_spans[i * 4 + 3];
    }
    // RFC 9110 12.5: same as the resume in h2_feed - the values point into
    // the decode buffer this stream no longer owns, and the copied fields
    // are where they still are.
    http::ReqValues pvals;
    values_of_copied_fields({hv, nh}, pvals);
    ReqView rv;
    rv.method = facts.method;
    rv.content = body.empty() ? nullptr : body.data();
    rv.content_len = body.size();
    rv.fields = nh != 0 ? hv : nullptr;
    rv.field_count = nh;
    rv.values = &pvals;
    const ReqView* rvp = h2_parked_view(st0, target, rv);
    const H2Request q{stream_id, facts, &pvals, rvp, target, route, head_only};
    if (!h2_answer(st0, q, sink)) {
      return false;
    }
    h2_log(st0, {facts, target});
    return true;
  }

  flow::ReqFacts facts;
  http::ReqValues vals;
  const char* path_val = nullptr;
  size_t path_vlen = 0;
  bool ok = true, saw_regular = false;
  bool have_method = false, have_path = false, have_scheme = false, have_authority = false;
  ClaimedLength claimed;
  // RFC 9113 8.3: the request's own fields, in the shape h1 hands down,
  // so request.headers and every by-name accessor answer the same way on
  // both protocols. Filled in the loop that already holds the pointers -
  // the pseudo-fields are not among them, because the branch below takes
  // them first, which is also what h1 means by a header.
  struct phr_header hv[kH2MaxFields];
  size_t nh = 0;
  for (size_t i = 0; ok && i < nq; i += 4) {
    const char* name = h2.hdrbuf.data() + quads[i];
    const size_t nlen = quads[i + 1];
    const char* val = h2.hdrbuf.data() + quads[i + 2];
    const size_t vlen = quads[i + 3];
    if (nlen == 0) {
      ok = false;
      break;
    }
    if (name[0] == ':') {
      if (saw_regular) {
        ok = false;
        break;
      }
      if (nlen == 7 && std::memcmp(name, ":method", 7) == 0) {
        if (have_method) { ok = false; break; }
        have_method = true;
        facts.method = http::parse_method(val, vlen);
      } else if (nlen == 5 && std::memcmp(name, ":path", 5) == 0) {
        if (path_val != nullptr) { ok = false; break; }
        have_path = vlen != 0;
        path_val = val;
        path_vlen = vlen;
      } else if (nlen == 7 && std::memcmp(name, ":scheme", 7) == 0) {
        if (have_scheme) { ok = false; break; }
        have_scheme = true;
      } else if (nlen == 10 && std::memcmp(name, ":authority", 10) == 0) {
        if (have_authority) { ok = false; break; }
        have_authority = true;
      } else {
        ok = false;
      }
      continue;
    }
    saw_regular = true;
    if (h2_has_upper(name, nlen)) {
      ok = false;
      break;
    }
    // Where this field lands, for vals.named to point at. A block past
    // kH2MaxFields keeps no slot, and SIZE_MAX says so.
    size_t at = SIZE_MAX;
    if (nh < kH2MaxFields) {
      hv[nh].name = name;
      hv[nh].name_len = nlen;
      hv[nh].value = val;
      hv[nh].value_len = vlen;
      at = nh;
      nh++;
    }
    if (http::header_switch({{name, nlen}, {val, vlen}}, {facts, vals, at}) &&
        !h2_wire_header_ok({{name, nlen}, {val, vlen}}, claimed)) {
      ok = false;
    }
  }
  if (!ok || !have_method || !have_path || !have_scheme) {
    h2_rst(st0, stream_id, kH2ProtocolError, sink);
    return true;
  }

  if (stream_id > h2.last_stream) h2.last_stream = stream_id;
  if (stream_id > h2.highest_opened) h2.highest_opened = stream_id;
  if (h2.streams.size() >= kH2MaxConcurrentStreams) {
    h2_rst(st0, stream_id, kH2RefusedStream, sink);
    return true;
  }
  const bool head_only = facts.method == flow::Method::kHead;

  const AssetEntry* asset = nullptr;
  uint16_t asset_status = 0;
  size_t asset_off = 0;
  size_t asset_end = 0;
  if (assets_ != nullptr) {
    if (AssetEntry* ae = assets_->find(path_val, path_vlen)) {
      asset = ae;
      asset_status = assets_->verdict(*ae, {facts, vals});
      asset_end = Assets::wire_len(*ae);
      if (asset_status == 200 && !head_only && facts.method == flow::Method::kGet &&
          vals.range != nullptr &&
          (vals.if_range == nullptr ||
           http::if_range_matches({vals.if_range, vals.if_range_len},
                                  {ae->etag, sizeof(ae->etag)}))) {
        http::ByteRange r = {0, 0};
        switch (http::parse_range({{vals.range, vals.range_len}, asset_end}, r)) {
          case http::RangeParse::kOne:
            asset_status = 206;
            asset_off = r.first;
            asset_end = r.last + 1;
            break;
          case http::RangeParse::kUnsat: asset_status = 416; break;
          case http::RangeParse::kNone: break;
        }
      }
    }
  }

  RouteSpans spans;
  const int r = apps_[st0.listener].table->match(path_val, path_vlen, spans);
  const uint16_t route = r < 0 ? kNoRoute : static_cast<uint16_t>(r);

  if (end_stream) {
    if (claimed.have && claimed.value != 0) {
      h2_rst(st0, stream_id, kH2ProtocolError, sink);
      return true;
    }
    if (asset != nullptr) {
      const H2Asset ask = {stream_id, *asset, asset_status, head_only, asset_off, asset_end};
      if (!h2_asset_answer(st0, ask, sink)) return false;
      h2_log(st0, {facts, {path_val, path_vlen}});
      return true;
    }
    ReqView rv;
    rv.request_target = path_val;
    rv.request_target_len = path_vlen;
    rv.path_len = http::path_only(path_val, path_vlen);
    rv.method = facts.method;
    rv.table = apps_[st0.listener].table;
    rv.route = r;
    rv.spans = spans;
    // hdrbuf is still the block this dispatch decoded, so the fields can
    // be lent for the length of the answer.
    rv.fields = hv;
    rv.field_count = nh;
    rv.values = &vals;
    const H2Request q{stream_id, facts, &vals, r < 0 ? nullptr : &rv,
                      {path_val, path_vlen}, route, head_only};
    if (!h2_answer(st0, q, sink)) {
      return false;
    }
    h2_log(st0, {facts, {path_val, path_vlen}});
    return true;
  }
  H2Stream& stx = h2.open(stream_id);
  stx.end_headers = true;
  stx.facts = facts;
  stx.head_method = head_only;
  stx.parked_asset = asset;
  stx.parked_status = asset_status;
  stx.parked_first = asset_off;
  stx.parked_end = asset_end;
  stx.route = route;
  stx.request_target.assign(path_val, path_vlen);
  stx.field_blob.clear();
  stx.field_spans.clear();
  stx.field_spans.reserve(nh * 4);
  for (size_t i = 0; i < nh; i++) {
    stx.field_spans.push_back(static_cast<uint32_t>(stx.field_blob.size()));
    stx.field_spans.push_back(static_cast<uint32_t>(hv[i].name_len));
    stx.field_blob.append(hv[i].name, hv[i].name_len);
    stx.field_spans.push_back(static_cast<uint32_t>(stx.field_blob.size()));
    stx.field_spans.push_back(static_cast<uint32_t>(hv[i].value_len));
    stx.field_blob.append(hv[i].value, hv[i].value_len);
  }
  stx.content_length = claimed.value;
  stx.content_length_given = claimed.have;
  return true;
}

// RFC 7541 Appendix A: never-indexed blocks per asset entry, at setup.
void Http1::h2_build_asset_blocks(AssetEntry& e) {
  std::string& b = e.h2_head_200;
  b.clear();
  b.push_back(static_cast<char>(0x88));
  hp_name_idx(b, 31);
  hp_len(b, e.content_type.size());
  b.append(e.content_type);
  if (e.deflated) {
    hp_name_idx(b, 26);
    hp_len(b, 4);
    b.append("gzip", 4);
    hp_name_idx(b, 59);
    hp_len(b, 15);
    b.append("Accept-Encoding", 15);
  }
  hp_name_idx(b, 34);
  hp_len(b, sizeof(e.etag));
  b.append(e.etag, sizeof(e.etag));
  if (e.last_modified_valid) {
    hp_name_idx(b, 44);
    hp_len(b, sizeof(e.last_modified));
    b.append(e.last_modified, sizeof(e.last_modified));
  }
  hp_name_idx(b, 18);
  hp_len(b, 5);
  b.append("bytes", 5);

  std::string& c = e.h2_head_304;
  c.clear();
  c.push_back(static_cast<char>(0x8b));
  hp_name_idx(c, 34);
  hp_len(c, sizeof(e.etag));
  c.append(e.etag, sizeof(e.etag));
  if (e.deflated) {
    hp_name_idx(c, 59);
    hp_len(c, 15);
    c.append("Accept-Encoding", 15);
  }
}

// RFC 7541: the asset tier's shared 405 and 406 blocks.
void Http1::h2_build_asset_shared() {
  static const std::string kAllow = "GET, HEAD";
  h2_build_block(h2_asset405_, {405, nullptr, &kAllow});
  h2_build_block(h2_asset406_, {406});
  hp_name_idx(h2_asset406_.bytes, 59);
  hp_len(h2_asset406_.bytes, 15);
  h2_asset406_.bytes.append("Accept-Encoding", 15);
}

// RFC 9113 6.1/6.9: the asset answer - body as segments over the mapping,
// window-refused remainder parked.
bool Http1::h2_asset_answer(Conn& st0, const H2Asset& a, std::string& sink) {
  const uint32_t stream_id = a.stream_id;
  const AssetEntry& e = a.entry;
  const uint16_t status = a.status;
  const bool head_only = a.head_only;
  const size_t win_off = a.win_off;
  const size_t win_end = a.win_end;
  H2State& h2 = *st0.h2;
  std::string rblk;
  const std::string* blk;
  switch (status) {
    case 200: blk = &e.h2_head_200; break;
    case 206: {
      rblk.push_back(static_cast<char>(0x8a));
      hp_name_idx(rblk, 31);
      hp_len(rblk, e.content_type.size());
      rblk.append(e.content_type);
      if (e.deflated) {
        hp_name_idx(rblk, 26);
        hp_len(rblk, 4);
        rblk.append("gzip", 4);
        hp_name_idx(rblk, 59);
        hp_len(rblk, 15);
        rblk.append("Accept-Encoding", 15);
      }
      hp_name_idx(rblk, 34);
      hp_len(rblk, sizeof(e.etag));
      rblk.append(e.etag, sizeof(e.etag));
      hp_name_idx(rblk, 30);
      const std::string cr = "bytes " + std::to_string(win_off) + "-" +
                             std::to_string(win_end - 1) + "/" +
                             std::to_string(Assets::wire_len(e));
      hp_len(rblk, cr.size());
      rblk.append(cr);
      blk = &rblk;
      break;
    }
    case 416: {
      hp_name_idx(rblk, 8);
      hp_len(rblk, 3);
      rblk.append("416", 3);
      if (e.deflated) {
        hp_name_idx(rblk, 59);
        hp_len(rblk, 15);
        rblk.append("Accept-Encoding", 15);
      }
      hp_name_idx(rblk, 30);
      const std::string cr = "bytes */" + std::to_string(Assets::wire_len(e));
      hp_len(rblk, cr.size());
      rblk.append(cr);
      blk = &rblk;
      break;
    }
    case 304: blk = &e.h2_head_304; break;
    case 405: blk = &h2_asset405_.bytes; break;
    case 406: blk = &h2_asset406_.bytes; break;
    default: blk = &h2_store_[index_[status]].bytes; break;
  }

  const bool has_body = status == 200 || status == 206;
  const size_t blen = has_body ? win_end - win_off : 0;
  const bool no_data = head_only || blen == 0;
  alog_status_ = status;
  alog_bytes_ = no_data ? 0 : blen;

  unsigned char dbuf[64];
  unsigned char* dp = dbuf;
  if (!h2_enc_field({&h2.enc, dp, dbuf + sizeof(dbuf)}, {"date", {date_, sizeof(date_)}})) {
    return h2_error(st0, kH2InternalError, sink);
  }
  const size_t dlen = static_cast<size_t>(dp - dbuf);

  unsigned char fh[kH2FrameHeaderLen];
  const uint8_t head_flags = kH2FlagEndHeaders | (no_data ? kH2FlagEndStream : 0);
  h2_put_frame_header(
      fh, {static_cast<uint32_t>(blk->size() + dlen), kH2Headers, head_flags, stream_id});
  sink.append(reinterpret_cast<const char*>(fh), sizeof(fh));
  sink.append(*blk);
  sink.append(reinterpret_cast<const char*>(dbuf), dlen);

  if (no_data) {
    h2.close_stream(stream_id);
    return true;
  }

  H2Stream& keep = h2.open(stream_id);
  keep.response_content.take_asset(&e, win_off, win_end);
  keep.end_headers = true;
  keep.half_closed_remote = true;
  return true;
}

// RFC 9113 6.2/6.9.1: HEADERS and DATA for one stream; DATA beyond
// min(connection, stream) is PARKED, never written.
// RFC 9110 15.6.1: see the declaration. A run that named a file never
// lends its body either (see the O18 body handler in resource.cpp), so
// lent_have is already false here and there is nothing to unwind.
uint16_t Http1::h2_refuse_file(Conn& st, const ReqView* req) {
  static const char kWhy[] =
      "response.file is not wired for HTTP/2 yet - this stream would have been "
      "answered with an empty body, so it is refused instead";
  log_internal_error(elog_, {{static_cast<const char*>(st.peer), st.peer_len},
                             req != nullptr
                                 ? std::string_view{req->request_target, req->request_target_len}
                                 : std::string_view{},
                             {kWhy, sizeof(kWhy) - 1},
                             500});
  body_.clear();
  rhdrs_.clear();
  return 500;
}

bool Http1::h2_answer(Conn& st0, const H2Request& q, std::string& sink) {
  const uint32_t stream_id = q.stream_id;
  const flow::ReqFacts& facts = q.facts;
  const http::ReqValues* vals = q.vals;
  const ReqView* req = q.req;
  const uint16_t route = q.route;
  const bool head_only = q.head_only;
  H2State& h2 = *st0.h2;

  const Bundle* b = nullptr;
  const std::array<uint16_t, 600>* idx = &index_;
  uint16_t status;
  bool have_body = false;
  bool dynamic = false;
  // What this run LENT instead of copying, if anything: not yet owned by a
  // stream, so every path out of here below still has to place or free it.
  mrb_state* lent_mrb = nullptr;
  mrb_value lent_v = {};
  const char* lent = nullptr;
  size_t lent_len = 0;
  bool lent_have = false;
  if (route == kNoRoute) {
    status = 404;
  } else {
    b = &bundles_[apps_[st0.listener].base + route];
    idx = &b->index;
    if (b->bound) {
      // The Values die with the frame that carried them, so a run reached
      // from here - parked or not - gets none.
      // The SAME [tune] zero_copy_threshold h1 reads: a HEAD sends no bytes
      // to lend, and h2 has no gzip path for a dynamic body to collide with.
      const RunAsk asked = {facts, vals, req, head_only ? 0 : zc_min_};
      const RunAnswer answer = {&body_, &have_body, &rhdrs_};
      status = resource_run(*b->res, asked, answer);
      LentBody lent_body;
      lent_have = resource_body_lent(*b->res, lent_body);
      lent_v = lent_body.value;
      lent = lent_body.bytes.data();
      lent_len = lent_body.bytes.size();
      if (lent_have) lent_mrb = b->res->mrb;
      // response.file is h1-only for now: the deferred open lives on the
      // CONNECTION (Http1::Conn), and an h2 connection multiplexes streams
      // that would each need their own. The slot is taken either way - left
      // set it would answer the next request through this Resource - and a
      // run that named a file is REFUSED here rather than quietly served the
      // empty body it never meant to send.
      {
        WantedFile wanted;
        if (resource_file_wanted(*b->res, wanted)) {
          have_body = false;
          status = h2_refuse_file(st0, req);
        }
      }
      dynamic = (!b->res->run_content_type.empty() || !rhdrs_.empty()) && status != 500;
    } else {
      // RFC 9110 12.5.1: the same c4 h1 asks. The facts arrive const here -
      // they belong to the stream - so the one negotiated bit is answered on
      // a copy, and only when the client sent an Accept at all.
      // A stream reached from a parked frame carries facts but no Values -
      // the bytes died with the frame. No Accept bytes, nothing to weigh,
      // and c3 already sent this request the way it went before.
      flow::ReqFacts cf = facts;
      if (facts.has_accept && vals != nullptr && vals->accept != nullptr) {
        cf.accept_ok =
            http::choose_media_type({{&b->accept_type, 1}, {vals->accept, vals->accept_len}}) >= 0;
      }
      const size_t mi = static_cast<size_t>(cf.method);
      status = flow::answer(cf, {b->konst.per_method[mi], b->konst.shortcut[mi]});
    }
  }

  H2Answer wire;
  H2Block dynblk;
  // #210 / #146: an error carries the same page here that h1 spells. It
  // outlives the framing below, because a body the window cannot finish
  // is copied onto the stream from THIS buffer.
  H2ErrorPage err_page;
  // #210 response.error_asset: the run named an entry of the error
  // assets, and this stream carries it the way the asset tier's own
  // streams carry one - Content::Src::kAsset, parked and framed by
  // h2_flush_pending against the window. Nothing is rooted: the entry
  // lives in a mapping that outlives every stream that parks on it.
  const AssetEntry* run_asset =
      (b != nullptr && b->res != nullptr) ? b->res->run_asset : nullptr;
  // Its wire length is the answer's length: what h2_build_block declares,
  // what the access log counts, and what END_STREAM is measured against.
  const size_t asset_len = run_asset != nullptr ? Assets::wire_len(*run_asset) : 0;
  if (dynamic) {
    const bool bodyless = status == 204 || status == 304;
    if (bodyless || !have_body) body_.clear();
    // The same bake h1 names: a `def self.to_html` renders at setup, and the
    // block being built here is not the prebuilt one that carries it.
    const bool baked = !bodyless && !have_body && !lent_have && status == 200 &&
                       !b->dynamic_body && !b->konst.body.empty();
    std::string ctype;
    std::string epage;
    // The same debt h1 pays here: a 4xx or 5xx whose run wrote a field of
    // its own never reaches h2_error_page, and would go out as a bare
    // status with the page missing.
    if (status >= 400 && !bodyless && !have_body && !lent_have && run_asset == nullptr) {
      const int em = err_pages_.media_for(status, vals != nullptr ? vals->accept : nullptr,
                                          vals != nullptr ? vals->accept_len : 0);
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
      if (!b->res->run_content_type.empty()) ctype = http::with_charset(b->res->run_content_type);
      else if (have_body || baked) ctype = b->konst.content_type;
    }
    h2_build_block(dynblk, {status, ctype.empty() ? nullptr : &ctype});
    // A status that sends no body cleared body_ above, and a lend it does
    // not carry is handed back below - the same order h1 spells it in.
    const bool use_lent = lent_have && !bodyless && have_body;
    const bool use_asset = run_asset != nullptr && !bodyless && have_body;
    // An asset's octets are never framed from `body` - h2_flush_pending
    // reads them out of the mapping - so only its length is set here.
    wire.body =
        use_asset ? nullptr : (use_lent ? lent : (baked ? b->konst.body.data() : body_.data()));
    wire.blen = use_asset ? asset_len
                          : (use_lent ? lent_len : (baked ? b->konst.body.size() : body_.size()));
    wire.blk = &dynblk;
  } else if (have_body && status == 200) {
    wire.body = run_asset != nullptr ? nullptr : (lent_have ? lent : body_.data());
    wire.blen = run_asset != nullptr ? asset_len : (lent_have ? lent_len : body_.size());
    wire.blk = &h2_store_[(*idx)[200]];
  } else if (status == 500 && b != nullptr && b->bound) {
    // #210: what led here, gathered once - the record and the page carry
    // the same hash because they are taken over the same facts.
    ErrFacts ef;
    std::string ef_backtrace;
    std::string ef_steering;
    char ef_hash[kFingerprintLen] = {};
    ef.peer = st0.peer;
    ef.peer_len = st0.peer_len;
    ef.request_target = req != nullptr ? req->request_target : nullptr;
    ef.request_target_len = req != nullptr ? req->request_target_len : 0;
    ef.method = req != nullptr ? req->method_token : nullptr;
    ef.method_len = req != nullptr ? req->method_token_len : 0;
    spell_steering(vals, ef_steering);
    ef.steering = ef_steering.data();
    ef.steering_len = ef_steering.size();
    ef.body = req != nullptr ? req->content : nullptr;
    ef.body_len = req != nullptr ? req->content_len : 0;
    ef.body_full = ef.body_len;
    ef.status_code = 500;
    exception_facts(b->res->mrb, {ef, ef_backtrace});
    spell_fingerprint(ef_hash, fingerprint_of(ef));
    if (elog_.enabled) log_error(elog_, ef);
    // #210: handle_exception lives on the error resource and nowhere
    // else, so the exception object itself is what crosses over.
    std::string message;
    mrb_value exc = mrb_nil_value();
    if (resource_exception_take(*b->res, &exc)) err_pages_.exception_text(exc, message);
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
    const H2ErrorAsk ask = {500, f, vals, b};
    if (!h2_error_page(ask, err_page, wire)) {
      wire.blk = &h2_store_[(*idx)[500]];
    }
  } else if (status == 200) {
    wire.body = b->konst.body.data();
    wire.blen = b->konst.body.size();
    wire.blk = &h2_store_[(*idx)[200]];
  } else {
    // RFC 9110 15: only a 4xx or 5xx has something to explain.
    bool spelled = false;
    if (status >= 400) {
      ErrorPages::Fields f;
      const H2ErrorAsk ask = {status, f, vals, b};
      spelled = h2_error_page(ask, err_page, wire);
    }
    if (!spelled) wire.blk = &h2_store_[(*idx)[status]];
  }

  const bool no_data = head_only || wire.blen == 0;

  // A lend the chain above did not adopt (a bodyless status, a 500 that
  // spelled its own body) never reached a plan, so this IS its release.
  if (lent_have && (no_data || wire.body != lent)) {
    resource_body_unlend(lent_mrb, lent_v);
    lent_have = false;
  }
  // And one that WAS adopted becomes the stream's before anything below can
  // fail: from here on close_stream and ~H2State own it, so no error path
  // can strand a rooted body nobody comes back for.
  if (lent_have) {
    H2Stream& keep = h2.open(stream_id);
    keep.response_content.take_lent(lent_mrb, lent_v, lent, lent_len);
    keep.end_headers = true;
    keep.half_closed_remote = true;
  }
  // #210: and an asset parks the same way the asset TIER parks one, with
  // the same Src - so h2_flush_pending frames it out of the mapping and
  // the sweep there closes the stream once the window has let all of it
  // through. A head-only answer, or a status that sends nothing, takes
  // no stream: no_data covers both.
  const bool asset_data = run_asset != nullptr && !no_data;
  if (asset_data) {
    H2Stream& keep = h2.open(stream_id);
    keep.response_content.take_asset(run_asset, 0, wire.blen);
    keep.end_headers = true;
    keep.half_closed_remote = true;
  }

  alog_status_ = status;
  alog_bytes_ = no_data ? 0 : wire.blen;

  H2Stream* stp = no_data ? nullptr : h2.find(stream_id);
  int64_t budget = 0;
  if (!no_data) {
    const int64_t swin = stp != nullptr ? stp->flow_window : h2.peer_initial_window;
    budget = h2.flow_window < swin ? h2.flow_window : swin;
  }

  bool merged = false;
  if (dynamic) {
    // RFC 7541: lane 1 spells :status and Content-Type, lane 2 the Date and
    // every field line this run produced. A per-request head is never cached.
    unsigned char ebuf[2048];
    unsigned char* ep = ebuf;
    unsigned char* const eend = ebuf + sizeof(ebuf);
    // Indexed, unlike the cached path's: this head is spelled once and
    // thrown away, so an insert here costs nothing to replay - but it
    // DOES move every index a cached head may be holding, which is what
    // enc_ins counts.
    if (!h2_enc_field({&h2.enc, ep, eend}, {"date", {date_, sizeof(date_)}})) {
      return h2_error(st0, kH2InternalError, sink);
    }
    h2.enc_ins++;
    std::string name;
    size_t at = 0;
    while (at < rhdrs_.size()) {
      const size_t eol = rhdrs_.find("\r\n", at);
      if (eol == std::string::npos) break;
      const size_t colon = rhdrs_.find(':', at);
      if (colon != std::string::npos && colon < eol) {
        size_t vs = colon + 1;
        while (vs < eol && (rhdrs_[vs] == ' ' || rhdrs_[vs] == '\t')) vs++;
        name.assign(rhdrs_, at, colon - at);
        for (char& c : name) {
          if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
        }
        if (!h2_enc_field({&h2.enc, ep, eend}, {name, {rhdrs_.data() + vs, eol - vs}})) {
          return h2_error(st0, kH2InternalError, sink);
        }
        h2.enc_ins++;
      }
      at = eol + 2;
    }
    const size_t elen = static_cast<size_t>(ep - ebuf);
    unsigned char fh[kH2FrameHeaderLen];
    const uint8_t head_flags = kH2FlagEndHeaders | (no_data ? kH2FlagEndStream : 0);
    h2_put_frame_header(fh, {static_cast<uint32_t>(wire.blk->bytes.size() + elen), kH2Headers,
                             head_flags, stream_id});
    sink.append(reinterpret_cast<const char*>(fh), sizeof(fh));
    sink.append(wire.blk->bytes);
    sink.append(reinterpret_cast<const char*>(ebuf), elen);
  } else {
    if (h2.head_cache.status != status || h2.head_cache.route != route ||
        h2.head_cache.sec != sec_ || h2.head_cache.enc_ins != h2.enc_ins) {
      // RFC 7541 6.2.1 / 6.1: content-type is the same string for every
      // answer this route ever gives, so it goes into the peer's dynamic
      // table ONCE and is a one-byte reference after that. Encoded
      // twice: ls-hpack answers the first call with the insert and the
      // second with the index it just made, which is exactly the two
      // forms this cache needs. Only the 200 has one - the shared status
      // blocks carry no content-type, and a bound route never reaches
      // this branch.
      const std::string* ct =
          (status == 200 && b != nullptr && !b->konst.content_type.empty())
              ? &b->konst.content_type
              : nullptr;
      unsigned char pbuf[256];
      unsigned char rbuf[256];
      size_t plen = 0;
      size_t rlen = 0;
      if (ct != nullptr) {
        unsigned char* pp = pbuf;
        unsigned char* rp = rbuf;
        if (!h2_enc_field({&h2.enc, pp, pbuf + sizeof(pbuf)}, {"content-type", *ct}) ||
            !h2_enc_field({&h2.enc, rp, rbuf + sizeof(rbuf)}, {"content-type", *ct})) {
          return h2_error(st0, kH2InternalError, sink);
        }
        plen = static_cast<size_t>(pp - pbuf);
        rlen = static_cast<size_t>(rp - rbuf);
        h2.enc_ins++;
        // The block that carried the literal is the wrong one now: the
        // shared 200 spells :status and nothing else.
        wire.blk = &h2_store_[index_[200]];
      }
      unsigned char dbuf[64];
      unsigned char* dp = dbuf;
      // NOT indexed: these bytes are kept and sent again for every
      // answer of this second, and an insert replayed is an insert the
      // peer performs again each time. content-type above may be
      // indexed for the opposite reason - it is inserted once and the
      // cache then replays the REFERENCE, never the insert.
      if (!h2_enc_field({&h2.enc, dp, dbuf + sizeof(dbuf)},
                        {"date", {date_, sizeof(date_)}, false})) {
        return h2_error(st0, kH2InternalError, sink);
      }
      const size_t dlen = static_cast<size_t>(dp - dbuf);
      cache_headers(h2.head_cache.bytes, {*wire.blk, {rbuf, rlen}, {dbuf, dlen}});
      h2.head_cache.head_len = h2.head_cache.bytes.size();
      h2.head_cache.primed = ct == nullptr;
      if (ct != nullptr) {
        cache_headers(h2.head_cache.prime, {*wire.blk, {pbuf, plen}, {dbuf, dlen}});
      }
      h2.head_cache.has_data = b != nullptr && !b->bound && status == 200 &&
                               !b->konst.body.empty() &&
                               b->konst.body.size() <= kH2MergeBody;
      if (h2.head_cache.has_data) h2.head_cache.bytes.append(b->h2_data200);
      h2.head_cache.status = status;
      h2.head_cache.route = route;
      h2.head_cache.sec = sec_;
      // Taken AFTER the encodes above, so the reference this head holds
      // and the table it points into are recorded together.
      h2.head_cache.enc_ins = h2.enc_ins;
    }
    // One answer per connection carries the insert; it is never merged
    // with a DATA frame, because it is one response in a second and the
    // merge exists for the other thousands.
    const bool prime = !h2.head_cache.primed;
    merged = !prime && !no_data && h2.head_cache.has_data &&
             budget >= static_cast<int64_t>(wire.blen) && wire.blen <= h2.peer_max_frame;
    const size_t hoff = sink.size();
    if (prime) {
      sink.append(h2.head_cache.prime);
      h2.head_cache.primed = true;
    } else if (merged) {
      sink.append(h2.head_cache.bytes);
    } else {
      sink.append(h2.head_cache.bytes, 0, h2.head_cache.head_len);
    }
    unsigned char* hp = reinterpret_cast<unsigned char*>(&sink[hoff]);
    hp[4] = kH2FlagEndHeaders | (no_data ? kH2FlagEndStream : 0);
    h2_patch_stream_id(hp, stream_id);
    if (merged) h2_patch_stream_id(hp + h2.head_cache.head_len, stream_id);
  }

  // RFC 9113 6.9.1: not one byte of a LENT body is framed here. All of it
  // is parked on the stream and h2_flush_pending - the only place holding a
  // plan - gives it the window, the frames and the external segment, the
  // same way the asset tier's `src` is delivered.
  size_t give = 0;
  if (!lent_have && !asset_data && !no_data) {
    if (merged) {
      give = wire.blen;
    } else {
      give = wire.blen;
      if (budget <= 0) {
        give = 0;
      } else if (static_cast<int64_t>(give) > budget) {
        give = static_cast<size_t>(budget);
      }
      unsigned char fh[kH2FrameHeaderLen];
      size_t off = 0;
      while (off < give) {
        size_t n = give - off;
        if (n > h2.peer_max_frame) n = h2.peer_max_frame;
        const bool last = off + n == wire.blen;
        const uint8_t end_flag = last ? kH2FlagEndStream : 0;
        h2_put_frame_header(fh, {static_cast<uint32_t>(n), kH2Data, end_flag, stream_id});
        sink.append(reinterpret_cast<const char*>(fh), sizeof(fh));
        sink.append(wire.body + off, n);
        off += n;
      }
    }
    const bool had_stream = stp != nullptr;
    h2.flow_window -= static_cast<int64_t>(give);
    if (had_stream) stp->flow_window -= static_cast<int64_t>(give);
    if (give < wire.blen) {
      H2Stream& keep = h2.open(stream_id);
      keep.response_content.take_owned(wire.body + give, wire.blen - give);
      keep.end_headers = true;
      keep.half_closed_remote = true;
      if (!had_stream) keep.flow_window -= static_cast<int64_t>(give);
    }
  }
  // A lent stream is never closed here: its bytes have not been framed yet,
  // and the sweep at the end of h2_flush_pending closes it once they are.
  if (!lent_have && !asset_data && (no_data || give == wire.blen)) h2.close_stream(stream_id);
  return true;
}

namespace {
struct RoundOut {
  std::string& sink;
  Http1::Plan* plan;
  size_t emitted = 0;

  // RFC 9113: claim the sink bytes this round started with - a plan naming
  // any sink range describes the sink COMPLETELY.
  void prime() {
    if (plan == nullptr || plan->iovlen != 0 || sink.empty()) return;
    plan->iov[plan->iovlen++] = Http1::Plan::Seg{nullptr, 0, sink.size()};
    plan->byte_total += sink.size();
  }

  // RFC 9113 6.1: room for one more DATA frame - its header plus up to three
  // payload spans. Every gate sits BEFORE the frame, never inside one.
  bool room_for_frame() const {
    if (plan == nullptr) return emitted < kDeliverChunk;
    if (plan->iovlen + 4 > Http1::Plan::kSegs) return false;
    return plan->byte_cap == 0 || plan->byte_total < plan->byte_cap;
  }

  // RFC 9113: framing bytes, coalesced into the open sink run.
  void bytes(const char* p, size_t n) {
    if (plan == nullptr) {
      sink.append(p, n);
      emitted += n;
      return;
    }
    prime();
    const size_t at = sink.size();
    sink.append(p, n);
    if (plan->iovlen > 0) {
      Http1::Plan::Seg& open = plan->iov[plan->iovlen - 1];
      if (open.iov_base == nullptr && open.off + open.iov_len == at) {
        open.iov_len += n;
        plan->byte_total += n;
        return;
      }
    }
    plan->iov[plan->iovlen++] = Http1::Plan::Seg{nullptr, at, n};
    plan->byte_total += n;
  }

  static constexpr size_t kCopyFloor = 4096;

  // RFC 1952: asset payload as POINTERS into the mapping; small pieces are
  // copied instead (one page is the measured line).
  void span(const AssetEntry& e, size_t off, size_t n) {
    if (plan == nullptr) {
      Assets::copy_wire(e, off, n, sink);
      emitted += n;
      return;
    }
    prime();
    struct iovec iv[3];
    const unsigned k = Assets::wire_iov(e, off, n, iv);
    for (unsigned i = 0; i < k; i++) {
      if (iv[i].iov_len < kCopyFloor) {
        bytes(static_cast<const char*>(iv[i].iov_base), iv[i].iov_len);
        continue;
      }
      plan->iov[plan->iovlen++] =
          Http1::Plan::Seg{static_cast<const char*>(iv[i].iov_base), 0, iv[i].iov_len};
      plan->byte_total += iv[i].iov_len;
    }
  }

  // RFC 9110 8.6: the body a run LENT, as a POINTER into its own frozen
  // String. Without a plan there is no segment to hang it on, so the round
  // copies - correct either way, since the lend outlives this round.
  void lent(const char* p, size_t n) {
    if (plan == nullptr) {
      sink.append(p, n);
      emitted += n;
      return;
    }
    prime();
    plan->iov[plan->iovlen++] = Http1::Plan::Seg{p, 0, n};
    plan->byte_total += n;
  }
};
}

#define WM_H2_LOG_DEFINED
// RFC 9113 8.3: the method column, from the enum - the wire bytes are gone.
static const char* alog_method(flow::Method m, size_t* n) {
  switch (m) {
    case flow::Method::kGet: *n = 3; return "GET";
    case flow::Method::kHead: *n = 4; return "HEAD";
    case flow::Method::kPost: *n = 4; return "POST";
    case flow::Method::kPut: *n = 3; return "PUT";
    case flow::Method::kDelete: *n = 6; return "DELETE";
    case flow::Method::kOptions: *n = 7; return "OPTIONS";
    default: *n = 1; return "-";
  }
}

// RFC 9113: one answer, one access line, written where :path still lives.
void Http1::h2_log(Conn& st, const H2Logged& l) {
  if (!alog_.enabled) return;
  const flow::ReqFacts& facts = l.facts;
  const char* const target = l.target.data();
  const size_t tlen = l.target.size();
  size_t mn = 0;
  const char* m = alog_method(facts.method, &mn);
  log_access(alog_, {{static_cast<const char*>(st.peer), st.peer_len},
                     {m, mn},
                     {target, tlen},
                     {}, {},
                     alog_bytes_,
                     alog_status_,
                     static_cast<uint8_t>(kLogH2 | (facts.no_track ? kLogNoTrack : 0))});
}

// RFC 9113 6.9: one round of parked streams, as segments; the cursor keeps
// the cut fair between them.
// RFC 9113 6.1: carve the round into DATA frames. END_STREAM rides the
// frame that lands on the last byte - which is why the step carries the
// body's total and not just what this round gives. Returns what ACTUALLY
// went out: the round can run out of plan room mid-body, and then nothing
// ends.
// One stream, and what it may put on the wire this round.
struct H2Sending {
  const H2Stream& stream;
  const Http1::H2SendStep& step;
  size_t max_frame;
};

static size_t h2_emit(RoundOut& out, const H2Sending& sending) {
  const H2Stream& s = sending.stream;
  const Http1::H2SendStep& step = sending.step;
  const size_t max_frame = sending.max_frame;
  size_t off = 0;
  while (off < step.give) {
    if (!out.room_for_frame()) break;
    size_t n = step.give - off;
    if (n > max_frame) n = max_frame;
    const bool last = step.start + off + n == step.total;
    unsigned char fh[kH2FrameHeaderLen];
    const uint8_t end_flag = last ? kH2FlagEndStream : 0;
    h2_put_frame_header(fh, {static_cast<uint32_t>(n), kH2Data, end_flag, s.id});
    out.bytes(reinterpret_cast<const char*>(fh), sizeof(fh));
    switch (s.response_content.src) {
      case H2Stream::Content::Src::kAsset:
        out.span(*s.response_content.asset, step.start + off, n);
        break;
      case H2Stream::Content::Src::kLent: out.lent(s.response_content.lent + step.start + off, n); break;
      case H2Stream::Content::Src::kOwned:
        out.bytes(s.response_content.owned.data() + step.start + off, n);
        break;
      case H2Stream::Content::Src::kNone: break;
    }
    off += n;
  }
  return off;
}

// Both windows and the body's one cursor, from what really went out. The
// owned buffer used to erase from its front - a memmove per round to say
// what an offset says for free.
static void h2_advance(H2State& h2, H2Stream& s, size_t sent) {
  if (sent == 0) return;
  h2.flow_window -= static_cast<int64_t>(sent);
  s.flow_window -= static_cast<int64_t>(sent);
  s.response_content.sent += sent;
}

void Http1::h2_flush_pending(Conn& st0, std::string& sink, Plan* plan) {
  H2State& h2 = *st0.h2;
  RoundOut out{sink, plan};
  const size_t n_streams = h2.streams.size();
  if (n_streams == 0) return;
  size_t walked = 0;
  for (; walked < n_streams; walked++) {
    if (!out.room_for_frame()) break;
    H2Stream& stp = h2.streams[(h2.flush_cursor + walked) % n_streams];
    const H2SendStep step = h2_send_step(stp, h2.flow_window, kDeliverChunk);
    if (step.give == 0) continue;
    const size_t sent = h2_emit(out, {stp, step, h2.peer_max_frame});
    h2_advance(h2, stp, sent);
  }
  h2.flush_cursor = n_streams != 0 ? (h2.flush_cursor + walked) % n_streams : 0;
  for (size_t i = 0; i < h2.streams.size();) {
    H2Stream& stp = h2.streams[i];
    if (stp.end_headers && stp.half_closed_remote && !stp.response_content.owes()) {
      // close_stream RETIRES the lend rather than freeing it: its last
      // frames are in the round being built, not yet on the wire.
      h2.close_stream(stp.id);
    } else {
      i++;
    }
  }
}

// Does this connection still owe bytes? Asked before a send, for MSG_MORE.
bool Http1::pending(const Conn& st) const {
  if (st.h2 != nullptr) {
    for (const H2Stream& s : st.h2->streams) {
      if (s.response_content.owes()) return true;
    }
    return false;
  }
  // A file the reactor is still opening owes bytes too - and saying so is
  // what keeps `more` from re-feeding the carry ahead of that answer.
  // kDone is deliberately NOT owed bytes: its last lend has drained and it
  // only has bookkeeping left. Counting it here cost 60 us per request -
  // MSG_MORE corked the final send, and on_send took the arm_meminfo
  // detour (an io-wq round trip) in front of a round that sends nothing.
  return st.asset != nullptr ||
         (st.file != nullptr && st.file->stage != FileStage::kNone &&
          st.file->stage != FileStage::kDone);
}

// The continuation both protocols share: the sink has fully drained.
bool Http1::more(Conn& st, std::string& sink, Plan& plan) {
  // THE release point: the Ring reaches here only once a whole round has
  // drained, so a body lent to that round is off the wire. Before the next
  // one is built, so a connection never holds two.
  st.zc_release();
  // response.file, spelled: the head, then the window buffer or a chunk of
  // the mapping LENT as an external segment - the same door the asset tier
  // and a lent body use, so the bytes reach the kernel without a copy.
  if (st.file != nullptr && (st.file->stage == FileStage::kDeliver ||
                                         st.file->stage == FileStage::kDone)) {
    // The round is COMPUTED first and performed second. Everything that
    // used to be decided in the middle of doing - which window, whether the
    // mapping may go back, whether the access line is owed - is one value
    // now, and file_apply is the only thing that writes.
    const FileStep step = file_step(*st.file, send_chunk_);
    if (step.head) sink.append(st.file->head);
    if (step.src != FileStep::Src::kNone) {
      const char* base = step.src == FileStep::Src::kMapping ? st.file->map_addr
                                                             : st.file->buf.data();
      lend_body(st, sink, {{base + step.start, step.give}, plan});
    }
    file_apply(st, step);
    // Still owed: this round is spent.
    if (!step.clear) return true;
    // Over, and the connection ends with it.
    if (!step.persist) return false;
    // Over, and the connection lives: the kDone round put NOTHING on the
    // wire, so it does not get to consume the round - a pipelined request
    // waiting in the carry speaks below, in this same one. (Consuming it
    // wedged `response.file answers pipelined requests in order`: the
    // carry had no later round to be fed from.)
  }
  // The ring still owes the answer: nothing else may speak for this
  // connection until it lands, least of all the carry behind it.
  if (st.file != nullptr && st.file->stage != FileStage::kNone) return true;
  if (st.sse != nullptr) return sse_second(st.sse, sec_, sink);
  if (st.h2 != nullptr) {
    h2_flush_pending(st, sink, &plan);
    return true;
  }
  if (st.asset != nullptr) {
    const AssetEntry& e = *st.asset;
    const size_t lim = st.asset_end;
    size_t take = lim - st.asset_off;
    if (plan.byte_cap != 0 && take > plan.byte_cap) take = plan.byte_cap;
    struct iovec iv[3];
    const unsigned k = Assets::wire_iov(e, st.asset_off, take, iv);
    for (unsigned i = 0; i < k; i++) {
      plan.iov[plan.iovlen++] =
          Plan::Seg{static_cast<const char*>(iv[i].iov_base), 0, iv[i].iov_len};
    }
    plan.byte_total = take;
    st.asset_off += take;
    if (st.asset_off == lim) {
      st.asset = nullptr;
      st.asset_off = 0;
      st.asset_end = 0;
    }
    return true;
  }
  if (st.carry.empty()) return true;
  std::string held;
  held.swap(st.carry);
  return feed(st, held.data(), held.size(), sink, &plan);
}

// RFC 9113 4/6: the frame loop. A header block owns the connection until
// END_HEADERS (6.10).
bool Http1::h2_feed(Conn& st0, const char* data, size_t len, std::string& sink, Plan* plan) {
  H2State& h2 = *st0.h2;
  const bool in_place = st0.carry.empty();
  const char* view = data;
  size_t viewlen = len;
  if (!in_place) {
    st0.carry.append(data, len);
    view = st0.carry.data();
    viewlen = st0.carry.size();
  }

  size_t off = 0;
  while (viewlen - off >= kH2FrameHeaderLen) {
    const unsigned char* fh = reinterpret_cast<const unsigned char*>(view) + off;
    const uint32_t flen = h2_u24(fh);
    if (flen > kH2MaxFrameSize) return h2_error(st0, kH2FrameSizeError, sink);
    if (viewlen - off - kH2FrameHeaderLen < flen) break;
    const uint8_t type = fh[3];
    const uint8_t flags = fh[4];
    const uint32_t stream = h2_u31(fh + 5);
    const unsigned char* p = fh + kH2FrameHeaderLen;
    off += kH2FrameHeaderLen + flen;

    if (h2.frag_active && type != kH2Continuation) {
      return h2_error(st0, kH2ProtocolError, sink);
    }

    switch (type) {
      case kH2Data: {
        if (stream == 0) return h2_error(st0, kH2ProtocolError, sink);
        H2Stream* stp = h2.find(stream);
        if (stp == nullptr) {
          if (h2_is_idle(h2, stream)) return h2_error(st0, kH2ProtocolError, sink);
          h2_rst(st0, stream, kH2StreamClosed, sink);
          break;
        }
        if (!stp->end_headers || stp->half_closed_remote) {
          h2_rst(st0, stream, kH2StreamClosed, sink);
          break;
        }
        const unsigned char* dp = p;
        size_t dlen = flen;
        if (flags & kH2FlagPadded) {
          if (dlen < 1) return h2_error(st0, kH2ProtocolError, sink);
          const uint8_t pad = dp[0];
          dp++;
          dlen--;
          if (pad > dlen) return h2_error(st0, kH2ProtocolError, sink);
          dlen -= pad;
        }
        if (stp->content_received + dlen > kMaxBody) {
          h2_rst(st0, stream, kH2RefusedStream, sink);
          break;
        }
        stp->content_received += dlen;
        // Stored only where a bound resource will read them - a konst
        // route's or a miss's bytes are counted and dropped, so idle
        // streams cannot hold megabytes nobody will ever ask for.
        if (stp->route != kNoRoute &&
            bundles_[apps_[st0.listener].base + stp->route].bound) {
          stp->request_content.append(reinterpret_cast<const char*>(dp), dlen);
        }
        if (flen != 0) {
          unsigned char inc[4];
          put_u32(inc, flen);
          emit_control(sink, {kH2WindowUpdate, 0, 0, inc});
          emit_control(sink, {kH2WindowUpdate, 0, stream, inc});
        }
        if (flags & kH2FlagEndStream) {
          if (stp->content_length_given && stp->content_received != stp->content_length) {
            h2_rst(st0, stream, kH2ProtocolError, sink);
            break;
          }
          stp->half_closed_remote = true;
          const flow::ReqFacts facts = stp->facts;
          const bool head_only = stp->head_method;
          const uint16_t route = stp->route;
          const std::string target = stp->request_target;
          std::string body;
          body.swap(stp->request_content);
          // The fields the HEADERS frame copied when this stream parked,
          // rebuilt over the blob that outlived hdrbuf's reuse.
          struct phr_header hv[kH2MaxFields];
          size_t nh = stp->field_spans.size() / 4;
          if (nh > kH2MaxFields) nh = kH2MaxFields;
          for (size_t i = 0; i < nh; i++) {
            hv[i].name = stp->field_blob.data() + stp->field_spans[i * 4];
            hv[i].name_len = stp->field_spans[i * 4 + 1];
            hv[i].value = stp->field_blob.data() + stp->field_spans[i * 4 + 2];
            hv[i].value_len = stp->field_spans[i * 4 + 3];
          }
          // RFC 9110 12.5: the values negotiation reads point into hdrbuf
          // too, so a parked answer had none and every request that named
          // an Accept was refused 406 for a header it had actually sent.
          // Re-derived from the copied fields, which is the only place
          // they still exist.
          http::ReqValues pvals;
          values_of_copied_fields({hv, nh}, pvals);
          ReqView rv;
          // h2_parked_view only knows the target - the method and the DATA
          // bytes come from the stream that carried them.
          rv.method = facts.method;
          rv.content = body.empty() ? nullptr : body.data();
          rv.content_len = body.size();
          rv.fields = nh != 0 ? hv : nullptr;
          rv.field_count = nh;
          const ReqView* rvp = h2_parked_view(st0, target, rv);
          const H2Request q{stream, facts, &pvals, rvp, target, route, head_only};
          if (!h2_answer(st0, q, sink)) {            return false;
          }
          h2_log(st0, {facts, target});
        }
        break;
      }

      case kH2Headers: {
        if (stream == 0 || (stream & 1) == 0) return h2_error(st0, kH2ProtocolError, sink);
        if (h2.find(stream) == nullptr && !h2_is_idle(h2, stream)) {
          return h2_error(st0, kH2ProtocolError, sink);
        }
        const unsigned char* hp = p;
        size_t hlen = flen;
        if (flags & kH2FlagPadded) {
          if (hlen < 1) return h2_error(st0, kH2ProtocolError, sink);
          const uint8_t pad = hp[0];
          hp++;
          hlen--;
          if (pad > hlen) return h2_error(st0, kH2ProtocolError, sink);
          hlen -= pad;
        }
        if (flags & kH2FlagPriority) {
          if (hlen < 5) return h2_error(st0, kH2FrameSizeError, sink);
          if (h2_u31(hp) == stream) return h2_error(st0, kH2ProtocolError, sink);
          hp += 5;
          hlen -= 5;
        }
        if (flags & kH2FlagEndHeaders) {
          // The whole block is already contiguous in the recv buffer, so
          // it is decoded where it lies; frag exists for the split that
          // CONTINUATION makes, and this is not one.
          h2.frag_active = false;
          const H2Headers head = {stream, (flags & kH2FlagEndStream) != 0, {hp, hlen}};
          if (!h2_dispatch(st0, head, sink)) return false;
          break;
        }
        if (hlen > kH2FragBudget) return h2_error(st0, kH2EnhanceYourCalm, sink);
        h2.frag.assign(reinterpret_cast<const char*>(hp), hlen);
        h2.frag_stream = stream;
        h2.frag_flags = flags;
        h2.frag_active = true;
        break;
      }

      case kH2Continuation: {
        if (!h2.frag_active || stream != h2.frag_stream) {
          return h2_error(st0, kH2ProtocolError, sink);
        }
        if (h2.frag.size() + flen > kH2FragBudget) {
          return h2_error(st0, kH2EnhanceYourCalm, sink);
        }
        h2.frag.append(reinterpret_cast<const char*>(p), flen);
        if (flags & kH2FlagEndHeaders) {
          h2.frag_active = false;
          const H2Headers head = {
              h2.frag_stream, (h2.frag_flags & kH2FlagEndStream) != 0,
              {reinterpret_cast<const unsigned char*>(h2.frag.data()), h2.frag.size()}};
          if (!h2_dispatch(st0, head, sink)) return false;
        }
        break;
      }

      case kH2Priority:
        if (stream == 0) return h2_error(st0, kH2ProtocolError, sink);
        if (flen != 5) return h2_error(st0, kH2FrameSizeError, sink);
        if (h2_u31(p) == stream) return h2_error(st0, kH2ProtocolError, sink);
        break;

      case kH2RstStream:
        if (stream == 0) return h2_error(st0, kH2ProtocolError, sink);
        if (flen != 4) return h2_error(st0, kH2FrameSizeError, sink);
        if (h2.find(stream) == nullptr && h2_is_idle(h2, stream)) {
          return h2_error(st0, kH2ProtocolError, sink);
        }
        h2.close_stream(stream);
        break;

      case kH2Settings: {
        if (stream != 0) return h2_error(st0, kH2ProtocolError, sink);
        if (flags & kH2FlagAck) {
          if (flen != 0) return h2_error(st0, kH2FrameSizeError, sink);
          break;
        }
        if (flen % 6 != 0) return h2_error(st0, kH2FrameSizeError, sink);
        for (uint32_t e = 0; e < flen; e += 6) {
          const uint16_t id = h2_u16(p + e);
          const uint32_t v = h2_u32(p + e + 2);
          switch (id) {
            case kH2SettingsHeaderTableSize:
              // Clamped, never forwarded raw: this is a peer-chosen
              // 32-bit number and neither RFC 9113 6.5.2 nor RFC 7541
              // 4.2 bounds it. Encoding with a SMALLER table than the
              // peer permits is always legal, so the ceiling is ours.
              lshpack_enc_set_max_capacity(&h2.enc,
                                           v > kH2EncTableMax ? kH2EncTableMax : v);
              break;
            case kH2SettingsEnablePush:
              if (v > 1) return h2_error(st0, kH2ProtocolError, sink);
              break;
            case kH2SettingsInitialWindowSize: {
              if (v > kH2WindowCeiling) return h2_error(st0, kH2FlowControlError, sink);
              const int64_t delta = static_cast<int64_t>(v) - h2.peer_initial_window;
              h2.peer_initial_window = static_cast<int64_t>(v);
              for (H2Stream& stp : h2.streams) stp.flow_window += delta;
              break;
            }
            case kH2SettingsMaxFrameSize:
              if (v < 16384 || v > 16777215) return h2_error(st0, kH2ProtocolError, sink);
              h2.peer_max_frame = v > kH2MaxFrameSize ? kH2MaxFrameSize : v;
              break;
            default:
              break;
          }
        }
        emit_control(sink, {kH2Settings, kH2FlagAck, 0, {}});
        break;
      }

      case kH2PushPromise:
        return h2_error(st0, kH2ProtocolError, sink);

      case kH2Ping:
        if (stream != 0 || flen != 8) return h2_error(st0, kH2FrameSizeError, sink);
        if (!(flags & kH2FlagAck)) emit_control(sink, {kH2Ping, kH2FlagAck, 0, {p, 8}});
        break;

      case kH2Goaway:
        if (flen < 8) return h2_error(st0, kH2FrameSizeError, sink);
        h2.goaway_recv = true;
        break;

      case kH2WindowUpdate: {
        if (flen != 4) return h2_error(st0, kH2FrameSizeError, sink);
        const uint32_t inc = h2_u31(p);
        if (inc == 0) return h2_error(st0, kH2ProtocolError, sink);
        if (stream == 0) {
          h2.flow_window += inc;
          if (h2.flow_window > kH2WindowCeiling) {
            return h2_error(st0, kH2FlowControlError, sink);
          }
        } else if (H2Stream* stp = h2.find(stream)) {
          stp->flow_window += inc;
          if (stp->flow_window > kH2WindowCeiling) {
            h2_rst(st0, stream, kH2FlowControlError, sink);
            break;
          }
        } else if (h2_is_idle(h2, stream)) {
          return h2_error(st0, kH2ProtocolError, sink);
        }
        h2_flush_pending(st0, sink, nullptr);
        break;
      }

      default:
        break;
    }
  }

  if (in_place) {
    if (off < viewlen) st0.carry.assign(view + off, viewlen - off);
  } else {
    st0.carry.erase(0, off);
  }
  h2_flush_pending(st0, sink, plan);
  return !h2.goaway_recv;
}
}
