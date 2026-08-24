// The h2 half of the app: preface, frames, streams, flow control
// (RFC 9113). The same konst vectors, the same run frame, the same
// sink - a connection that spoke the preface routes its bytes here
// instead of through phr, and only the serialization differs: HPACK +
// HEADERS/DATA frames instead of prebuilt h1 heads. Ported from the
// h2c-frames branch (96ebdda) onto the Ring<App> seams.
//
// Deliberately absent, per RFC 9113: priority trees (deprecated
// there), server push (8.4 forbids the client side, nothing here
// wants the server side). Request bodies are COUNTED and discarded -
// exactly the tier the h1 framer is at (no consumer until the
// POST/PUT tier delivers bodies).

#include "webmachine.hpp"

#include <cstring>


namespace webmachine {
namespace {

// Room for the decoded fields of one request: kMaxHeaders regular
// ones plus the pseudo-fields h2 moves out of the request line.
constexpr size_t kH2MaxFields = kMaxHeaders + 8;
// A header block may span CONTINUATIONs; twice the h1 head budget
// bounds the compressed side (the decoded side is bounded per field
// in the decode loop).
constexpr size_t kH2FragBudget = kMaxHead * 2;
// Up to this much konst body rides in the per-connection response
// cache, so head and body leave as one append (h2_answer). Past it
// the memmove dominates the per-call overhead the merge saves, and
// the copy is per CONNECTION - the trade stops paying.
constexpr size_t kH2MergeBody = 1024;

void put_u32(unsigned char* p, uint32_t v) {
  p[0] = static_cast<unsigned char>(v >> 24);
  p[1] = static_cast<unsigned char>(v >> 16);
  p[2] = static_cast<unsigned char>(v >> 8);
  p[3] = static_cast<unsigned char>(v);
}

// One control frame, header + fixed payload, straight into the sink.
void emit_control(std::string& sink, uint8_t type, uint8_t flags, uint32_t stream,
                  const unsigned char* payload, uint32_t len) {
  unsigned char fh[kH2FrameHeaderLen];
  h2_put_frame_header(fh, len, type, flags, stream);
  sink.append(reinterpret_cast<const char*>(fh), sizeof(fh));
  if (len != 0) sink.append(reinterpret_cast<const char*>(payload), len);
}

// HPACK string length: 7-bit prefix integer, H bit 0 - no Huffman on
// the way out (RFC 7541 5.2).
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

// Literal field without indexing, indexed name: 4-bit prefix integer
// (RFC 7541 6.2.2) - never-indexed responses keep the blocks
// connection-independent, which is what makes precomputing them legal.
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

}  // namespace

void h2_free(H2State* h2) { delete h2; }

// The request view for a PARKED request (#116 slice 4): its bytes are
// the stream's own copy, and the spans have to be captured again -
// the ones the dispatch computed died with that frame. One table walk,
// paid only by a request that carried a body, which allocated for its
// body long before it got here. The route it finds is the route the
// dispatch found: the same table, the same bytes, the same order.
const ReqView* Http1::h2_parked_view(Conn& st0, const std::string& target, ReqView& out) {
  if (target.empty()) return nullptr;
  const AppSlot& slot = apps_[st0.listener];
  const int r = slot.table->match(target.data(), target.size(), out.spans);
  if (r < 0) return nullptr;
  out.target = target.data();
  out.target_len = target.size();
  out.path_len = http::path_only(target.data(), target.size());
  out.table = slot.table;
  out.route = r;
  return &out;
}

// Lane 2: one per-request response field through ls-hpack's encoder
// and its dynamic table. lsxpack's canonical layout is name ": "
// value in one buffer; the ": " is what LSHPACK_DEC_HTTP1X_OUTPUT
// builds expect between the offsets, kept even though this build does
// not set it. False = buffer exhausted (the caller's connection
// error). The date is its standing caller (it CHANGES, per second);
// the value tiers (etag, location, ...) join it when they land.
bool Http1::h2_enc_field(void* encp, unsigned char*& ep, unsigned char* eend,
                         const char* name, size_t nlen, const char* val, size_t vlen) {
  struct lshpack_enc* enc = static_cast<struct lshpack_enc*>(encp);
  char hbuf[512];
  if (nlen + 2 + vlen > sizeof(hbuf)) return false;
  std::memcpy(hbuf, name, nlen);
  hbuf[nlen] = ':';
  hbuf[nlen + 1] = ' ';
  std::memcpy(hbuf + nlen + 2, val, vlen);
  lsxpack_header_t xh;
  lsxpack_header_set_offset2(&xh, hbuf, 0, nlen, nlen + 2, vlen);
  unsigned char* np = lshpack_enc_encode(enc, ep, eend, &xh);
  if (np == ep) return false;
  ep = np;
  return true;
}

// Lane 1, one precomputed response header block - ONLY what never
// changes: :status rides its static-table entry where one exists (RFC
// 7541 6.1, Appendix A idx 8-14) or a literal without indexing;
// content-type and allow are konst per resource. The date is NOT here:
// it changes (per second), so it speaks through ls-hpack (lane 2),
// where the connection's dynamic table turns it into a one-byte
// reference for both sides until the second rolls.
void Http1::h2_build_block(H2Block& b, uint16_t status, const std::string* ctype,
                           const std::string* allow) {
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
      hp_name_idx(b.bytes, 8);  // :status, literal value
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
    hp_name_idx(b.bytes, 31);  // content-type
    hp_len(b.bytes, ctype->size());
    b.bytes.append(*ctype);
  }
  if (allow != nullptr && !allow->empty()) {
    b.bytes.push_back(0x00);  // literal without indexing, new name
    hp_len(b.bytes, 5);
    b.bytes.append("allow", 5);
    hp_len(b.bytes, allow->size());
    b.bytes.append(*allow);
  }
}

bool Http1::h2_begin(Conn& st, std::string& sink) {
  st.h2 = new H2State();
  // The server side of the connection preface is a SETTINGS frame
  // (RFC 9113 3.4). One entry: the concurrency cap; everything else
  // keeps its default and saying so would only be bytes.
  unsigned char payload[6];
  payload[0] = 0;
  payload[1] = kH2SettingsMaxConcurrentStreams;
  put_u32(payload + 2, kH2MaxConcurrentStreams);
  emit_control(sink, kH2Settings, 0, 0, payload, sizeof(payload));
  return true;
}

bool Http1::h2_error(Conn& st, uint32_t code, std::string& sink) {
  H2State& h2 = *st.h2;
  // The connection is done; whatever else it sent will not be read.
  st.carry.clear();
  if (!h2.goaway_sent) {
    unsigned char payload[8];
    put_u32(payload, h2.last_stream);
    put_u32(payload + 4, code);
    emit_control(sink, kH2Goaway, 0, 0, payload, sizeof(payload));
    h2.goaway_sent = true;
  }
  return false;  // feed's contract: close once the sink has drained
}

// RFC 9113 5.1's three states, out of two numbers: a stream in the
// table is OPEN (or half-closed), an id above everything ever accepted
// is IDLE, and anything else is CLOSED. Idle and closed earn different
// errors on almost every frame type, which is the whole reason this
// exists.
static bool h2_is_idle(const H2State& h2, uint32_t id) { return id > h2.highest_opened; }

void Http1::h2_rst(Conn& st, uint32_t stream_id, uint32_t code, std::string& sink) {
  unsigned char payload[4];
  put_u32(payload, code);
  emit_control(sink, kH2RstStream, 0, stream_id, payload, sizeof(payload));
  st.h2->close_stream(stream_id);
}

// Decode the accumulated header block; dispatch, or park the facts on
// the stream when a body is still owed. False only when the
// CONNECTION died - stream-level refusals return true and the frame
// loop carries on.
bool Http1::h2_dispatch(Conn& st0, uint32_t stream_id, bool end_stream, std::string& sink) {
  H2State& h2 = *st0.h2;

  // Decode into the shared buffer; quads carry offsets because the
  // buffer relocates as it grows.
  // `used` is the cursor the old code kept in hdrbuf.size() - and that
  // is why it is a cursor now. resize() VALUE-INITIALIZES, so growing
  // the buffer per field zeroed 4 KiB of scratch ls-hpack overwrites
  // immediately: 16 KiB per 4-field request, measured on forgecore as
  // the single largest h2-over-h1 cost (+2.42% in memset, more than
  // h2_answer itself). Keeping the high-water mark instead means the
  // zeroing happens on a connection's FIRST request and never again -
  // and the buffer stops relocating mid-decode, which is what the
  // offsets in `quads` existed to survive.
  uint32_t quads[4 * kH2MaxFields];
  size_t nq = 0;
  size_t used = 0;
  const unsigned char* p = reinterpret_cast<const unsigned char*>(h2.frag.data());
  const unsigned char* end = p + h2.frag.size();
  while (p < end) {
    if (nq + 4 > 4 * kH2MaxFields) return h2_error(st0, kH2EnhanceYourCalm, sink);
    // A field larger than the request-header budget is refused either
    // way; one slot of that size is the decode ceiling per field.
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
    used += xh.val_offset + xh.val_len;
  }
  h2.frag.clear();

  H2Stream* existing = h2.find(stream_id);
  if (existing != nullptr && existing->headers_done) {
    // Trailers (RFC 9113 8.1): legal only as the very end of the
    // request; their fields are decoded (the dynamic table demands
    // it) and not forwarded.
    if (!end_stream || existing->half_closed_remote) {
      return h2_error(st0, kH2ProtocolError, sink);
    }
    existing->half_closed_remote = true;
    const flow::ReqFacts facts = existing->facts;
    const bool head_only = existing->head_only;
    const AssetEntry* asset = existing->asset;
    const uint16_t asset_status = existing->asset_status;
    const size_t asset_off = existing->asset_off;
    const size_t asset_end = existing->asset_end;
    const uint16_t route = existing->route;
    const std::string target = existing->target;
    if (asset != nullptr) {
      if (!h2_asset_answer(st0, stream_id, *asset, asset_status, head_only, asset_off,
                           asset_end, sink)) {
        return false;
      }
      h2_log(st0, facts, target.data(), target.size());
      return true;
    }
    ReqView rv;
    const ReqView* rvp = h2_parked_view(st0, target, rv);
    if (!h2_answer(st0, stream_id, facts, head_only, route, rvp, sink)) return false;
    h2_log(st0, facts, target.data(), target.size());
    return true;
  }

  // Facts from the decoded fields. RFC 9113 8.3: pseudo-fields first,
  // exactly one :method/:scheme/:path; 8.2: field names lowercase;
  // 8.2.2: connection-specific fields make the request malformed.
  flow::ReqFacts facts;
  http::ReqValues vals;  // borrows hdrbuf; dead once this dispatch answers
  const char* path_val = nullptr;
  size_t path_vlen = 0;
  bool ok = true, saw_regular = false;
  bool have_method = false, have_path = false, have_scheme = false, have_authority = false;
  // 8.1.2.6: what the request CLAIMS its body is. Compared against the
  // DATA that actually arrives - here if this dispatch is the whole
  // request, on the stream if a body follows.
  size_t claimed_len = 0;
  bool have_claimed_len = false;
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
      // 8.3: exactly ONE of each pseudo-field. A second one is not a
      // later value winning - it is a malformed request.
      if (nlen == 7 && std::memcmp(name, ":method", 7) == 0) {
        if (have_method) { ok = false; break; }
        have_method = true;
        facts.method = http::parse_method(val, vlen);
      } else if (nlen == 5 && std::memcmp(name, ":path", 5) == 0) {
        if (path_val != nullptr) { ok = false; break; }
        have_path = vlen != 0;
        path_val = val;  // the asset tier reads it; the router (#116) will too
        path_vlen = vlen;
      } else if (nlen == 7 && std::memcmp(name, ":scheme", 7) == 0) {
        if (have_scheme) { ok = false; break; }
        have_scheme = true;  // h2c: the scheme is a claim, the socket is the fact
      } else if (nlen == 10 && std::memcmp(name, ":authority", 10) == 0) {
        if (have_authority) { ok = false; break; }
        have_authority = true;  // host's seat; nothing reads it at this tier
      } else {
        ok = false;
      }
      continue;
    }
    saw_regular = true;
    for (size_t j = 0; j < nlen; j++) {
      if (name[j] >= 'A' && name[j] <= 'Z') {
        ok = false;
        break;
      }
    }
    if (!ok) break;
    http::header_switch(name, nlen, val, vlen, facts, vals,
                        [&](const char* n, size_t nl, const char* v, size_t vl) {
                          // Connection-specific fields are malformed per
                          // 8.2.2; content-length is a CLAIM to be
                          // checked against the DATA (8.1.2.6); te may
                          // say "trailers" and nothing else (8.2.2).
                          switch (nl) {
                            case 2:
                              if (http::tok_eq(n, nl, "te", 2) &&
                                  !(vl == 8 && http::tok_eq(v, vl, "trailers", 8))) {
                                ok = false;
                              }
                              break;
                            case 14:
                              if (http::tok_eq(n, nl, "content-length", 14)) {
                                if (have_claimed_len) { ok = false; break; }
                                have_claimed_len = true;
                                if (http::parse_content_length(v, vl, &claimed_len) !=
                                    http::ClStatus::kOk) {
                                  ok = false;
                                }
                              }
                              break;
                            case 10:
                              if (http::tok_eq(n, nl, "connection", 10) ||
                                  http::tok_eq(n, nl, "keep-alive", 10)) {
                                ok = false;
                              }
                              break;
                            case 17:
                              if (http::tok_eq(n, nl, "transfer-encoding", 17)) ok = false;
                              break;
                            case 7:
                              if (http::tok_eq(n, nl, "upgrade", 7)) ok = false;
                              break;
                            default:
                              break;
                          }
                        });
  }
  if (!ok || !have_method || !have_path || !have_scheme) {
    // A malformed request is a stream error (8.1.1), not a connection
    // error; the frame loop carries on.
    h2_rst(st0, stream_id, kH2ProtocolError, sink);
    return true;
  }

  if (stream_id > h2.last_stream) h2.last_stream = stream_id;
  // The state machine's other half (5.1): from here this id counts as
  // used, so a later frame naming it - or naming a SMALLER one - is
  // measured against a stream that once existed rather than an idle
  // one.
  if (stream_id > h2.highest_opened) h2.highest_opened = stream_id;
  // The cap counts streams the connection still OWES something - a body
  // to arrive, or a parked remainder to drain. One answered inside its
  // own dispatch owes nothing and never enters the table, so it cannot
  // occupy a slot (RFC 9113 5.1.2 counts open streams, and it is not
  // one by the time the next frame is read).
  if (h2.streams.size() >= kH2MaxConcurrentStreams) {
    // We announced the cap in our SETTINGS; a peer past it is refused
    // per stream, not per connection.
    h2_rst(st0, stream_id, kH2RefusedStream, sink);
    return true;
  }
  const bool head_only = facts.method == flow::Method::kHead;

  // The asset tier (#170): resolved NOW, while the value pointers
  // still live in hdrbuf - what survives into a parked stream is the
  // entry and the finished verdict.
  const AssetEntry* asset = nullptr;
  uint16_t asset_status = 0;
  size_t asset_off = 0;
  size_t asset_end = 0;
  if (assets_ != nullptr) {
    if (AssetEntry* ae = assets_->find(path_val, path_vlen)) {
      asset = ae;
      asset_status = assets_->verdict(*ae, facts.method, facts, vals);
      asset_end = Assets::wire_len(*ae);
      // Range (#148), resolved here for the same reason the verdict
      // is: GET only, 200 only, past a matching If-Range; ignored
      // forms serve the full 200 (h1's rules, verbatim).
      if (asset_status == 200 && !head_only && facts.method == flow::Method::kGet &&
          vals.range != nullptr &&
          (vals.if_range == nullptr ||
           http::if_range_matches(vals.if_range, vals.if_range_len, ae->etag,
                                  sizeof(ae->etag)))) {
        size_t rf = 0, rl = 0;
        switch (http::parse_range(vals.range, vals.range_len, asset_end, &rf, &rl)) {
          case http::RangeParse::kOne:
            asset_status = 206;
            asset_off = rf;
            asset_end = rl + 1;
            break;
          case http::RangeParse::kUnsat: asset_status = 416; break;
          case http::RangeParse::kNone: break;
        }
      }
    }
  }

  // THE ROUTER (#116), the SAME table h1 walks, in the same
  // registration order - resolved NOW, while the :path bytes still
  // live in hdrbuf, exactly like the asset verdict above. What
  // survives into a parked stream is the index, never a pointer into
  // the decode buffer.
  RouteSpans spans;
  const int r = apps_[st0.listener].table->match(path_val, path_vlen, spans);
  const uint16_t route = r < 0 ? kNoRoute : static_cast<uint16_t>(r);

  if (end_stream) {
    // 8.1.2.6: END_STREAM here means no DATA is coming, so a non-zero
    // content-length was a claim about a body that never existed.
    if (have_claimed_len && claimed_len != 0) {
      h2_rst(st0, stream_id, kH2ProtocolError, sink);
      return true;
    }
    if (asset != nullptr) {
      if (!h2_asset_answer(st0, stream_id, *asset, asset_status, head_only, asset_off,
                           asset_end, sink)) {
        return false;
      }
      h2_log(st0, facts, path_val, path_vlen);
      return true;
    }
    // h2.hpp already claimed this ("A stream answered in full inside
    // its own dispatch never appears here"); it just was not true yet.
    // Opening it here only to close it at the end of h2_answer cost an
    // emplace_back with a std::string member, two more linear scans and
    // the matching destructor - per request, on the hot path. The facts
    // are on this stack, which is all the answer needs; h2_answer opens
    // a stream itself if the peer's window parks a remainder.
    // The request object's view, on THIS frame: the :path bytes are
    // still in the decode buffer and the spans are still in registers.
    ReqView rv;
    rv.target = path_val;
    rv.target_len = path_vlen;
    rv.path_len = http::path_only(path_val, path_vlen);
    rv.method = facts.method;
    rv.table = apps_[st0.listener].table;
    rv.route = r;
    rv.spans = spans;
    if (!h2_answer(st0, stream_id, facts, head_only, route, r < 0 ? nullptr : &rv, sink)) {
      return false;
    }
    h2_log(st0, facts, path_val, path_vlen);
    return true;
  }
  // A body follows; THAT is what the stream has to be remembered for -
  // the facts wait on it, the bytes will not.
  H2Stream& stx = h2.open(stream_id);
  stx.headers_done = true;
  stx.facts = facts;
  stx.head_only = head_only;
  stx.asset = asset;
  stx.asset_status = asset_status;
  stx.asset_off = asset_off;
  stx.asset_end = asset_end;
  stx.route = route;
  // #116 slice 4: what a callback will be allowed to ask about, kept
  // because this request answers after its decode buffer is gone.
  stx.target.assign(path_val, path_vlen);
  stx.content_length = claimed_len;
  stx.have_content_length = have_claimed_len;
  return true;
}

// The asset tier's h2 setup half: never-indexed blocks per entry (the
// same lane-1 discipline h2_build_block has), spelled here because the
// HPACK helpers live in this file. Static-table name indexes are RFC
// 7541 Appendix A: content-type 31, content-encoding 26, vary 59,
// etag 34, last-modified 44.
void Http1::h2_build_asset_blocks(AssetEntry& e) {
  std::string& b = e.h2_200;
  b.clear();
  b.push_back(static_cast<char>(0x88));  // :status 200, indexed
  hp_name_idx(b, 31);
  hp_len(b, e.ctype.size());
  b.append(e.ctype);
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
  if (e.lm_valid) {
    hp_name_idx(b, 44);
    hp_len(b, sizeof(e.lm));
    b.append(e.lm, sizeof(e.lm));
  }
  hp_name_idx(b, 18);  // accept-ranges (#148): advertised because true
  hp_len(b, 5);
  b.append("bytes", 5);

  std::string& c = e.h2_304;
  c.clear();
  c.push_back(static_cast<char>(0x8b));  // :status 304, indexed
  hp_name_idx(c, 34);
  hp_len(c, sizeof(e.etag));
  c.append(e.etag, sizeof(e.etag));
  if (e.deflated) {
    hp_name_idx(c, 59);
    hp_len(c, 15);
    c.append("Accept-Encoding", 15);
  }
}

void Http1::h2_build_asset_shared() {
  static const std::string kAllow = "GET, HEAD";
  h2_build_block(h2_asset405_, 405, nullptr, &kAllow);
  h2_build_block(h2_asset406_, 406, nullptr, nullptr);
  hp_name_idx(h2_asset406_.bytes, 59);  // vary: the 406 varies by AE too
  hp_len(h2_asset406_.bytes, 15);
  h2_asset406_.bytes.append("Accept-Encoding", 15);
}

// The asset answer: same window/park discipline as h2_answer, body as
// segments over the mapping (gzip header + deflate bytes + trailer for
// method 8; the stored bytes alone for method 0) instead of one
// contiguous buffer. Bypasses the head_cache - it is keyed by status
// alone and asset heads differ per entry.
bool Http1::h2_asset_answer(Conn& st0, uint32_t stream_id, const AssetEntry& e,
                            uint16_t status, bool head_only, size_t win_off, size_t win_end,
                            std::string& sink) {
  H2State& h2 = *st0.h2;
  std::string rblk;  // 206/416 blocks carry request numbers: built per request (rare path)
  const std::string* blk;
  switch (status) {
    case 200: blk = &e.h2_200; break;
    case 206: {
      rblk.push_back(static_cast<char>(0x8a));  // :status 206, indexed
      hp_name_idx(rblk, 31);
      hp_len(rblk, e.ctype.size());
      rblk.append(e.ctype);
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
      hp_name_idx(rblk, 30);  // content-range
      const std::string cr = "bytes " + std::to_string(win_off) + "-" +
                             std::to_string(win_end - 1) + "/" +
                             std::to_string(Assets::wire_len(e));
      hp_len(rblk, cr.size());
      rblk.append(cr);
      blk = &rblk;
      break;
    }
    case 416: {
      hp_name_idx(rblk, 8);  // :status literal
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
    case 304: blk = &e.h2_304; break;
    case 405: blk = &h2_asset405_.bytes; break;
    case 406: blk = &h2_asset406_.bytes; break;
    default: blk = &h2_store_[index_[status]].bytes; break;  // 412/501: the shared store
  }

  const bool has_body = status == 200 || status == 206;
  const size_t blen = has_body ? win_end - win_off : 0;
  const bool no_data = head_only || blen == 0;
  alog_status_ = status;
  alog_bytes_ = no_data ? 0 : blen;

  // The date rides the encoder lane, as everywhere.
  unsigned char dbuf[64];
  unsigned char* dp = dbuf;
  if (!h2_enc_field(&h2.enc, dp, dbuf + sizeof(dbuf), "date", 4, date_, sizeof(date_))) {
    return h2_error(st0, kH2InternalError, sink);
  }
  const size_t dlen = static_cast<size_t>(dp - dbuf);

  unsigned char fh[kH2FrameHeaderLen];
  h2_put_frame_header(fh, static_cast<uint32_t>(blk->size() + dlen), kH2Headers,
                      kH2FlagEndHeaders | (no_data ? kH2FlagEndStream : 0), stream_id);
  sink.append(reinterpret_cast<const char*>(fh), sizeof(fh));
  sink.append(*blk);
  sink.append(reinterpret_cast<const char*>(dbuf), dlen);

  if (no_data) {
    h2.close_stream(stream_id);
    return true;
  }

  // The body is PARKED, never copied - not even a first chunk. Three
  // numbers (#168: no byte lies in the park, an offset does; absolute
  // wire offsets, so a 206 window parks exactly like a full body), and
  // h2_flush_pending delivers them as a plan: frame headers as sink
  // runs, payload as pointers into the mapping. When h2_feed holds a
  // plan the flush runs at ITS end, so the body leaves in the SAME
  // sendmsg as these headers; otherwise (a send in flight) the next
  // drained sink or WINDOW_UPDATE picks it up. All window accounting
  // lives in the flush - nothing is debited here, because nothing is
  // sent here (RFC 9113 6.9: debits follow DATA, and this function no
  // longer emits any).
  H2Stream& keep = h2.open(stream_id);
  keep.src = &e;
  keep.src_off = win_off;
  keep.src_len = win_end;
  keep.headers_done = true;
  keep.half_closed_remote = true;
  return true;
}

bool Http1::h2_answer(Conn& st0, uint32_t stream_id, const flow::ReqFacts& facts,
                      bool head_only, uint16_t route, const ReqView* req,
                      std::string& sink) {
  H2State& h2 = *st0.h2;

  // The router's verdict decides who answers, exactly as in h1: a miss
  // is 404 out of the generic table, before B13 and before any method
  // test. Otherwise the same decision the h1 path makes: konst
  // resources never see the VM, anything dynamic runs the whole flow
  // inside ONE VM frame.
  const Bundle* b = nullptr;
  const std::array<uint16_t, 600>* idx = &index_;
  uint16_t status;
  bool have_body = false;
  if (route == kNoRoute) {
    status = 404;
  } else {
    // The route index is the APP's, so it needs the app's base - the
    // listener says which app, exactly as in h1's feed.
    b = &bundles_[apps_[st0.listener].base + route];
    idx = &b->index;
    if (b->bound) {
      status = resource_run(*b->res, facts, req, &body_, &have_body);
    } else {
      status = flow::answer(facts, b->konst.per_method[static_cast<size_t>(facts.method)],
                           b->konst.shortcut[static_cast<size_t>(facts.method)]);
    }
  }

  const char* body = nullptr;
  size_t blen = 0;
  const H2Block* blk;
  if (have_body && status == 200) {
    body = body_.data();
    blen = body_.size();
    blk = &h2_store_[(*idx)[200]];
  } else if (status == 500 && b != nullptr && b->bound) {
    // A raising callback answers in the negotiated type, the reason as
    // body; the lent bytes are appended (copied) before any next mruby
    // call can run.
    const char* bp = nullptr;
    size_t bl = 0;
    if (resource_exception_begin(*b->res, &bp, &bl)) {
      body = bp;
      blen = bl;
      blk = &b->h2_err;
    } else {
      blk = &h2_store_[(*idx)[500]];
    }
  } else if (status == 200) {
    body = b->konst.body.data();
    blen = b->konst.body.size();
    blk = &h2_store_[(*idx)[200]];
  } else {
    // Every status block was precomputed at setup (405 carries Allow,
    // RFC 9110 10.2.1); 204/304 are bodyless and every other status
    // sends no body at this tier - DATA framing already delimits, so
    // there is no Content-Length to spell (RFC 9113 8.1.1).
    blk = &h2_store_[(*idx)[status]];
  }

  // HEAD answers with the head and no DATA; its render already ran for
  // parity with h1 (the Content-Length h1 announces is the GET's).
  const bool no_data = head_only || blen == 0;

  // For h2_log, which runs right after this answer returns. %b is the
  // full body length even when the peer's window parks a remainder -
  // the same "what the answer says, not what this round sent" h1 logs.
  alog_status_ = status;
  alog_bytes_ = no_data ? 0 : blen;

  // The cache is rebuilt when the status changes or the second rolls -
  // so a MISS is the rare case, not the per-response default, and the
  // encoder sees a genuinely new date at most once per second per
  // connection. Both frames are built here, back to back, because the
  // answer wants to leave as ONE append.
  if (h2.head_cache.status != status || h2.head_cache.route != route ||
      h2.head_cache.sec != sec_) {
    unsigned char dbuf[64];
    unsigned char* dp = dbuf;
    if (!h2_enc_field(&h2.enc, dp, dbuf + sizeof(dbuf), "date", 4, date_, sizeof(date_))) {
      return h2_error(st0, kH2InternalError, sink);
    }
    const size_t dlen = static_cast<size_t>(dp - dbuf);
    unsigned char fh[kH2FrameHeaderLen];
    h2_put_frame_header(fh, static_cast<uint32_t>(blk->bytes.size() + dlen), kH2Headers,
                        kH2FlagEndHeaders, 0);
    h2.head_cache.bytes.assign(reinterpret_cast<const char*>(fh), sizeof(fh));
    h2.head_cache.bytes.append(blk->bytes);
    h2.head_cache.bytes.append(reinterpret_cast<const char*>(dbuf), dlen);
    h2.head_cache.head_len = h2.head_cache.bytes.size();
    // The DATA frame joins it when the body is konst (!bound - it is
    // then the same bytes for the life of the process) and SMALL. The
    // cap is the whole argument for the size: this saves per-call
    // overhead, and past a kilobyte the memmove dominates that anyway,
    // while the copy is per CONNECTION - h2.hpp's header says what
    // eager per-connection bytes cost at scale. Small bodies get one
    // append; large ones keep the two they already had, and lose
    // nothing.
    h2.head_cache.has_data = b != nullptr && !b->bound && status == 200 &&
                             !b->konst.body.empty() &&
                             b->konst.body.size() <= kH2MergeBody;
    if (h2.head_cache.has_data) h2.head_cache.bytes.append(b->h2_data200);
    h2.head_cache.status = status;
    h2.head_cache.route = route;
    h2.head_cache.sec = sec_;
  }

  // Whether DATA rides along has to be settled BEFORE the append, so
  // the window is read first. DATA beyond min(connection, stream) is
  // PARKED, never written - writing it anyway is the flow-control
  // violation that gets a GOAWAY (RFC 9113 6.9.1).
  H2Stream* stp = no_data ? nullptr : h2.find(stream_id);
  int64_t budget = 0;
  if (!no_data) {
    const int64_t swin = stp != nullptr ? stp->send_window : h2.peer_initial_window;
    budget = h2.send_window < swin ? h2.send_window : swin;
  }
  const bool merged = !no_data && h2.head_cache.has_data &&
                      budget >= static_cast<int64_t>(blen) && blen <= h2.peer_max_frame;

  // ONE append for the whole answer when it can be - head and body,
  // the shape h1 has always had. Everything variable is patched after
  // it: the END_STREAM bit (byte 4 of the HEADERS header) and one
  // stream id per frame, at offsets h2_put_frame_header defines.
  const size_t hoff = sink.size();
  if (merged) {
    sink.append(h2.head_cache.bytes);
  } else {
    sink.append(h2.head_cache.bytes, 0, h2.head_cache.head_len);
  }
  unsigned char* hp = reinterpret_cast<unsigned char*>(&sink[hoff]);
  hp[4] = kH2FlagEndHeaders | (no_data ? kH2FlagEndStream : 0);
  h2_patch_stream_id(hp, stream_id);
  if (merged) h2_patch_stream_id(hp + h2.head_cache.head_len, stream_id);

  size_t give = 0;
  if (!no_data) {
    if (merged) {
      // The DATA frame already left with the head, whole and within
      // the window - that is what `merged` asserted.
      give = blen;
    } else {
      give = blen;
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
        const bool last = off + n == blen;
        h2_put_frame_header(fh, static_cast<uint32_t>(n), kH2Data,
                            last ? kH2FlagEndStream : 0, stream_id);
        sink.append(reinterpret_cast<const char*>(fh), sizeof(fh));
        sink.append(body + off, n);
        off += n;
      }
    }
    // Sent is sent: the debit belongs to BOTH ways out of here, or a
    // merged answer would put bytes on the wire the peer's window
    // never paid for. Whether a stream existed BEFORE this answer
    // decides who owes it - and h2.open() may move the vector, so the
    // answer has to be taken while stp is still meaningful.
    const bool had_stream = stp != nullptr;
    h2.send_window -= static_cast<int64_t>(give);
    if (had_stream) stp->send_window -= static_cast<int64_t>(give);
    if (give < blen) {
      // The window-refused remainder parks on the stream and drains on
      // WINDOW_UPDATE. Copied NOW: the body_ buffer is reused by the
      // next dispatch and exception bytes die with the next mruby call.
      H2Stream& keep = h2.open(stream_id);
      keep.pending.assign(body + give, blen - give);
      keep.headers_done = true;
      keep.half_closed_remote = true;
      // Opened only now (dispatch no longer opens the common case), so
      // it starts at the peer's initial window and has NOT been debited
      // for the bytes this answer already sent. Missing this would let
      // the drain overshoot the peer's window by exactly `give` - a
      // flow-control violation the park test cannot see, because it
      // only checks that the remainder arrives.
      if (!had_stream) keep.send_window -= static_cast<int64_t>(give);
    }
  }
  if (no_data || give == blen) h2.close_stream(stream_id);
  return true;
}

// One round's output, as segments (#168's successor). Sink bytes
// coalesce into the OPEN sink run - so a whole round of framing costs
// one segment, however many streams contributed to it - while asset
// payload becomes pointers into the mapping and is never touched by
// this process. Without a plan every byte lands in the sink, which is
// exactly what this file did before, and what the WINDOW_UPDATE call
// site still needs.
namespace {
struct RoundOut {
  std::string& sink;
  Http1::Plan* plan;
  // Bytes this round emitted on the COPY path (plan == nullptr). That
  // path is per-byte work, so it keeps Gebot 18's round bound
  // (kDeliverChunk) that the pointer path replaced with byte_cap.
  size_t emitted = 0;

  // The resolver treats a plan that names any sink range as a COMPLETE
  // description of the sink, so bytes that were already in it when the
  // flush started - feed's HEADERS frames - must be claimed before the
  // first thing this round emits. Lazily, on first emission: a flush
  // that finds nothing to send leaves the plan empty and the Ring
  // takes the plain-send path.
  void prime() {
    if (plan == nullptr || plan->nseg != 0 || sink.empty()) return;
    plan->seg[plan->nseg++] = Http1::Plan::Seg{nullptr, 0, sink.size()};
    plan->iov_len += sink.size();
  }

  // Room for one more DATA frame: its header opens or extends a sink
  // run, and its payload is up to three spans (a deflated entry's wire
  // body is gzip header + mapping + trailer). Four is the worst case
  // and the only one worth checking - guessing lower would truncate a
  // round mid-frame, and a truncated frame is a corrupt stream.
  // Three gates, one per resource a frame consumes: segments, the
  // round's byte cap (Plan::byte_cap says why), and - on the copy
  // path - kDeliverChunk, because copies are per-byte work. Every
  // gate sits BEFORE the frame, so a cap is overshot by at most one
  // frame, never split across one.
  bool room_for_frame() const {
    if (plan == nullptr) return emitted < kDeliverChunk;
    if (plan->nseg + 4 > Http1::Plan::kSegs) return false;
    return plan->byte_cap == 0 || plan->iov_len < plan->byte_cap;
  }

  void bytes(const char* p, size_t n) {
    if (plan == nullptr) {
      sink.append(p, n);
      emitted += n;
      return;
    }
    prime();
    const size_t at = sink.size();
    sink.append(p, n);
    if (plan->nseg > 0) {
      Http1::Plan::Seg& open = plan->seg[plan->nseg - 1];
      if (open.base == nullptr && open.off + open.len == at) {
        open.len += n;
        plan->iov_len += n;
        return;
      }
    }
    plan->seg[plan->nseg++] = Http1::Plan::Seg{nullptr, at, n};
    plan->iov_len += n;
  }

  // Below this, a piece is COPIED into the open sink run instead of
  // becoming an iovec of its own. The kernel pays a setup-and-walk
  // cost per iovec that a small memcpy undercuts: a 4 KiB gzip
  // response is three tiny pieces (10-byte header, ~1.9K deflate,
  // 8-byte trailer), and as three iovecs it measured 14% SLOWER than
  // its stored twin's one (forgecore, h2 -m32, 2026-08-23). The 18%
  // memmove this file removed came from 64 KiB pieces - LARGE spans,
  // which stay pointers.
  //
  // THE VALUE IS BRACKETED BY TWO MEASUREMENTS, same host, same day:
  // a 4096-byte span is faster as a POINTER (1.42M req/s against
  // 1.30M when an 8192 floor copied it), a ~1.9K deflate span is
  // faster COPIED (its response rose 1.79M -> 1.87M when it stopped
  // being three iovecs). The crossover sits between; one page is the
  // natural line. Strictly below: a 4096 piece stays a pointer.
  static constexpr size_t kCopyFloor = 4096;

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
      plan->seg[plan->nseg++] =
          Http1::Plan::Seg{static_cast<const char*>(iv[i].iov_base), 0, iv[i].iov_len};
      plan->iov_len += iv[i].iov_len;
    }
  }
};
}  // namespace

// The access log's method column for h2, where the wire bytes are
// gone by answer time: the enum spells itself. kOther logs "-" - the
// name was never kept, and inventing one would be a lie in a log.
// One h2 response, one line - referer and user-agent are "-" by
// honesty: an h2 answer can run after its decode buffer died, and the
// two fields were never worth copying per stream for a log column.
#define WM_H2_LOG_DEFINED
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

void Http1::h2_log(Conn& st, const flow::ReqFacts& facts, const char* target, size_t tlen) {
  if (!alog_.enabled) return;
  size_t mn = 0;
  const char* m = alog_method(facts.method, &mn);
  alog_.line(st.peer, st.peer_len, m, mn, target, tlen,
             static_cast<uint8_t>(kLogH2 | (facts.no_track ? kLogNoTrack : 0)), alog_status_,
             alog_bytes_, nullptr, 0, nullptr, 0);
}

void Http1::h2_flush_pending(Conn& st0, std::string& sink, Plan* plan) {
  H2State& h2 = *st0.h2;
  RoundOut out{sink, plan};
  const size_t n_streams = h2.streams.size();
  if (n_streams == 0) return;
  // The round is bounded by plan CAPACITY and the peer's windows -
  // there is no byte budget on top (see Plan::kSegs: the kernel paces
  // via the sndbuf, a bound here only multiplied sends; 64 KiB a round
  // cost -14.5% on forgecore, measured 2026-08-23). The cursor keeps
  // the cut fair: a stream cut off by capacity yields the next round's
  // start to its neighbour instead of taking every round until done.
  size_t walked = 0;
  for (; walked < n_streams; walked++) {
    if (!out.room_for_frame()) break;
    H2Stream& stp = h2.streams[(h2.flush_cursor + walked) % n_streams];
    // A parked SOURCE drains by offset (#168), continued by
    // WINDOW_UPDATE and every drained sink.
    if (stp.src != nullptr) {
      const int64_t budget =
          h2.send_window < stp.send_window ? h2.send_window : stp.send_window;
      if (budget <= 0) continue;
      const size_t remaining = stp.src_len - stp.src_off;
      size_t give = remaining;
      if (static_cast<int64_t>(give) > budget) give = static_cast<size_t>(budget);
      size_t off = 0;
      while (off < give) {
        if (!out.room_for_frame()) break;
        size_t n = give - off;
        if (n > h2.peer_max_frame) n = h2.peer_max_frame;
        const bool last = stp.src_off + off + n == stp.src_len;
        unsigned char fh[kH2FrameHeaderLen];
        h2_put_frame_header(fh, static_cast<uint32_t>(n), kH2Data,
                            last ? kH2FlagEndStream : 0, stp.id);
        out.bytes(reinterpret_cast<const char*>(fh), sizeof(fh));
        out.span(*stp.src, stp.src_off + off, n);
        off += n;
      }
      // `off`, not `give`: the frame loop stops early when the plan
      // fills up, and the windows must be debited by what actually
      // went out or the peer's accounting and ours drift apart.
      h2.send_window -= static_cast<int64_t>(off);
      stp.send_window -= static_cast<int64_t>(off);
      stp.src_off += off;
      if (stp.src_off == stp.src_len) stp.src = nullptr;
      continue;
    }
    if (stp.pending.empty()) continue;
    const int64_t budget =
        h2.send_window < stp.send_window ? h2.send_window : stp.send_window;
    if (budget <= 0) continue;
    // Dynamic bodies have no durable backing to point into, so these
    // bytes are copied as they always were - and for exactly that
    // reason they keep a per-stream cap (Gebot 18: the copy IS work,
    // per byte, unlike a pointer): kDeliverChunk each per round, the
    // pre-plan behaviour. They are sink bytes, so a round of them
    // costs ONE segment however many streams sent.
    size_t give = stp.pending.size() < kDeliverChunk ? stp.pending.size() : kDeliverChunk;
    if (static_cast<int64_t>(give) > budget) give = static_cast<size_t>(budget);
    size_t off = 0;
    while (off < give) {
      if (!out.room_for_frame()) break;
      size_t n = give - off;
      if (n > h2.peer_max_frame) n = h2.peer_max_frame;
      const bool last = off + n == stp.pending.size();
      unsigned char fh[kH2FrameHeaderLen];
      h2_put_frame_header(fh, static_cast<uint32_t>(n), kH2Data,
                          last ? kH2FlagEndStream : 0, stp.id);
      out.bytes(reinterpret_cast<const char*>(fh), sizeof(fh));
      out.bytes(stp.pending.data() + off, n);
      off += n;
    }
    h2.send_window -= static_cast<int64_t>(off);
    stp.send_window -= static_cast<int64_t>(off);
    stp.pending.erase(0, off);
  }
  h2.flush_cursor = n_streams != 0 ? (h2.flush_cursor + walked) % n_streams : 0;
  // Streams drained in the loop close outside it: close_stream
  // reorders the vector under the iterator.
  for (size_t i = 0; i < h2.streams.size();) {
    H2Stream& stp = h2.streams[i];
    if (stp.headers_done && stp.half_closed_remote && stp.pending.empty() &&
        stp.src == nullptr) {
      h2.close_stream(stp.id);
    } else {
      i++;
    }
  }
}

// Does this connection still owe bytes the Ring has not seen? Asked
// BEFORE a send, so a segment with more behind it can carry MSG_MORE
// rather than going out small and waiting out the peer's delayed ACK
// (#168; the previous tree measured that stall at 44.30ms average).
bool Http1::pending(const Conn& st) const {
  if (st.h2 != nullptr) {
    for (const H2Stream& s : st.h2->streams) {
      if (s.src != nullptr || !s.pending.empty()) return true;
    }
    return false;
  }
  return st.xfer != nullptr;
}

// The continuation both protocols share (#168): the Ring calls this
// when the connection's sink has fully drained. h1 pulls the active
// transfer's next slice as POINTERS and resumes pipelined bytes once
// the source is exhausted; h2 re-runs the parked-stream flush. feed's
// contract.
bool Http1::more(Conn& st, std::string& sink, Plan& plan) {
  // An event stream owes nothing between seconds (#102): the Ring
  // asks it again on the second, which is what sse_second answers.
  // Nothing here reads a carry - a stream has no next request.
  if (st.sse != nullptr) return sse_second(st.sse, sec_, sink);
  if (st.h2 != nullptr) {
    h2_flush_pending(st, sink, &plan);
    return true;
  }
  if (st.xfer != nullptr) {
    const AssetEntry& e = *st.xfer;
    const size_t lim = st.xfer_end;  // full body or a 206 window alike
    // As much of the remainder as the round's byte bound allows
    // (Plan::byte_cap says why; both fixed bounds were tried and
    // lost - 64 KiB multiplied sends, unbounded slept out the
    // one-third wake past the sndbuf). h1 has no framing inside a
    // body, so this is at most three pointers however large the body -
    // and pacing is not this layer's job: the kernel keeps what fits
    // in the sndbuf, the short write says how much, and the Ring
    // resumes from Conn::sent without asking here again. Chunking this
    // (64 KiB per round, once) only multiplied sends and CQEs.
    size_t take = lim - st.xfer_off;
    if (plan.byte_cap != 0 && take > plan.byte_cap) take = plan.byte_cap;
    struct iovec iv[3];
    const unsigned k = Assets::wire_iov(e, st.xfer_off, take, iv);
    for (unsigned i = 0; i < k; i++) {
      plan.seg[plan.nseg++] =
          Plan::Seg{static_cast<const char*>(iv[i].iov_base), 0, iv[i].iov_len};
    }
    plan.iov_len = take;
    st.xfer_off += take;
    if (st.xfer_off == lim) {
      st.xfer = nullptr;
      st.xfer_off = 0;
      st.xfer_end = 0;
    }
    // RETURN here: a plan is unsent bytes, and the carry below would
    // put the NEXT response in the sink ahead of them - the transfer
    // owns the wire order until its last segment has left. The round
    // after this one drains the carry, by which time these pointers
    // are spent. (Found as a hang: the plan branch first fell through
    // to feed() and the next response overtook the body.)
    return true;
  }
  if (st.carry.empty()) return true;
  // What was pipelined behind a transfer parses now (a plain partial
  // head re-carries itself harmlessly); feed's verdict is the
  // connection's verdict.
  std::string held;
  held.swap(st.carry);
  // The plan rides along: a pipelined asset request parsed out of the
  // carry can hand its body over in this same round.
  return feed(st, held.data(), held.size(), sink, &plan);
}

bool Http1::h2_feed(Conn& st0, const char* data, size_t len, std::string& sink, Plan* plan) {
  H2State& h2 = *st0.h2;
  // The carry is the frame buffer; the hot path parses the receive in
  // place and only a frame split across receives pays the copy.
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
    if (viewlen - off - kH2FrameHeaderLen < flen) break;  // frame incomplete
    const uint8_t type = fh[3];
    const uint8_t flags = fh[4];
    const uint32_t stream = h2_u31(fh + 5);
    const unsigned char* p = fh + kH2FrameHeaderLen;
    off += kH2FrameHeaderLen + flen;

    // A header block owns the connection until END_HEADERS (RFC 9113
    // 6.10): nothing else may interleave.
    if (h2.frag_active && type != kH2Continuation) {
      return h2_error(st0, kH2ProtocolError, sink);
    }

    switch (type) {
      case kH2Data: {
        if (stream == 0) return h2_error(st0, kH2ProtocolError, sink);
        H2Stream* stp = h2.find(stream);
        if (stp == nullptr) {
          // 5.1: DATA on an IDLE stream is a connection error; on a
          // CLOSED one it is the stream's, and the connection lives.
          if (h2_is_idle(h2, stream)) return h2_error(st0, kH2ProtocolError, sink);
          h2_rst(st0, stream, kH2StreamClosed, sink);
          break;
        }
        if (!stp->headers_done || stp->half_closed_remote) {
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
        if (stp->body_len + dlen > kMaxBody) {
          // The h1 path answers 413; the stream answer here is a
          // refusal. Counted, never stored - this tier has no body
          // consumer.
          h2_rst(st0, stream, kH2RefusedStream, sink);
          break;
        }
        stp->body_len += dlen;
        // Credit the peer for the whole frame, padding included - that
        // is what the spec counts - so it can keep sending.
        if (flen != 0) {
          unsigned char inc[4];
          put_u32(inc, flen);
          emit_control(sink, kH2WindowUpdate, 0, 0, inc, 4);
          emit_control(sink, kH2WindowUpdate, 0, stream, inc, 4);
        }
        if (flags & kH2FlagEndStream) {
          // 8.1.2.6: the body that arrived must be the body that was
          // announced. Checked here, where both numbers finally exist.
          if (stp->have_content_length && stp->body_len != stp->content_length) {
            h2_rst(st0, stream, kH2ProtocolError, sink);
            break;
          }
          stp->half_closed_remote = true;
          // Copies: h2_answer may grow the stream vector under stp.
          const flow::ReqFacts facts = stp->facts;
          const bool head_only = stp->head_only;
          const uint16_t route = stp->route;
          const std::string target = stp->target;
          ReqView rv;
          const ReqView* rvp = h2_parked_view(st0, target, rv);
          if (!h2_answer(st0, stream, facts, head_only, route, rvp, sink)) return false;
          h2_log(st0, facts, target.data(), target.size());
        }
        break;
      }

      case kH2Headers: {
        if (stream == 0 || (stream & 1) == 0) return h2_error(st0, kH2ProtocolError, sink);
        // 5.1 / 5.1.1: HEADERS opens a stream, and only an IDLE id can
        // be opened - an id at or below the highest one ever accepted
        // is either closed or out of order, and both are the
        // connection's error.
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
          // Deprecated by RFC 9113, so the five bytes are skipped - but
          // 5.3.1 still forbids a stream depending on ITSELF, and that
          // is a check, not a priority tree.
          if (hlen < 5) return h2_error(st0, kH2FrameSizeError, sink);
          if (h2_u31(hp) == stream) return h2_error(st0, kH2ProtocolError, sink);
          hp += 5;
          hlen -= 5;
        }
        h2.frag.assign(reinterpret_cast<const char*>(hp), hlen);
        h2.frag_stream = stream;
        h2.frag_flags = flags;
        h2.frag_active = true;
        if (flags & kH2FlagEndHeaders) {
          h2.frag_active = false;
          if (!h2_dispatch(st0, stream, (flags & kH2FlagEndStream) != 0, sink)) return false;
        }
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
          if (!h2_dispatch(st0, h2.frag_stream, (h2.frag_flags & kH2FlagEndStream) != 0,
                           sink)) {
            return false;
          }
        }
        break;
      }

      case kH2Priority:
        // Deprecated by RFC 9113, and still not free: 6.3 gives it a
        // stream of its own (never 0), and 5.3.1 forbids depending on
        // itself. Everything else about it is ignored.
        if (stream == 0) return h2_error(st0, kH2ProtocolError, sink);
        if (flen != 5) return h2_error(st0, kH2FrameSizeError, sink);
        if (h2_u31(p) == stream) return h2_error(st0, kH2ProtocolError, sink);
        break;

      case kH2RstStream:
        // 6.4: stream 0 and an IDLE stream are the connection's error;
        // a wrong length is its own.
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
              lshpack_enc_set_max_capacity(&h2.enc, v);
              break;
            case kH2SettingsEnablePush:
              // 6.5.2: 0 or 1, and nothing else. This server never
              // pushes either way (8.4), so the VALUE changes nothing
              // here - the refusal is about the peer being wrong.
              if (v > 1) return h2_error(st0, kH2ProtocolError, sink);
              break;
            case kH2SettingsInitialWindowSize: {
              if (v > kH2WindowCeiling) return h2_error(st0, kH2FlowControlError, sink);
              // The new initial window reflows onto every live stream
              // (RFC 9113 6.9.2).
              const int64_t delta = static_cast<int64_t>(v) - h2.peer_initial_window;
              h2.peer_initial_window = static_cast<int64_t>(v);
              for (H2Stream& stp : h2.streams) stp.send_window += delta;
              break;
            }
            case kH2SettingsMaxFrameSize:
              if (v < 16384 || v > 16777215) return h2_error(st0, kH2ProtocolError, sink);
              // Stored clamped: frames smaller than the peer's cap are
              // always legal, and our buffers are sized to the floor.
              h2.peer_max_frame = v > kH2MaxFrameSize ? kH2MaxFrameSize : v;
              break;
            default:
              break;  // unknown settings are ignored, per spec
          }
        }
        emit_control(sink, kH2Settings, kH2FlagAck, 0, nullptr, 0);
        break;
      }

      case kH2PushPromise:
        // A client must not push (RFC 9113 8.4).
        return h2_error(st0, kH2ProtocolError, sink);

      case kH2Ping:
        if (stream != 0 || flen != 8) return h2_error(st0, kH2FrameSizeError, sink);
        if (!(flags & kH2FlagAck)) emit_control(sink, kH2Ping, kH2FlagAck, 0, p, 8);
        break;

      case kH2Goaway:
        // The peer is done with this connection. Everything already in
        // the sink still goes out (feed's contract); nothing new
        // starts.
        if (flen < 8) return h2_error(st0, kH2FrameSizeError, sink);
        h2.goaway_recv = true;
        break;

      case kH2WindowUpdate: {
        if (flen != 4) return h2_error(st0, kH2FrameSizeError, sink);
        const uint32_t inc = h2_u31(p);
        if (inc == 0) return h2_error(st0, kH2ProtocolError, sink);
        if (stream == 0) {
          h2.send_window += inc;
          if (h2.send_window > kH2WindowCeiling) {
            return h2_error(st0, kH2FlowControlError, sink);
          }
        } else if (H2Stream* stp = h2.find(stream)) {
          // 6.9.1: a window past 2^31-1 is the STREAM's error, not the
          // connection's - the stream dies, the peer keeps talking.
          stp->send_window += inc;
          if (stp->send_window > kH2WindowCeiling) {
            h2_rst(st0, stream, kH2FlowControlError, sink);
            break;
          }
        } else if (h2_is_idle(h2, stream)) {
          // 5.1: an idle stream has no window to update.
          return h2_error(st0, kH2ProtocolError, sink);
        }
        h2_flush_pending(st0, sink, nullptr);
        break;
      }

      default:
        break;  // unknown frame types are ignored, per spec
    }
  }

  // Keep what the next receive completes.
  if (in_place) {
    if (off < viewlen) st0.carry.assign(view + off, viewlen - off);
  } else {
    st0.carry.erase(0, off);
  }
  // Everything this receive parked leaves NOW, with its headers, in
  // one sendmsg - as a plan when the Ring handed one in (no send in
  // flight), as parked state otherwise, drained on the next sink
  // drain. This is the h2 asset path's only body delivery: the answer
  // parks, this flushes.
  h2_flush_pending(st0, sink, plan);
  // A peer that said GOAWAY is finished once the sink drains.
  return !h2.goaway_recv;
}

}  // namespace webmachine
