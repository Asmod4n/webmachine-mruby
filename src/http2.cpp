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

#include <cstring>

#include "h2.hpp"
#include "http.hpp"
#include "http1.hpp"

namespace webmachine {
namespace {

// Room for the decoded fields of one request: kMaxHeaders regular
// ones plus the pseudo-fields h2 moves out of the request line.
constexpr size_t kH2MaxFields = kMaxHeaders + 8;
// A header block may span CONTINUATIONs; twice the h1 head budget
// bounds the compressed side (the decoded side is bounded per field
// in the decode loop).
constexpr size_t kH2FragBudget = kMaxHead * 2;

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
  h2.hdrbuf.clear();
  uint32_t quads[4 * kH2MaxFields];
  size_t nq = 0;
  const unsigned char* p = reinterpret_cast<const unsigned char*>(h2.frag.data());
  const unsigned char* end = p + h2.frag.size();
  while (p < end) {
    if (nq + 4 > 4 * kH2MaxFields) return h2_error(st0, kH2EnhanceYourCalm, sink);
    const size_t base = h2.hdrbuf.size();
    // A field larger than the request-header budget is refused either
    // way; one slot of that size is the decode ceiling per field.
    if (base > kH2FragBudget) return h2_error(st0, kH2EnhanceYourCalm, sink);
    h2.hdrbuf.resize(base + 4096);
    lsxpack_header_t xh;
    lsxpack_header_prepare_decode(&xh, &h2.hdrbuf[base], 0, 4096);
    if (lshpack_dec_decode(&h2.dec, &p, end, &xh) != 0) {
      return h2_error(st0, kH2CompressionError, sink);
    }
    quads[nq++] = static_cast<uint32_t>(base + xh.name_offset);
    quads[nq++] = xh.name_len;
    quads[nq++] = static_cast<uint32_t>(base + xh.val_offset);
    quads[nq++] = xh.val_len;
    h2.hdrbuf.resize(base + xh.val_offset + xh.val_len);
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
    if (!h2_answer(st0, stream_id, facts, head_only, sink)) return false;
    return true;
  }

  // Facts from the decoded fields. RFC 9113 8.3: pseudo-fields first,
  // exactly one :method/:scheme/:path; 8.2: field names lowercase;
  // 8.2.2: connection-specific fields make the request malformed.
  flow::ReqFacts facts;
  bool ok = true, saw_regular = false;
  bool have_method = false, have_path = false, have_scheme = false;
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
        have_method = true;
        facts.method = http::parse_method(val, vlen);
      } else if (nlen == 5 && std::memcmp(name, ":path", 5) == 0) {
        have_path = vlen != 0;  // routing reads it when the router lands
      } else if (nlen == 7 && std::memcmp(name, ":scheme", 7) == 0) {
        have_scheme = true;  // h2c: the scheme is a claim, the socket is the fact
      } else if (nlen == 10 && std::memcmp(name, ":authority", 10) == 0) {
        // host's seat; nothing reads it at this tier
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
    http::header_switch(name, nlen, val, vlen, facts,
                        [&](const char* n, size_t nl, const char*, size_t) {
                          // content-length is advisory here (DATA frames
                          // are counted instead); connection-specific
                          // fields are malformed per 8.2.2.
                          switch (nl) {
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
  if (h2.streams.size() >= kH2MaxConcurrentStreams) {
    // We announced the cap in our SETTINGS; a peer past it is refused
    // per stream, not per connection (RFC 9113 5.1.2).
    h2_rst(st0, stream_id, kH2RefusedStream, sink);
    return true;
  }
  H2Stream& stx = h2.open(stream_id);
  stx.headers_done = true;
  stx.facts = facts;
  stx.head_only = facts.method == flow::Method::kHead;

  if (end_stream) {
    stx.half_closed_remote = true;
    if (!h2_answer(st0, stream_id, facts, stx.head_only, sink)) return false;
    return true;
  }
  // A body follows; the facts wait on the stream, the bytes will not.
  return true;
}

bool Http1::h2_answer(Conn& st0, uint32_t stream_id, const flow::ReqFacts& facts,
                      bool head_only, std::string& sink) {
  H2State& h2 = *st0.h2;

  // The same decision the h1 path makes: konst resources never see the
  // VM, anything dynamic runs the whole flow inside ONE VM frame.
  uint16_t status;
  bool have_body = false;
  if (bound_) {
    status = resource_run(*res_, facts, &body_, &have_body);
  } else {
    status = flow::walk(facts, konst_.per_method[static_cast<size_t>(facts.method)]);
  }

  const char* body = nullptr;
  size_t blen = 0;
  const H2Block* blk;
  if (have_body && status == 200) {
    body = body_.data();
    blen = body_.size();
    blk = &h2_store_[index_[200]];
  } else if (status == 500 && bound_) {
    // A raising callback answers in the negotiated type, the reason as
    // body; the lent bytes are appended (copied) before any next mruby
    // call can run.
    const char* bp = nullptr;
    size_t bl = 0;
    if (resource_exception_begin(*res_, &bp, &bl)) {
      body = bp;
      blen = bl;
      blk = &h2_err_;
    } else {
      blk = &h2_store_[index_[500]];
    }
  } else if (status == 200) {
    body = konst_.body.data();
    blen = konst_.body.size();
    blk = &h2_store_[index_[200]];
  } else {
    // Every status block was precomputed at setup (405 carries Allow,
    // RFC 9110 10.2.1); 204/304 are bodyless and every other status
    // sends no body at this tier - DATA framing already delimits, so
    // there is no Content-Length to spell (RFC 9113 8.1.1).
    blk = &h2_store_[index_[status]];
  }

  // HEAD answers with the head and no DATA; its render already ran for
  // parity with h1 (the Content-Length h1 announces is the GET's).
  const bool no_data = head_only || blen == 0;

  // HEADERS region, cheat #1: the encoder only sees a genuinely new
  // value once per second per connection (h2.head_cache.sec), and only
  // the status's block content differs otherwise - so a cache MISS is
  // the rare case, not the per-response default. Flags carries the
  // one bit (END_STREAM) that varies for a cached status between a
  // bodied GET and a bodyless HEAD/204/304; it and stream id are the
  // ONLY bytes patched after the append, both at fixed offsets
  // (h2_put_frame_header's own layout, mirrored by h2_patch_stream_id).
  if (h2.head_cache.status != status || h2.head_cache.sec != sec_) {
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
    h2.head_cache.status = status;
    h2.head_cache.sec = sec_;
  }
  const size_t hoff = sink.size();
  sink.append(h2.head_cache.bytes);
  unsigned char* hp = reinterpret_cast<unsigned char*>(&sink[hoff]);
  hp[4] = kH2FlagEndHeaders | (no_data ? kH2FlagEndStream : 0);
  h2_patch_stream_id(hp, stream_id);

  size_t give = 0;
  if (!no_data) {
    // DATA beyond min(connection, stream) window is PARKED, never
    // written - writing it anyway is the flow-control violation that
    // gets a GOAWAY (RFC 9113 6.9.1).
    H2Stream* stp = h2.find(stream_id);
    const int64_t swin = stp != nullptr ? stp->send_window : h2.peer_initial_window;
    const int64_t budget = h2.send_window < swin ? h2.send_window : swin;
    // DATA region, cheat #2: konst_.body never varies (!bound_), so
    // the whole frame - header, length, END_STREAM, bytes - was baked
    // once at setup (Http1's ctor). Only when it fits unclamped: the
    // window-park and multi-frame-chunk paths below are untouched and
    // still own every case this fast path does not.
    if (!bound_ && status == 200 && budget >= static_cast<int64_t>(blen) &&
        blen <= h2.peer_max_frame) {
      const size_t doff = sink.size();
      sink.append(h2_data200_);
      h2_patch_stream_id(reinterpret_cast<unsigned char*>(&sink[doff]), stream_id);
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
    h2.send_window -= static_cast<int64_t>(give);
    if (stp != nullptr) stp->send_window -= static_cast<int64_t>(give);
    if (give < blen) {
      // The window-refused remainder parks on the stream and drains on
      // WINDOW_UPDATE. Copied NOW: the body_ buffer is reused by the
      // next dispatch and exception bytes die with the next mruby call.
      H2Stream& keep = h2.open(stream_id);
      keep.pending.assign(body + give, blen - give);
      keep.headers_done = true;
      keep.half_closed_remote = true;
    }
  }
  if (no_data || give == blen) h2.close_stream(stream_id);
  return true;
}

void Http1::h2_flush_pending(Conn& st0, std::string& sink) {
  H2State& h2 = *st0.h2;
  for (H2Stream& stp : h2.streams) {
    if (stp.pending.empty()) continue;
    const int64_t budget =
        h2.send_window < stp.send_window ? h2.send_window : stp.send_window;
    if (budget <= 0) continue;
    size_t give = stp.pending.size();
    if (static_cast<int64_t>(give) > budget) give = static_cast<size_t>(budget);
    size_t off = 0;
    while (off < give) {
      size_t n = give - off;
      if (n > h2.peer_max_frame) n = h2.peer_max_frame;
      const bool last = off + n == stp.pending.size();
      unsigned char fh[kH2FrameHeaderLen];
      h2_put_frame_header(fh, static_cast<uint32_t>(n), kH2Data,
                          last ? kH2FlagEndStream : 0, stp.id);
      sink.append(reinterpret_cast<const char*>(fh), sizeof(fh));
      sink.append(stp.pending.data() + off, n);
      off += n;
    }
    h2.send_window -= static_cast<int64_t>(give);
    stp.send_window -= static_cast<int64_t>(give);
    stp.pending.erase(0, give);
  }
  // Streams drained in the loop close outside it: close_stream
  // reorders the vector under the iterator.
  for (size_t i = 0; i < h2.streams.size();) {
    H2Stream& stp = h2.streams[i];
    if (stp.headers_done && stp.half_closed_remote && stp.pending.empty()) {
      h2.close_stream(stp.id);
    } else {
      i++;
    }
  }
}

bool Http1::h2_feed(Conn& st0, const char* data, size_t len, std::string& sink) {
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
        if (stp == nullptr || !stp->headers_done || stp->half_closed_remote) {
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
          stp->half_closed_remote = true;
          // Copies: h2_answer may grow the stream vector under stp.
          const flow::ReqFacts facts = stp->facts;
          const bool head_only = stp->head_only;
          if (!h2_answer(st0, stream, facts, head_only, sink)) return false;
        }
        break;
      }

      case kH2Headers: {
        if (stream == 0 || (stream & 1) == 0) return h2_error(st0, kH2ProtocolError, sink);
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
          // Deprecated by RFC 9113; the five bytes are skipped.
          if (hlen < 5) return h2_error(st0, kH2FrameSizeError, sink);
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
        // Deprecated by RFC 9113; parsed for length and ignored.
        if (flen != 5) return h2_error(st0, kH2FrameSizeError, sink);
        break;

      case kH2RstStream:
        if (flen != 4 || stream == 0) return h2_error(st0, kH2FrameSizeError, sink);
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
          stp->send_window += inc;
          if (stp->send_window > kH2WindowCeiling) {
            return h2_error(st0, kH2FlowControlError, sink);
          }
        }
        h2_flush_pending(st0, sink);
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
  // A peer that said GOAWAY is finished once the sink drains.
  return !h2.goaway_recv;
}

}  // namespace webmachine
