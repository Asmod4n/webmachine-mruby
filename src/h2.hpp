// HTTP/2 connection state and wire helpers (RFC 9113). One H2State per
// connection that spoke the client preface, allocated THEN and never
// before - eager per-connection objects measured -12% throughput /
// +58% p99 at 7000 idle connections on the old tree, so an h1
// connection carries one null pointer and nothing else.
//
// Only the HPACK codec is foreign (ls-hpack, see mrbgem.rake); the
// frame and stream machinery is this tree's own, driven from
// http2.cpp. Priority trees are deprecated in RFC 9113 and absent
// here; so is server push (8.4 forbids the client, nothing here wants
// the server side).
#ifndef WEBMACHINE_H2_HPP
#define WEBMACHINE_H2_HPP

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include "flow_walk.hpp"
#include "lshpack.h"

namespace webmachine {

// Frame types (RFC 9113 6).
enum : uint8_t {
  kH2Data = 0x0,
  kH2Headers = 0x1,
  kH2Priority = 0x2,
  kH2RstStream = 0x3,
  kH2Settings = 0x4,
  kH2PushPromise = 0x5,
  kH2Ping = 0x6,
  kH2Goaway = 0x7,
  kH2WindowUpdate = 0x8,
  kH2Continuation = 0x9,
};

// Frame flags. ACK shares the END_STREAM bit on purpose (the spec's).
enum : uint8_t {
  kH2FlagEndStream = 0x1,
  kH2FlagAck = 0x1,
  kH2FlagEndHeaders = 0x4,
  kH2FlagPadded = 0x8,
  kH2FlagPriority = 0x20,
};

// Error codes (RFC 9113 7).
enum : uint32_t {
  kH2NoError = 0x0,
  kH2ProtocolError = 0x1,
  kH2InternalError = 0x2,
  kH2FlowControlError = 0x3,
  kH2StreamClosed = 0x5,
  kH2FrameSizeError = 0x6,
  kH2RefusedStream = 0x7,
  kH2CompressionError = 0x9,
  kH2EnhanceYourCalm = 0xb,
};

// Settings identifiers (RFC 9113 6.5.2).
enum : uint16_t {
  kH2SettingsHeaderTableSize = 0x1,
  kH2SettingsMaxConcurrentStreams = 0x3,
  kH2SettingsInitialWindowSize = 0x4,
  kH2SettingsMaxFrameSize = 0x5,
};

// The client connection preface (RFC 9113 3.4).
inline constexpr char kH2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
inline constexpr size_t kH2PrefaceLen = 24;

inline constexpr size_t kH2FrameHeaderLen = 9;
// Ours, and also the floor every peer must accept (RFC 9113 4.2).
inline constexpr uint32_t kH2MaxFrameSize = 16384;
inline constexpr int64_t kH2DefaultWindow = 65535;
inline constexpr uint32_t kH2MaxConcurrentStreams = 256;
inline constexpr int64_t kH2WindowCeiling = 0x7fffffff;

inline void h2_put_frame_header(unsigned char* p, uint32_t len, uint8_t type,
                                uint8_t flags, uint32_t stream) {
  p[0] = static_cast<unsigned char>(len >> 16);
  p[1] = static_cast<unsigned char>(len >> 8);
  p[2] = static_cast<unsigned char>(len);
  p[3] = type;
  p[4] = flags;
  p[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
  p[6] = static_cast<unsigned char>(stream >> 16);
  p[7] = static_cast<unsigned char>(stream >> 8);
  p[8] = static_cast<unsigned char>(stream);
}

// Patches the 4 stream-id bytes h2_put_frame_header wrote at a fixed
// offset (5) within an ALREADY-EMITTED frame header - the same trick
// http1's on_tick uses for its date_off, applied to stream id instead
// of date. p must point at byte 0 of that 9-byte frame header.
inline void h2_patch_stream_id(unsigned char* p, uint32_t stream) {
  p[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
  p[6] = static_cast<unsigned char>(stream >> 16);
  p[7] = static_cast<unsigned char>(stream >> 8);
  p[8] = static_cast<unsigned char>(stream);
}

inline uint32_t h2_u24(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | p[2];
}
inline uint32_t h2_u32(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
inline uint32_t h2_u31(const unsigned char* p) { return h2_u32(p) & 0x7fffffff; }
inline uint16_t h2_u16(const unsigned char* p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

// One stream the connection still needs to remember. A stream answered
// in full inside its own dispatch never appears here. Request bodies
// are COUNTED and discarded, exactly the h1 tier (no consumer until
// the POST/PUT tier delivers them) - what survives until END_STREAM is
// the facts vector, not the bytes.
struct AssetEntry;  // assets.hpp owns it (#170)

struct H2Stream {
  uint32_t id = 0;
  int64_t send_window = kH2DefaultWindow;
  size_t body_len = 0;  // received DATA payload, counted against kMaxBody
  // Response DATA the peer's window refused; flushed on WINDOW_UPDATE.
  std::string pending;
  flow::ReqFacts facts;  // decoded at HEADERS, dispatched at END_STREAM
  // An asset request resolves at dispatch - the header VALUES it
  // negotiates with die with the decode buffer - so what parks here is
  // the entry and the finished verdict, never a value pointer.
  const AssetEntry* asset = nullptr;
  uint16_t asset_status = 0;
  // A parked DELIVERY (#168): no byte lies in the park, an offset
  // does. src_off walks [0, src_len) over Assets::copy_wire's virtual
  // wire body; `pending` (bytes) remains for dynamic bodies, which
  // have no durable backing to point into.
  const AssetEntry* src = nullptr;
  size_t src_off = 0;
  size_t src_len = 0;
  bool head_only = false;
  bool headers_done = false;
  bool half_closed_remote = false;
};

struct H2State {
  // Two lanes on the sending side: what never changes is PRECOMPUTED
  // as never-indexed blocks (Http1::h2_build_block - status, date
  // patched per second, konst content-type, allow) and costs a
  // memcpy; what is dynamic per request goes through ls-hpack's
  // encoder (Http1::h2_enc_field). Never-indexed literals touch no
  // table state on either side, so the lanes interleave freely in one
  // header block.
  struct lshpack_enc enc;
  struct lshpack_dec dec;

  // What the PEER may still receive - connection-level, debited by
  // every DATA payload byte sent, credited by their WINDOW_UPDATEs.
  int64_t send_window = kH2DefaultWindow;
  int64_t peer_initial_window = kH2DefaultWindow;
  uint32_t peer_max_frame = kH2MaxFrameSize;
  uint32_t last_stream = 0;  // highest stream id seen, for GOAWAY
  bool goaway_sent = false;
  bool goaway_recv = false;  // the peer is done; finish and close

  // A header block split over HEADERS + CONTINUATION accumulates here;
  // frag_stream says whose it is, END_STREAM travels in frag_flags.
  std::string frag;
  uint32_t frag_stream = 0;
  uint8_t frag_flags = 0;
  bool frag_active = false;

  // Decoded header bytes for the request being dispatched. Reused, so
  // its capacity survives; facts are extracted before the next decode.
  std::string hdrbuf;

  std::vector<H2Stream> streams;

  // The response cache: one slot, deliberately not one per status -
  // the -12%/+58% eager-per-connection-object cost above is exactly
  // why this stays small. Homogeneous traffic (the common case) gets
  // the full win; a status change just falls back to rebuilding it
  // fresh, same cost as before this cache existed, never wrong.
  //
  // bytes holds a whole HEADERS frame (header + h2_store_ block +
  // encoded date) and, when has_data, the whole DATA frame right
  // behind it - so the common answer is ONE append of one contiguous
  // buffer, the way h1 answers. head_len says where the HEADERS frame
  // ends, which is both the second frame's patch point and the length
  // to append when the body must not ride along (HEAD, a bodyless
  // status, or a window too small for it).
  //
  // Every byte in here is fixed except two 4-byte stream ids and one
  // flags byte, all at offsets h2_put_frame_header defines. Valid
  // only while status/sec still match.
  struct {
    std::string bytes;
    size_t head_len = 0;
    bool has_data = false;
    uint16_t status = 0;
    time_t sec = 0;
  } head_cache;

  H2State() {
    lshpack_enc_init(&enc);
    lshpack_dec_init(&dec);
  }
  ~H2State() {
    lshpack_enc_cleanup(&enc);
    lshpack_dec_cleanup(&dec);
  }
  H2State(const H2State&) = delete;
  H2State& operator=(const H2State&) = delete;

  H2Stream* find(uint32_t id) {
    for (H2Stream& st : streams)
      if (st.id == id) return &st;
    return nullptr;
  }
  H2Stream& open(uint32_t id) {
    if (H2Stream* st = find(id)) return *st;
    streams.emplace_back();
    H2Stream& st = streams.back();
    st.id = id;
    st.send_window = peer_initial_window;
    return st;
  }
  void close_stream(uint32_t id) {
    for (size_t i = 0; i < streams.size(); i++) {
      if (streams[i].id == id) {
        streams[i] = std::move(streams.back());
        streams.pop_back();
        return;
      }
    }
  }
};

}  // namespace webmachine

#endif
