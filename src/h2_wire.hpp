#ifndef WEBMACHINE_H2_WIRE_HPP
#define WEBMACHINE_H2_WIRE_HPP

// RFC 9113 4/6 and RFC 7541: the h2 wire layer, and nothing above it.
//
// What a frame is - its type, flag, error and settings numbers, the
// preface, the nine header bytes, the big-endian reads, one HPACK field
// encode - is the same for a server answering and a client asking.
//
// It lives here so the two ends cannot drift: src/http2.cpp and
// bench/load/load.cpp both include it, and a misread length is a bug in
// one place.
//
// Header-only and free of everything else in this tree: no mruby, no
// io_uring, no Conn, no state. Only <cstddef>/<cstdint> and nghttp2.

#include <cstddef>
#include <cstdint>
#include <cstring>

#include <nghttp2/nghttp2.h>

namespace webmachine {
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

enum : uint8_t {
  kH2FlagEndStream = 0x1,
  kH2FlagAck = 0x1,
  kH2FlagEndHeaders = 0x4,
  kH2FlagPadded = 0x8,
  kH2FlagPriority = 0x20,
};

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

enum : uint16_t {
  kH2SettingsHeaderTableSize = 0x1,
  kH2SettingsEnablePush = 0x2,
  kH2SettingsMaxConcurrentStreams = 0x3,
  kH2SettingsInitialWindowSize = 0x4,
  kH2SettingsMaxFrameSize = 0x5,
  // RFC 8441 3: the server says it accepts the extended CONNECT, which is
  // how a WebSocket reaches an h2 stream.
  kH2SettingsEnableConnectProtocol = 0x8,
};

inline constexpr char kH2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
inline constexpr size_t kH2PrefaceLen = 24;
inline constexpr size_t kH2PrefaceAnnounce = 18;

inline constexpr size_t kH2FrameHeaderLen = 9;
inline constexpr uint32_t kH2MaxFrameSize = 16384;
inline constexpr int64_t kH2DefaultWindow = 65535;
inline constexpr uint32_t kH2MaxConcurrentStreams = 256;
// RFC 7541 4.2 / RFC 9113 6.5.2: SETTINGS_HEADER_TABLE_SIZE arrives as a
// 32-bit number with no upper bound in either RFC - the peer is telling
// us how large a dynamic table its decoder will keep, and how large a
// one our encoder may therefore build. A peer may name 4294967295. Using
// less than the peer allows is always legal (RFC 7541 4.2: the encoder
// decides), so the number is clamped here rather than handed to the
// encoder as it arrived. Without this the peer sizes our allocation.
inline constexpr uint32_t kH2EncTableMax = 65536;
// RFC 7541 4.2: the decoder's table size is whatever this side announced
// in SETTINGS_HEADER_TABLE_SIZE. We announce nothing, so RFC 9113 6.5.2's
// default stands - and it is stated to the decoder here rather than left
// to agree with the encoder's own default by luck. One number, one place;
// if the SETTINGS frame ever names a size, it names this.
inline constexpr uint32_t kH2DecTableSize = 4096;
inline constexpr int64_t kH2WindowCeiling = 0x7fffffff;

// RFC 9113 4.1: the four fields of a frame header.
struct H2FrameHead {
  uint32_t len;
  uint8_t type;
  uint8_t flags;
  uint32_t stream;
};

// The 9 bytes they make; stream id at offset 5.
inline void h2_put_frame_header(unsigned char* p, H2FrameHead f) {
  const uint32_t len = f.len;
  const uint32_t stream = f.stream;
  p[0] = static_cast<unsigned char>(len >> 16);
  p[1] = static_cast<unsigned char>(len >> 8);
  p[2] = static_cast<unsigned char>(len);
  p[3] = f.type;
  p[4] = f.flags;
  p[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
  p[6] = static_cast<unsigned char>(stream >> 16);
  p[7] = static_cast<unsigned char>(stream >> 8);
  p[8] = static_cast<unsigned char>(stream);
}

// RFC 9113 4.1: the 4 stream-id bytes of an already-emitted frame header.
inline void h2_patch_stream_id(unsigned char* p, uint32_t stream) {
  p[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
  p[6] = static_cast<unsigned char>(stream >> 16);
  p[7] = static_cast<unsigned char>(stream >> 8);
  p[8] = static_cast<unsigned char>(stream);
}

// RFC 9113 4.1: a frame's length field.
inline uint32_t h2_u24(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | p[2];
}
// RFC 9113 4.1: a 32-bit field, network order.
inline uint32_t h2_u32(const unsigned char* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | p[3];
}
// RFC 9113 4.1: a stream id, reserved bit masked off.
inline uint32_t h2_u31(const unsigned char* p) { return h2_u32(p) & 0x7fffffff; }
// RFC 9113 6.5.1: a settings identifier.
inline uint16_t h2_u16(const unsigned char* p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

// One HPACK block under construction: the encoder whose dynamic table it
// moves, the cursor the next field lands at, and the end it may not pass.
// The cursor is a reference - encoding a field advances it, and what the
// caller wrote is `at` minus where it started.
struct H2BlockOut {
  nghttp2_hd_deflater* enc;
  unsigned char*& at;
  unsigned char* end;
};

// RFC 7541 6.2: one field line to encode. `index` says whether the
// encoder
// may put it in the dynamic table (6.2.1) or must spell it without one
// (6.2.2). It matters for any block that is cached and replayed: HPACK is
// stateful, so replaying an insert makes the peer insert - and evict -
// once per replay, which on a busy connection is one allocation per answer
// in every client that talks to us. A block we send more than once must
// not move the peer's table.
struct H2Field {
  std::string_view name;
  std::string_view value;
  bool index = true;
};

// Lane 2 - one per-request field through the encoder. nghttp2 takes the
// name and the value as they are, so nothing is copied to spell the pair
// out. Returns false when the field would not fit - the caller then has
// an error to name, not a truncated block. Shared: the server encodes
// its response fields with this, the load generator its request
// pseudo-fields.
//
// One field per call, not the whole block at once: the callers build
// their blocks a line at a time and mix in blocks that were spelled by
// hand. nghttp2_hd_deflate_hd appends the field's representation and
// adds no framing of its own, so a block built by many calls is the
// same octets as one built by a single call with every field in it.
inline bool h2_enc_field(H2BlockOut out, const H2Field& f) {
  // Nothing is checked here, and that is deliberate: what an app can
  // shape is checked where it enters the header buffer - http::
  // field_name_ok / field_value_ok, at response.cpp's Headers#[]= and at
  // resource.cpp's `field`. By the time a line reaches this encoder it
  // has already passed that gate, so a second check would guard against
  // something no user can reach. The pointers cannot be null either:
  // they are our own literals and std::string::data().
  nghttp2_nv nv;
  nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(f.name.data()));
  nv.namelen = f.name.size();
  nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(f.value.data()));
  nv.valuelen = f.value.size();
  // RFC 7541 6.2.2: without indexing, for a block this server sends more
  // than once. NGHTTP2_NV_FLAG_NO_INDEX is that, and not 6.2.3's "never
  // indexed", which would say the field is sensitive - a Date is not.
  nv.flags = f.index ? NGHTTP2_NV_FLAG_NONE : NGHTTP2_NV_FLAG_NO_INDEX;
  const ssize_t n =
      nghttp2_hd_deflate_hd(out.enc, out.at, static_cast<size_t>(out.end - out.at), &nv, 1);
  if (n <= 0) return false;
  out.at += n;
  return true;
}
}  // namespace webmachine

#endif  // WEBMACHINE_H2_WIRE_HPP
