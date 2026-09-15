#ifndef WEBMACHINE_H2_WIRE_HPP
#define WEBMACHINE_H2_WIRE_HPP

// RFC 9113 4/6 and RFC 7541. A frame is the same for a server answering
// and a client asking, and it lives apart so a misread length is a bug
// in one place. Nothing else in this tree may enter here: no mruby, no
// io_uring, no Conn, no state.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "lshpack.h"

namespace webmachine
{
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
// to agree with ls-hpack's own default by luck. One number, one place;
// if the SETTINGS frame ever names a size, it names this.
inline constexpr uint32_t kH2DecTableSize = 4096;
inline constexpr int64_t kH2WindowCeiling = 0x7fffffff;

struct H2FrameHead {
    uint32_t len;
    uint8_t type;
    uint8_t flags;
    uint32_t stream;
};



// RFC 9113 4.1: every field of a frame header is network order, and a
// stream id carries a reserved bit that h2_u31 masks off.
inline void h2_put_frame_header(unsigned char *bytes, H2FrameHead facts)
{
    const uint32_t len = facts.len;
    const uint32_t stream = facts.stream;
    bytes[0] = static_cast<unsigned char>(len >> 16);
    bytes[1] = static_cast<unsigned char>(len >> 8);
    bytes[2] = static_cast<unsigned char>(len);
    bytes[3] = facts.type;
    bytes[4] = facts.flags;
    bytes[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
    bytes[6] = static_cast<unsigned char>(stream >> 16);
    bytes[7] = static_cast<unsigned char>(stream >> 8);
    bytes[8] = static_cast<unsigned char>(stream);
}

inline void h2_patch_stream_id(unsigned char *bytes, uint32_t stream)
{
    bytes[5] = static_cast<unsigned char>((stream >> 24) & 0x7f);
    bytes[6] = static_cast<unsigned char>(stream >> 16);
    bytes[7] = static_cast<unsigned char>(stream >> 8);
    bytes[8] = static_cast<unsigned char>(stream);
}

inline uint32_t h2_u24(const unsigned char *bytes)
{
    return (static_cast<uint32_t>(bytes[0]) << 16) | (static_cast<uint32_t>(bytes[1]) << 8) |
           bytes[2];
}

inline uint32_t h2_u32(const unsigned char *bytes)
{
    return (static_cast<uint32_t>(bytes[0]) << 24) | (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) | bytes[3];
}

inline uint32_t h2_u31(const unsigned char *bytes)
{
    return h2_u32(bytes) & 0x7fffffff;
}

uint16_t h2_u16(const unsigned char *bytes);

// `at` is a reference: encoding a field advances it, and what the caller
// wrote is `at` minus where it started.
struct H2BlockOut {
    struct lshpack_enc *enc;
    unsigned char *&at;
    unsigned char *end;
};

// RFC 7541 6.2: `index` says whether ls-hpack may put the line in the
// dynamic table (6.2.1) or must spell it without one (6.2.2). It
// matters for any block that is cached and replayed: HPACK is
// stateful, so replaying an insert makes the peer insert - and evict -
// once per replay, which on a busy connection is one allocation per answer
// in every client that talks to us. A block we send more than once must
// not move the peer's table.
struct H2Field {
    std::string_view name;
    std::string_view value;
    bool index = true;
};

// Lane 2 - one per-request field through ls-hpack's encoder. ls-hpack
// wants name and value in one buffer with the offsets named, so the pair
// is spelled out here first. Returns false when the field would not fit -
// the caller then has an error to name, not a truncated block.
bool h2_enc_field(H2BlockOut out, const H2Field &facts);
} // namespace webmachine

#endif // WEBMACHINE_H2_WIRE_HPP
