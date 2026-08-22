// WebSocket (#175), round one: the HANDSHAKE key and the FRAMING, and
// nothing else. No IO, no mruby, no connection state - bytes in, bytes
// out, the way embed.hpp cut h1 (#173). Everything here is protocol
// truth from RFC 6455, so it can be driven from a test binary and
// later by Autobahn without a socket in sight.
//
// Why this tree writes its own instead of taking a library: the
// framing IS this file - a bit test, a length, a four-byte mask - and
// every candidate library brought its own event loop, its own
// allocator, or its own buffer discipline, each of which is a thing
// this tree already owns and only owns once.
//
// What round one deliberately does NOT do: text-frame UTF-8
// validation (round one's caller does it through
// mruby-string-is-utf8, whose simdutf validates a whole buffer with
// SIMD - reimplementing that here would be the slow variant of a
// solved problem), permessage-deflate (round two, the system zlib), and any
// policy about who may open a socket (that is the route's).
#ifndef WEBMACHINE_WEBSOCKET_HPP
#define WEBMACHINE_WEBSOCKET_HPP

#include <cstddef>
#include <cstdint>

namespace webmachine {
namespace ws {

// RFC 6455 5.2: opcodes. The gaps are reserved and refused by name.
enum : uint8_t {
  kContinuation = 0x0,
  kText = 0x1,
  kBinary = 0x2,
  kClose = 0x8,
  kPing = 0x9,
  kPong = 0xa,
};

// RFC 6455 7.4.1: the close codes this tree can be the sender of.
enum : uint16_t {
  kCloseNormal = 1000,
  kCloseGoingAway = 1001,
  kCloseProtocolError = 1002,
  kCloseUnsupportedData = 1003,
  kCloseInvalidPayload = 1007,
  kClosePolicyViolation = 1008,
  kCloseTooBig = 1009,
  kCloseInternalError = 1011,
};

// RFC 6455 5.5: a control frame's payload is at most 125 bytes and it
// may not be fragmented. Both are refusals, not clamps.
inline constexpr size_t kMaxControlPayload = 125;

// The 24 bytes of "<key>258EAFA5-E914-47DA-95CA-C5AB0DC85B11" hashed
// and base64'd - RFC 6455 4.2.2 step 5.4. `out` takes 28 bytes plus no
// terminator. False: the key was not 24 base64 characters, which is
// the one thing the client half of the handshake must get right.
bool accept_key(const char* key, size_t key_len, char out[28]);

// What one parse produced. `payload` points INTO the caller's buffer,
// unmasked in place - a frame is never copied here.
struct Frame {
  uint8_t opcode = 0;
  bool fin = false;
  const char* payload = nullptr;
  size_t len = 0;
  size_t consumed = 0;  // bytes of the input this frame occupied
};

enum class Parse : uint8_t {
  kOk,       // a whole frame, in `out`
  kNeedMore, // a prefix - call again when more bytes arrived
  kError,    // protocol error; `code` says which close it earns
};

// ONE frame off the front of `data`. The buffer is WRITTEN to: a
// client frame is masked (5.3) and unmasking in place is what makes
// the payload usable without a copy, which is the whole reason this
// takes a mutable buffer.
//
// `max_payload` bounds what this side is willing to hold; past it the
// answer is kError with 1009 rather than an allocation the peer chose
// the size of.
Parse parse(char* data, size_t len, size_t max_payload, Frame& out, uint16_t& code);

// A SERVER frame: never masked (5.1), FIN set unless the caller is
// fragmenting on purpose. Returns the header length written into
// `head` (at most 10 bytes); the payload follows unchanged, which is
// why this writes a header instead of a buffer - the body goes out
// where it already lies.
size_t build_header(uint8_t opcode, bool fin, size_t payload_len, char head[10]);

// A close frame's payload: the code big-endian, then the reason (7.1.6
// - at most 123 bytes of it, so the frame stays a legal control
// frame). Returns the payload length written into `out` (125 max).
size_t build_close_payload(uint16_t code, const char* reason, size_t reason_len,
                           char out[125]);

// The code a received close frame carries, and its reason. A zero
// length payload is 1005 "no status" (7.1.5) and NOT an error; a
// one-byte payload IS one (7.1.6 gives the code two bytes). False =
// malformed, answer 1002.
bool read_close(const char* payload, size_t len, uint16_t& code, const char** reason,
                size_t* reason_len);

}  // namespace ws
}  // namespace webmachine

#endif
