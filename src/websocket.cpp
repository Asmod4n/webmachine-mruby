// Design decisions live in .DESIGN.md, filed under what each comment names.
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "webmachine.hpp"

#include <openssl/sha.h>
#include <simdutf.h>

#include <cstring>

namespace webmachine {
namespace ws {
namespace {
// RFC 6455 4.2.2 step 5.4: the 20-byte digest as 28 base64 characters.
void b64_20(const unsigned char in[20], char out[28]) {
  simdutf::binary_to_base64(reinterpret_cast<const char*>(in), 20, out);
}

// RFC 6455 4.2.1 step 5: the alphabet a Sec-WebSocket-Key is spelled in.
bool b64_char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' ||
         c == '/' || c == '=';
}
}

// RFC 6455 4.2.2 step 5.4: key + GUID, SHA-1, base64.
bool accept_key(const char* key, size_t key_len, char out[28]) {
  if (key_len != 24) return false;
  for (size_t i = 0; i < 24; i++) {
    if (!b64_char(key[i])) return false;
  }
  unsigned char in[24 + 36];
  std::memcpy(in, key, 24);
  std::memcpy(in + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
  unsigned char digest[20];
  SHA1(in, sizeof(in), digest);
  b64_20(digest, out);
  return true;
}

Parse parse(char* data, size_t len, size_t max_payload, bool allow_rsv1, Frame& out,
            uint16_t& code) {
  code = kCloseProtocolError;
  if (len < 2) return Parse::kNeedMore;
  const unsigned char b0 = static_cast<unsigned char>(data[0]);
  const unsigned char b1 = static_cast<unsigned char>(data[1]);
  const bool fin = (b0 & 0x80) != 0;
  const bool rsv1 = (b0 & 0x40) != 0;
  const uint8_t opcode = static_cast<uint8_t>(b0 & 0x0f);
  if ((b0 & 0x30) != 0) return Parse::kError;
  if (rsv1 && !allow_rsv1) return Parse::kError;
  switch (opcode) {
    case kContinuation:
    case kText:
    case kBinary:
    case kClose:
    case kPing:
    case kPong: break;
    default: return Parse::kError;
  }
  const bool control = (opcode & 0x08) != 0;
  if (rsv1 && (control || opcode == kContinuation)) return Parse::kError;
  const bool masked = (b1 & 0x80) != 0;
  uint64_t payload_length = static_cast<uint64_t>(b1 & 0x7f);
  size_t at = 2;
  if (payload_length == 126) {
    if (len < at + 2) return Parse::kNeedMore;
    payload_length = (static_cast<uint64_t>(static_cast<unsigned char>(data[at])) << 8) |
           static_cast<unsigned char>(data[at + 1]);
    at += 2;
    if (payload_length < 126) return Parse::kError;
  } else if (payload_length == 127) {
    if (len < at + 8) return Parse::kNeedMore;
    payload_length = 0;
    for (int i = 0; i < 8; i++) {
      payload_length = (payload_length << 8) | static_cast<unsigned char>(data[at + i]);
    }
    at += 8;
    if (payload_length <= 0xffff) return Parse::kError;
    if ((payload_length >> 63) != 0) return Parse::kError;
  }
  if (control && (payload_length > kMaxControlPayload || !fin)) return Parse::kError;
  if (payload_length > max_payload) {
    code = kCloseTooBig;
    return Parse::kError;
  }
  if (!masked) return Parse::kError;
  if (len < at + 4) return Parse::kNeedMore;
  unsigned char mask[4];
  std::memcpy(mask, data + at, 4);
  at += 4;
  if (len - at < payload_length) return Parse::kNeedMore;

  char* payload = data + at;
  const size_t n = static_cast<size_t>(payload_length);
  for (size_t i = 0; i < n; i++) payload[i] = static_cast<char>(payload[i] ^ mask[i & 3]);

  out.opcode = opcode;
  out.fin = fin;
  out.rsv1 = rsv1;
  out.payload = payload;
  out.payload_length = n;
  out.consumed = at + n;
  return Parse::kOk;
}

// RFC 6455 5.1/5.2: a server frame header (never masked, RSV1 per 7692 6).
size_t build_header(uint8_t opcode, bool fin, bool rsv1, size_t payload_len, char head[10]) {
  head[0] = static_cast<char>((fin ? 0x80 : 0x00) | (rsv1 ? 0x40 : 0x00) | (opcode & 0x0f));
  if (payload_len < 126) {
    head[1] = static_cast<char>(payload_len);
    return 2;
  }
  if (payload_len <= 0xffff) {
    head[1] = 126;
    head[2] = static_cast<char>((payload_len >> 8) & 0xff);
    head[3] = static_cast<char>(payload_len & 0xff);
    return 4;
  }
  head[1] = 127;
  for (int i = 0; i < 8; i++) {
    head[2 + i] = static_cast<char>((payload_len >> (56 - i * 8)) & 0xff);
  }
  return 10;
}

size_t build_close_payload(uint16_t code, const char* reason, size_t reason_len,
                           char out[125]) {
  out[0] = static_cast<char>((code >> 8) & 0xff);
  out[1] = static_cast<char>(code & 0xff);
  size_t n = reason_len > 123 ? 123 : reason_len;
  if (n != 0) std::memcpy(out + 2, reason, n);
  return n + 2;
}

bool read_close(const char* payload, size_t len, uint16_t& code, const char** reason,
                size_t* reason_len) {
  *reason = nullptr;
  *reason_len = 0;
  if (len == 0) {
    code = 1005;
    return true;
  }
  if (len == 1) return false;
  code = static_cast<uint16_t>((static_cast<unsigned char>(payload[0]) << 8) |
                               static_cast<unsigned char>(payload[1]));
  if (code < 1000 || code == 1004 || code == 1005 || code == 1006 ||
      (code >= 1016 && code <= 2999) || code == 1015) {
    return false;
  }
  *reason = payload + 2;
  *reason_len = len - 2;
  return true;
}
}
}
