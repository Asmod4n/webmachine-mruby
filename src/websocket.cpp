// Design decisions live in .DESIGN.md, filed under what each comment names.
// SHA-1 and base64 come from libraries.
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
