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
size_t build_header(Frame f, char head[10]) {
  const size_t payload_len = f.payload_len;
  head[0] = static_cast<char>((f.fin ? 0x80 : 0x00) | (f.rsv1 ? 0x40 : 0x00) | (f.opcode & 0x0f));
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

size_t build_close_payload(Close close, char out[125]) {
  out[0] = static_cast<char>((close.code >> 8) & 0xff);
  out[1] = static_cast<char>(close.code & 0xff);
  const size_t n = close.reason.size() > 123 ? 123 : close.reason.size();
  if (n != 0) std::memcpy(out + 2, close.reason.data(), n);
  return n + 2;
}

bool read_close(std::string_view payload, Close& out) {
  const size_t len = payload.size();
  out.reason = {};
  if (len == 0) {
    out.code = 1005;
    return true;
  }
  if (len == 1) return false;
  const uint16_t code = static_cast<uint16_t>((static_cast<unsigned char>(payload[0]) << 8) |
                                              static_cast<unsigned char>(payload[1]));
  if (code < 1000 || code == 1004 || code == 1005 || code == 1006 ||
      (code >= 1016 && code <= 2999) || code == 1015) {
    return false;
  }
  out.code = code;
  out.reason = payload.substr(2);
  return true;
}
}
}
