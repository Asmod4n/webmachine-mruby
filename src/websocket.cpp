#include "websocket.hpp"

#include <cstring>

namespace webmachine {
namespace ws {
namespace {

// SHA-1 (FIPS 180-4), written here because the handshake needs exactly
// one hash of exactly one short string, once per connection, and every
// way of getting it from elsewhere costs a dependency this tree would
// carry for 60 lines. It is not a security primitive in this position:
// RFC 6455 4.2.2 uses it as a fixed transform proving the peer read
// the request, and the spec says so itself.
struct Sha1 {
  uint32_t h[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u};
  unsigned char buf[64] = {};
  size_t n = 0;       // bytes in buf
  uint64_t total = 0;  // bytes hashed

  static uint32_t rol(uint32_t v, int s) { return (v << s) | (v >> (32 - s)); }

  void block(const unsigned char* p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
      w[i] = (static_cast<uint32_t>(p[i * 4]) << 24) | (static_cast<uint32_t>(p[i * 4 + 1]) << 16) |
             (static_cast<uint32_t>(p[i * 4 + 2]) << 8) | static_cast<uint32_t>(p[i * 4 + 3]);
    }
    for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
      uint32_t f, k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999u;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1u;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdcu;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6u;
      }
      const uint32_t t = rol(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  }

  void update(const char* p, size_t len) {
    total += len;
    while (len > 0) {
      const size_t take = 64 - n < len ? 64 - n : len;
      std::memcpy(buf + n, p, take);
      n += take;
      p += take;
      len -= take;
      if (n == 64) {
        block(buf);
        n = 0;
      }
    }
  }

  void finish(unsigned char out[20]) {
    const uint64_t bits = total * 8;
    const unsigned char one = 0x80;
    update(reinterpret_cast<const char*>(&one), 1);
    const unsigned char zero = 0;
    while (n != 56) update(reinterpret_cast<const char*>(&zero), 1);
    unsigned char len[8];
    for (int i = 0; i < 8; i++) len[i] = static_cast<unsigned char>(bits >> (56 - i * 8));
    // update() would count these into `total`; the length block is not
    // message bytes, so it goes straight into the buffer.
    std::memcpy(buf + n, len, 8);
    block(buf);
    for (int i = 0; i < 5; i++) {
      out[i * 4] = static_cast<unsigned char>(h[i] >> 24);
      out[i * 4 + 1] = static_cast<unsigned char>(h[i] >> 16);
      out[i * 4 + 2] = static_cast<unsigned char>(h[i] >> 8);
      out[i * 4 + 3] = static_cast<unsigned char>(h[i]);
    }
  }
};

const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// 20 bytes -> 28 base64 characters, the ONE size this file encodes.
// A general encoder would be simdutf's job (mruby-string-is-utf8 ships
// binary_to_base64); this is six lines for a fixed shape.
void b64_20(const unsigned char in[20], char out[28]) {
  size_t o = 0;
  for (size_t i = 0; i < 18; i += 3) {
    const uint32_t v = (static_cast<uint32_t>(in[i]) << 16) |
                       (static_cast<uint32_t>(in[i + 1]) << 8) | in[i + 2];
    out[o++] = kB64[(v >> 18) & 63];
    out[o++] = kB64[(v >> 12) & 63];
    out[o++] = kB64[(v >> 6) & 63];
    out[o++] = kB64[v & 63];
  }
  // The last two bytes: 16 bits -> three characters and one pad.
  const uint32_t v = (static_cast<uint32_t>(in[18]) << 16) | (static_cast<uint32_t>(in[19]) << 8);
  out[o++] = kB64[(v >> 18) & 63];
  out[o++] = kB64[(v >> 12) & 63];
  out[o++] = kB64[(v >> 6) & 63];
  out[o] = '=';
}

bool b64_char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' ||
         c == '/' || c == '=';
}

}  // namespace

bool accept_key(const char* key, size_t key_len, char out[28]) {
  // RFC 6455 4.2.1 step 5: the key is 16 bytes base64'd, so 24
  // characters. Checked rather than assumed - the hash below would
  // happily digest anything, and a peer that sent nonsense should be
  // told so instead of getting a valid-looking accept.
  if (key_len != 24) return false;
  for (size_t i = 0; i < 24; i++) {
    if (!b64_char(key[i])) return false;
  }
  Sha1 s;
  s.update(key, 24);
  s.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);  // 4.2.2, the fixed GUID
  unsigned char digest[20];
  s.finish(digest);
  b64_20(digest, out);
  return true;
}

Parse parse(char* data, size_t len, size_t max_payload, Frame& out, uint16_t& code) {
  code = kCloseProtocolError;
  if (len < 2) return Parse::kNeedMore;
  const unsigned char b0 = static_cast<unsigned char>(data[0]);
  const unsigned char b1 = static_cast<unsigned char>(data[1]);
  const bool fin = (b0 & 0x80) != 0;
  const uint8_t rsv = static_cast<uint8_t>(b0 & 0x70);
  const uint8_t opcode = static_cast<uint8_t>(b0 & 0x0f);
  // RSV1-3 must be zero unless an extension negotiated them (5.2).
  // Round one negotiates none, so any of them is a protocol error -
  // round two's permessage-deflate is what makes RSV1 legal.
  if (rsv != 0) return Parse::kError;
  switch (opcode) {
    case kContinuation:
    case kText:
    case kBinary:
    case kClose:
    case kPing:
    case kPong: break;
    default: return Parse::kError;  // 5.2: every other opcode is reserved
  }
  const bool control = (opcode & 0x08) != 0;
  const bool masked = (b1 & 0x80) != 0;
  uint64_t plen = static_cast<uint64_t>(b1 & 0x7f);
  size_t at = 2;
  if (plen == 126) {
    if (len < at + 2) return Parse::kNeedMore;
    plen = (static_cast<uint64_t>(static_cast<unsigned char>(data[at])) << 8) |
           static_cast<unsigned char>(data[at + 1]);
    at += 2;
    // 5.2: the minimal number of bytes MUST be used for the length.
    if (plen < 126) return Parse::kError;
  } else if (plen == 127) {
    if (len < at + 8) return Parse::kNeedMore;
    plen = 0;
    for (int i = 0; i < 8; i++) {
      plen = (plen << 8) | static_cast<unsigned char>(data[at + i]);
    }
    at += 8;
    if (plen <= 0xffff) return Parse::kError;      // not minimal
    if ((plen >> 63) != 0) return Parse::kError;   // 5.2: the high bit is 0
  }
  // 5.5: a control frame carries at most 125 bytes and is never
  // fragmented. Both are the frame being wrong, not the payload.
  if (control && (plen > kMaxControlPayload || !fin)) return Parse::kError;
  if (plen > max_payload) {
    code = kCloseTooBig;
    return Parse::kError;
  }
  // 5.1: a client-to-server frame MUST be masked.
  if (!masked) return Parse::kError;
  if (len < at + 4) return Parse::kNeedMore;
  unsigned char mask[4];
  std::memcpy(mask, data + at, 4);
  at += 4;
  if (len - at < plen) return Parse::kNeedMore;

  char* payload = data + at;
  const size_t n = static_cast<size_t>(plen);
  // 5.3: unmask IN PLACE - the payload is then the caller's to read
  // where it already lies, and no frame is ever copied here.
  for (size_t i = 0; i < n; i++) payload[i] = static_cast<char>(payload[i] ^ mask[i & 3]);

  out.opcode = opcode;
  out.fin = fin;
  out.payload = payload;
  out.len = n;
  out.consumed = at + n;
  return Parse::kOk;
}

size_t build_header(uint8_t opcode, bool fin, size_t payload_len, char head[10]) {
  head[0] = static_cast<char>((fin ? 0x80 : 0x00) | (opcode & 0x0f));
  // 5.1: a server frame is never masked, so the mask bit stays 0 and
  // there are no mask bytes to write.
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
  // 7.1.6 with 5.5: the reason shares a control frame's 125 bytes with
  // the two-byte code, so 123 is what is left. Truncated, not refused:
  // a reason is human text, and losing its tail is better than losing
  // the close.
  size_t n = reason_len > 123 ? 123 : reason_len;
  if (n != 0) std::memcpy(out + 2, reason, n);
  return n + 2;
}

bool read_close(const char* payload, size_t len, uint16_t& code, const char** reason,
                size_t* reason_len) {
  *reason = nullptr;
  *reason_len = 0;
  if (len == 0) {
    // 7.1.5: no payload means no status - a normal close, not an error.
    code = 1005;
    return true;
  }
  if (len == 1) return false;  // 7.1.6: the code is two bytes or nothing
  code = static_cast<uint16_t>((static_cast<unsigned char>(payload[0]) << 8) |
                               static_cast<unsigned char>(payload[1]));
  // 7.4.1: 0-999 are never used, 1004/1005/1006 and 1015 are reserved
  // for the local end and MUST NOT appear on the wire, and 1016-2999
  // is unassigned.
  if (code < 1000 || code == 1004 || code == 1005 || code == 1006 ||
      (code >= 1016 && code <= 2999) || code == 1015) {
    return false;
  }
  *reason = payload + 2;
  *reason_len = len - 2;
  return true;
}

}  // namespace ws
}  // namespace webmachine
