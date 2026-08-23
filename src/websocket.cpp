// Silences OpenSSL 3's deprecation of the one-shot SHA1() - see above.
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "webmachine.hpp"

#include <openssl/sha.h>
#include <simdutf.h>

#include <cstring>

namespace webmachine {
namespace ws {
namespace {

// SHA-1 and base64 both come from a library, and NEITHER is written
// here any more (Nutzer-Entscheid 2026-08-22, on measured experience:
// a hand-rolled SHA-1 was a bottleneck in an earlier tree). The
// handshake is the only place this tree hashes anything at all - RFC
// 6455 4.2.2 uses SHA-1 as a fixed transform proving the peer read the
// request, not as a security primitive, and says so itself.
//
// <openssl/sha.h>, deliberately, and it is not a TLS dependency
// sneaking back in: it is ONE function out of libcrypto, which is on
// every server distribution (the standing rule: a stable ABI that is
// everywhere gets used, not carried), and aws-lc - the crypto library
// this stack will bring along when TLS returns through mruby-ktls/s2n
// - answers the SAME API. So the day libcrypto here IS aws-lc, not a
// line below changes.
//
// SHA1() is a low-level call OpenSSL 3 marks deprecated in favour of
// EVP. Named here rather than obeyed: EVP would allocate a context per
// handshake to hash sixty bytes, and aws-lc does not deprecate it at
// all.
// 20 bytes -> 28 base64 characters, through simdutf (the same library
// that validates text frames, arriving through the user's own
// mruby-string-is-utf8). Writing this by hand was six lines and it is
// still gone: one base64 in the process, and it is the one that has
// been fuzzed by somebody else.
void b64_20(const unsigned char in[20], char out[28]) {
  simdutf::binary_to_base64(reinterpret_cast<const char*>(in), 20, out);
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
  // 4.2.2: the key, then the fixed GUID - sixty bytes, one block.
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
  // RSV1-3 must be zero unless an extension negotiated them (5.2).
  // RSV2 and RSV3 name extensions this tree does not offer, so they
  // are refusals for good; RSV1 is permessage-deflate's, legal exactly
  // when it was negotiated.
  if ((b0 & 0x30) != 0) return Parse::kError;
  if (rsv1 && !allow_rsv1) return Parse::kError;
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
  // RFC 7692 6: the bit belongs to the message, so it rides its FIRST
  // frame. A continuation carrying it, or a control frame carrying it,
  // is the peer confusing a message with a frame.
  if (rsv1 && (control || opcode == kContinuation)) return Parse::kError;
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
  out.rsv1 = rsv1;
  out.payload = payload;
  out.len = n;
  out.consumed = at + n;
  return Parse::kOk;
}

size_t build_header(uint8_t opcode, bool fin, bool rsv1, size_t payload_len, char head[10]) {
  head[0] = static_cast<char>((fin ? 0x80 : 0x00) | (rsv1 ? 0x40 : 0x00) | (opcode & 0x0f));
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
