// SHA-1 and base64 come from libraries.
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "http1.hpp"

#include <openssl/sha.h>
#include <simdutf.h>

#include <cstring>

namespace webmachine
{
namespace ws
{
namespace
{
// RFC 6455 4.2.2 step 5.4: the 20-byte digest as 28 base64 characters.
void base64_encode_digest(const unsigned char incoming[20], char out[28])
{
    simdutf::binary_to_base64(reinterpret_cast<const char *>(incoming), 20, out);
}

// RFC 6455 4.2.1 step 5: the alphabet a Sec-WebSocket-Key is spelled in.
bool base64_is_char(char character)
{
    return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
           (character >= '0' && character <= '9') || character == '+' || character == '/' ||
           character == '=';
}
} // namespace

// RFC 6455 4.2.2 step 5.4: key + GUID, SHA-1, base64.
bool accept_key_compute(const char *key, size_t key_len, char out[28])
{
    if (key_len != 24)
        return false;
    for (size_t i = 0; i < 24; i++) {
        if (!base64_is_char(key[i]))
            return false;
    }
    unsigned char in[24 + 36];
    std::memcpy(in, key, 24);
    std::memcpy(in + 24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);
    unsigned char digest[20];
    SHA1(in, sizeof(in), digest);
    base64_encode_digest(digest, out);
    return true;
}

// RFC 6455 5.1/5.2: a server frame header (never masked, RSV1 per 7692 6).
size_t header_build(Frame frame, char head[10])
{
    const size_t payload_len = frame.payload_len;
    head[0] = static_cast<char>((frame.fin ? 0x80 : 0x00) | (frame.rsv1 ? 0x40 : 0x00) |
                                (frame.opcode & 0x0f));
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

size_t close_payload_build(Close close, char out[125])
{
    out[0] = static_cast<char>((close.code >> 8) & 0xff);
    out[1] = static_cast<char>(close.code & 0xff);
    const size_t length = close.reason.size() > 123 ? 123 : close.reason.size();
    if (length != 0)
        std::memcpy(out + 2, close.reason.data(), length);
    return length + 2;
}

bool close_read(std::string_view payload, Close &out)
{
    const size_t len = payload.size();
    out.reason = {};
    if (len == 0) {
        out.code = 1005;
        return true;
    }
    if (len == 1)
        return false;
    const uint16_t code = static_cast<uint16_t>((static_cast<unsigned char>(payload[0]) << 8) |
                                                static_cast<unsigned char>(payload[1]));
    // RFC 6455 7.4.2: 1000 to 4999 name a close, and the registered ones
    // this endpoint may be sent are a subset of those. Above 4999 is not a
    // close code at all, and echoing one back made this server spell a
    // number it was never allowed to.
    if (code < 1000 || code > 4999 || code == 1004 || code == 1005 || code == 1006 ||
        (code >= 1016 && code <= 2999) || code == 1015) {
        return false;
    }
    out.code = code;
    out.reason = payload.substr(2);
    return true;
}
} // namespace ws
} // namespace webmachine
