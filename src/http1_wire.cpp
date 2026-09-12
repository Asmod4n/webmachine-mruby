// The bodies of the free functions http1.hpp declares.
#include "http1.hpp"

namespace webmachine
{
} // namespace webmachine

namespace webmachine
{
namespace wsdeflate
{
namespace detail
{
bool ci_eq(std::string_view text, std::string_view lit)
{
    const char *const sqe = text.data();
    const size_t count = text.size();
    const size_t litn = lit.size();
    if (count != litn)
        return false;
    for (size_t i = 0; i < count; i++) {
        char conn = sqe[i];
        if (conn >= 'A' && conn <= 'Z')
            conn = static_cast<char>(conn + 32);
        if (conn != lit[i])
            return false;
    }
    return true;
}

bool window_bits(const char *value, size_t count, uint8_t &out_value)
{
    if (count == 0 || count > 2)
        return false;
    if (value[0] == '0')
        return false;
    unsigned x = 0;
    for (size_t i = 0; i < count; i++) {
        if (value[i] < '0' || value[i] > '9')
            return false;
        x = x * 10 + static_cast<unsigned>(value[i] - '0');
    }
    if (x < 8 || x > 15)
        return false;
    out_value = static_cast<uint8_t>(x);
    return true;
}

} // namespace detail
} // namespace wsdeflate
} // namespace webmachine

namespace webmachine
{
namespace wsdeflate
{
bool negotiate(std::string_view value, Negotiated out_value)
{
    const char *const v = value.data();
    const size_t length = value.size();
    size_t i = 0;
    while (i < length) {
        while (i < length && (detail::is_ows(v[i]) || v[i] == ','))
            i++;
        const size_t name_at = i;
        while (i < length && detail::is_tchar(v[i]))
            i++;
        const size_t name_len = i - name_at;
        bool accepted = detail::ci_eq({v + name_at, name_len}, "permessage-deflate");

        Params bytes;
        bytes.on = true;
        bool seen_snct = false, seen_cnct = false, seen_smwb = false, seen_cmwb = false;
        bool echo_cmwb = false;

        while (true) {
            while (i < length && detail::is_ows(v[i]))
                i++;
            if (i >= length || v[i] != ';')
                break;
            i++;
            while (i < length && detail::is_ows(v[i]))
                i++;
            const size_t pn_at = i;
            while (i < length && detail::is_tchar(v[i]))
                i++;
            const size_t pn_len = i - pn_at;
            while (i < length && detail::is_ows(v[i]))
                i++;
            const char *pv = nullptr;
            size_t pv_len = 0;
            bool have_value = false;
            if (i < length && v[i] == '=') {
                i++;
                while (i < length && detail::is_ows(v[i]))
                    i++;
                have_value = true;
                if (i < length && v[i] == '"') {
                    i++;
                    pv = v + i;
                    while (i < length && v[i] != '"') {
                        if (v[i] == '\\' && i + 1 < length)
                            i++;
                        i++;
                    }
                    pv_len = static_cast<size_t>(v + i - pv);
                    if (i < length)
                        i++;
                } else {
                    pv = v + i;
                    while (i < length && detail::is_tchar(v[i]))
                        i++;
                    pv_len = static_cast<size_t>(v + i - pv);
                }
            }
            if (!accepted)
                continue;

            if (detail::ci_eq({v + pn_at, pn_len}, "server_no_context_takeover")) {
                if (seen_snct || have_value) {
                    accepted = false;
                    continue;
                }
                seen_snct = true;
                bytes.server_no_context_takeover = true;
            } else if (detail::ci_eq({v + pn_at, pn_len}, "client_no_context_takeover")) {
                if (seen_cnct || have_value) {
                    accepted = false;
                    continue;
                }
                seen_cnct = true;
                bytes.client_no_context_takeover = true;
            } else if (detail::ci_eq({v + pn_at, pn_len}, "server_max_window_bits")) {
                uint8_t block = 0;
                if (seen_smwb || !have_value || !detail::window_bits(pv, pv_len, block) ||
                    block < kMinRawWindowBits) {
                    accepted = false;
                    continue;
                }
                seen_smwb = true;
                bytes.server_max_window_bits = block;
            } else if (detail::ci_eq({v + pn_at, pn_len}, "client_max_window_bits")) {
                if (seen_cmwb) {
                    accepted = false;
                    continue;
                }
                seen_cmwb = true;
                if (have_value) {
                    uint8_t block = 0;
                    if (!detail::window_bits(pv, pv_len, block)) {
                        accepted = false;
                        continue;
                    }
                    bytes.client_max_window_bits = block;
                    echo_cmwb = true;
                }
            } else {
                accepted = false;
            }
        }

        if (accepted) {
            out_value.params = bytes;
            out_value.echo.assign("permessage-deflate");
            if (bytes.server_no_context_takeover)
                out_value.echo.append("; server_no_context_takeover");
            if (bytes.client_no_context_takeover)
                out_value.echo.append("; client_no_context_takeover");
            if (seen_smwb) {
                out_value.echo.append("; server_max_window_bits=")
                    .append(std::to_string(static_cast<unsigned>(bytes.server_max_window_bits)));
            }
            if (echo_cmwb) {
                out_value.echo.append("; client_max_window_bits=")
                    .append(std::to_string(static_cast<unsigned>(bytes.client_max_window_bits)));
            }
            return true;
        }
        while (i < length && v[i] != ',')
            i++;
    }
    return false;
}

} // namespace wsdeflate
} // namespace webmachine

namespace webmachine
{
namespace ws
{
uint8_t header_need(const unsigned char *headers, uint8_t have)
{
    if (have < 2)
        return 2;
    const uint8_t len7 = static_cast<uint8_t>(headers[1] & 0x7f);
    const uint8_t ext = len7 == 126 ? 2 : (len7 == 127 ? 8 : 0);
    return static_cast<uint8_t>(2 + ext + ((headers[1] & 0x80) != 0 ? 4 : 0));
}

void unmask_copy(char *dst, std::string_view src, Mask method)
{
    for (size_t i = 0; i < src.size(); i++) {
        dst[i] = static_cast<char>(src[i] ^ method.key[(method.at + i) & 3]);
    }
}

Head read_head(const unsigned char *headers, bool have_codec)
{
    Head other;
    const unsigned char b0 = headers[0];
    const unsigned char b1 = headers[1];
    other.fin = (b0 & 0x80) != 0;
    other.rsv1 = (b0 & 0x40) != 0;
    other.opcode = static_cast<uint8_t>(b0 & 0x0f);
    other.control = (other.opcode & 0x08) != 0;
    // RFC 6455 5.2: RSV2 and RSV3 are never negotiated here, and RSV1 only
    // where a codec was.
    if ((b0 & 0x30) != 0) {
        other.err = Head::Err::kProtocol;
        return other;
    }
    if (other.rsv1 && !have_codec) {
        other.err = Head::Err::kProtocol;
        return other;
    }
    switch (other.opcode) {
        case kContinuation:
        case kText:
        case kBinary:
        case kClose:
        case kPing:
        case kPong:
            break;
        default:
            other.err = Head::Err::kProtocol;
            return other;
    }
    // RFC 7692 6: the per-message bit rides the first frame of a data
    // message and nothing else.
    if (other.rsv1 && (other.control || other.opcode == kContinuation)) {
        other.err = Head::Err::kProtocol;
        return other;
    }
    // RFC 6455 5.1: every client frame is masked.
    if ((b1 & 0x80) == 0) {
        other.err = Head::Err::kProtocol;
        return other;
    }
    other.payload_length = static_cast<uint64_t>(b1 & 0x7f);
    other.masking_key_at = 2;
    // RFC 6455 5.2: the shortest encoding that fits, and the top bit of a
    // 64-bit length is reserved.
    if (other.payload_length == 126) {
        other.payload_length = (static_cast<uint64_t>(headers[2]) << 8) | headers[3];
        other.masking_key_at = 4;
        if (other.payload_length < 126) {
            other.err = Head::Err::kProtocol;
            return other;
        }
    } else if (other.payload_length == 127) {
        other.payload_length = 0;
        for (int i = 0; i < 8; i++)
            other.payload_length = (other.payload_length << 8) | headers[2 + i];
        other.masking_key_at = 10;
        if (other.payload_length <= 0xffff || (other.payload_length >> 63) != 0) {
            other.err = Head::Err::kProtocol;
            return other;
        }
    }
    // RFC 6455 5.5: a control frame is short and never fragmented.
    if (other.control && (other.payload_length > kMaxControlPayload || !other.fin)) {
        other.err = Head::Err::kProtocol;
        return other;
    }
    return other;
}

Head::Err admit(const Head &headers, const Message &msg)
{
    const uint8_t msg_op = msg.op;
    const bool msg_deflated = msg.deflated;
    const uint64_t msg_len = msg.len;
    const uint64_t max_message = msg.max;
    if (headers.control)
        return Head::Err::kNone;
    if (headers.opcode == kContinuation) {
        if (msg_op == 0)
            return Head::Err::kProtocol; // continues nothing
        // A deflated message is bounded after inflation, not here.
        if (!msg_deflated && msg_len + headers.payload_length > max_message)
            return Head::Err::kTooBig;
        return Head::Err::kNone;
    }
    if (msg_op != 0)
        return Head::Err::kProtocol; // interleaved data frames
    if (!headers.rsv1 && headers.payload_length > max_message)
        return Head::Err::kTooBig;
    return Head::Err::kNone;
}

} // namespace ws
} // namespace webmachine

namespace webmachine
{
namespace wsdeflate
{
} // namespace wsdeflate
} // namespace webmachine
