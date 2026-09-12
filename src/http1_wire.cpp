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
    const char *const s = text.data();
    const size_t n = text.size();
    const size_t litn = lit.size();
    if (n != litn)
        return false;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + 32);
        if (c != lit[i])
            return false;
    }
    return true;
}

bool window_bits(const char *v, size_t n, uint8_t &out)
{
    if (n == 0 || n > 2)
        return false;
    if (v[0] == '0')
        return false;
    unsigned x = 0;
    for (size_t i = 0; i < n; i++) {
        if (v[i] < '0' || v[i] > '9')
            return false;
        x = x * 10 + static_cast<unsigned>(v[i] - '0');
    }
    if (x < 8 || x > 15)
        return false;
    out = static_cast<uint8_t>(x);
    return true;
}

} // namespace detail
} // namespace wsdeflate
} // namespace webmachine

namespace webmachine
{
namespace wsdeflate
{
bool negotiate(std::string_view value, Negotiated out)
{
    const char *const v = value.data();
    const size_t len = value.size();
    size_t i = 0;
    while (i < len) {
        while (i < len && (detail::is_ows(v[i]) || v[i] == ','))
            i++;
        const size_t name_at = i;
        while (i < len && detail::is_tchar(v[i]))
            i++;
        const size_t name_len = i - name_at;
        bool ok = detail::ci_eq({v + name_at, name_len}, "permessage-deflate");

        Params p;
        p.on = true;
        bool seen_snct = false, seen_cnct = false, seen_smwb = false, seen_cmwb = false;
        bool echo_cmwb = false;

        while (true) {
            while (i < len && detail::is_ows(v[i]))
                i++;
            if (i >= len || v[i] != ';')
                break;
            i++;
            while (i < len && detail::is_ows(v[i]))
                i++;
            const size_t pn_at = i;
            while (i < len && detail::is_tchar(v[i]))
                i++;
            const size_t pn_len = i - pn_at;
            while (i < len && detail::is_ows(v[i]))
                i++;
            const char *pv = nullptr;
            size_t pv_len = 0;
            bool have_value = false;
            if (i < len && v[i] == '=') {
                i++;
                while (i < len && detail::is_ows(v[i]))
                    i++;
                have_value = true;
                if (i < len && v[i] == '"') {
                    i++;
                    pv = v + i;
                    while (i < len && v[i] != '"') {
                        if (v[i] == '\\' && i + 1 < len)
                            i++;
                        i++;
                    }
                    pv_len = static_cast<size_t>(v + i - pv);
                    if (i < len)
                        i++;
                } else {
                    pv = v + i;
                    while (i < len && detail::is_tchar(v[i]))
                        i++;
                    pv_len = static_cast<size_t>(v + i - pv);
                }
            }
            if (!ok)
                continue;

            if (detail::ci_eq({v + pn_at, pn_len}, "server_no_context_takeover")) {
                if (seen_snct || have_value) {
                    ok = false;
                    continue;
                }
                seen_snct = true;
                p.server_no_context_takeover = true;
            } else if (detail::ci_eq({v + pn_at, pn_len}, "client_no_context_takeover")) {
                if (seen_cnct || have_value) {
                    ok = false;
                    continue;
                }
                seen_cnct = true;
                p.client_no_context_takeover = true;
            } else if (detail::ci_eq({v + pn_at, pn_len}, "server_max_window_bits")) {
                uint8_t b = 0;
                if (seen_smwb || !have_value || !detail::window_bits(pv, pv_len, b) ||
                    b < kMinRawWindowBits) {
                    ok = false;
                    continue;
                }
                seen_smwb = true;
                p.server_max_window_bits = b;
            } else if (detail::ci_eq({v + pn_at, pn_len}, "client_max_window_bits")) {
                if (seen_cmwb) {
                    ok = false;
                    continue;
                }
                seen_cmwb = true;
                if (have_value) {
                    uint8_t b = 0;
                    if (!detail::window_bits(pv, pv_len, b)) {
                        ok = false;
                        continue;
                    }
                    p.client_max_window_bits = b;
                    echo_cmwb = true;
                }
            } else {
                ok = false;
            }
        }

        if (ok) {
            out.params = p;
            out.echo.assign("permessage-deflate");
            if (p.server_no_context_takeover)
                out.echo.append("; server_no_context_takeover");
            if (p.client_no_context_takeover)
                out.echo.append("; client_no_context_takeover");
            if (seen_smwb) {
                out.echo.append("; server_max_window_bits=")
                    .append(std::to_string(static_cast<unsigned>(p.server_max_window_bits)));
            }
            if (echo_cmwb) {
                out.echo.append("; client_max_window_bits=")
                    .append(std::to_string(static_cast<unsigned>(p.client_max_window_bits)));
            }
            return true;
        }
        while (i < len && v[i] != ',')
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
uint8_t header_need(const unsigned char *h, uint8_t have)
{
    if (have < 2)
        return 2;
    const uint8_t len7 = static_cast<uint8_t>(h[1] & 0x7f);
    const uint8_t ext = len7 == 126 ? 2 : (len7 == 127 ? 8 : 0);
    return static_cast<uint8_t>(2 + ext + ((h[1] & 0x80) != 0 ? 4 : 0));
}

void unmask_copy(char *dst, std::string_view src, Mask m)
{
    for (size_t i = 0; i < src.size(); i++) {
        dst[i] = static_cast<char>(src[i] ^ m.key[(m.at + i) & 3]);
    }
}

Head read_head(const unsigned char *h, bool have_codec)
{
    Head o;
    const unsigned char b0 = h[0];
    const unsigned char b1 = h[1];
    o.fin = (b0 & 0x80) != 0;
    o.rsv1 = (b0 & 0x40) != 0;
    o.opcode = static_cast<uint8_t>(b0 & 0x0f);
    o.control = (o.opcode & 0x08) != 0;
    // RFC 6455 5.2: RSV2 and RSV3 are never negotiated here, and RSV1 only
    // where a codec was.
    if ((b0 & 0x30) != 0) {
        o.err = Head::Err::kProtocol;
        return o;
    }
    if (o.rsv1 && !have_codec) {
        o.err = Head::Err::kProtocol;
        return o;
    }
    switch (o.opcode) {
        case kContinuation:
        case kText:
        case kBinary:
        case kClose:
        case kPing:
        case kPong:
            break;
        default:
            o.err = Head::Err::kProtocol;
            return o;
    }
    // RFC 7692 6: the per-message bit rides the first frame of a data
    // message and nothing else.
    if (o.rsv1 && (o.control || o.opcode == kContinuation)) {
        o.err = Head::Err::kProtocol;
        return o;
    }
    // RFC 6455 5.1: every client frame is masked.
    if ((b1 & 0x80) == 0) {
        o.err = Head::Err::kProtocol;
        return o;
    }
    o.payload_length = static_cast<uint64_t>(b1 & 0x7f);
    o.masking_key_at = 2;
    // RFC 6455 5.2: the shortest encoding that fits, and the top bit of a
    // 64-bit length is reserved.
    if (o.payload_length == 126) {
        o.payload_length = (static_cast<uint64_t>(h[2]) << 8) | h[3];
        o.masking_key_at = 4;
        if (o.payload_length < 126) {
            o.err = Head::Err::kProtocol;
            return o;
        }
    } else if (o.payload_length == 127) {
        o.payload_length = 0;
        for (int i = 0; i < 8; i++)
            o.payload_length = (o.payload_length << 8) | h[2 + i];
        o.masking_key_at = 10;
        if (o.payload_length <= 0xffff || (o.payload_length >> 63) != 0) {
            o.err = Head::Err::kProtocol;
            return o;
        }
    }
    // RFC 6455 5.5: a control frame is short and never fragmented.
    if (o.control && (o.payload_length > kMaxControlPayload || !o.fin)) {
        o.err = Head::Err::kProtocol;
        return o;
    }
    return o;
}

Head::Err admit(const Head &h, const Message &msg)
{
    const uint8_t msg_op = msg.op;
    const bool msg_deflated = msg.deflated;
    const uint64_t msg_len = msg.len;
    const uint64_t max_message = msg.max;
    if (h.control)
        return Head::Err::kNone;
    if (h.opcode == kContinuation) {
        if (msg_op == 0)
            return Head::Err::kProtocol; // continues nothing
        // A deflated message is bounded after inflation, not here.
        if (!msg_deflated && msg_len + h.payload_length > max_message)
            return Head::Err::kTooBig;
        return Head::Err::kNone;
    }
    if (msg_op != 0)
        return Head::Err::kProtocol; // interleaved data frames
    if (!h.rsv1 && h.payload_length > max_message)
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
