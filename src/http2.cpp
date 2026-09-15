#include "webmachine.hpp"

#include "ring.hpp"

#include <array>
#include <optional>
#include <picohttpparser.h>

#include <cstring>

namespace webmachine
{
namespace
{
constexpr size_t kH2FragBudget = kMaxHead * 2;
// RFC 7541 5.2: the bytes one decoded field may take, name and value
// together, with the decoder's own CRLF. hdrbuf holds a whole block plus
// one such window, sized once, so nothing that points into it moves
// while a block is read.
constexpr size_t kH2FieldWindow = 4096;
constexpr size_t kH2HdrBufSize = kH2FragBudget + kH2FieldWindow;

// RFC 9113 8.1.1: how many streams one connection may lose to a request
// that breaks its own Content-Length before the connection itself ends.
// Four leaves room for a client with a defect and ends a client that
// makes the defect its method.
constexpr uint32_t kH2LieBudget = 4;

// RFC 9113 8.1: how many streams one connection may reset inside
// kH2ResetWindow seconds before the connection itself ends. A cancelled
// fetch is one reset. A hundred in ten seconds is a peer spending this
// server's time on purpose.
// This is Helidon's number, the strictest of nginx, Netty and Helidon.
// One core here answers about a million requests a second, so an honest
// client stays far below it.
constexpr uint32_t kH2ResetBudget = 100;
constexpr int64_t kH2ResetWindow = 10;
constexpr size_t kH2MergeBody = 1024;

void u32_put(unsigned char *bytes, uint32_t value)
{
    bytes[0] = static_cast<unsigned char>(value >> 24);
    bytes[1] = static_cast<unsigned char>(value >> 16);
    bytes[2] = static_cast<unsigned char>(value >> 8);
    bytes[3] = static_cast<unsigned char>(value);
}

struct H2Control {
    uint8_t type;
    uint8_t flags;
    uint32_t stream;
    std::span<const unsigned char> payload;
};

void control_frame_emit(std::string &sink, const H2Control &control)
{
    const uint32_t length = static_cast<uint32_t>(control.payload.size());
    unsigned char frame_head[kH2FrameHeaderLen];
    h2_put_frame_header(frame_head, {length, control.type, control.flags, control.stream});
    sink.append(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
    if (length != 0)
        sink.append(reinterpret_cast<const char *>(control.payload.data()), length);
}

// RFC 9113 6.9: every DATA frame counts against the connection window,
// a refused one as well. The credit for it goes back at once.
void h2_credit_connection(std::string &sink, uint32_t flen)
{
    if (flen == 0)
        return;
    unsigned char increment[4];
    u32_put(increment, flen);
    control_frame_emit(sink, {kH2WindowUpdate, 0, 0, increment});
}

// RFC 7541 5.2: a string length, 7-bit prefix, H bit 0.
void hpack_length_spell(std::string &out_answer, size_t length)
{
    if (length < 127) {
        out_answer.push_back(static_cast<char>(length));
        return;
    }
    out_answer.push_back(0x7f);
    length -= 127;
    while (length >= 128) {
        out_answer.push_back(static_cast<char>(0x80 | (length & 0x7f)));
        length >>= 7;
    }
    out_answer.push_back(static_cast<char>(length));
}

// RFC 7541 6.2.2: literal without indexing, indexed name, 4-bit prefix.
void hpack_name_index_spell(std::string &out_answer, uint32_t index)
{
    if (index < 15) {
        out_answer.push_back(static_cast<char>(index));
        return;
    }
    out_answer.push_back(0x0f);
    index -= 15;
    while (index >= 128) {
        out_answer.push_back(static_cast<char>(0x80 | (index & 0x7f)));
        index >>= 7;
    }
    out_answer.push_back(static_cast<char>(index));
}
} // namespace

void h2_free(H2State *h2_state)
{
    delete h2_state;
}

// A parked request's bytes are the stream's own copy, so the spans
// have to be captured again.
const ReqView *Http1::h2_parked_view(Conn &conn, Parked bytes)
{
    const std::string_view target = bytes.target;
    ReqView &out_answer = bytes.view;
    if (target.empty())
        return nullptr;
    const AppSlot &slot = apps_[conn.listener];
    const int round = slot.table->match(target.data(), target.size(), bytes.spans);
    if (round < 0)
        return nullptr;
    out_answer.spans = &bytes.spans;
    out_answer.request_target = target.data();
    out_answer.request_target_len = target.size();
    out_answer.path_len = http::path_only(target.data(), target.size());
    out_answer.table = slot.table;
    out_answer.route = round;
    return &out_answer;
}

void Http1::h2_build_block(H2Block &block, const H2BlockFields &field)
{
    const uint16_t status = field.status;
    const std::string *const ctype = field.ctype;
    const std::string *const allow = field.allow;
    block.bytes.clear();
    switch (status) {
        case 200:
            block.bytes.push_back(static_cast<char>(0x88));
            break;
        case 204:
            block.bytes.push_back(static_cast<char>(0x89));
            break;
        case 206:
            block.bytes.push_back(static_cast<char>(0x8a));
            break;
        case 304:
            block.bytes.push_back(static_cast<char>(0x8b));
            break;
        case 400:
            block.bytes.push_back(static_cast<char>(0x8c));
            break;
        case 404:
            block.bytes.push_back(static_cast<char>(0x8d));
            break;
        case 500:
            block.bytes.push_back(static_cast<char>(0x8e));
            break;
        default: {
            hpack_name_index_spell(block.bytes, 8);
            char dynamic_body[3];
            dynamic_body[0] = static_cast<char>('0' + status / 100);
            dynamic_body[1] = static_cast<char>('0' + (status / 10) % 10);
            dynamic_body[2] = static_cast<char>('0' + status % 10);
            hpack_length_spell(block.bytes, 3);
            block.bytes.append(dynamic_body, 3);
            break;
        }
    }
    if (ctype != nullptr && !ctype->empty()) {
        hpack_name_index_spell(block.bytes, 31);
        hpack_length_spell(block.bytes, ctype->size());
        block.bytes.append(*ctype);
    }
    if (allow != nullptr && !allow->empty()) {
        block.bytes.push_back(0x00);
        hpack_length_spell(block.bytes, 5);
        block.bytes.append("allow", 5);
        hpack_length_spell(block.bytes, allow->size());
        block.bytes.append(*allow);
    }
}

bool Http1::h2_begin(Conn &conn, std::string &sink)
{
    conn.h2 = new H2State();
    // The encoder allocates; without it there is no answer to send, so the
    // connection ends here rather than at the first field.
    if (!conn.h2->hpack_ready)
        return false;
    unsigned char payload[12];
    payload[0] = 0;
    payload[1] = kH2SettingsMaxConcurrentStreams;
    u32_put(payload + 2, kH2MaxConcurrentStreams);
    // RFC 8441 3: a WebSocket reaches an h2 stream through the extended
    // CONNECT, and a client may only send one when the server said this.
    payload[6] = 0;
    payload[7] = kH2SettingsEnableConnectProtocol;
    u32_put(payload + 8, 1);
    control_frame_emit(sink, {kH2Settings, 0, 0, payload});
    return true;
}

bool Http1::h2_error(Conn &conn, uint32_t code, std::string &sink)
{
    H2State &h2_state = *conn.h2;
    conn.carry.clear();
    if (!h2_state.goaway_sent) {
        unsigned char payload[8];
        u32_put(payload, h2_state.last_stream);
        u32_put(payload + 4, code);
        control_frame_emit(sink, {kH2Goaway, 0, 0, payload});
        h2_state.goaway_sent = true;
    }
    return false;
}

struct ClaimedLength {
    bool have = false;
    size_t value = 0;
};

// RFC 9113 8.2.2: h2 forbids the connection-specific fields. RFC 9113
// 8.1.1: content-length may be named once.
bool h2_wire_header_ok(http::Field field, ClaimedLength &claimed)
{
    const char *const length = field.name.data();
    const size_t name_length = field.name.size();
    const char *const value = field.value.data();
    const size_t value_length = field.value.size();
    // te(2) upgrade(7) connection/keep-alive(10) content-length(14)
    // transfer-encoding(17).
    static constexpr size_t kLengths[] = {2, 7, 10, 14, 17};
    static constexpr uint32_t kMask =
        http::lengths_mask(kLengths, sizeof(kLengths) / sizeof(kLengths[0]));
    if (!http::length_is_one_of(name_length, kMask))
        return true;
    switch (name_length) {
        case 2:
            if (http::tok_eq({length, name_length}, "te") &&
                !(value_length == 8 && http::tok_eq({value, value_length}, "trailers"))) {
                return false;
            }
            break;
        case 14:
            if (http::tok_eq({length, name_length}, "content-length")) {
                if (claimed.have)
                    return false;
                claimed.have = true;
                if (http::parse_content_length({value, value_length}, &claimed.value) !=
                    http::ClStatus::kOk) {
                    return false;
                }
            }
            break;
        case 10:
            if (http::tok_eq({length, name_length}, "connection") ||
                http::tok_eq({length, name_length}, "keep-alive")) {
                return false;
            }
            break;
        case 17:
            if (http::tok_eq({length, name_length}, "transfer-encoding"))
                return false;
            break;
        case 7:
            if (http::tok_eq({length, name_length}, "upgrade"))
                return false;
            break;
        default:
            break;
    }
    return true;
}

// RFC 9113 8.1: a trailer carries no field about framing, the
// connection, or the length of the body it closes.
bool h2_trailer_name_ok(const char *length, size_t name_length)
{
    // te(2) host(4) upgrade(7) connection/keep-alive(10) content-length(14)
    // transfer-encoding(17).
    static constexpr size_t kLengths[] = {2, 4, 7, 10, 14, 17};
    static constexpr uint32_t kMask =
        http::lengths_mask(kLengths, sizeof(kLengths) / sizeof(kLengths[0]));
    if (!http::length_is_one_of(name_length, kMask))
        return true;
    switch (name_length) {
        case 2:
            return !http::tok_eq({length, name_length}, "te");
        case 4:
            return !http::tok_eq({length, name_length}, "host");
        case 7:
            return !http::tok_eq({length, name_length}, "upgrade");
        case 10:
            return !http::tok_eq({length, name_length}, "connection") &&
                   !http::tok_eq({length, name_length}, "keep-alive");
        case 14:
            return !http::tok_eq({length, name_length}, "content-length");
        case 17:
            return !http::tok_eq({length, name_length}, "transfer-encoding");
        default:
            break;
    }
    return true;
}

// RFC 9110 5.6.2 / RFC 9113 8.2.1: a field name is a token without
// 'A' to 'Z'. One table of 256 flags, so the scan is one load and one
// test per octet.
constexpr std::array<bool, 256> h2_name_octets()
{
    std::array<bool, 256> status_text{};
    for (unsigned control = 0; control < 256; control++) {
        status_text[control] =
            (control >= 'a' && control <= 'z') || (control >= '0' && control <= '9') ||
            control == '!' || control == '#' || control == '$' || control == '%' ||
            control == '&' || control == '\'' || control == '*' || control == '+' ||
            control == '-' || control == '.' || control == '^' || control == '_' ||
            control == '`' || control == '|' || control == '~';
    }
    return status_text;
}
constexpr std::array<bool, 256> kH2NameOctet = h2_name_octets();

// RFC 9113 8.2.1: SP and HTAB may not start or end a field value.
constexpr bool h2_character_is_blank(char control)
{
    return control == ' ' || control == '\t';
}

// RFC 9113 8.2.1: a name is a lowercase token. A value carries no NUL,
// CR or LF, and no SP or HTAB at either end. RFC 9113 8.1.1: a broken
// field is a stream error of type PROTOCOL_ERROR.
// RFC 7541 B: every static-table name is a lowercase token, so a known
// name skips the scan.
// RFC 9113 8.3: a pseudo-header carries a colon. h2_dispatch compares it
// whole, so the token rule does not run on it here.
inline bool h2_field_ok(std::string_view name, std::string_view value, bool name_known)
{
    if (name.empty())
        return false;
    if (!name_known && !name.starts_with(':')) {
        for (const char octet : name) {
            if (!kH2NameOctet.at(static_cast<unsigned char>(octet)))
                return false;
        }
    }
    if (!value.empty() && (h2_character_is_blank(value.front()) || h2_character_is_blank(value.back())))
        return false;
    return http::field_value_ok(value.data(), value.size());
}

// RFC 9113 8.3.1: :path is "*" or starts with "/". RFC 3986 3.3: a
// target carries no control octet, no SP and no DEL. picohttpparser
// refuses the same octets on h1, so h1 and h2 agree.
constexpr bool h2_word_is_path(uint64_t word)
{
    return !http::word_has_octet_under(word, 0x21) &&
           !http::word_has_zero_octet(word ^ http::octet_repeated(0x7f));
}

inline bool h2_path_ok(std::string_view path)
{
    if (path.empty())
        return false;
    if (!path.starts_with('/') && path != "*")
        return false;
    std::string_view left = path;
    while (left.size() >= sizeof(uint64_t)) {
        uint64_t word;
        std::memcpy(&word, left.data(), sizeof word);
        if (!h2_word_is_path(word))
            return false;
        left.remove_prefix(sizeof word);
    }
    for (const char octet : left) {
        const unsigned char control = static_cast<unsigned char>(octet);
        if (control <= 0x20 || control == 0x7f)
            return false;
    }
    return true;
}

static bool h2_is_idle(const H2State &h2_state, uint32_t stream_id)
{
    return stream_id > h2_state.highest_opened;
}

void Http1::cache_headers(std::string &out_answer, const CachedHead &head)
{
    const size_t clen = head.fields.size();
    const size_t dlen = head.date.size();
    unsigned char frame_head[kH2FrameHeaderLen];
    h2_put_frame_header(frame_head, {static_cast<uint32_t>(head.block.bytes.size() + clen + dlen),
                                     kH2Headers, kH2FlagEndHeaders, 0});
    out_answer.assign(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
    out_answer.append(head.block.bytes);
    if (clen != 0)
        out_answer.append(reinterpret_cast<const char *>(head.fields.data()), clen);
    out_answer.append(reinterpret_cast<const char *>(head.date.data()), dlen);
}

// RFC 9113 8.1.2.6: a request that sent another length than it said
// is a stream error. A connection that does it kH2LieBudget times ends,
// because each such stream costs a route match, a buffer or a file.
bool Http1::h2_count_lie(Conn &conn, uint32_t stream_id, std::string &sink)
{
    h2_reset_stream(conn, stream_id, kH2ProtocolError, sink);
    conn.h2->lies++;
    if (conn.h2->lies < kH2LieBudget)
        return true;
    return h2_error(conn, kH2EnhanceYourCalm, sink);
}

// Both directions count. Rapid Reset (CVE-2023-44487) sends RST_STREAM
// from the client. MadeYouReset (2025) sends frames that break a rule,
// and the server resets the stream itself. A count of only the peer's
// resets sees nothing.
// sec_ is the coarse second clock_tick keeps, so the window costs no
// syscall.
void Http1::h2_count_reset(Conn &conn)
{
    H2State &h2_state = *conn.h2;
    if (sec_ - h2_state.resets_window_began >= kH2ResetWindow) {
        h2_state.resets_window_began = sec_;
        h2_state.resets = 0;
    }
    if (h2_state.resets != 0xffffffffu)
        h2_state.resets++;
}

void Http1::h2_reset_stream(Conn &conn, uint32_t stream_id, uint32_t code, std::string &sink)
{
    unsigned char payload[4];
    u32_put(payload, code);
    control_frame_emit(sink, {kH2RstStream, 0, stream_id, payload});
    conn.h2->close_stream(stream_id);
    h2_count_reset(conn);
}

// kH2SpillFilesMax bounds the files this connection holds open.
// kBodyFilesMax bounds the process, and BodySpill::open_file refuses
// over it. Both refusals are REFUSED_STREAM, so the client sends the
// request again later. A file the platform could not make is the
// server's own error.
bool Http1::h2_body_file_open(Conn &conn, H2Stream &file_stat,
                                                        uint32_t stream_id, std::string &sink)
{
    size_t open_files = 0;
    for (const H2Stream &other : conn.h2->streams) {
        if (other.spill.fd >= 0)
            open_files++;
    }
    if (mrb_unlikely(open_files >= kH2SpillFilesMax)) {
        h2_reset_stream(conn, stream_id, kH2RefusedStream, sink);
        return false;
    }
    const SpillOpen opened = file_stat.spill.open_file();
    if (mrb_unlikely(opened != SpillOpen::kOpen)) {
        h2_reset_stream(conn, stream_id,
                        opened == SpillOpen::kNoSlot ? kH2RefusedStream : kH2InternalError, sink);
        return false;
    }
    return true;
}

bool Http1::h2_error_page(const H2ErrorAsk &asset_ask, H2ErrorPage &bytes, H2Answer &out_answer)
{
    const http::ReqValues *vals = asset_ask.vals;
    const int method =
        err_pages_.media_pick_for_status(asset_ask.status, vals != nullptr ? vals->accept : nullptr,
                                         vals != nullptr ? vals->accept_len : 0);
    size_t plen = 0;
    const char *pbody = err_pages_.body_of_page({asset_ask.status, method, asset_ask.fields},
                                                bytes.rendered, &plen);
    if (pbody == nullptr)
        return false;
    const std::string ctype(err_pages_.media_type_of_slot(method));
    // RFC 9110 15.5.6: a 405 says which methods it would take, and the page
    // it now carries must not cost it that field.
    const Bundle *block = asset_ask.bundle;
    const std::string *allow =
        (asset_ask.status == 405 && block != nullptr && !block->konst.allow.empty())
            ? &block->konst.allow
            : nullptr;
    h2_build_block(bytes.block, {asset_ask.status, &ctype, allow});
    // A render lands in the caller's H2ErrorPage, which outlives the framing.
    out_answer.body = pbody;
    out_answer.blen = plen;
    out_answer.blk = &bytes.block;
    return true;
}

size_t Http1::h2_fields_of_parked(const H2Stream &stream,
                                  std::array<struct phr_header, kH2MaxFields> &header_vector)
{
    const std::string_view blob(stream.field_blob);
    const size_t name_length = std::min(stream.field_spans.size(), kH2MaxFields);
    for (size_t i = 0; i < name_length; i++) {
        const H2FieldSpan &span = stream.field_spans.at(i);
        const std::string_view name = blob.substr(span.name_at, span.name_len);
        const std::string_view value = blob.substr(span.value_at, span.value_len);
        header_vector.at(i) = {name.data(), name.size(), value.data(), value.size()};
    }
    return name_length;
}

// One write flies per connection, because the ring answers with a
// connection and a generation and has no field for a stream.
BodySpill *Http1::spill_waiting_h2(Conn &conn)
{
    for (H2Stream &s : conn.h2->streams) {
        if (s.spill.owes_write())
            return &s.spill;
    }
    return nullptr;
}

// Marking the round ready is the whole resume: the loop that drives
// parked runs walks it on from the node it stopped at.
bool Http1::h2_body_ready(Conn &conn, uint32_t stream_id)
{
    for (Conn::H2Parked &p : conn.h2_parked) {
        if (p.stream_id != stream_id)
            continue;

        Conn::Round *const round = conn.park_at(p.run.co.promise().park);
        if (round == nullptr || !round->wants_body)
            return false;

        round->answer_ready = true;
        return true;
    }
    return false;
}

bool Http1::h2_serve_parked(Conn &conn, H2Stream &stream, std::string &sink, bool complete)
{
    const uint32_t stream_id = stream.id;
    // RFC 9113 5.1: only the end of the request closes this half. A stream
    // served while its body is still arriving is not half closed yet.
    if (complete)
        stream.half_closed_remote = true;
    const flow::ReqFacts facts = stream.facts;
    const bool head_only = stream.head_method;
    const AssetEntry *asset = stream.parked_asset;
    const uint16_t asset_status = stream.parked_status;
    const size_t asset_off = stream.parked_first;
    const size_t asset_end = stream.parked_end;
    const uint16_t route = stream.route;
    const std::string target = stream.request_target;
    if (asset != nullptr) {
        const H2Asset request_ask = {stream_id, *asset,    asset_status,
                                     head_only, asset_off, asset_end};
        if (!h2_asset_answer(conn, request_ask, sink))
            return false;
        h2_log(conn, {facts, target});
        return true;
    }
    std::string body;
    body.swap(stream.request_content);
    // The file stays this stream's until close_stream drops the entry, so
    // a parked run still finds it.
    const int body_fd = stream.spill.fd;
    const size_t body_fd_len = stream.spill.written;
    const bool body_whole = complete;
    std::array<struct phr_header, kH2MaxFields> header_vector;
    const size_t name_length = h2_fields_of_parked(stream, header_vector);
    http::ReqValues pvals;
    values_of_copied_fields({header_vector.data(), name_length}, pvals);
    ReqView result;
    result.tls = apps_[conn.listener].tls;
    RouteSpans pspans;
    result.method = facts.method;
    result.content_ready = body_whole;
    result.declared_len = stream.content_length_given ? stream.content_length : body.size();
    if (!body_whole) {
        // Nothing is bound while octets are still coming. The resume binds
        // the whole body.
    } else if (body_fd >= 0) {
        result.content_fd = body_fd;
        result.content_len = body_fd_len;
        stream.spill.bound = true;
    } else {
        result.content = body.empty() ? nullptr : body.data();
        result.content_len = body.size();
    }
    result.fields = header_vector.data();
    result.field_count = name_length;
    result.values = &pvals;
    const ReqView *rvp = h2_parked_view(conn, {target, result, pspans});
    H2Request q{stream_id,
                facts,
                &pvals,
                rvp,
                target,
                route,
                head_only,
                stream.field_blob.data(),
                stream.field_blob.size()};
    q.complete = body_whole;
    q.bundle = route == kNoRoute ? nullptr : &bundles_[apps_[conn.listener].base + route];
    const H2Served served = h2_serve(conn, q, sink);
    if (served == H2Served::kClosed)
        return false;
    if (served == H2Served::kAnswered)
        h2_log(conn, {facts, target});
    return true;
}

// RFC 8441 4: an extended CONNECT opens a WebSocket on this stream.
// Anything else that carries :protocol is malformed.
bool Http1::h2_extended_connect(Conn &conn, const H2Connect &request_ask, std::string &sink)
{
    const bool is_connect =
        request_ask.method.size() == 7 && std::memcmp(request_ask.method.data(), "CONNECT", 7) == 0;
    const bool is_ws =
        request_ask.protocol.size() == 9 && http::tok_eq(request_ask.protocol, "websocket");
    if (!is_connect || !is_ws || apps_[conn.listener].ws_table == nullptr) {
        h2_reset_stream(conn, request_ask.stream_id, kH2ProtocolError, sink);
        return true;
    }
    RouteSpans wspans;
    const int writer = apps_[conn.listener].ws_table->match(request_ask.path.data(),
                                                            request_ask.path.size(), wspans);
    if (writer < 0) {
        h2_reset_stream(conn, request_ask.stream_id, kH2RefusedStream, sink);
        return true;
    }
    const H2WsAsk wask = {
        request_ask.stream_id, static_cast<uint16_t>(writer), request_ask.path, &wspans,
        request_ask.fields,    request_ask.nfields,           request_ask.vals};
    return h2_ws_begin(conn, wask, sink);
}

bool Http1::h2_dispatch(Conn &conn, const H2Headers &headers, std::string &sink)
{
    const uint32_t stream_id = headers.stream_id;
    const bool end_stream = headers.end_stream;
    H2State &h2_state = *conn.h2;

    if (h2_state.hdrbuf.size() != kH2HdrBufSize)
        h2_state.hdrbuf.resize(kH2HdrBufSize);
    std::array<H2DecodedField, kH2MaxFields> &fields = h2_state.decoded_fields;
    size_t count = 0;
    size_t used = 0;
    const unsigned char *cursor = headers.block.data();
    const unsigned char *const block_end =
        std::next(cursor, static_cast<std::ptrdiff_t>(headers.block.size()));
    while (cursor != block_end) {
        if (count == kH2MaxFields)
            return h2_error(conn, kH2EnhanceYourCalm, sink);
        // kH2HdrBufSize is kH2FragBudget + kH2FieldWindow, so a window at
        // any used up to the budget lies inside hdrbuf whole.
        if (used > kH2FragBudget)
            return h2_error(conn, kH2EnhanceYourCalm, sink);
        char *const window = std::next(h2_state.hdrbuf.data(), static_cast<std::ptrdiff_t>(used));
        lsxpack_header_t hpack_field;
        lsxpack_header_prepare_decode(&hpack_field, window, 0, kH2FieldWindow);
        if (lshpack_dec_decode(&h2_state.dec, &cursor, block_end, &hpack_field) != 0) {
            return h2_error(conn, kH2CompressionError, sink);
        }
        // lshpack.h: one decode writes name_len + val_len +
        // lshpack_dec_extra_bytes(dec) octets from the start of the window.
        const size_t footprint = static_cast<size_t>(hpack_field.name_len) + hpack_field.val_len +
                                 lshpack_dec_extra_bytes(&h2_state.dec);
        *std::next(fields.begin(), static_cast<std::ptrdiff_t>(count)) = {
            std::string_view(std::next(window, hpack_field.name_offset), hpack_field.name_len),
            std::string_view(std::next(window, hpack_field.val_offset), hpack_field.val_len),
            hpack_field.hpack_index};
        count++;
        used += footprint;
    }
    h2_state.decoded_count = count;
    const std::span<const H2DecodedField> decoded(fields.data(), count);
    h2_state.frag.clear();

    H2Stream *existing = h2_state.find(stream_id);
    if (existing != nullptr && existing->end_headers) {
        // RFC 9113 8.1: a second field block on an open stream is the trailer
        // section, and it carries END_STREAM. A websocket or an event stream
        // carries a tunnel, not a flow, so a trailer on one is an error.
        if (!end_stream || existing->half_closed_remote || existing->ws != nullptr ||
            existing->sse != nullptr || existing->streaming) {
            return h2_error(conn, kH2ProtocolError, sink);
        }
        // RFC 9113 8.1: a trailer section carries no pseudo-header, and 8.2.1
        // holds there too. RFC 9113 8.1.1: a malformed request is a stream
        // error, and the connection stays open.
        for (const H2DecodedField &field : decoded) {
            if (!h2_field_ok(field.name, field.value, field.known != LSHPACK_HDR_UNKNOWN) ||
                field.name.starts_with(':') ||
                !h2_trailer_name_ok(field.name.data(), field.name.size())) {
                h2_reset_stream(conn, stream_id, kH2ProtocolError, sink);
                return true;
            }
        }
        // A trailer section ends the body, so the octets have to match the
        // declared length, and a body in a file is whole only once its last
        // write has landed.
        if (existing->content_length_given &&
            existing->content_received != existing->content_length) {
            return h2_count_lie(conn, stream_id, sink);
        }
        existing->spill.ended = true;
        if (mrb_unlikely(existing->spill.fd >= 0 && !existing->spill.drained()))
            return true;
        return h2_serve_parked(conn, *existing, sink, true);
    }

    flow::ReqFacts facts;
    http::ReqValues vals;
    const char *path_val = nullptr;
    size_t path_vlen = 0;
    const char *authority_val = nullptr;
    size_t authority_vlen = 0;
    bool accepted = true, saw_regular = false;
    bool have_method = false, have_path = false, have_scheme = false, have_authority = false;
    ClaimedLength claimed;
    // RFC 9113 8.3: the fields in the shape h1 hands down, so every
    // by-name accessor answers the same way on both protocols.
    std::array<struct phr_header, kH2MaxFields> header_vector;
    size_t name_length = 0;
    // RFC 8441 4: CONNECT is not a method the flow knows, so parse_method
    // answers kOther and the wire bytes are kept.
    const char *protocol_val = nullptr;
    size_t protocol_vlen = 0;
    const char *method_val = nullptr;
    size_t method_vlen = 0;
    for (const H2DecodedField &field : decoded) {
        if (!accepted)
            break;
        const char *const name = field.name.data();
        const size_t nlen = field.name.size();
        const char *const field_value = field.value.data();
        const size_t vlen = field.value.size();
        const uint8_t known = field.known;
        const bool pseudo = field.name.starts_with(':');
        if (!pseudo && !h2_field_ok(field.name, field.value, known != LSHPACK_HDR_UNKNOWN)) {
            accepted = false;
            break;
        }
        // RFC 9113 8.3: the colon marks a pseudo-header. The static index alone
        // does not: :status is a static entry too, and the arm at the end
        // refuses it.
        if (pseudo) {
            if (saw_regular) {
                accepted = false;
                break;
            }
            enum : uint8_t { kNone, kMethod, kPath, kScheme, kAuthority, kProtocol };
            uint8_t which = kNone;
            switch (known) {
                case LSHPACK_HDR_METHOD_GET:
                case LSHPACK_HDR_METHOD_POST:
                    which = kMethod;
                    break;
                case LSHPACK_HDR_PATH:
                case LSHPACK_HDR_PATH_INDEX_HTML:
                    which = kPath;
                    break;
                case LSHPACK_HDR_SCHEME_HTTP:
                case LSHPACK_HDR_SCHEME_HTTPS:
                    which = kScheme;
                    break;
                case LSHPACK_HDR_AUTHORITY:
                    which = kAuthority;
                    break;
                case LSHPACK_HDR_UNKNOWN:
                    if (field.name == ":method")
                        which = kMethod;
                    else if (field.name == ":path")
                        which = kPath;
                    else if (field.name == ":scheme")
                        which = kScheme;
                    else if (field.name == ":authority")
                        which = kAuthority;
                    else if (field.name == ":protocol")
                        which = kProtocol;
                    break;
                default:
                    break;
            }
            // RFC 9113 8.3.1: :path takes h2_path_ok below, which refuses more.
            if (which != kPath && !h2_field_ok(field.name, field.value, true)) {
                accepted = false;
                break;
            }
            if (which == kMethod) {
                if (have_method) {
                    accepted = false;
                    break;
                }
                have_method = true;
                method_val = field_value;
                method_vlen = vlen;
                facts.method = http::parse_method(field_value, vlen);
            } else if (which == kPath) {
                if (path_val != nullptr) {
                    accepted = false;
                    break;
                }
                have_path = true;
                path_val = field_value;
                path_vlen = vlen;
            } else if (which == kScheme) {
                if (have_scheme) {
                    accepted = false;
                    break;
                }
                have_scheme = true;
            } else if (which == kAuthority) {
                if (have_authority) {
                    accepted = false;
                    break;
                }
                have_authority = true;
                authority_val = field_value;
                authority_vlen = vlen;
            } else if (which == kProtocol) {
                // RFC 8441 4: only an extended CONNECT carries it, and only once.
                if (protocol_val != nullptr) {
                    accepted = false;
                    break;
                }
                protocol_val = field_value;
                protocol_vlen = vlen;
            } else {
                accepted = false;
            }
            continue;
        }
        saw_regular = true;
        size_t index = SIZE_MAX;
        if (name_length < kH2MaxFields) {
            *std::next(header_vector.begin(), static_cast<std::ptrdiff_t>(name_length)) = {
                name, nlen, field_value, vlen};
            index = name_length;
            name_length++;
        }
        if (http::header_switch({{name, nlen}, {field_value, vlen}}, {facts, vals, index}) &&
            !h2_wire_header_ok({{name, nlen}, {field_value, vlen}}, claimed)) {
            accepted = false;
        }
    }
    if (!accepted || !have_method || !have_path || !have_scheme ||
        !h2_path_ok(std::string_view(path_val, path_vlen))) {
        h2_reset_stream(conn, stream_id, kH2ProtocolError, sink);
        return true;
    }

    // RFC 9113 8.3.1: a server treats :authority as the host field of the
    // equivalent HTTP/1.1 request. It is the last entry: the list is in
    // arrival order, and prepending would move every entry. A client that
    // sends a host field keeps it, so the list holds one host field.
    if (authority_val != nullptr && !vals.named.carries(http::NamedField::kHost) &&
        name_length < kH2MaxFields) {
        constexpr std::string_view kHost = "host";
        *std::next(header_vector.begin(), static_cast<std::ptrdiff_t>(name_length)) = {
            kHost.data(), kHost.size(), authority_val, authority_vlen};
        vals.host = authority_val;
        vals.host_len = authority_vlen;
        vals.named.note(http::NamedField::kHost, name_length);
        name_length++;
    }

    if (stream_id > h2_state.last_stream)
        h2_state.last_stream = stream_id;
    if (stream_id > h2_state.highest_opened)
        h2_state.highest_opened = stream_id;
    if (h2_state.streams.size() >= kH2MaxConcurrentStreams) {
        h2_reset_stream(conn, stream_id, kH2RefusedStream, sink);
        return true;
    }
    const bool head_only = facts.method == flow::Method::kHead;

    const AssetEntry *asset = nullptr;
    uint16_t asset_status = 0;
    size_t asset_off = 0;
    size_t asset_end = 0;
    if (assets_ != nullptr) {
        if (AssetEntry *asset_entry = assets_->find(path_val, path_vlen)) {
            asset = asset_entry;
            asset_status = assets_->entry_verdict(*asset_entry, {facts, vals});
            asset_end = Assets::wire_len(*asset_entry);
            if (asset_status == 200 && !head_only && facts.method == flow::Method::kGet &&
                vals.range != nullptr &&
                (vals.if_range == nullptr ||
                 http::if_range_matches({vals.if_range, vals.if_range_len},
                                        {asset_entry->etag, sizeof(asset_entry->etag)}))) {
                http::ByteRange round = {0, 0};
                switch (http::parse_range({{vals.range, vals.range_len}, asset_end}, round)) {
                    case http::RangeParse::kOne:
                        asset_status = 206;
                        asset_off = round.first;
                        asset_end = round.last + 1;
                        break;
                    case http::RangeParse::kUnsat:
                        asset_status = 416;
                        break;
                    case http::RangeParse::kNone:
                        break;
                }
            }
        }
    }

    // RFC 8441 4: an extended CONNECT opens a WebSocket on this stream.
    if (mrb_unlikely(protocol_val != nullptr)) {
        const H2Connect request_ask = {stream_id,
                                       {method_val, method_vlen},
                                       {protocol_val, protocol_vlen},
                                       {path_val, path_vlen},
                                       header_vector.data(),
                                       name_length,
                                       &vals};
        return h2_extended_connect(conn, request_ask, sink);
    }

    RouteSpans spans;
    // WHATWG HTML: an event stream route answers before the ordinary
    // table, as h1 does in feed_parse.
    if (mrb_unlikely(apps_[conn.listener].sse_table != nullptr)) {
        RouteSpans sspans;
        const int sse_route = apps_[conn.listener].sse_table->match(path_val, path_vlen, sspans);
        if (sse_route >= 0) {
            const H2SseAsk request_ask = {stream_id,
                                          static_cast<uint16_t>(sse_route),
                                          {path_val, path_vlen},
                                          &sspans,
                                          header_vector.data(),
                                          name_length,
                                          &vals};
            return h2_sse_begin(conn, request_ask, sink);
        }
    }
    const int round = apps_[conn.listener].table->match(path_val, path_vlen, spans);
    const uint16_t route = round < 0 ? kNoRoute : static_cast<uint16_t>(round);
    const Bundle *block = round < 0 ? nullptr : &bundles_[apps_[conn.listener].base + route];

    if (end_stream) {
        if (claimed.have && claimed.value != 0) {
            h2_reset_stream(conn, stream_id, kH2ProtocolError, sink);
            return true;
        }
        if (asset != nullptr) {
            const H2Asset request_ask = {stream_id, *asset,    asset_status,
                                         head_only, asset_off, asset_end};
            if (!h2_asset_answer(conn, request_ask, sink))
                return false;
            h2_log(conn, {facts, {path_val, path_vlen}});
            return true;
        }
        // A konst route answers from the flow table and the head alone, so
        // nothing is filled for it.
        const bool bound = block != nullptr && block->bound;
        std::optional<ReqView> view;
        if (bound) {
            ReqView &result = view.emplace();
            result.tls = apps_[conn.listener].tls;
            result.request_target = path_val;
            result.request_target_len = path_vlen;
            result.path_len = http::path_only(path_val, path_vlen);
            result.method = facts.method;
            result.table = apps_[conn.listener].table;
            result.route = round;
            result.spans = &spans;
            result.declared_len = claimed.have ? claimed.value : 0;
            // hdrbuf is still the block this dispatch decoded, so the fields can
            // be lent for the length of the answer.
            result.fields = header_vector.data();
            result.field_count = name_length;
            result.values = &vals;
        }
        H2Request q{stream_id,
                    facts,
                    &vals,
                    bound ? &*view : nullptr,
                    {path_val, path_vlen},
                    route,
                    head_only,
                    h2_state.hdrbuf.data(),
                    used};
        q.bundle = block;
        // A run that cannot stop needs no frame, so it skips h2_serve.
        bool answered;
        if (!h2_can_stop(block)) {
            if (!h2_answer(conn, q, sink))
                return false;
            answered = true;
        } else {
            const H2Served served = h2_serve(conn, q, sink);
            if (served == H2Served::kClosed)
                return false;
            answered = served == H2Served::kAnswered;
        }
        if (answered)
            h2_log(conn, {facts, {path_val, path_vlen}});
        return true;
    }
    H2Stream &file_stat = h2_state.open(stream_id);
    // RFC 9110 15.5.14: the nearest limit answers. The resource's own
    // `def self.max_body` wins over the application's number.
    file_stat.max_body = apps_[conn.listener].max_body;
    if (route != kNoRoute) {
        const Bundle &listener_bundle = bundles_[apps_[conn.listener].base + route];
        if (listener_bundle.bound && listener_bundle.res->max_body >= 0)
            file_stat.max_body = static_cast<size_t>(listener_bundle.res->max_body);
    }
    if (asset != nullptr || route == kNoRoute) {
        file_stat.data = H2Stream::Data::kDrop;
    } else {
        const Bundle &db = bundles_[apps_[conn.listener].base + route];
        const bool reads = db.bound && db.res->takes_body;
        // RFC 9110 6.4: a body of kBodySpill or more opens its file now, so no
        // octet is ever moved from memory into it part way through.
        if (!reads || (claimed.have && claimed.value > file_stat.max_body)) {
            // A declared length above the limit opens no file. The first DATA
            // frame crosses the limit, and the stream is refused there.
            file_stat.data = H2Stream::Data::kDrop;
        } else if (!claimed.have && !db.res->saves_body) {
            // RFC 9110 8.6: nothing was declared. The body starts in memory and
            // moves to a file when it grows.
            file_stat.data = H2Stream::Data::kMem;
        } else if (claimed.value >= kBodySpill || db.res->saves_body) {
            if (mrb_unlikely(!h2_body_file_open(conn, file_stat, stream_id, sink)))
                return true;
            file_stat.data = H2Stream::Data::kFile;
        } else {
            // No reserve for a declared number. 256 streams that each name 255 KiB
            // and send nothing took 64 MiB of this process, per connection.
            file_stat.data = H2Stream::Data::kMem;
        }
    }
    file_stat.end_headers = true;
    file_stat.facts = facts;
    file_stat.head_method = head_only;
    file_stat.parked_asset = asset;
    file_stat.parked_status = asset_status;
    file_stat.parked_first = asset_off;
    file_stat.parked_end = asset_end;
    file_stat.route = route;
    file_stat.request_target.assign(path_val, path_vlen);
    file_stat.field_blob.clear();
    file_stat.field_spans.clear();
    file_stat.field_spans.reserve(name_length);
    for (size_t i = 0; i < name_length; i++) {
        const struct phr_header &field = header_vector.at(i);
        H2FieldSpan span{};
        span.name_at = static_cast<uint32_t>(file_stat.field_blob.size());
        span.name_len = static_cast<uint32_t>(field.name_len);
        file_stat.field_blob.append(field.name, field.name_len);
        span.value_at = static_cast<uint32_t>(file_stat.field_blob.size());
        span.value_len = static_cast<uint32_t>(field.value_len);
        file_stat.field_blob.append(field.value, field.value_len);
        file_stat.field_spans.push_back(span);
    }
    file_stat.content_length = claimed.value;
    file_stat.content_length_given = claimed.have;

    // The flow walks on the head, and the body waits behind it. A request
    // this server refuses - 401, 403, 404, 405, 406, 412 - is refused before
    // its octets arrive. Otherwise an upload to a route that answers 404
    // held a kBodyFilesMax slot for as long as the upload lasted.
    // Only a run that can stop may walk here. The straight path would
    // answer from a body that has not arrived.
    if (asset == nullptr && route != kNoRoute && file_stat.data != H2Stream::Data::kDrop) {
        const Bundle &error_bundle = bundles_[apps_[conn.listener].base + route];
        if (error_bundle.bound && error_bundle.res != nullptr &&
            conn.h2_parked.size() < static_cast<size_t>(Conn::kParkSlots)) {
            // The stream table may move under the serve, so nothing of file_stat
            // is read after this call.
            if (!h2_serve_parked(conn, file_stat, sink, false))
                return false;

            bool parked_now = false;
            for (const Conn::H2Parked &p : conn.h2_parked) {
                if (p.stream_id == stream_id) {
                    parked_now = true;
                    break;
                }
            }
            if (!parked_now) {
                // RFC 9113 8.1: the answer is whole and the request is not. NO_ERROR
                // tells the peer to stop sending, because nothing went wrong.
                h2_reset_stream(conn, stream_id, kH2NoError, sink);
            }
        }
    }
    return true;
}

void Http1::h2_build_asset_blocks(AssetEntry &entry)
{
    std::string &block = entry.h2_head_200;
    block.clear();
    block.push_back(static_cast<char>(0x88));
    hpack_name_index_spell(block, 31);
    hpack_length_spell(block, entry.content_type.size());
    block.append(entry.content_type);
    if (entry.deflated) {
        hpack_name_index_spell(block, 26);
        hpack_length_spell(block, 4);
        block.append("gzip", 4);
        hpack_name_index_spell(block, 59);
        hpack_length_spell(block, 15);
        block.append("Accept-Encoding", 15);
    }
    hpack_name_index_spell(block, 34);
    hpack_length_spell(block, sizeof(entry.etag));
    block.append(entry.etag, sizeof(entry.etag));
    if (entry.last_modified_valid) {
        hpack_name_index_spell(block, 44);
        hpack_length_spell(block, sizeof(entry.last_modified));
        block.append(entry.last_modified, sizeof(entry.last_modified));
    }
    hpack_name_index_spell(block, 18);
    hpack_length_spell(block, 5);
    block.append("bytes", 5);

    std::string &control = entry.h2_head_304;
    control.clear();
    control.push_back(static_cast<char>(0x8b));
    hpack_name_index_spell(control, 34);
    hpack_length_spell(control, sizeof(entry.etag));
    control.append(entry.etag, sizeof(entry.etag));
    if (entry.deflated) {
        hpack_name_index_spell(control, 59);
        hpack_length_spell(control, 15);
        control.append("Accept-Encoding", 15);
    }
}

void Http1::h2_build_asset_shared()
{
    static const std::string kAllow = "GET, HEAD";
    h2_build_block(h2_asset405_, {405, nullptr, &kAllow});
    h2_build_block(h2_asset406_, {406});
    hpack_name_index_spell(h2_asset406_.bytes, 59);
    hpack_length_spell(h2_asset406_.bytes, 15);
    h2_asset406_.bytes.append("Accept-Encoding", 15);
}

bool Http1::h2_asset_answer(Conn &conn, const H2Asset &asset_ask, std::string &sink)
{
    const uint32_t stream_id = asset_ask.stream_id;
    const AssetEntry &entry = asset_ask.entry;
    const uint16_t status = asset_ask.status;
    const bool head_only = asset_ask.head_only;
    const size_t win_off = asset_ask.win_off;
    const size_t win_end = asset_ask.win_end;
    H2State &h2_state = *conn.h2;
    std::string rblk;
    const std::string *block;
    switch (status) {
        case 200:
            block = &entry.h2_head_200;
            break;
        case 206: {
            rblk.push_back(static_cast<char>(0x8a));
            hpack_name_index_spell(rblk, 31);
            hpack_length_spell(rblk, entry.content_type.size());
            rblk.append(entry.content_type);
            if (entry.deflated) {
                hpack_name_index_spell(rblk, 26);
                hpack_length_spell(rblk, 4);
                rblk.append("gzip", 4);
                hpack_name_index_spell(rblk, 59);
                hpack_length_spell(rblk, 15);
                rblk.append("Accept-Encoding", 15);
            }
            hpack_name_index_spell(rblk, 34);
            hpack_length_spell(rblk, sizeof(entry.etag));
            rblk.append(entry.etag, sizeof(entry.etag));
            hpack_name_index_spell(rblk, 30);
            const std::string content_range = "bytes " + std::to_string(win_off) + "-" +
                                              std::to_string(win_end - 1) + "/" +
                                              std::to_string(Assets::wire_len(entry));
            hpack_length_spell(rblk, content_range.size());
            rblk.append(content_range);
            block = &rblk;
            break;
        }
        case 416: {
            hpack_name_index_spell(rblk, 8);
            hpack_length_spell(rblk, 3);
            rblk.append("416", 3);
            if (entry.deflated) {
                hpack_name_index_spell(rblk, 59);
                hpack_length_spell(rblk, 15);
                rblk.append("Accept-Encoding", 15);
            }
            hpack_name_index_spell(rblk, 30);
            const std::string content_range = "bytes */" + std::to_string(Assets::wire_len(entry));
            hpack_length_spell(rblk, content_range.size());
            rblk.append(content_range);
            block = &rblk;
            break;
        }
        case 304:
            block = &entry.h2_head_304;
            break;
        case 405:
            block = &h2_asset405_.bytes;
            break;
        case 406:
            block = &h2_asset406_.bytes;
            break;
        default:
            block = &h2_store_[index_[status]].bytes;
            break;
    }

    const bool has_body = status == 200 || status == 206;
    const size_t blen = has_body ? win_end - win_off : 0;
    const bool no_data = head_only || blen == 0;
    alog_status_ = status;
    alog_bytes_ = no_data ? 0 : blen;

    // No insert here: an insert would move every index a cached konst
    // head holds, and nothing counts it there.
    unsigned char dbuf[64];
    unsigned char *data_plan = dbuf;
    if (!h2_enc_field({&h2_state.enc, data_plan, dbuf + sizeof(dbuf)},
                      {"date", {date_, sizeof(date_)}, false})) {
        return h2_error(conn, kH2InternalError, sink);
    }
    const size_t dlen = static_cast<size_t>(data_plan - dbuf);

    unsigned char frame_head[kH2FrameHeaderLen];
    const uint8_t head_flags = kH2FlagEndHeaders | (no_data ? kH2FlagEndStream : 0);
    h2_put_frame_header(frame_head, {static_cast<uint32_t>(block->size() + dlen), kH2Headers,
                                     head_flags, stream_id});
    sink.append(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
    sink.append(*block);
    sink.append(reinterpret_cast<const char *>(dbuf), dlen);

    if (no_data) {
        h2_state.close_stream(stream_id);
        return true;
    }

    H2Stream &keep = h2_state.open(stream_id);
    keep.response_content.take_asset(&entry, win_off, win_end);
    keep.end_headers = true;
    keep.half_closed_remote = true;
    return true;
}

// A run that named a file never lends its body (the O18 body handler
// in resource.cpp), so lent_have is already false here.
uint16_t Http1::h2_refuse_file(Conn &conn, const ReqView *request_view)
{
    static const char kWhy[] =
        "response.file is not wired for HTTP/2 yet - this stream would have been "
        "answered with an empty body, so it is refused instead";
    log_internal_error(elog_,
                       {{static_cast<const char *>(conn.peer), conn.peer_len},
                        request_view != nullptr ? std::string_view{request_view->request_target,
                                                                   request_view->request_target_len}
                                                : std::string_view{},
                        {kWhy, sizeof(kWhy) - 1},
                        500});
    body_.clear();
    rhdrs_.clear();
    return 500;
}

// A run that parked answers long after h2_produce returned, so this
// is its own step.
void Http1::h2_after_run(Conn &conn, const H2Request &request, H2Produced &bytes, uint16_t status)
{
    const Bundle *const block = bytes.b;
    if (block == nullptr || !block->bound)
        return;
    LentBody lent_body;
    bytes.lent_have = resource_body_lent(*block->res, lent_body);
    bytes.lent_v = lent_body.value;
    bytes.lent = lent_body.bytes.data();
    bytes.lent_len = lent_body.bytes.size();
    if (bytes.lent_have)
        bytes.lent_mrb = block->res->mrb;
    // response.file is h1-only: the deferred open lives on the connection,
    // and h2 multiplexes streams that would each need one. The slot is
    // taken either way, because left set it would answer the next request
    // through this Resource.
    {
        WantedFile wanted;
        if (resource_file_wanted(*block->res, wanted)) {
            bytes.have_body = false;
            status = h2_refuse_file(conn, request.req);
        }
    }
    bytes.status = status;
    // RFC 9111: a target that ends in "/" names a page whose bytes change
    // under a name that does not, so a cache may not guess its freshness.
    // The run's own Cache-Control or Expires wins.
    if (status < 400 && request.req != nullptr &&
        http::target_names_a_directory(
            {request.req->request_target, request.req->request_target_len}) &&
        !http::freshness_is_stated(*bytes.rhdrs)) {
        bytes.rhdrs->append(http::kNoCacheLine);
    }
    bytes.dynamic =
        (!block->res->run.content_type.empty() || !bytes.rhdrs->empty()) && status != 500;
}

// `can_park` says whether the caller holds a frame that can keep a
// stopped run. The h2 dispatcher does not, the coroutine does.
void Http1::h2_produce(Conn &conn, const H2Request &request, bool can_park, H2Produced &bytes)
{
    const flow::ReqFacts &facts = request.facts;
    const http::ReqValues *vals = request.vals;
    const ReqView *request_view = request.req;
    const uint16_t route = request.route;
    const bool head_only = request.head_only;

    bytes.idx = &index_;
    const Bundle *block = nullptr;
    uint16_t status;
    bool have_body = false;
    bool dynamic = false;
    // What this run lent is not yet owned by a stream, so every path out
    // of here has to place or free it.
    if (route == kNoRoute) {
        status = 404;
    } else {
        block = request.bundle != nullptr ? request.bundle
                                          : &bundles_[apps_[conn.listener].base + route];
        bytes.idx = &block->index;
        if (block->bound) {
            // The Values die with the frame that carried them, so a parked run
            // gets none. A HEAD sends no bytes to lend.
            const RunAsk asked = {facts, vals, request_view, head_only ? 0 : zc_min_, can_park};
            const RunAnswer answer = {bytes.body, &have_body, bytes.rhdrs};
            status = resource_run(*block->res, asked, answer);
            bytes.b = block;
            bytes.status = status;
            bytes.have_body = have_body;
            // The walk stopped and has not answered, so the caller parks and
            // calls h2_after_run when the answer is back.
            if (mrb_unlikely(run_stopped(*block->res)))
                return;
            h2_after_run(conn, request, bytes, status);
            return;
        } else {
            // RFC 9110 12.5.1: the facts belong to the stream and arrive const, so
            // the negotiated bit is answered on a copy, and only when the client
            // sent an Accept.
            const flow::ReqFacts *use = &facts;
            std::optional<flow::ReqFacts> cf;
            if (facts.has_accept && vals != nullptr && vals->accept != nullptr) {
                cf.emplace(facts);
                if (http::accept_is_exact({vals->accept, vals->accept_len}, block->accept_type)) {
                    cf->has_accept = false;
                } else {
                    cf->plain = false;
                    cf->accept_ok =
                        http::choose_media_type(
                            {{&block->accept_type, 1}, {vals->accept, vals->accept_len}}) >= 0;
                }
                use = &*cf;
            }
            const size_t method_index = static_cast<size_t>(use->method);
            status = flow::answer(
                *use, {block->konst.per_method[method_index], block->konst.shortcut[method_index]});
        }
    }
    bytes.b = block;
    bytes.status = status;
    bytes.have_body = have_body;
    bytes.dynamic = dynamic;
}

// RFC 8441: an extended CONNECT carries :scheme and :path, so the route
// is looked up like any other request's. The answer is 200, not 101:
// the stream itself is the transport, and its DATA frames carry RFC
// 6455 frames. RFC 7692 travels unchanged in the field lines.
bool Http1::h2_ws_begin(Conn &conn, const H2WsAsk &request_ask, std::string &sink)
{
    H2State &h2_state = *conn.h2;
    const AppSlot &slot = apps_[conn.listener];

    ReqView result;
    result.tls = apps_[conn.listener].tls;
    result.request_target = request_ask.target.data();
    result.request_target_len = request_ask.target.size();
    result.path_len = http::path_only(request_ask.target.data(), request_ask.target.size());
    result.method = flow::Method::kGet;
    result.table = slot.ws_table;
    result.route = request_ask.route;
    result.spans = request_ask.spans;
    result.fields = request_ask.fields;
    result.field_count = request_ask.nfields;
    result.values = request_ask.vals;
    request_bind(&result);
    std::string proto;
    uint16_t refused = 0;
    WsConn *const control = ws_admit(ws_res_[slot.ws_base + static_cast<size_t>(request_ask.route)],
                                     elog_.enabled ? &elog_ : nullptr, {proto, refused});
    request_bind(nullptr);
    if (control == nullptr) {
        const uint16_t status = refused == 0 ? 403 : refused;
        alog_status_ = status;
        alog_bytes_ = 0;
        H2Block block;
        h2_build_block(block, {status, nullptr});
        unsigned char frame_head[kH2FrameHeaderLen];
        h2_put_frame_header(frame_head, {static_cast<uint32_t>(block.bytes.size()), kH2Headers,
                                         static_cast<uint8_t>(kH2FlagEndHeaders | kH2FlagEndStream),
                                         request_ask.stream_id});
        sink.append(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
        sink.append(block.bytes);
        return true;
    }

    // RFC 7692 5.1: the first offer this endpoint can accept, or none.
    wsdeflate::Params dparams;
    std::string ext_answer;
    if (ws_wants_deflate(ws_res_[slot.ws_base + static_cast<size_t>(request_ask.route)])) {
        const struct phr_header *const fields =
            static_cast<const struct phr_header *>(request_ask.fields);
        for (size_t i = 0; i < request_ask.nfields && !dparams.on; i++) {
            if (!http::tok_eq({fields[i].name, fields[i].name_len}, "sec-websocket-extensions"))
                continue;
            wsdeflate::negotiate({fields[i].value, fields[i].value_len}, {dparams, ext_answer});
        }
    }

    H2Block block;
    h2_build_block(block, {200, nullptr});
    unsigned char ebuf[256];
    unsigned char *error_page = ebuf;
    unsigned char *const eend = ebuf + sizeof(ebuf);
    bool enc_ok = h2_enc_field({&h2_state.enc, error_page, eend}, {"date", {date_, sizeof(date_)}});
    h2_state.enc_ins++;
    if (enc_ok && !proto.empty()) {
        enc_ok = h2_enc_field({&h2_state.enc, error_page, eend}, {"sec-websocket-protocol", proto});
        h2_state.enc_ins++;
    }
    if (enc_ok && dparams.on) {
        // RFC 9113 8.2: a field name on the wire is lower case, always.
        enc_ok = h2_enc_field({&h2_state.enc, error_page, eend},
                              {"sec-websocket-extensions", ext_answer});
        h2_state.enc_ins++;
    }
    if (!enc_ok) {
        ws_free(control);
        return h2_error(conn, kH2InternalError, sink);
    }
    const size_t elen = static_cast<size_t>(error_page - ebuf);
    unsigned char frame_head[kH2FrameHeaderLen];
    h2_put_frame_header(frame_head, {static_cast<uint32_t>(block.bytes.size() + elen), kH2Headers,
                                     kH2FlagEndHeaders, request_ask.stream_id});
    sink.append(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
    sink.append(block.bytes);
    sink.append(reinterpret_cast<const char *>(ebuf), elen);

    ws_open(control, dparams);
    H2Stream &stream = h2_state.open(request_ask.stream_id);
    stream.ws = control;
    stream.streaming = true;
    stream.end_headers = true;
    // The peer keeps sending: its DATA frames are the WebSocket's own.
    stream.half_closed_remote = false;
    alog_status_ = 200;
    alog_bytes_ = 0;
    return true;
}

// WHATWG HTML over RFC 9113: the head is HEADERS without END_STREAM,
// and every tick is DATA against the stream's window. h2 has no
// Transfer-Encoding; the stream is the framing. One connection can
// hold several event streams, each with its own resource object.
bool Http1::h2_sse_begin(Conn &conn, const H2SseAsk &request_ask, std::string &sink)
{
    H2State &h2_state = *conn.h2;
    const AppSlot &slot = apps_[conn.listener];

    ReqView result;
    result.tls = apps_[conn.listener].tls;
    result.request_target = request_ask.target.data();
    result.request_target_len = request_ask.target.size();
    result.path_len = http::path_only(request_ask.target.data(), request_ask.target.size());
    result.method = flow::Method::kGet;
    result.table = slot.sse_table;
    result.route = request_ask.route;
    result.spans = request_ask.spans;
    result.fields = request_ask.fields;
    result.field_count = request_ask.nfields;
    result.values = request_ask.vals;
    request_bind(&result);
    uint16_t refused = 0;
    SseStream *const text =
        sse_open(sse_res_[slot.sse_base + static_cast<size_t>(request_ask.route)],
                 elog_.enabled ? &elog_ : nullptr, refused);
    request_bind(nullptr);
    if (text == nullptr) {
        // RFC 9110 15.5.4: a stream the app would not open is a 403 unless
        // the app named a status of its own.
        const uint16_t status = refused == 0 ? 403 : refused;
        alog_status_ = status;
        alog_bytes_ = 0;
        H2Block block;
        h2_build_block(block, {status, nullptr});
        unsigned char frame_head[kH2FrameHeaderLen];
        h2_put_frame_header(frame_head, {static_cast<uint32_t>(block.bytes.size()), kH2Headers,
                                         static_cast<uint8_t>(kH2FlagEndHeaders | kH2FlagEndStream),
                                         request_ask.stream_id});
        sink.append(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
        sink.append(block.bytes);
        return true;
    }

    static const std::string kEventStream = "text/event-stream";
    H2Block block;
    h2_build_block(block, {200, &kEventStream});
    unsigned char ebuf[256];
    unsigned char *error_page = ebuf;
    unsigned char *const eend = ebuf + sizeof(ebuf);
    if (!h2_enc_field({&h2_state.enc, error_page, eend}, {"date", {date_, sizeof(date_)}}) ||
        !h2_enc_field({&h2_state.enc, error_page, eend}, {"cache-control", "no-store"})) {
        sse_free(text);
        return h2_error(conn, kH2InternalError, sink);
    }
    h2_state.enc_ins += 2;
    const size_t elen = static_cast<size_t>(error_page - ebuf);
    unsigned char frame_head[kH2FrameHeaderLen];
    h2_put_frame_header(frame_head, {static_cast<uint32_t>(block.bytes.size() + elen), kH2Headers,
                                     kH2FlagEndHeaders, request_ask.stream_id});
    sink.append(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
    sink.append(block.bytes);
    sink.append(reinterpret_cast<const char *>(ebuf), elen);

    H2Stream &stream = h2_state.open(request_ask.stream_id);
    stream.sse = text;
    stream.streaming = true;
    stream.end_headers = true;
    stream.half_closed_remote = true;
    alog_status_ = 200;
    alog_bytes_ = 0;
    return true;
}

void Http1::h2_sse_second(Conn &conn, std::string &sink)
{
    H2State &h2_state = *conn.h2;
    for (size_t i = 0; i < h2_state.streams.size(); i++) {
        H2Stream &stream = h2_state.streams[i];
        if (stream.sse == nullptr)
            continue;
        std::string body;
        const bool go_on = sse_tick(stream.sse, sec_, body);
        if (!body.empty())
            stream.response_content.append_owned(body.data(), body.size());
        // A client that reads its socket but never credits the stream. The
        // tick speaks every second whatever the window says, so nothing else
        // bounds what piles up.
        if (mrb_unlikely(stream.response_content.owed_bytes() > kTunnelOutCap)) {
            const uint32_t stream_id = stream.id;
            stream.streaming = false;
            stream.response_content.clear();
            h2_reset_stream(conn, stream_id, kH2EnhanceYourCalm, sink);
            h2_state.close_stream(stream_id);
            i--;
            continue;
        }
        if (go_on)
            continue;
        // END_STREAM rides the last DATA frame. A stream that owes nothing
        // gets an empty one, or the peer waits for an end that never comes.
        sse_free(stream.sse);
        stream.sse = nullptr;
        stream.streaming = false;
        if (!stream.response_content.owes()) {
            unsigned char end_head[kH2FrameHeaderLen];
            h2_put_frame_header(end_head, {0, kH2Data, kH2FlagEndStream, stream.id});
            sink.append(reinterpret_cast<const char *>(end_head), sizeof(end_head));
            h2_state.close_stream(stream.id);
            i--;
        }
    }
}

Http1::H2Served Http1::h2_serve(Conn &conn, const H2Request &request, std::string &sink)
{
    const Bundle *block = request.bundle;
    // A body is a reason to stop that belongs to no resource, so a request
    // whose body has not arrived takes the parkable path whatever the
    // resource declares. The straight path runs with can_park false and
    // would answer from a body that is not there.
    if (request.complete && !h2_can_stop(block)) {
        return h2_answer(conn, request, sink) ? H2Served::kAnswered : H2Served::kClosed;
    }
    // A connection holds as many stopped runs as a tag can name. Past
    // that the request takes the straight way: a compute task runs here
    // and a watcher is refused by name.
    if (conn.h2_parked.size() >= static_cast<size_t>(Conn::kParkSlots)) {
        return h2_answer(conn, request, sink) ? H2Served::kAnswered : H2Served::kClosed;
    }
    // A run that stops copies what it is given, so it is given this
    // request's own span. A HEADERS block decodes in one run, so the span
    // is contiguous.
    const char *head_at = request.head_at;
    size_t head_len = request.head_len;
    if (request.req != nullptr && request.req->field_count != 0 && request.head_at != nullptr) {
        const auto *headers = static_cast<const struct phr_header *>(request.req->fields);
        const char *low = nullptr;
        const char *high = nullptr;
        for (size_t i = 0; i < request.req->field_count; i++) {
            if (headers[i].name != nullptr && (low == nullptr || headers[i].name < low))
                low = headers[i].name;
            if (headers[i].value != nullptr &&
                (high == nullptr || headers[i].value + headers[i].value_len > high)) {
                high = headers[i].value + headers[i].value_len;
            }
        }
        // The target is read beside the fields and lands in the same
        // buffer, so the span has to hold it as well.
        if (!request.target.empty()) {
            if (low == nullptr || request.target.data() < low)
                low = request.target.data();
            if (high == nullptr || request.target.data() + request.target.size() > high) {
                high = request.target.data() + request.target.size();
            }
        }
        if (low != nullptr && high != nullptr && low >= request.head_at &&
            high <= request.head_at + request.head_len) {
            head_at = low;
            head_len = static_cast<size_t>(high - low);
        }
    }
    RunStart start;
    start.proto = RunStart::Proto::kH2;
    start.h2.stream_id = request.stream_id;
    start.h2.route = request.route;
    start.h2.head_only = request.head_only;
    start.h2.facts = request.facts;
    start.h2.target.assign(request.target);
    start.h2.view = request.req;
    start.h2.head_at = head_at;
    start.h2.head_len = head_len;
    Run round = run_parkable(conn, std::move(start), &sink, nullptr);
    if (round.done()) {
        return round.status() != 0 ? H2Served::kAnswered : H2Served::kClosed;
    }
    // The stream keeps an entry while the run is parked, so a RST_STREAM
    // closes it and a WINDOW_UPDATE credits it. The sweep leaves a parked
    // entry alone.
    H2Stream &keep = conn.h2->open(request.stream_id);
    keep.parked = true;
    keep.end_headers = true;
    // RFC 9113 5.1: a run that stopped for its body waits on DATA, so the
    // stream is still open to the peer.
    if (request.complete)
        keep.half_closed_remote = true;
    conn.h2_parked.push_back({request.stream_id, std::move(round)});
    return H2Served::kParked;
}

bool Http1::h2_answer(Conn &conn, const H2Request &request, std::string &sink)
{
    H2Produced bytes;
    bytes.body = &body_;
    bytes.rhdrs = &rhdrs_;
    h2_produce(conn, request, false, bytes);
    return h2_frame(conn, request, sink, bytes);
}

bool Http1::h2_frame(Conn &conn, const H2Request &request, std::string &sink, H2Produced &bytes)
{
    const uint32_t stream_id = request.stream_id;
    const http::ReqValues *vals = request.vals;
    const ReqView *request_view = request.req;
    const uint16_t route = request.route;
    const bool head_only = request.head_only;
    const flow::ReqFacts &facts = request.facts;
    (void)facts;
    H2State &h2_state = *conn.h2;
    H2Answer wire;
    // Built only by the arm that needs it: a std::string the straight
    // line never reads costs a construction and a destruction.
    std::optional<H2Block> dynblk;
    // The error page outlives the framing below, because a body the
    // window cannot finish is copied onto the stream from this buffer.
    std::optional<H2ErrorPage> err_page;
    // response.error_asset: the stream carries the entry the way the
    // asset tier's streams do. Nothing is rooted: the entry lives in a
    // mapping that outlives every stream.
    const AssetEntry *run_asset =
        (bytes.b != nullptr && bytes.b->res != nullptr) ? bytes.b->res->run.asset : nullptr;
    const size_t asset_len = run_asset != nullptr ? Assets::wire_len(*run_asset) : 0;
    if (bytes.dynamic) {
        const bool bodyless = bytes.status == 204 || bytes.status == 304;
        if (bodyless || !bytes.have_body)
            (*bytes.body).clear();
        // A `def self.to_html` renders at setup, and the block built here is
        // not the prebuilt one that carries it.
        const bool baked = !bodyless && !bytes.have_body && !bytes.lent_have &&
                           bytes.status == 200 && !bytes.b->dynamic_body &&
                           !bytes.b->konst.body.empty();
        std::string ctype;
        std::string epage;
        // A 4xx or 5xx whose run wrote a field of its own never reaches
        // h2_error_page, so the page is spelled here.
        if (bytes.status >= 400 && !bodyless && !bytes.have_body && !bytes.lent_have &&
            run_asset == nullptr) {
            const int error_message = err_pages_.media_pick_for_status(
                bytes.status, vals != nullptr ? vals->accept : nullptr,
                vals != nullptr ? vals->accept_len : 0);
            size_t elen = 0;
            const ErrorPages::Fields none;
            const char *error_page =
                err_pages_.body_of_page({bytes.status, error_message, none}, epage, &elen);
            if (error_page != nullptr) {
                (*bytes.body).assign(error_page, elen);
                bytes.have_body = true;
                ctype = err_pages_.media_type_of_slot(error_message);
            }
        }
        if (!bodyless && ctype.empty()) {
            if (!bytes.b->res->run.content_type.empty())
                ctype = http::with_charset(bytes.b->res->run.content_type);
            else if (bytes.have_body || baked)
                ctype = bytes.b->konst.content_type;
        }
        h2_build_block(dynblk.emplace(), {bytes.status, ctype.empty() ? nullptr : &ctype});
        const bool use_lent = bytes.lent_have && !bodyless && bytes.have_body;
        const bool use_asset = run_asset != nullptr && !bodyless && bytes.have_body;
        // h2_flush_pending frames an asset out of the mapping, never from
        // `body`, so only its length is set here.
        wire.body = use_asset
                        ? nullptr
                        : (use_lent ? bytes.lent
                                    : (baked ? bytes.b->konst.body.data() : (*bytes.body).data()));
        wire.blen = use_asset
                        ? asset_len
                        : (use_lent ? bytes.lent_len
                                    : (baked ? bytes.b->konst.body.size() : (*bytes.body).size()));
        wire.blk = &*dynblk;
    } else if (bytes.have_body && bytes.status == 200) {
        wire.body =
            run_asset != nullptr ? nullptr : (bytes.lent_have ? bytes.lent : (*bytes.body).data());
        wire.blen = run_asset != nullptr
                        ? asset_len
                        : (bytes.lent_have ? bytes.lent_len : (*bytes.body).size());
        wire.blk = &h2_store_[(*bytes.idx)[200]];
    } else if (bytes.status == 500 && bytes.b != nullptr && bytes.b->bound) {
        // The record and the page carry the same hash because they are taken
        // over the same facts.
        ErrFacts error_facts;
        std::string ef_backtrace;
        std::string ef_steering;
        char ef_hash[kFingerprintLen] = {};
        error_facts.peer = conn.peer;
        error_facts.peer_len = conn.peer_len;
        error_facts.request_target =
            request_view != nullptr ? request_view->request_target : nullptr;
        error_facts.request_target_len =
            request_view != nullptr ? request_view->request_target_len : 0;
        error_facts.method = request_view != nullptr ? request_view->method_token : nullptr;
        error_facts.method_len = request_view != nullptr ? request_view->method_token_len : 0;
        spell_steering(vals, ef_steering);
        error_facts.steering = ef_steering.data();
        error_facts.steering_len = ef_steering.size();
        error_facts.body = request_view != nullptr ? request_view->content : nullptr;
        error_facts.body_len = request_view != nullptr ? request_view->content_len : 0;
        error_facts.body_full = error_facts.body_len;
        error_facts.status_code = 500;
        exception_facts(bytes.b->res->mrb, {error_facts, ef_backtrace});
        spell_fingerprint(ef_hash, fingerprint_of(error_facts));
        if (elog_.enabled)
            log_error(elog_, error_facts);
        // handle_exception lives on the error resource, so the exception
        // object itself is what crosses over.
        std::string message;
        mrb_value exc = mrb_nil_value();
        if (resource_exception_take(*bytes.b->res, &exc))
            err_pages_.exception_text(exc, message);
        ErrorPages::Fields field;
        field.message = message.data();
        field.message_len = message.size();
        field.fingerprint = ef_hash;
        // A ship build says what was thrown and where the log has the rest. A
        // debug build puts the trace on the page too.
        if (kDebugBuild) {
            field.backtrace = error_facts.backtrace;
            field.backtrace_len = error_facts.backtrace_len;
        }
        const H2ErrorAsk request_ask = {500, field, vals, bytes.b};
        if (!h2_error_page(request_ask, err_page.emplace(), wire)) {
            wire.blk = &h2_store_[(*bytes.idx)[500]];
        }
    } else if (bytes.status == 200) {
        wire.body = bytes.b->konst.body.data();
        wire.blen = bytes.b->konst.body.size();
        wire.blk = &h2_store_[(*bytes.idx)[200]];
    } else {
        // RFC 9110 15: only a 4xx or 5xx has something to explain.
        bool spelled = false;
        if (bytes.status >= 400) {
            ErrorPages::Fields field;
            const H2ErrorAsk request_ask = {bytes.status, field, vals, bytes.b};
            spelled = h2_error_page(request_ask, err_page.emplace(), wire);
        }
        if (!spelled)
            wire.blk = &h2_store_[(*bytes.idx)[bytes.status]];
    }

    const bool no_data = head_only || wire.blen == 0;

    // A lend the chain above did not adopt never reached a plan, so this
    // is its release.
    if (bytes.lent_have && (no_data || wire.body != bytes.lent)) {
        resource_body_unlend(bytes.lent_mrb, bytes.lent_v);
        bytes.lent_have = false;
    }
    // An adopted lend becomes the stream's before anything below can
    // fail: from here on close_stream and ~H2State own it.
    if (bytes.lent_have) {
        H2Stream &keep = h2_state.open(stream_id);
        keep.response_content.take_lent(bytes.lent_mrb, bytes.lent_v, bytes.lent, bytes.lent_len);
        keep.end_headers = true;
        keep.half_closed_remote = true;
    }
    // An asset parks the way the asset tier parks one. h2_flush_pending
    // frames it out of the mapping, and the sweep closes the stream once
    // the window let all of it through.
    const bool asset_data = run_asset != nullptr && !no_data;
    if (asset_data) {
        H2Stream &keep = h2_state.open(stream_id);
        keep.response_content.take_asset(run_asset, 0, wire.blen);
        keep.end_headers = true;
        keep.half_closed_remote = true;
    }

    alog_status_ = bytes.status;
    alog_bytes_ = no_data ? 0 : wire.blen;

    H2Stream *stream = no_data ? nullptr : h2_state.find(stream_id);
    int64_t budget = 0;
    if (!no_data) {
        const int64_t swin = stream != nullptr ? stream->flow_window : h2_state.peer_initial_window;
        budget = std::min(h2_state.flow_window, swin);
    }

    bool merged = false;
    if (bytes.dynamic) {
        unsigned char ebuf[2048];
        unsigned char *error_page = ebuf;
        unsigned char *const eend = ebuf + sizeof(ebuf);
        // Indexed, unlike the cached path: this head is spelled once and
        // thrown away, so an insert costs nothing to replay. It does move every
        // index a cached head holds, which is what enc_ins counts.
        if (!h2_enc_field({&h2_state.enc, error_page, eend}, {"date", {date_, sizeof(date_)}})) {
            return h2_error(conn, kH2InternalError, sink);
        }
        h2_state.enc_ins++;
        std::string name;
        size_t index = 0;
        while (index < (*bytes.rhdrs).size()) {
            const size_t eol = (*bytes.rhdrs).find("\r\n", index);
            if (eol == std::string::npos)
                break;
            const size_t colon = (*bytes.rhdrs).find(':', index);
            if (colon != std::string::npos && colon < eol) {
                size_t value_start = colon + 1;
                while (value_start < eol &&
                       ((*bytes.rhdrs)[value_start] == ' ' || (*bytes.rhdrs)[value_start] == '\t'))
                    value_start++;
                name.assign((*bytes.rhdrs), index, colon - index);
                for (char &c : name) {
                    if (c >= 'A' && c <= 'Z')
                        c = static_cast<char>(c + 32);
                }
                if (!h2_enc_field(
                        {&h2_state.enc, error_page, eend},
                        {name, {(*bytes.rhdrs).data() + value_start, eol - value_start}})) {
                    return h2_error(conn, kH2InternalError, sink);
                }
                h2_state.enc_ins++;
            }
            index = eol + 2;
        }
        const size_t elen = static_cast<size_t>(error_page - ebuf);
        unsigned char frame_head[kH2FrameHeaderLen];
        const uint8_t head_flags = kH2FlagEndHeaders | (no_data ? kH2FlagEndStream : 0);
        h2_put_frame_header(frame_head, {static_cast<uint32_t>(wire.blk->bytes.size() + elen),
                                         kH2Headers, head_flags, stream_id});
        sink.append(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
        sink.append(wire.blk->bytes);
        sink.append(reinterpret_cast<const char *>(ebuf), elen);
    } else {
        if (h2_state.head_cache.status != bytes.status || h2_state.head_cache.route != route ||
            h2_state.head_cache.sec != sec_ || h2_state.head_cache.enc_ins != h2_state.enc_ins) {
            // RFC 7541 6.2.1 / 6.1: content-type goes into the peer's dynamic
            // table once and is a one-byte reference after that. Encoded twice:
            // ls-hpack answers the first call with the insert and the second with
            // the index, which are the two forms this cache needs.
            const std::string *ct =
                (bytes.status == 200 && bytes.b != nullptr && !bytes.b->konst.content_type.empty())
                    ? &bytes.b->konst.content_type
                    : nullptr;
            unsigned char pbuf[256];
            unsigned char rbuf[256];
            size_t plen = 0;
            size_t rlen = 0;
            if (ct != nullptr) {
                unsigned char *pseudo_cursor = pbuf;
                unsigned char *regular_cursor = rbuf;
                if (!h2_enc_field({&h2_state.enc, pseudo_cursor, pbuf + sizeof(pbuf)},
                                  {"content-type", *ct}) ||
                    !h2_enc_field({&h2_state.enc, regular_cursor, rbuf + sizeof(rbuf)},
                                  {"content-type", *ct})) {
                    return h2_error(conn, kH2InternalError, sink);
                }
                plen = static_cast<size_t>(pseudo_cursor - pbuf);
                rlen = static_cast<size_t>(regular_cursor - rbuf);
                h2_state.enc_ins++;
                // The shared 200 block spells :status and nothing else, so it
                // replaces the block that carried the literal.
                wire.blk = &h2_store_[index_[200]];
            }
            unsigned char dbuf[64];
            unsigned char *data_plan = dbuf;
            // Not indexed: these bytes are replayed for every answer of this
            // second, and a replayed insert is an insert the peer performs again.
            if (!h2_enc_field({&h2_state.enc, data_plan, dbuf + sizeof(dbuf)},
                              {"date", {date_, sizeof(date_)}, false})) {
                return h2_error(conn, kH2InternalError, sink);
            }
            const size_t dlen = static_cast<size_t>(data_plan - dbuf);
            cache_headers(h2_state.head_cache.bytes, {*wire.blk, {rbuf, rlen}, {dbuf, dlen}});
            h2_state.head_cache.head_len = h2_state.head_cache.bytes.size();
            h2_state.head_cache.primed = ct == nullptr;
            if (ct != nullptr) {
                cache_headers(h2_state.head_cache.prime, {*wire.blk, {pbuf, plen}, {dbuf, dlen}});
            }
            h2_state.head_cache.has_data = bytes.b != nullptr && !bytes.b->bound &&
                                           bytes.status == 200 && !bytes.b->konst.body.empty() &&
                                           bytes.b->konst.body.size() <= kH2MergeBody;
            if (h2_state.head_cache.has_data)
                h2_state.head_cache.bytes.append(bytes.b->h2_data200);
            h2_state.head_cache.status = bytes.status;
            h2_state.head_cache.route = route;
            h2_state.head_cache.sec = sec_;
            // Taken after the encodes above, so the reference this head holds
            // and the table it points into are recorded together.
            h2_state.head_cache.enc_ins = h2_state.enc_ins;
        }
        // The answer that carries the insert is never merged with a DATA
        // frame: it is one response in a second, and the merge exists for the
        // other thousands.
        const bool prime = !h2_state.head_cache.primed;
        merged = !prime && !no_data && h2_state.head_cache.has_data &&
                 budget >= static_cast<int64_t>(wire.blen) && wire.blen <= h2_state.peer_max_frame;
        const size_t hoff = sink.size();
        if (prime) {
            sink.append(h2_state.head_cache.prime);
            h2_state.head_cache.primed = true;
        } else if (merged) {
            sink.append(h2_state.head_cache.bytes);
        } else {
            sink.append(h2_state.head_cache.bytes, 0, h2_state.head_cache.head_len);
        }
        unsigned char *hpack = reinterpret_cast<unsigned char *>(&sink[hoff]);
        hpack[4] = kH2FlagEndHeaders | (no_data ? kH2FlagEndStream : 0);
        h2_patch_stream_id(hpack, stream_id);
        if (merged)
            h2_patch_stream_id(hpack + h2_state.head_cache.head_len, stream_id);
    }

    // RFC 9113 6.9.1: a lent body is not framed here. It is parked on the
    // stream, and h2_flush_pending, the only place holding a plan, gives it
    // the window and the external segment.
    size_t give = 0;
    if (!bytes.lent_have && !asset_data && !no_data) {
        if (merged) {
            give = wire.blen;
        } else {
            give = wire.blen;
            if (budget <= 0) {
                give = 0;
            } else if (static_cast<int64_t>(give) > budget) {
                give = static_cast<size_t>(budget);
            }
            unsigned char frame_head[kH2FrameHeaderLen];
            size_t offset = 0;
            while (offset < give) {
                size_t length = give - offset;
                if (length > h2_state.peer_max_frame)
                    length = h2_state.peer_max_frame;
                const bool last = offset + length == wire.blen;
                const uint8_t end_flag = last ? kH2FlagEndStream : 0;
                h2_put_frame_header(frame_head,
                                    {static_cast<uint32_t>(length), kH2Data, end_flag, stream_id});
                sink.append(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
                sink.append(wire.body + offset, length);
                offset += length;
            }
        }
        const bool had_stream = stream != nullptr;
        h2_state.flow_window -= static_cast<int64_t>(give);
        if (had_stream)
            stream->flow_window -= static_cast<int64_t>(give);
        if (give < wire.blen) {
            H2Stream &keep = h2_state.open(stream_id);
            keep.response_content.take_owned(wire.body + give, wire.blen - give);
            keep.end_headers = true;
            keep.half_closed_remote = true;
            if (!had_stream)
                keep.flow_window -= static_cast<int64_t>(give);
        }
    }
    // A lent stream is never closed here: its bytes are not framed yet,
    // and the sweep at the end of h2_flush_pending closes it once they are.
    if (!bytes.lent_have && !asset_data && (no_data || give == wire.blen))
        h2_state.close_stream(stream_id);
    return true;
}

namespace
{
struct RoundOut {
    std::string &sink;
    Http1::Plan *plan;
    size_t emitted = 0;

    // A plan naming any sink range describes the sink completely, so the
    // bytes this round started with are claimed first.
    void prime()
    {
        if (plan == nullptr || plan->iovlen != 0 || sink.empty())
            return;
        plan->iov[plan->iovlen++] = Http1::Plan::Seg{nullptr, 0, sink.size()};
        plan->byte_total += sink.size();
    }

    // Room for one more DATA frame: its header plus up to three payload
    // spans. Every gate sits before the frame, never inside one.
    bool room_for_frame() const
    {
        if (plan == nullptr)
            return emitted < kDeliverChunk;
        if (plan->iovlen + 4 > Http1::Plan::kSegs)
            return false;
        return plan->byte_cap == 0 || plan->byte_total < plan->byte_cap;
    }

    void bytes(const char *bytes, size_t length)
    {
        if (plan == nullptr) {
            sink.append(bytes, length);
            emitted += length;
            return;
        }
        prime();
        const size_t index = sink.size();
        sink.append(bytes, length);
        if (plan->iovlen > 0) {
            Http1::Plan::Seg &open = plan->iov[plan->iovlen - 1];
            if (open.iov_base == nullptr && open.off + open.iov_len == index) {
                open.iov_len += length;
                plan->byte_total += length;
                return;
            }
        }
        plan->iov[plan->iovlen++] = Http1::Plan::Seg{nullptr, index, length};
        plan->byte_total += length;
    }

    static constexpr size_t kCopyFloor = 4096;

    // Pieces under one page are copied; one page is the measured line.
    void span(const AssetEntry &entry, size_t offset, size_t length)
    {
        if (plan == nullptr) {
            Assets::entry_copy_wire(entry, {offset, length}, sink);
            emitted += length;
            return;
        }
        prime();
        struct iovec iov[3];
        const unsigned k = Assets::entry_wire_iov(entry, {offset, length}, iov);
        for (unsigned i = 0; i < k; i++) {
            if (iov[i].iov_len < kCopyFloor) {
                bytes(static_cast<const char *>(iov[i].iov_base), iov[i].iov_len);
                continue;
            }
            plan->iov[plan->iovlen++] =
                Http1::Plan::Seg{static_cast<const char *>(iov[i].iov_base), 0, iov[i].iov_len};
            plan->byte_total += iov[i].iov_len;
        }
    }

    // Without a plan there is no segment to hang the lend on, so the
    // round copies. The lend outlives this round either way.
    void lent(const char *bytes, size_t length)
    {
        if (plan == nullptr) {
            sink.append(bytes, length);
            emitted += length;
            return;
        }
        prime();
        plan->iov[plan->iovlen++] = Http1::Plan::Seg{bytes, 0, length};
        plan->byte_total += length;
    }
};
} // namespace

#define WM_H2_LOG_DEFINED
static const char *access_log_method_name(flow::Method method, size_t *length)
{
    switch (method) {
        case flow::Method::kGet:
            *length = 3;
            return "GET";
        case flow::Method::kHead:
            *length = 4;
            return "HEAD";
        case flow::Method::kPost:
            *length = 4;
            return "POST";
        case flow::Method::kPut:
            *length = 3;
            return "PUT";
        case flow::Method::kDelete:
            *length = 6;
            return "DELETE";
        case flow::Method::kOptions:
            *length = 7;
            return "OPTIONS";
        default:
            *length = 1;
            return "-";
    }
}

void Http1::h2_log(Conn &conn, const H2Logged &logged)
{
    if (!alog_.enabled)
        return;
    const flow::ReqFacts &facts = logged.facts;
    const char *const target = logged.target.data();
    const size_t tlen = logged.target.size();
    size_t mn = 0;
    const char *method = access_log_method_name(facts.method, &mn);
    log_access(alog_, {{static_cast<const char *>(conn.peer), conn.peer_len},
                       {method, mn},
                       {target, tlen},
                       {},
                       {},
                       alog_bytes_,
                       alog_status_,
                       static_cast<uint8_t>(kLogH2 | (facts.no_track ? kLogNoTrack : 0))});
}

struct H2Sending {
    const H2Stream &stream;
    const Http1::H2SendStep &step;
    size_t max_frame;
};
// END_STREAM rides the frame that lands on the last byte, so the step
// carries the body's total and not only what this round gives. The
// round can run out of plan room mid-body, and then nothing ends.

static size_t h2_emit(RoundOut &out_answer, const H2Sending &sending)
{
    const H2Stream &text = sending.stream;
    const Http1::H2SendStep &step = sending.step;
    const size_t max_frame = sending.max_frame;
    size_t offset = 0;
    while (offset < step.give) {
        if (!out_answer.room_for_frame())
            break;
        size_t length = step.give - offset;
        if (length > max_frame)
            length = max_frame;
        // WHATWG HTML: an event stream drains between ticks and is not over.
        const bool last = !text.streaming && step.start + offset + length == step.total;
        unsigned char frame_head[kH2FrameHeaderLen];
        const uint8_t end_flag = last ? kH2FlagEndStream : 0;
        h2_put_frame_header(frame_head,
                            {static_cast<uint32_t>(length), kH2Data, end_flag, text.id});
        out_answer.bytes(reinterpret_cast<const char *>(frame_head), sizeof(frame_head));
        switch (text.response_content.src) {
            case H2Stream::Content::Src::kAsset:
                out_answer.span(*text.response_content.asset, step.start + offset, length);
                break;
            case H2Stream::Content::Src::kLent:
                out_answer.lent(text.response_content.lent + step.start + offset, length);
                break;
            case H2Stream::Content::Src::kOwned:
                out_answer.bytes(text.response_content.owned.data() + step.start + offset, length);
                break;
            case H2Stream::Content::Src::kNone:
                break;
        }
        offset += length;
    }
    return offset;
}

// An offset says this for free; erasing from the front of a buffer
// would cost a memmove per round.
static void h2_advance(H2State &h2_state, H2Stream &text, size_t sent)
{
    if (sent == 0)
        return;
    h2_state.flow_window -= static_cast<int64_t>(sent);
    text.flow_window -= static_cast<int64_t>(sent);
    text.response_content.sent += sent;
}

void Http1::h2_flush_pending(Conn &conn, std::string &sink, Plan *plan)
{
    H2State &h2_state = *conn.h2;
    RoundOut out{sink, plan};
    const size_t n_streams = h2_state.streams.size();
    if (n_streams == 0)
        return;
    size_t walked = 0;
    for (; walked < n_streams; walked++) {
        if (!out.room_for_frame())
            break;
        H2Stream &stream = h2_state.streams[(h2_state.flush_cursor + walked) % n_streams];
        const H2SendStep step = h2_send_step(stream, {h2_state.flow_window, kDeliverChunk});
        if (step.give == 0)
            continue;
        const size_t sent = h2_emit(out, {stream, step, h2_state.peer_max_frame});
        h2_advance(h2_state, stream, sent);
    }
    h2_state.flush_cursor = n_streams != 0 ? (h2_state.flush_cursor + walked) % n_streams : 0;
    for (size_t i = 0; i < h2_state.streams.size();) {
        H2Stream &stream = h2_state.streams[i];
        if (stream.end_headers && stream.half_closed_remote && !stream.response_content.owes() &&
            !stream.streaming && !stream.parked) {
            // close_stream retires the lend rather than freeing it: its last
            // frames are in the round being built, not yet on the wire.
            h2_state.close_stream(stream.id);
        } else {
            i++;
        }
    }
}

// Asked before a send, for MSG_MORE.
bool Http1::pending(const Conn &conn) const
{
    if (conn.h2 != nullptr) {
        for (const H2Stream &s : conn.h2->streams) {
            if (s.response_content.owes())
                return true;
        }
        return false;
    }
    // A file the reactor is still opening owes bytes too. That keeps
    // spell_next_round from re-feeding the carry ahead of that answer.
    // kDone owes nothing: counting it cost 60 us per request, because
    // MSG_MORE corked the final send and on_send took the arm_meminfo
    // detour (an io-wq round trip) before a round that sends nothing.
    return conn.asset != nullptr || (conn.file != nullptr && conn.file->stage != FileStage::kNone &&
                                     conn.file->stage != FileStage::kDone);
}

bool Http1::spell_next_round(Conn &conn, std::string &sink, Plan &plan)
{
    // The Ring reaches here only once a whole round has drained, so a body
    // lent to that round is off the wire. The release comes before the next
    // round is built, so a connection never holds two.
    conn.zc_release();
    // A stopped run may go on here and nowhere else: the sink and the plan
    // exist here, and did not exist at the completion that said its answer
    // had arrived.
    if (mrb_unlikely(conn.run_parked())) {
        // Nothing else may speak for this connection while a run is stopped.
        // RFC 9112 9.3.2: responses go out in the order the requests came.
        Conn::Round *const parked_round = conn.park_at(conn.parked.co.promise().park);
        if (parked_round == nullptr || !parked_round->answer_ready)
            return true;
        parked_round->answer_ready = false;
        // What the round holds is not cleared here. The run reads it after
        // this resume.
        auto &bytes = conn.parked.co.promise();
        bytes.sink = &sink;
        bytes.plan = &plan;
        conn.parked.co.resume();
        if (!conn.parked.done())
            return true;
        const bool persist = bytes.persist;
        conn.parked.destroy();
        return persist;
    }
    // response.file: the head, then the window buffer or a chunk of the
    // mapping as an external segment, so the bytes reach the kernel
    // without a copy.
    if (conn.file != nullptr &&
        (conn.file->stage == FileStage::kDeliver || conn.file->stage == FileStage::kDone)) {
        // The round is one value, and file_apply is the only thing that writes.
        const FileStep step = file_step(*conn.file, send_chunk_);
        if (step.head)
            sink.append(conn.file->head);
        if (step.src != FileStep::Src::kNone) {
            const char *base =
                step.src == FileStep::Src::kMapping ? conn.file->map_addr : conn.file->chunk.data();
            body_lend(conn, sink, {{base + step.start, step.give}, plan});
        }
        file_apply(conn, step);
        if (!step.clear)
            return true;
        if (!step.persist)
            return false;
        // The kDone round put nothing on the wire, so it does not consume the
        // round: a pipelined request waiting in the carry speaks below.
        // Consuming it wedged `response.file answers pipelined requests in
        // order`.
    }
    // The ring still owes the answer, so nothing else may speak for this
    // connection until it lands.
    if (conn.file != nullptr && conn.file->stage != FileStage::kNone)
        return true;
    if (conn.sse != nullptr)
        return sse_second(conn.sse, sec_, sink);
    if (conn.h2 != nullptr) {
        h2_sse_second(conn, sink);
        // RFC 9110 6.4: the DATA frame that ended this stream could not
        // answer, because the last octets were still on their way to the disk.
        // `ended` is cleared here, so a stream is served once.
        for (size_t i = 0; i < conn.h2->streams.size(); i++) {
            H2Stream &text = conn.h2->streams[i];
            if (!text.spill.ended || text.spill.fd < 0 || !text.spill.drained())
                continue;
            text.spill.ended = false;
            text.half_closed_remote = true;
            if (!h2_body_ready(conn, text.id)) {
                if (!h2_serve_parked(conn, text, sink, true))
                    return false;
            }
        }
        // Each parked run frames its own stream, so several may go out in one round.
        for (size_t i = 0; i < conn.h2_parked.size();) {
            Conn::H2Parked &bytes = conn.h2_parked[i];
            Conn::Round *const round = conn.park_at(bytes.run.co.promise().park);
            if (round == nullptr || !round->answer_ready) {
                i++;
                continue;
            }
            round->answer_ready = false;
            auto &promise = bytes.run.co.promise();
            promise.sink = &sink;
            promise.plan = &plan;
            bytes.run.co.resume();
            if (!bytes.run.done()) {
                i++;
                continue;
            }
            const bool lives = promise.status != 0;
            conn.h2_parked.erase(conn.h2_parked.begin() + static_cast<long>(i));
            if (!lives)
                return false;
        }
        h2_flush_pending(conn, sink, &plan);
        return true;
    }
    if (conn.asset != nullptr) {
        const AssetEntry &entry = *conn.asset;
        const size_t lim = conn.asset_end;
        size_t take = lim - conn.asset_off;
        if (plan.byte_cap != 0 && take > plan.byte_cap)
            take = plan.byte_cap;
        struct iovec iov[3];
        const unsigned k = Assets::entry_wire_iov(entry, {conn.asset_off, take}, iov);
        for (unsigned i = 0; i < k; i++) {
            plan.iov[plan.iovlen++] =
                Plan::Seg{static_cast<const char *>(iov[i].iov_base), 0, iov[i].iov_len};
        }
        plan.byte_total = take;
        conn.asset_off += take;
        if (conn.asset_off == lim) {
            conn.asset = nullptr;
            conn.become(ConnMode::kHead);
            conn.asset_off = 0;
            conn.asset_end = 0;
        }
        return true;
    }
    if (conn.carry.empty())
        return true;
    std::string held;
    held.swap(conn.carry);
    return connection_feed(conn, held, {sink, &plan});
}

// RFC 9113 6.10: a header block owns the connection until END_HEADERS.
bool Http1::h2_feed(Conn &conn, std::string_view incoming, Sink out_answer)
{
    const char *const data = incoming.data();
    const size_t length = incoming.size();
    std::string &sink = out_answer.bytes;
    Plan *const plan = out_answer.plan;
    H2State &h2_state = *conn.h2;
    const bool in_place = conn.carry.empty();
    const char *view = data;
    size_t viewlen = length;
    if (!in_place) {
        conn.carry.append(data, length);
        view = conn.carry.data();
        viewlen = conn.carry.size();
    }

    size_t offset = 0;
    while (viewlen - offset >= kH2FrameHeaderLen) {
        const unsigned char *frame_head = reinterpret_cast<const unsigned char *>(view) + offset;
        const uint32_t flen = h2_u24(frame_head);
        if (flen > kH2MaxFrameSize)
            return h2_error(conn, kH2FrameSizeError, sink);
        if (viewlen - offset - kH2FrameHeaderLen < flen)
            break;
        const uint8_t type = frame_head[3];
        const uint8_t flags = frame_head[4];
        const uint32_t frame_stream_id = h2_u31(frame_head + 5);
        const unsigned char *bytes = frame_head + kH2FrameHeaderLen;
        offset += kH2FrameHeaderLen + flen;

        if (h2_state.frag_active && type != kH2Continuation) {
            return h2_error(conn, kH2ProtocolError, sink);
        }

        // RFC 9113 8.1: the reset budget is tested here because this is the
        // one place in the frame walk that ends the connection.
        if (mrb_unlikely(h2_state.resets > kH2ResetBudget))
            return h2_error(conn, kH2EnhanceYourCalm, sink);

        switch (type) {
            case kH2Data: {
                if (frame_stream_id == 0)
                    return h2_error(conn, kH2ProtocolError, sink);
                H2Stream *stream = h2_state.find(frame_stream_id);
                if (stream == nullptr) {
                    if (h2_is_idle(h2_state, frame_stream_id))
                        return h2_error(conn, kH2ProtocolError, sink);
                    h2_credit_connection(sink, flen);
                    h2_reset_stream(conn, frame_stream_id, kH2StreamClosed, sink);
                    break;
                }
                if (!stream->end_headers || stream->half_closed_remote) {
                    h2_credit_connection(sink, flen);
                    h2_reset_stream(conn, frame_stream_id, kH2StreamClosed, sink);
                    break;
                }
                const unsigned char *data_plan = bytes;
                size_t dlen = flen;
                if (flags & kH2FlagPadded) {
                    if (dlen < 1)
                        return h2_error(conn, kH2ProtocolError, sink);
                    const uint8_t pad = data_plan[0];
                    data_plan++;
                    dlen--;
                    if (pad > dlen)
                        return h2_error(conn, kH2ProtocolError, sink);
                    dlen -= pad;
                }
                // RFC 8441: on a WebSocket stream the DATA frames are the WebSocket.
                if (mrb_unlikely(stream->ws != nullptr)) {
                    // RFC 9113 6.9: the credit goes back first. ws_feed consumes these
                    // bytes at once, and a websocket that never returns its window stalls
                    // after 65535 of them, which is one Autobahn case.
                    if (flen != 0) {
                        unsigned char increment[4];
                        u32_put(increment, flen);
                        control_frame_emit(sink, {kH2WindowUpdate, 0, 0, increment});
                        control_frame_emit(sink, {kH2WindowUpdate, 0, frame_stream_id, increment});
                    }
                    std::string websocket_out;
                    const bool go_on =
                        ws_feed(stream->ws, {reinterpret_cast<const char *>(data_plan), dlen},
                                websocket_out);
                    if (!websocket_out.empty())
                        stream->response_content.append_owned(websocket_out.data(),
                                                              websocket_out.size());
                    // RFC 9113 5.1: END_STREAM closes the peer's half, so this websocket
                    // is over. The credit above let the peer keep sending, so what the
                    // handler answers is bounded here.
                    if (mrb_unlikely(stream->response_content.owed_bytes() > kTunnelOutCap)) {
                        stream->streaming = false;
                        stream->response_content.clear();
                        h2_reset_stream(conn, frame_stream_id, kH2EnhanceYourCalm, sink);
                        h2_state.close_stream(frame_stream_id);
                        break;
                    }
                    if (!go_on || (flags & kH2FlagEndStream) != 0) {
                        // RFC 6455 7: the handler said the connection is over. What it still
                        // owes leaves first, and END_STREAM rides the last frame of it.
                        ws_free(stream->ws);
                        stream->ws = nullptr;
                        stream->streaming = false;
                        stream->half_closed_remote = true;
                        if (!stream->response_content.owes()) {
                            unsigned char end_head[kH2FrameHeaderLen];
                            h2_put_frame_header(end_head,
                                                {0, kH2Data, kH2FlagEndStream, frame_stream_id});
                            sink.append(reinterpret_cast<const char *>(end_head), sizeof(end_head));
                            h2_state.close_stream(frame_stream_id);
                        }
                    }
                    break;
                }
                if (stream->content_received + dlen > stream->max_body) {
                    h2_credit_connection(sink, flen);
                    h2_reset_stream(conn, frame_stream_id, kH2RefusedStream, sink);
                    break;
                }
                // RFC 9113 8.1.2.6: the frame that passes the declared length ends
                // the stream. Waiting for END_STREAM would store a body the request
                // already disowned.
                if (stream->content_length_given &&
                    stream->content_received + dlen > stream->content_length) {
                    h2_credit_connection(sink, flen);
                    if (!h2_count_lie(conn, frame_stream_id, sink))
                        return false;
                    break;
                }
                stream->content_received += dlen;
                // RFC 9110 6.4: only content_types_accepted, create_path and
                // process_post read a body, and the head chose the destination. Any
                // other stream's octets are counted and dropped, so an idle stream
                // cannot hold megabytes nobody asks for.
                {
                    const char *const bp = reinterpret_cast<const char *>(data_plan);
                    bool wrote = true;
                    switch (stream->data) {
                        case H2Stream::Data::kMem:
                            wrote = MemWriter{&stream->request_content}.put(bp, dlen);
                            break;
                        case H2Stream::Data::kFile:
                            wrote = FileWriter{&stream->spill}.put(bp, dlen);
                            break;
                        case H2Stream::Data::kDrop:
                            break;
                    }
                    // A body that named no length has outgrown memory, so what memory
                    // holds goes to the file now.
                    if (mrb_unlikely(wrote && stream->data == H2Stream::Data::kMem &&
                                     stream->request_content.size() >= kBodySpill)) {
                        // RFC 9113 8.7: no slot for the file is load, and REFUSED_STREAM says
                        // the client may send the request again.
                        const SpillOpen opened = stream->spill.open_file();
                        if (mrb_unlikely(opened == SpillOpen::kNoSlot)) {
                            h2_credit_connection(sink, flen);
                            h2_reset_stream(conn, frame_stream_id, kH2RefusedStream, sink);
                            break;
                        }
                        wrote = opened == SpillOpen::kOpen &&
                                FileWriter{&stream->spill}.put(stream->request_content.data(),
                                                               stream->request_content.size());
                        if (wrote) {
                            stream->request_content.clear();
                            stream->request_content.shrink_to_fit();
                            stream->data = H2Stream::Data::kFile;
                        }
                    }
                    if (mrb_unlikely(!wrote)) {
                        stream->spill.close_file();
                        h2_credit_connection(sink, flen);
                        h2_reset_stream(conn, frame_stream_id, kH2InternalError, sink);
                        break;
                    }
                }
                if (flen != 0) {
                    unsigned char increment[4];
                    u32_put(increment, flen);
                    control_frame_emit(sink, {kH2WindowUpdate, 0, 0, increment});
                    control_frame_emit(sink, {kH2WindowUpdate, 0, frame_stream_id, increment});
                }
                if (flags & kH2FlagEndStream) {
                    // RFC 9113 8.1.2.6: a body that ends short of what it declared.
                    if (stream->content_length_given &&
                        stream->content_received != stream->content_length) {
                        if (!h2_count_lie(conn, frame_stream_id, sink))
                            return false;
                        break;
                    }
                    // RFC 9110 6.4: the descriptor a run reads from must hold every octet,
                    // so the answer waits for the last write. The reactor serves this
                    // stream when the file is drained.
                    stream->spill.ended = true;
                    if (mrb_unlikely(stream->spill.fd >= 0 && !stream->spill.drained()))
                        break;
                    // A run that stopped for this body is resumed. Only a stream with no
                    // such run is served here.
                    stream->half_closed_remote = true;
                    if (!h2_body_ready(conn, frame_stream_id)) {
                        if (!h2_serve_parked(conn, *stream, sink, true))
                            return false;
                    }
                }
                break;
            }

            case kH2Headers: {
                if (frame_stream_id == 0 || (frame_stream_id & 1) == 0)
                    return h2_error(conn, kH2ProtocolError, sink);
                if (h2_state.find(frame_stream_id) == nullptr &&
                    !h2_is_idle(h2_state, frame_stream_id)) {
                    return h2_error(conn, kH2ProtocolError, sink);
                }
                const unsigned char *hpack = bytes;
                size_t hlen = flen;
                if (flags & kH2FlagPadded) {
                    if (hlen < 1)
                        return h2_error(conn, kH2ProtocolError, sink);
                    const uint8_t pad = hpack[0];
                    hpack++;
                    hlen--;
                    if (pad > hlen)
                        return h2_error(conn, kH2ProtocolError, sink);
                    hlen -= pad;
                }
                if (flags & kH2FlagPriority) {
                    if (hlen < 5)
                        return h2_error(conn, kH2FrameSizeError, sink);
                    if (h2_u31(hpack) == frame_stream_id)
                        return h2_error(conn, kH2ProtocolError, sink);
                    hpack += 5;
                    hlen -= 5;
                }
                if (flags & kH2FlagEndHeaders) {
                    // The whole block is contiguous in the recv buffer, so it is decoded
                    // where it lies. frag exists for the split CONTINUATION makes.
                    h2_state.frag_active = false;
                    const H2Headers head = {
                        frame_stream_id, (flags & kH2FlagEndStream) != 0, {hpack, hlen}};
                    if (!h2_dispatch(conn, head, sink))
                        return false;
                    break;
                }
                if (hlen > kH2FragBudget)
                    return h2_error(conn, kH2EnhanceYourCalm, sink);
                h2_state.frag.assign(reinterpret_cast<const char *>(hpack), hlen);
                h2_state.frag_stream = frame_stream_id;
                h2_state.frag_flags = flags;
                h2_state.frag_active = true;
                break;
            }

            case kH2Continuation: {
                if (!h2_state.frag_active || frame_stream_id != h2_state.frag_stream) {
                    return h2_error(conn, kH2ProtocolError, sink);
                }
                if (h2_state.frag.size() + flen > kH2FragBudget) {
                    return h2_error(conn, kH2EnhanceYourCalm, sink);
                }
                h2_state.frag.append(reinterpret_cast<const char *>(bytes), flen);
                if (flags & kH2FlagEndHeaders) {
                    h2_state.frag_active = false;
                    const H2Headers head = {
                        h2_state.frag_stream,
                        (h2_state.frag_flags & kH2FlagEndStream) != 0,
                        {reinterpret_cast<const unsigned char *>(h2_state.frag.data()),
                         h2_state.frag.size()}};
                    if (!h2_dispatch(conn, head, sink))
                        return false;
                }
                break;
            }

            case kH2Priority:
                if (frame_stream_id == 0)
                    return h2_error(conn, kH2ProtocolError, sink);
                if (flen != 5)
                    return h2_error(conn, kH2FrameSizeError, sink);
                if (h2_u31(bytes) == frame_stream_id)
                    return h2_error(conn, kH2ProtocolError, sink);
                break;

            case kH2RstStream:
                if (frame_stream_id == 0)
                    return h2_error(conn, kH2ProtocolError, sink);
                if (flen != 4)
                    return h2_error(conn, kH2FrameSizeError, sink);
                if (h2_state.find(frame_stream_id) == nullptr &&
                    h2_is_idle(h2_state, frame_stream_id)) {
                    return h2_error(conn, kH2ProtocolError, sink);
                }
                h2_state.close_stream(frame_stream_id);
                h2_count_reset(conn);
                break;

            case kH2Settings: {
                if (frame_stream_id != 0)
                    return h2_error(conn, kH2ProtocolError, sink);
                if (flags & kH2FlagAck) {
                    if (flen != 0)
                        return h2_error(conn, kH2FrameSizeError, sink);
                    break;
                }
                if (flen % 6 != 0)
                    return h2_error(conn, kH2FrameSizeError, sink);
                for (uint32_t entry = 0; entry < flen; entry += 6) {
                    const uint16_t setting_id = h2_u16(bytes + entry);
                    const uint32_t value = h2_u32(bytes + entry + 2);
                    switch (setting_id) {
                        case kH2SettingsHeaderTableSize:
                            // Neither RFC 9113 6.5.2 nor RFC 7541 4.2 bounds this peer-chosen
                            // number. Encoding with a smaller table than the peer permits is
                            // legal, so the ceiling is ours.
                            lshpack_enc_set_max_capacity(
                                &h2_state.enc, value > kH2EncTableMax ? kH2EncTableMax : value);
                            break;
                        case kH2SettingsEnablePush:
                            if (value > 1)
                                return h2_error(conn, kH2ProtocolError, sink);
                            break;
                        case kH2SettingsInitialWindowSize: {
                            if (value > kH2WindowCeiling)
                                return h2_error(conn, kH2FlowControlError, sink);
                            const int64_t delta =
                                static_cast<int64_t>(value) - h2_state.peer_initial_window;
                            // RFC 9113 6.9.2: the change applies to every open stream, and a
                            // stream that would go over the ceiling is a FLOW_CONTROL_ERROR.
                            for (const H2Stream &stp : h2_state.streams) {
                                if (stp.flow_window + delta > kH2WindowCeiling) {
                                    return h2_error(conn, kH2FlowControlError, sink);
                                }
                            }
                            h2_state.peer_initial_window = static_cast<int64_t>(value);
                            for (H2Stream &stp : h2_state.streams)
                                stp.flow_window += delta;
                            break;
                        }
                        case kH2SettingsMaxFrameSize:
                            if (value < 16384 || value > 16777215)
                                return h2_error(conn, kH2ProtocolError, sink);
                            h2_state.peer_max_frame =
                                value > kH2MaxFrameSize ? kH2MaxFrameSize : value;
                            break;
                        default:
                            break;
                    }
                }
                control_frame_emit(sink, {kH2Settings, kH2FlagAck, 0, {}});
                break;
            }

            case kH2PushPromise:
                return h2_error(conn, kH2ProtocolError, sink);

            case kH2Ping:
                // RFC 9113 6.7: a PING on a stream is a PROTOCOL_ERROR, and only a
                // length other than 8 is a FRAME_SIZE_ERROR.
                if (frame_stream_id != 0)
                    return h2_error(conn, kH2ProtocolError, sink);
                if (flen != 8)
                    return h2_error(conn, kH2FrameSizeError, sink);
                if (!(flags & kH2FlagAck))
                    control_frame_emit(sink, {kH2Ping, kH2FlagAck, 0, {bytes, 8}});
                break;

            case kH2Goaway:
                if (flen < 8)
                    return h2_error(conn, kH2FrameSizeError, sink);
                h2_state.goaway_recv = true;
                break;

            case kH2WindowUpdate: {
                if (flen != 4)
                    return h2_error(conn, kH2FrameSizeError, sink);
                const uint32_t increment = h2_u31(bytes);
                if (increment == 0)
                    return h2_error(conn, kH2ProtocolError, sink);
                if (frame_stream_id == 0) {
                    h2_state.flow_window += increment;
                    if (h2_state.flow_window > kH2WindowCeiling) {
                        return h2_error(conn, kH2FlowControlError, sink);
                    }
                } else if (H2Stream *stream = h2_state.find(frame_stream_id)) {
                    stream->flow_window += increment;
                    if (stream->flow_window > kH2WindowCeiling) {
                        h2_reset_stream(conn, frame_stream_id, kH2FlowControlError, sink);
                        break;
                    }
                } else if (h2_is_idle(h2_state, frame_stream_id)) {
                    return h2_error(conn, kH2ProtocolError, sink);
                }
                h2_flush_pending(conn, sink, nullptr);
                break;
            }

            default:
                break;
        }
    }

    if (in_place) {
        if (offset < viewlen)
            conn.carry.assign(view + offset, viewlen - offset);
    } else {
        conn.carry.erase(0, offset);
    }
    h2_flush_pending(conn, sink, plan);
    return !h2_state.goaway_recv;
}
} // namespace webmachine
