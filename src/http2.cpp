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
constexpr size_t kH2MaxFields = kMaxHeaders + 8;
constexpr size_t kH2FragBudget = kMaxHead * 2;
// RFC 9113 8.1.1: how many streams one connection may lose to a request
// that breaks its own Content-Length before the connection itself ends.
// Four leaves room for a client with a defect and ends a client that
// makes the defect its method.
constexpr uint32_t kH2LieBudget = 4;
constexpr size_t kH2MergeBody = 1024;

// RFC 9113 4.1: a 32-bit field, network order.
void u32_put(unsigned char *bytes, uint32_t value)
{
    bytes[0] = static_cast<unsigned char>(value >> 24);
    bytes[1] = static_cast<unsigned char>(value >> 16);
    bytes[2] = static_cast<unsigned char>(value >> 8);
    bytes[3] = static_cast<unsigned char>(value);
}

// RFC 9113 6: one control frame - its type, its flags, the stream it names
// (0 = the connection itself), and its fixed payload.
struct H2Control {
    uint8_t type;
    uint8_t flags;
    uint32_t stream;
    std::span<const unsigned char> payload;
};

// Header + payload, into the sink.
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

// RFC 7541 5.2: a string length, 7-bit prefix, H bit 0 - no Huffman out.
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

// RFC 9113: the connection's state dies with the connection.
void h2_free(H2State *h2_state)
{
    delete h2_state;
}

// RFC 9110 4.2.1: a parked request's view - its bytes are the stream's own
// copy, so the spans have to be captured again.
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

// RFC 7541 6.1/6.2.2: lane 1 - a precomputed block of what never changes.
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

// RFC 9113 3.4: this side's half of the preface, a SETTINGS frame.
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

// RFC 9113 6.8: GOAWAY, and the connection is done.
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

// RFC 9113 5.1: an id above everything ever accepted is idle.
// RFC 9113 8.2.2: the connection-specific fields h2 forbids outright, and
// 8.1.1's content-length, which may be named once. False = malformed, and
// the stream is reset.
// RFC 9113 8.1.2: what a content-length field claimed, if one did - a
// second one is the protocol error this returns false for.
struct ClaimedLength {
    bool have = false;
    size_t value = 0;
};

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

// RFC 9113 8.1: a trailer field name the head owns alone. A trailer says
// nothing about framing, about the connection, or about the length of the
// body it closes.
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

// RFC 9110 5.6.2 / RFC 9113 8.2.1: which octets may stand in a field
// name. A name is a token, and RFC 9113 8.2.1 takes the uppercase
// letters out of it. One table of 256 flags, so the scan is one load
// and one test per octet. The tchar set is the one field_name_ok in
// webmachine.hpp spells, without 'A' to 'Z'.
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

// RFC 9113 8.2.1: one field of a request, head or trailer. The name is
// a lowercase token. The value carries no NUL, CR or LF, and it neither
// starts nor ends with SP or HTAB. False = the request is malformed,
// and RFC 9113 8.1.1 makes that a stream error of type PROTOCOL_ERROR.
//
// This runs once per field on the hot path, so it is one call from
// h2_dispatch and it stays out of line. nm -S on the host build reads
// its size on its own.
//
// RFC 7541 B: name_known says the decoder copied the name out of the
// static table. Every static name is a lowercase token, so such a name
// skips the scan.
//
// RFC 9113 8.3: a pseudo-header carries a colon, which no token has.
// h2_dispatch compares such a name whole against the five it serves.
// It refuses every other one, so the token rule does not run on a
// pseudo-header here. Its value takes the value rule like any other.
__attribute__((noinline)) bool h2_field_ok(http::Field field, bool name_known)
{
    const char *const length = field.name.data();
    const size_t name_length = field.name.size();
    if (name_length == 0)
        return false;
    if (!name_known && length[0] != ':') {
        for (size_t i = 0; i < name_length; i++) {
            if (!kH2NameOctet[static_cast<unsigned char>(length[i])])
                return false;
        }
    }
    const char *const value = field.value.data();
    const size_t value_length = field.value.size();
    if (value_length != 0 &&
        (h2_character_is_blank(value[0]) || h2_character_is_blank(value[value_length - 1])))
        return false;
    return http::field_value_ok(value, value_length);
}

// RFC 9113 8.3.1: :path is not empty, and it is "*" or it starts with
// "/". RFC 3986 3.3: a target carries no control octet, no SP and no
// DEL. picohttpparser refuses the same octets in an h1 request-line, so
// h1 and h2 refuse the same octets. An octet of 0x80 or more passes on
// both. A "*" with any method reaches the router and misses, as it
// does on h1. False = malformed (RFC 9113 8.1.1).
__attribute__((noinline)) bool h2_path_ok(const char *bytes, size_t length)
{
    if (length == 0)
        return false;
    if (bytes[0] != '/' && !(length == 1 && bytes[0] == '*'))
        return false;
    for (size_t i = 0; i < length; i++) {
        const unsigned char control = static_cast<unsigned char>(bytes[i]);
        if (control <= 0x20 || control == 0x7f)
            return false;
    }
    return true;
}

static bool h2_is_idle(const H2State &h2_state, uint32_t stream_id)
{
    return stream_id > h2_state.highest_opened;
}

// RFC 9113 6.2: one whole HEADERS frame - the route's prebuilt block, the
// per-answer fields, and the date - laid down for the cache to replay.
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

// RFC 9113 8.1.2.6: one request said one length and sent another. The
// stream dies for it. A connection that does it kH2LieBudget times is
// not a client with a defect, and it ends: every such stream costs a
// route match, a buffer or a file, and the octets already read.
//
// False = the connection is going away, and the caller stops feeding it.
bool Http1::h2_count_lie(Conn &conn, uint32_t stream_id, std::string &sink)
{
    h2_reset_stream(conn, stream_id, kH2ProtocolError, sink);
    conn.h2->lies++;
    if (conn.h2->lies < kH2LieBudget)
        return true;
    return h2_error(conn, kH2EnhanceYourCalm, sink);
}

// RFC 9113 6.4: a stream error - the stream dies, the connection lives.
void Http1::h2_reset_stream(Conn &conn, uint32_t stream_id, uint32_t code, std::string &sink)
{
    unsigned char payload[4];
    u32_put(payload, code);
    control_frame_emit(sink, {kH2RstStream, 0, stream_id, payload});
    conn.h2->close_stream(stream_id);
}

// RFC 9113 5.1.2: a client opens streams as fast as the settings allow,
// and each large body takes a descriptor. kH2SpillFilesMax counts the
// files this connection holds open. RFC 9110 6.4: kBodyFilesMax counts
// the files the process holds open, and BodySpill::open_file refuses
// the slot over it. Both refusals are REFUSED_STREAM, the code that
// tells the client to send the request again later. A file the
// platform could not make is the server's own error.
//
// Out of line on purpose: this runs once per large body, and inline it
// cost h2_dispatch 90 bytes. nm -S on the host build decided it.
__attribute__((noinline)) bool Http1::h2_body_file_open(Conn &conn, H2Stream &file_stat,
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

// #210 / #146: the page h1 spells for this status, framed for h2. False =
// there is nothing to say and the prebuilt bodyless block stands.
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
    // Lent where it lies, whether that is the picture in the mapping or the
    // page prepared at boot; a render lands in p.rendered, which
    // outlives the framing at the call site either way.
    out_answer.body = pbody;
    out_answer.blen = plen;
    out_answer.blk = &bytes.block;
    return true;
}

// RFC 9113 8.1/8.2/8.3: decode the block, check the pseudo-fields, and
// either answer or park the facts on the stream.
// RFC 9113 8.1: the fields a parked stream copied when its HEADERS came,
// rebuilt over the blob that outlived hdrbuf. Returns how many.
size_t Http1::h2_fields_of_parked(const H2Stream &stream, struct phr_header *header_vector)
{
    size_t name_length = stream.field_spans.size() / 4;
    if (name_length > kH2MaxFields)
        name_length = kH2MaxFields;
    for (size_t i = 0; i < name_length; i++) {
        header_vector[i].name = stream.field_blob.data() + stream.field_spans[i * 4];
        header_vector[i].name_len = stream.field_spans[i * 4 + 1];
        header_vector[i].value = stream.field_blob.data() + stream.field_spans[i * 4 + 2];
        header_vector[i].value_len = stream.field_spans[i * 4 + 3];
    }
    return name_length;
}

// A stream that parked at its HEADERS is served now: its request ended
// with the last DATA frame, or with trailers. Both ends come here. The
// values negotiation reads point into the decode buffer this stream no
// longer owns, so they are derived again from the copied fields, which
// are the only place they still exist.
// RFC 9110 6.4: which stream of this connection still owes octets to
// its file. One write flies per connection, because the ring answers
// with a connection and a generation and has no field for a stream.
// An upload is a run of large frames, so the streams take turns at the
// rate the disk allows rather than each waiting for its own turn.
BodySpill *Http1::spill_waiting_h2(Conn &conn)
{
    for (H2Stream &s : conn.h2->streams) {
        if (s.spill.owes_write())
            return &s.spill;
    }
    return nullptr;
}

// #53: the octets a run stopped for have all arrived. The run is in
// h2_parked with its round marked wants_body, and making that round ready
// is the whole resume - the loop that drives parked runs walks it on from
// the node it stopped at, and the resume binds the body.
//
// False = no run of this stream is waiting on a body, so the caller
// serves the stream itself. That is every stream whose flow has not run
// yet: an asset, a konst route, or a connection already at kParkSlots.
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
    // RFC 9110 6.4: a spilled body reaches request.body as a descriptor.
    // The file stays this stream's until close_stream drops the entry, so
    // a parked run still finds it when it asks.
    const int body_fd = stream.spill.fd;
    const size_t body_fd_len = stream.spill.written;
    // #36: is the whole body here? A stream served while its DATA is
    // still coming says no, and the walk stops at the first node that
    // reads content.
    const bool body_whole = complete;
    struct phr_header header_vector[kH2MaxFields];
    const size_t name_length = h2_fields_of_parked(stream, header_vector);
    http::ReqValues pvals;
    values_of_copied_fields({header_vector, name_length}, pvals);
    ReqView result;
    result.tls = apps_[conn.listener].tls;
    RouteSpans pspans;
    result.method = facts.method;
    result.content_ready = body_whole;
    // What the client declared. A stream with content declares it or it
    // is refused at the head, so this is the number B4 asks about even
    // while the octets are still coming.
    result.declared_len = stream.content_length_given ? stream.content_length : body.size();
    if (!body_whole) {
        // Nothing is bound while octets are still coming. The walk stops at
        // the first node that reads content, and the resume binds the whole
        // body - a part of one never reaches a callback.
    } else if (body_fd >= 0) {
        result.content_fd = body_fd;
        result.content_len = body_fd_len;
        stream.spill.bound = true;
    } else {
        result.content = body.empty() ? nullptr : body.data();
        result.content_len = body.size();
    }
    result.fields = header_vector;
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
    // A parked run logs from its own tail, with its own status.
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
    const unsigned char *const blk = headers.block.data();
    const size_t blk_len = headers.block.size();
    H2State &h2_state = *conn.h2;

    uint32_t quads[4 * kH2MaxFields];
    // RFC 7541 B: which static entry each name came from, or 0. One byte
    // per field, beside the four offsets.
    uint8_t hidx[kH2MaxFields];
    size_t next_request = 0;
    size_t used = 0;
    const unsigned char *bytes = blk;
    const unsigned char *text_end = bytes + blk_len;
    while (bytes < text_end) {
        if (next_request + 4 > 4 * kH2MaxFields)
            return h2_error(conn, kH2EnhanceYourCalm, sink);
        if (used > kH2FragBudget)
            return h2_error(conn, kH2EnhanceYourCalm, sink);
        if (h2_state.hdrbuf.size() < used + 4096)
            h2_state.hdrbuf.resize(used + 4096);
        lsxpack_header_t xh;
        lsxpack_header_prepare_decode(&xh, &h2_state.hdrbuf[used], 0, 4096);
        if (lshpack_dec_decode(&h2_state.dec, &bytes, text_end, &xh) != 0) {
            return h2_error(conn, kH2CompressionError, sink);
        }
        // RFC 7541 B: the decoder resolved this name out of the static
        // table and says which entry it was. That integer is the name, so
        // the scan below does not spell it out of the buffer again. A
        // literal name says LSHPACK_HDR_UNKNOWN and is compared as before.
        hidx[next_request / 4] = xh.hpack_index;
        quads[next_request++] = static_cast<uint32_t>(used + xh.name_offset);
        quads[next_request++] = xh.name_len;
        quads[next_request++] = static_cast<uint32_t>(used + xh.val_offset);
        quads[next_request++] = xh.val_len;
        // lshpack.h states what one decode writes into the buffer we lent:
        // name_len + val_len + lshpack_dec_extra_bytes(dec). Advancing by
        // val_offset + val_len is short by exactly those extra bytes (the
        // HTTP/1.x CRLF the decoder appends), so the next field's window
        // began inside bytes this one had just written. Their number, not
        // ours.
        used += static_cast<size_t>(xh.name_len) + xh.val_len + lshpack_dec_extra_bytes(&h2.dec);
    }
    h2_state.frag.clear();

    H2Stream *existing = h2_state.find(stream_id);
    if (existing != nullptr && existing->end_headers) {
        // RFC 9113 8.1: a second field block on an open stream is the
        // trailer section, and END_STREAM is the only way it comes.
        //
        // A stream that is not a request has none. A websocket or an event
        // stream carries a tunnel, not a flow, and serving one here would
        // run the route its entry never named - route 0, with facts nobody
        // sent - and free the tunnel under the handler that is using it.
        if (!end_stream || existing->half_closed_remote || existing->ws != nullptr ||
            existing->sse != nullptr || existing->streaming) {
            return h2_error(conn, kH2ProtocolError, sink);
        }
        // RFC 9113 8.1: a trailer section carries no pseudo-header, and the
        // rules on a field name and a field value (8.2.1) hold there as they
        // do in the head. The block was decoded and then thrown away, so a
        // trailer could spell anything at all.
        // RFC 9113 8.1.1: a malformed request is a stream error. The stream
        // ends with PROTOCOL_ERROR. The connection stays open.
        for (size_t i = 0; i < next_request; i += 4) {
            const char *const tname = h2_state.hdrbuf.data() + quads[i];
            const size_t tlen = quads[i + 1];
            const char *const tval = h2_state.hdrbuf.data() + quads[i + 2];
            const size_t tvlen = quads[i + 3];
            const bool tknown = hidx[i / 4] != LSHPACK_HDR_UNKNOWN;
            if (!h2_field_ok({{tname, tlen}, {tval, tvlen}}, tknown) || tname[0] == ':' ||
                !h2_trailer_name_ok(tname, tlen)) {
                h2_reset_stream(conn, stream_id, kH2ProtocolError, sink);
                return true;
            }
        }
        // The two gates the last DATA frame of a body passes. A trailer
        // section ends the body, so it answers to both: the octets have to
        // be the number the head declared, and a body in a file is whole
        // only once its last write has landed.
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
    bool accepted = true, saw_regular = false;
    bool have_method = false, have_path = false, have_scheme = false, have_authority = false;
    ClaimedLength claimed;
    // RFC 9113 8.3: the request's own fields, in the shape h1 hands down,
    // so request.headers and every by-name accessor answer the same way on
    // both protocols. Filled in the loop that already holds the pointers -
    // the pseudo-fields are not among them, because the branch below takes
    // them first, which is also what h1 means by a header.
    struct phr_header header_vector[kH2MaxFields];
    size_t name_length = 0;
    // RFC 8441 4: the :protocol pseudo-field, when the client sent one,
    // and the method as the client spelled it - CONNECT is not one of the
    // methods the flow knows, so parse_method answers kOther for it.
    const char *protocol_val = nullptr;
    size_t protocol_vlen = 0;
    const char *method_val = nullptr;
    size_t method_vlen = 0;
    for (size_t i = 0; accepted && i < next_request; i += 4) {
        const char *name = h2_state.hdrbuf.data() + quads[i];
        const size_t nlen = quads[i + 1];
        const char *field_value = h2_state.hdrbuf.data() + quads[i + 2];
        const size_t vlen = quads[i + 3];
        const uint8_t known = hidx[i / 4];
        // RFC 9113 8.2.1: the name is a lowercase token. The value carries
        // no NUL, CR or LF and no blank at either end. A field that breaks
        // one of these rules makes the request malformed. One call per
        // field; the scan is the helper's, not this function's. A name the
        // decoder took from the static table is a token already and skips
        // the scan.
        if (!h2_field_ok({{name, nlen}, {field_value, vlen}}, known != LSHPACK_HDR_UNKNOWN)) {
            accepted = false;
            break;
        }
        // RFC 8441 4 / RFC 9113 8.3: the colon says a field is a
        // pseudo-header, and nothing else may. The static index says which
        // one it is, and that is all it is used for below - a name the
        // decoder resolved is not spelled out of the buffer again. It may
        // not stand in for the colon: :status is a static entry too, and a
        // request that carries one is refused by the arm at the end.
        if (name[0] == ':') {
            if (saw_regular) {
                accepted = false;
                break;
            }
            // RFC 9113 8.2.1: the value rule holds for a pseudo-header as it
            // holds for every other field. The name carries a colon, so
            // h2_field_ok runs no token scan on it, and the switch below is
            // what refuses a name that is not one of the five.
            if (!h2_field_ok({{name, nlen}, {field_value, vlen}}, known != LSHPACK_HDR_UNKNOWN)) {
                accepted = false;
                break;
            }
            // One switch on the index, and the memcmp chain only for a name
            // the decoder did not resolve. The chain that tested the index
            // and the name together cost more than the memcmp it replaced:
            // a field low in the chain paid every compare above it.
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
                    if (nlen == 7 && std::memcmp(name, ":method", 7) == 0)
                        which = kMethod;
                    else if (nlen == 5 && std::memcmp(name, ":path", 5) == 0)
                        which = kPath;
                    else if (nlen == 7 && std::memcmp(name, ":scheme", 7) == 0)
                        which = kScheme;
                    else if (nlen == 10 && std::memcmp(name, ":authority", 10) == 0)
                        which = kAuthority;
                    else if (nlen == 9 && std::memcmp(name, ":protocol", 9) == 0)
                        which = kProtocol;
                    break;
                default:
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
        // Where this field lands, for vals.named to point at. A block past
        // kH2MaxFields keeps no slot, and SIZE_MAX says so.
        size_t index = SIZE_MAX;
        if (name_length < kH2MaxFields) {
            header_vector[name_length].name = name;
            header_vector[name_length].name_len = nlen;
            header_vector[name_length].value = field_value;
            header_vector[name_length].value_len = vlen;
            index = name_length;
            name_length++;
        }
        if (http::header_switch({{name, nlen}, {field_value, vlen}}, {facts, vals, index}) &&
            !h2_wire_header_ok({{name, nlen}, {field_value, vlen}}, claimed)) {
            accepted = false;
        }
    }
    // RFC 9113 8.3.1: the :path came, and it has the shape of a target.
    // have_path is tested first, so path_val is never null here.
    if (!accepted || !have_method || !have_path || !have_scheme ||
        !h2_path_ok(path_val, path_vlen)) {
        h2_reset_stream(conn, stream_id, kH2ProtocolError, sink);
        return true;
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
                                       header_vector,
                                       name_length,
                                       &vals};
        return h2_extended_connect(conn, request_ask, sink);
    }

    RouteSpans spans;
    // WHATWG HTML: an event stream route answers before the ordinary
    // table, the same order h1 asks in (feed_parse).
    if (mrb_unlikely(apps_[conn.listener].sse_table != nullptr)) {
        RouteSpans sspans;
        const int sr = apps_[conn.listener].sse_table->match(path_val, path_vlen, sspans);
        if (sr >= 0) {
            const H2SseAsk request_ask = {stream_id,
                                          static_cast<uint16_t>(sr),
                                          {path_val, path_vlen},
                                          &sspans,
                                          header_vector,
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
        // Only a bound resource reads a request view: a konst route answers
        // from the flow table and the head alone, so nothing is filled for it.
        const bool bound = block != nullptr && block->bound;
        ReqView result;
        if (bound) {
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
            result.fields = header_vector;
            result.field_count = name_length;
            result.values = &vals;
        }
        H2Request q{stream_id,
                    facts,
                    &vals,
                    bound ? &result : nullptr,
                    {path_val, path_vlen},
                    route,
                    head_only,
                    h2_state.hdrbuf.data(),
                    h2_state.hdrbuf.size()};
        q.bundle = block;
        // The straight line: a run that cannot stop needs no frame and no
        // held head, so it skips h2_serve and what h2_serve computes for one.
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
    // Decide, then do: what every DATA frame of this stream earns, worked
    // out once here instead of per frame in the feed.
    //
    // RFC 9110 15.5.14: the nearest limit answers. The application's
    // number holds until this route's resource names its own with
    // `def self.max_body`.
    file_stat.max_body = apps_[conn.listener].max_body;
    if (route != kNoRoute) {
        const Bundle &lb = bundles_[apps_[conn.listener].base + route];
        if (lb.bound && lb.res->max_body >= 0)
            file_stat.max_body = static_cast<size_t>(lb.res->max_body);
    }
    if (asset != nullptr || route == kNoRoute) {
        file_stat.data = H2Stream::Data::kDrop;
    } else {
        const Bundle &db = bundles_[apps_[conn.listener].base + route];
        const bool reads = db.bound && db.res->takes_body;
        // RFC 9110 6.4: the declared length picks where the octets land,
        // here, before the first one arrives. A body of kBodySpill or more
        // opens its file now, so no octet is ever moved from memory into it
        // part way through; a smaller one takes its buffer once.
        if (!reads || (claimed.have && claimed.value > file_stat.max_body)) {
            // A declared length above the limit opens no file and reserves no
            // buffer. The first DATA frame crosses the limit and the stream
            // is refused there, before an octet is stored.
            file_stat.data = H2Stream::Data::kDrop;
        } else if (!claimed.have && !db.res->saves_body) {
            // RFC 9110 8.6: nothing was declared, so nothing is known. The
            // body starts in memory and the count moves it to a file when it
            // grows. No reserve: the size is what arrives.
            file_stat.data = H2Stream::Data::kMem;
        } else if (claimed.value >= kBodySpill || db.res->saves_body) {
            // One descriptor per large body, and two ceilings on how many are
            // open: this connection's and the process's. Over either the
            // stream is refused, and the client sends it again later.
            if (mrb_unlikely(!h2_body_file_open(conn, file_stat, stream_id, sink)))
                return true;
            file_stat.data = H2Stream::Data::kFile;
        } else {
            // No reserve for a number the client only declared. 256 streams
            // that each name 255 KiB and send nothing took 64 MiB of this
            // process, per connection. The string grows with what arrives,
            // which is geometric and bounded by kBodySpill - over that the
            // body moves to a file.
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
    file_stat.field_spans.reserve(name_length * 4);
    for (size_t i = 0; i < name_length; i++) {
        file_stat.field_spans.push_back(static_cast<uint32_t>(file_stat.field_blob.size()));
        file_stat.field_spans.push_back(static_cast<uint32_t>(header_vector[i].name_len));
        file_stat.field_blob.append(header_vector[i].name, header_vector[i].name_len);
        file_stat.field_spans.push_back(static_cast<uint32_t>(file_stat.field_blob.size()));
        file_stat.field_spans.push_back(static_cast<uint32_t>(header_vector[i].value_len));
        file_stat.field_blob.append(header_vector[i].value, header_vector[i].value_len);
    }
    file_stat.content_length = claimed.value;
    file_stat.content_length_given = claimed.have;

    // #53: the flow walks on the head, and the body waits behind it.
    //
    // A request this server was always going to refuse - 401 from
    // is_authorized?, 403, 404 from resource_exists?, 405, 406, 412 - is
    // refused now, before its octets arrive. h1 has answered that way
    // since #36. h2 waited for the whole body first, so an upload to a
    // route that answers 404 was taken in full, and the body file opened
    // at this head held a slot of the process-wide count (kBodyFilesMax)
    // for as long as the upload lasted. An unauthenticated peer could
    // hold those slots against every other upload of the process.
    //
    // Only a run that can stop may walk here. A route that cannot stop,
    // or a connection with no park slot left, would take h2_serve's
    // straight path and answer from a body that has not arrived - a wrong
    // answer rather than a late one. Those wait, as they did before.
    if (asset == nullptr && route != kNoRoute && file_stat.data != H2Stream::Data::kDrop) {
        const Bundle &eb = bundles_[apps_[conn.listener].base + route];
        // Any bound resource may be asked to wait for a body, so what
        // matters here is a park slot to wait in, not what the resource
        // declares. Without one the stream waits for its body as before.
        if (eb.bound && eb.res != nullptr &&
            conn.h2_parked.size() < static_cast<size_t>(Conn::kParkSlots)) {
            // The stream table may move under the serve, so nothing of stx is
            // read after this call.
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
                // RFC 9113 8.1: the answer is whole and the request is not. The
                // peer is told to stop rather than left sending a body into a
                // stream that is finished with it. NO_ERROR, because nothing
                // went wrong - the answer simply needed none of it.
                h2_reset_stream(conn, stream_id, kH2NoError, sink);
            }
        }
    }
    return true;
}

// RFC 7541 Appendix A: never-indexed blocks per asset entry, at setup.
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

// RFC 7541: the asset tier's shared 405 and 406 blocks.
void Http1::h2_build_asset_shared()
{
    static const std::string kAllow = "GET, HEAD";
    h2_build_block(h2_asset405_, {405, nullptr, &kAllow});
    h2_build_block(h2_asset406_, {406});
    hpack_name_index_spell(h2_asset406_.bytes, 59);
    hpack_length_spell(h2_asset406_.bytes, 15);
    h2_asset406_.bytes.append("Accept-Encoding", 15);
}

// RFC 9113 6.1/6.9: the asset answer - body as segments over the mapping,
// window-refused remainder parked.
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
            const std::string cr = "bytes " + std::to_string(win_off) + "-" +
                                   std::to_string(win_end - 1) + "/" +
                                   std::to_string(Assets::wire_len(entry));
            hpack_length_spell(rblk, cr.size());
            rblk.append(cr);
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
            const std::string cr = "bytes */" + std::to_string(Assets::wire_len(entry));
            hpack_length_spell(rblk, cr.size());
            rblk.append(cr);
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

    // Without an insert: an insert here would move every index a cached
    // konst head holds, and nothing counts it there.
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

// RFC 9113 6.2/6.9.1: HEADERS and DATA for one stream; DATA beyond
// min(connection, stream) is parked, never written.
// RFC 9110 15.6.1: see the declaration. A run that named a file never
// lends its body either (see the O18 body handler in resource.cpp), so
// lent_have is already false here and there is nothing to unwind.
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

// #30: what the run left, read after it answered. A run that parked
// answers long after h2_produce returned, so this is its own step - the
// straight path calls it at once, and the coroutine calls it when the
// round is done.
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
    // response.file is h1-only for now: the deferred open lives on the
    // connection, and h2 multiplexes streams that would each need one.
    //
    // The slot is taken either way, because left set it would answer the
    // next request through this Resource. A run that named a file is
    // refused here rather than served an empty body it never meant.
    {
        WantedFile wanted;
        if (resource_file_wanted(*block->res, wanted)) {
            bytes.have_body = false;
            status = h2_refuse_file(conn, request.req);
        }
    }
    bytes.status = status;
    bytes.dynamic =
        (!block->res->run.content_type.empty() || !bytes.rhdrs->empty()) && status != 500;
}

// #30: the walk. `can_park` says whether the caller holds a frame that
// can keep a stopped run - the h2 dispatcher does not, the coroutine
// does. It is the same question run_parkable answers for h1.
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
    // What this run lent instead of copying, if anything: not yet owned by a
    // stream, so every path out of here below still has to place or free it.
    if (route == kNoRoute) {
        status = 404;
    } else {
        block = request.bundle != nullptr ? request.bundle
                                          : &bundles_[apps_[conn.listener].base + route];
        bytes.idx = &block->index;
        if (block->bound) {
            // The Values die with the frame that carried them, so a run reached
            // from here - parked or not - gets none.
            // The same [tune] zero_copy_threshold h1 reads: a HEAD sends no bytes
            // to lend, and h2 has no gzip path for a dynamic body to collide with.
            const RunAsk asked = {facts, vals, request_view, head_only ? 0 : zc_min_, can_park};
            const RunAnswer answer = {bytes.body, &have_body, bytes.rhdrs};
            status = resource_run(*block->res, asked, answer);
            bytes.b = block;
            bytes.status = status;
            bytes.have_body = have_body;
            // #30: the walk stopped. What it left cannot be read yet - it has
            // not answered - so the caller parks and calls h2_after_run when
            // the answer is back. Only a caller that can park ever sees this.
            if (mrb_unlikely(run_stopped(*block->res)))
                return;
            h2_after_run(conn, request, bytes, status);
            return;
        } else {
            // RFC 9110 12.5.1: the same c4 h1 asks. The facts arrive const here -
            // they belong to the stream - so the one negotiated bit is answered on
            // a copy, and only when the client sent an Accept at all.
            // A stream reached from a parked frame carries facts but no Values -
            // the bytes died with the frame. No Accept bytes, nothing to weigh,
            // and c3 already sent this request the way it went before.
            // The copy is made only for a request that sent an Accept: every
            // other one answers on the facts as they stand. One call to
            // flow::answer, because it is inlined at each call it has.
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
            const size_t mi = static_cast<size_t>(use->method);
            status = flow::answer(*use, {block->konst.per_method[mi], block->konst.shortcut[mi]});
        }
    }
    bytes.b = block;
    bytes.status = status;
    bytes.have_body = have_body;
    bytes.dynamic = dynamic;
}

// #30: a stream whose resource can stop takes the coroutine; every
// other one takes the straight answer. The frame costs an allocation,
// so only a resource that declared `compute` or `watch` pays for it -
// the same rule h1 follows in feed_parse.
// RFC 8441: a WebSocket on one h2 stream.
//
// The client sends an extended CONNECT - :method CONNECT with
// :protocol websocket, and, unlike a plain CONNECT, with :scheme and
// :path - so the route is looked up the way every other request's is.
// The answer is 200 and not 101: there is nothing to switch, the stream
// itself is the transport, and its DATA frames carry RFC 6455 frames.
//
// RFC 7692 travels unchanged: the offer arrives as an ordinary
// `sec-websocket-extensions` field of the CONNECT, and the answer goes
// back as one of the response. The compression is the WebSocket's, not
// the transport's, so nothing about it is h2's business.
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
    // Not half-closed: the peer keeps sending, and its DATA frames are the
    // WebSocket's own.
    stream.half_closed_remote = false;
    alog_status_ = 200;
    alog_bytes_ = 0;
    return true;
}

// WHATWG HTML over RFC 9113: an event stream on one h2 stream.
//
// The head goes out as HEADERS without END_STREAM, and every later tick
// is DATA against that stream's window - the same bytes h1 wraps in a
// chunk (RFC 9112 7.1). No Transfer-Encoding: h2 has none, and the
// stream itself is the framing.
//
// It is per stream, not per connection. An h2 connection multiplexes,
// so one client can hold several event streams at once, and each one
// keeps its own resource object.
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

// WHATWG HTML: one second has passed. Every event stream this connection
// carries is asked, and what it says goes on its own stream.
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
        // tick speaks every second whatever the window says, so what the
        // resource hands over piles up with nothing to bound it.
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
        // The resource said :close. The stream ends when what it already
        // handed over has left, so END_STREAM rides the last DATA frame.
        // A stream that owes nothing gets an empty one, or the peer waits
        // for an end that never comes.
        sse_free(stream.sse);
        stream.sse = nullptr;
        stream.streaming = false;
        if (!stream.response_content.owes()) {
            unsigned char eh[kH2FrameHeaderLen];
            h2_put_frame_header(eh, {0, kH2Data, kH2FlagEndStream, stream.id});
            sink.append(reinterpret_cast<const char *>(eh), sizeof(eh));
            h2_state.close_stream(stream.id);
            i--;
        }
    }
}

Http1::H2Served Http1::h2_serve(Conn &conn, const H2Request &request, std::string &sink)
{
    const Bundle *block = request.bundle;
    // #53: h2_can_stop asks whether the resource has a compute task or a
    // watcher - whether it can stop for a worker. A body is the other
    // reason to stop, and it belongs to no resource: any route may be
    // asked to wait for one. So a request whose body has not arrived takes
    // the parkable path whatever the resource declares. The straight path
    // runs the walk with can_park false, and the body stop is gated on
    // that, so it would answer from a body that is not there.
    if (request.complete && !h2_can_stop(block)) {
        return h2_answer(conn, request, sink) ? H2Served::kAnswered : H2Served::kClosed;
    }
    // A connection holds as many stopped runs as a tag can name. Past
    // that the request is answered the straight way: it cannot stop, so a
    // compute task runs here and a watcher is refused by name. A caller
    // serving an incomplete body checks for a slot before it asks, and
    // nothing between that check and this one takes one.
    if (conn.h2_parked.size() >= static_cast<size_t>(Conn::kParkSlots)) {
        return h2_answer(conn, request, sink) ? H2Served::kAnswered : H2Served::kClosed;
    }
    // #54: the range this request's fields sit in, and not one octet
    // more. The decode buffer holds every field of every stream this
    // dispatch read, and a run that stops copies what it is given - so
    // it is given this request's own span. A HEADERS block decodes in
    // one run, so the span is contiguous.
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
    // #54: the request, and the bytes it points into. The run holds both
    // before it can stop.
    start.h2.view = request.req;
    start.h2.head_at = head_at;
    start.h2.head_len = head_len;
    Run round = run_parkable(conn, std::move(start), &sink, nullptr);
    if (round.done()) {
        // It never stopped. The answer is already in the sink.
        return round.status() != 0 ? H2Served::kAnswered : H2Served::kClosed;
    }
    // The stream keeps an entry while the run is parked, so a RST_STREAM
    // closes it and a WINDOW_UPDATE credits it. The sweep leaves a parked
    // entry alone, and the run's tail clears the mark before it answers.
    H2Stream &keep = conn.h2->open(request.stream_id);
    keep.parked = true;
    keep.end_headers = true;
    // RFC 9113 5.1: only the end of the request closes this half. A run
    // that stopped for its body is waiting on DATA that has not arrived,
    // so the stream is still open to the peer.
    if (request.complete)
        keep.half_closed_remote = true;
    conn.h2_parked.push_back({request.stream_id, std::move(round)});
    return H2Served::kParked;
}

// RFC 9110 15.5.12: the stream sent content and declared no length. The
// answer is the head's, not a run's: the request view carries the head
// and no content, because none of it may be read.
//
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
    H2Block dynblk;
    // #210 / #146: an error carries the same page here that h1 spells. It
    // outlives the framing below, because a body the window cannot finish
    // is copied onto the stream from this buffer.
    H2ErrorPage err_page;
    // #210 response.error_asset: the run named an entry of the error
    // assets, and this stream carries it the way the asset tier's own
    // streams carry one - Content::Src::kAsset, parked and framed by
    // h2_flush_pending against the window. Nothing is rooted: the entry
    // lives in a mapping that outlives every stream that parks on it.
    const AssetEntry *run_asset =
        (bytes.b != nullptr && bytes.b->res != nullptr) ? bytes.b->res->run.asset : nullptr;
    // Its wire length is the answer's length: what h2_build_block declares,
    // what the access log counts, and what END_STREAM is measured against.
    const size_t asset_len = run_asset != nullptr ? Assets::wire_len(*run_asset) : 0;
    if (bytes.dynamic) {
        const bool bodyless = bytes.status == 204 || bytes.status == 304;
        if (bodyless || !bytes.have_body)
            (*bytes.body).clear();
        // The same bake h1 names: a `def self.to_html` renders at setup, and the
        // block being built here is not the prebuilt one that carries it.
        const bool baked = !bodyless && !bytes.have_body && !bytes.lent_have &&
                           bytes.status == 200 && !bytes.b->dynamic_body &&
                           !bytes.b->konst.body.empty();
        std::string ctype;
        std::string epage;
        // The same debt h1 pays here: a 4xx or 5xx whose run wrote a field of
        // its own never reaches h2_error_page, and would go out as a bare
        // p.status with the page missing.
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
        h2_build_block(dynblk, {bytes.status, ctype.empty() ? nullptr : &ctype});
        // A p.status that sends no body cleared (*p.body) above, and a lend it does
        // not carry is handed back below - the same order h1 spells it in.
        const bool use_lent = bytes.lent_have && !bodyless && bytes.have_body;
        const bool use_asset = run_asset != nullptr && !bodyless && bytes.have_body;
        // An asset's octets are never framed from `body` - h2_flush_pending
        // reads them out of the mapping - so only its length is set here.
        wire.body = use_asset
                        ? nullptr
                        : (use_lent ? bytes.lent
                                    : (baked ? bytes.b->konst.body.data() : (*bytes.body).data()));
        wire.blen = use_asset
                        ? asset_len
                        : (use_lent ? bytes.lent_len
                                    : (baked ? bytes.b->konst.body.size() : (*bytes.body).size()));
        wire.blk = &dynblk;
    } else if (bytes.have_body && bytes.status == 200) {
        wire.body =
            run_asset != nullptr ? nullptr : (bytes.lent_have ? bytes.lent : (*bytes.body).data());
        wire.blen = run_asset != nullptr
                        ? asset_len
                        : (bytes.lent_have ? bytes.lent_len : (*bytes.body).size());
        wire.blk = &h2_store_[(*bytes.idx)[200]];
    } else if (bytes.status == 500 && bytes.b != nullptr && bytes.b->bound) {
        // #210: what led here, gathered once - the record and the page carry
        // the same hash because they are taken over the same facts.
        ErrFacts ef;
        std::string ef_backtrace;
        std::string ef_steering;
        char ef_hash[kFingerprintLen] = {};
        ef.peer = conn.peer;
        ef.peer_len = conn.peer_len;
        ef.request_target = request_view != nullptr ? request_view->request_target : nullptr;
        ef.request_target_len = request_view != nullptr ? request_view->request_target_len : 0;
        ef.method = request_view != nullptr ? request_view->method_token : nullptr;
        ef.method_len = request_view != nullptr ? request_view->method_token_len : 0;
        spell_steering(vals, ef_steering);
        ef.steering = ef_steering.data();
        ef.steering_len = ef_steering.size();
        ef.body = request_view != nullptr ? request_view->content : nullptr;
        ef.body_len = request_view != nullptr ? request_view->content_len : 0;
        ef.body_full = ef.body_len;
        ef.status_code = 500;
        exception_facts(bytes.b->res->mrb, {ef, ef_backtrace});
        spell_fingerprint(ef_hash, fingerprint_of(ef));
        if (elog_.enabled)
            log_error(elog_, ef);
        // #210: handle_exception lives on the error resource and nowhere
        // else, so the exception object itself is what crosses over.
        std::string message;
        mrb_value exc = mrb_nil_value();
        if (resource_exception_take(*bytes.b->res, &exc))
            err_pages_.exception_text(exc, message);
        ErrorPages::Fields field;
        field.message = message.data();
        field.message_len = message.size();
        field.fingerprint = ef_hash;
        // A ship build says what was thrown and where the log has the rest; a
        // debug build is already telling you about itself, so the trace goes
        // on the page too.
        if (kDebugBuild) {
            field.backtrace = ef.backtrace;
            field.backtrace_len = ef.backtrace_len;
        }
        const H2ErrorAsk request_ask = {500, field, vals, bytes.b};
        if (!h2_error_page(request_ask, err_page, wire)) {
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
            spelled = h2_error_page(request_ask, err_page, wire);
        }
        if (!spelled)
            wire.blk = &h2_store_[(*bytes.idx)[bytes.status]];
    }

    const bool no_data = head_only || wire.blen == 0;

    // A lend the chain above did not adopt (a bodyless p.status, a 500 that
    // spelled its own body) never reached a plan, so this is its release.
    if (bytes.lent_have && (no_data || wire.body != bytes.lent)) {
        resource_body_unlend(bytes.lent_mrb, bytes.lent_v);
        bytes.lent_have = false;
    }
    // And one that was adopted becomes the stream's before anything below can
    // fail: from here on close_stream and ~H2State own it, so no error path
    // can strand a rooted body nobody comes back for.
    if (bytes.lent_have) {
        H2Stream &keep = h2_state.open(stream_id);
        keep.response_content.take_lent(bytes.lent_mrb, bytes.lent_v, bytes.lent, bytes.lent_len);
        keep.end_headers = true;
        keep.half_closed_remote = true;
    }
    // #210: an asset parks the way the asset tier parks one, with the same
    // Src. h2_flush_pending frames it out of the mapping, and the sweep
    // there closes the stream once the window has let all of it through.
    //
    // A head-only answer, or a status that sends nothing, takes no stream:
    // no_data covers both.
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
        budget = h2_state.flow_window < swin ? h2_state.flow_window : swin;
    }

    bool merged = false;
    if (bytes.dynamic) {
        // RFC 7541: lane 1 spells :p.status and Content-Type, lane 2 the Date and
        // every field line this run produced. A per-request head is never cached.
        unsigned char ebuf[2048];
        unsigned char *error_page = ebuf;
        unsigned char *const eend = ebuf + sizeof(ebuf);
        // Indexed, unlike the cached path's: this head is spelled once and
        // thrown away, so an insert here costs nothing to replay - but it
        // does move every index a cached head may be holding, which is what
        // enc_ins counts.
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
                size_t vs = colon + 1;
                while (vs < eol && ((*bytes.rhdrs)[vs] == ' ' || (*bytes.rhdrs)[vs] == '\t'))
                    vs++;
                name.assign((*bytes.rhdrs), index, colon - index);
                for (char &c : name) {
                    if (c >= 'A' && c <= 'Z')
                        c = static_cast<char>(c + 32);
                }
                if (!h2_enc_field({&h2_state.enc, error_page, eend},
                                  {name, {(*bytes.rhdrs).data() + vs, eol - vs}})) {
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
            // RFC 7541 6.2.1 / 6.1: content-type is the same string for every
            // answer this route ever gives, so it goes into the peer's p.dynamic
            // table once and is a one-byte reference after that. Encoded
            // twice: ls-hpack answers the first call with the insert and the
            // second with the index it just made, which is exactly the two
            // forms this cache needs. Only the 200 has one - the shared p.status
            // blocks carry no content-type, and a bound route never reaches
            // this branch.
            const std::string *ct =
                (bytes.status == 200 && bytes.b != nullptr && !bytes.b->konst.content_type.empty())
                    ? &bytes.b->konst.content_type
                    : nullptr;
            unsigned char pbuf[256];
            unsigned char rbuf[256];
            size_t plen = 0;
            size_t rlen = 0;
            if (ct != nullptr) {
                unsigned char *pp = pbuf;
                unsigned char *rp = rbuf;
                if (!h2_enc_field({&h2_state.enc, pp, pbuf + sizeof(pbuf)},
                                  {"content-type", *ct}) ||
                    !h2_enc_field({&h2_state.enc, rp, rbuf + sizeof(rbuf)},
                                  {"content-type", *ct})) {
                    return h2_error(conn, kH2InternalError, sink);
                }
                plen = static_cast<size_t>(pp - pbuf);
                rlen = static_cast<size_t>(rp - rbuf);
                h2_state.enc_ins++;
                // The block that carried the literal is the wrong one now: the
                // shared 200 spells :p.status and nothing else.
                wire.blk = &h2_store_[index_[200]];
            }
            unsigned char dbuf[64];
            unsigned char *data_plan = dbuf;
            // Not indexed: these bytes are kept and sent again for every
            // answer of this second, and an insert replayed is an insert the
            // peer performs again each time. content-type above may be
            // indexed for the opposite reason - it is inserted once and the
            // cache then replays the reference, never the insert.
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
        // One answer per connection carries the insert; it is never merged
        // with a DATA frame, because it is one response in a second and the
        // merge exists for the other thousands.
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

    // RFC 9113 6.9.1: not one byte of a lent body is framed here. All of it
    // is parked on the stream and h2_flush_pending - the only place holding a
    // plan - gives it the window, the frames and the external segment, the
    // same way the asset tier's `src` is delivered.
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
    // A p.lent stream is never closed here: its bytes have not been framed yet,
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

    // RFC 9113: claim the sink bytes this round started with - a plan naming
    // any sink range describes the sink completely.
    void prime()
    {
        if (plan == nullptr || plan->iovlen != 0 || sink.empty())
            return;
        plan->iov[plan->iovlen++] = Http1::Plan::Seg{nullptr, 0, sink.size()};
        plan->byte_total += sink.size();
    }

    // RFC 9113 6.1: room for one more DATA frame - its header plus up to three
    // payload spans. Every gate sits before the frame, never inside one.
    bool room_for_frame() const
    {
        if (plan == nullptr)
            return emitted < kDeliverChunk;
        if (plan->iovlen + 4 > Http1::Plan::kSegs)
            return false;
        return plan->byte_cap == 0 || plan->byte_total < plan->byte_cap;
    }

    // RFC 9113: framing bytes, coalesced into the open sink run.
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

    // RFC 1952: asset payload as pointers into the mapping; small pieces are
    // copied instead (one page is the measured line).
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

    // RFC 9110 8.6: the body a run lent, as a pointer into its own frozen
    // String. Without a plan there is no segment to hang it on, so the round
    // copies - correct either way, since the lend outlives this round.
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
// RFC 9113 8.3: the method column, from the enum - the wire bytes are gone.
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

// RFC 9113: one answer, one access line, written where :path still lives.
void Http1::h2_log(Conn &conn, const H2Logged &l)
{
    if (!alog_.enabled)
        return;
    const flow::ReqFacts &facts = l.facts;
    const char *const target = l.target.data();
    const size_t tlen = l.target.size();
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

// RFC 9113 6.9: one round of parked streams, as segments; the cursor keeps
// the cut fair between them.
// RFC 9113 6.1: carve the round into DATA frames. END_STREAM rides the
// frame that lands on the last byte - which is why the step carries the
// body's total and not just what this round gives. Returns what actually
// went out: the round can run out of plan room mid-body, and then nothing
// ends.
// One stream, and what it may put on the wire this round.
struct H2Sending {
    const H2Stream &stream;
    const Http1::H2SendStep &step;
    size_t max_frame;
};

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

// Both windows and the body's one cursor, from what really went out. An
// offset says this for free; erasing from the front of a buffer would
// cost a memmove per round.
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

// Does this connection still owe bytes? Asked before a send, for MSG_MORE.
bool Http1::pending(const Conn &conn) const
{
    if (conn.h2 != nullptr) {
        for (const H2Stream &s : conn.h2->streams) {
            if (s.response_content.owes())
                return true;
        }
        return false;
    }
    // A file the reactor is still opening owes bytes too - and saying so is
    // what keeps spell_next_round from re-feeding the carry ahead of that answer.
    // kDone is deliberately not owed bytes: its last lend has drained and it
    // only has bookkeeping left. Counting it here cost 60 us per request -
    // MSG_MORE corked the final send, and on_send took the arm_meminfo
    // detour (an io-wq round trip) in front of a round that sends nothing.
    return conn.asset != nullptr || (conn.file != nullptr && conn.file->stage != FileStage::kNone &&
                                     conn.file->stage != FileStage::kDone);
}

// The continuation both protocols share: the sink has fully drained.
bool Http1::spell_next_round(Conn &conn, std::string &sink, Plan &plan)
{
    // The release point: the Ring reaches here only once a whole round has
    // drained, so a body lent to that round is off the wire. Before the next
    // one is built, so a connection never holds two.
    conn.zc_release();
    // #80: a run stopped on this connection. This is where it may go on and
    // nowhere else - the sink and the plan it writes into exist here, and
    // did not exist at the completion that said its answer had arrived.
    if (mrb_unlikely(conn.run_parked())) {
        // Still owed. Nothing else may speak for this connection while a run
        // is stopped, least of all a pipelined request behind it: RFC 9112
        // 9.3.2 puts the responses out in the order the requests came.
        // #30: the round of the run that stopped here. The frame holds it;
        // the connection knows which park slot it took.
        Conn::Round *const parked_round = conn.park_at(conn.parked.co.promise().park);
        if (parked_round == nullptr || !parked_round->answer_ready)
            return true;
        parked_round->answer_ready = false;
        // What the round holds is not cleared here. The run reads it after
        // this resume, and the next stop starts it at zero anyway.
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
    // response.file, spelled: the head, then the window buffer or a chunk of
    // the mapping lent as an external segment - the same door the asset tier
    // and a lent body use, so the bytes reach the kernel without a copy.
    if (conn.file != nullptr &&
        (conn.file->stage == FileStage::kDeliver || conn.file->stage == FileStage::kDone)) {
        // The round is computed first and performed second. Which window,
        // whether the mapping may go back, whether the access line is owed:
        // one value, and file_apply is the only thing that writes.
        const FileStep step = file_step(*conn.file, send_chunk_);
        if (step.head)
            sink.append(conn.file->head);
        if (step.src != FileStep::Src::kNone) {
            const char *base =
                step.src == FileStep::Src::kMapping ? conn.file->map_addr : conn.file->chunk.data();
            body_lend(conn, sink, {{base + step.start, step.give}, plan});
        }
        file_apply(conn, step);
        // Still owed: this round is spent.
        if (!step.clear)
            return true;
        // Over, and the connection ends with it.
        if (!step.persist)
            return false;
        // Over, and the connection lives: the kDone round put nothing on the
        // wire, so it does not get to consume the round - a pipelined request
        // waiting in the carry speaks below, in this same one. (Consuming it
        // wedged `response.file answers pipelined requests in order`: the
        // carry had no later round to be fed from.)
    }
    // The ring still owes the answer: nothing else may speak for this
    // connection until it lands, least of all the carry behind it.
    if (conn.file != nullptr && conn.file->stage != FileStage::kNone)
        return true;
    if (conn.sse != nullptr)
        return sse_second(conn.sse, sec_, sink);
    if (conn.h2 != nullptr) {
        // WHATWG HTML: every event stream this connection carries, asked
        // once per second, before the frames go out.
        h2_sse_second(conn, sink);
        // RFC 9110 6.4: a stream whose body is whole on the wire and whole
        // in its file as well. The DATA frame that ended it could not
        // answer, because the last octets were still on their way to the
        // disk. `ended` is cleared here, so a stream is served once.
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
        // #30: every run this connection stopped whose round is done. Each
        // one frames its own stream, so several may go out in one round.
        for (size_t i = 0; i < conn.h2_parked.size();) {
            Conn::H2Parked &bytes = conn.h2_parked[i];
            Conn::Round *const round = conn.park_at(bytes.run.co.promise().park);
            if (round == nullptr || !round->answer_ready) {
                i++;
                continue;
            }
            round->answer_ready = false;
            auto &pr = bytes.run.co.promise();
            pr.sink = &sink;
            pr.plan = &plan;
            bytes.run.co.resume();
            if (!bytes.run.done()) {
                i++;
                continue;
            }
            const bool lives = pr.status != 0;
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

// RFC 9113 4/6: the frame loop. A header block owns the connection until
// END_HEADERS (6.10).
bool Http1::h2_feed(Conn &conn, std::string_view in, Sink out_answer)
{
    const char *const data = in.data();
    const size_t length = in.size();
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
                // RFC 8441: on a WebSocket stream the DATA frames are the
                // WebSocket. What the handler answers goes back on the same
                // stream, against its window, like an event stream's ticks.
                if (mrb_unlikely(stream->ws != nullptr)) {
                    // RFC 9113 6.9: the credit goes back first. These bytes are
                    // consumed the moment ws_feed reads them, and a websocket that
                    // never returns its window stalls the moment the peer has sent
                    // 65535 of them - which is one Autobahn case, not an edge.
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
                    // RFC 9113 5.1: END_STREAM closes the peer's half, so no more
                    // of the tunnel can arrive and this websocket is over - the
                    // same end a handler reaches when it says so. Without this the
                    // stream and its WsConn stood until the connection went, and
                    // DATA after END_STREAM was still read.
                    // The peer's own window is shut and it keeps sending. The
                    // credit above let it, so what this handler answers has
                    // nowhere to go and nothing bounded it.
                    if (mrb_unlikely(stream->response_content.owed_bytes() > kTunnelOutCap)) {
                        stream->streaming = false;
                        stream->response_content.clear();
                        h2_reset_stream(conn, frame_stream_id, kH2EnhanceYourCalm, sink);
                        h2_state.close_stream(frame_stream_id);
                        break;
                    }
                    if (!go_on || (flags & kH2FlagEndStream) != 0) {
                        // RFC 6455 7: the handler said the connection is over. What
                        // it still owes leaves first, and END_STREAM rides the last
                        // frame of it.
                        ws_free(stream->ws);
                        stream->ws = nullptr;
                        stream->streaming = false;
                        stream->half_closed_remote = true;
                        if (!stream->response_content.owes()) {
                            unsigned char eh[kH2FrameHeaderLen];
                            h2_put_frame_header(eh,
                                                {0, kH2Data, kH2FlagEndStream, frame_stream_id});
                            sink.append(reinterpret_cast<const char *>(eh), sizeof(eh));
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
                // RFC 9113 8.1.2.6: the octets that arrive are counted against
                // the length the request declared, and the frame that passes it
                // is the frame that ends the stream. Waiting for END_STREAM
                // would store a body the request already disowned.
                if (stream->content_length_given &&
                    stream->content_received + dlen > stream->content_length) {
                    h2_credit_connection(sink, flen);
                    if (!h2_count_lie(conn, frame_stream_id, sink))
                        return false;
                    break;
                }
                stream->content_received += dlen;
                // RFC 9110 6.4: stored only where a node of this resource can
                // read them, and in the place the head chose. Only
                // content_types_accepted, create_path and process_post read a
                // body, and the fold wrote that answer on the resource; the
                // head wrote it and the destination on the stream. A konst
                // route's octets, a miss's, and a resource that reads no body
                // at all are counted and dropped, so an idle stream cannot hold
                // megabytes nobody will ever ask for.
                //
                // Neither writer below tests where the octets belong. That is
                // the same switch the frame already needed.
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
                    // The one move: a body that named no length has outgrown
                    // memory. What memory holds goes to the file now, and every
                    // frame after this one is a file write. The count decides, so
                    // the test is a comparison the frame already loaded.
                    if (mrb_unlikely(wrote && stream->data == H2Stream::Data::kMem &&
                                     stream->request_content.size() >= kBodySpill)) {
                        // RFC 9113 8.7: no slot for the file is load, and REFUSED_STREAM
                        // says the client may send the request again. No node that
                        // reads content has run: each one waits for END_STREAM.
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
                    // The other half of the same rule: a body that ends short of
                    // what it declared.
                    if (stream->content_length_given &&
                        stream->content_received != stream->content_length) {
                        if (!h2_count_lie(conn, frame_stream_id, sink))
                            return false;
                        break;
                    }
                    // RFC 9110 6.4: the body is whole on the wire, and it may not
                    // be whole in its file. The descriptor a run reads from must
                    // hold every octet, so the answer waits for the last write.
                    // The reactor serves this stream when the file is drained.
                    stream->spill.ended = true;
                    if (mrb_unlikely(stream->spill.fd >= 0 && !stream->spill.drained()))
                        break;
                    // #53: a run that walked on the head and stopped for this body
                    // is resumed. Only a stream with no such run is served here.
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
                    // The whole block is already contiguous in the recv buffer, so
                    // it is decoded where it lies; frag exists for the split that
                    // CONTINUATION makes, and this is not one.
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
                            // Clamped, never forwarded raw: this is a peer-chosen
                            // 32-bit number and neither RFC 9113 6.5.2 nor RFC 7541
                            // 4.2 bounds it. Encoding with a smaller table than the
                            // peer permits is always legal, so the ceiling is ours.
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
                            // RFC 9113 6.9.2: the change applies to every open stream,
                            // and a stream that would go over the ceiling is a
                            // FLOW_CONTROL_ERROR rather than a window this server
                            // quietly carries.
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
                // RFC 9113 6.7: a PING on a stream is a PROTOCOL_ERROR, and only
                // a length other than 8 is a FRAME_SIZE_ERROR. One code for both
                // told the peer the wrong thing about its own mistake.
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
