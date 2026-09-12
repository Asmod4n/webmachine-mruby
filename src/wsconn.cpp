#include "http1.hpp"
#include "ruby_value.hpp"

#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/proc.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <simdutf.h>

#include <cstdio>
#include <cstring>

namespace webmachine
{
namespace wsdeflate
{
// RFC 7692 7.2.2: where inflated bytes go. False stops the pump, which is
// how the message cap is enforced against a decompression bomb.
using InflateSink = bool (*)(void *ud, const char *q, size_t qn);

class Codec
{
  public:
    Codec() = default;
    Codec(const Codec &) = delete;
    Codec &operator=(const Codec &) = delete;
    // RFC 7692: both zlib streams die with the connection.
    ~Codec()
    {
        if (inf_on_)
            inflateEnd(&inf_);
        if (def_on_)
            deflateEnd(&def_);
    }

    // RFC 7692 7.1.2: what the negotiation settled on.
    void configure(const Params &bytes)
    {
        p_ = bytes;
    }
    // RFC 7692: what this connection agreed to.
    const Params &params() const
    {
        return p_;
    }

    // RFC 7692 7.2.2: payload bytes as they arrive; the sink is the only
    // bound, which is the whole decompression-bomb answer.
    int inflate_some(const char *incoming, size_t length, InflateSink sink, void *user_data)
    {
        if (!inflate_ready())
            return -1;
        inf_.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(incoming));
        inf_.avail_in = static_cast<uInt>(length);
        return pump(sink, user_data);
    }

    // RFC 7692 7.2.2 step 1: the four bytes the sender stripped go back on.
    int inflate_finish(InflateSink sink, void *user_data)
    {
        if (!inflate_ready())
            return -1;
        inf_.next_in = const_cast<Bytef *>(kSyncTail);
        inf_.avail_in = sizeof(kSyncTail);
        const int status = pump(sink, user_data);
        if (status != 0)
            return status;
        if (p_.client_no_context_takeover || inf_ended_) {
            inflateReset(&inf_);
            inf_ended_ = false;
        }
        return 0;
    }

    // RFC 7692 7.2.1: one whole message. False means send this message
    // uncompressed, which is always legal and leaves the peer's inflater
    // untouched. A deflate stream that failed in the middle of a message is
    // never started again: with context takeover the peer keeps the window
    // of every message before, and a new stream starts from an empty window.
    // The two sides would then disagree. So a failure here stops compression
    // for this connection.
    bool compress(const char *incoming, size_t length, std::string &answer)
    {
        if (length > std::numeric_limits<uInt>::max())
            return false;
        if (deflate_stopped_ || !deflate_ready())
            return false;
        answer.clear();
        def_.next_in = reinterpret_cast<Bytef *>(const_cast<char *>(incoming));
        def_.avail_in = static_cast<uInt>(length);
        unsigned char chunk[8192];
        for (;;) {
            def_.next_out = chunk;
            def_.avail_out = sizeof(chunk);
            const int status = deflate(&def_, Z_SYNC_FLUSH);
            if (status != Z_OK && status != Z_BUF_ERROR) {
                deflate_stopped_ = true;
                return false;
            }
            answer.append(reinterpret_cast<const char *>(chunk), sizeof(chunk) - def_.avail_out);
            if (def_.avail_out != 0)
                break;
        }
        if (answer.size() < sizeof(kSyncTail) ||
            std::memcmp(answer.data() + answer.size() - sizeof(kSyncTail), kSyncTail,
                        sizeof(kSyncTail)) != 0) {
            deflate_stopped_ = true;
            return false;
        }
        answer.resize(answer.size() - sizeof(kSyncTail));
        if (p_.server_no_context_takeover)
            deflateReset(&def_);
        return true;
    }

  private:
    // RFC 7692 7.1.2.1: never below 9 bits - no zlib can produce an 8-bit
    // window, and larger than promised is always safe.
    bool inflate_ready()
    {
        if (inf_on_)
            return true;
        const int bits = p_.client_max_window_bits < kMinRawWindowBits ? kMinRawWindowBits
                                                                       : p_.client_max_window_bits;
        if (inflateInit2(&inf_, -bits) != Z_OK)
            return false;
        inf_on_ = true;
        return true;
    }

    // RFC 7692 7.1.2.1: raw deflate, the negotiated window, Z_BEST_SPEED.
    // zlib refuses to build the stream for two different reasons. Z_MEM_ERROR
    // says the machine has no memory now. No stream exists yet, so no window
    // can disagree, and a later message tries again. Every other code says
    // zlib will not take these parameters. The same parameters get the same
    // answer, so this connection stops compressing.
    bool deflate_ready()
    {
        if (def_on_)
            return true;
        const int status =
            deflateInit2(&def_, Z_BEST_SPEED, Z_DEFLATED,
                         -static_cast<int>(p_.server_max_window_bits), 8, Z_DEFAULT_STRATEGY);
        if (status != Z_OK) {
            if (status != Z_MEM_ERROR)
                deflate_stopped_ = true;
            return false;
        }
        def_on_ = true;
        return true;
    }

    // RFC 7692 7.2.2: inflate until zlib stops producing.
    int pump(InflateSink sink, void *user_data)
    {
        unsigned char chunk[8192];
        for (;;) {
            inf_.next_out = chunk;
            inf_.avail_out = sizeof(chunk);
            const int status = inflate(&inf_, Z_NO_FLUSH);
            if (status == Z_STREAM_END)
                inf_ended_ = true;
            else if (status != Z_OK && status != Z_BUF_ERROR)
                return -1;
            const size_t read_bytes = sizeof(chunk) - inf_.avail_out;
            if (read_bytes != 0 &&
                !sink(user_data, reinterpret_cast<const char *>(chunk), read_bytes))
                return -2;
            if (inf_.avail_out != 0)
                return 0;
        }
    }

    Params p_;
    z_stream inf_{};
    z_stream def_{};
    bool inf_on_ = false;
    bool def_on_ = false;
    bool deflate_stopped_ = false;
    bool inf_ended_ = false;
};
} // namespace wsdeflate

struct WsResource {
    mrb_state *mrb = nullptr;
    struct RClass *klass = nullptr;
    bool have_close = false;
    size_t max_message = kMaxWsMessageDefault;
    bool validate_text = true;
    bool want_deflate = false;
};

struct WsConn {
    const WsResource *res = nullptr;
    Logger *elog = nullptr;
    mrb_value self = mrb_nil_value();

    unsigned char hbuf[14] = {};
    uint8_t hlen = 0;
    uint8_t hneed = 2;

    bool in_payload = false;
    uint8_t opcode = 0;
    bool is_final = false;
    bool control = false;
    uint64_t remaining = 0;
    unsigned char mask[4] = {};
    uint8_t mask_off = 0;

    char ctl[125] = {};
    uint8_t ctl_len = 0;

    mrb_value message = mrb_nil_value();
    bool msg_live = false;
    uint8_t msg_op = 0;
    size_t validated = 0;

    wsdeflate::Codec *codec = nullptr;
    bool msg_deflated = false;

    bool sent_close = false;
    bool got_close = false;
    bool closed_reported = false;
};

namespace
{
// RFC 6455 7.4.1: a Symbol answer by name. This is the vocabulary.
bool close_code_of_symbol(mrb_sym symbol, uint16_t &code)
{
    if (symbol == MRB_SYM(close) || symbol == MRB_SYM(normal))
        code = ws::kCloseNormal;
    else if (symbol == MRB_SYM(going_away))
        code = ws::kCloseGoingAway;
    else if (symbol == MRB_SYM(protocol_error))
        code = ws::kCloseProtocolError;
    else if (symbol == MRB_SYM(unsupported))
        code = ws::kCloseUnsupportedData;
    else if (symbol == MRB_SYM(invalid))
        code = ws::kCloseInvalidPayload;
    else if (symbol == MRB_SYM(policy))
        code = ws::kClosePolicyViolation;
    else if (symbol == MRB_SYM(too_big))
        code = ws::kCloseTooBig;
    else if (symbol == MRB_SYM(internal_error))
        code = ws::kCloseInternalError;
    else
        return false;
    return true;
}

// RFC 6455 5.1: one frame into the sink - header here, payload where it lies.
// One frame to send: what it is, the octets it carries, and whether those
// octets are deflated (RFC 7692 6).
struct Outgoing {
    uint8_t opcode;
    std::string_view payload;
    bool deflated = false;
};

void frame_emit(std::string &sink, Outgoing frame)
{
    const size_t length = frame.payload.size();
    char head[10];
    const size_t head_length = ws::header_build({frame.opcode, true, frame.deflated, length}, head);
    sink.append(head, head_length);
    if (length != 0)
        sink.append(frame.payload);
}

// RFC 6455 5.6 / RFC 7692 6: a DATA message, compressed where negotiated.
// How many of `most` arguments the method takes, or false if it is not
// defined. A cfunc is handed all of them; a Ruby method only its arity.
// One method to look for: the class it would be on, and its name.
struct Method {
    struct RClass *klass;
    mrb_sym sym;
};

// A websocket resource answers on_data(data, binary), and may answer
// on_close(code, reason). The call passes both arguments and asks
// nothing about the method: how many arguments a method takes is a
// question for mrb_get_args, and a resource of another shape raises
// ArgumentError when the callback runs.
bool method_is_defined(mrb_state *mrb, Method want)
{
    struct RClass *owner = want.klass;
    return !MRB_METHOD_UNDEF_P(mrb_method_search_vm(mrb, &owner, want.sym));
}

// RFC 7692 7.2.2: inflated bytes onto the message being assembled, up to
// the resource's cap. False is what stops a decompression bomb.
bool message_append_inflated(void *user_data, const char *inflated, size_t inflated_length)
{
    WsConn *conn = static_cast<WsConn *>(user_data);
    if (ruby_string_length(conn->message) + inflated_length > conn->res->max_message)
        return false;
    mrb_str_cat(conn->res->mrb, conn->message, inflated, inflated_length);
    return true;
}

void data_frame_emit(WsConn *conn, std::string &sink, Outgoing frame)
{
    const uint8_t opcode = frame.opcode;
    const char *const bytes = frame.payload.data();
    const size_t length = frame.payload.size();
    if (conn->codec != nullptr) {
        static std::string scratch;
        if (conn->codec->compress(bytes, length, scratch)) {
            frame_emit(sink, {opcode, scratch, true});
            return;
        }
    }
    frame_emit(sink, {opcode, {bytes, length}});
}

// RFC 6455 5.5.1: the close handshake's own half, sent at most once.
void close_frame_emit(WsConn *conn, std::string &sink, ws::Close close)
{
    if (conn->sent_close)
        return;
    conn->sent_close = true;
    char payload[125];
    const size_t length = ws::close_payload_build(close, payload);
    frame_emit(sink, {ws::kClose, {payload, length}});
}

// RFC 3629: can these 1-3 bytes still become a valid sequence?
bool utf8_prefix_may_still_be_valid(const unsigned char *bytes, size_t length)
{
    if (length == 0)
        return true;
    const unsigned char first_byte = bytes[0];
    size_t need = 0;
    unsigned char low = 0x80, hi = 0xbf;
    if (first_byte >= 0xc2 && first_byte <= 0xdf)
        need = 1;
    else if (first_byte == 0xe0) {
        need = 2;
        low = 0xa0;
    } else if (first_byte >= 0xe1 && first_byte <= 0xec)
        need = 2;
    else if (first_byte == 0xed) {
        need = 2;
        hi = 0x9f;
    } else if (first_byte >= 0xee && first_byte <= 0xef)
        need = 2;
    else if (first_byte == 0xf0) {
        need = 3;
        low = 0x90;
    } else if (first_byte >= 0xf1 && first_byte <= 0xf3)
        need = 3;
    else if (first_byte == 0xf4) {
        need = 3;
        hi = 0x8f;
    } else
        return false;
    if (length - 1 > need)
        return false;
    for (size_t i = 1; i < length; i++) {
        const unsigned char lim_lo = i == 1 ? low : 0x80;
        const unsigned char lim_hi = i == 1 ? hi : 0xbf;
        if (bytes[i] < lim_lo || bytes[i] > lim_hi)
            return false;
    }
    return true;
}

// RFC 6455 8.1: UTF-8 over a message that is still arriving.
bool message_utf8_is_valid(WsConn *conn, bool final)
{
    if (!conn->res->validate_text)
        return true;
    const std::string_view message = ruby_string_bytes(conn->message);
    const char *bytes = message.data();
    const size_t length = message.size();
    if (length <= conn->validated)
        return true;
    const simdutf::result resource =
        simdutf::validate_utf8_with_errors(bytes + conn->validated, length - conn->validated);
    if (resource.error == simdutf::error_code::SUCCESS) {
        conn->validated = length;
        return true;
    }
    if (!final && resource.error == simdutf::error_code::TOO_SHORT &&
        conn->validated + resource.count + 4 > length) {
        const size_t at = conn->validated + resource.count;
        if (!utf8_prefix_may_still_be_valid(reinterpret_cast<const unsigned char *>(bytes) + at,
                                            length - at))
            return false;
        conn->validated = at;
        return true;
    }
    return false;
}

// RFC 6455 5.4: the message under construction is released.
void message_drop(WsConn *conn)
{
    if (!conn->msg_live)
        return;
    mrb_gc_unregister(conn->res->mrb, conn->message);
    conn->message = mrb_nil_value();
    conn->msg_live = false;
    conn->msg_op = 0;
    conn->msg_deflated = false;
    conn->validated = 0;
}

// RFC 6455 7.1.5: on_close, once, however the connection ended.
void close_report_to_resource(WsConn *conn, ws::Close close)
{
    const uint16_t code = close.code;
    const char *const reason = close.reason.data();
    const size_t reason_len = close.reason.size();
    if (conn->closed_reported || !conn->res->have_close)
        return;
    conn->closed_reported = true;
    mrb_state *mrb = conn->res->mrb;
    const int arena = mrb_gc_arena_save(mrb);
    mrb_value argv[2];
    argv[0] = mrb_fixnum_value(code);
    argv[1] = mrb_str_new(mrb, reason == nullptr ? "" : reason, reason_len);
    mrb_funcall_argv(mrb, conn->self, MRB_SYM(on_close), 2, argv);
    if (mrb->exc != nullptr) {
        report_raise(conn->elog, mrb, 0);
    }
    mrb_gc_arena_restore(mrb, arena);
}

// RFC 6455 5.5.1: this side found something wrong - close with the code.
bool connection_fail(WsConn *conn, std::string &sink, uint16_t code)
{
    close_frame_emit(conn, sink, {code, {}});
    close_report_to_resource(conn, {code, {}});
    message_drop(conn);
    return false;
}

// RFC 6455 5.6: a complete message to the resource, and act on the answer.
bool message_deliver(WsConn *conn, std::string &sink)
{
    const WsResource *resource = conn->res;
    mrb_state *mrb = resource->mrb;
    const bool binary = conn->msg_op == ws::kBinary;
    const int arena = mrb_gc_arena_save(mrb);
    mrb_value argv[2];
    argv[0] = conn->message;
    argv[1] = mrb_bool_value(binary);
    const mrb_value answer = mrb_funcall_argv(mrb, conn->self, MRB_SYM(on_data), 2, argv);
    message_drop(conn);
    if (mrb->exc != nullptr) {
        report_raise(conn->elog, mrb, 0);
        mrb_gc_arena_restore(mrb, arena);
        return connection_fail(conn, sink, ws::kCloseInternalError);
    }
    if (mrb_string_p(answer)) {
        data_frame_emit(conn, sink, {binary ? ws::kBinary : ws::kText, ruby_string_bytes(answer)});
    } else if (mrb_symbol_p(answer)) {
        uint16_t code = 0;
        if (close_code_of_symbol(mrb_symbol(answer), code)) {
            close_frame_emit(conn, sink, {code, {}});
            close_report_to_resource(conn, {code, {}});
        } else {
            std::fprintf(stderr,
                         "webmachine: on_data returned :%s, which is not a close this endpoint "
                         "can speak (RFC 6455 7.4.1). Say a String, nil, or one of :close "
                         ":going_away :protocol_error :unsupported :invalid :policy :too_big "
                         ":internal_error\n",
                         mrb_sym_name(mrb, mrb_symbol(answer)));
            mrb_gc_arena_restore(mrb, arena);
            return connection_fail(conn, sink, ws::kCloseInternalError);
        }
    } else if (!mrb_nil_p(answer)) {
        std::fprintf(stderr,
                     "webmachine: on_data returned a %s - a websocket answer is a String (a "
                     "message), a Symbol (a close by name) or nil (nothing said)\n",
                     mrb_obj_classname(mrb, answer));
        mrb_gc_arena_restore(mrb, arena);
        return connection_fail(conn, sink, ws::kCloseInternalError);
    }
    mrb_gc_arena_restore(mrb, arena);
    return true;
}

// RFC 6455 5.5/5.6: a frame whose payload is now complete.
bool frame_finish(WsConn *conn, std::string &sink)
{
    switch (conn->opcode) {
        case ws::kPing:
            if (!conn->sent_close)
                frame_emit(sink, {ws::kPong, {conn->ctl, conn->ctl_len}});
            return true;
        case ws::kPong:
            return true;
        case ws::kClose: {
            ws::Close close;
            if (!ws::close_read({conn->ctl, conn->ctl_len}, close)) {
                return connection_fail(conn, sink, ws::kCloseProtocolError);
            }
            const char *const reason = close.reason.data();
            const size_t rlen = close.reason.size();
            const uint16_t code = close.code;
            if (rlen != 0 && !simdutf::validate_utf8(reason, rlen)) {
                return connection_fail(conn, sink, ws::kCloseInvalidPayload);
            }
            conn->got_close = true;
            const uint16_t say = code == 1005 ? ws::kCloseNormal : code;
            close_frame_emit(conn, sink, {say, close.reason});
            close_report_to_resource(conn, {code, close.reason});
            message_drop(conn);
            return false;
        }
        default:
            break;
    }
    if (!conn->is_final)
        return true;
    if (conn->msg_deflated) {
        const int status = conn->codec->inflate_finish(message_append_inflated, conn);
        if (status != 0) {
            return connection_fail(conn, sink,
                                   status == -2 ? ws::kCloseTooBig : ws::kCloseProtocolError);
        }
    }
    if (conn->msg_op == ws::kText && !message_utf8_is_valid(conn, true)) {
        return connection_fail(conn, sink, ws::kCloseInvalidPayload);
    }
    if (conn->sent_close) {
        message_drop(conn);
        return true;
    }
    return message_deliver(conn, sink);
}

// RFC 6455 5.2/5.5, RFC 7692 6: everything the header must satisfy.
bool frame_begin(WsConn *conn, std::string &sink)
{
    // RFC 6455 5.2 / 5.4: the header is read and judged first, whole. It used
    // to be judged one rule at a time with the refusal written from inside
    // the check that failed.
    const ws::Head header = ws::read_head(conn->hbuf, conn->codec != nullptr);
    if (header.err != ws::Head::Err::kNone)
        return connection_fail(conn, sink, ws::kCloseProtocolError);
    const uint64_t msg_len = conn->msg_op != 0 ? ruby_string_length(conn->message) : 0;
    const ws::Head::Err a =
        ws::admit(header, {conn->msg_op, conn->msg_deflated, msg_len, conn->res->max_message});
    if (a != ws::Head::Err::kNone) {
        return connection_fail(
            conn, sink, a == ws::Head::Err::kTooBig ? ws::kCloseTooBig : ws::kCloseProtocolError);
    }

    std::memcpy(conn->mask, conn->hbuf + header.masking_key_at, 4);
    conn->mask_off = 0;
    conn->opcode = header.opcode;
    conn->is_final = header.fin;
    conn->control = header.control;
    conn->remaining = header.payload_length;
    conn->ctl_len = 0;

    // A data frame that starts a message opens the buffer it collects into -
    // the one thing here the VM has to be asked for.
    if (!header.control && header.opcode != ws::kContinuation) {
        mrb_state *mrb = conn->res->mrb;
        const uint64_t max = conn->res->max_message;
        const uint64_t capa = header.payload_length > max ? max : header.payload_length;
        conn->message = mrb_str_new_capa(mrb, static_cast<mrb_int>(capa));
        mrb_gc_register(mrb, conn->message);
        conn->msg_live = true;
        conn->msg_op = header.opcode;
        conn->msg_deflated = header.rsv1;
    }
    conn->in_payload = header.payload_length != 0;
    return true;
}

struct FeedCall {
    WsConn *conn;
    const char *data;
    size_t length;
    std::string *sink;
};

// RFC 6455 5.3: the reader - unmasked straight into the mruby String.
mrb_value feed_in_protected_call(mrb_state *mrb, void *user_data)
{
    FeedCall *facts = static_cast<FeedCall *>(user_data);
    WsConn *conn = facts->conn;
    std::string &sink = *facts->sink;
    const char *bytes = facts->data;
    size_t length = facts->length;
    bool alive = true;

    while (length != 0) {
        if (!conn->in_payload) {
            conn->hneed = ws::header_need(conn->hbuf, conn->hlen);
            while (conn->hlen < conn->hneed && length != 0) {
                conn->hbuf[conn->hlen++] = static_cast<unsigned char>(*bytes++);
                length--;
                conn->hneed = ws::header_need(conn->hbuf, conn->hlen);
            }
            if (conn->hlen < conn->hneed)
                break;
            conn->hlen = 0;
            if (!frame_begin(conn, sink)) {
                alive = false;
                break;
            }
            if (!conn->in_payload) {
                if (!frame_finish(conn, sink)) {
                    alive = false;
                    break;
                }
            }
            continue;
        }

        size_t take = length < conn->remaining ? length : static_cast<size_t>(conn->remaining);
        if (conn->control) {
            ws::unmask_copy(conn->ctl + conn->ctl_len, {bytes, take}, {conn->mask, conn->mask_off});
            conn->ctl_len += take;
        } else {
            char unmasked[512];
            size_t done = 0;
            bool broke = false;
            while (done < take) {
                const size_t chunk =
                    take - done < sizeof(unmasked) ? take - done : sizeof(unmasked);
                ws::unmask_copy(unmasked, {bytes + done, chunk},
                                {conn->mask, conn->mask_off + done});
                if (conn->msg_deflated) {
                    const int status =
                        conn->codec->inflate_some(unmasked, chunk, message_append_inflated, conn);
                    if (status != 0) {
                        alive = connection_fail(
                            conn, sink, status == -2 ? ws::kCloseTooBig : ws::kCloseProtocolError);
                        broke = true;
                        break;
                    }
                } else {
                    mrb_str_cat(mrb, conn->message, unmasked, chunk);
                }
                done += chunk;
            }
            if (broke)
                break;
            if (conn->msg_op == ws::kText && !message_utf8_is_valid(conn, false)) {
                alive = connection_fail(conn, sink, ws::kCloseInvalidPayload);
                break;
            }
        }
        conn->mask_off = static_cast<uint8_t>((conn->mask_off + take) & 3);
        conn->remaining -= take;
        bytes += take;
        length -= take;
        if (conn->remaining == 0) {
            conn->in_payload = false;
            if (!frame_finish(conn, sink)) {
                alive = false;
                break;
            }
            if (conn->got_close)
                break;
        }
    }
    return mrb_bool_value(alive);
}
} // namespace

// RFC 6455: Webmachine::WebsocketResource, the class a route may name.
void ws_init(mrb_state *mrb, struct RClass *webmachine_module)
{
    mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(WebsocketResource),
                              mrb->object_class);
}

// RFC 6455: one route's folded resource.
WsResource *ws_resource_new()
{
    return new WsResource();
}

// RFC 6455: unique_ptr's deleter across the TU boundary.
void ws_resource_free(WsResource *resource)
{
    if (resource == nullptr)
        return;
    delete resource;
}

// RFC 6455: fold a resource class for a websocket route, once, at
// route.websocket - arities read, konst answers asked, the class frozen.
void ws_fold(mrb_state *mrb, mrb_value klass, WsResource &answer)
{
    if (!mrb_class_p(klass)) {
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "route.websocket wants a class inheriting Webmachine::WebsocketResource, not %v",
                   klass);
    }
    struct RClass *webmachine_module = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
    struct RClass *base =
        mrb_class_get_under_id(mrb, webmachine_module, MRB_SYM(WebsocketResource));
    bool ok = false;
    for (struct RClass *k = mrb_class_ptr(klass)->super; k != nullptr; k = k->super) {
        if (k == base) {
            ok = true;
            break;
        }
    }
    if (!ok) {
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "route.websocket: %v does not inherit Webmachine::WebsocketResource - a "
                   "websocket resource is not a Webmachine::Resource: no response, no status, no "
                   "flow survives the upgrade, only the handshake's head",
                   klass);
    }
    answer.mrb = mrb;
    answer.klass = mrb_class_ptr(klass);

    if (!method_is_defined(mrb, {answer.klass, MRB_SYM(on_data)})) {
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
                  "route.websocket: the resource defines no on_data - that is the one method a "
                  "websocket resource is (on_data(data, binary))");
    }
    answer.have_close = method_is_defined(mrb, {answer.klass, MRB_SYM(on_close)});

    {
        struct RClass *meta = mrb_class(mrb, klass);
        mrb_method_t method = mrb_method_search_vm(mrb, &meta, MRB_SYM_Q(validate_text));
        if (!MRB_METHOD_UNDEF_P(method)) {
            const mrb_value value =
                mrb_funcall_argv(mrb, klass, MRB_SYM_Q(validate_text), 0, nullptr);
            if (mrb->exc != nullptr)
                rethrow(mrb);
            answer.validate_text = mrb_test(value);
        }
    }

    {
        struct RClass *meta = mrb_class(mrb, klass);
        mrb_method_t method = mrb_method_search_vm(mrb, &meta, MRB_SYM_Q(permessage_deflate));
        if (!MRB_METHOD_UNDEF_P(method)) {
            const mrb_value value =
                mrb_funcall_argv(mrb, klass, MRB_SYM_Q(permessage_deflate), 0, nullptr);
            if (mrb->exc != nullptr)
                rethrow(mrb);
            answer.want_deflate = mrb_test(value);
        }
    }

    {
        struct RClass *meta = mrb_class(mrb, klass);
        mrb_method_t method = mrb_method_search_vm(mrb, &meta, MRB_SYM(max_message));
        if (!MRB_METHOD_UNDEF_P(method)) {
            const mrb_value value = mrb_funcall_argv(mrb, klass, MRB_SYM(max_message), 0, nullptr);
            if (mrb->exc != nullptr)
                rethrow(mrb);
            if (!mrb_fixnum_p(value) || mrb_fixnum(value) <= 0) {
                mrb_raisef(
                    mrb, E_WM_ROUTE_ERROR(mrb),
                    "route.websocket: max_message answers with a positive Integer of bytes, or "
                    "it is not defined at all (the default is %i) - not %v",
                    static_cast<mrb_int>(kMaxWsMessageDefault), value);
            }
            answer.max_message = static_cast<size_t>(mrb_fixnum(value));
        }
    }

    mrb_obj_freeze(mrb, klass);
}

// RFC 6455 4.2.2: build this peer's resource; its initialize is the
// connect hook and its return value is the answer.
WsConn *ws_admit(const WsResource *resource, Logger *elog, WsAdmit answered)
{
    std::string &proto = answered.proto;
    uint16_t &status = answered.status;
    proto.clear();
    status = 0;
    mrb_state *mrb = resource->mrb;
    const int arena = mrb_gc_arena_save(mrb);
    const mrb_value obj =
        mrb_obj_value(mrb_obj_alloc(mrb, MRB_INSTANCE_TT(resource->klass), resource->klass));
    mrb_gc_register(mrb, obj);
    const mrb_value answer = mrb_funcall_argv(mrb, obj, MRB_SYM(initialize), 0, nullptr);
    if (mrb->exc != nullptr) {
        report_raise(elog, mrb, 500);
        mrb_gc_unregister(mrb, obj);
        mrb_gc_arena_restore(mrb, arena);
        status = 500;
        return nullptr;
    }
    bool admit = true;
    if (mrb_string_p(answer)) {
        // RFC 6455 4.2.2: the answer names one subprotocol, and a subprotocol
        // is one token. Anything else this String holds would write a field
        // value of the server's own making - or a second field.
        if (!ruby_string_is_field_name(answer)) {
            mrb_gc_unregister(mrb, obj);
            mrb_gc_arena_restore(mrb, arena);
            status = 500;
            return nullptr;
        }
        proto.assign(ruby_string_bytes(answer));
    } else if (mrb_symbol_p(answer)) {
        const mrb_sym symbol = mrb_symbol(answer);
        if (symbol == MRB_SYM(forbidden))
            status = 403;
        else if (symbol == MRB_SYM(not_found))
            status = 404;
        else if (symbol == MRB_SYM(bad_request))
            status = 400;
        else
            status = 403;
        admit = false;
    }
    if (!admit) {
        mrb_gc_unregister(mrb, obj);
        mrb_gc_arena_restore(mrb, arena);
        return nullptr;
    }
    mrb_gc_arena_restore(mrb, arena);
    WsConn *conn = new WsConn();
    conn->res = resource;
    conn->elog = elog;
    conn->self = obj;
    return conn;
}

// RFC 6455 7.1.1: the idle time ran out, so this end starts the close
// handshake with 1001 - going away - and the socket follows the frame.
bool ws_going_away(WsConn *conn, std::string &sink)
{
    if (conn == nullptr || conn->sent_close)
        return false;
    const size_t was = sink.size();
    close_frame_emit(conn, sink, {1001, {}});
    return sink.size() != was;
}

// RFC 7692: does this route accept the extension at all?
bool ws_wants_deflate(const WsResource *resource)
{
    return resource->want_deflate;
}

// RFC 7692: settle what the handshake negotiated; the codec is lazy.
void ws_open(WsConn *conn, const wsdeflate::Params &deflate)
{
    if (deflate.on) {
        conn->codec = new wsdeflate::Codec();
        conn->codec->configure(deflate);
    }
}

// RFC 6455 7.4.1: 1006 where no close frame was ever seen.
void ws_free(WsConn *conn)
{
    if (conn == nullptr)
        return;
    close_report_to_resource(conn, {1006, {}});
    message_drop(conn);
    if (conn->res != nullptr && conn->res->mrb != nullptr && !mrb_nil_p(conn->self)) {
        mrb_gc_unregister(conn->res->mrb, conn->self);
        conn->self = mrb_nil_value();
    }
    delete conn->codec;
    delete conn;
}

// RFC 6455 5.3: wire bytes for an upgraded connection, under protection.
bool ws_feed(WsConn *conn, std::string_view incoming, std::string &sink)
{
    const char *const data = incoming.data();
    const size_t length = incoming.size();
    if (length == 0)
        return true;
    mrb_state *mrb = conn->res->mrb;
    FeedCall call{conn, data, length, &sink};
    mrb_bool raised = FALSE;
    const mrb_value resource = mrb_protect_error(mrb, feed_in_protected_call, &call, &raised);
    if (raised) {
        // Only an exception object may be stored in mrb->exc; mrb_obj_ptr on
        // an immediate (Integer, Symbol, nil) would read its bits as a
        // pointer. Same check as resource.cpp's take_pending.
        if (mrb_exception_p(resource))
            mrb->exc = mrb_obj_ptr(resource);
        else
            mrb->exc = mrb_obj_ptr(mrb_exc_new_lit(mrb, E_WM_ERROR(mrb),
                                                   "the websocket handler ended without an "
                                                   "exception object"));
        report_raise(conn->elog, mrb, 0);
        return connection_fail(conn, sink, ws::kCloseInternalError);
    }
    return mrb_test(resource);
}
} // namespace webmachine
