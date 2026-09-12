#include "http1.hpp"
#include "ruby_value.hpp"

#include <mruby/array.h>
#include <mruby/chrono.hpp>
#include <mruby/class.h>
#include <mruby/hash.h>
#include <mruby/proc.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <chrono>
#include <cstdio>
#include <cstring>

namespace webmachine
{
struct SseResource {
    mrb_state *mrb = nullptr;
    struct RClass *klass = nullptr;
    bool have_close = false;
    int64_t heartbeat = 15;
};

struct SseStream {
    const SseResource *resource = nullptr;
    Logger *elog = nullptr;
    mrb_value self = mrb_nil_value();
    int64_t last_out_s = 0;
    int64_t last_tick_s = 0;
};

namespace
{
// WHATWG HTML: one "field: value" line; a value with newlines is
// several lines of the same field.
void field(std::string &out_text, http::Field field_to_write)
{
    const char *const name = field_to_write.name.data();
    const size_t nlen = field_to_write.name.size();
    const char *const value = field_to_write.value.data();
    const size_t vlen = field_to_write.value.size();
    // WHATWG HTML: a line of an event stream ends at CR, at LF, or at CR
    // LF, and all three are this field's end. The split looked for LF
    // alone, so a bare CR stayed inside the value and the client read it
    // as a line of its own - an `id:` or an `event:` spelled by whatever
    // string the application relayed.
    size_t i = 0;
    for (;;) {
        size_t line_end = i;
        while (line_end < vlen && value[line_end] != '\n' && value[line_end] != '\r')
            line_end++;
        out_text.append(name, nlen).append(": ", 2).append(value + i, line_end - i).append("\n", 1);
        if (line_end >= vlen)
            break;
        i = line_end + 1;
        if (value[line_end] == '\r' && i < vlen && value[i] == '\n')
            i++;
    }
}

// WHATWG HTML: the same line, from a Ruby value.
void field(std::string &out_text, const char *name, const mrb_value &value)
{
    if (!mrb_string_p(value))
        return;
    field(out_text, {name, ruby_string_bytes(value)});
}

// WHATWG HTML: one event out of what on_tick returned.
bool event_spell(mrb_state *mrb, const mrb_value &event, std::string &out_text)
{
    if (mrb_string_p(event)) {
        field(out_text, {"data", ruby_string_bytes(event)});
        out_text.append("\n", 1);
        return true;
    }
    if (!mrb_hash_p(event))
        return false;
    const mrb_value event_field = mrb_hash_get(mrb, event, mrb_symbol_value(MRB_SYM(event)));
    const mrb_value id_field = mrb_hash_get(mrb, event, mrb_symbol_value(MRB_SYM(id)));
    const mrb_value retry_field = mrb_hash_get(mrb, event, mrb_symbol_value(MRB_SYM(retry)));
    const mrb_value data_field = mrb_hash_get(mrb, event, mrb_symbol_value(MRB_SYM(data)));
    field(out_text, "event", event_field);
    field(out_text, "id", id_field);
    if (mrb_fixnum_p(retry_field)) {
        char digits[24];
        const int spelled = std::snprintf(digits, sizeof digits, "%lld",
                                          static_cast<long long>(mrb_fixnum(retry_field)));
        if (spelled > 0)
            field(out_text, {"retry", {digits, static_cast<size_t>(spelled)}});
    }
    if (mrb_array_p(data_field)) {
        const size_t count = ruby_array_length(data_field);
        for (size_t i = 0; i < count; i++)
            field(out_text, "data", mrb_ary_entry(data_field, i));
    } else {
        field(out_text, "data", data_field);
    }
    out_text.append("\n", 1);
    return true;
}

// RFC 9112 7.1: one chunk - size in hex, CRLF around the data.
void chunk_wrap(std::string &sink, const std::string &body)
{
    if (body.empty())
        return;
    char size_line[24];
    const int spelled = std::snprintf(size_line, sizeof size_line, "%zx\r\n", body.size());
    sink.append(size_line, static_cast<size_t>(spelled));
    sink.append(body);
    sink.append("\r\n", 2);
}

// WHATWG HTML: on_close, once, however the stream ended.
void stream_report_close(SseStream *stream)
{
    if (!stream->resource->have_close)
        return;
    mrb_state *mrb = stream->resource->mrb;
    const int arena = mrb_gc_arena_save(mrb);
    mrb_funcall_argv(mrb, stream->self, MRB_SYM(on_close), 0, nullptr);
    if (mrb->exc != nullptr) {
        report_raise(stream->elog, mrb, 0);
    }
    mrb_gc_arena_restore(mrb, arena);
}
} // namespace

// WHATWG HTML: Webmachine::SseResource, the class a route may name.
void sse_init(mrb_state *mrb, struct RClass *webmachine_module)
{
    mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(SseResource), mrb->object_class);
}

// WHATWG HTML: one route's folded resource.
SseResource *sse_resource_new()
{
    return new SseResource();
}

// WHATWG HTML: unique_ptr's deleter across the TU boundary.
void sse_resource_free(SseResource *resource)
{
    delete resource;
}

// WHATWG HTML: fold a resource class for an SSE route, once, at route.sse.
void sse_fold(mrb_state *mrb, mrb_value klass, SseResource &out_resource)
{
    if (!mrb_class_p(klass)) {
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "route.sse wants a class inheriting Webmachine::SseResource, not %v", klass);
    }
    struct RClass *webmachine_module = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
    struct RClass *base = mrb_class_get_under_id(mrb, webmachine_module, MRB_SYM(SseResource));
    bool defined = false;
    for (struct RClass *k = mrb_class_ptr(klass)->super; k != nullptr; k = k->super) {
        if (k == base) {
            defined = true;
            break;
        }
    }
    if (!defined) {
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "route.sse: %v does not inherit Webmachine::SseResource - an event stream is "
                   "not a Webmachine::Resource: no status to negotiate, no representation to "
                   "compare, no end to declare",
                   klass);
    }
    out_resource.mrb = mrb;
    out_resource.klass = mrb_class_ptr(klass);

    {
        struct RClass *owner = out_resource.klass;
        if (MRB_METHOD_UNDEF_P(mrb_method_search_vm(mrb, &owner, MRB_SYM(on_tick)))) {
            mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
                      "route.sse: the resource defines no on_tick - that is the one method an SSE "
                      "resource is, asked once a second for what it has to say");
        }
    }
    {
        struct RClass *owner = out_resource.klass;
        out_resource.have_close =
            !MRB_METHOD_UNDEF_P(mrb_method_search_vm(mrb, &owner, MRB_SYM(on_close)));
    }

    {
        struct RClass *meta = mrb_class(mrb, klass);
        if (!MRB_METHOD_UNDEF_P(mrb_method_search_vm(mrb, &meta, MRB_SYM(heartbeat)))) {
            const mrb_value answer = mrb_funcall_argv(mrb, klass, MRB_SYM(heartbeat), 0, nullptr);
            if (mrb->exc != nullptr)
                rethrow(mrb);
            const auto secs = mrb_chrono::ceil<std::chrono::seconds>(mrb, answer);
            if (secs.count() < 0 || secs.count() > 86400) {
                mrb_raisef(
                    mrb, E_WM_ROUTE_ERROR(mrb),
                    "route.sse: heartbeat is a duration from 0 (never) to a day - 15.s is the "
                    "default, %v is not in range",
                    answer);
            }
            out_resource.heartbeat = static_cast<int64_t>(secs.count());
        }
    }

    mrb_obj_freeze(mrb, klass);
}

// WHATWG HTML: build this stream's resource; its initialize is the open hook.
SseStream *sse_open(const SseResource *resource, Logger *logger, uint16_t &code)
{
    uint16_t &status = code;
    status = 0;
    mrb_state *mrb = resource->mrb;
    const int arena = mrb_gc_arena_save(mrb);
    const mrb_value instance =
        mrb_obj_value(mrb_obj_alloc(mrb, MRB_INSTANCE_TT(resource->klass), resource->klass));
    mrb_gc_register(mrb, instance);
    const mrb_value answer = mrb_funcall_argv(mrb, instance, MRB_SYM(initialize), 0, nullptr);
    if (mrb->exc != nullptr) {
        report_raise(logger, mrb, 500);
        mrb_gc_unregister(mrb, instance);
        mrb_gc_arena_restore(mrb, arena);
        status = 500;
        return nullptr;
    }
    if (mrb_symbol_p(answer)) {
        const mrb_sym which = mrb_symbol(answer);
        if (which == MRB_SYM(not_found))
            status = 404;
        else if (which == MRB_SYM(bad_request))
            status = 400;
        else
            status = 403;
        mrb_gc_unregister(mrb, instance);
        mrb_gc_arena_restore(mrb, arena);
        return nullptr;
    }
    auto *stream = new SseStream();
    stream->resource = resource;
    stream->elog = logger;
    stream->self = instance;
    mrb_gc_arena_restore(mrb, arena);
    return stream;
}

// WHATWG HTML: one second has passed - ask the resource, and hand back
// what it said as the event-stream bytes themselves.
//
// The framing is not here, because the two protocols frame it
// differently: h1 wraps each tick in a chunk (RFC 9112 7.1) and h2 puts
// the same bytes in DATA frames against the stream window (RFC 9113
// 6.1). What the resource said is the same either way.
bool sse_tick(SseStream *stream, int64_t now_s, std::string &body)
{
    const SseResource *resource = stream->resource;
    mrb_state *mrb = resource->mrb;
    if (stream->last_tick_s == now_s)
        return true;
    stream->last_tick_s = now_s;

    const int arena = mrb_gc_arena_save(mrb);
    const mrb_value answer = mrb_funcall_argv(mrb, stream->self, MRB_SYM(on_tick), 0, nullptr);
    if (mrb->exc != nullptr) {
        report_raise(stream->elog, mrb, 0);
        mrb_gc_arena_restore(mrb, arena);
        return false;
    }

    bool go_on = true;
    if (mrb_symbol_p(answer)) {
        if (mrb_symbol(answer) != MRB_SYM(close)) {
            std::fprintf(stderr,
                         "webmachine: SSE on_tick answered :%s - only :close is a word here\n",
                         mrb_sym_name(mrb, mrb_symbol(answer)));
        }
        go_on = false;
    } else if (mrb_array_p(answer)) {
        const size_t count = ruby_array_length(answer);
        for (size_t i = 0; i < count && go_on; i++) {
            if (!event_spell(mrb, mrb_ary_entry(answer, i), body)) {
                std::fprintf(stderr, "webmachine: SSE on_tick answered an Array holding something "
                                     "that is neither a String nor a Hash\n");
                go_on = false;
            }
        }
    } else if (!mrb_nil_p(answer) && !mrb_false_p(answer)) {
        if (!event_spell(mrb, answer, body)) {
            std::fprintf(stderr,
                         "webmachine: SSE on_tick answered %s - a String, a Hash, an Array "
                         "of those, nil or :close\n",
                         mrb_obj_classname(mrb, answer));
            go_on = false;
        }
    }
    mrb_gc_arena_restore(mrb, arena);

    if (!body.empty()) {
        stream->last_out_s = now_s;
    } else if (go_on && resource->heartbeat != 0 &&
               now_s - stream->last_out_s >= resource->heartbeat) {
        // WHATWG HTML: a comment line, so a proxy in the middle sees traffic.
        body.assign(":\n\n");
        stream->last_out_s = now_s;
    }
    return go_on;
}

// RFC 9112 7.1: h1's framing of one tick - a chunk, and a last chunk when
// the stream ends.
bool sse_second(SseStream *stream, int64_t now_s, std::string &sink)
{
    std::string body;
    const bool go_on = sse_tick(stream, now_s, body);
    chunk_wrap(sink, body);
    if (!go_on)
        sink.append("0\r\n\r\n", 5);
    return go_on;
}

// WHATWG HTML: the stream ends; the resource hears about it once.
void sse_free(SseStream *stream)
{
    if (stream == nullptr)
        return;
    stream_report_close(stream);
    mrb_gc_unregister(stream->resource->mrb, stream->self);
    delete stream;
}
} // namespace webmachine
