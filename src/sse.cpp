#include "webmachine.hpp"

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

namespace webmachine {

// The route's own answers, folded once. No Ruby object lives here -
// the STREAM holds it, because a stream is a session (#181).
struct SseResource {
  mrb_state* mrb = nullptr;
  struct RClass* klass = nullptr;
  bool have_close = false;
  // 0 = never. Seconds, read through mruby-chrono at fold like every
  // other duration that crosses this boundary.
  int64_t heartbeat = 15;
};

// One open stream.
struct SseStream {
  const SseResource* res = nullptr;
  // Where a raising callback lands, or null if no error log was asked
  // for. Held for the stream's life: on_tick runs once a second long
  // after the request that opened it is gone.
  Logger* elog = nullptr;
  mrb_value self = mrb_nil_value();
  // The wall second this stream last put BYTES on the wire, event or
  // heartbeat alike - the heartbeat measures silence, not events.
  int64_t last_out_s = 0;
  int64_t last_tick_s = 0;
};

namespace {

// One `field: value` line, and the spec's rule that a value with
// newlines in it is several lines of the same field (a data: block is
// rejoined with "\n" by the client).
void field(std::string& out, const char* name, size_t nlen, const char* v, size_t vlen) {
  size_t i = 0;
  do {
    const char* nl = static_cast<const char*>(std::memchr(v + i, '\n', vlen - i));
    const size_t end = nl != nullptr ? size_t(nl - v) : vlen;
    out.append(name, nlen).append(": ", 2);
    // A trailing CR belongs to the line break, not to the value: a
    // Ruby String that came off a CRLF wire must not put a stray CR
    // into the field.
    size_t stop = end;
    if (stop > i && v[stop - 1] == '\r') stop--;
    out.append(v + i, stop - i).append("\n", 1);
    i = end + 1;
  } while (i <= vlen && i != 0 && i - 1 < vlen);
}

void field(std::string& out, const char* name, const mrb_value& v) {
  if (!mrb_string_p(v)) return;
  field(out, name, std::strlen(name), RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
}

// One event out of what on_tick returned. False = the value is not
// something this layer can spell, and the caller ends the stream.
bool spell_event(mrb_state* mrb, const mrb_value& v, std::string& out) {
  if (mrb_string_p(v)) {
    field(out, "data", 4, RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
    out.append("\n", 1);
    return true;
  }
  if (!mrb_hash_p(v)) return false;
  // The fields by name, in the order the spec lists them - `id` and
  // `retry` are the client's own bookkeeping, `event` names the
  // listener, `data` is the payload.
  const mrb_value ev = mrb_hash_get(mrb, v, mrb_symbol_value(MRB_SYM(event)));
  const mrb_value id = mrb_hash_get(mrb, v, mrb_symbol_value(MRB_SYM(id)));
  const mrb_value rt = mrb_hash_get(mrb, v, mrb_symbol_value(MRB_SYM(retry)));
  const mrb_value da = mrb_hash_get(mrb, v, mrb_symbol_value(MRB_SYM(data)));
  field(out, "event", ev);
  field(out, "id", id);
  if (mrb_fixnum_p(rt)) {
    char buf[24];
    const int n = std::snprintf(buf, sizeof buf, "%lld",
                                static_cast<long long>(mrb_fixnum(rt)));
    if (n > 0) field(out, "retry", 5, buf, static_cast<size_t>(n));
  }
  if (mrb_array_p(da)) {
    const mrb_int n = RARRAY_LEN(da);
    for (mrb_int i = 0; i < n; i++) field(out, "data", mrb_ary_entry(da, i));
  } else {
    field(out, "data", da);
  }
  out.append("\n", 1);
  return true;
}

// RFC 9112 7.1: one chunk, size in hex, CRLF around the data. Every
// second that says something is exactly one chunk - the stream's
// framing and the stream's rhythm are the same thing.
void chunk(std::string& sink, const std::string& body) {
  if (body.empty()) return;
  char hdr[24];
  const int n = std::snprintf(hdr, sizeof hdr, "%zx\r\n", body.size());
  sink.append(hdr, static_cast<size_t>(n));
  sink.append(body);
  sink.append("\r\n", 2);
}

void report_close(SseStream* s) {
  if (!s->res->have_close) return;
  mrb_state* mrb = s->res->mrb;
  const int ai = mrb_gc_arena_save(mrb);
  mrb_funcall_argv(mrb, s->self, MRB_SYM(on_close), 0, nullptr);
  if (mrb->exc != nullptr) {
    // The stream is already over; a raising close handler is logged
    // and swallowed, exactly as the websocket one is.
    if (s->elog != nullptr) log_exception(*s->elog, mrb, nullptr, 0, nullptr, 0, 0);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
  }
  mrb_gc_arena_restore(mrb, ai);
}

}  // namespace

void sse_init(mrb_state* mrb, struct RClass* wm) {
  // Object, not Resource: an event stream has no flow, no conneg and
  // no precondition (see the header). The class exists so route.sse
  // can name what it wants and refuse everything else.
  mrb_define_class_under_id(mrb, wm, MRB_SYM(SseResource), mrb->object_class);
}

SseResource* sse_resource_new() { return new SseResource(); }

void sse_resource_free(SseResource* r) { delete r; }

bool sse_fold(mrb_state* mrb, mrb_value klass, SseResource& out, char* err, size_t errlen) {
  if (!mrb_class_p(klass)) {
    std::snprintf(err, errlen, "route.sse wants a class inheriting Webmachine::SseResource");
    return false;
  }
  struct RClass* wm = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
  struct RClass* base = mrb_class_get_under_id(mrb, wm, MRB_SYM(SseResource));
  bool ok = false;
  for (struct RClass* k = mrb_class_ptr(klass)->super; k != nullptr; k = k->super) {
    if (k == base) {
      ok = true;
      break;
    }
  }
  if (!ok) {
    std::snprintf(err, errlen,
                  "route.sse: the class does not inherit Webmachine::SseResource - an event "
                  "stream is NOT a Webmachine::Resource: no status to negotiate, no "
                  "representation to compare, no end to declare");
    return false;
  }
  out.mrb = mrb;
  out.klass = mrb_class_ptr(klass);

  {
    struct RClass* owner = out.klass;
    if (MRB_METHOD_UNDEF_P(mrb_method_search_vm(mrb, &owner, MRB_SYM(on_tick)))) {
      std::snprintf(err, errlen,
                    "route.sse: the resource defines no on_tick - that is the one method an "
                    "SSE resource IS, asked once a second for what it has to say");
      return false;
    }
  }
  {
    struct RClass* owner = out.klass;
    out.have_close = !MRB_METHOD_UNDEF_P(mrb_method_search_vm(mrb, &owner, MRB_SYM(on_close)));
  }

  // The heartbeat, as a DURATION: mruby-chrono owns every one of them
  // that crosses this boundary, so `15.s`, `30` and `2.5` are all the
  // same question asked once at fold.
  {
    struct RClass* meta = mrb_class(mrb, klass);
    if (!MRB_METHOD_UNDEF_P(mrb_method_search_vm(mrb, &meta, MRB_SYM(heartbeat)))) {
      const mrb_value v = mrb_funcall_argv(mrb, klass, MRB_SYM(heartbeat), 0, nullptr);
      if (mrb->exc != nullptr) {
        std::snprintf(err, errlen, "route.sse: heartbeat raised (exception below)");
        mrb_print_error(mrb);
        mrb->exc = nullptr;
        return false;
      }
      const auto secs = mrb_chrono::ceil<std::chrono::seconds>(mrb, v);
      if (secs.count() < 0 || secs.count() > 86400) {
        std::snprintf(err, errlen,
                      "route.sse: heartbeat is a duration from 0 (never) to a day - 15.s is "
                      "the default");
        return false;
      }
      out.heartbeat = static_cast<int64_t>(secs.count());
    }
  }

  // Frozen like every routed class: nothing may be redefined behind an
  // open stream.
  mrb_obj_freeze(mrb, klass);
  return true;
}

SseStream* sse_open(const SseResource* r, Logger* elog, uint16_t& status) {
  status = 0;
  mrb_state* mrb = r->mrb;
  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value obj =
      mrb_obj_value(mrb_obj_alloc(mrb, MRB_INSTANCE_TT(r->klass), r->klass));
  mrb_gc_register(mrb, obj);
  // Allocated and initialized in two steps, like ws_admit and for the
  // same reason: `new` swallows what initialize answered, and the
  // answer IS the decision.
  const mrb_value out = mrb_funcall_argv(mrb, obj, MRB_SYM(initialize), 0, nullptr);
  if (mrb->exc != nullptr) {
    if (elog != nullptr) log_exception(*elog, mrb, nullptr, 0, nullptr, 0, 500);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_unregister(mrb, obj);
    mrb_gc_arena_restore(mrb, ai);
    status = 500;
    return nullptr;
  }
  if (mrb_symbol_p(out)) {
    // The resource refused and named the status - the same three
    // words ws_admit takes, because it is the same decision: this
    // peer does not get the stream, and gets an HTTP answer instead.
    const mrb_sym w = mrb_symbol(out);
    if (w == MRB_SYM(not_found)) status = 404;
    else if (w == MRB_SYM(bad_request)) status = 400;
    else status = 403;
    mrb_gc_unregister(mrb, obj);
    mrb_gc_arena_restore(mrb, ai);
    return nullptr;
  }
  auto* s = new SseStream();
  s->res = r;
  s->elog = elog;
  s->self = obj;
  mrb_gc_arena_restore(mrb, ai);
  return s;
}

bool sse_second(SseStream* s, int64_t now_s, std::string& sink) {
  const SseResource* r = s->res;
  mrb_state* mrb = r->mrb;
  if (s->last_tick_s == now_s) return true;  // one call per second, never two
  s->last_tick_s = now_s;

  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value out = mrb_funcall_argv(mrb, s->self, MRB_SYM(on_tick), 0, nullptr);
  if (mrb->exc != nullptr) {
    if (s->elog != nullptr) log_exception(*s->elog, mrb, nullptr, 0, nullptr, 0, 0);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }

  bool go_on = true;
  std::string body;
  if (mrb_symbol_p(out)) {
    // :close is the only word here; anything else is a typo the app
    // should hear about rather than a message to guess at.
    if (mrb_symbol(out) != MRB_SYM(close)) {
      std::fprintf(stderr, "webmachine: SSE on_tick answered :%s - only :close is a word here\n",
                   mrb_sym_name(mrb, mrb_symbol(out)));
    }
    go_on = false;
  } else if (mrb_array_p(out)) {
    const mrb_int n = RARRAY_LEN(out);
    for (mrb_int i = 0; i < n && go_on; i++) {
      if (!spell_event(mrb, mrb_ary_entry(out, i), body)) {
        std::fprintf(stderr, "webmachine: SSE on_tick answered an Array holding something "
                             "that is neither a String nor a Hash\n");
        go_on = false;
      }
    }
  } else if (!mrb_nil_p(out) && !mrb_false_p(out)) {
    if (!spell_event(mrb, out, body)) {
      std::fprintf(stderr, "webmachine: SSE on_tick answered %s - a String, a Hash, an Array "
                           "of those, nil or :close\n",
                   mrb_obj_classname(mrb, out));
      go_on = false;
    }
  }
  mrb_gc_arena_restore(mrb, ai);

  if (!body.empty()) {
    chunk(sink, body);
    s->last_out_s = now_s;
  } else if (go_on && r->heartbeat != 0 && now_s - s->last_out_s >= r->heartbeat) {
    // A bare comment, which the spec defines as ignorable: it exists
    // for the proxies in between, which cannot tell a quiet stream
    // from a dead one.
    chunk(sink, ":\n\n");
    s->last_out_s = now_s;
  }
  if (!go_on) {
    // The terminal chunk: the stream ends as a well-formed message,
    // not as a dropped socket.
    sink.append("0\r\n\r\n", 5);
  }
  return go_on;
}

void sse_free(SseStream* s) {
  if (s == nullptr) return;
  report_close(s);
  mrb_gc_unregister(s->res->mrb, s->self);
  delete s;
}

}  // namespace webmachine
