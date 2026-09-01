// Design decisions live in .DESIGN.md, filed under what each comment names.
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
struct SseResource {
  mrb_state* mrb = nullptr;
  struct RClass* klass = nullptr;
  bool have_close = false;
  int64_t heartbeat = 15;
};

struct SseStream {
  const SseResource* res = nullptr;
  Logger* elog = nullptr;
  mrb_value self = mrb_nil_value();
  int64_t last_out_s = 0;
  int64_t last_tick_s = 0;
};

namespace {
// WHATWG HTML: one "field: value" line; a value with newlines is
// several lines of the same field.
void field(std::string& out, http::Field f) {
  const char* const name = f.name.data();
  const size_t nlen = f.name.size();
  const char* const v = f.value.data();
  const size_t vlen = f.value.size();
  size_t i = 0;
  do {
    const char* nl = static_cast<const char*>(std::memchr(v + i, '\n', vlen - i));
    const size_t end = nl != nullptr ? size_t(nl - v) : vlen;
    out.append(name, nlen).append(": ", 2);
    size_t stop = end;
    if (stop > i && v[stop - 1] == '\r') stop--;
    out.append(v + i, stop - i).append("\n", 1);
    i = end + 1;
  } while (i <= vlen && i != 0 && i - 1 < vlen);
}

// WHATWG HTML: the same line, from a Ruby value.
void field(std::string& out, const char* name, const mrb_value& v) {
  if (!mrb_string_p(v)) return;
  field(out, {name, {RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v))}});
}

// WHATWG HTML: one event out of what on_tick returned.
bool spell_event(mrb_state* mrb, const mrb_value& v, std::string& out) {
  if (mrb_string_p(v)) {
    field(out, {"data", {RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v))}});
    out.append("\n", 1);
    return true;
  }
  if (!mrb_hash_p(v)) return false;
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
    if (n > 0) field(out, {"retry", {buf, static_cast<size_t>(n)}});
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

// RFC 9112 7.1: one chunk - size in hex, CRLF around the data.
void chunk(std::string& sink, const std::string& body) {
  if (body.empty()) return;
  char hdr[24];
  const int n = std::snprintf(hdr, sizeof hdr, "%zx\r\n", body.size());
  sink.append(hdr, static_cast<size_t>(n));
  sink.append(body);
  sink.append("\r\n", 2);
}

// WHATWG HTML: on_close, once, however the stream ended.
void report_close(SseStream* s) {
  if (!s->res->have_close) return;
  mrb_state* mrb = s->res->mrb;
  const int ai = mrb_gc_arena_save(mrb);
  mrb_funcall_argv(mrb, s->self, MRB_SYM(on_close), 0, nullptr);
  if (mrb->exc != nullptr) {
    if (s->elog != nullptr) log_raise(*s->elog, mrb, 0);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
  }
  mrb_gc_arena_restore(mrb, ai);
}
}

// WHATWG HTML: Webmachine::SseResource, the class a route may name.
void sse_init(mrb_state* mrb, struct RClass* wm) {
  mrb_define_class_under_id(mrb, wm, MRB_SYM(SseResource), mrb->object_class);
}

// WHATWG HTML: one route's folded resource.
SseResource* sse_resource_new() { return new SseResource(); }

// WHATWG HTML: unique_ptr's deleter across the TU boundary.
void sse_resource_free(SseResource* r) { delete r; }

// WHATWG HTML: fold a resource class for an SSE route, once, at route.sse.
bool sse_fold(Setup s, mrb_value klass, SseResource& out) {
  mrb_state* const mrb = s.mrb;
  char* const err = s.why.buf;
  const size_t errlen = s.why.len;
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

  mrb_obj_freeze(mrb, klass);
  return true;
}

// WHATWG HTML: build THIS stream's resource; its initialize is the open hook.
SseStream* sse_open(const SseResource* r, Logger* elog, uint16_t& code) {
  uint16_t& status = code;
  status = 0;
  mrb_state* mrb = r->mrb;
  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value obj =
      mrb_obj_value(mrb_obj_alloc(mrb, MRB_INSTANCE_TT(r->klass), r->klass));
  mrb_gc_register(mrb, obj);
  const mrb_value out = mrb_funcall_argv(mrb, obj, MRB_SYM(initialize), 0, nullptr);
  if (mrb->exc != nullptr) {
    if (elog != nullptr) log_raise(*elog, mrb, 500);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_unregister(mrb, obj);
    mrb_gc_arena_restore(mrb, ai);
    status = 500;
    return nullptr;
  }
  if (mrb_symbol_p(out)) {
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

// WHATWG HTML: one second has passed - ask the resource, frame what it said.
bool sse_second(SseStream* s, int64_t now_s, std::string& sink) {
  const SseResource* r = s->res;
  mrb_state* mrb = r->mrb;
  if (s->last_tick_s == now_s) return true;
  s->last_tick_s = now_s;

  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value out = mrb_funcall_argv(mrb, s->self, MRB_SYM(on_tick), 0, nullptr);
  if (mrb->exc != nullptr) {
    if (s->elog != nullptr) log_raise(*s->elog, mrb, 0);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }

  bool go_on = true;
  std::string body;
  if (mrb_symbol_p(out)) {
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
    chunk(sink, ":\n\n");
    s->last_out_s = now_s;
  }
  if (!go_on) {
    sink.append("0\r\n\r\n", 5);
  }
  return go_on;
}

// WHATWG HTML: the stream ends; the resource hears about it once.
void sse_free(SseStream* s) {
  if (s == nullptr) return;
  report_close(s);
  mrb_gc_unregister(s->res->mrb, s->self);
  delete s;
}
}
