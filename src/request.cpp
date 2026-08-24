#include "webmachine.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>

#include <picohttpparser.h>

namespace webmachine {
namespace {
const ReqView* view_ = nullptr;

mrb_value obj_ = mrb_nil_value();

const struct mrb_data_type request_type = {"webmachine.request", nullptr};

// RFC 9110: the request being answered, or a named refusal outside a run frame.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
const ReqView* live(mrb_state* mrb) {
  if (view_ == nullptr) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "request is only alive inside a resource callback - there is no request "
              "being answered here");
  }
  return view_;
}

// RFC 9110: request bytes as a Ruby String, materialised on demand.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
mrb_value lend(mrb_state* mrb, const char* p, size_t n) {
  return mrb_str_new(mrb, p, n);
}

// RFC 9110 9.1: the method, by name.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
mrb_value req_method(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  switch (v->method) {
    case flow::Method::kGet: return mrb_str_new_lit(mrb, "GET");
    case flow::Method::kHead: return mrb_str_new_lit(mrb, "HEAD");
    case flow::Method::kPost: return mrb_str_new_lit(mrb, "POST");
    case flow::Method::kPut: return mrb_str_new_lit(mrb, "PUT");
    case flow::Method::kDelete: return mrb_str_new_lit(mrb, "DELETE");
    case flow::Method::kOptions: return mrb_str_new_lit(mrb, "OPTIONS");
    case flow::Method::kOther: break;
  }
  if (v->method_p != nullptr) return lend(mrb, v->method_p, v->method_n);
  mrb_raise(mrb, E_RUNTIME_ERROR,
            "this request's method is outside the set the flow names, and its bytes are "
            "not lent on this path");
  return mrb_nil_value();
}

// RFC 9110 4.2.1: the request-target as it arrived, query and all.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
mrb_value req_uri(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  return lend(mrb, v->target, v->target_len);
}

// RFC 9110 4.2.1: the target up to '?'.
// .DESIGN.md #h-target "4.2.1 - the query is not part of the path"
mrb_value req_path(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  return lend(mrb, v->target, v->path_len);
}

// RFC 9110 4.2.1: what is left of the path for the resource to dispatch on.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
mrb_value req_disp_path(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  if (v->spans.has_splat) return lend(mrb, v->spans.splat.p, v->spans.splat.n);
  return lend(mrb, v->target, v->path_len);
}

// RFC 9110 4.2.1: the Symbol tokens this route bound, by name.
// .DESIGN.md #app-spans "What a match captures, and why it captures it at all"
mrb_value req_path_info(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  mrb_value h = mrb_hash_new_capa(mrb, v->spans.nbind);
  if (v->table == nullptr || v->route < 0) return h;
  for (uint8_t i = 0; i < v->spans.nbind; i++) {
    const mrb_sym k = static_cast<mrb_sym>(v->table->binding_sym(v->route, i));
    if (k == 0) continue;
    mrb_hash_set(mrb, h, mrb_symbol_value(k),
                 lend(mrb, v->spans.bind[i].p, v->spans.bind[i].n));
  }
  return h;
}

// RFC 9110 4.2.1: the splat's segments, in order.
// .DESIGN.md #app-spans "What a match captures, and why it captures it at all"
mrb_value req_path_tokens(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  mrb_value a = mrb_ary_new(mrb);
  if (!v->spans.has_splat) return a;
  const char* p = v->spans.splat.p;
  size_t n = v->spans.splat.n;
  size_t at = 0;
  while (at < n) {
    size_t seg = at;
    while (at < n && p[at] != '/') at++;
    mrb_ary_push(mrb, a, lend(mrb, p + seg, at - seg));
    if (at < n) at++;
  }
  return a;
}

// RFC 9110 4.2.1: the raw query, without the '?'.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
mrb_value req_query_string(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  if (v->path_len >= v->target_len) return mrb_str_new(mrb, "", 0);
  const size_t off = v->path_len + 1;
  return lend(mrb, v->target + off, v->target_len - off);
}

// RFC 9110 2.4 / percent-encoding: one hex digit, or -1.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
int hex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// RFC 9110 2.4: one percent-decoded value; '+' is a space, a bad escape is kept.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
mrb_value decoded(mrb_state* mrb, const char* p, size_t n) {
  mrb_value s = mrb_str_new_capa(mrb, n);
  for (size_t i = 0; i < n; i++) {
    if (p[i] == '+') {
      mrb_str_cat(mrb, s, " ", 1);
      continue;
    }
    if (p[i] == '%' && i + 2 < n) {
      const int hi = hex(p[i + 1]);
      const int lo = hex(p[i + 2]);
      if (hi >= 0 && lo >= 0) {
        const char b = static_cast<char>((hi << 4) | lo);
        mrb_str_cat(mrb, s, &b, 1);
        i += 2;
        continue;
      }
    }
    mrb_str_cat(mrb, s, p + i, 1);
  }
  return s;
}

// RFC 9110 4.2.1: key=value pairs, '&' or ';' separated.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
mrb_value req_query(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  mrb_value h = mrb_hash_new(mrb);
  if (v->path_len >= v->target_len) return h;
  const char* p = v->target + v->path_len + 1;
  const size_t n = v->target_len - v->path_len - 1;
  size_t at = 0;
  while (at < n) {
    const size_t start = at;
    while (at < n && p[at] != '&' && p[at] != ';') at++;
    const size_t len = at - start;
    if (at < n) at++;
    if (len == 0) continue;
    size_t eq = 0;
    while (eq < len && p[start + eq] != '=') eq++;
    const mrb_value key = decoded(mrb, p + start, eq);
    const mrb_value val =
        eq < len ? decoded(mrb, p + start + eq + 1, len - eq - 1) : mrb_str_new(mrb, "", 0);
    mrb_hash_set(mrb, h, key, val);
  }
  return h;
}

// RFC 9110 5.1/5.3, RFC 9113 8.2: the head's fields, names lowercased,
// repeats joined with ", ".
// .DESIGN.md #h-field-names "5.1 - field names are case-insensitive"
mrb_value req_headers(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  if (v->hdrs == nullptr) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "request.headers: this request's head is gone - an HTTP/2 request that "
              "parked on its body answers after its decode buffer was reused, so its "
              "fields cannot be lent. They are there on HTTP/1.1 and at a websocket "
              "handshake");
  }
  const struct phr_header* hs = static_cast<const struct phr_header*>(v->hdrs);
  mrb_value h = mrb_hash_new_capa(mrb, static_cast<mrb_int>(v->nhdr));
  for (size_t i = 0; i < v->nhdr; i++) {
    mrb_value name = mrb_str_new(mrb, hs[i].name, hs[i].name_len);
    char* np = RSTRING_PTR(name);
    for (mrb_int j = 0; j < RSTRING_LEN(name); j++) {
      if (np[j] >= 'A' && np[j] <= 'Z') np[j] = static_cast<char>(np[j] + 32);
    }
    const mrb_value had = mrb_hash_get(mrb, h, name);
    if (mrb_string_p(had)) {
      mrb_str_cat_lit(mrb, had, ", ");
      mrb_str_cat(mrb, had, hs[i].value, hs[i].value_len);
      continue;
    }
    mrb_hash_set(mrb, h, name, mrb_str_new(mrb, hs[i].value, hs[i].value_len));
  }
  return h;
}

// RFC 9110 6.4: refused by name until a body tier exists.
// .DESIGN.md #mruby-refusals
//   "What a resource may not do yet, and says so by name"
mrb_value req_body(mrb_state* mrb, mrb_value) {
  mrb_raise(mrb, E_RUNTIME_ERROR,
            "request.body is not built: this tree skips request bodies at the framer "
            "(they are counted and discarded), so there is nothing to hand over yet");
  return mrb_nil_value();
}

// RFC 9110: Resource#request - the one object, never a new one.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
mrb_value resource_request(mrb_state* mrb, mrb_value) {
  live(mrb);
  return obj_;
}
}

// RFC 9110: point the one object at this request, or at nothing.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
void request_bind(const ReqView* view) { view_ = view; }

// RFC 9110: Webmachine::Request, defined once at gem init.
// .DESIGN.md #mruby-request
//   "The request object is lazy, and there is one of it"
void request_init(mrb_state* mrb, struct RClass* wm) {
  struct RClass* req = mrb_define_class_under_id(mrb, wm, MRB_SYM(Request), mrb->object_class);
  MRB_SET_INSTANCE_TT(req, MRB_TT_CDATA);
  mrb_undef_class_method_id(mrb, req, MRB_SYM(new));
  mrb_define_method_id(mrb, req, MRB_SYM(method), req_method, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(uri), req_uri, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(path), req_path, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(disp_path), req_disp_path, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(path_info), req_path_info, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(path_tokens), req_path_tokens, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(query), req_query, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(query_string), req_query_string, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(headers), req_headers, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(body), req_body, MRB_ARGS_NONE());

  obj_ = mrb_obj_value(mrb_data_object_alloc(mrb, req, nullptr, &request_type));
  mrb_gc_register(mrb, obj_);

  struct RClass* res = mrb_class_get_under_id(mrb, wm, MRB_SYM(Resource));
  mrb_define_method_id(mrb, res, MRB_SYM(request), resource_request, MRB_ARGS_NONE());
  struct RClass* wsres = mrb_class_get_under_id(mrb, wm, MRB_SYM(WebsocketResource));
  mrb_define_method_id(mrb, wsres, MRB_SYM(request), resource_request, MRB_ARGS_NONE());
  struct RClass* sseres = mrb_class_get_under_id(mrb, wm, MRB_SYM(SseResource));
  mrb_define_method_id(mrb, sseres, MRB_SYM(request), resource_request, MRB_ARGS_NONE());
}
}
