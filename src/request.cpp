#include "request.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>

namespace webmachine {
namespace {

// The one view, swapped per request. A file-static because there is
// one thread, one ring and one VM - the same reason the application
// registry is one (application.cpp says it at length). Null outside a
// run frame, and every accessor checks: reaching the request object
// from anywhere else is a mistake worth naming, not a segfault.
const ReqView* view_ = nullptr;

// The one object. Rooted at init: nothing names its class, so it would
// otherwise be collectable, and it must outlive every request.
mrb_value obj_ = mrb_nil_value();

const struct mrb_data_type request_type = {"webmachine.request", nullptr};

const ReqView* live(mrb_state* mrb) {
  if (view_ == nullptr) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "request is only alive inside a resource callback - there is no request "
              "being answered here");
  }
  return view_;
}

mrb_value lend(mrb_state* mrb, const char* p, size_t n) {
  return mrb_str_new(mrb, p, n);
}

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
  // The flow knows every method it DECIDES on by name; anything else
  // is one token to it. Where the bytes are lent, they are the answer.
  if (v->method_p != nullptr) return lend(mrb, v->method_p, v->method_n);
  mrb_raise(mrb, E_RUNTIME_ERROR,
            "this request's method is outside the set the flow names, and its bytes are "
            "not lent on this path");
  return mrb_nil_value();
}

// The request-target as it arrived, query and all (RFC 9110 4.2.1 -
// webmachine-ruby's `uri` is the full thing too).
mrb_value req_uri(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  return lend(mrb, v->target, v->target_len);
}

mrb_value req_path(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  return lend(mrb, v->target, v->path_len);
}

// What is LEFT of the path for the resource to dispatch on: the splat
// tail where the route has one, the whole path where it does not -
// webmachine-ruby's disp_path, same meaning.
mrb_value req_disp_path(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  if (v->spans.has_splat) return lend(mrb, v->spans.splat.p, v->spans.splat.n);
  return lend(mrb, v->target, v->path_len);
}

// The Symbol tokens the route bound, by NAME - the names came off the
// token array at add_route (router.hpp), the bytes off this request.
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

// The splat's segments, in order. No splat = an empty Array, which is
// what webmachine-ruby hands a route that has none.
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
    if (at < n) at++;  // step over the '/'
  }
  return a;
}

// The raw query, exactly as it arrived, without the '?'. Empty where
// there was none.
mrb_value req_query_string(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  if (v->path_len >= v->target_len) return mrb_str_new(mrb, "", 0);
  const size_t off = v->path_len + 1;  // past the '?'
  return lend(mrb, v->target + off, v->target_len - off);
}

// One percent-decoded value. '+' is a space (HTML form encoding, which
// is what a query string is in practice); a truncated or non-hex
// escape is kept VERBATIM rather than guessed at - a decoder that
// invents bytes is worse than one that hands them back.
int hex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

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

// key=value pairs, '&' or ';' separated, percent-decoded on both
// sides. A repeated key keeps the LAST value, which is what a Hash
// means; a key without '=' maps to "".
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

mrb_value req_headers(mrb_state* mrb, mrb_value) {
  // NOT built. Header VALUES are the value tier's subject (#165), and
  // on the h2 side they do not survive to here at all: a parked stream
  // answers after its decode buffer is gone (h2.hpp says so at the
  // stream struct, which is why the router's verdict is parked and not
  // a pointer). Lending them from h1 only would make `headers` mean
  // two different things depending on the wire, which is the one thing
  // the router was built not to do.
  mrb_raise(mrb, E_RUNTIME_ERROR,
            "request.headers is not built: header values are #165's value tier, and on "
            "HTTP/2 they do not outlive the decode buffer a parked request answers after. "
            "The facts the flow decides on are already folded into the flow");
  return mrb_nil_value();
}

mrb_value req_body(mrb_state* mrb, mrb_value) {
  mrb_raise(mrb, E_RUNTIME_ERROR,
            "request.body is not built: this tree skips request bodies at the framer "
            "(they are counted and discarded), so there is nothing to hand over yet");
  return mrb_nil_value();
}

mrb_value resource_request(mrb_state* mrb, mrb_value) {
  live(mrb);  // the refusal belongs at the door, not at the accessor
  return obj_;
}

}  // namespace

void request_bind(const ReqView* view) { view_ = view; }

void request_init(mrb_state* mrb, struct RClass* wm) {
  struct RClass* req = mrb_define_class_under_id(mrb, wm, MRB_SYM(Request), mrb->object_class);
  MRB_SET_INSTANCE_TT(req, MRB_TT_CDATA);
  // No `new`: the object is the process's, handed out by
  // Resource#request and made by nobody else.
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

  // ONE object for the process: the view behind it is what changes.
  obj_ = mrb_obj_value(mrb_data_object_alloc(mrb, req, nullptr, &request_type));
  mrb_gc_register(mrb, obj_);

  struct RClass* res = mrb_class_get_under_id(mrb, wm, MRB_SYM(Resource));
  mrb_define_method_id(mrb, res, MRB_SYM(request), resource_request, MRB_ARGS_NONE());
}

}  // namespace webmachine
