// Design decisions live in .DESIGN.md, filed under what each comment names.
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

const struct mrb_data_type request_type = {"webmachine.request", nullptr};

// RFC 9110 9.3.3: n11's create_path names a new disp_path for THIS run
// only; request_bind clears it again on the way in and on the way out.
std::string disp_override_;
bool disp_override_set_ = false;

// RFC 9110: the request being answered, or a named refusal outside a run frame.
const ReqView* live(mrb_state* mrb) {
  if (view_ == nullptr) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "request is only alive inside a resource callback - there is no request "
              "being answered here");
  }
  return view_;
}


// RFC 9110: request bytes as a Ruby String, materialised on demand.
mrb_value lend(mrb_state* mrb, const char* p, size_t n) {
  return mrb_str_new(mrb, p, n);
}

// RFC 9110 9.1: the method, by name.
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
  if (v->method_token != nullptr) return lend(mrb, v->method_token, v->method_token_len);
  mrb_raise(mrb, E_RUNTIME_ERROR,
            "this request's method is outside the set the flow names, and its bytes are "
            "not lent on this path");
  return mrb_nil_value();
}

// RFC 9110 4.2.1: the request-target as it arrived, query and all.
mrb_value req_uri(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  return lend(mrb, v->request_target, v->request_target_len);
}

// RFC 9110 4.2.1: the target up to '?'.
mrb_value req_path(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  return lend(mrb, v->request_target, v->path_len);
}

// RFC 9110 4.2.1: what is left of the path for the resource to dispatch
// on - n11's create_path override wins when this run set one.
mrb_value req_disp_path(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  if (disp_override_set_) return lend(mrb, disp_override_.data(), disp_override_.size());
  if (v->spans.has_splat) return lend(mrb, v->spans.splat.p, v->spans.splat.n);
  return lend(mrb, v->request_target, v->path_len);
}

// RFC 9110 4.2.1: the Symbol tokens this route bound, by name.
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
mrb_value req_path_tokens(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  mrb_value a = mrb_ary_new(mrb);
  if (!v->spans.has_splat) return a;
  const char* p = v->spans.splat.p;
  size_t n = v->spans.splat.n;
  size_t at = 0;
  // One String per segment, and a splat takes as many as the client
  // sends. The array is rooted before the save.
  const int ai = mrb_gc_arena_save(mrb);
  while (at < n) {
    size_t seg = at;
    while (at < n && p[at] != '/') at++;
    mrb_ary_push(mrb, a, lend(mrb, p + seg, at - seg));
    mrb_gc_arena_restore(mrb, ai);
    if (at < n) at++;
  }
  return a;
}

// RFC 9110 4.2.1: the raw query, without the '?'.
mrb_value req_query_string(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  if (v->path_len >= v->request_target_len) return mrb_str_new(mrb, "", 0);
  const size_t off = v->path_len + 1;
  return lend(mrb, v->request_target + off, v->request_target_len - off);
}

// RFC 9110 2.4 / percent-encoding: one hex digit, or -1.
int hex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// RFC 9110 2.4: one percent-decoded value; '+' is a space, a bad escape is kept.
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
mrb_value req_query(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  mrb_value h = mrb_hash_new(mrb);
  if (v->path_len >= v->request_target_len) return h;
  const char* p = v->request_target + v->path_len + 1;
  const size_t n = v->request_target_len - v->path_len - 1;
  size_t at = 0;
  // Two Strings per pair, and the pair count is the client's to choose:
  // held to the end they would fill a 100-slot MRB_GC_FIXED_ARENA at ~50
  // pairs. The hash is rooted before the save, so it keeps what it was
  // handed and the restore only drops the temporaries.
  const int ai = mrb_gc_arena_save(mrb);
  while (at < n) {
    const size_t start = at;
    while (at < n && p[at] != '&' && p[at] != ';') at++;
    const size_t len = at - start;
    if (at < n) at++;
    if (len == 0) continue;
    size_t eq = 0;
    while (eq < len && p[start + eq] != '=') eq++;
    // Frozen key: hash.c h_key_for would otherwise dup it (ea96df2).
    const mrb_value key = mrb_obj_freeze(mrb, decoded(mrb, p + start, eq));
    const mrb_value val =
        eq < len ? decoded(mrb, p + start + eq + 1, len - eq - 1) : mrb_str_new(mrb, "", 0);
    mrb_hash_set(mrb, h, key, val);
    mrb_gc_arena_restore(mrb, ai);
  }
  return h;
}

// RFC 9110 5.1/5.3, RFC 9113 8.2: the parsed header array, or a named
// refusal when this request's head is gone (a parked HTTP/2 body) -
// every field-by-name accessor below shares this one refusal.
const struct phr_header* live_hdrs(mrb_state* mrb, const ReqView* v) {
  if (v->fields == nullptr) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "request.headers: this request's head is gone - an HTTP/2 request that "
              "parked on its body answers after its decode buffer was reused, so its "
              "fields cannot be lent. They are there on HTTP/1.1 and at a websocket "
              "handshake");
  }
  return static_cast<const struct phr_header*>(v->fields);
}

// RFC 9110 5.1/5.3, RFC 9113 8.2: the head's fields, names lowercased,
// repeats joined with ", ".
mrb_value req_headers(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  const struct phr_header* hs = live_hdrs(mrb, v);
  mrb_value h = mrb_hash_new_capa(mrb, static_cast<mrb_int>(v->field_count));
  for (size_t i = 0; i < v->field_count; i++) {
    mrb_value name = mrb_str_new(mrb, hs[i].name, hs[i].name_len);
    char* np = RSTRING_PTR(name);
    for (mrb_int j = 0; j < RSTRING_LEN(name); j++) {
      if (np[j] >= 'A' && np[j] <= 'Z') np[j] = static_cast<char>(np[j] + 32);
    }
    // hash.c h_key_for dups every String key that is not already
    // frozen; freezing after the downcase hands it the final bytes and
    // skips one allocation and one copy per header (ea96df2).
    name = mrb_obj_freeze(mrb, name);
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

// RFC 9110 6.4: the request body, lent like everything else here; nil
// when none arrived.
mrb_value req_body(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  if (v->content == nullptr) return mrb_nil_value();
  return lend(mrb, v->content, v->content_len);
}

// RFC 9110 6.4: is there a body worth reading? An empty body counts as none.
mrb_value req_has_body(mrb_state* mrb, mrb_value) {
  return mrb_bool_value(live(mrb)->content_len > 0);
}

// RFC 9110 5.1: one field, by its (already-lowercase) name; nil when absent.
// RFC 9110 5.1: the value of one of the ten fields Resource#request names,
// or nil when the request did not carry it. Where it sits was noted by the
// one pass over the field array (http::NamedFieldIndex); this reads it.
mrb_value req_named(mrb_state* mrb, http::NamedField f) {
  const ReqView* v = live(mrb);
  if (v->values == nullptr) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "request: this request's head is gone - an HTTP/2 request that parked on "
              "its body answers after its decode buffer was reused, so its fields cannot "
              "be lent. They are there on HTTP/1.1 and at a websocket handshake");
  }
  if (!v->values->named.carries(f)) return mrb_nil_value();
  // The index is applied by the thing that stored it, against the array
  // it is being applied TO - see http::NamedFieldIndex. A position this
  // request's array cannot reach reads as "no such field" instead of
  // reading past the end.
  const struct phr_header* h =
      v->values->named.find(f, {live_hdrs(mrb, v), v->field_count});
  if (h == nullptr) return mrb_nil_value();
  return lend(mrb, h->value, h->value_len);
}

// RFC 9110 8.3: the entity's media type.
mrb_value req_content_type(mrb_state* mrb, mrb_value) {
  return req_named(mrb, http::NamedField::kContentType);
}
// RFC 9110 8.6: the entity's length, as webmachine-ruby hands it back -
// a String the caller is expected to .to_i.
mrb_value req_content_length(mrb_state* mrb, mrb_value) {
  return req_named(mrb, http::NamedField::kContentLength);
}
// RFC 9110 11.6.2: the credentials, verbatim.
mrb_value req_authorization(mrb_state* mrb, mrb_value) {
  return req_named(mrb, http::NamedField::kAuthorization);
}
// RFC 9110 12.5.1: what the client would rather have.
mrb_value req_accept(mrb_state* mrb, mrb_value) {
  return req_named(mrb, http::NamedField::kAccept);
}
// RFC 9110 12.5.3: which codings it will take.
mrb_value req_accept_encoding(mrb_state* mrb, mrb_value) {
  return req_named(mrb, http::NamedField::kAcceptEncoding);
}
// RFC 9110 13.1.1: the precondition on the current representation.
mrb_value req_if_match(mrb_state* mrb, mrb_value) {
  return req_named(mrb, http::NamedField::kIfMatch);
}
// RFC 9110 13.1.2: its negation.
mrb_value req_if_none_match(mrb_state* mrb, mrb_value) {
  return req_named(mrb, http::NamedField::kIfNoneMatch);
}
// RFC 9110 13.1.3: the date form of the same question.
mrb_value req_if_modified_since(mrb_state* mrb, mrb_value) {
  return req_named(mrb, http::NamedField::kIfModifiedSince);
}
// RFC 9110 13.1.4: and its negation.
mrb_value req_if_unmodified_since(mrb_state* mrb, mrb_value) {
  return req_named(mrb, http::NamedField::kIfUnmodifiedSince);
}

mrb_value req_host(mrb_state* mrb, mrb_value) {
  return req_named(mrb, http::NamedField::kHost);
}

// RFC 6265 5.4: the Cookie header's k=v pairs, lazily parsed into a
// Hash. No Cookie field: an empty Hash, same as webmachine-ruby.
mrb_value req_cookies(mrb_state* mrb, mrb_value) {
  const ReqView* v = live(mrb);
  mrb_value h = mrb_hash_new(mrb);
  // RFC 6265 4.2: the one pass kept the span; the field array is not
  // walked again to find it.
  if (v->values == nullptr || v->values->cookie == nullptr) return h;
  const char* p = v->values->cookie;
  const size_t n = v->values->cookie_len;
  size_t at = 0;
  // As in req_query: the cookie count is the client's, so each pair's
  // Strings are dropped once the hash holds them.
  const int ai = mrb_gc_arena_save(mrb);
  while (at < n) {
    while (at < n && (p[at] == ' ' || p[at] == '\t')) at++;
    const size_t start = at;
    while (at < n && p[at] != ';') at++;
    size_t end = at;
    while (end > start && (p[end - 1] == ' ' || p[end - 1] == '\t')) end--;
    if (at < n) at++;  // skip ';'
    if (end <= start) continue;
    size_t eq = start;
    while (eq < end && p[eq] != '=') eq++;
    if (eq >= end) continue;
    // Frozen key: hash.c h_key_for would otherwise dup it (ea96df2).
    mrb_hash_set(mrb, h, mrb_str_new_frozen(mrb, p + start, eq - start),
                 mrb_str_new(mrb, p + eq + 1, end - eq - 1));
    mrb_gc_arena_restore(mrb, ai);
  }
  return h;
}

// RFC 9110 4.2.1: base_uri as webmachine-ruby spells it - scheme and
// Host only, no port/query normalization, no URI object.
mrb_value req_base_uri(mrb_state* mrb, mrb_value) {
  const mrb_value host = req_named(mrb, http::NamedField::kHost);
  mrb_value s = mrb_str_new_lit(mrb, "http://");
  if (!mrb_nil_p(host)) {
    mrb_str_cat(mrb, s, RSTRING_PTR(host), static_cast<size_t>(RSTRING_LEN(host)));
  }
  mrb_str_cat_lit(mrb, s, "/");
  return s;
}

// RFC 9110 9.3.1: is this a GET?
mrb_value req_is_get(mrb_state* mrb, mrb_value) {
  return mrb_bool_value(live(mrb)->method == flow::Method::kGet);
}
// RFC 9110 9.3.2: is this a HEAD?
mrb_value req_is_head(mrb_state* mrb, mrb_value) {
  return mrb_bool_value(live(mrb)->method == flow::Method::kHead);
}
// RFC 9110 9.3.3: is this a POST?
mrb_value req_is_post(mrb_state* mrb, mrb_value) {
  return mrb_bool_value(live(mrb)->method == flow::Method::kPost);
}
// RFC 9110 9.3.4: is this a PUT?
mrb_value req_is_put(mrb_state* mrb, mrb_value) {
  return mrb_bool_value(live(mrb)->method == flow::Method::kPut);
}
// RFC 9110 9.3.5: is this a DELETE?
mrb_value req_is_delete(mrb_state* mrb, mrb_value) {
  return mrb_bool_value(live(mrb)->method == flow::Method::kDelete);
}
// RFC 9110 9.3.7: is this an OPTIONS?
mrb_value req_is_options(mrb_state* mrb, mrb_value) {
  return mrb_bool_value(live(mrb)->method == flow::Method::kOptions);
}

// RFC 9110: Resource#request - a FRESH handle on every call, never one the
// process keeps and hands back. What the caller does with it afterwards is
// the caller's; the callback's own GC arena roots it, the same way Response
// is rooted.
mrb_value resource_request(mrb_state* mrb, mrb_value) {
  live(mrb);
  struct RClass* wm = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
  struct RClass* rc = mrb_class_get_under_id(mrb, wm, MRB_SYM(Request));
  return mrb_obj_value(mrb_data_object_alloc(mrb, rc, nullptr, &request_type));
}
}

// RFC 9110: this run's request, or nothing between runs - and any
// create_path override goes with it, because it belongs to the run that is
// ending, never to the next one.
void request_bind(const ReqView* view) {
  view_ = view;
  disp_override_.clear();
  disp_override_set_ = false;
}

// RFC 9110 9.3.3: n11's create_path names a new disp_path for THIS run;
// the next request_bind (in or out) clears it again.
void request_disp_override(const char* p, size_t n) {
  disp_override_.assign(p, n);
  disp_override_set_ = true;
}

// RFC 9110: Webmachine::Request, defined once at gem init.
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
  mrb_define_method_id(mrb, req, MRB_SYM_Q(has_body), req_has_body, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(content_type), req_content_type, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(content_length), req_content_length, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(authorization), req_authorization, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(accept), req_accept, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(accept_encoding), req_accept_encoding, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(if_match), req_if_match, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(if_none_match), req_if_none_match, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(if_modified_since), req_if_modified_since,
                       MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(if_unmodified_since), req_if_unmodified_since,
                       MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(host), req_host, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(cookies), req_cookies, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM(base_uri), req_base_uri, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM_Q(get), req_is_get, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM_Q(head), req_is_head, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM_Q(post), req_is_post, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM_Q(put), req_is_put, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM_Q(delete), req_is_delete, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, req, MRB_SYM_Q(options), req_is_options, MRB_ARGS_NONE());


  struct RClass* res = mrb_class_get_under_id(mrb, wm, MRB_SYM(Resource));
  mrb_define_method_id(mrb, res, MRB_SYM(request), resource_request, MRB_ARGS_NONE());
  struct RClass* wsres = mrb_class_get_under_id(mrb, wm, MRB_SYM(WebsocketResource));
  mrb_define_method_id(mrb, wsres, MRB_SYM(request), resource_request, MRB_ARGS_NONE());
  struct RClass* sseres = mrb_class_get_under_id(mrb, wm, MRB_SYM(SseResource));
  mrb_define_method_id(mrb, sseres, MRB_SYM(request), resource_request, MRB_ARGS_NONE());
}

// RFC 9110 5.1: the one way a stored position is read - see the
// declaration in webmachine.hpp for why it is the only one. Lives here
// because this is a file where phr_header is a complete type; the header
// only forward-declares it.
namespace http {
const struct phr_header* NamedFieldIndex::find(NamedField f, HeaderList hs) const {
  if (hs.items == nullptr || !carries(f)) return nullptr;
  const uint8_t i = at[static_cast<uint8_t>(f)];
  // A position this array cannot reach is no field. The producers all
  // build this beside the array they derived it from, so this branch
  // should never be taken - and it is here precisely so that "should"
  // is not what stands between a bad index and a read past the end.
  return i < hs.count ? &hs.items[i] : nullptr;
}
}  // namespace http

// RFC 9110 12.5: see the declaration - the values negotiation reads, out of
// the fields a parked stream copied, which is the only place they still are.
void values_of_copied_fields(const ::phr_header* fields, size_t n, http::ReqValues& out) {
  flow::ReqFacts scratch;
  for (size_t i = 0; i < n; i++) {
    http::header_switch({{fields[i].name, fields[i].name_len},
                         {fields[i].value, fields[i].value_len}},
                        {scratch, out, i});
  }
}

}
