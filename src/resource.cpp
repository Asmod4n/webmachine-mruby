// Design decisions live in .DESIGN.md, filed under what each comment names.
#define OPENSSL_SUPPRESS_DEPRECATED 1
#include "webmachine.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/object.h>
#include <mruby/proc.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <openssl/md5.h>
#include <simdutf.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define WM_RES_UNLIKELY(x) __builtin_expect(!!(x), 0)

extern "C" mrb_value mrb_exc_backtrace(mrb_state* mrb, mrb_value exc);
extern "C" mrb_int mrb_proc_arity(const struct RProc* p);

namespace webmachine {
namespace {
using flow::Node;

constexpr const char* kMethodName[6] = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"};

// mruby: a setup raise becomes a named refusal, printed by the VM itself.
void exc_into(mrb_state* mrb, const char* what, char* err, size_t errlen) {
  std::snprintf(err, errlen, "%s (exception below)", what);
  mrb_print_error(mrb);
  mrb->exc = nullptr;
}

// mruby: unwrap MRB_PROC_ALIAS once, at fold, instead of at every call.
mrb_method_t resolve_alias(mrb_method_t m) {
  if (MRB_METHOD_UNDEF_P(m) || MRB_METHOD_FUNC_P(m)) return m;
  const struct RProc* p = MRB_METHOD_PROC(m);
  while (p != nullptr && MRB_PROC_ALIAS_P(p)) p = p->upper;
  if (p == nullptr) return m;
  mrb_method_t out = m;
  MRB_METHOD_FROM_PROC(out, p);
  return out;
}

struct Resolved {
  mrb_method_t m = {};
  bool defined = false;
  bool fast = false;
};

// mruby: where does this symbol answer, and may we enter its proc directly?
Resolved resolve(mrb_state* mrb, struct RClass* c, mrb_sym sym) {
  Resolved r;
  struct RClass* owner = c;
  r.m = resolve_alias(mrb_method_search_vm(mrb, &owner, sym));
  r.defined = !MRB_METHOD_UNDEF_P(r.m);
  r.fast = r.defined && !MRB_METHOD_CFUNC_P(r.m);
  return r;
}

// mruby: is this a runtime callback? A direct look into the method table.
bool instance_defined(mrb_state* mrb, mrb_value klass, mrb_sym sym) {
  return resolve(mrb, mrb_class_ptr(klass), sym).defined;
}

// mruby: how many arguments the method DECLARED, capped at what its node offers.
uint8_t argc_of(mrb_method_t m, uint8_t most) {
  int a = most;
  if (!MRB_METHOD_FUNC_P(m)) {
    const struct RProc* p = MRB_METHOD_PROC(m);
    if (p != nullptr) {
      const mrb_int ar = mrb_proc_arity(p);
      if (ar >= 0) a = static_cast<int>(ar) < most ? static_cast<int>(ar) : most;
    }
  }
  return static_cast<uint8_t>(a);
}

// cb.rb: a value callback - the instance method wins; a class-only version is
// kept with an undef method slot and funcalled on the class at runtime.
Resource::ValueCb value_cb(mrb_state* mrb, mrb_value klass, mrb_sym sym, uint8_t maxargs,
                           bool class_fallback) {
  Resource::ValueCb cb;
  cb.sym = sym;
  const Resolved inst = resolve(mrb, mrb_class_ptr(klass), sym);
  if (inst.defined) {
    cb.has = true;
    cb.m = inst.m;
    cb.fast = inst.fast;
    cb.argc = argc_of(inst.m, maxargs);
    return cb;
  }
  if (!class_fallback) return cb;
  const Resolved meta = resolve(mrb, mrb_class(mrb, klass), sym);
  if (meta.defined) {
    cb.has = true;
    cb.argc = argc_of(meta.m, maxargs);
  }
  return cb;
}

struct SetupCall {
  const struct RProc* proc;
  mrb_sym sym;
  mrb_value self;
  struct RClass* c;
};

// mruby: the yield body a setup call runs under mrb_protect_error.
mrb_value setup_call_body(mrb_state* mrb, void* ud) {
  const SetupCall* c = static_cast<const SetupCall*>(ud);
  mrb_callinfo* ci = mrb->c->ci;
  const mrb_sym saved_mid = ci->mid;
  ci->mid = c->sym;
  mrb_value r = mrb_yield_with_class(mrb, mrb_obj_value(const_cast<struct RProc*>(c->proc)), 0,
                                     nullptr, c->self, c->c);
  ci->mid = saved_mid;
  return r;
}

// mruby: invoke a resolved method at SETUP time; a raise stays pending.
mrb_value call_resolved(mrb_state* mrb, const Resolved& r, mrb_sym sym, mrb_value self,
                        struct RClass* c) {
  if (!r.fast) return mrb_funcall_argv(mrb, self, sym, 0, nullptr);
  SetupCall ctx{MRB_METHOD_PROC(r.m), sym, self, c};
  mrb_bool raised = FALSE;
  mrb_value v = mrb_protect_error(mrb, setup_call_body, &ctx, &raised);
  if (WM_RES_UNLIKELY(raised)) {
    mrb->exc = mrb_obj_ptr(v);
    return mrb_nil_value();
  }
  mrb_gc_protect(mrb, v);
  return v;
}

// RFC 9110: one konst flow callback, asked once on the class.
bool ask(mrb_state* mrb, mrb_value klass, mrb_sym sym, const char* name, bool defv, bool* out,
         char* err, size_t errlen) {
  const Resolved r = resolve(mrb, mrb_class(mrb, klass), sym);
  if (!r.defined) {
    *out = defv;
    return true;
  }
  const mrb_value v = call_resolved(mrb, r, sym, klass, mrb_class(mrb, klass));
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    exc_into(mrb, name, err, errlen);
    return false;
  }
  *out = mrb_test(v);
  return true;
}

// RFC 9110 9.1: known_methods / allowed_methods as one String of tokens or
// webmachine-ruby's Array-of-Strings form.
bool ask_methods(mrb_state* mrb, mrb_value klass, mrb_sym sym, const char* name, bool present[7],
                 char* err, size_t errlen) {
  const Resolved r = resolve(mrb, mrb_class(mrb, klass), sym);
  if (!r.defined) return true;
  const mrb_value v = call_resolved(mrb, r, sym, klass, mrb_class(mrb, klass));
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    exc_into(mrb, name, err, errlen);
    return false;
  }
  const auto scan = [&](const char* p, const char* end) -> bool {
    while (p < end) {
      while (p < end && (*p == ' ' || *p == ',')) p++;
      const char* tok = p;
      while (p < end && *p != ' ' && *p != ',') p++;
      if (tok == p) break;
      bool known = false;
      for (uint8_t m = 0; m < 6; m++) {
        const size_t n = std::strlen(kMethodName[m]);
        if (static_cast<size_t>(p - tok) == n && std::memcmp(tok, kMethodName[m], n) == 0) {
          present[m] = true;
          known = true;
          break;
        }
      }
      if (WM_RES_UNLIKELY(!known)) {
        std::snprintf(err, errlen, "%s names '%.*s' - outside the compiled method set", name,
                      static_cast<int>(p - tok), tok);
        return false;
      }
    }
    return true;
  };
  for (uint8_t m = 0; m < 7; m++) present[m] = false;
  if (mrb_string_p(v)) return scan(RSTRING_PTR(v), RSTRING_PTR(v) + RSTRING_LEN(v));
  if (mrb_array_p(v)) {
    for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
      const mrb_value s = RARRAY_PTR(v)[j];
      if (WM_RES_UNLIKELY(!mrb_string_p(s))) {
        std::snprintf(err, errlen, "%s must return method Strings", name);
        return false;
      }
      if (!scan(RSTRING_PTR(s), RSTRING_PTR(s) + RSTRING_LEN(s))) return false;
    }
    return true;
  }
  std::snprintf(err, errlen, "%s must return an Array of Strings or a String like 'GET HEAD'",
                name);
  return false;
}

struct BoolCb {
  Node node;
  mrb_sym sym;
  const char* name;
  bool defv;
  uint8_t maxargs;
};
const BoolCb kBools[] = {
    {Node::kB13, MRB_SYM_Q(service_available), "service_available?", true, 0},
    {Node::kB11, MRB_SYM_Q(uri_too_long), "uri_too_long?", false, 1},
    {Node::kB9b, MRB_SYM_Q(malformed_request), "malformed_request?", false, 0},
    {Node::kB7, MRB_SYM_Q(forbidden), "forbidden?", false, 0},
    {Node::kB6, MRB_SYM_Q(valid_content_headers), "valid_content_headers?", true, 1},
    {Node::kB5, MRB_SYM_Q(known_content_type), "known_content_type?", true, 1},
    {Node::kB4, MRB_SYM_Q(valid_entity_length), "valid_entity_length?", true, 1},
    {Node::kG7, MRB_SYM_Q(resource_exists), "resource_exists?", true, 0},
    {Node::kK7, MRB_SYM_Q(previously_existed), "previously_existed?", false, 0},
    {Node::kM7, MRB_SYM_Q(allow_missing_post), "allow_missing_post?", false, 0},
    {Node::kN5, MRB_SYM_Q(allow_missing_post), "allow_missing_post?", false, 0},
    {Node::kM20, MRB_SYM(delete_resource), "delete_resource", false, 0},
    {Node::kM20b, MRB_SYM_Q(delete_completed), "delete_completed?", true, 0},
    {Node::kO14, MRB_SYM_Q(is_conflict), "is_conflict?", false, 0},
    {Node::kP3, MRB_SYM_Q(is_conflict), "is_conflict?", false, 0},
    {Node::kO18b, MRB_SYM_Q(multiple_choices), "multiple_choices?", false, 0},
};

// flow.rb b8/b9a: value-semantics nodes riding the node tables; a class-only
// version keeps an undef method slot and is funcalled on the class.
struct NodeValueCb {
  Node node;
  mrb_sym sym;
  uint8_t maxargs;
};
const NodeValueCb kNodeValues[] = {
    {Node::kB8, MRB_SYM_Q(is_authorized), 1},
    {Node::kB9a, MRB_SYM(validate_content_checksum), 0},
};

struct NamedSym {
  mrb_sym sym;
  const char* name;
};
const NamedSym kUnhonored[] = {
    {MRB_SYM(languages_provided), "languages_provided"},
    {MRB_SYM(charsets_provided), "charsets_provided"},
    {MRB_SYM(language_chosen), "language_chosen"},
};
const NamedSym kKonstOnly[] = {
    {MRB_SYM(encodings_provided), "encodings_provided"},
};

// RFC 9110 5.1: case-insensitive token equality, neither side canonical.
bool ci_eq(const char* a, size_t an, const char* b, size_t bn) {
  if (an != bn) return false;
  for (size_t i = 0; i < an; i++) {
    char x = a[i];
    char y = b[i];
    if (x >= 'A' && x <= 'Z') x = static_cast<char>(x + 32);
    if (y >= 'A' && y <= 'Z') y = static_cast<char>(y + 32);
    if (x != y) return false;
  }
  return true;
}

// RFC 9110 10.2.2: does this run's header block already carry a Location line?
bool headers_has_location(const std::string& h) {
  size_t at = 0;
  while (at < h.size()) {
    size_t eol = h.find("\r\n", at);
    if (eol == std::string::npos) eol = h.size();
    if (eol - at > 9 && http::tok_eq(h.data() + at, 9, "location:", 9)) return true;
    at = eol + 2;
  }
  return false;
}

// RFC 1864: decode64(Content-MD5) against MD5(body) spelled as 32 lowercase
// hex characters - webmachine-ruby compares against the HEXDIGEST string.
bool content_md5_ok(const Resource& res) {
  const http::ReqValues* v = res.run_vals;
  if (v == nullptr || v->content_md5 == nullptr) return true;
  const char* bp = "";
  size_t bn = 0;
  if (res.run_req != nullptr && res.run_req->content != nullptr) {
    bp = res.run_req->content;
    bn = res.run_req->content_len;
  }
  unsigned char dg[MD5_DIGEST_LENGTH];
  MD5(reinterpret_cast<const unsigned char*>(bp), bn, dg);
  char hex[32];
  static const char kHexDigit[] = "0123456789abcdef";
  for (int i = 0; i < 16; i++) {
    hex[i * 2] = kHexDigit[dg[i] >> 4];
    hex[i * 2 + 1] = kHexDigit[dg[i] & 15];
  }
  const size_t cap =
      simdutf::maximal_binary_length_from_base64(v->content_md5, v->content_md5_len);
  std::string dec;
  dec.resize(cap);
  const simdutf::result r =
      simdutf::base64_to_binary(v->content_md5, v->content_md5_len, dec.data());
  if (r.error != simdutf::error_code::SUCCESS) return false;
  return r.count == 32 && std::memcmp(dec.data(), hex, 32) == 0;
}

// RFC 9110: THE runtime tier - webmachine-ruby's value semantics for the
// whole flow (flow.rb + helpers.rb, 1:1) inside one VM frame.
// RFC 9110: one request's walk through the flow. Entered as a C++ call
// from resource_run - a Ruby frame around it would cost a method lookup
// per request and leave a class in the GC's mark set.
struct RescueCtx {
  const Resource* res;
  mrb_value exc;
  bool handled = false;
};

// fsm.rb: the raise path - handle_exception when the app declared one,
// then finish_request, both inside their own guarded frame.
mrb_value run_rescue_body(mrb_state* mrb, void* ud) {
  RescueCtx& rc = *static_cast<RescueCtx*>(ud);
  const Resource& res = *rc.res;
  if (res.cb_handle_exception.has && !mrb_nil_p(res.live)) {
    rc.handled = true;
    mrb_value e = rc.exc;
    const mrb_value recv =
        MRB_METHOD_UNDEF_P(res.cb_handle_exception.m) ? mrb_obj_value(res.klass) : res.live;
    mrb_funcall_argv(mrb, recv, res.cb_handle_exception.sym,
                     res.cb_handle_exception.argc != 0 ? 1 : 0, &e);
    if (res.cb_finish_request.has) {
      const mrb_value frecv =
          MRB_METHOD_UNDEF_P(res.cb_finish_request.m) ? mrb_obj_value(res.klass) : res.live;
      mrb_funcall_argv(mrb, frecv, res.cb_finish_request.sym, 0, nullptr);
    }
  }
  return mrb_nil_value();
}

mrb_value run_engine(mrb_state* mrb, const Resource& res);

// mruby: the ONE guarded entry per request. Without a jmpbuf on the
// state a raise reaches mrb_exc_raise with mrb->jmp NULL, which prints
// and calls abort() - so the frame is not optional. mrb_protect_error
// buys it for a C function pointer, with no method lookup and no
// object to construct.
mrb_value run_engine_body(mrb_state* mrb, void* ud) {
  return run_engine(mrb, *static_cast<const Resource*>(ud));
}

mrb_value run_engine(mrb_state* mrb, const Resource& res) {
  // #181: the resource instance belongs to ONE request. Allocate it and
  // nothing else - mrb_obj_new would search for initialize twice per
  // request (mrb_func_basic_p, then mrb_funcall_argv) to arrive where the
  // fold already stands. The call itself, when one is owed, is below,
  // where the direct-entry path exists.
  res.live = mrb_obj_value(mrb_obj_alloc(mrb, res.live_tt, res.klass));
  const flow::ReqFacts& facts = *res.run_facts;
  const flow::KonstAnswers& k = res.konst.per_method[static_cast<size_t>(facts.method)];
  const http::ReqValues* vals = res.run_vals;
  std::string& hdrs = *res.run_headers;

  const auto naked = [&](mrb_method_t m, bool fast, mrb_sym sym, mrb_int argc = 0,
                         const mrb_value* argv = nullptr) -> mrb_value {
    if (WM_RES_UNLIKELY(!fast || mrb_obj_ptr(res.live)->c != res.klass)) {
      return mrb_funcall_argv(mrb, res.live, sym, argc, argv);
    }
    mrb_callinfo* ci = mrb->c->ci;
    const mrb_sym saved = ci->mid;
    ci->mid = sym;
    mrb_value r = mrb_yield_with_class(
        mrb, mrb_obj_value(const_cast<struct RProc*>(MRB_METHOD_PROC(m))), argc, argv, res.live,
        res.klass);
    ci->mid = saved;
    return r;
  };

  // #181: the app's own initialize, entered through the resolved method
  // rather than looked up again. init_needed is false for every resource
  // that did not override Object's - the implicit one is not a reason to
  // run anything.
  if (WM_RES_UNLIKELY(res.init_needed)) {
    naked(res.init_m, res.init_fast, MRB_SYM(initialize));
  }

  // cb.rb: a value callback - an undef method slot means class-only, called
  // on the class; everything else runs on the live instance.
  const auto cbv = [&](const Resource::ValueCb& cb, mrb_int argc = 0,
                       const mrb_value* argv = nullptr) -> mrb_value {
    if (MRB_METHOD_UNDEF_P(cb.m)) {
      return mrb_funcall_argv(mrb, mrb_obj_value(res.klass), cb.sym, argc, argv);
    }
    return naked(cb.m, cb.fast, cb.sym, argc, argv);
  };

  // flow.rb: one node's callback out of the node tables, class-only via funcall.
  const auto nodecall = [&](Node nd, mrb_int argc, const mrb_value* argv) -> mrb_value {
    const size_t i = static_cast<size_t>(nd);
    if (MRB_METHOD_UNDEF_P(res.node_m[i])) {
      return mrb_funcall_argv(mrb, mrb_obj_value(res.klass), res.node_sym[i], argc, argv);
    }
    return naked(res.node_m[i], res.node_fast[i], res.node_sym[i], argc, argv);
  };

  // flow.rb decision_test: ANY callback may halt with an Integer status.
  const auto halt_of = [&](mrb_value v, mrb_sym sym) -> uint16_t {
    const mrb_int code = mrb_integer(v);
    if (code < 100 || code > 599) {
      mrb_raisef(mrb, E_RANGE_ERROR, "%s answered %i, which is not an HTTP status",
                 mrb_sym_name(mrb, sym), code);
    }
    return static_cast<uint16_t>(code);
  };

  // RFC 9110: what ONE node's callback is handed. webmachine-ruby's
  // signatures decide this, and a method that declared the parameter must
  // not be called with nothing; one that declared none gets nothing.
  const auto arg_for = [&](Node nd) -> mrb_value {
    switch (nd) {
      case Node::kB8:
        return vals != nullptr && vals->authorization != nullptr
                   ? mrb_str_new(mrb, vals->authorization, vals->authorization_len)
                   : mrb_nil_value();
      case Node::kB11:
        return res.run_req != nullptr && res.run_req->request_target != nullptr
                   ? mrb_str_new(mrb, res.run_req->request_target, res.run_req->request_target_len)
                   : mrb_nil_value();
      case Node::kB6: {
        const mrb_value rq = mrb_funcall_argv(mrb, res.live, MRB_SYM(request), 0, nullptr);
        const mrb_value hs = mrb_funcall_argv(mrb, rq, MRB_SYM(headers), 0, nullptr);
        const mrb_value out = mrb_hash_new(mrb);
        if (mrb_hash_p(hs)) {
          const mrb_value keys = mrb_hash_keys(mrb, hs);
          for (mrb_int j = 0; j < RARRAY_LEN(keys); j++) {
            const mrb_value key = RARRAY_PTR(keys)[j];
            if (!mrb_string_p(key) || RSTRING_LEN(key) < 8) continue;
            if (!http::tok_eq(RSTRING_PTR(key), 8, "content-", 8)) continue;
            mrb_hash_set(mrb, out, key, mrb_hash_get(mrb, hs, key));
          }
        }
        return out;
      }
      case Node::kB5:
        return vals != nullptr && vals->content_type != nullptr
                   ? mrb_str_new(mrb, vals->content_type, vals->content_type_len)
                   : mrb_nil_value();
      case Node::kB4:
        return mrb_int_value(
            mrb, static_cast<mrb_int>(res.run_req != nullptr ? res.run_req->content_len : 0));
      default:
        return mrb_nil_value();
    }
  };

  // RFC 9110 9.1: this request's method, by name.
  const auto method_name = [&](const char** p, size_t* n) {
    if (res.run_req != nullptr && res.run_req->method_token != nullptr) {
      *p = res.run_req->method_token;
      *n = res.run_req->method_token_len;
      return;
    }
    const size_t m = static_cast<size_t>(facts.method);
    *p = m < 6 ? kMethodName[m] : "";
    *n = m < 6 ? std::strlen(kMethodName[m]) : 0;
  };

  // RFC 9110 9.1: one method-list answer (Array or token String), marshalled
  // once into run_methods.
  const auto marshal_methods = [&](const Resource::ValueCb& cb) {
    res.run_methods.clear();
    const mrb_value v = cbv(cb);
    if (mrb_array_p(v)) {
      for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
        const mrb_value s = RARRAY_PTR(v)[j];
        if (WM_RES_UNLIKELY(!mrb_string_p(s))) {
          mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer method Strings",
                     mrb_sym_name(mrb, cb.sym));
        }
        res.run_methods.emplace_back(RSTRING_PTR(s), static_cast<size_t>(RSTRING_LEN(s)));
      }
      return;
    }
    if (WM_RES_UNLIKELY(!mrb_string_p(v))) {
      mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer an Array of Strings or a String",
                 mrb_sym_name(mrb, cb.sym));
    }
    const char* p = RSTRING_PTR(v);
    const char* end = p + RSTRING_LEN(v);
    while (p < end) {
      while (p < end && (*p == ' ' || *p == ',')) p++;
      const char* tok = p;
      while (p < end && *p != ' ' && *p != ',') p++;
      if (tok != p) res.run_methods.emplace_back(tok, static_cast<size_t>(p - tok));
    }
  };

  // flow.rb b10/b12: include?(request.method) over the marshalled list.
  const auto methods_contain = [&]() -> bool {
    const char* mp;
    size_t mn;
    method_name(&mp, &mn);
    for (const std::string& s : res.run_methods) {
      if (s.size() == mn && std::memcmp(s.data(), mp, mn) == 0) return true;
    }
    return false;
  };

  // RFC 9112 5: field-line = field-name ":" OWS field-value OWS CRLF. A
  // node decides WHICH field it produces; this is the only place that
  // knows how one is spelled. Every node below used to spell its own,
  // which is why "Allow: " and "ETag: " carried the colon inside the
  // literal and every site ended with its own append("\r\n", 2).
  const auto field = [&](const char* name, size_t nlen, const char* value, size_t vlen) {
    hdrs.append(name, nlen);
    hdrs.append(": ", 2);
    hdrs.append(value, vlen);
    hdrs.append("\r\n", 2);
  };

  // RFC 9110 5.6.1: a field whose value is a #rule - a comma-separated
  // list. The members go in one at a time, so a list never needs a string
  // built to hold it: `head` is the member that is not in `tail`, empty
  // when there is none.
  const auto field_list = [&](const char* name, size_t nlen, const char* head, size_t headn,
                              const std::vector<std::string>& tail) {
    hdrs.append(name, nlen);
    hdrs.append(": ", 2);
    bool first = true;
    if (headn != 0) {
      hdrs.append(head, headn);
      first = false;
    }
    for (const std::string& s : tail) {
      if (!first) hdrs.append(", ", 2);
      hdrs.append(s);
      first = false;
    }
    hdrs.append("\r\n", 2);
  };

  // RFC 9110 10.2.1: the Allow value, from the dynamic list or the konst join.
  const auto allow_line = [&]() {
    if (res.cb_allowed_methods.has) {
      field_list("Allow", 5, nullptr, 0, res.run_methods);
    } else {
      field("Allow", 5, res.konst.allow.data(), res.konst.allow.size());
    }
  };

  const bool ct_dyn = res.cb_content_types_provided.has;
  // cb.rb content_types_provided: the dynamic answer, marshalled once.
  const auto marshal_ct = [&]() {
    if (!ct_dyn || !res.run_content_types_provided.empty()) return;
    const mrb_value v = cbv(res.cb_content_types_provided);
    if (WM_RES_UNLIKELY(!mrb_array_p(v) || RARRAY_LEN(v) == 0)) {
      mrb_raise(mrb, E_WM_ERROR(mrb),
                "content_types_provided must answer [[type, handler]] pairs");
    }
    for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
      const mrb_value pair = RARRAY_PTR(v)[j];
      if (WM_RES_UNLIKELY(!mrb_array_p(pair) || RARRAY_LEN(pair) < 2 ||
                          !mrb_string_p(RARRAY_PTR(pair)[0]) ||
                          !mrb_symbol_p(RARRAY_PTR(pair)[1]))) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_provided pairs are [String, Symbol]");
      }
      Resource::TypedHandler th;
      th.type.assign(RSTRING_PTR(RARRAY_PTR(pair)[0]),
                     static_cast<size_t>(RSTRING_LEN(RARRAY_PTR(pair)[0])));
      th.handler = mrb_symbol(RARRAY_PTR(pair)[1]);
      res.run_content_types_provided.push_back(std::move(th));
    }
  };
  // RFC 9110 12.5.1: the list conneg runs against - dynamic or konst-folded.
  const auto active_ct = [&]() -> const std::vector<Resource::TypedHandler>& {
    return ct_dyn ? res.run_content_types_provided : res.content_types_provided;
  };

  // cb.rb generate_etag: asked at most once per run; g11, k13 and the
  // caching headers all read the same memo.
  const auto ensure_etag = [&]() -> int {
    if (res.etag_asked) return -1;
    res.etag_asked = true;
    if (!res.cb_generate_etag.has) return -1;
    mrb_value v = cbv(res.cb_generate_etag);
    if (mrb_integer_p(v)) return halt_of(v, res.cb_generate_etag.sym);
    if (mrb_nil_p(v) || mrb_false_p(v)) return -1;
    if (!mrb_string_p(v)) v = mrb_obj_as_string(mrb, v);
    http::etag_spell(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)), res.etag_value);
    res.etag_present = true;
    return -1;
  };

  // cb.rb last_modified/expires: asked at most once - a Time answers via
  // to_i, an Integer is the epoch, nil is not present.
  const auto epoch_memo = [&](const Resource::ValueCb& cb, bool* asked, bool* present,
                              int64_t* epoch) {
    if (*asked) return;
    *asked = true;
    if (!cb.has) return;
    mrb_value v = cbv(cb);
    if (mrb_nil_p(v) || mrb_false_p(v)) return;
    if (!mrb_integer_p(v)) v = mrb_funcall_argv(mrb, v, MRB_SYM(to_i), 0, nullptr);
    if (WM_RES_UNLIKELY(!mrb_integer_p(v))) {
      mrb_raisef(mrb, E_TYPE_ERROR, "%s must answer a Time or an epoch Integer",
                 mrb_sym_name(mrb, cb.sym));
    }
    *epoch = static_cast<int64_t>(mrb_integer(v));
    *present = true;
  };

  // RFC 9110 5.6.7: one dated field, IMF-fixdate.
  const auto date_line = [&](const char* name, size_t nlen, int64_t epoch) {
    struct tm tmv {};
    const time_t t = static_cast<time_t>(epoch);
    gmtime_r(&t, &tmv);
    char buf[http::kDateLen];
    http::date_core(buf, tmv);
    field(name, nlen, buf, http::kDateLen);
  };

  // helpers.rb add_caching_headers: ETag, Expires, Last-Modified.
  const auto add_caching = [&]() -> int {
    const int h = ensure_etag();
    if (h >= 0) return h;
    if (res.etag_present) {
      field("ETag", 4, res.etag_value.data(), res.etag_value.size());
    }
    epoch_memo(res.cb_expires, &res.expires_asked, &res.expires_present, &res.expires_epoch);
    if (res.expires_present) date_line("Expires", 7, res.expires_epoch);
    epoch_memo(res.cb_last_modified, &res.last_modified_asked, &res.last_modified_present,
               &res.last_modified_epoch);
    if (res.last_modified_present) date_line("Last-Modified", 13, res.last_modified_epoch);
    return -1;
  };

  // helpers.rb accept_helper: the request's Content-Type against
  // content_types_accepted - exact, type/* or */* - then yield the handler.
  // MediaType#match?: every parameter the accepted type carries must be
  // present with an equal value in the request's Content-Type.
  const auto param_find = [](const char* s, size_t n, const char* key, size_t kn,
                             const char** vout, size_t* vn) -> bool {
    size_t i = 0;
    while (i < n && s[i] != ';') i++;
    while (i < n) {
      i++;
      while (i < n && (s[i] == ' ' || s[i] == '\t')) i++;
      size_t ks = i;
      while (i < n && s[i] != '=' && s[i] != ';') i++;
      size_t ke = i;
      while (ke > ks && (s[ke - 1] == ' ' || s[ke - 1] == '\t')) ke--;
      const char* v = nullptr;
      size_t vlen = 0;
      if (i < n && s[i] == '=') {
        i++;
        size_t vs = i;
        while (i < n && s[i] != ';') i++;
        size_t vend = i;
        while (vend > vs && (s[vend - 1] == ' ' || s[vend - 1] == '\t')) vend--;
        v = s + vs;
        vlen = vend - vs;
      }
      if (ci_eq(s + ks, ke - ks, key, kn)) {
        *vout = v;
        *vn = vlen;
        return true;
      }
    }
    return false;
  };
  const auto accept_helper = [&]() -> int {
    const char* ct = "application/octet-stream";
    size_t ct_full = 24;
    if (vals != nullptr && vals->content_type != nullptr) {
      ct = vals->content_type;
      ct_full = vals->content_type_len;
    }
    size_t ctn = 0;
    while (ctn < ct_full && ct[ctn] != ';') ctn++;
    while (ctn > 0 && (ct[ctn - 1] == ' ' || ct[ctn - 1] == '\t')) ctn--;
    if (!res.cb_content_types_accepted.has) return 415;
    const mrb_value v = cbv(res.cb_content_types_accepted);
    if (WM_RES_UNLIKELY(!mrb_array_p(v))) {
      mrb_raise(mrb, E_WM_ERROR(mrb),
                "content_types_accepted must answer [[type, Symbol]] pairs");
    }
    for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
      const mrb_value pair = RARRAY_PTR(v)[j];
      if (WM_RES_UNLIKELY(!mrb_array_p(pair) || RARRAY_LEN(pair) < 2 ||
                          !mrb_string_p(RARRAY_PTR(pair)[0]) ||
                          !mrb_symbol_p(RARRAY_PTR(pair)[1]))) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_accepted pairs are [String, Symbol]");
      }
      const char* pt = RSTRING_PTR(RARRAY_PTR(pair)[0]);
      const size_t pt_full = static_cast<size_t>(RSTRING_LEN(RARRAY_PTR(pair)[0]));
      size_t pn = 0;
      while (pn < pt_full && pt[pn] != ';') pn++;
      while (pn > 0 && (pt[pn - 1] == ' ' || pt[pn - 1] == '\t')) pn--;
      bool hit;
      if (pn == 3 && pt[0] == '*' && pt[1] == '/' && pt[2] == '*') {
        hit = true;
      } else if (pn >= 2 && pt[pn - 1] == '*' && pt[pn - 2] == '/') {
        size_t slash = 0;
        while (slash < ctn && ct[slash] != '/') slash++;
        hit = slash == pn - 2 && ci_eq(pt, pn - 2, ct, slash);
      } else {
        hit = ci_eq(pt, pn, ct, ctn);
      }
      if (hit && pn < pt_full) {
        size_t i = pn;
        while (i < pt_full && pt[i] != ';') i++;
        while (hit && i < pt_full) {
          i++;
          while (i < pt_full && (pt[i] == ' ' || pt[i] == '\t')) i++;
          size_t ks = i;
          while (i < pt_full && pt[i] != '=' && pt[i] != ';') i++;
          size_t ke = i;
          while (ke > ks && (pt[ke - 1] == ' ' || pt[ke - 1] == '\t')) ke--;
          const char* pv = nullptr;
          size_t pvn = 0;
          if (i < pt_full && pt[i] == '=') {
            i++;
            size_t vs = i;
            while (i < pt_full && pt[i] != ';') i++;
            size_t vend = i;
            while (vend > vs && (pt[vend - 1] == ' ' || pt[vend - 1] == '\t')) vend--;
            pv = pt + vs;
            pvn = vend - vs;
          }
          if (ke == ks) continue;
          const char* rv = nullptr;
          size_t rvn = 0;
          hit = param_find(ct, ct_full, pt + ks, ke - ks, &rv, &rvn) &&
                rvn == pvn && (pvn == 0 || std::memcmp(rv, pv, pvn) == 0);
        }
      }
      if (!hit) continue;
      const mrb_sym hs = mrb_symbol(RARRAY_PTR(pair)[1]);
      const mrb_value r = mrb_funcall_argv(mrb, res.live, hs, 0, nullptr);
      if (mrb_integer_p(r)) return halt_of(r, hs);
      return -1;
    }
    return 415;
  };

  // flow.rb n11: post_is_create?/create_path/base_uri or process_post; the
  // 303 answer needs a Location the run already set.
  const auto run_n11 = [&]() -> int {
    mrb_value pic = mrb_false_value();
    if (res.cb_post_is_create.has) pic = cbv(res.cb_post_is_create);
    if (mrb_test(pic)) {
      if (WM_RES_UNLIKELY(!res.cb_create_path.has)) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "post_is_create? is true but create_path answered nil");
      }
      const mrb_value cp = cbv(res.cb_create_path);
      if (mrb_integer_p(cp)) return halt_of(cp, res.cb_create_path.sym);
      if (WM_RES_UNLIKELY(mrb_nil_p(cp))) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "post_is_create? is true but create_path answered nil");
      }
      if (WM_RES_UNLIKELY(!mrb_string_p(cp))) {
        mrb_raise(mrb, E_TYPE_ERROR, "create_path must answer a String path");
      }
      mrb_value base = mrb_nil_value();
      if (res.cb_base_uri.has) base = cbv(res.cb_base_uri);
      {
        std::string b;
        if (mrb_string_p(base)) {
          b.assign(RSTRING_PTR(base), static_cast<size_t>(RSTRING_LEN(base)));
        } else {
          b.assign("http://");
          if (vals != nullptr && vals->host != nullptr) {
            b.append(vals->host, vals->host_len);
          } else {
            b.append("localhost");
          }
          b.push_back('/');
        }
        std::string uri;
        http::uri_join(b.data(), b.size(), RSTRING_PTR(cp),
                       static_cast<size_t>(RSTRING_LEN(cp)), uri);
        size_t at = 0;
        if (uri.size() >= 8 && uri.compare(0, 4, "http") == 0) {
          const size_t ss = uri.find("://");
          if (ss != std::string::npos) {
            const size_t sl = uri.find('/', ss + 3);
            at = sl == std::string::npos ? uri.size() : sl;
          }
        }
        const size_t plen = http::path_only(uri.data() + at, uri.size() - at);
        res.run_disp_path.assign(uri.data() + at, plen);
        res.run_disp_set = true;
        request_disp_override(uri.data() + at, plen);
        field("Location", 8, uri.data(), uri.size());
      }
      const int h = accept_helper();
      if (h >= 0) return h;
    } else {
      if (WM_RES_UNLIKELY(!res.cb_process_post.has)) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "process_post answered false, which is invalid");
      }
      const mrb_value pp = cbv(res.cb_process_post);
      if (mrb_integer_p(pp)) return halt_of(pp, res.cb_process_post.sym);
      if (WM_RES_UNLIKELY(!mrb_true_p(pp))) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "process_post must answer true or a response code");
      }
    }
    if (res.run_redirect) {
      if (headers_has_location(hdrs)) return 303;
      mrb_raise(mrb, E_WM_ERROR(mrb), "do_redirect requires a Location header");
    }
    return -1;
  };

  Node n = Node::kB13;
  uint16_t status = 0;
  bool halted = false;
  int chosen = 0;

  // fsm.rb run: one step's edge, out of the graph table. Split so the
  // one caller that already holds `f` (the generic node path below,
  // which reads it to check f.kind first) does not pay for a second
  // flow::kFlow[n] lookup of the same node take() would otherwise redo.
  const auto take_edge = [&](const flow::FlowNode& f, bool a) {
    const flow::Target& t = a ? f.on_true : f.on_false;
    if (t.status != 0) {
      status = t.status;
      halted = true;
    } else {
      n = t.node;
    }
  };
  const auto take = [&](bool a) { take_edge(flow::kFlow[static_cast<size_t>(n)], a); };

  while (!halted) {
    switch (n) {
      case Node::kB12: {
        if (!res.cb_known_methods.has) break;
        marshal_methods(res.cb_known_methods);
        take(methods_contain());
        continue;
      }
      case Node::kB10: {
        if (!res.cb_allowed_methods.has) break;
        marshal_methods(res.cb_allowed_methods);
        const bool ok = methods_contain();
        if (!ok) allow_line();
        take(ok);
        continue;
      }
      case Node::kB9a: {
        bool pass = false;
        bool settled = false;
        if ((res.dynamic >> static_cast<size_t>(Node::kB9a)) & 1) {
          const mrb_value v = nodecall(n, 0, nullptr);
          if (mrb_integer_p(v)) {
            status = halt_of(v, res.node_sym[static_cast<size_t>(n)]);
            halted = true;
            continue;
          }
          if (mrb_true_p(v)) {
            pass = true;
            settled = true;
          } else if (mrb_false_p(v)) {
            settled = true;
          }
        }
        if (!settled) pass = content_md5_ok(res);
        if (pass) {
          take(true);
          continue;
        }
        res.run_body->assign("Content-MD5 header does not match request body.");
        res.run_have_body = true;
        status = 400;
        halted = true;
        continue;
      }
      case Node::kB8: {
        if (((res.dynamic >> static_cast<size_t>(Node::kB8)) & 1) == 0) break;
        const size_t i = static_cast<size_t>(Node::kB8);
        mrb_value a = mrb_nil_value();
        if (res.node_argc[i] != 0) a = arg_for(n);
        const mrb_value v = nodecall(n, res.node_argc[i], &a);
        if (mrb_true_p(v)) {
          take(true);
          continue;
        }
        if (mrb_integer_p(v)) {
          status = halt_of(v, res.node_sym[i]);
          halted = true;
          continue;
        }
        if (mrb_string_p(v)) {
          field("WWW-Authenticate", 16, RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
        }
        status = 401;
        halted = true;
        continue;
      }
      case Node::kB3: {
        if (facts.method != flow::Method::kOptions) {
          n = Node::kC3;
          continue;
        }
        if (res.cb_options.has) {
          const mrb_value v = cbv(res.cb_options);
          if (WM_RES_UNLIKELY(!mrb_hash_p(v))) {
            mrb_raise(mrb, E_TYPE_ERROR, "options must answer a Hash of header fields");
          }
          const mrb_value keys = mrb_hash_keys(mrb, v);
          for (mrb_int j = 0; j < RARRAY_LEN(keys); j++) {
            const mrb_value key = RARRAY_PTR(keys)[j];
            const mrb_value val = mrb_hash_get(mrb, v, key);
            if (!mrb_string_p(key) || !mrb_string_p(val)) continue;
            field(RSTRING_PTR(key), static_cast<size_t>(RSTRING_LEN(key)), RSTRING_PTR(val),
                  static_cast<size_t>(RSTRING_LEN(val)));
          }
        } else {
          allow_line();
        }
        status = 200;
        halted = true;
        continue;
      }
      case Node::kC3: {
        marshal_ct();
        if (WM_RES_UNLIKELY(active_ct().empty())) {
          mrb_raise(mrb, E_WM_ERROR(mrb), "content_types_provided answered no pairs");
        }
        if (!facts.has_accept) {
          chosen = 0;
          if (ct_dyn) {
            res.run_content_type = active_ct()[0].type;
          }
          n = Node::kD4;
          continue;
        }
        n = Node::kC4;
        continue;
      }
      case Node::kC4: {
        const std::vector<Resource::TypedHandler>& cts = active_ct();
        int idx = -1;
        {
          std::vector<std::string> names;
          names.reserve(cts.size());
          for (const Resource::TypedHandler& th : cts) names.push_back(th.type);
          idx = http::choose_media_type(names.data(), names.size(),
                                        vals != nullptr ? vals->accept : nullptr,
                                        vals != nullptr ? vals->accept_len : 0);
        }
        if (idx < 0) {
          status = 406;
          halted = true;
          continue;
        }
        chosen = idx;
        if (idx != 0 || ct_dyn) {
          res.run_content_type = cts[static_cast<size_t>(idx)].type;
        }
        n = Node::kD4;
        continue;
      }
      case Node::kG7: {
        if (res.cb_variances.has) {
          const mrb_value v = cbv(res.cb_variances);
          if (WM_RES_UNLIKELY(!mrb_array_p(v))) {
            mrb_raise(mrb, E_TYPE_ERROR, "variances must answer an Array of Strings");
          }
          res.run_variances.clear();
          for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
            const mrb_value s = RARRAY_PTR(v)[j];
            if (mrb_string_p(s)) {
              res.run_variances.emplace_back(RSTRING_PTR(s),
                                             static_cast<size_t>(RSTRING_LEN(s)));
            }
          }
        }
        const bool accept_varies = active_ct().size() > 1;
        if (accept_varies || !res.run_variances.empty()) {
          field_list("Vary", 4, accept_varies ? "Accept" : nullptr, accept_varies ? 6 : 0,
                     res.run_variances);
        }
        break;
      }
      case Node::kG11: {
        const int h = ensure_etag();
        if (h >= 0) {
          status = static_cast<uint16_t>(h);
          halted = true;
          continue;
        }
        take(res.etag_present && vals != nullptr && vals->if_match != nullptr &&
             http::etag_list_match(vals->if_match, vals->if_match_len, res.etag_value.data(),
                                   res.etag_value.size(), false));
        continue;
      }
      case Node::kK13: {
        const int h = ensure_etag();
        if (h >= 0) {
          status = static_cast<uint16_t>(h);
          halted = true;
          continue;
        }
        take(res.etag_present && vals != nullptr && vals->if_none_match != nullptr &&
             http::etag_list_match(vals->if_none_match, vals->if_none_match_len,
                                   res.etag_value.data(), res.etag_value.size(), true));
        continue;
      }
      case Node::kH12: {
        epoch_memo(res.cb_last_modified, &res.last_modified_asked, &res.last_modified_present,
                   &res.last_modified_epoch);
        take(res.last_modified_present && vals != nullptr &&
             res.last_modified_epoch > vals->if_unmodified_since_epoch);
        continue;
      }
      case Node::kL17: {
        epoch_memo(res.cb_last_modified, &res.last_modified_asked, &res.last_modified_present,
                   &res.last_modified_epoch);
        take(!res.last_modified_present || vals == nullptr ||
             res.last_modified_epoch > vals->if_modified_since_epoch);
        continue;
      }
      case Node::kI4:
      case Node::kK5:
      case Node::kL5: {
        const Resource::ValueCb& cb =
            n == Node::kL5 ? res.cb_moved_temporarily : res.cb_moved_permanently;
        if (!cb.has) break;
        const mrb_value v = cbv(cb);
        if (mrb_string_p(v)) {
          field("Location", 8, RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
          status = n == Node::kL5 ? 307 : 301;
          halted = true;
          continue;
        }
        if (mrb_integer_p(v)) {
          status = halt_of(v, cb.sym);
          halted = true;
          continue;
        }
        take(false);
        continue;
      }
      case Node::kN11: {
        const int h = run_n11();
        if (h >= 0) {
          status = static_cast<uint16_t>(h);
          halted = true;
        } else {
          n = Node::kP11;
        }
        continue;
      }
      case Node::kO14:
      case Node::kP3: {
        const size_t i = static_cast<size_t>(n);
        bool conflict;
        if ((res.dynamic >> i) & 1) {
          const mrb_value v = nodecall(n, 0, nullptr);
          if (mrb_integer_p(v)) {
            status = halt_of(v, res.node_sym[i]);
            halted = true;
            continue;
          }
          conflict = mrb_test(v);
        } else {
          conflict = k.ans[i];
        }
        if (conflict) {
          status = 409;
          halted = true;
          continue;
        }
        const int h = accept_helper();
        if (h >= 0) {
          status = static_cast<uint16_t>(h);
          halted = true;
        } else {
          n = Node::kP11;
        }
        continue;
      }
      case Node::kO18: {
        if (facts.method == flow::Method::kGet || facts.method == flow::Method::kHead) {
          const int h = add_caching();
          if (h >= 0) {
            status = static_cast<uint16_t>(h);
            halted = true;
            continue;
          }
          const std::vector<Resource::TypedHandler>& cts = active_ct();
          const size_t idx =
              static_cast<size_t>(chosen) < cts.size() ? static_cast<size_t>(chosen) : 0;
          const Resource::TypedHandler& th = cts[idx];
          const bool prebuilt = !ct_dyn && idx == 0 && !res.dynamic_body;
          if (!prebuilt) {
            mrb_value v;
            if (!MRB_METHOD_UNDEF_P(th.m)) {
              v = naked(th.m, th.fast, th.handler);
            } else if (ct_dyn) {
              v = mrb_funcall_argv(mrb, res.live, th.handler, 0, nullptr);
            } else {
              v = mrb_funcall_argv(mrb, mrb_obj_value(res.klass), th.handler, 0, nullptr);
            }
            if (mrb_integer_p(v)) {
              status = halt_of(v, th.handler);
              halted = true;
              continue;
            }
            if (WM_RES_UNLIKELY(!mrb_string_p(v))) {
              mrb_raise(mrb, E_TYPE_ERROR, "the body handler must return a String");
            }
            // response.file= already named the answer - this String (the
            // handler's own '' by convention) is dead on arrival, so
            // neither the freeze+register interlock nor the copy is worth
            // taking. The caller reads run_have_file first and never looks
            // at run_body/run_have_body for this run.
            if (!res.run_have_file) {
              const size_t blen = static_cast<size_t>(RSTRING_LEN(v));
              // Already frozen means the app kept this String, so a second
              // connection may be holding it too - and the release would
              // lift a freeze that was not ours. Our own freeze is
              // therefore also the interlock: one lend per String at a
              // time, everything else copies.
              if (res.run_zc_min != 0 && blen >= res.run_zc_min &&
                  !mrb_frozen_p(mrb_basic_ptr(v))) {
                // Frozen so mrb_str_modify cannot realloc the bytes out
                // from under a send in flight, rooted so the GC cannot
                // take them; the writer hands RSTRING_PTR straight to the
                // kernel.
                mrb_obj_freeze(mrb, v);
                mrb_gc_register(mrb, v);
                res.run_zc = v;
                res.run_zc_have = true;
                res.run_body->clear();
              } else {
                res.run_body->assign(RSTRING_PTR(v), blen);
              }
              res.run_have_body = true;
            }
          }
        }
        n = Node::kO18b;
        continue;
      }
      case Node::kO20: {
        take(res.run_have_body);
        continue;
      }
      case Node::kP11: {
        take(headers_has_location(hdrs));
        continue;
      }
      default:
        break;
    }

    const flow::FlowNode& f = flow::kFlow[static_cast<size_t>(n)];
    bool ans;
    if (f.kind == flow::Kind::kRequest) {
      ans = flow::eval_request(n, facts);
    } else if ((res.dynamic >> static_cast<size_t>(n)) & 1) {
      const size_t i = static_cast<size_t>(n);
      mrb_value a = mrb_nil_value();
      if (res.node_argc[i] != 0) a = arg_for(n);
      const mrb_value v = nodecall(n, res.node_argc[i], &a);
      // ANY callback may answer with an Integer, and then that integer
      // IS the response status - webmachine-ruby's own convention.
      if (WM_RES_UNLIKELY(mrb_integer_p(v))) {
        status = halt_of(v, res.node_sym[i]);
        halted = true;
        continue;
      }
      ans = mrb_test(v);
    } else {
      ans = k.ans[static_cast<size_t>(n)];
    }
    take_edge(f, ans);
  }

  // fsm.rb respond: a 304 sheds Content-Type at the writer and carries the
  // caching headers; finish_request runs LAST and may rename the status
  // through response.code=.
  if (status == 304) {
    const int h = add_caching();
    if (h >= 0) status = static_cast<uint16_t>(h);
  }
  res.run_resp_code = status;
  res.run_status = status;
  if (res.cb_finish_request.has) cbv(res.cb_finish_request);
  res.run_status = res.run_resp_code;
  return mrb_nil_value();
}
}

// RFC 9110: fold one resource class - every konst callback asked once,
// every dynamic callback resolved, the class frozen.
bool resource_fold(mrb_state* mrb, mrb_value klass, Resource& out, char* err, size_t errlen) {
  const int ai = mrb_gc_arena_save(mrb);
  out = Resource{};
  out.mrb = mrb;

  for (const NamedSym& cb : kUnhonored) {
    if (WM_RES_UNLIKELY(resolve(mrb, mrb_class(mrb, klass), cb.sym).defined ||
                        instance_defined(mrb, klass, cb.sym))) {
      std::snprintf(err, errlen,
                    "%s is defined but i18n/charset conversion does not exist in this tree",
                    cb.name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }
  for (const NamedSym& cb : kKonstOnly) {
    if (WM_RES_UNLIKELY(instance_defined(mrb, klass, cb.sym))) {
      std::snprintf(err, errlen, "%s shapes the compiled vectors - declare it konst (def self.%s)",
                    cb.name, cb.name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  bool ans[sizeof(kBools) / sizeof(kBools[0])];
  for (size_t i = 0; i < sizeof(kBools) / sizeof(kBools[0]); i++) {
    const BoolCb& cb = kBools[i];
    ans[i] = cb.defv;
    const Resolved inst = resolve(mrb, mrb_class_ptr(klass), cb.sym);
    if (inst.defined) {
      const size_t at = static_cast<size_t>(cb.node);
      out.dynamic |= uint64_t{1} << at;
      out.node_sym[at] = cb.sym;
      out.node_m[at] = inst.m;
      out.node_fast[at] = inst.fast;
      out.node_argc[at] = argc_of(inst.m, cb.maxargs);
      continue;
    }
    if (WM_RES_UNLIKELY(!ask(mrb, klass, cb.sym, cb.name, cb.defv, &ans[i], err, errlen))) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // flow.rb b8/b9a: value-semantics nodes - instance method into the node
  // tables, a class-only one as an undef slot the engine funcalls on the class.
  for (const NodeValueCb& cb : kNodeValues) {
    const size_t at = static_cast<size_t>(cb.node);
    const Resolved inst = resolve(mrb, mrb_class_ptr(klass), cb.sym);
    if (inst.defined) {
      out.dynamic |= uint64_t{1} << at;
      out.node_sym[at] = cb.sym;
      out.node_m[at] = inst.m;
      out.node_fast[at] = inst.fast;
      out.node_argc[at] = argc_of(inst.m, cb.maxargs);
      continue;
    }
    const Resolved meta = resolve(mrb, mrb_class(mrb, klass), cb.sym);
    if (meta.defined) {
      out.dynamic |= uint64_t{1} << at;
      out.node_sym[at] = cb.sym;
      out.node_fast[at] = false;
      out.node_argc[at] = argc_of(meta.m, cb.maxargs);
    }
  }

  // cb.rb: the value callbacks; known/allowed/content_types_provided keep their konst
  // twin on the class, everything else may live on either side.
  out.cb_known_methods = value_cb(mrb, klass, MRB_SYM(known_methods), 0, false);
  out.cb_allowed_methods = value_cb(mrb, klass, MRB_SYM(allowed_methods), 0, false);
  out.cb_content_types_provided = value_cb(mrb, klass, MRB_SYM(content_types_provided), 0, false);
  out.cb_content_types_accepted = value_cb(mrb, klass, MRB_SYM(content_types_accepted), 0, true);
  out.cb_options = value_cb(mrb, klass, MRB_SYM(options), 0, true);
  out.cb_variances = value_cb(mrb, klass, MRB_SYM(variances), 0, true);
  out.cb_generate_etag = value_cb(mrb, klass, MRB_SYM(generate_etag), 0, true);
  out.cb_last_modified = value_cb(mrb, klass, MRB_SYM(last_modified), 0, true);
  out.cb_expires = value_cb(mrb, klass, MRB_SYM(expires), 0, true);
  out.cb_moved_permanently = value_cb(mrb, klass, MRB_SYM_Q(moved_permanently), 0, true);
  out.cb_moved_temporarily = value_cb(mrb, klass, MRB_SYM_Q(moved_temporarily), 0, true);
  out.cb_post_is_create = value_cb(mrb, klass, MRB_SYM_Q(post_is_create), 0, true);
  out.cb_create_path = value_cb(mrb, klass, MRB_SYM(create_path), 0, true);
  out.cb_base_uri = value_cb(mrb, klass, MRB_SYM(base_uri), 0, true);
  out.cb_process_post = value_cb(mrb, klass, MRB_SYM(process_post), 0, true);
  out.cb_finish_request = value_cb(mrb, klass, MRB_SYM(finish_request), 0, true);
  out.cb_handle_exception = value_cb(mrb, klass, MRB_SYM(handle_exception), 1, true);
  // The fast part: one bit per ValueCb above, set once here so every run
  // asks "does X exist" with one load instead of touching X's own struct.
  out.cb_mask = 0;
  if (out.cb_known_methods.has) out.cb_mask |= Resource::kCbKnownMethods;
  if (out.cb_allowed_methods.has) out.cb_mask |= Resource::kCbAllowedMethods;
  if (out.cb_content_types_provided.has) out.cb_mask |= Resource::kCbContentTypesProvided;
  if (out.cb_content_types_accepted.has) out.cb_mask |= Resource::kCbContentTypesAccepted;
  if (out.cb_options.has) out.cb_mask |= Resource::kCbOptions;
  if (out.cb_variances.has) out.cb_mask |= Resource::kCbVariances;
  if (out.cb_generate_etag.has) out.cb_mask |= Resource::kCbGenerateEtag;
  if (out.cb_last_modified.has) out.cb_mask |= Resource::kCbLastModified;
  if (out.cb_expires.has) out.cb_mask |= Resource::kCbExpires;
  if (out.cb_moved_permanently.has) out.cb_mask |= Resource::kCbMovedPermanently;
  if (out.cb_moved_temporarily.has) out.cb_mask |= Resource::kCbMovedTemporarily;
  if (out.cb_post_is_create.has) out.cb_mask |= Resource::kCbPostIsCreate;
  if (out.cb_create_path.has) out.cb_mask |= Resource::kCbCreatePath;
  if (out.cb_base_uri.has) out.cb_mask |= Resource::kCbBaseUri;
  if (out.cb_process_post.has) out.cb_mask |= Resource::kCbProcessPost;
  if (out.cb_finish_request.has) out.cb_mask |= Resource::kCbFinishRequest;
  if (out.cb_handle_exception.has) out.cb_mask |= Resource::kCbHandleException;
  // kC3 is a request-kind node: its dynamic bit forces the run tier without
  // touching any konst answer.
  if (out.cb_mask != 0) out.dynamic |= uint64_t{1} << static_cast<size_t>(Node::kC3);

  std::string content_type = "text/html";
  {
    const Resolved ct = resolve(mrb, mrb_class(mrb, klass), MRB_SYM(content_type));
    if (ct.defined) {
      const mrb_value v = call_resolved(mrb, ct, MRB_SYM(content_type), klass,
                                        mrb_class(mrb, klass));
      if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_string_p(v))) {
        mrb->exc == nullptr
            ? static_cast<void>(std::snprintf(err, errlen, "content_type must return a String"))
            : exc_into(mrb, "content_type", err, errlen);
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      content_type.assign(RSTRING_PTR(v), RSTRING_LEN(v));
    }
  }

  // cb.rb content_types_provided: the konst pairs; a class-level answer
  // wins, otherwise [[content_type-or-text/html, :to_html]].
  {
    const Resolved ctp = resolve(mrb, mrb_class(mrb, klass), MRB_SYM(content_types_provided));
    if (ctp.defined) {
      const mrb_value v = call_resolved(mrb, ctp, MRB_SYM(content_types_provided), klass,
                                        mrb_class(mrb, klass));
      if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
        exc_into(mrb, "content_types_provided", err, errlen);
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      if (WM_RES_UNLIKELY(!mrb_array_p(v) || RARRAY_LEN(v) == 0)) {
        std::snprintf(err, errlen,
                      "content_types_provided must return [[type, handler]] pairs");
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      for (mrb_int j = 0; j < RARRAY_LEN(v); j++) {
        const mrb_value pair = RARRAY_PTR(v)[j];
        if (WM_RES_UNLIKELY(!mrb_array_p(pair) || RARRAY_LEN(pair) < 2 ||
                            !mrb_string_p(RARRAY_PTR(pair)[0]) ||
                            !mrb_symbol_p(RARRAY_PTR(pair)[1]))) {
          std::snprintf(err, errlen, "content_types_provided pairs are [String, Symbol]");
          mrb_gc_arena_restore(mrb, ai);
          return false;
        }
        Resource::TypedHandler th;
        th.type.assign(RSTRING_PTR(RARRAY_PTR(pair)[0]),
                       static_cast<size_t>(RSTRING_LEN(RARRAY_PTR(pair)[0])));
        th.handler = mrb_symbol(RARRAY_PTR(pair)[1]);
        const Resolved hr = resolve(mrb, mrb_class_ptr(klass), th.handler);
        if (hr.defined) {
          th.m = hr.m;
          th.fast = hr.fast;
        }
        out.content_types_provided.push_back(std::move(th));
      }
    } else {
      Resource::TypedHandler th;
      th.type = content_type;
      th.handler = MRB_SYM(to_html);
      const Resolved hr = resolve(mrb, mrb_class_ptr(klass), MRB_SYM(to_html));
      if (hr.defined) {
        th.m = hr.m;
        th.fast = hr.fast;
      }
      out.content_types_provided.push_back(std::move(th));
    }
  }

  {
    const Resolved enc = resolve(mrb, mrb_class(mrb, klass), MRB_SYM(encodings_provided));
    if (enc.defined) {
      const mrb_value v = call_resolved(mrb, enc, MRB_SYM(encodings_provided), klass,
                                        mrb_class(mrb, klass));
      if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_hash_p(v))) {
        mrb->exc == nullptr
            ? static_cast<void>(
                  std::snprintf(err, errlen, "encodings_provided must return a Hash"))
            : exc_into(mrb, "encodings_provided", err, errlen);
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      out.gzip_offered = mrb_hash_key_p(mrb, v, mrb_str_new_lit(mrb, "gzip"));
    }
  }

  // helpers.rb encode_body: the default body path - content_types_provided[0]'s handler
  // pre-renders when it lives on the class, runs per request when it is an
  // instance method.
  {
    const Resource::TypedHandler& first = out.content_types_provided[0];
    const Resolved body_k = resolve(mrb, mrb_class(mrb, klass), first.handler);
    if (body_k.defined) {
      const mrb_value rendered =
          call_resolved(mrb, body_k, first.handler, klass, mrb_class(mrb, klass));
      if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_string_p(rendered))) {
        mrb->exc == nullptr
            ? static_cast<void>(std::snprintf(err, errlen, "the body handler must return a String"))
            : exc_into(mrb, "body handler raised", err, errlen);
        mrb_gc_arena_restore(mrb, ai);
        return false;
      }
      out.konst.body.assign(RSTRING_PTR(rendered), RSTRING_LEN(rendered));
    } else if (!MRB_METHOD_UNDEF_P(first.m)) {
      out.dynamic_body = true;
      out.body_sym = first.handler;
      out.body_m = first.m;
      out.body_fast = first.fast;
    }
  }
  out.konst.content_type = out.content_types_provided[0].type;

  bool known[7] = {true, true, true, true, true, true, false};
  if (!out.cb_known_methods.has &&
      WM_RES_UNLIKELY(!ask_methods(mrb, klass, MRB_SYM(known_methods), "known_methods", known,
                                   err, errlen))) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  bool allowed[7] = {true, true, false, false, false, false, false};
  if (!out.cb_allowed_methods.has &&
      WM_RES_UNLIKELY(!ask_methods(mrb, klass, MRB_SYM(allowed_methods), "allowed_methods",
                                   allowed, err, errlen))) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }

  out.konst.allow.clear();
  for (uint8_t m = 0; m < 6; m++) {
    if (allowed[m]) {
      if (!out.konst.allow.empty()) out.konst.allow.append(", ");
      out.konst.allow.append(kMethodName[m]);
    }
  }
  for (uint8_t m = 0; m < 7; m++) {
    flow::KonstAnswers& k = out.konst.per_method[m];
    k.ans[static_cast<size_t>(Node::kB12)] = known[m];
    k.ans[static_cast<size_t>(Node::kB10)] = allowed[m];
    for (size_t i = 0; i < sizeof(kBools) / sizeof(kBools[0]); i++) {
      k.ans[static_cast<size_t>(kBools[i].node)] = ans[i];
    }
  }
  out.konst.resolve_shortcuts();

  out.klass = mrb_class_ptr(klass);
  mrb_obj_freeze(mrb, klass);

  // What building the per-request instance costs, decided once: the
  // allocation's type, and whether the author wrote an initialize at all.
  // Object's is undef'd on Webmachine::Resource (see gem_init), so this is
  // a plain "is it defined" and no longer a comparison against a method
  // every object has.
  out.live_tt = MRB_INSTANCE_TT(out.klass) != 0 ? MRB_INSTANCE_TT(out.klass) : MRB_TT_OBJECT;
  const Resolved init = resolve(mrb, out.klass, MRB_SYM(initialize));
  out.init_needed = init.defined;
  out.init_m = init.m;
  out.init_fast = init.fast;
  mrb_gc_arena_restore(mrb, ai);
  return true;
}

// RFC 9110: decision + render for one request inside one bound frame; the
// respond order is fsm.rb's - halt seeds the code, finish_request may rename
// it, handle_exception owns the raise path when the app declared it.
uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts,
                      const http::ReqValues* vals, const ReqView* req, std::string* body,
                      bool* have_body, std::string* headers, size_t zc_min) {
  mrb_state* mrb = res.mrb;
  request_bind(req);
  response_bind(&res);
  res.run_facts = &facts;
  res.run_vals = vals;
  res.run_req = req;
  res.run_headers = headers;
  headers->clear();
  res.run_body = body;
  res.run_have_body = false;
  res.run_zc_min = zc_min;
  res.run_zc_have = false;
  res.run_status = 0;
  res.run_resp_code = 0;
  res.run_redirect = false;
  res.run_content_type.clear();
  res.run_disp_path.clear();
  res.run_disp_set = false;
  res.run_have_file = false;
  res.run_file_bad = false;
  res.etag_asked = false;
  res.etag_present = false;
  res.etag_value.clear();
  res.last_modified_asked = false;
  res.last_modified_present = false;
  res.last_modified_epoch = 0;
  res.expires_asked = false;
  res.expires_present = false;
  res.expires_epoch = 0;
  res.run_content_types_provided.clear();
  res.run_methods.clear();
  res.run_variances.clear();
  mrb_bool raised = FALSE;
  const mrb_value thrown =
      mrb_protect_error(mrb, run_engine_body, const_cast<Resource*>(&res), &raised);
  uint16_t status = res.run_resp_code;
  // A raise voids whatever the run lent: the rescue path spells its own
  // body, and a root nobody comes back for outlives the process.
  if (WM_RES_UNLIKELY(res.run_zc_have && raised != FALSE)) {
    resource_body_unlend(mrb, res.run_zc);
    res.run_zc_have = false;
  }
  if (WM_RES_UNLIKELY(raised != FALSE)) {
    // fsm.rb: handle_exception owns the raise when the app declared it,
    // and finish_request still runs. Both may raise again, so they get
    // their own guarded frame - the rare path pays for a second one.
    RescueCtx rc = {&res, thrown};
    mrb_bool again = FALSE;
    const mrb_value second = mrb_protect_error(mrb, run_rescue_body, &rc, &again);
    // The writer's contract (resource_exception_begin): with nothing that
    // handled it, the exception is still pending when this returns.
    if (again != FALSE) {
      if (mrb_exception_p(second)) mrb->exc = mrb_obj_ptr(second);
    } else if (!rc.handled && mrb_exception_p(thrown)) {
      mrb->exc = mrb_obj_ptr(thrown);
    }
    status = res.run_resp_code != 0 ? res.run_resp_code : 500;
  }
  request_bind(nullptr);
  response_bind(nullptr);
  res.live = mrb_nil_value();
  res.run_vals = nullptr;
  res.run_req = nullptr;
  res.run_headers = nullptr;
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    if (res.run_zc_have) {
      resource_body_unlend(mrb, res.run_zc);
      res.run_zc_have = false;
    }
    *have_body = false;
    return 500;
  }
  *have_body = res.run_have_body;
  res.run_status = status;
  return status;
}

// The lend window OPENS here for the caller: the run is over, so the value
// has to leave the Resource - the next request through it resets the slot.
bool resource_body_lent(const Resource& res, mrb_value* v, const char** ptr, size_t* len) {
  if (!res.run_zc_have) return false;
  res.run_zc_have = false;
  *v = res.run_zc;
  *ptr = RSTRING_PTR(res.run_zc);
  *len = static_cast<size_t>(RSTRING_LEN(res.run_zc));
  return true;
}

// response.file, handed over the same way: the run is over, so the name
// leaves the Resource before the next request through it resets the slot.
bool resource_file_wanted(const Resource& res, const char** ptr, size_t* len, bool* bad) {
  if (!res.run_have_file) return false;
  res.run_have_file = false;
  *ptr = res.run_file.data();
  *len = res.run_file.size();
  *bad = res.run_file_bad;
  return true;
}

// And it CLOSES here: unrooted so the GC may take it, and the freeze lifted
// - it was ours for the in-flight window, and Ruby has no #unfreeze.
void resource_body_unlend(mrb_state* mrb, mrb_value v) {
  mrb_gc_unregister(mrb, v);
  mrb_basic_ptr(v)->frozen = 0;
}

// RFC 9110 15.6.1: the pending exception's message, lent for the 500 body.
bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len) {
  if (res.mrb->exc == nullptr) return false;
  struct RException* e = reinterpret_cast<struct RException*>(res.mrb->exc);
  res.mrb->exc = nullptr;
  if (e->mesg == nullptr || e->mesg->tt != MRB_TT_STRING) return false;
  const mrb_value mesg = mrb_obj_value(e->mesg);
  *ptr = RSTRING_PTR(mesg);
  *len = static_cast<size_t>(RSTRING_LEN(mesg));
  return true;
}

// mruby: one raise as one error-log record - class, message, backtrace.
void log_exception(Logger& lg, mrb_state* mrb, const void* peer, size_t peer_len,
                   const char* request_target, size_t request_target_len, uint16_t status_code) {
  if (mrb->exc == nullptr) return;
  const mrb_value exc = mrb_obj_value(mrb->exc);
  const char* exception_class = mrb_obj_classname(mrb, exc);
  const char* message = nullptr;
  size_t message_len = 0;
  struct RException* e = reinterpret_cast<struct RException*>(mrb->exc);
  if (e->mesg != nullptr && e->mesg->tt == MRB_TT_STRING) {
    const mrb_value mesg = mrb_obj_value(e->mesg);
    message = RSTRING_PTR(mesg);
    message_len = static_cast<size_t>(RSTRING_LEN(mesg));
  }
  std::string backtrace;
  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value bt = mrb_exc_backtrace(mrb, exc);
  if (mrb_array_p(bt)) {
    const mrb_int n = RARRAY_LEN(bt);
    for (mrb_int i = 0; i < n; i++) {
      const mrb_value f = RARRAY_PTR(bt)[i];
      if (!mrb_string_p(f)) continue;
      if (!backtrace.empty()) backtrace.push_back('\n');
      backtrace.append(RSTRING_PTR(f), static_cast<size_t>(RSTRING_LEN(f)));
    }
  }
  mrb_gc_arena_restore(mrb, ai);
  log_error(lg, peer, peer_len, exception_class, std::strlen(exception_class), request_target,
            request_target_len, status_code, message, message_len, backtrace.data(),
            backtrace.size());
}
}

// #181: a resource instance belongs to ONE request and the server makes it.
// Ruby may not - a route names the CLASS, and C++ allocates from it with
// mrb_obj_alloc. Without this, Resource.new would fail on the undef'd
// initialize with "undefined method", which says nothing about why.
mrb_value resource_new_refused(mrb_state* mrb, mrb_value self) {
  mrb_raise(mrb, E_WM_ERROR(mrb),
            "a resource is the server's to build, one per request - name the class in a "
            "route, never an instance");
  return self;
}

extern "C" {
// mruby: the gem's Ruby surface - the base classes and the loop's three doors.
void mrb_webmachine_mruby_gem_init(mrb_state* mrb) {
  struct RClass* wm = mrb_define_module_id(mrb, MRB_SYM(Webmachine));
  struct RClass* err =
      mrb_define_class_under_id(mrb, wm, MRB_SYM(Error), mrb->eStandardError_class);
  mrb_define_class_under_id(mrb, wm, MRB_SYM(ConfigError), err);
  mrb_define_class_under_id(mrb, wm, MRB_SYM(RouteError), err);
  // mruby: EVERY object carries initialize on the instance, inherited from
  // Object, unless it is undef'd - so "does this resource define one" could
  // never be asked, only "does it differ from Object's". Undef it here and
  // the question becomes the honest one: an initialize on a resource exists
  // exactly when its author wrote it. The fold then stores the resolved
  // method and the run enters it directly; mrb_obj_new is not used at all,
  // because it would search for the same method twice per request.
  // Webmachine::WebsocketResource and SseResource keep theirs: there
  // initialize is the documented open hook, it runs once per connection
  // rather than per request, and sse_open/ws_admit call it unconditionally.
  struct RClass* res_class =
      mrb_define_class_under_id(mrb, wm, MRB_SYM(Resource), mrb->object_class);
  mrb_undef_method_id(mrb, res_class, MRB_SYM(initialize));
  mrb_define_class_method_id(mrb, res_class, MRB_SYM(new), resource_new_refused,
                             MRB_ARGS_ANY());
  webmachine::ws_init(mrb, wm);
  webmachine::sse_init(mrb, wm);
  webmachine::application_init(mrb, wm);
  webmachine::request_init(mrb, wm);
  webmachine::response_init(mrb, wm);
  webmachine::server_init(mrb, wm);
}

// mruby: nothing outlives the VM here.
void mrb_webmachine_mruby_gem_final(mrb_state*) {}
}
