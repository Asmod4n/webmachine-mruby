#include "webmachine.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/proc.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <cstdio>
#include <cstring>
#include <string>

#define WM_RES_UNLIKELY(x) __builtin_expect(!!(x), 0)

extern "C" mrb_value mrb_exc_backtrace(mrb_state* mrb, mrb_value exc);

namespace webmachine {
namespace {
using flow::KonstSet;
using flow::Node;

constexpr const char* kMethodName[6] = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"};

// mruby: a setup raise becomes a named refusal, printed by the VM itself.
// .DESIGN.md #mruby-protect
//   "Setup calls run under protection, request calls do not"
void exc_into(mrb_state* mrb, const char* what, char* err, size_t errlen) {
  std::snprintf(err, errlen, "%s (exception below)", what);
  mrb_print_error(mrb);
  mrb->exc = nullptr;
}

// mruby: unwrap MRB_PROC_ALIAS once, at fold, instead of at every call.
// .DESIGN.md #mruby-resolve "One resolution, one call path"
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
// .DESIGN.md #mruby-resolve "One resolution, one call path"
Resolved resolve(mrb_state* mrb, struct RClass* c, mrb_sym sym) {
  Resolved r;
  struct RClass* owner = c;
  r.m = resolve_alias(mrb_method_search_vm(mrb, &owner, sym));
  r.defined = !MRB_METHOD_UNDEF_P(r.m);
  r.fast = r.defined && !MRB_METHOD_CFUNC_P(r.m);
  return r;
}

// mruby: is this a runtime callback? A direct look into the method table.
// .DESIGN.md #mruby-two-kinds "Two kinds of method, by declaration"
bool instance_defined(mrb_state* mrb, mrb_value klass, mrb_sym sym) {
  return resolve(mrb, mrb_class_ptr(klass), sym).defined;
}

struct SetupCall {
  const struct RProc* proc;
  mrb_sym sym;
  mrb_value self;
  struct RClass* c;
};

// mruby: the yield body a setup call runs under mrb_protect_error.
// .DESIGN.md #mruby-protect
//   "Setup calls run under protection, request calls do not"
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
// .DESIGN.md #mruby-protect
//   "Setup calls run under protection, request calls do not"
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
// .DESIGN.md #mruby-two-kinds "Two kinds of method, by declaration"
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

// RFC 9110 9.1: known_methods / allowed_methods as one String of tokens.
// .DESIGN.md #mruby-refusals
//   "What a resource may not do yet, and says so by name"
bool ask_methods(mrb_state* mrb, mrb_value klass, mrb_sym sym, const char* name, bool present[7],
                 char* err, size_t errlen) {
  const Resolved r = resolve(mrb, mrb_class(mrb, klass), sym);
  if (!r.defined) return true;
  const mrb_value v = call_resolved(mrb, r, sym, klass, mrb_class(mrb, klass));
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    exc_into(mrb, name, err, errlen);
    return false;
  }
  if (WM_RES_UNLIKELY(!mrb_string_p(v))) {
    std::snprintf(err, errlen, "%s must return a String like 'GET HEAD'", name);
    return false;
  }
  for (uint8_t m = 0; m < 7; m++) present[m] = false;
  const char* p = RSTRING_PTR(v);
  const char* end = p + RSTRING_LEN(v);
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
}

struct BoolCb {
  Node node;
  mrb_sym sym;
  const char* name;
  bool defv;
};
const BoolCb kBools[] = {
    {Node::kB13, MRB_SYM_Q(service_available), "service_available?", true},
    {Node::kB11, MRB_SYM_Q(uri_too_long), "uri_too_long?", false},
    {Node::kB9a, MRB_SYM(validate_content_checksum), "validate_content_checksum", true},
    {Node::kB9b, MRB_SYM_Q(malformed_request), "malformed_request?", false},
    {Node::kB7, MRB_SYM_Q(forbidden), "forbidden?", false},
    {Node::kB6, MRB_SYM_Q(valid_content_headers), "valid_content_headers?", true},
    {Node::kB5, MRB_SYM_Q(known_content_type), "known_content_type?", true},
    {Node::kB4, MRB_SYM_Q(valid_entity_length), "valid_entity_length?", true},
    {Node::kG7, MRB_SYM_Q(resource_exists), "resource_exists?", true},
    {Node::kK7, MRB_SYM_Q(previously_existed), "previously_existed?", false},
    {Node::kM7, MRB_SYM_Q(allow_missing_post), "allow_missing_post?", false},
    {Node::kN5, MRB_SYM_Q(allow_missing_post), "allow_missing_post?", false},
    {Node::kM20, MRB_SYM(delete_resource), "delete_resource", false},
    {Node::kM20b, MRB_SYM_Q(delete_completed), "delete_completed?", true},
    {Node::kO14, MRB_SYM_Q(is_conflict), "is_conflict?", false},
    {Node::kP3, MRB_SYM_Q(is_conflict), "is_conflict?", false},
    {Node::kO18b, MRB_SYM_Q(multiple_choices), "multiple_choices?", false},
};

struct NamedSym {
  mrb_sym sym;
  const char* name;
};
const NamedSym kUnhonored[] = {
    {MRB_SYM(content_types_provided), "content_types_provided"},
    {MRB_SYM(languages_provided), "languages_provided"},
    {MRB_SYM(charsets_provided), "charsets_provided"},
    {MRB_SYM(generate_etag), "generate_etag"},
    {MRB_SYM(last_modified), "last_modified"},
    {MRB_SYM(options), "options"},
    {MRB_SYM(create_path), "create_path"},
    {MRB_SYM(process_post), "process_post"},
    {MRB_SYM(content_types_accepted), "content_types_accepted"},
    {MRB_SYM(base_uri), "base_uri"},
    {MRB_SYM(expires), "expires"},
    {MRB_SYM(variances), "variances"},
};
const NamedSym kKonstOnly[] = {
    {MRB_SYM(known_methods), "known_methods"},
    {MRB_SYM(allowed_methods), "allowed_methods"},
    {MRB_SYM(content_type), "content_type"},
    {MRB_SYM(encodings_provided), "encodings_provided"},
    {MRB_SYM_Q(is_authorized), "is_authorized?"},
    {MRB_SYM_Q(moved_permanently), "moved_permanently?"},
    {MRB_SYM_Q(moved_temporarily), "moved_temporarily?"},
};

// RFC 9110: THE runtime tier - the whole flow inside one VM frame.
// .DESIGN.md #mruby-run-frame "The run frame is the memory model"
mrb_value run_cfunc(mrb_state* mrb, mrb_value) {
  const Resource& res = *static_cast<const Resource*>(mrb_cptr(mrb_proc_cfunc_env_get(mrb, 0)));
  res.live = mrb_obj_new(mrb, res.klass, 0, nullptr);
  const flow::ReqFacts& facts = *res.run_facts;
  const flow::KonstAnswers& k = res.konst.per_method[static_cast<size_t>(facts.method)];
  const auto naked = [&](mrb_method_t m, bool fast, mrb_sym sym) -> mrb_value {
    if (WM_RES_UNLIKELY(!fast || mrb_obj_ptr(res.live)->c != res.klass)) {
      return mrb_funcall_argv(mrb, res.live, sym, 0, nullptr);
    }
    mrb_callinfo* ci = mrb->c->ci;
    const mrb_sym saved = ci->mid;
    ci->mid = sym;
    mrb_value r = mrb_yield_with_class(
        mrb, mrb_obj_value(const_cast<struct RProc*>(MRB_METHOD_PROC(m))), 0, nullptr, res.live,
        res.klass);
    ci->mid = saved;
    return r;
  };

  flow::Node n = flow::Node::kB13;
  uint16_t status = 0;
  for (;;) {
    const flow::FlowNode& f = flow::kFlow[static_cast<size_t>(n)];
    bool ans;
    if (f.kind == flow::Kind::kRequest) {
      ans = flow::eval_request(n, facts);
    } else if ((res.dynamic >> static_cast<size_t>(n)) & 1) {
      const size_t i = static_cast<size_t>(n);
      ans = mrb_test(naked(res.node_m[i], res.node_fast[i], res.node_sym[i]));
    } else {
      ans = k.ans[static_cast<size_t>(n)];
    }
    const flow::Target& t = ans ? f.on_true : f.on_false;
    if (t.status != 0) {
      status = t.status;
      break;
    }
    n = t.node;
  }
  if (status == 200 && res.dynamic_body) {
    const mrb_value v = naked(res.body_m, res.body_fast, res.body_sym);
    if (WM_RES_UNLIKELY(!mrb_string_p(v))) {
      mrb_raise(mrb, E_TYPE_ERROR, "the body handler must return a String");
    }
    res.run_body->assign(RSTRING_PTR(v), RSTRING_LEN(v));
    res.run_have_body = true;
  }
  res.run_status = status;
  return mrb_nil_value();
}
}

// RFC 9110: fold one resource class - every konst callback asked once,
// every dynamic callback resolved, the class frozen.
// .DESIGN.md #mruby-lifetime "Resource lifetime: one request"
bool resource_fold(mrb_state* mrb, mrb_value klass, Resource& out, char* err, size_t errlen) {
  const int ai = mrb_gc_arena_save(mrb);
  out = Resource{};
  out.mrb = mrb;

  for (const NamedSym& cb : kUnhonored) {
    if (WM_RES_UNLIKELY(resolve(mrb, mrb_class(mrb, klass), cb.sym).defined ||
                        instance_defined(mrb, klass, cb.sym))) {
      std::snprintf(err, errlen, "%s is defined but no tier can honor it yet", cb.name);
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
      out.dynamic |= uint64_t{1} << static_cast<size_t>(cb.node);
      out.node_sym[static_cast<size_t>(cb.node)] = cb.sym;
      out.node_m[static_cast<size_t>(cb.node)] = inst.m;
      out.node_fast[static_cast<size_t>(cb.node)] = inst.fast;
      continue;
    }
    if (WM_RES_UNLIKELY(!ask(mrb, klass, cb.sym, cb.name, cb.defv, &ans[i], err, errlen))) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  bool authorized = true;
  if (WM_RES_UNLIKELY(!ask(mrb, klass, MRB_SYM_Q(is_authorized), "is_authorized?", true,
                           &authorized, err, errlen))) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  if (WM_RES_UNLIKELY(!authorized)) {
    std::snprintf(err, errlen, "is_authorized? not returning true needs a later tier");
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  const NamedSym kMoved[] = {
      {MRB_SYM_Q(moved_permanently), "moved_permanently?"},
      {MRB_SYM_Q(moved_temporarily), "moved_temporarily?"},
  };
  for (const NamedSym& cb : kMoved) {
    bool moved = false;
    if (WM_RES_UNLIKELY(!ask(mrb, klass, cb.sym, cb.name, false, &moved, err, errlen))) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    if (WM_RES_UNLIKELY(moved)) {
      std::snprintf(err, errlen, "%s with a Location is not representable yet", cb.name);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

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

  const Resolved body_k = resolve(mrb, mrb_class(mrb, klass), MRB_SYM(to_html));
  const Resolved body_i = resolve(mrb, mrb_class_ptr(klass), MRB_SYM(to_html));
  if (body_k.defined) {
    const mrb_value rendered =
        call_resolved(mrb, body_k, MRB_SYM(to_html), klass, mrb_class(mrb, klass));
    if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_string_p(rendered))) {
      mrb->exc == nullptr
          ? static_cast<void>(std::snprintf(err, errlen, "the body handler must return a String"))
          : exc_into(mrb, "body handler raised", err, errlen);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    out.konst.body.assign(RSTRING_PTR(rendered), RSTRING_LEN(rendered));
  } else if (body_i.defined) {
    out.dynamic_body = true;
    out.body_sym = MRB_SYM(to_html);
    out.body_m = body_i.m;
    out.body_fast = body_i.fast;
  }
  out.konst.content_type = content_type;

  out.klass = mrb_class_ptr(klass);
  mrb_obj_freeze(mrb, klass);

  if (out.dynamic != 0 || out.dynamic_body) {
    struct RClass* hidden = mrb_class_new(mrb, mrb->object_class);
    const mrb_value env = mrb_cptr_value(mrb, &out);
    struct RProc* run_proc = mrb_proc_new_cfunc_with_env(mrb, run_cfunc, 1, &env);
    mrb_method_t m;
    MRB_METHOD_FROM_PROC(m, run_proc);
    mrb_define_method_raw(mrb, hidden, MRB_SYM(call), m);
    out.run_self = mrb_obj_new(mrb, hidden, 0, nullptr);
    mrb_gc_register(mrb, out.run_self);
  }

  bool known[7] = {true, true, true, true, true, true, false};
  if (WM_RES_UNLIKELY(!ask_methods(mrb, klass, MRB_SYM(known_methods), "known_methods", known,
                                   err, errlen))) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  bool allowed[7] = {true, true, false, false, false, false, false};
  if (WM_RES_UNLIKELY(!ask_methods(mrb, klass, MRB_SYM(allowed_methods), "allowed_methods",
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
  mrb_gc_arena_restore(mrb, ai);
  return true;
}

// RFC 9110: decision + render for one request; a raise leaves 500 pending.
// .DESIGN.md #mruby-run-frame "The run frame is the memory model"
uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts, const ReqView* req,
                      std::string* body, bool* have_body) {
  request_bind(req);
  res.run_facts = &facts;
  res.run_body = body;
  res.run_have_body = false;
  res.run_status = 0;
  mrb_funcall_argv(res.mrb, res.run_self, MRB_SYM(call), 0, nullptr);
  request_bind(nullptr);
  res.live = mrb_nil_value();
  if (WM_RES_UNLIKELY(res.mrb->exc != nullptr)) {
    *have_body = false;
    return 500;
  }
  *have_body = res.run_have_body;
  return res.run_status;
}

// RFC 9110 15.6.1: the pending exception's message, lent for the 500 body.
// .DESIGN.md #mruby-exception "With an exception pending, no funcall"
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
// .DESIGN.md #log-error "What is an error, and what is not"
void log_exception(Logger& lg, mrb_state* mrb, const void* peer, size_t plen, const char* target,
                   size_t tlen, uint16_t status) {
  if (mrb->exc == nullptr) return;
  const mrb_value exc = mrb_obj_value(mrb->exc);
  const char* kn = mrb_obj_classname(mrb, exc);
  const char* mp = nullptr;
  size_t mlen = 0;
  struct RException* e = reinterpret_cast<struct RException*>(mrb->exc);
  if (e->mesg != nullptr && e->mesg->tt == MRB_TT_STRING) {
    const mrb_value mesg = mrb_obj_value(e->mesg);
    mp = RSTRING_PTR(mesg);
    mlen = static_cast<size_t>(RSTRING_LEN(mesg));
  }
  std::string trace;
  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value bt = mrb_exc_backtrace(mrb, exc);
  if (mrb_array_p(bt)) {
    const mrb_int n = RARRAY_LEN(bt);
    for (mrb_int i = 0; i < n; i++) {
      const mrb_value f = RARRAY_PTR(bt)[i];
      if (!mrb_string_p(f)) continue;
      if (!trace.empty()) trace.push_back('\n');
      trace.append(RSTRING_PTR(f), static_cast<size_t>(RSTRING_LEN(f)));
    }
  }
  mrb_gc_arena_restore(mrb, ai);
  log_error(lg, peer, plen, kn, std::strlen(kn), target, tlen, status, mp, mlen, trace.data(),
            trace.size());
}
}

extern "C" {
// mruby: the gem's Ruby surface - the base classes and the loop's three doors.
// .DESIGN.md #app "The application surface"
void mrb_webmachine_mruby_gem_init(mrb_state* mrb) {
  struct RClass* wm = mrb_define_module_id(mrb, MRB_SYM(Webmachine));
  struct RClass* err =
      mrb_define_class_under_id(mrb, wm, MRB_SYM(Error), mrb->eStandardError_class);
  mrb_define_class_under_id(mrb, wm, MRB_SYM(ConfigError), err);
  mrb_define_class_under_id(mrb, wm, MRB_SYM(RouteError), err);
  mrb_define_class_under_id(mrb, wm, MRB_SYM(Resource), mrb->object_class);
  webmachine::ws_init(mrb, wm);
  webmachine::sse_init(mrb, wm);
  webmachine::application_init(mrb, wm);
  webmachine::request_init(mrb, wm);
  webmachine::server_init(mrb, wm);
}

// mruby: nothing outlives the VM here.
// .DESIGN.md #mruby "mruby: the VM as a guest"
void mrb_webmachine_mruby_gem_final(mrb_state*) {}
}
