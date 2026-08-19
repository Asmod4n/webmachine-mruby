#include "resource.hpp"

#include <mruby/class.h>
#include <mruby/compile.h>
#include <mruby/error.h>
#include <mruby/proc.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <cstdio>
#include <cstring>
#include <string>

// Prediction hints only where the taken side is terminal (see ring.hpp).
#define WM_RES_UNLIKELY(x) __builtin_expect(!!(x), 0)

namespace webmachine {
namespace {

using flow::KonstSet;
using flow::Node;

constexpr const char* kMethodName[6] = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"};

// Class#inherited fires when the app writes
// `class Hello < Webmachine::Resource`; the subclass lands in the C
// slot resource_setup parked in mrb->ud - no ivar, no Ruby-side state.
mrb_value resource_inherited(mrb_state* mrb, mrb_value) {
  mrb_value sub;
  mrb_get_args(mrb, "C", &sub);
  if (mrb->ud != nullptr) *static_cast<mrb_value*>(mrb->ud) = sub;
  return mrb_nil_value();
}

void exc_into(mrb_state* mrb, const char* what, char* err, size_t errlen) {
  // The direct variant: mruby prints exception + backtrace to stderr
  // itself; err carries only the context line.
  std::snprintf(err, errlen, "%s (exception below)", what);
  mrb_print_error(mrb);
  mrb->exc = nullptr;
}

// Is `sym` defined as an INSTANCE method (runtime, per request)?
bool instance_defined(mrb_state* mrb, mrb_value klass, mrb_sym sym) {
  mrb_value symv = mrb_symbol_value(sym);
  const mrb_value defined =
      mrb_funcall_argv(mrb, klass, MRB_SYM_Q(method_defined), 1, &symv);
  return mrb->exc == nullptr && mrb_test(defined);
}

// A konst callback, asked once on the CLASS. Absent -> the default
// stands. Raise -> a named refusal (a setup that cannot answer cannot
// serve).
bool ask(mrb_state* mrb, mrb_value klass, mrb_sym sym, const char* name, bool defv, bool* out,
         char* err, size_t errlen) {
  if (!mrb_respond_to(mrb, klass, sym)) {
    *out = defv;
    return true;
  }
  const mrb_value v = mrb_funcall_argv(mrb, klass, sym, 0, nullptr);
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    exc_into(mrb, name, err, errlen);
    return false;
  }
  *out = mrb_test(v);
  return true;
}

// A method list (known_methods / allowed_methods): ONE String like
// 'GET HEAD POST', tokenized here from its bytes - no Ruby arrays
// cross the boundary. Tokens outside the compiled set are refused -
// a method the walker cannot name would silently 501.
bool ask_methods(mrb_state* mrb, mrb_value klass, mrb_sym sym, const char* name, bool present[7],
                 char* err, size_t errlen) {
  if (!mrb_respond_to(mrb, klass, sym)) return true;
  const mrb_value v = mrb_funcall_argv(mrb, klass, sym, 0, nullptr);
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

// Every symbol below is a COMPILE-TIME constant from mruby's presym
// table - the build scans this file - so nothing is ever interned at
// runtime; names ride along solely for error text.

// The boolean flow callbacks: node ans = callback truthiness, exactly
// flow.rb's decision_test orientation, already encoded in the table.
struct BoolCb {
  Node node;
  mrb_sym sym;
  const char* name;
  bool defv;
};
const BoolCb kBools[] = {
    {Node::kB13, MRB_SYM_Q(service_available), "service_available?", true},
    {Node::kB11, MRB_SYM_Q(uri_too_long), "uri_too_long?", false},
    // nil = not validated reads as pass
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
// Callbacks whose VALUES the machine cannot speak yet - konst or
// runtime alike, they refuse the start by name.
const NamedSym kUnhonored[] = {
    // the *_provided pair arrays are value conneg - say content_type
    {MRB_SYM(content_types_provided), "content_types_provided"},
    {MRB_SYM(languages_provided), "languages_provided"},
    {MRB_SYM(charsets_provided), "charsets_provided"},
    {MRB_SYM(encodings_provided), "encodings_provided"},
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
// These shape the compiled vectors or carry values: class methods only.
const NamedSym kKonstOnly[] = {
    {MRB_SYM(known_methods), "known_methods"},
    {MRB_SYM(allowed_methods), "allowed_methods"},
    {MRB_SYM(content_type), "content_type"},
    {MRB_SYM_Q(is_authorized), "is_authorized?"},
    {MRB_SYM_Q(moved_permanently), "moved_permanently?"},
    {MRB_SYM_Q(moved_temporarily), "moved_temporarily?"},
};

// An alias (`alias_method` in the class body) stores a proc carrying
// MRB_PROC_ALIAS whose body holds the aliased-from mid, not an irep;
// vm.c unwraps that at every call site. Unwrapped ONCE here instead -
// the chain is fixed the moment the class freezes.
mrb_method_t resolve_alias(mrb_method_t m) {
  if (MRB_METHOD_UNDEF_P(m) || MRB_METHOD_FUNC_P(m)) return m;
  const struct RProc* p = MRB_METHOD_PROC(m);
  while (p != nullptr && MRB_PROC_ALIAS_P(p)) p = p->upper;  // aliases chain
  if (p == nullptr) return m;
  mrb_method_t out = m;
  MRB_METHOD_FROM_PROC(out, p);
  return out;
}

// The yield body, run under mrb_protect_error: yield_with_class has no
// TRY of its own (funcall builds one when mrb->jmp is empty; yield does
// not), so a raising callback would longjmp into nothing.
struct YieldCtx {
  const Resource* res;
  const struct RProc* proc;
  mrb_sym sym;
};

mrb_value call_cached_body(mrb_state* mrb, void* ud) {
  const YieldCtx* c = static_cast<const YieldCtx*>(ud);
  // Lend the callback its own name: yield_with_class fills the new
  // frame's mid from the CURRENT frame for a plain def, and `super`
  // resolves through ci->mid - without this a callback calling super
  // hunted its caller's superclass method. Restored after; on a raise
  // the unwind pops past the frame and the value is moot.
  mrb_callinfo* ci = mrb->c->ci;
  const mrb_sym saved_mid = ci->mid;
  ci->mid = c->sym;
  mrb_value r = mrb_yield_with_class(mrb, mrb_obj_value(const_cast<struct RProc*>(c->proc)), 0,
                                     nullptr, c->res->self, c->res->klass);
  ci->mid = saved_mid;
  return r;
}

// Invoke a bind-time-resolved method. The frozen class guarantees the
// method still IS what was resolved; the one thing Ruby code can still
// do is grow a singleton class on the instance - checked with a load
// and a branch, falling back to the full funcall when it happened.
mrb_value call_cached(const Resource& res, mrb_method_t m, bool fast, mrb_sym sym) {
  mrb_state* mrb = res.mrb;
  if (WM_RES_UNLIKELY(!fast || mrb_obj_ptr(res.self)->c != res.klass)) {
    return mrb_funcall_argv(mrb, res.self, sym, 0, nullptr);
  }
  YieldCtx ctx{&res, MRB_METHOD_PROC(m), sym};
  mrb_bool raised = FALSE;
  mrb_value r = mrb_protect_error(mrb, call_cached_body, &ctx, &raised);
  if (WM_RES_UNLIKELY(raised)) {
    // protect_error hands the exception back as the value and clears
    // mrb->exc; re-arm it so the one pending-exception path answers.
    mrb->exc = mrb_obj_ptr(r);
    return mrb_nil_value();
  }
  // PROTECTED, because yield_with_class does not: funcall ends with
  // arena_restore + gc_protect, yield does neither - the old tree
  // watched a rendered String go live -> FREE across the next VM call
  // under MRB_GC_STRESS (gc.c:1772). One arena entry per real VM call.
  mrb_gc_protect(mrb, r);
  return r;
}

}  // namespace

bool resource_setup(mrb_state* mrb, const char* path, Resource& out, char* err, size_t errlen) {
  const int ai = mrb_gc_arena_save(mrb);
  FILE* f = std::fopen(path, "r");
  if (WM_RES_UNLIKELY(f == nullptr)) {
    std::snprintf(err, errlen, "cannot open %s", path);
    return false;
  }
  // The inherited hook fills this slot through mrb->ud while the app
  // file loads; the class itself is held alive by its own constant.
  mrb_value klass = mrb_nil_value();
  void* prev_ud = mrb->ud;
  mrb->ud = &klass;
  mrb_load_file(mrb, f);
  mrb->ud = prev_ud;
  std::fclose(f);
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    exc_into(mrb, "app raised while loading", err, errlen);
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  if (WM_RES_UNLIKELY(mrb_type(klass) != MRB_TT_CLASS)) {
    std::snprintf(err, errlen, "the app must define a class inheriting Webmachine::Resource");
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }

  out = Resource{};
  out.mrb = mrb;

  for (const NamedSym& cb : kUnhonored) {
    if (WM_RES_UNLIKELY(mrb_respond_to(mrb, klass, cb.sym) ||
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

  // The booleans: class method -> konst bit; instance method -> the
  // node goes dynamic and is asked through the VM on every request.
  bool ans[sizeof(kBools) / sizeof(kBools[0])];
  for (size_t i = 0; i < sizeof(kBools) / sizeof(kBools[0]); i++) {
    const BoolCb& cb = kBools[i];
    ans[i] = cb.defv;
    if (instance_defined(mrb, klass, cb.sym)) {
      out.dynamic |= uint64_t{1} << static_cast<size_t>(cb.node);
      out.node_sym[static_cast<size_t>(cb.node)] = cb.sym;
      struct RClass* owner = mrb_class_ptr(klass);  // search_vm scribbles on it
      const mrb_method_t m = resolve_alias(mrb_method_search_vm(mrb, &owner, cb.sym));
      out.node_m[static_cast<size_t>(cb.node)] = m;
      out.node_fast[static_cast<size_t>(cb.node)] =
          !MRB_METHOD_UNDEF_P(m) && !MRB_METHOD_CFUNC_P(m);
      continue;
    }
    if (WM_RES_UNLIKELY(!ask(mrb, klass, cb.sym, cb.name, cb.defv, &ans[i], err, errlen))) {
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
  }

  // is_authorized?: only an unconditional true is konst (a 401 with
  // WWW-Authenticate needs the callback's string - a later tier).
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
  // moved_*: a truthy answer carries a Location URI - a later tier.
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

  // The representation: content_type is one String (default text/html),
  // to_html the one handler - no pair arrays, that ceremony is value
  // conneg and refused above. A CLASS handler renders once, here; an
  // INSTANCE handler renders per request through the VM.
  std::string content_type = "text/html";
  const mrb_sym handler = MRB_SYM(to_html);
  if (mrb_respond_to(mrb, klass, MRB_SYM(content_type))) {
    const mrb_value v = mrb_funcall_argv(mrb, klass, MRB_SYM(content_type), 0, nullptr);
    if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_string_p(v))) {
      mrb->exc == nullptr
          ? static_cast<void>(std::snprintf(err, errlen, "content_type must return a String"))
          : exc_into(mrb, "content_type", err, errlen);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    content_type.assign(RSTRING_PTR(v), RSTRING_LEN(v));
  }
  const bool body_konst = mrb_respond_to(mrb, klass, handler);
  const bool body_runtime = !body_konst && instance_defined(mrb, klass, handler);
  if (body_konst) {
    const mrb_value rendered = mrb_funcall_argv(mrb, klass, handler, 0, nullptr);
    if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_string_p(rendered))) {
      mrb->exc == nullptr
          ? static_cast<void>(std::snprintf(err, errlen, "the body handler must return a String"))
          : exc_into(mrb, "body handler raised", err, errlen);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    out.konst.body.assign(RSTRING_PTR(rendered), RSTRING_LEN(rendered));
  } else if (body_runtime) {
    out.dynamic_body = true;
    out.body_sym = handler;
    struct RClass* owner = mrb_class_ptr(klass);  // search_vm scribbles on it
    out.body_m = resolve_alias(mrb_method_search_vm(mrb, &owner, handler));
    out.body_fast = !MRB_METHOD_UNDEF_P(out.body_m) && !MRB_METHOD_CFUNC_P(out.body_m);
  }
  out.konst.content_type = content_type;  // the negotiated type, body or not

  out.klass = mrb_class_ptr(klass);
  // routes.add is where resources FREEZE: from here no method can be
  // redefined, so every method_t resolved above stays true forever.
  mrb_obj_freeze(mrb, klass);

  // The instance dynamic callbacks are asked on: created once, pinned
  // against GC, holding whatever state the app's initialize gave it.
  if (out.dynamic != 0 || out.dynamic_body) {
    out.self = mrb_obj_new(mrb, mrb_class_ptr(klass), 0, nullptr);
    if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
      exc_into(mrb, "resource initialize raised", err, errlen);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    mrb_gc_register(mrb, out.self);
  }

  // The method lists, folded (defaults: webmachine's standard known
  // set, GET/HEAD allowed).
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

  // Fold everything into the per-method vectors, and spell the Allow
  // line B10's 405 will speak (RFC 9110 10.2.1).
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
  mrb_gc_arena_restore(mrb, ai);
  return true;
}

uint16_t resource_decide(const Resource& res, const flow::ReqFacts& facts) {
  const flow::KonstAnswers& k = res.konst.per_method[static_cast<size_t>(facts.method)];
  flow::Node n = flow::Node::kB13;
  int ai = -1;  // one arena cycle for the whole decision, opened lazily
  uint16_t status = 0;
  for (;;) {  // terminates: proven acyclic in flow.hpp
    const flow::FlowNode& f = flow::kFlow[static_cast<size_t>(n)];
    bool ans;
    if (f.kind == flow::Kind::kRequest) {
      ans = flow::eval_request(n, facts);
    } else if ((res.dynamic >> static_cast<size_t>(n)) & 1) {
      // The budgeted entry: this node's answer lives in the world, the
      // VM is asked on every request. A raise ends in 500, never in a
      // dead process (the VM boundary is always protected).
      if (ai < 0) ai = mrb_gc_arena_save(res.mrb);
      const mrb_value v = call_cached(res, res.node_m[static_cast<size_t>(n)],
                                      res.node_fast[static_cast<size_t>(n)],
                                      res.node_sym[static_cast<size_t>(n)]);
      if (WM_RES_UNLIKELY(res.mrb->exc != nullptr)) {
        // The exception stays pending: it becomes the 500's body, in
        // the negotiated type (resource_exception_begin lends it).
        status = 500;
        break;
      }
      ans = mrb_test(v);
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
  if (ai >= 0) mrb_gc_arena_restore(res.mrb, ai);
  return status;
}

bool resource_render_begin(const Resource& res, const char** ptr, size_t* len, int* arena) {
  // ONE copy, made by the caller straight into the sink: the VM string
  // is lent out and stays alive until resource_render_end restores the
  // arena - the borrow contract, not a scratch buffer.
  mrb_state* mrb = res.mrb;  // E_TYPE_ERROR expands against this name
  const int ai = mrb_gc_arena_save(mrb);
  const mrb_value v = call_cached(res, res.body_m, res.body_fast, res.body_sym);
  if (WM_RES_UNLIKELY(mrb->exc != nullptr || !mrb_string_p(v))) {
    if (mrb->exc == nullptr) {
      // A non-String is the handler's own fault - raise it as one, so
      // the one exception path answers.
      mrb->exc = mrb_obj_ptr(
          mrb_exc_new_lit(mrb, E_TYPE_ERROR, "the body handler must return a String"));
    }
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  *ptr = RSTRING_PTR(v);
  *len = static_cast<size_t>(RSTRING_LEN(v));
  *arena = ai;
  return true;
}

bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len, int* arena) {
  if (res.mrb->exc == nullptr) return false;
  const int ai = mrb_gc_arena_save(res.mrb);
  const mrb_value msg = mrb_funcall_argv(res.mrb, mrb_obj_value(res.mrb->exc),
                                         MRB_SYM(message), 0, nullptr);
  res.mrb->exc = nullptr;
  if (WM_RES_UNLIKELY(res.mrb->exc != nullptr || !mrb_string_p(msg))) {
    res.mrb->exc = nullptr;  // even message raised; the plain 500 stands
    mrb_gc_arena_restore(res.mrb, ai);
    return false;
  }
  *ptr = RSTRING_PTR(msg);
  *len = static_cast<size_t>(RSTRING_LEN(msg));
  *arena = ai;
  return true;
}

void resource_render_end(const Resource& res, int arena) {
  mrb_gc_arena_restore(res.mrb, arena);
}

}  // namespace webmachine

// The gem's Ruby surface: the Webmachine::Resource base class an app
// subclasses; Class#inherited records the subclass for resource_setup.
extern "C" {

void mrb_webmachine_mruby_gem_init(mrb_state* mrb) {
  struct RClass* wm = mrb_define_module_id(mrb, MRB_SYM(Webmachine));
  struct RClass* res = mrb_define_class_under_id(mrb, wm, MRB_SYM(Resource), mrb->object_class);
  mrb_define_class_method_id(mrb, res, MRB_SYM(inherited), webmachine::resource_inherited,
                             MRB_ARGS_REQ(1));
}

void mrb_webmachine_mruby_gem_final(mrb_state*) {}

}  // extern "C"
