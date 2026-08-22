#include "resource.hpp"

#include <mruby/class.h>
#include <mruby/dump.h>
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

void exc_into(mrb_state* mrb, const char* what, char* err, size_t errlen) {
  // The direct variant: mruby prints exception + backtrace to stderr
  // itself; err carries only the context line.
  std::snprintf(err, errlen, "%s (exception below)", what);
  mrb_print_error(mrb);
  mrb->exc = nullptr;
}

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

// ONE resolver: where does `sym` answer for receivers of class `c`?
// mrb_method_search_vm scribbles on the class it is given - always a
// copy. fast = a Ruby proc we may enter directly.
struct Resolved {
  mrb_method_t m = {};
  bool defined = false;
  bool fast = false;
};

Resolved resolve(mrb_state* mrb, struct RClass* c, mrb_sym sym) {
  Resolved r;
  struct RClass* owner = c;
  r.m = resolve_alias(mrb_method_search_vm(mrb, &owner, sym));
  r.defined = !MRB_METHOD_UNDEF_P(r.m);
  r.fast = r.defined && !MRB_METHOD_CFUNC_P(r.m);
  return r;
}

// Is `sym` an INSTANCE method (runtime, per request)? A direct look
// into the class's method table - no funcall, no method_defined?.
bool instance_defined(mrb_state* mrb, mrb_value klass, mrb_sym sym) {
  return resolve(mrb, mrb_class_ptr(klass), sym).defined;
}

// The yield body for SETUP calls, run under mrb_protect_error: outside
// a VM frame nothing catches a raise (funcall builds its own TRY,
// yield does not).
struct SetupCall {
  const struct RProc* proc;
  mrb_sym sym;
  mrb_value self;
  struct RClass* c;
};

mrb_value setup_call_body(mrb_state* mrb, void* ud) {
  const SetupCall* c = static_cast<const SetupCall*>(ud);
  // Lend the callback its own name: yield_with_class fills the new
  // frame's mid from the CURRENT frame for a plain def, and `super`
  // resolves through ci->mid. Restored after; on a raise the unwind
  // pops past the frame and the value is moot.
  mrb_callinfo* ci = mrb->c->ci;
  const mrb_sym saved_mid = ci->mid;
  ci->mid = c->sym;
  mrb_value r = mrb_yield_with_class(mrb, mrb_obj_value(const_cast<struct RProc*>(c->proc)), 0,
                                     nullptr, c->self, c->c);
  ci->mid = saved_mid;
  return r;
}

// Invoke a resolved method at SETUP time (cold): Ruby procs enter
// directly under protection, cfuncs go through funcall (vm.c's frame
// setup is not worth owning). On a raise the exception stays pending.
mrb_value call_resolved(mrb_state* mrb, const Resolved& r, mrb_sym sym, mrb_value self,
                        struct RClass* c) {
  if (!r.fast) return mrb_funcall_argv(mrb, self, sym, 0, nullptr);
  SetupCall ctx{MRB_METHOD_PROC(r.m), sym, self, c};
  mrb_bool raised = FALSE;
  mrb_value v = mrb_protect_error(mrb, setup_call_body, &ctx, &raised);
  if (WM_RES_UNLIKELY(raised)) {
    mrb->exc = mrb_obj_ptr(v);  // protect_error cleared it; re-arm
    return mrb_nil_value();
  }
  mrb_gc_protect(mrb, v);  // yield does not protect its result; funcall does
  return v;
}

// A konst callback, asked once on the CLASS (its metaclass owns class
// methods). Absent -> the default stands. Raise -> a named refusal.
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

// A method list (known_methods / allowed_methods): ONE String like
// 'GET HEAD POST', tokenized here from its bytes - no Ruby arrays
// cross the boundary. Tokens outside the compiled set are refused -
// a method the walker cannot name would silently 501.
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

// --- the run: the whole flow inside ONE VM frame ---------------------
//
// Within this cfunc the wrapper funcall's TRY catches raises, the
// wrapper's arena roots every value until exit, and anything one
// callback returns stays alive for the next one - the frame IS the
// memory model. The Resource arrives through the proc's env.
mrb_value run_cfunc(mrb_state* mrb, mrb_value) {
  const Resource& res = *static_cast<const Resource*>(mrb_cptr(mrb_proc_cfunc_env_get(mrb, 0)));
  const flow::ReqFacts& facts = *res.run_facts;
  const flow::KonstAnswers& k = res.konst.per_method[static_cast<size_t>(facts.method)];
  const auto naked = [&](mrb_method_t m, bool fast, mrb_sym sym) -> mrb_value {
    if (WM_RES_UNLIKELY(!fast || mrb_obj_ptr(res.self)->c != res.klass)) {
      // cfunc, or a singleton class grew on the instance: full funcall.
      return mrb_funcall_argv(mrb, res.self, sym, 0, nullptr);
    }
    mrb_callinfo* ci = mrb->c->ci;
    const mrb_sym saved = ci->mid;
    ci->mid = sym;
    mrb_value r = mrb_yield_with_class(
        mrb, mrb_obj_value(const_cast<struct RProc*>(MRB_METHOD_PROC(m))), 0, nullptr, res.self,
        res.klass);
    ci->mid = saved;
    return r;
  };

  flow::Node n = flow::Node::kB13;
  uint16_t status = 0;
  for (;;) {  // terminates: proven acyclic in flow.hpp
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
    // Copied while the frame roots it - the frame is the borrow.
    res.run_body->assign(RSTRING_PTR(v), RSTRING_LEN(v));
    res.run_have_body = true;
  }
  res.run_status = status;
  return mrb_nil_value();
}

}  // namespace

bool resource_setup(mrb_state* mrb, const char* path, Resource& out, char* err, size_t errlen) {
  const int ai = mrb_gc_arena_save(mrb);
  // DECIDED (#100): --app takes a precompiled .mrb; this server never
  // compiles Ruby itself (build_config.rb asks mruby-compiler for
  // nothing of its own - see the comment there on what still pulls it
  // in transitively, and why that is a build-time fact, not a reason
  // for this function to behave differently). A .rb here is refused BY
  // NAME, with the mrbc line that produces what --app wants -
  // compiling it as a fallback is how the source path would come back
  // in through the side door.
  const size_t path_len = std::strlen(path);
  if (WM_RES_UNLIKELY(path_len >= 3 && std::memcmp(path + path_len - 3, ".rb", 3) == 0)) {
    const std::string mrb_path(path, path_len - 3);
    std::snprintf(err, errlen,
                  "%s is Ruby source, not bytecode - this server loads bytecode only. "
                  "Compile it first: mrbc -o %s.mrb %s",
                  path, mrb_path.c_str(), path);
    return false;
  }
  FILE* f = std::fopen(path, "rb");
  if (WM_RES_UNLIKELY(f == nullptr)) {
    std::snprintf(err, errlen, "cannot open %s", path);
    return false;
  }
  mrb_load_irep_file(mrb, f);
  std::fclose(f);
  if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
    exc_into(mrb, "app raised while loading", err, errlen);
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  // The app's class: found by walking Object's constant table in C -
  // a value of class type whose super chain hits Webmachine::Resource.
  // Exactly one, or a named refusal. No hook, no ivar, no mrb->ud.
  struct RClass* wm = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
  struct RClass* base = mrb_class_get_under_id(mrb, wm, MRB_SYM(Resource));
  struct Finder {
    struct RClass* base;
    mrb_value found;
    int count;
  } finder{base, mrb_nil_value(), 0};
  mrb_iv_foreach(
      mrb, mrb_obj_value(mrb->object_class),
      [](mrb_state*, mrb_sym, mrb_value v, void* p) -> int {
        Finder* fd = static_cast<Finder*>(p);
        if (mrb_type(v) == MRB_TT_CLASS) {
          for (struct RClass* c = mrb_class_ptr(v)->super; c != nullptr; c = c->super) {
            if (c == fd->base) {
              fd->found = v;
              fd->count++;
              break;
            }
          }
        }
        return 0;  // keep going
      },
      &finder);
  if (WM_RES_UNLIKELY(finder.count != 1)) {
    std::snprintf(err, errlen,
                  "the app must define exactly one top-level class inheriting "
                  "Webmachine::Resource (found %d)",
                  finder.count);
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  const mrb_value klass = finder.found;

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

  // The booleans: class method -> konst bit; instance method -> the
  // node goes dynamic, resolved HERE, asked inside the run frame.
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
  // to_html the one handler. A CLASS handler renders once, here; an
  // INSTANCE handler renders per request inside the run frame.
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
  out.konst.content_type = content_type;  // the negotiated type, body or not

  out.klass = mrb_class_ptr(klass);
  // routes.add is where resources FREEZE: from here no method can be
  // redefined, so every method_t resolved above stays true forever.
  mrb_obj_freeze(mrb, klass);

  // The instance dynamic callbacks are asked on: created once, pinned
  // against GC, holding whatever state the app's initialize gave it.
  // Plus the run carrier: a HIDDEN class (no constant - unreachable
  // from Ruby) whose one method is the run cfunc, the Resource wired
  // in through the proc's env as a cptr.
  if (out.dynamic != 0 || out.dynamic_body) {
    out.self = mrb_obj_new(mrb, mrb_class_ptr(klass), 0, nullptr);
    if (WM_RES_UNLIKELY(mrb->exc != nullptr)) {
      exc_into(mrb, "resource initialize raised", err, errlen);
      mrb_gc_arena_restore(mrb, ai);
      return false;
    }
    mrb_gc_register(mrb, out.self);

    struct RClass* hidden = mrb_class_new(mrb, mrb->object_class);
    const mrb_value env = mrb_cptr_value(mrb, &out);
    struct RProc* run_proc = mrb_proc_new_cfunc_with_env(mrb, run_cfunc, 1, &env);
    mrb_method_t m;
    MRB_METHOD_FROM_PROC(m, run_proc);
    mrb_define_method_raw(mrb, hidden, MRB_SYM(call), m);
    out.run_self = mrb_obj_new(mrb, hidden, 0, nullptr);
    mrb_gc_register(mrb, out.run_self);
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
  // The vectors just changed, so the answers derived from them are
  // stale. A fully konst resource (no dynamic node, no dynamic body)
  // is NOT bound_, so it answers through flow::answer and reads these.
  out.konst.resolve_shortcuts();
  mrb_gc_arena_restore(mrb, ai);
  return true;
}

uint16_t resource_run(const Resource& res, const flow::ReqFacts& facts, std::string* body,
                      bool* have_body) {
  res.run_facts = &facts;
  res.run_body = body;
  res.run_have_body = false;
  res.run_status = 0;
  // The wrapper: funcall arms the TRY, its arena roots the whole frame,
  // its exit restores - one entry pays for everything inside.
  mrb_funcall_argv(res.mrb, res.run_self, MRB_SYM(call), 0, nullptr);
  if (WM_RES_UNLIKELY(res.mrb->exc != nullptr)) {
    *have_body = false;
    return 500;  // exception stays pending for the answering path
  }
  *have_body = res.run_have_body;
  return res.run_status;
}

bool resource_exception_begin(const Resource& res, const char** ptr, size_t* len) {
  if (res.mrb->exc == nullptr) return false;
  // Straight from the field (mruby/error.h: RException.mesg is "NULL or
  // probably RString"). The exception roots the message while pending;
  // the caller copies before any mruby call can run, so clearing exc
  // here is safe - no allocation happens in between.
  struct RException* e = reinterpret_cast<struct RException*>(res.mrb->exc);
  res.mrb->exc = nullptr;
  if (e->mesg == nullptr || e->mesg->tt != MRB_TT_STRING) return false;
  const mrb_value mesg = mrb_obj_value(e->mesg);
  *ptr = RSTRING_PTR(mesg);
  *len = static_cast<size_t>(RSTRING_LEN(mesg));
  return true;
}

}  // namespace webmachine

// The gem's Ruby surface: the Webmachine::Resource base class an app
// subclasses. Registration happens by inheritance alone - setup finds
// the subclass in the constant table, no hook, no state.
extern "C" {

void mrb_webmachine_mruby_gem_init(mrb_state* mrb) {
  struct RClass* wm = mrb_define_module_id(mrb, MRB_SYM(Webmachine));
  mrb_define_class_under_id(mrb, wm, MRB_SYM(Resource), mrb->object_class);
}

void mrb_webmachine_mruby_gem_final(mrb_state*) {}

}  // extern "C"
