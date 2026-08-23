#include "application.hpp"

#include "error.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/dump.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace webmachine {
namespace {

// Every AppSpec ever built lives here; `registered_` names the ones
// whose Application.new block RETURNED (new without a block builds a
// spec nobody serves - legal, and deliberately inert).
//
// A file-static registry rather than mrb->ud or a Ruby constant: the
// server is one process, one VM, one ring, and the tool reads this
// straight after `main` returns. Nothing on a request path touches it.
std::vector<std::unique_ptr<AppSpec>> specs_;
std::vector<AppSpec*> registered_;

// The three hidden objects are DATA carrying the SAME AppSpec pointer.
// The registry owns the spec, so free is a no-op.
const struct mrb_data_type app_type = {"webmachine.app", nullptr};

// The config and routes classes carry no constant: Ruby can reach them
// only through the object `configure`/`routes` yields. They are rooted
// once at init because a class nothing names is collectable.
struct RClass* conf_class_ = nullptr;
struct RClass* route_class_ = nullptr;

// --- conf ------------------------------------------------------------

// Exactly one of port / unix_path / url per app (RFC-free house rule:
// a listener has one spelling). Several APPS may each name their own
// (#116 slice 2); several listeners for ONE app is what nothing has
// asked for, so nothing here builds it.
void claim_form(mrb_state* mrb, AppSpec* s, AppSpec::Form f, const char* name) {
  if (s->form != AppSpec::Form::kNone && s->form != f) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "conf.%s: this application already named its listener another way - "
               "exactly one of port, unix_path or url per application",
               name);
  }
  s->form = f;
}

mrb_value conf_port_set(mrb_state* mrb, mrb_value self) {
  mrb_int p;
  mrb_get_args(mrb, "i", &p);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
  claim_form(mrb, s, AppSpec::Form::kPort, "port");
  // 0 means "the OS picks". Slice 2 refused it ("io_uring has no
  // getsockname"); that world ended when the access log's %h brought
  // SOCKET_URING_OP_GETSOCKNAME into the tree - the ring now asks the
  // BOUND listener its local name at setup (local form of the same
  // cmd arm_peer rides) and conf.url reads the pick back in ready.
  // A kernel without the cmd refuses THE START by name, and only for
  // a port-0 ask - fixed ports never ask the question.
  if (p < 0 || p > 65535) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.port = %d is outside 0..65535", (int)p);
  }
  s->port = static_cast<int>(p);
  return mrb_nil_value();
}

mrb_value conf_unix_set(mrb_state* mrb, mrb_value self) {
  const char* p;
  mrb_int n;
  mrb_get_args(mrb, "s", &p, &n);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
  claim_form(mrb, s, AppSpec::Form::kUnix, "unix_path");
  if (n == 0) mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.unix_path is empty");
  s->unix_path.assign(p, static_cast<size_t>(n));
  return mrb_nil_value();
}

mrb_value conf_url_set(mrb_state* mrb, mrb_value self) {
  const char* p;
  mrb_int n;
  mrb_get_args(mrb, "s", &p, &n);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
  claim_form(mrb, s, AppSpec::Form::kUrl, "url");
  const std::string u(p, static_cast<size_t>(n));
  const size_t sep = u.find("://");
  if (sep == std::string::npos) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url = %s is not scheme://host[:port]", u.c_str());
  }
  const std::string scheme = u.substr(0, sep);
  if (scheme == "https") {
    mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb),
           "conf.url names https, and there is no TLS in this tree (#110/#112/#157 are "
           "parked). The name is reserved so today's 443 app file runs when TLS returns");
  }
  if (scheme != "http") {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url scheme %s is not http", scheme.c_str());
  }
  std::string rest = u.substr(sep + 3);
  const size_t slash = rest.find('/');
  if (slash != std::string::npos) rest.resize(slash);
  int port = 80;
  const size_t colon = rest.rfind(':');
  if (colon != std::string::npos) {
    const std::string ps = rest.substr(colon + 1);
    // :0 is legal - "the OS picks", same contract as conf.port = 0
    // (the comment there says how the pick is read back). An EMPTY
    // port ("http://h:") is not a zero, it is a malformed url.
    port = ps.empty() ? -1 : 0;
    for (char c : ps) {
      if (c < '0' || c > '9') { port = -1; break; }
      port = port * 10 + (c - '0');
    }
    if (port < 0 || port > 65535) {
      mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url = %s has no usable port", u.c_str());
    }
    rest.resize(colon);
  }
  if (rest.empty()) mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url = %s has no host", u.c_str());
  s->url_host = rest;
  s->port = port;
  return mrb_nil_value();
}

mrb_value conf_url_get(mrb_state* mrb, mrb_value self) {
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
  // After the bind this is where the listener REALLY is; before it,
  // where it was asked to be.
  if (s->bound) return mrb_str_new(mrb, s->bound_url.data(), s->bound_url.size());
  char buf[300];
  int n = 0;
  switch (s->form) {
    case AppSpec::Form::kUnix:
      n = std::snprintf(buf, sizeof(buf), "unix://%s", s->unix_path.c_str());
      break;
    case AppSpec::Form::kUrl:
      n = std::snprintf(buf, sizeof(buf), "http://%s:%d", s->url_host.c_str(), s->port);
      break;
    case AppSpec::Form::kPort:
      n = std::snprintf(buf, sizeof(buf), "http://0.0.0.0:%d", s->port);
      break;
    case AppSpec::Form::kNone: return mrb_nil_value();
  }
  return mrb_str_new(mrb, buf, static_cast<size_t>(n < 0 ? 0 : n));
}

// conf.adapter= and the four ssl/certificate names USED to live here.
// Both were wrong and both are gone (Nutzer-Entscheid 2026-08-23,
// reversing an earlier decision of his own):
//
//   adapter= accepted a value and threw it away, so a file naming a
//   reactor this tree does not have "worked" while doing nothing -
//   the silent fallback this tree forbids everywhere else. Its
//   compatibility promise ("a webmachine-ruby file runs unchanged")
//   was worth less than the lie, so that promise is withdrawn: a file
//   naming an adapter now gets NoMethodError, which is true.
//
//   ssl=/ssl_options=/certificate=/certificate_key= reserved names for
//   a TLS that is not in this tree (#110/#112/#157 parked) - code on
//   stock with no second user. When TLS returns it brings its own
//   setters; until then NoMethodError says exactly what is the case.
// --- routes ----------------------------------------------------------

// route.add [tokens], Klass - the ONE route form this slice builds.
// Also app.add_route, webmachine-ruby's own spelling: same C function,
// same mechanics, because both objects carry the same AppSpec.
mrb_value route_add(mrb_state* mrb, mrb_value self) {
  mrb_value toks, klass;
  mrb_get_args(mrb, "Ao", &toks, &klass);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));

  if (!mrb_class_p(klass)) {
    mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "route.add wants a class inheriting Webmachine::Resource");
  }
  struct RClass* wm = mrb_module_get_id(mrb, MRB_SYM(Webmachine));
  struct RClass* base = mrb_class_get_under_id(mrb, wm, MRB_SYM(Resource));
  bool is_resource = false;
  for (struct RClass* c = mrb_class_ptr(klass)->super; c != nullptr; c = c->super) {
    if (c == base) {
      is_resource = true;
      break;
    }
  }
  if (!is_resource) {
    mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "route.add: %v does not inherit Webmachine::Resource",
               klass);
  }

  // The token array crosses this boundary ONCE: from here the route is
  // bytes and offsets in a flat table (router.hpp), and no Ruby object
  // is looked at again on any request path.
  const mrb_int n = RARRAY_LEN(toks);
  s->table.open();
  for (mrb_int i = 0; i < n; i++) {
    const mrb_value t = mrb_ary_entry(toks, i);
    if (s->table.pending_splat()) {
      s->table.abandon();
      mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "route.add: :* is the tail of a route - nothing may follow it");
    }
    if (mrb_string_p(t)) {
      if (!s->table.literal(RSTRING_PTR(t), static_cast<size_t>(RSTRING_LEN(t)))) {
        s->table.abandon();
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "route.add: a literal token is too long");
      }
      continue;
    }
    if (mrb_symbol_p(t)) {
      if (mrb_symbol(t) == MRB_OPSYM(mul)) {
        s->table.splat();
        continue;
      }
      // The Symbol's own id rides into the table: slice 4's request
      // object names what the span captured, and this is the only
      // moment the name exists.
      if (!s->table.binding(static_cast<uint32_t>(mrb_symbol(t)))) {
        s->table.abandon();
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "route.add: too many bindings in one route (16 is the table's width)");
      }
      continue;
    }
    s->table.abandon();
    mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "route.add: a token is a String (literal), a Symbol (binding) or :* (tail)");
  }

  // The resource is folded and FROZEN right here: every method the
  // flow will ever ask is resolved now, so nothing can be redefined
  // behind the compiled answers.
  auto res = std::unique_ptr<Resource>(new Resource());
  char err[512] = "";
  if (!resource_fold(mrb, klass, *res, err, sizeof(err))) {
    s->table.abandon();
    mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "route.add: %s", err);
  }
  s->table.commit();
  s->resources.push_back(std::move(res));
  return self;
}

// route.websocket [tokens], Klass - the SAME token forms as route.add,
// walked out of the app's OWN websocket table (#175). A websocket
// route shares nothing with the flow: it is matched at the upgrade or
// not at all.
mrb_value route_websocket(mrb_state* mrb, mrb_value self) {
  mrb_value toks, klass;
  mrb_get_args(mrb, "Ao", &toks, &klass);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));

  const mrb_int n = RARRAY_LEN(toks);
  s->ws_table.open();
  for (mrb_int i = 0; i < n; i++) {
    const mrb_value t = mrb_ary_entry(toks, i);
    if (s->ws_table.pending_splat()) {
      s->ws_table.abandon();
      mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "route.websocket: :* is the tail of a route - nothing may follow it");
    }
    if (mrb_string_p(t)) {
      if (!s->ws_table.literal(RSTRING_PTR(t), static_cast<size_t>(RSTRING_LEN(t)))) {
        s->ws_table.abandon();
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "route.websocket: a literal token is too long");
      }
      continue;
    }
    if (mrb_symbol_p(t)) {
      if (mrb_symbol(t) == MRB_OPSYM(mul)) {
        s->ws_table.splat();
        continue;
      }
      if (!s->ws_table.binding(static_cast<uint32_t>(mrb_symbol(t)))) {
        s->ws_table.abandon();
        mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb), "route.websocket: too many bindings in one route (16 is the width)");
      }
      continue;
    }
    s->ws_table.abandon();
    mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
           "route.websocket: a token is a String (literal), a Symbol (binding) or :* (tail)");
  }

  std::unique_ptr<WsResource, void (*)(WsResource*)> res(ws_resource_new(), ws_resource_free);
  char err[512] = "";
  if (!ws_fold(mrb, klass, *res, err, sizeof(err))) {
    s->ws_table.abandon();
    mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "%s", err);
  }
  s->ws_table.commit();
  s->ws_resources.push_back(std::move(res));
  return self;
}

mrb_value route_assets(mrb_state* mrb, mrb_value) {
  mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
         "route.assets is reserved - the asset mount is #170/#115. Assets are configured "
         "with --assets and serve unchanged");
  return mrb_nil_value();  // never reached: the raise above leaves
}

// --- application ------------------------------------------------------

// Two applications may not name the same listener. Since slice 2 a
// process serves several apps, one listener each, so this is the
// refusal that keeps them apart - two apps on one socket have no
// answer to "whose request is this".
void register_app(mrb_state* mrb, AppSpec* s) {
  // Compared on the LISTENER, not on the spelling: conf.port = 80 and
  // conf.url = "http://host:80" are two ways to say one socket, and a
  // refusal that only looked at the spelling would miss that pair.
  if (s->form == AppSpec::Form::kNone) {
    s->registered = true;
    registered_.push_back(s);
    return;
  }
  const bool is_unix = s->form == AppSpec::Form::kUnix;
  for (AppSpec* other : registered_) {
    if (other->form == AppSpec::Form::kNone) continue;
    const bool other_unix = other->form == AppSpec::Form::kUnix;
    if (is_unix != other_unix) continue;
    if (is_unix) {
      if (s->unix_path == other->unix_path) {
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "two applications claim the same listener: unix %s",
                   s->unix_path.c_str());
      }
    } else if (s->port == other->port && s->port != 0) {
      // Two port-0 asks are NOT one socket - the kernel picks a fresh
      // ephemeral port for each bind, so they collide with nothing.
      mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "two applications claim the same listener: port %d",
                 s->port);
    }
  }
  s->registered = true;
  registered_.push_back(s);
}

mrb_value app_new(mrb_state* mrb, mrb_value self) {
  mrb_value blk = mrb_nil_value();
  mrb_get_args(mrb, "&", &blk);
  specs_.push_back(std::unique_ptr<AppSpec>(new AppSpec()));
  AppSpec* s = specs_.back().get();
  mrb_value obj =
      mrb_obj_value(mrb_data_object_alloc(mrb, mrb_class_ptr(self), s, &app_type));
  // The two facades, built ONCE and hung on the application: they are
  // views of this AppSpec, and a view has no reason to be manufactured
  // per access. As ivars they are rooted by the object that owns them -
  // no mrb_gc_register, no second lifetime to reason about - and
  // `app.conf` is the same object every time it is asked for, which is
  // what a reader should mean. (mrblib/webmachine.rb reads @conf; that
  // attr_reader is the whole accessor.)
  mrb_iv_set(mrb, obj, MRB_IVSYM(conf),
             mrb_obj_value(mrb_data_object_alloc(mrb, conf_class_, s, &app_type)));
  mrb_iv_set(mrb, obj, MRB_IVSYM(routes),
             mrb_obj_value(mrb_data_object_alloc(mrb, route_class_, s, &app_type)));
  // No block: a built but UNREGISTERED application. Legal, and served
  // by nobody - registration is what the block's return means.
  if (mrb_nil_p(blk)) return obj;
  mrb_yield(mrb, blk, obj);
  register_app(mrb, s);
  return obj;
}

// The CANONICAL surface (user decision): app.conf.url = "...",
// app.conf.port = 8080 - direct writes, no ceremony. `conf` itself is
// not here: it reads an ivar, which is what attr_reader is for, and it
// lives in mrblib/webmachine.rb. The block forms below (configure /
// config / routes) exist for webmachine-ruby compatibility only: tests
// pin them, the examples never show them. A block stays canonical
// exactly where it IS a callback: app.ready.
mrb_value app_configure(mrb_state* mrb, mrb_value self) {
  mrb_value blk = mrb_nil_value();
  mrb_get_args(mrb, "&", &blk);
  if (mrb_nil_p(blk)) mrb_raise(mrb, E_WM_ERROR(mrb), "app.configure wants a block");
  mrb_yield(mrb, blk, mrb_iv_get(mrb, self, MRB_IVSYM(conf)));
  return self;
}

mrb_value app_routes(mrb_state* mrb, mrb_value self) {
  mrb_value blk = mrb_nil_value();
  mrb_get_args(mrb, "&", &blk);
  if (mrb_nil_p(blk)) mrb_raise(mrb, E_WM_ERROR(mrb), "app.routes wants a block");
  mrb_yield(mrb, blk, mrb_iv_get(mrb, self, MRB_IVSYM(routes)));
  return self;
}

mrb_value app_ready(mrb_state* mrb, mrb_value self) {
  mrb_value blk = mrb_nil_value();
  mrb_get_args(mrb, "&", &blk);
  if (mrb_nil_p(blk)) mrb_raise(mrb, E_WM_ERROR(mrb), "app.ready wants a block");
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
  if (s->have_ready) mrb_gc_unregister(mrb, s->ready);
  s->ready = blk;
  s->have_ready = true;
  mrb_gc_register(mrb, blk);  // it must survive until after the bind
  return self;
}

}  // namespace

void application_init(mrb_state* mrb, struct RClass* wm) {
  struct RClass* app = mrb_define_class_under_id(mrb, wm, MRB_SYM(Application),
                                                 mrb->object_class);
  MRB_SET_INSTANCE_TT(app, MRB_TT_CDATA);
  mrb_define_class_method_id(mrb, app, MRB_SYM(new), app_new, MRB_ARGS_NONE() |
                                                                  MRB_ARGS_BLOCK());
  // configure is webmachine-ruby's name; config is the same method
  // under its other spelling, not a second one.
  mrb_define_method_id(mrb, app, MRB_SYM(configure), app_configure, MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, app, MRB_SYM(config), app_configure, MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, app, MRB_SYM(routes), app_routes, MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, app, MRB_SYM(ready), app_ready, MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, app, MRB_SYM(add_route), route_add, MRB_ARGS_REQ(2));
  // The canonical websocket spelling, parallel to add_route: the same
  // C function route.websocket runs, because app and route objects
  // carry the same AppSpec.
  mrb_define_method_id(mrb, app, MRB_SYM(add_websocket), route_websocket, MRB_ARGS_REQ(2));

  // Hidden: no constant names either class, so an app file can neither
  // reopen nor instantiate them. Rooted by hand - a class nothing
  // names is collectable.
  conf_class_ = mrb_class_new(mrb, mrb->object_class);
  MRB_SET_INSTANCE_TT(conf_class_, MRB_TT_CDATA);
  mrb_gc_register(mrb, mrb_obj_value(conf_class_));
  mrb_define_method_id(mrb, conf_class_, MRB_SYM_E(port), conf_port_set, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_class_, MRB_SYM_E(unix_path), conf_unix_set,
                       MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_class_, MRB_SYM_E(url), conf_url_set, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_class_, MRB_SYM(url), conf_url_get, MRB_ARGS_NONE());

  route_class_ = mrb_class_new(mrb, mrb->object_class);
  MRB_SET_INSTANCE_TT(route_class_, MRB_TT_CDATA);
  mrb_gc_register(mrb, mrb_obj_value(route_class_));
  mrb_define_method_id(mrb, route_class_, MRB_SYM(add), route_add, MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, route_class_, MRB_SYM(websocket), route_websocket,
                       MRB_ARGS_ANY());
  mrb_define_method_id(mrb, route_class_, MRB_SYM(assets), route_assets, MRB_ARGS_ANY());
}

bool app_load(mrb_state* mrb, const char* path, char* err, size_t errlen) {
  // DECIDED (#100): --app takes a precompiled .mrb; this server never
  // compiles Ruby itself. A .rb here is refused BY NAME, with the mrbc
  // line that produces what --app wants - compiling it as a fallback is
  // how the source path would come back in through the side door.
  const size_t path_len = std::strlen(path);
  if (path_len >= 3 && std::memcmp(path + path_len - 3, ".rb", 3) == 0) {
    const std::string mrb_path(path, path_len - 3);
    std::snprintf(err, errlen,
                  "%s is Ruby source, not bytecode - this server loads bytecode only. "
                  "Compile it first: mrbc -o %s.mrb %s",
                  path, mrb_path.c_str(), path);
    return false;
  }
  FILE* f = std::fopen(path, "rb");
  if (f == nullptr) {
    std::snprintf(err, errlen, "cannot open %s", path);
    return false;
  }
  const int ai = mrb_gc_arena_save(mrb);
  mrb_load_irep_file(mrb, f);
  std::fclose(f);
  if (mrb->exc != nullptr) {
    std::snprintf(err, errlen, "app raised while loading (exception below)");
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  // The app file defines ONE method. Asked for straight in the method
  // table - no respond_to?, no funcall that would report a missing
  // `main` as a NoMethodError instead of as the refusal it is.
  struct RClass* owner = mrb->object_class;
  if (MRB_METHOD_UNDEF_P(mrb_method_search_vm(mrb, &owner, MRB_SYM(main)))) {
    std::snprintf(err, errlen,
                  "the app defines no `main` - since #116 an app file defines exactly "
                  "that, and Webmachine::Application.new inside it registers the app");
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  mrb_funcall_argv(mrb, mrb_top_self(mrb), MRB_SYM(main), 0, nullptr);
  if (mrb->exc != nullptr) {
    std::snprintf(err, errlen, "main raised (exception below)");
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  mrb_gc_arena_restore(mrb, ai);
  return true;
}

bool app_registered_all(std::vector<AppSpec*>& out, size_t max_listeners, char* err,
                        size_t errlen) {
  if (registered_.empty()) {
    std::snprintf(err, errlen,
                  "main registered no application - Webmachine::Application.new takes a "
                  "block, and returning from it is what registers the app");
    return false;
  }
  if (registered_.size() > max_listeners) {
    std::snprintf(err, errlen,
                  "main registered %zu applications and the ring holds %zu listeners",
                  registered_.size(), max_listeners);
    return false;
  }
  out.assign(registered_.begin(), registered_.end());
  return true;
}

AppSpec* app_default() {
  specs_.push_back(std::unique_ptr<AppSpec>(new AppSpec()));
  AppSpec* s = specs_.back().get();
  // ONE splat route on webmachine-ruby's unbound resource: exactly what
  // a server without --app answered at every path before routes
  // existed, now spelled as the route it always was.
  s->table.open();
  s->table.splat();
  s->table.commit();
  s->resources.push_back(std::unique_ptr<Resource>(new Resource()));
  s->registered = true;
  registered_.push_back(s);
  return s;
}

void app_mark_bound(AppSpec& spec, const char* unix_path, int port) {
  char buf[300];
  if (unix_path != nullptr) std::snprintf(buf, sizeof(buf), "unix://%s", unix_path);
  else if (!spec.url_host.empty()) {
    std::snprintf(buf, sizeof(buf), "http://%s:%d", spec.url_host.c_str(), port);
  } else {
    std::snprintf(buf, sizeof(buf), "http://0.0.0.0:%d", port);
  }
  spec.bound_url = buf;
  spec.bound = true;
}

bool app_ready_run(mrb_state* mrb, AppSpec& spec, char* err, size_t errlen) {
  if (!spec.have_ready) return true;
  const int ai = mrb_gc_arena_save(mrb);
  // Proc#call, not mrb_yield: this runs from the TOOL, outside any VM
  // frame, and only a funcall arms the TRY that catches a raise here
  // (resource.cpp makes the same distinction at setup).
  mrb_funcall_argv(mrb, spec.ready, MRB_SYM(call), 0, nullptr);
  if (mrb->exc != nullptr) {
    std::snprintf(err, errlen, "ready raised (exception below)");
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  mrb_gc_arena_restore(mrb, ai);
  return true;
}

}  // namespace webmachine
