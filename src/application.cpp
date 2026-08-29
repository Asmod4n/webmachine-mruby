// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

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
std::vector<std::unique_ptr<AppSpec>> specs_;
std::vector<AppSpec*> registered_;

const struct mrb_data_type app_type = {"webmachine.app", nullptr};

struct RClass* conf_class_ = nullptr;
struct RClass* route_class_ = nullptr;

// Exactly one listener spelling per app; a second refuses by name.
void claim_form(mrb_state* mrb, AppSpec* s, AppSpec::Form f, const char* name) {
  if (s->form != AppSpec::Form::kNone && s->form != f) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "conf.%s: this application already named its listener another way - "
               "exactly one of port, unix_path or url per application",
               name);
  }
  s->form = f;
}

// conf.port = N. 0 means the OS picks, read back after the bind.
mrb_value conf_port_set(mrb_state* mrb, mrb_value self) {
  mrb_int p;
  mrb_get_args(mrb, "i", &p);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
  claim_form(mrb, s, AppSpec::Form::kPort, "port");
  if (p < 0 || p > 65535) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.port = %d is outside 0..65535", (int)p);
  }
  s->port = static_cast<int>(p);
  return mrb_nil_value();
}

// conf.unix_path = PATH.
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

// conf.zero_copy_threshold = N. The body size at which a dynamic response is
// LENT to the writer instead of copied; 0 copies every body. A typed flag and
// [tune] both beat this, the way every other choice in here is beaten.
mrb_value conf_zc_set(mrb_state* mrb, mrb_value self) {
  mrb_int n;
  mrb_get_args(mrb, "i", &n);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
  if (n < 0 || n > static_cast<mrb_int>(kZeroCopyMax)) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "conf.zero_copy_threshold = %lld is outside 0..%lld bytes",
               static_cast<long long>(n), static_cast<long long>(kZeroCopyMax));
  }
  s->zero_copy_threshold = static_cast<long long>(n);
  return mrb_nil_value();
}

// conf.file_map_threshold = N. The file size from which response.file maps
// instead of reading window by window; 0 never maps. A typed flag and [tune]
// both beat this, the way every other choice in here is beaten.
mrb_value conf_map_set(mrb_state* mrb, mrb_value self) {
  mrb_int n;
  mrb_get_args(mrb, "i", &n);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
  if (n < 0 || n > static_cast<mrb_int>(kFileMapMax)) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "conf.file_map_threshold = %lld is outside 0..%lld bytes",
               static_cast<long long>(n), static_cast<long long>(kFileMapMax));
  }
  s->file_map_threshold = static_cast<long long>(n);
  return mrb_nil_value();
}

// conf.docroot = PATH. The ONE directory response.file may reach, resolved
// and opened once before the first accept. --docroot and [server] docroot
// both beat this, the same order everything else in here is beaten. Nothing
// is checked here on purpose: the path is validated where it is opened, so
// ONE refusal names it however the operator spelled it.
mrb_value conf_docroot_set(mrb_state* mrb, mrb_value self) {
  const char* p;
  mrb_int n;
  mrb_get_args(mrb, "s", &p, &n);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
  if (n == 0) mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.docroot is empty");
  s->docroot.assign(p, static_cast<size_t>(n));
  return mrb_nil_value();
}

// conf.url = "scheme://host:port" - webmachine-ruby's own spelling.
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

// conf.url reads both ways: the ask before the bind, the truth after it.
mrb_value conf_url_get(mrb_state* mrb, mrb_value self) {
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
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

// The token array crosses the boundary ONCE, here, for all three route kinds.
void walk_tokens(mrb_state* mrb, RouteTable& table, mrb_value toks, const char* who) {
  const mrb_int n = RARRAY_LEN(toks);
  table.open();
  for (mrb_int i = 0; i < n; i++) {
    const mrb_value t = mrb_ary_entry(toks, i);
    if (table.pending_splat()) {
      table.abandon();
      mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                 "%s: :* is the tail of a route - nothing may follow it", who);
    }
    if (mrb_string_p(t)) {
      // RFC 3986 3.3: a path is segments SEPARATED by "/", so a segment
      // can never contain one - match() splits on them before a literal
      // is ever compared. A route carrying one therefore matches nothing
      // at all, and the way that showed up was every request 404ing with
      // the routes looking right. ['/'] is the near-universal way to
      // write it wrong: the root is the EMPTY list, because the root has
      // no segments.
      const char* lit = RSTRING_PTR(t);
      const size_t litlen = static_cast<size_t>(RSTRING_LEN(t));
      if (std::memchr(lit, '/', litlen) != nullptr) {
        table.abandon();
        if (litlen == 1) {
          mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                     "%s: [\"/\"] is a route with one segment named \"/\", which no request "
                     "can have - the root is the empty list, add [], YourResource", who);
        }
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "%s: a route token is ONE path segment, and %v carries a \"/\" - split it "
                   "into one token per segment", who, t);
      }
      if (litlen == 0) {
        table.abandon();
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "%s: an empty token is a segment no request can have - to route the root, "
                   "pass no tokens at all", who);
      }
      if (!table.literal(lit, litlen)) {
        table.abandon();
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "%s: a literal token is too long", who);
      }
      continue;
    }
    if (mrb_symbol_p(t)) {
      if (mrb_symbol(t) == MRB_OPSYM(mul)) {
        table.splat();
        continue;
      }
      if (!table.binding(static_cast<uint32_t>(mrb_symbol(t)))) {
        table.abandon();
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "%s: too many bindings in one route (16 is the table's width)", who);
      }
      continue;
    }
    table.abandon();
    mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
               "%s: a token is a String (literal), a Symbol (binding) or :* (tail)", who);
  }
}

// route.add / app.add_route: the flow's table. Folds and FREEZES the class.
mrb_value route_add(mrb_state* mrb, mrb_value self) {
  mrb_value toks, klass;
  mrb_get_args(mrb, "Ao", &toks, &klass);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));

  if (!mrb_class_p(klass)) {
    mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
              "route.add wants a class inheriting Webmachine::Resource");
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

  walk_tokens(mrb, s->table, toks, "route.add");

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

// RFC 6455: route.websocket - the app's own second table.
mrb_value route_websocket(mrb_state* mrb, mrb_value self) {
  mrb_value toks, klass;
  mrb_get_args(mrb, "Ao", &toks, &klass);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));

  walk_tokens(mrb, s->ws_table, toks, "route.websocket");

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

// WHATWG HTML: route.sse - the app's own third table.
mrb_value route_sse(mrb_state* mrb, mrb_value self) {
  mrb_value toks, klass;
  mrb_get_args(mrb, "Ao", &toks, &klass);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));

  walk_tokens(mrb, s->sse_table, toks, "route.sse");

  std::unique_ptr<SseResource, void (*)(SseResource*)> res(sse_resource_new(),
                                                           sse_resource_free);
  char err[512] = "";
  if (!sse_fold(mrb, klass, *res, err, sizeof(err))) {
    s->sse_table.abandon();
    mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "%s", err);
  }
  s->sse_table.commit();
  s->sse_resources.push_back(std::move(res));
  return self;
}

// A signpost: assets are configured with --assets and serve unchanged.
mrb_value route_assets(mrb_state* mrb, mrb_value) {
  mrb_raise(mrb, E_WM_ROUTE_ERROR(mrb),
         "route.assets is reserved - the asset mount is #170/#115. Assets are configured "
         "with --assets and serve unchanged");
  return mrb_nil_value();
}

// Two applications may not name the same listener - compared on the SOCKET.
void register_app(mrb_state* mrb, AppSpec* s) {
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
      mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb), "two applications claim the same listener: port %d",
                 s->port);
    }
  }
  s->registered = true;
  registered_.push_back(s);
}

// Webmachine::Application.new { |app| ... } - the app's whole surface.
// initialize, not a hand-rolled .new: Class#new already allocates the
// MRB_TT_CDATA instance and forwards the block here.
mrb_value app_initialize(mrb_state* mrb, mrb_value self) {
  mrb_value blk = mrb_nil_value();
  mrb_get_args(mrb, "&", &blk);
  specs_.push_back(std::unique_ptr<AppSpec>(new AppSpec()));
  AppSpec* s = specs_.back().get();
  mrb_data_init(self, s, &app_type);
  mrb_iv_set(mrb, self, MRB_IVSYM(conf),
             mrb_obj_value(mrb_data_object_alloc(mrb, conf_class_, s, &app_type)));
  mrb_iv_set(mrb, self, MRB_IVSYM(routes),
             mrb_obj_value(mrb_data_object_alloc(mrb, route_class_, s, &app_type)));
  if (mrb_nil_p(blk)) return self;
  mrb_yield(mrb, blk, self);
  register_app(mrb, s);
  return self;
}

// webmachine-ruby compatibility: configure / config yield the one conf facade.
mrb_value app_configure(mrb_state* mrb, mrb_value self) {
  mrb_value blk = mrb_nil_value();
  mrb_get_args(mrb, "&", &blk);
  if (mrb_nil_p(blk)) mrb_raise(mrb, E_WM_ERROR(mrb), "app.configure wants a block");
  mrb_yield(mrb, blk, mrb_iv_get(mrb, self, MRB_IVSYM(conf)));
  return self;
}

// webmachine-ruby compatibility: routes yields the one route facade.
mrb_value app_routes(mrb_state* mrb, mrb_value self) {
  mrb_value blk = mrb_nil_value();
  mrb_get_args(mrb, "&", &blk);
  if (mrb_nil_p(blk)) mrb_raise(mrb, E_WM_ERROR(mrb), "app.routes wants a block");
  mrb_yield(mrb, blk, mrb_iv_get(mrb, self, MRB_IVSYM(routes)));
  return self;
}

// The hook that runs after the bind and before the first accept.
mrb_value app_ready(mrb_state* mrb, mrb_value self) {
  mrb_value blk = mrb_nil_value();
  mrb_get_args(mrb, "&", &blk);
  if (mrb_nil_p(blk)) mrb_raise(mrb, E_WM_ERROR(mrb), "app.ready wants a block");
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));
  if (s->have_ready) mrb_gc_unregister(mrb, s->ready);
  s->ready = blk;
  s->have_ready = true;
  mrb_gc_register(mrb, blk);
  return self;
}
}

// Webmachine::Application and its two hidden facade classes.
void application_init(mrb_state* mrb, struct RClass* wm) {
  struct RClass* app = mrb_define_class_under_id(mrb, wm, MRB_SYM(Application),
                                                 mrb->object_class);
  MRB_SET_INSTANCE_TT(app, MRB_TT_CDATA);
  mrb_define_method_id(mrb, app, MRB_SYM(initialize), app_initialize,
                        MRB_ARGS_NONE() | MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, app, MRB_SYM(configure), app_configure, MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, app, MRB_SYM(config), app_configure, MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, app, MRB_SYM(routes), app_routes, MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, app, MRB_SYM(ready), app_ready, MRB_ARGS_BLOCK());
  mrb_define_method_id(mrb, app, MRB_SYM(add_route), route_add, MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, app, MRB_SYM(add_websocket), route_websocket, MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, app, MRB_SYM(add_sse), route_sse, MRB_ARGS_REQ(2));

  conf_class_ = mrb_class_new(mrb, mrb->object_class);
  MRB_SET_INSTANCE_TT(conf_class_, MRB_TT_CDATA);
  mrb_gc_register(mrb, mrb_obj_value(conf_class_));
  mrb_define_method_id(mrb, conf_class_, MRB_SYM_E(port), conf_port_set, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_class_, MRB_SYM_E(unix_path), conf_unix_set,
                       MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_class_, MRB_SYM_E(url), conf_url_set, MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_class_, MRB_SYM(url), conf_url_get, MRB_ARGS_NONE());
  mrb_define_method_id(mrb, conf_class_, MRB_SYM_E(file_map_threshold), conf_map_set,
                       MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_class_, MRB_SYM_E(zero_copy_threshold), conf_zc_set,
                       MRB_ARGS_REQ(1));
  mrb_define_method_id(mrb, conf_class_, MRB_SYM_E(docroot), conf_docroot_set,
                       MRB_ARGS_REQ(1));

  route_class_ = mrb_class_new(mrb, mrb->object_class);
  MRB_SET_INSTANCE_TT(route_class_, MRB_TT_CDATA);
  mrb_gc_register(mrb, mrb_obj_value(route_class_));
  mrb_define_method_id(mrb, route_class_, MRB_SYM(add), route_add, MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, route_class_, MRB_SYM(sse), route_sse, MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, route_class_, MRB_SYM(websocket), route_websocket,
                       MRB_ARGS_ANY());
  mrb_define_method_id(mrb, route_class_, MRB_SYM(assets), route_assets, MRB_ARGS_ANY());
}

// Load the app's bytecode and call its `main`. A .rb is refused by name.
bool app_load(mrb_state* mrb, const char* path, char* err, size_t errlen) {
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

// Every application `main` registered - registration order IS listener order.
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

// A pack and no app: the asset tier answers before routing, so this app
// exists only to BE a listener's app - no routes, no resources, and every
// path the pack does not name is a 404. There is deliberately no resource
// here: an unfolded one answers out of nowhere, with no media type and no
// callback behind any of it (#201).
AppSpec* app_assets_only() {
  specs_.push_back(std::unique_ptr<AppSpec>(new AppSpec()));
  AppSpec* s = specs_.back().get();
  // No open()/commit() here: that pair IS a route - the one with an empty
  // token list, which is the root path. An empty table matches nothing, and
  // that is the point.
  s->registered = true;
  registered_.push_back(s);
  return s;
}

// What the listener REALLY became; this is what conf.url reads back.
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

// Run the ready hook from the TOOL, outside any VM frame - so, funcall.
bool app_ready_run(mrb_state* mrb, AppSpec& spec, char* err, size_t errlen) {
  if (!spec.have_ready) return true;
  const int ai = mrb_gc_arena_save(mrb);
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
}
