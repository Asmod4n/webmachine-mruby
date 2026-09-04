// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/dump.h>
#include <mruby/error.h>
#include <mruby/irep.h>
#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <cstdio>
#include <cstring>
#include <string>

#include <mruby/task_hal_webmachine.h>
#include <task.h>

#include <ada.h>

namespace webmachine {
namespace {
std::vector<std::unique_ptr<AppSpec>> specs_;
std::vector<AppSpec*> registered_;

const struct mrb_data_type app_type = {"webmachine.app", nullptr};

// Webmachine::Config, defined in mrblib. Looked up once, when the
// mrblib that defines it has run - C makes what Ruby needs to run,
// so this is the other direction and cannot be done at gem init.
struct RClass* config_class_ = nullptr;
struct RClass* route_class_ = nullptr;

// Exactly one listener spelling per app; a second refuses by name.
// One form an application may be declared in, and the word that names it.
struct Form {
  AppSpec::Form kind;
  const char* name;
};

void claim_form(mrb_state* mrb, AppSpec* s, Form want) {
  const AppSpec::Form f = want.kind;
  const char* const name = want.name;
  if (s->form != AppSpec::Form::kNone && s->form != f) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "conf.%s: this application already named its listener another way - "
               "exactly one of port, unix_path or url per application",
               name);
  }
  s->form = f;
}

// The whole set of settings a URL or a config file may reach, and the
// reason it is a TABLE and not a name lookup.
//
// The parameters are spelled like the conf setters on purpose - a knob
// is called the same thing everywhere it can be named (AppSpec's own
// comment says so). It would therefore be one line to send the setter
// by that name and be done. That line would be remote code execution:
// whoever writes the URL or the config file would be calling methods on
// the conf object by name, and every method conf ever gains would join
// the attack surface by existing. Routes are Ruby because a route names
// a CLASS; nothing here may name one.
//
// So the names are a convention for people, and the dispatch is this
// switch. What a URL can set is countable by reading it, an unknown key
// is refused, and add_route, add_websocket, add_sse and ready are not
// reachable from here because they are not in it.
enum class Setting : uint8_t {
  kDocroot,
  kCertificate,
  kPrivateKey,
  kFileMapThreshold,
  kZeroCopyThreshold,
  kDisableHttpCats,
  kUnknown,
};

Setting setting_for(std::string_view k) {
  if (k == "docroot") return Setting::kDocroot;
  if (k == "certificate") return Setting::kCertificate;
  if (k == "private_key") return Setting::kPrivateKey;
  if (k == "file_map_threshold") return Setting::kFileMapThreshold;
  if (k == "zero_copy_threshold") return Setting::kZeroCopyThreshold;
  if (k == "disable_http_cats") return Setting::kDisableHttpCats;
  return Setting::kUnknown;
}

// A whole-string unsigned read: strtoll would accept "8k" and a leading
// '+' or space, and this must not.
bool whole_number(std::string_view v, long long* out) {
  if (v.empty() || v.size() > 19) return false;
  long long n = 0;
  for (const char c : v) {
    if (c < '0' || c > '9') return false;
    n = n * 10 + (c - '0');
  }
  *out = n;
  return true;
}

// RFC-nothing: what an operator writes for a flag. Spelled out rather
// than "anything that is not 0", so a typo is a refusal and not a
// silent true.
bool whole_flag(std::string_view v, bool* out) {
  if (v == "1" || v == "true") { *out = true; return true; }
  if (v == "0" || v == "false") { *out = false; return true; }
  return false;
}

// One setting from the URL's query, refused rather than applied twice.
// The bounds are the setters' own - a value that conf.docroot= would
// reject is rejected here in the same words, because there is one rule
// per knob and this is not a second one.
void apply_setting(mrb_state* mrb, AppSpec* s, std::string_view key, std::string_view val) {
  const Setting what = setting_for(key);
  if (what == Setting::kUnknown) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "conf.url: %s is not a setting - a URL may name docroot, certificate, "
               "private_key, file_map_threshold, zero_copy_threshold or "
               "disable_http_cats, and routes stay in Ruby",
               std::string(key).c_str());
  }
  long long n = 0;
  bool flag = false;
  switch (what) {
    case Setting::kDocroot:
      if (val.empty()) mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: docroot is empty");
      if (!s->docroot.empty()) {
        mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: docroot was already named");
      }
      s->docroot.assign(val);
      return;
    case Setting::kCertificate:
      if (val.empty()) mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: certificate is empty");
      if (!s->cert_path.empty()) {
        mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: certificate was already named");
      }
      s->cert_path.assign(val);
      return;
    case Setting::kPrivateKey:
      if (val.empty()) mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: private_key is empty");
      if (!s->key_path.empty()) {
        mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: private_key was already named");
      }
      s->key_path.assign(val);
      return;
    case Setting::kFileMapThreshold:
      if (!whole_number(val, &n) || n > static_cast<long long>(kFileMapMax)) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "conf.url: file_map_threshold = %s is outside 0..%i bytes",
                   std::string(val).c_str(), static_cast<mrb_int>(kFileMapMax));
      }
      if (s->file_map_threshold >= 0) {
        mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: file_map_threshold was already named");
      }
      s->file_map_threshold = n;
      return;
    case Setting::kZeroCopyThreshold:
      if (!whole_number(val, &n) || n > static_cast<long long>(kZeroCopyMax)) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "conf.url: zero_copy_threshold = %s is outside 0..%i bytes",
                   std::string(val).c_str(), static_cast<mrb_int>(kZeroCopyMax));
      }
      if (s->zero_copy_threshold >= 0) {
        mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: zero_copy_threshold was already named");
      }
      s->zero_copy_threshold = n;
      return;
    case Setting::kDisableHttpCats:
      if (!whole_flag(val, &flag)) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                   "conf.url: disable_http_cats = %s is not 1, 0, true or false",
                   std::string(val).c_str());
      }
      if (s->disable_http_cats >= 0) {
        mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: disable_http_cats was already named");
      }
      s->disable_http_cats = flag ? 1 : 0;
      return;
    case Setting::kUnknown:
      break;
  }
  __builtin_unreachable();
}

// conf.url = "scheme://host[:port][?setting=value&...]" - webmachine-ruby's
// own spelling, parsed by ada (WHATWG URL Standard) rather than by
// find("://") and rfind(':').
//
// What the hand-rolled one got wrong, and no test covered because every
// test used the same happy shape:
//
//   http://[::1]              refused with "has no usable port" -
//                             rfind(':') landed INSIDE the literal, so
//                             the port read as "1]". A valid absolute
//                             URL whose port is the scheme's 80.
//   http://user@127.0.0.1:80  accepted, and url_host became
//                             "user@127.0.0.1" - userinfo folded into
//                             the host and on into bound_url.
//
// The scheme names the listener - http, https, or unix for a socket
// path - and the query carries the rest of the conf object, under the
// setters' own names. It is an ADDITION: every setter stays, and a knob
// named twice is a ConfigError rather than a precedence rule, the same
// answer claim_form gives a listener named twice.
//
// What may appear there is apply_setting's table and nothing else, for
// the reason written above it: routes name classes and stay in Ruby.
//
// Credentials are refused rather than carried - they name nothing a
// listener can serve. A path is ignored under http and https, as it was
// before: webmachine-ruby's conf.url may carry one and it names no
// listener. Under unix the path IS the listener.
void apply_url(mrb_state* mrb, AppSpec* s, const std::string& u) {

  auto parsed = ada::parse<ada::url_aggregator>(u);
  if (!parsed) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "conf.url = %s is not scheme://host[:port] or unix:///path", u.c_str());
  }
  // ada spells a scheme with its colon; the message says what was asked
  // for, not what ada calls it.
  const std::string_view proto = parsed->get_protocol();
  const bool unix_form = proto == "unix:";
  const bool tls = proto == "https:";
  if (!unix_form && !tls && proto != "http:") {
    const std::string scheme(proto.substr(0, proto.size() - 1));
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url scheme %s is not http, https or unix",
               scheme.c_str());
  }
  if (parsed->has_credentials()) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "conf.url = %s carries credentials, which name no listener", u.c_str());
  }

  // The FORM is the URL's, not the setter's: everything downstream reads
  // it to decide what to bind (server.cpp), which listener collides with
  // which (app_register), and what conf.url reads back. A unix:// URL
  // that claimed kUrl would be bound as a port - port 0, since it never
  // named one.
  claim_form(mrb, s, {unix_form ? AppSpec::Form::kUnix : AppSpec::Form::kUrl, "url"});

  if (unix_form) {
    // A socket path, percent-decoded: ada hands the pathname back in the
    // URL's own spelling, and a path with a space in it is written %20.
    const std::string_view path = parsed->get_pathname();
    const size_t pct = path.find('%');
    const std::string sock = pct == std::string_view::npos
                                 ? std::string(path)
                                 : ada::unicode::percent_decode(path, pct);
    if (sock.empty() || sock == "/") {
      mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url = %s names no socket path", u.c_str());
    }
    s->tls = false;
    s->unix_path = sock;
  } else {
    const std::string_view host = parsed->get_hostname();
    if (host.empty()) mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url = %s has no host", u.c_str());
    // An absent port IS the scheme's default; ada leaves get_port() empty
    // for it rather than writing 80 or 443 back out.
    int port = tls ? 443 : 80;
    const std::string_view ps = parsed->get_port();
    if (!ps.empty()) {
      port = 0;
      for (char c : ps) port = port * 10 + (c - '0');
    }
    s->tls = tls;
    s->url_host.assign(host);
    s->port = port;
  }

  const std::string_view search = parsed->get_search();
  if (!search.empty()) {
    // get_search() keeps the '?'; url_search_params wants the query.
    ada::url_search_params params{search.substr(1)};
    for (const auto& kv : params) apply_setting(mrb, s, kv.first, kv.second);
  }
}

// The configuration arrives as ONE value: the Webmachine::Config struct
// mrblib defines. A Struct in mruby IS an array (MRB_TT_STRUCT is struct
// RArray in value.h), so this walks it - through mrb_ary_entry, never by
// reaching into the object - and decides what each slot means.
//
// The ORDER is the contract, and it is written down twice on purpose:
// once as the member list in mrblib/webmachine.rb and once here. The
// length check below is what notices if the two ever drift, at the first
// Application.new rather than in whichever knob happened to move.
//
// Ruby collects; this decides. Every ceiling, every refusal and the
// whole grammar of conf.url are here, in the words they had when they
// were nine separate setters.
enum ConfIdx {
  kConfPort,
  kConfUnixPath,
  kConfUrl,
  kConfDocroot,
  kConfCertificate,
  kConfPrivateKey,
  kConfFileMapThreshold,
  kConfZeroCopyThreshold,
  kConfDisableHttpCats,
  kConfMax,
};

// A named string slot: absent is nothing said, present and empty is a
// refusal, because an empty path is a mistake and not an answer.
bool conf_str(mrb_state* mrb, mrb_value conf, ConfIdx at, const char* name, std::string* out) {
  const mrb_value v = mrb_ary_entry(conf, at);
  if (mrb_nil_p(v)) return false;
  if (!mrb_string_p(v)) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s wants a String", name);
  }
  if (RSTRING_LEN(v) == 0) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s is empty", name);
  }
  out->assign(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
  return true;
}

// A named whole-number slot, refused by the ceiling that owns it.
bool conf_int(mrb_state* mrb, mrb_value conf, ConfIdx at, const char* name, mrb_int ceiling,
              const char* unit, mrb_int* out) {
  const mrb_value v = mrb_ary_entry(conf, at);
  if (mrb_nil_p(v)) return false;
  if (!mrb_integer_p(v)) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s wants an Integer", name);
  }
  const mrb_int n = mrb_integer(v);
  if (n < 0 || n > ceiling) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s = %i is outside 0..%i%s", name, n, ceiling,
               unit);
  }
  *out = n;
  return true;
}

void read_config(mrb_state* mrb, mrb_value conf, AppSpec* s) {
  // MRB_TT_STRUCT, not MRB_TT_ARRAY: a Struct is struct RArray in memory
  // and mrb_ary_entry reads it, but it carries its OWN type tag, so
  // mrb_array_p says no. Checked before the first mrb_ary_entry, because
  // that one trusts the tag it was handed.
  if (mrb_type(conf) != MRB_TT_STRUCT || RARRAY_LEN(conf) != kConfMax) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "conf is not the %i values Webmachine::Config names - application.cpp's "
               "ConfIdx and mrblib's Struct member list have drifted apart",
               static_cast<mrb_int>(kConfMax));
  }

  // The listener first, and exactly one spelling of it: claim_form is
  // what refuses the second, and it refuses in member order now rather
  // than in the order the app happened to write them.
  mrb_int n = 0;
  if (conf_int(mrb, conf, kConfPort, "port", 65535, "", &n)) {
    claim_form(mrb, s, {AppSpec::Form::kPort, "port"});
    s->port = static_cast<int>(n);
  }
  std::string text;
  if (conf_str(mrb, conf, kConfUnixPath, "unix_path", &text)) {
    claim_form(mrb, s, {AppSpec::Form::kUnix, "unix_path"});
    s->unix_path = text;
  }
  if (conf_str(mrb, conf, kConfUrl, "url", &text)) apply_url(mrb, s, text);

  if (conf_str(mrb, conf, kConfDocroot, "docroot", &text)) {
    if (!s->docroot.empty()) {
      mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: docroot was already named");
    }
    s->docroot = text;
  }
  if (conf_str(mrb, conf, kConfCertificate, "certificate", &text)) {
    if (!s->cert_path.empty()) {
      mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: certificate was already named");
    }
    s->cert_path = text;
  }
  if (conf_str(mrb, conf, kConfPrivateKey, "private_key", &text)) {
    if (!s->key_path.empty()) {
      mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: private_key was already named");
    }
    s->key_path = text;
  }
  if (conf_int(mrb, conf, kConfFileMapThreshold, "file_map_threshold",
               static_cast<mrb_int>(kFileMapMax), " bytes", &n)) {
    if (s->file_map_threshold >= 0) {
      mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: file_map_threshold was already named");
    }
    s->file_map_threshold = n;
  }
  if (conf_int(mrb, conf, kConfZeroCopyThreshold, "zero_copy_threshold",
               static_cast<mrb_int>(kZeroCopyMax), " bytes", &n)) {
    if (s->zero_copy_threshold >= 0) {
      mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: zero_copy_threshold was already named");
    }
    s->zero_copy_threshold = n;
  }
  const mrb_value cats = mrb_ary_entry(conf, kConfDisableHttpCats);
  if (!mrb_nil_p(cats)) {
    const int8_t want = mrb_test(cats) ? 1 : 0;
    if (s->disable_http_cats >= 0) {
      mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb), "conf.url: disable_http_cats was already named");
    }
    s->disable_http_cats = want;
  }

  // conf.url reads both ways: the ask before the bind, the truth after
  // it. Before the bind there is nothing truer than what was written, so
  // the slot keeps it; app_mark_bound overwrites it with what the
  // listener really became.
  if (mrb_nil_p(mrb_ary_entry(conf, kConfUrl)) && s->form != AppSpec::Form::kNone) {
    const char* const scheme = s->tls ? "https" : "http";
    const mrb_value said =
        s->form == AppSpec::Form::kUnix
            ? mrb_format(mrb, "unix://%s", s->unix_path.c_str())
            : mrb_format(mrb, "%s://0.0.0.0:%d", scheme, s->port);
    mrb_ary_set(mrb, conf, kConfUrl, said);
  }
}

// The token array crosses the boundary ONCE, here, for all three route kinds.
// The route tokens an app handed over, and the call that handed them -
// which is the word a refusal names.
struct Tokens {
  mrb_value list;
  const char* who;
};

void walk_tokens(mrb_state* mrb, RouteTable& table, Tokens t) {
  const mrb_value toks = t.list;
  const char* const who = t.who;
  const mrb_int n = RARRAY_LEN(toks);
  for (mrb_int i = 0; i < n; i++) {
    const mrb_value t = mrb_ary_entry(toks, i);
    if (table.pending_splat()) {
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
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "%s: an empty token is a segment no request can have - to route the root, "
                   "pass no tokens at all", who);
      }
      if (!table.literal(lit, litlen)) {
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
        mrb_raisef(mrb, E_WM_ROUTE_ERROR(mrb),
                   "%s: too many bindings in one route (16 is the table's width)", who);
      }
      continue;
    }
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

  OpenRoute route(s->table);
  walk_tokens(mrb, s->table, {toks, "route.add"});

  auto res = std::unique_ptr<Resource>(new Resource());
  resource_fold(mrb, klass, *res);
  route.commit();
  s->resources.push_back(std::move(res));
  return self;
}

// RFC 6455: route.websocket - the app's own second table.
mrb_value route_websocket(mrb_state* mrb, mrb_value self) {
  mrb_value toks, klass;
  mrb_get_args(mrb, "Ao", &toks, &klass);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));

  OpenRoute route(s->ws_table);
  walk_tokens(mrb, s->ws_table, {toks, "route.websocket"});

  std::unique_ptr<WsResource, void (*)(WsResource*)> res(ws_resource_new(), ws_resource_free);
  ws_fold(mrb, klass, *res);
  route.commit();
  s->ws_resources.push_back(std::move(res));
  return self;
}

// WHATWG HTML: route.sse - the app's own third table.
mrb_value route_sse(mrb_state* mrb, mrb_value self) {
  mrb_value toks, klass;
  mrb_get_args(mrb, "Ao", &toks, &klass);
  AppSpec* s = static_cast<AppSpec*>(mrb_data_get_ptr(mrb, self, &app_type));

  OpenRoute route(s->sse_table);
  walk_tokens(mrb, s->sse_table, {toks, "route.sse"});

  std::unique_ptr<SseResource, void (*)(SseResource*)> res(sse_resource_new(),
                                                           sse_resource_free);
  sse_fold(mrb, klass, *res);
  route.commit();
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
  // Looked up here and not at gem init: mrblib runs AFTER the C side, so
  // Webmachine::Config does not exist yet when this file's init does.
  if (config_class_ == nullptr) {
    config_class_ = mrb_class_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)),
                                           MRB_SYM(Config));
  }
  // The conf object is Ruby's: mrblib names the members, this only reads
  // them back at the end of the block. mrb_obj_new and not a hand-built
  // array, so Struct.new's own initialize decides the shape.
  const mrb_value conf = mrb_obj_new(mrb, config_class_, 0, nullptr);
  s->conf = conf;
  mrb_gc_register(mrb, conf);
  mrb_iv_set(mrb, self, MRB_IVSYM(conf), conf);
  mrb_iv_set(mrb, self, MRB_IVSYM(routes),
             mrb_obj_value(mrb_data_object_alloc(mrb, route_class_, s, &app_type)));
  if (mrb_nil_p(blk)) return self;
  mrb_yield(mrb, blk, self);
  read_config(mrb, conf, s);
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
  // The ceilings, named once. mrblib's Config refuses a value against
  // these at the moment it is assigned - which is what makes a refusal
  // catchable where it was caused - and read_config checks them again on
  // the way out, because Struct#[]= reaches a member without a writer.
  // One source, two readers; the numbers are not written down in Ruby.
  mrb_define_const_id(mrb, wm, MRB_SYM(PORT_MAX), mrb_fixnum_value(65535));
  mrb_define_const_id(mrb, wm, MRB_SYM(FILE_MAP_MAX),
                      mrb_fixnum_value(static_cast<mrb_int>(kFileMapMax)));
  mrb_define_const_id(mrb, wm, MRB_SYM(ZERO_COPY_MAX),
                      mrb_fixnum_value(static_cast<mrb_int>(kZeroCopyMax)));

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

  route_class_ = mrb_class_new(mrb, mrb->object_class);
  MRB_SET_INSTANCE_TT(route_class_, MRB_TT_CDATA);
  mrb_gc_register(mrb, mrb_obj_value(route_class_));
  mrb_define_method_id(mrb, route_class_, MRB_SYM(add), route_add, MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, route_class_, MRB_SYM(sse), route_sse, MRB_ARGS_REQ(2));
  mrb_define_method_id(mrb, route_class_, MRB_SYM(websocket), route_websocket,
                       MRB_ARGS_ANY());
  mrb_define_method_id(mrb, route_class_, MRB_SYM(assets), route_assets, MRB_ARGS_ANY());
}

namespace {
// mrb_protect_error's shape: one mrb_value in, one out. The tool's step
// wants a process exit code, so the code comes back through Guarded.
struct GuardedRun {
  Guarded step;
  int rc;
};

mrb_value guarded_body(mrb_state* mrb, void* ud) {
  GuardedRun* g = static_cast<GuardedRun*>(ud);
  g->rc = g->step.body(mrb, g->step.ud);
  return mrb_nil_value();
}
}  // namespace

int run_guarded(mrb_state* mrb, Guarded step) {
  // The two things every VM in this process needs, and the only place
  // this one passes through right after mrb_open. The HAL header says
  // why the queue can only be taken away here.
  mrb_hal_task_drop_queue(mrb);
  // This VM answers requests. It runs no task - only a worker does, in
  // a VM of its own - and a scheduler nobody uses is not free: with it
  // on, mrb_vm_exec evaluates RETURN_IF_TASK_STOPPED at EVERY opcode
  // (mruby/src/vm.c:2267 and :2336). The build has MRB_USE_TASK_SCHEDULER
  // because the workers need it, so the check is compiled in and only
  // `task.enabled` can turn it off.
  //
  // mrbgem.rake said this was already done. It was not: nothing called
  // it, in any binary, so every request walked Ruby with the check on.
  //
  // The function is not in upstream mruby yet (mruby/mruby#7491), so
  // mrbgem.rake reads mruby-task's header and defines this only when the
  // checkout has it. A checkout without it builds and answers requests -
  // slower, with the check on. patches/ carries the three commits.
#ifdef WM_TASK_SCHEDULER_CAN_BE_DISABLED
  mrb_disable_task_scheduler(mrb);
#endif
  GuardedRun g{step, 0};
  mrb_bool raised = FALSE;
  const mrb_value e = mrb_protect_error(mrb, guarded_body, &g, &raised);
  if (!raised) return g.rc;
  // mrb_protect_error hands back whatever was pending, and mrb->exc takes
  // an exception object or nothing - the same trap resource.cpp's
  // take_pending is about. With one, mruby prints class, message and
  // backtrace better than any format string here could.
  if (mrb_exception_p(e)) {
    mrb->exc = mrb_obj_ptr(e);
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    // The exit code is the exception's CLASS. A config the operator wrote
    // wrong is 2 - the shell's "what you asked for cannot be done" - and
    // every other refusal is 1. Nothing else has to agree on a number.
    return mrb_obj_is_kind_of(mrb, e, E_WM_CONFIG_ERROR(mrb)) ? 2 : 1;
  }
  const mrb_value said = mrb_obj_as_string(mrb, e);
  std::fputs("webmachine: ", stderr);
  std::fwrite(RSTRING_PTR(said), 1, static_cast<size_t>(RSTRING_LEN(said)), stderr);
  std::fputc('\n', stderr);
  return 1;
}

// Load the app's bytecode and call its `main`. A .rb is refused by name.
void app_load(mrb_state* mrb, const char* path) {
  const size_t path_len = std::strlen(path);
  if (path_len >= 3 && std::memcmp(path + path_len - 3, ".rb", 3) == 0) {
    const std::string mrb_path(path, path_len - 3);
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "%s is Ruby source, not bytecode - this server loads bytecode only. Compile "
               "it first: mrbc -o %s.mrb %s",
               path, mrb_path.c_str(), path);
  }
  FILE* f = std::fopen(path, "rb");
  if (f == nullptr) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "cannot open %s: %s", path, std::strerror(errno));
  }
  // Read before loading, so the bytes can be hashed: app_build_hash is
  // what every error fingerprint is taken over first, and it is these
  // bytes - a rake that changed anything changes it, and with it every
  // hash this build can produce.
  std::string image;
  char chunk[65536];
  size_t got = 0;
  while ((got = std::fread(chunk, 1, sizeof chunk, f)) != 0) image.append(chunk, got);
  std::fclose(f);
  if (image.empty()) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s is empty - that is no bytecode", path);
  }
  app_build_hash() = fnv1a(kFnvBasis, image.data(), image.size());
  const ArenaGuard arena(mrb);
  mrb_load_irep_buf(mrb, image.data(), image.size());
  // The app's own exception, with its class and its line. It used to be
  // printed here and replaced by "app raised while loading (exception
  // below)" - which said less than the exception and went to a stream
  // nothing reads.
  if (mrb->exc != nullptr) rethrow(mrb);
  struct RClass* owner = mrb->object_class;
  if (MRB_METHOD_UNDEF_P(mrb_method_search_vm(mrb, &owner, MRB_SYM(main)))) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "%s defines no `main` - since #116 an app file defines exactly that, and "
               "Webmachine::Application.new inside it registers the app",
               path);
  }
  mrb_funcall_argv(mrb, mrb_top_self(mrb), MRB_SYM(main), 0, nullptr);
  if (mrb->exc != nullptr) rethrow(mrb);
}

// Every application `main` registered - registration order IS listener order.
void app_registered_all(mrb_state* mrb, Registered out_) {
  std::vector<AppSpec*>& out = out_.specs;
  const size_t max_listeners = out_.max_listeners;
  if (registered_.empty()) {
    mrb_raise(mrb, E_WM_CONFIG_ERROR(mrb),
              "main registered no application - Webmachine::Application.new takes a block, "
              "and returning from it is what registers the app");
  }
  if (registered_.size() > max_listeners) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
               "main registered %i applications and the ring holds %i listeners",
               static_cast<mrb_int>(registered_.size()), static_cast<mrb_int>(max_listeners));
  }
  out.assign(registered_.begin(), registered_.end());
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
void app_mark_bound(mrb_state* mrb, AppSpec& spec, const char* unix_path, int port) {
  if (unix_path != nullptr) {
    spec.bound_url = std::string("unix://") + unix_path;
  } else if (!spec.url_host.empty()) {
    spec.bound_url = "http://" + spec.url_host + ":" + std::to_string(port);
  } else {
    spec.bound_url = "http://0.0.0.0:" + std::to_string(port);
  }
  spec.bound = true;
  if (!mrb_nil_p(spec.conf)) {
    mrb_ary_set(mrb, spec.conf, kConfUrl,
                mrb_str_new(mrb, spec.bound_url.data(), spec.bound_url.size()));
  }
}

// Run the ready hook from the TOOL, outside any VM frame - so, funcall.
void app_ready_run(mrb_state* mrb, AppSpec& spec) {
  if (!spec.have_ready) return;
  const ArenaGuard arena(mrb);
  mrb_funcall_argv(mrb, spec.ready, MRB_SYM(call), 0, nullptr);
  if (mrb->exc != nullptr) rethrow(mrb);
}
}
