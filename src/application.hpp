// The application (#116): `Webmachine::Application.new { |app| ... }`
// is the app's whole surface, and it is C - the block configures a
// listener, adds routes and leaves a `ready` hook, and by the time it
// returns everything a request will ever need is a table.
//
// The app file defines ONE method, `main`. app_load calls it; the
// constant scan that used to go looking for a resource class is gone
// (there is no hook, no ivar, no mrb->ud, and now no scan either).
#ifndef WEBMACHINE_APPLICATION_HPP
#define WEBMACHINE_APPLICATION_HPP

#include <mruby.h>

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

#include "resource.hpp"
#include "router.hpp"
#include "wsconn.hpp"

namespace webmachine {

// One application: its listener, its routes, its ready hook. Built
// entirely at setup - nothing in here is read on a request path except
// the RouteTable and the Resources it points at.
struct AppSpec {
  // EXACTLY ONE of the three forms (conf.port / conf.unix_path /
  // conf.url); a second one refuses by name.
  enum class Form : uint8_t { kNone, kPort, kUnix, kUrl };
  Form form = Form::kNone;
  int port = 0;
  std::string unix_path;
  std::string url_host;  // conf.url's authority; the ring binds INADDR_ANY
  // conf.url reads both ways: before the bind it spells where this app
  // WANTS to be, after it where it really is.
  std::string bound_url;
  bool bound = false;
  RouteTable table;
  // Parallel to table's routes, by index. unique_ptr because the run
  // frame's cfunc env borrows a Resource's ADDRESS (resource.hpp).
  std::vector<std::unique_ptr<Resource>> resources;
  // WEBSOCKET ROUTES ARE THEIR OWN TABLE (#175). They share nothing
  // with the flow: no status, no negotiation, no method test - a
  // websocket route is matched before all of that or not at all, so
  // giving it a second table costs one pointer compare on the upgrade
  // path and keeps the flow's table exactly as wide as the flow.
  RouteTable ws_table;
  std::vector<std::unique_ptr<WsResource, void (*)(WsResource*)>> ws_resources;
  mrb_value ready = mrb_nil_value();
  bool have_ready = false;
  bool registered = false;
};

// The gem's Application surface, defined next to Webmachine::Resource.
void application_init(mrb_state* mrb, struct RClass* wm);

// Loads the app's bytecode and calls its `main`. Every refusal (a .rb
// path, a load-time raise, a missing `main`, anything the block
// refused) lands in err by name.
bool app_load(mrb_state* mrb, const char* path, char* err, size_t errlen);

// Every application `main` registered, in registration order - that
// order IS the listener order, and a connection's listener index is
// how the writer finds its app again (#116 slice 2). False with a
// named reason: none registered, more than the ring has listeners, or
// one without a listener of its own.
bool app_registered_all(std::vector<AppSpec*>& out, size_t max_listeners, char* err,
                        size_t errlen);

// The app a server without --app serves: one splat route on
// webmachine-ruby's unbound resource, which is exactly what this
// server answered everywhere before routes existed.
AppSpec* app_default();

// What the listener REALLY became, once the ring has bound it: this is
// what conf.url reads back.
void app_mark_bound(AppSpec& spec, const char* unix_path, int port);

// The ready hook, called after the bind and before the first accept.
// False leaves the raise's reason in err.
bool app_ready_run(mrb_state* mrb, AppSpec& spec, char* err, size_t errlen);

}  // namespace webmachine

#endif
