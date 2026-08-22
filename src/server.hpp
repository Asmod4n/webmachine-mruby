// The serve loop as a Ruby surface (#116 slice 3): `Webmachine.run`,
// `Webmachine.tick(budget)` and `Webmachine.fd`.
//
// Slice 1 and 2 put everything a request needs into tables at setup;
// what was left was the loop itself, which lived in the server tool
// and could not be entered from Ruby at all. It lives here now, as ONE
// process-wide server built on first use out of the applications
// `main` registered - the tool and an embedder enter the SAME object
// through the same three doors, so there is no second loop to keep in
// step with this one.
//
// The three doors, and why exactly these:
//   run                 - the tool's own loop: block, serve, return
//                         when the stop signal's completion lands.
//   tick(budget = nil)  - ONE bounded step for an embedder that owns
//                         its own loop. Gebot 18 as an API: the budget
//                         bounds the WORK, not just the wait.
//   fd                  - what such an embedder polls between ticks,
//                         so an idle server costs its host nothing.
#ifndef WEBMACHINE_SERVER_HPP
#define WEBMACHINE_SERVER_HPP

#include <mruby.h>

#include <cstddef>

namespace webmachine {

// What the INVOCATION decides, as opposed to what the app file does.
// The tool states this once, before `main` runs; nothing here is
// reachable from Ruby, deliberately - an app file that could rewrite
// the CLI would make the command line a suggestion.
struct ServerOptions {
  const char* assets_path = nullptr;  // --assets, null = no asset tier
  int stop_fd = -1;                   // the signalfd the ring polls
  const char* cli_unix = nullptr;     // --unix override
  int cli_port = 0;                   // --port override
  const char* app_path = nullptr;     // only ever named in messages
  bool have_uring = false;            // URING_AVAILABLE, asked once in the tool
};
void server_options(const ServerOptions& opts);

// WHICH io backend got linked was settled at build time (#171), and
// there is no second one in the binary to fall back to. This says so -
// loudly, once, at startup - when the select implementation is what
// answers, and refuses BY NAME when the real ring is in and this
// machine cannot run it. Both entries (this server and the echo floor)
// ask it, so the words exist once.
bool server_backend_ok(bool have_uring, char* err, size_t errlen);

// Webmachine.run / .tick / .fd, defined next to Application.
void server_init(mrb_state* mrb, struct RClass* wm);

// The tool's entry: build the server if Ruby has not already, then
// loop until the stop signal. 0 = a clean stop; anything else left a
// named reason in err.
int server_run(mrb_state* mrb, char* err, size_t errlen);

// Did Ruby already enter run or tick itself? Then `main` served, and
// the tool has nothing left to do.
bool server_entered();

}  // namespace webmachine

#endif
