// The config file (#166): the INVOCATION, as a file. webmachine.toml
// says what the command line says - listener override, app bytecode,
// asset archive, access log, pidfile, ring tunables - in the format
// every deployment tool already reads and writes.
//
// PRECEDENCE, one line: CLI > file > the app's conf. The file is the
// invocation's second voice, so the first (the typed flags) beats it,
// and both beat what `main` configures - exactly the --port/--unix
// rule that already existed, extended one seat down.
//
// WHAT THE FILE CANNOT DO (user decision, final): create resources.
// No routes, no bodies, no apps - Ruby owns behavior, the file owns
// operation. A server with no app file still serves: the default
// splat resource and the asset archive are apps the TREE provides,
// not ones the file created.
//
// The parser is mruby-toml, through the VM the process already
// carries (user decision): config is read ONCE at startup, never on
// a request path, so the Ruby-side surface is exactly enough and the
// binary carries no second TOML implementation.
//
// Every refusal is by name: a TOML error carries the parser's own
// words, an unknown key inside a section is a typo that must not
// silently do nothing, a wrong type or value says what it is and
// what it takes.
#ifndef WEBMACHINE_CONFIG_HPP
#define WEBMACHINE_CONFIG_HPP

#include <mruby.h>

#include <cstddef>
#include <string>

namespace webmachine {

// Parsed and validated webmachine.toml. Strings are owned copies -
// the caller keeps this alive for the run; empty string / 0 = the key
// was absent (every valid value is non-empty / non-zero).
struct Config {
  std::string path;  // where it came from, for messages

  // [server]
  std::string unix_path;  // unix = "PATH" - listener override, like --unix
  int port = 0;           // port = N     - listener override, like --port
  std::string app;        // app = "FILE.mrb"
  std::string assets;     // assets = "FILE.zip"
  std::string pidfile;    // pidfile = "PATH"

  // [log]
  std::string log_file;     // file = "PATH" (the log is opt-in, as ever)
  std::string log_privacy;  // privacy = "none" | "anon" | "full"

  // [tune] - setup-only ring knobs; 0 = the tree's default
  int backlog = 0;           // listen backlog (default 511, ring.hpp)
  unsigned sq_entries = 0;   // SQ size first ask (default 32768, halves on refusal)
};

// Parses and validates PATH into out, through the given VM. False
// leaves the reason in err, named: the file, the key, what it takes.
// Leaves no exception behind and no lasting object in the VM.
bool config_load(mrb_state* mrb, const char* path, Config& out, char* err, size_t errlen);

}  // namespace webmachine

#endif
