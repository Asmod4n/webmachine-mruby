// config.hpp's head says what the file may decide and why; this file
// only reads, checks and copies. Everything here runs once, before
// the ring exists. mruby-toml does the parsing: TOML.load(path)
// returns a Document, and a section read through #[] arrives as a
// plain Hash - Ruby values this side walks with the C API and copies
// out of before the arena closes.

#include "webmachine.hpp"

#include <mruby/array.h>
#include <mruby/chrono.hpp>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>

#include <chrono>
#include <cstdio>
#include <cstring>

namespace webmachine {

namespace {

// Any raise on the way is the refusal's text: the parser's own words
// name the line and the reason better than a paraphrase would.
//
// Read STRAIGHT from the field, never through a funcall: with an
// exception pending the VM is not in a state to run Ruby, and calling
// #message there is asking for a second failure on top of the first.
// mruby/error.h says what the field is ("RException.mesg is NULL or
// probably RString"); resource_exception_begin reads it the same way.
bool exc_into(mrb_state* mrb, const char* path, char* err, size_t errlen) {
  if (mrb->exc == nullptr) return false;
  struct RException* e = reinterpret_cast<struct RException*>(mrb->exc);
  mrb->exc = nullptr;
  if (e->mesg != nullptr && e->mesg->tt == MRB_TT_STRING) {
    const mrb_value msg = mrb_obj_value(e->mesg);
    std::snprintf(err, errlen, "%s: %.*s", path, static_cast<int>(RSTRING_LEN(msg)),
                  RSTRING_PTR(msg));
  } else {
    std::snprintf(err, errlen, "%s: refused, and the reason carries no message", path);
  }
  return true;
}

// A top-level section: Document#[] raises KeyError for an absent key,
// which here just means "the CLI or the app's conf speaks" - any
// other raise is the file's problem. Present must be a table.
bool section(mrb_state* mrb, mrb_value doc, const char* name, mrb_value* out, bool* present,
             const char* path, char* err, size_t errlen) {
  *present = false;
  mrb_value key = mrb_str_new_cstr(mrb, name);
  const mrb_value v = mrb_funcall_argv(mrb, doc, MRB_OPSYM(aref), 1, &key);
  if (mrb->exc != nullptr) {
    if (mrb_obj_is_kind_of(mrb, mrb_obj_value(mrb->exc), E_KEY_ERROR)) {
      mrb->exc = nullptr;
      return true;
    }
    return !exc_into(mrb, path, err, errlen);
  }
  if (!mrb_hash_p(v)) {
    std::snprintf(err, errlen, "%s: [%s] must be a table", path, name);
    return false;
  }
  *out = v;
  *present = true;
  return true;
}

// A present key must have the right type and a usable value; absent
// is always fine.
bool take_string(mrb_state* mrb, mrb_value h, const char* where, const char* key,
                 std::string& out, const char* path, char* err, size_t errlen) {
  const mrb_value v = mrb_hash_get(mrb, h, mrb_str_new_cstr(mrb, key));
  if (mrb_nil_p(v)) return true;
  if (!mrb_string_p(v) || RSTRING_LEN(v) == 0) {
    std::snprintf(err, errlen, "%s: %s.%s takes a non-empty string", path, where, key);
    return false;
  }
  out.assign(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
  return true;
}

bool take_int(mrb_state* mrb, mrb_value h, const char* where, const char* key, mrb_int lo,
              mrb_int hi, mrb_int* out, const char* path, char* err, size_t errlen) {
  const mrb_value v = mrb_hash_get(mrb, h, mrb_str_new_cstr(mrb, key));
  if (mrb_nil_p(v)) return true;
  if (!mrb_integer_p(v) || mrb_integer(v) < lo || mrb_integer(v) > hi) {
    std::snprintf(err, errlen, "%s: %s.%s takes an integer in %lld..%lld", path, where, key,
                  static_cast<long long>(lo), static_cast<long long>(hi));
    return false;
  }
  *out = mrb_integer(v);
  return true;
}

// A DURATION crossing the Ruby<->C boundary goes through mruby-chrono
// and through nothing else (standing rule): ONE convention for every
// timeout this tree will ever take, which is also why `0.5` is a
// correct half second here instead of a parse error - the API reads
// Integer and Float alike.
//
// The target is seconds because that is what the ring can ENFORCE:
// #180's deadlines are whole seconds and its reaper runs once a
// second. A sub-second ask is therefore rounded UP (ceil), never
// down - the one direction that cannot cut a connection earlier than
// the operator asked for.
bool take_seconds(mrb_state* mrb, mrb_value h, const char* where, const char* key, int* out,
                  const char* path, char* err, size_t errlen) {
  const mrb_value v = mrb_hash_get(mrb, h, mrb_str_new_cstr(mrb, key));
  if (mrb_nil_p(v)) return true;
  if (!mrb_integer_p(v) && !mrb_float_p(v)) {
    std::snprintf(err, errlen, "%s: %s.%s takes a duration in seconds (60, or 0.5)", path,
                  where, key);
    return false;
  }
  const auto secs = mrb_chrono::ceil<std::chrono::seconds>(mrb, v);
  if (secs.count() < 1 || secs.count() > 86400) {
    std::snprintf(err, errlen, "%s: %s.%s is %lld seconds - the range is 1..86400", path, where,
                  key, static_cast<long long>(secs.count()));
    return false;
  }
  *out = static_cast<int>(secs.count());
  return true;
}

}  // namespace

bool config_load(mrb_state* mrb, const char* path, Config& out, char* err, size_t errlen) {
  const int ai = mrb_gc_arena_save(mrb);
  bool ok = false;
  out.path = path;

  mrb_value p = mrb_str_new_cstr(mrb, path);
  const mrb_value doc = mrb_funcall_argv(mrb, mrb_obj_value(mrb_module_get_id(mrb, MRB_SYM(TOML))),
                                         MRB_SYM(load), 1, &p);
  if (exc_into(mrb, path, err, errlen)) goto done;

  {
    mrb_value server{}, log{}, tune{};
    bool have_server = false, have_log = false, have_tune = false;
    mrb_int port = 0, backlog = 0, sq = 0, maxb = 0;
    if (!section(mrb, doc, "server", &server, &have_server, path, err, errlen)) goto done;
    if (!section(mrb, doc, "log", &log, &have_log, path, err, errlen)) goto done;
    if (!section(mrb, doc, "tune", &tune, &have_tune, path, err, errlen)) goto done;

    if (have_server) {
      if (!take_string(mrb, server, "server", "unix", out.unix_path, path, err, errlen)) goto done;
      if (!take_int(mrb, server, "server", "port", 1, 65535, &port, path, err, errlen)) goto done;
      if (!take_string(mrb, server, "server", "app", out.app, path, err, errlen)) goto done;
      if (!take_string(mrb, server, "server", "assets", out.assets, path, err, errlen)) goto done;
      if (!take_string(mrb, server, "server", "mime_types", out.mime_types, path, err, errlen)) {
        goto done;
      }
      if (!take_string(mrb, server, "server", "pidfile", out.pidfile, path, err, errlen)) {
        goto done;
      }
      out.port = static_cast<int>(port);
      // The same rule the CLI enforces for --unix/--port: one listener
      // override, not a quiet priority between two.
      if (!out.unix_path.empty() && out.port != 0) {
        std::snprintf(err, errlen, "%s: server.unix and server.port - at most one", path);
        goto done;
      }
    }

    if (have_log) {
      if (!take_string(mrb, log, "log", "file", out.log_file, path, err, errlen)) goto done;
      if (!take_string(mrb, log, "log", "privacy", out.log_privacy, path, err, errlen)) goto done;
      // The word is checked HERE, where the operator can still read
      // the answer, not in the daemon after the fork.
      if (!out.log_privacy.empty() && out.log_privacy != "none" && out.log_privacy != "anon" &&
          out.log_privacy != "full") {
        std::snprintf(err, errlen, "%s: log.privacy '%s'? none, anon or full", path,
                      out.log_privacy.c_str());
        goto done;
      }
      if (!out.log_privacy.empty() && out.log_file.empty()) {
        std::snprintf(err, errlen, "%s: log.privacy without log.file decides nothing", path);
        goto done;
      }
      if (!take_string(mrb, log, "log", "error_file", out.error_log_file, path, err, errlen)) {
        goto done;
      }
      // The ceiling is a COUNT of bytes, not a duration - take_int,
      // like backlog and sq_entries. Its floor is 4096: a cap smaller
      // than a line keeps nothing, and half of it (what the daemon
      // keeps) has to hold at least one whole entry to be a log.
      if (!take_int(mrb, log, "log", "max_bytes", 4096, 1LL << 40, &maxb, path, err, errlen)) {
        goto done;
      }
      out.log_max_bytes = static_cast<unsigned long long>(maxb);
    }

    if (have_tune) {
      if (!take_int(mrb, tune, "tune", "backlog", 1, 65535, &backlog, path, err, errlen)) {
        goto done;
      }
      // 32768 is IORING_MAX_ENTRIES, the kernel's own ceiling - more
      // is not "more headroom", it is -EINVAL at init.
      if (!take_int(mrb, tune, "tune", "sq_entries", 1, 32768, &sq, path, err, errlen)) goto done;
      // The #180 clocks are DURATIONS, so they take the chrono road
      // (take_seconds says why); backlog and sq_entries stay integers
      // because they are COUNTS, and a count is not a duration.
      if (!take_seconds(mrb, tune, "tune", "header_timeout", &out.header_timeout, path, err,
                        errlen)) {
        goto done;
      }
      if (!take_seconds(mrb, tune, "tune", "send_timeout", &out.send_timeout, path, err,
                        errlen)) {
        goto done;
      }
      if (!take_seconds(mrb, tune, "tune", "idle_timeout", &out.idle_timeout, path, err,
                        errlen)) {
        goto done;
      }
      out.backlog = static_cast<int>(backlog);
      out.sq_entries = static_cast<unsigned>(sq);
    }

    ok = true;
  }

done:
  // Everything worth keeping was copied into std::strings; the
  // Document and every converted Hash die with the arena.
  mrb_gc_arena_restore(mrb, ai);
  return ok;
}

}  // namespace webmachine
