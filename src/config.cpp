// Design decisions live in .DESIGN.md, filed under what each comment names.
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
// TOML: the parser's own words become the refusal's text.
bool exc_into(mrb_state* mrb, const char* path, Refusal why) {
  char* const err = why.buf;
  const size_t errlen = why.len;
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

// The file being read: the VM that parsed it, its path, and the buffer a
// refusal is spelled into. One per config_load, handed to everything that
// can refuse.
struct ConfigFile {
  mrb_state* mrb;
  const char* path;
  char* err;
  size_t errlen;
};

// One setting: the table it sits in and the two names a message spells it
// with - "server" and "port" make server.port. A top-level section sits in
// the document itself and has no section above it, so `where` is empty
// there and `key` is the section's own name.
struct Setting {
  mrb_value table;
  const char* where;
  const char* key;
};

// TOML: the closed range a count must fall in.
struct Bounds {
  mrb_int lo;
  mrb_int hi;
};

// TOML: one top-level table, and whether the file named it at all - an
// absent one means the CLI or conf speaks.
struct FoundTable {
  mrb_value table{};
  bool present = false;
};

// TOML: one top-level section; an absent one means the CLI or conf speaks.
bool section(Setting s, FoundTable& out, const ConfigFile& f) {
  mrb_state* const mrb = f.mrb;
  mrb_value key = mrb_str_new_cstr(mrb, s.key);
  const mrb_value v = mrb_funcall_argv(mrb, s.table, MRB_OPSYM(aref), 1, &key);
  if (mrb->exc != nullptr) {
    if (mrb_obj_is_kind_of(mrb, mrb_obj_value(mrb->exc), E_KEY_ERROR)) {
      mrb->exc = nullptr;
      return true;
    }
    return !exc_into(mrb, f.path, {f.err, f.errlen});
  }
  if (!mrb_hash_p(v)) {
    std::snprintf(f.err, f.errlen, "%s: [%s] must be a table", f.path, s.key);
    return false;
  }
  out.table = v;
  out.present = true;
  return true;
}

// TOML: a present key must have the right type; absent is always fine.
bool take_string(Setting s, std::string& out, const ConfigFile& f) {
  const mrb_value v = mrb_hash_get(f.mrb, s.table, mrb_str_new_cstr(f.mrb, s.key));
  if (mrb_nil_p(v)) return true;
  if (!mrb_string_p(v) || RSTRING_LEN(v) == 0) {
    std::snprintf(f.err, f.errlen, "%s: %s.%s takes a non-empty string", f.path, s.where, s.key);
    return false;
  }
  out.assign(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
  return true;
}

// TOML: a count, in range. Counts are not durations.
bool take_int(Setting s, Bounds b, mrb_int* out, const ConfigFile& f) {
  const mrb_value v = mrb_hash_get(f.mrb, s.table, mrb_str_new_cstr(f.mrb, s.key));
  if (mrb_nil_p(v)) return true;
  if (!mrb_integer_p(v) || mrb_integer(v) < b.lo || mrb_integer(v) > b.hi) {
    std::snprintf(f.err, f.errlen, "%s: %s.%s takes an integer in %lld..%lld", f.path, s.where,
                  s.key, static_cast<long long>(b.lo), static_cast<long long>(b.hi));
    return false;
  }
  *out = mrb_integer(v);
  return true;
}

// TOML: a DURATION, through mruby-chrono and nothing else; rounded up.
bool take_seconds(Setting s, int* out, const ConfigFile& f) {
  const mrb_value v = mrb_hash_get(f.mrb, s.table, mrb_str_new_cstr(f.mrb, s.key));
  if (mrb_nil_p(v)) return true;
  if (!mrb_integer_p(v) && !mrb_float_p(v)) {
    std::snprintf(f.err, f.errlen, "%s: %s.%s takes a duration in seconds (60, or 0.5)", f.path,
                  s.where, s.key);
    return false;
  }
  const auto secs = mrb_chrono::ceil<std::chrono::seconds>(f.mrb, v);
  if (secs.count() < 1 || secs.count() > 86400) {
    std::snprintf(f.err, f.errlen, "%s: %s.%s is %lld seconds - the range is 1..86400", f.path,
                  s.where, s.key, static_cast<long long>(secs.count()));
    return false;
  }
  *out = static_cast<int>(secs.count());
  return true;
}
}

// TOML: parse and validate webmachine.toml through the VM the process carries.
bool config_load(Setup s, const char* path, Config& out) {
  mrb_state* const mrb = s.mrb;
  char* const err = s.why.buf;
  const size_t errlen = s.why.len;
  const int ai = mrb_gc_arena_save(mrb);
  bool ok = false;
  out.path = path;

  mrb_value p = mrb_str_new_cstr(mrb, path);
  const mrb_value doc = mrb_funcall_argv(mrb, mrb_obj_value(mrb_module_get_id(mrb, MRB_SYM(TOML))),
                                         MRB_SYM(load), 1, &p);
  if (exc_into(mrb, path, {err, errlen})) goto done;

  {
    const ConfigFile file = {mrb, path, err, errlen};
    FoundTable server, log, tune;
    mrb_int port = 0, backlog = 0, sq = 0, maxb = 0, zct = -1, fmt = -1;
    if (!section({doc, "", "server"}, server, file)) goto done;
    if (!section({doc, "", "log"}, log, file)) goto done;
    if (!section({doc, "", "tune"}, tune, file)) goto done;

    if (server.present) {
      const mrb_value t = server.table;
      if (!take_string({t, "server", "unix"}, out.unix_path, file)) goto done;
      if (!take_int({t, "server", "port"}, {1, 65535}, &port, file)) goto done;
      if (!take_string({t, "server", "app"}, out.app, file)) goto done;
      if (!take_string({t, "server", "assets"}, out.assets, file)) goto done;
      if (!take_string({t, "server", "docroot"}, out.docroot, file)) goto done;
      if (!take_string({t, "server", "mime_types"}, out.mime_types, file)) goto done;
      if (!take_string({t, "server", "pidfile"}, out.pidfile, file)) goto done;
      out.port = static_cast<int>(port);
      if (!out.unix_path.empty() && out.port != 0) {
        std::snprintf(err, errlen, "%s: server.unix and server.port - at most one", path);
        goto done;
      }
    }

    if (log.present) {
      const mrb_value t = log.table;
      if (!take_string({t, "log", "file"}, out.log_file, file)) goto done;
      if (!take_string({t, "log", "privacy"}, out.log_privacy, file)) goto done;
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
      if (!take_string({t, "log", "error_file"}, out.error_log_file, file)) goto done;
      if (!take_int({t, "log", "max_bytes"}, {4096, 1LL << 40}, &maxb, file)) goto done;
      out.log_max_bytes = static_cast<unsigned long long>(maxb);
    }

    if (tune.present) {
      const mrb_value t = tune.table;
      if (!take_int({t, "tune", "backlog"}, {1, 65535}, &backlog, file)) goto done;
      if (!take_int({t, "tune", "sq_entries"}, {1, 32768}, &sq, file)) goto done;
      // 0 is the operator saying "never lend, always copy" - a real answer,
      // which is why absence is -1 and not 0. bench/vm/zero_copy_advise.sh
      // measures the crossover on the machine that will run this.
      if (!take_int({t, "tune", "zero_copy_threshold"},
                    {0, static_cast<mrb_int>(kZeroCopyMax)}, &zct, file)) {
        goto done;
      }
      // 0 is the operator saying "never map, always read" - a real answer,
      // which is why absence is -1 and not 0.
      if (!take_int({t, "tune", "file_map_threshold"},
                    {0, static_cast<mrb_int>(kFileMapMax)}, &fmt, file)) {
        goto done;
      }
      if (!take_seconds({t, "tune", "header_timeout"}, &out.header_timeout, file)) goto done;
      if (!take_seconds({t, "tune", "send_timeout"}, &out.send_timeout, file)) goto done;
      if (!take_seconds({t, "tune", "idle_timeout"}, &out.idle_timeout, file)) goto done;
      out.backlog = static_cast<int>(backlog);
      out.sq_entries = static_cast<unsigned>(sq);
      if (zct >= 0) out.zero_copy_threshold = static_cast<long long>(zct);
      if (fmt >= 0) out.file_map_threshold = static_cast<long long>(fmt);
    }

    ok = true;
  }

done:
  mrb_gc_arena_restore(mrb, ai);
  return ok;
}
}
