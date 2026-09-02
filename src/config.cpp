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
// The file being read: the VM that parsed it, and its path - which every
// refusal names, because an operator with three configs needs to know
// which one the sentence is about.
struct ConfigFile {
  mrb_state* mrb;
  const char* path;
};

// TOML::load, and what it was asked to read.
struct TomlAsk {
  mrb_value path;
};

mrb_value toml_load_body(mrb_state* mrb, void* ud) {
  TomlAsk* a = static_cast<TomlAsk*>(ud);
  struct RClass* toml = mrb_module_get_id(mrb, MRB_SYM(TOML));
  return mrb_funcall_argv(mrb, mrb_obj_value(toml), MRB_SYM(load), 1, &a->path);
}

// TOML: the parser's own words, under this file's name. Caught on purpose
// - the parser says what is wrong with the syntax and nothing about WHICH
// file, and the operator needs both in one sentence.
mrb_value toml_load(const ConfigFile& f) {
  mrb_state* const mrb = f.mrb;
  TomlAsk ask{mrb_str_new_cstr(mrb, f.path)};
  mrb_bool raised = FALSE;
  const mrb_value doc = mrb_protect_error(mrb, toml_load_body, &ask, &raised);
  if (raised) mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: %v", f.path, doc);
  return doc;
}

// TOML: one section, read out of the document. A missing key is how an
// absent section answers here, so that one exception is expected and the
// rest are the file's fault.
struct SectionAsk {
  mrb_value doc;
  mrb_value key;
};

mrb_value section_body(mrb_state* mrb, void* ud) {
  SectionAsk* a = static_cast<SectionAsk*>(ud);
  return mrb_funcall_argv(mrb, a->doc, MRB_OPSYM(aref), 1, &a->key);
}

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
void section(Setting s, FoundTable& out, const ConfigFile& f) {
  mrb_state* const mrb = f.mrb;
  SectionAsk ask{s.table, mrb_str_new_cstr(mrb, s.key)};
  mrb_bool raised = FALSE;
  const mrb_value v = mrb_protect_error(mrb, section_body, &ask, &raised);
  if (raised) {
    if (mrb_obj_is_kind_of(mrb, v, E_KEY_ERROR)) return;
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: %v", f.path, v);
  }
  if (!mrb_hash_p(v)) {
    mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: [%s] must be a table, not %v", f.path, s.key, v);
  }
  out.table = v;
  out.present = true;
}

// TOML: a present key must have the right type; absent is always fine.
void take_string(Setting s, std::string& out, const ConfigFile& f) {
  const mrb_value v = mrb_hash_get(f.mrb, s.table, mrb_str_new_cstr(f.mrb, s.key));
  if (mrb_nil_p(v)) return;
  if (!mrb_string_p(v) || RSTRING_LEN(v) == 0) {
    mrb_raisef(f.mrb, E_WM_CONFIG_ERROR(f.mrb), "%s: %s.%s takes a non-empty string, not %v",
               f.path, s.where, s.key, v);
  }
  out.assign(RSTRING_PTR(v), static_cast<size_t>(RSTRING_LEN(v)));
}

// TOML: a count, in range. Counts are not durations.
void take_int(Setting s, Bounds b, mrb_int* out, const ConfigFile& f) {
  const mrb_value v = mrb_hash_get(f.mrb, s.table, mrb_str_new_cstr(f.mrb, s.key));
  if (mrb_nil_p(v)) return;
  if (!mrb_integer_p(v) || mrb_integer(v) < b.lo || mrb_integer(v) > b.hi) {
    mrb_raisef(f.mrb, E_WM_CONFIG_ERROR(f.mrb), "%s: %s.%s takes an integer in %i..%i, not %v",
               f.path, s.where, s.key, b.lo, b.hi, v);
  }
  *out = mrb_integer(v);
}

// TOML: a DURATION, through mruby-chrono and nothing else; rounded up.
void take_seconds(Setting s, int* out, const ConfigFile& f) {
  const mrb_value v = mrb_hash_get(f.mrb, s.table, mrb_str_new_cstr(f.mrb, s.key));
  if (mrb_nil_p(v)) return;
  if (!mrb_integer_p(v) && !mrb_float_p(v)) {
    mrb_raisef(f.mrb, E_WM_CONFIG_ERROR(f.mrb),
               "%s: %s.%s takes a duration in seconds (60, or 0.5), not %v", f.path, s.where,
               s.key, v);
  }
  const auto secs = mrb_chrono::ceil<std::chrono::seconds>(f.mrb, v);
  if (secs.count() < 1 || secs.count() > 86400) {
    mrb_raisef(f.mrb, E_WM_CONFIG_ERROR(f.mrb), "%s: %s.%s is %i seconds - the range is 1..86400",
               f.path, s.where, s.key, static_cast<mrb_int>(secs.count()));
  }
  *out = static_cast<int>(secs.count());
}
}

// TOML: parse and validate webmachine.toml through the VM the process carries.
void config_load(mrb_state* mrb, const char* path, Config& out) {
  const ArenaGuard arena(mrb);
  out.path = path;
  const ConfigFile file = {mrb, path};
  const mrb_value doc = toml_load(file);

  FoundTable server, log, tune;
  mrb_int port = 0, backlog = 0, sq = 0, maxb = 0, zct = -1, fmt = -1;
  section({doc, "", "server"}, server, file);
  section({doc, "", "log"}, log, file);
  section({doc, "", "tune"}, tune, file);

  if (server.present) {
    const mrb_value t = server.table;
    take_string({t, "server", "unix"}, out.unix_path, file);
    take_int({t, "server", "port"}, {1, 65535}, &port, file);
    take_string({t, "server", "app"}, out.app, file);
    take_string({t, "server", "assets"}, out.assets, file);
    take_string({t, "server", "docroot"}, out.docroot, file);
    take_string({t, "server", "mime_types"}, out.mime_types, file);
    take_string({t, "server", "pidfile"}, out.pidfile, file);
    out.port = static_cast<int>(port);
    if (!out.unix_path.empty() && out.port != 0) {
      mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: server.unix and server.port - at most one",
                 path);
    }
  }

  if (log.present) {
    const mrb_value t = log.table;
    take_string({t, "log", "file"}, out.log_file, file);
    take_string({t, "log", "privacy"}, out.log_privacy, file);
    if (!out.log_privacy.empty() && out.log_privacy != "none" && out.log_privacy != "anon" &&
        out.log_privacy != "full") {
      mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: log.privacy '%s'? none, anon or full", path,
                 out.log_privacy.c_str());
    }
    if (!out.log_privacy.empty() && out.log_file.empty()) {
      mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: log.privacy without log.file decides nothing",
                 path);
    }
    take_string({t, "log", "error_file"}, out.error_log_file, file);
    take_int({t, "log", "max_bytes"}, {4096, 1LL << 40}, &maxb, file);
    out.log_max_bytes = static_cast<unsigned long long>(maxb);
  }

  if (tune.present) {
    const mrb_value t = tune.table;
    take_int({t, "tune", "backlog"}, {1, 65535}, &backlog, file);
    take_int({t, "tune", "sq_entries"}, {1, 32768}, &sq, file);
    // 0 is the operator saying "never lend, always copy" - a real answer,
    // which is why absence is -1 and not 0. bench/vm/zero_copy_advise.sh
    // measures the crossover on the machine that will run this.
    take_int({t, "tune", "zero_copy_threshold"}, {0, static_cast<mrb_int>(kZeroCopyMax)}, &zct,
             file);
    // 0 is the operator saying "never map, always read" - a real answer,
    // which is why absence is -1 and not 0.
    take_int({t, "tune", "file_map_threshold"}, {0, static_cast<mrb_int>(kFileMapMax)}, &fmt,
             file);
    take_seconds({t, "tune", "header_timeout"}, &out.header_timeout, file);
    take_seconds({t, "tune", "send_timeout"}, &out.send_timeout, file);
    take_seconds({t, "tune", "idle_timeout"}, &out.idle_timeout, file);
    out.backlog = static_cast<int>(backlog);
    out.sq_entries = static_cast<unsigned>(sq);
    if (zct >= 0) out.zero_copy_threshold = static_cast<long long>(zct);
    if (fmt >= 0) out.file_map_threshold = static_cast<long long>(fmt);
  }
}
}
