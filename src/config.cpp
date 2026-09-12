#include "ruby_value.hpp"

#include <mruby/array.h>
#include <mruby/chrono.hpp>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>

#include <chrono>
#include <cstdio>
#include <cstring>

namespace webmachine
{
namespace
{
// The file being read: the VM that parsed it, and its path - which every
// refusal names, because an operator with three configs needs to know
// which one the sentence is about.
struct ConfigFile {
    mrb_state *mrb;
    const char *path;
};

// TOML::load, and what it was asked to read.
struct TomlAsk {
    mrb_value path;
};

mrb_value toml_load_in_protected_call(mrb_state *mrb, void *user_data)
{
    TomlAsk *ask = static_cast<TomlAsk *>(user_data);
    struct RClass *toml = mrb_module_get_id(mrb, MRB_SYM(TOML));
    return mrb_funcall_argv(mrb, mrb_obj_value(toml), MRB_SYM(load), 1, &ask->path);
}

// TOML: the parser's own words, under this file's name. Caught on purpose
// - the parser says what is wrong with the syntax and nothing about which
// file, and the operator needs both in one sentence.
mrb_value toml_document_load(const ConfigFile &file)
{
    mrb_state *const mrb = file.mrb;
    TomlAsk ask{mrb_str_new_cstr(mrb, file.path)};
    mrb_bool raised = FALSE;
    const mrb_value document = mrb_protect_error(mrb, toml_load_in_protected_call, &ask, &raised);
    if (raised)
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: %v", file.path, document);
    return document;
}

// TOML: one section, read out of the document. A missing key is how an
// absent section answers here, so that one exception is expected and the
// rest are the file's fault.
struct SectionAsk {
    mrb_value document;
    mrb_value key;
};

mrb_value section_read_in_protected_call(mrb_state *mrb, void *user_data)
{
    SectionAsk *ask = static_cast<SectionAsk *>(user_data);
    return mrb_funcall_argv(mrb, ask->document, MRB_OPSYM(aref), 1, &ask->key);
}

// One setting: the table it sits in and the two names a message spells it
// with - "server" and "port" make server.port. A top-level section sits in
// the document itself and has no section above it, so `where` is empty
// there and `key` is the section's own name.
struct Setting {
    mrb_value table;
    const char *where;
    const char *key_name;
};

// TOML: the closed range a count must fall in.
struct Bounds {
    mrb_int low;
    mrb_int high;
};

// TOML: one top-level table, and whether the file named it at all - an
// absent one means the CLI or conf speaks.
struct FoundTable {
    mrb_value table{};
    bool present = false;
};

// TOML: one top-level section; an absent one means the CLI or conf speaks.
void section_take(Setting setting, FoundTable &out_table, const ConfigFile &file)
{
    mrb_state *const mrb = file.mrb;
    SectionAsk ask{setting.table, mrb_str_new_cstr(mrb, setting.key_name)};
    mrb_bool raised = FALSE;
    const mrb_value answer = mrb_protect_error(mrb, section_read_in_protected_call, &ask, &raised);
    if (raised) {
        if (mrb_obj_is_kind_of(mrb, answer, E_KEY_ERROR))
            return;
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: %v", file.path, answer);
    }
    if (!mrb_hash_p(answer)) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: [%s] must be a table, not %v", file.path,
                   setting.key_name, answer);
    }
    out_table.table = answer;
    out_table.present = true;
}

// TOML: a present key must have the right type; absent is always fine.
void setting_take_string(Setting setting, std::string &out_text, const ConfigFile &file)
{
    const mrb_value raw =
        mrb_hash_get(file.mrb, setting.table, mrb_str_new_cstr(file.mrb, setting.key_name));
    if (mrb_nil_p(raw))
        return;
    if (!mrb_string_p(raw) || ruby_string_length(raw) == 0) {
        mrb_raisef(file.mrb, E_WM_CONFIG_ERROR(file.mrb),
                   "%s: %s.%s takes a non-empty string, not %v", file.path, setting.where,
                   setting.key_name, raw);
    }
    out_text.assign(ruby_string_bytes(raw));
}

// TOML: a count, in range. Counts are not durations.
void setting_take_int(Setting setting, Bounds bounds, mrb_int *out_count, const ConfigFile &file)
{
    const mrb_value raw =
        mrb_hash_get(file.mrb, setting.table, mrb_str_new_cstr(file.mrb, setting.key_name));
    if (mrb_nil_p(raw))
        return;
    if (!mrb_integer_p(raw) || mrb_integer(raw) < bounds.low || mrb_integer(raw) > bounds.high) {
        mrb_raisef(file.mrb, E_WM_CONFIG_ERROR(file.mrb),
                   "%s: %s.%s takes an integer in %i..%i, not %v", file.path, setting.where,
                   setting.key_name, bounds.low, bounds.high, raw);
    }
    *out_count = mrb_integer(raw);
}

// TOML: a duration, through mruby-chrono and nothing else; rounded up.
void setting_take_seconds(Setting setting, int *out_seconds, const ConfigFile &file)
{
    const mrb_value raw =
        mrb_hash_get(file.mrb, setting.table, mrb_str_new_cstr(file.mrb, setting.key_name));
    if (mrb_nil_p(raw))
        return;
    if (!mrb_integer_p(raw) && !mrb_float_p(raw)) {
        mrb_raisef(file.mrb, E_WM_CONFIG_ERROR(file.mrb),
                   "%s: %s.%s takes a duration in seconds (60, or 0.5), not %v", file.path,
                   setting.where, setting.key_name, raw);
    }
    const auto secs = mrb_chrono::ceil<std::chrono::seconds>(file.mrb, raw);
    if (secs.count() < 1 || secs.count() > 86400) {
        mrb_raisef(file.mrb, E_WM_CONFIG_ERROR(file.mrb),
                   "%s: %s.%s is %i seconds - the range is 1..86400", file.path, setting.where,
                   setting.key_name, static_cast<mrb_int>(secs.count()));
    }
    *out_seconds = static_cast<int>(secs.count());
}
} // namespace

// The file --write-config leaves behind. What is in it is what this
// server would have done anyway, so an operator can read the defaults
// instead of being told them, and change one line instead of learning a
// flag. Nothing writes this without being asked.
bool config_write_default(const char *path, const char *error_assets)
{
    FILE *file = std::fopen(path, "wxe"); // x: never over a file somebody has
    if (file == nullptr)
        return false;
    const bool have_assets = error_assets != nullptr && error_assets[0] != '\0';
    std::fprintf(file,
                 "# webmachine.toml - written by --write-config.\n"
                 "#\n"
                 "# Every knob this server reads from a file is here, with what it does\n"
                 "# and what it does without you. Nothing in this file changes anything\n"
                 "# until you change a line: these are the answers.\n"
                 "#\n"
                 "# A flag beats this file; this file beats the app's own conf.\n"
                 "\n"
                 "[server]\n"
                 "# Where a standalone server answers. At most one of the two - a unix\n"
                 "# socket, or a TCP port. An application names its own listener in its\n"
                 "# conf, and one process serves any number of applications.\n"
                 "# unix = \"/run/webmachine.sock\"\n"
                 "# port = 8080\n"
                 "\n"
                 "# What it serves: an application, or files with --standalone. With\n"
                 "# nothing to serve there is no start. An application names its own\n"
                 "# pack and docroot in its conf (conf.assets, conf.docroot).\n"
                 "# app = \"site.mrb\"           # the application, as bytecode (mrbc)\n"
                 "# assets = \"site.zip\"        # standalone: a pack, answered from one mapping\n"
                 "# docroot = \"/srv/site\"      # standalone: a directory of files\n"
                 "\n"
                 "# The media-type database. Without it the machine's own is found:\n"
                 "# /etc/mime.types, then Apache's, then shared-mime-info, then the\n"
                 "# list compiled in.\n"
                 "# mime_types = \"/etc/mime.types\"\n"
                 "\n"
                 "# Where the pid goes, removed on the way out. Without it, nowhere.\n"
                 "# pidfile = \"/run/webmachine.pid\"\n"
                 "\n"
                 "# The error pages' pictures. Without it, the installed archive under\n"
                 "# /usr/local/share/webmachine-mruby, then under /usr/share; without\n"
                 "# either, the pages render without pictures.\n"
                 "%serror_assets = \"%s\"\n"
                 "\n"
                 "[log]\n"
                 "# The access log. Both logs are opt-in, separate files, separate\n"
                 "# writers, no field in common. Without them, nothing is written.\n"
                 "# file = \"/var/log/webmachine/access.log\"\n"
                 "\n"
                 "# What an address looks like in that log: none, anon or full.\n"
                 "# anon is the default and drops the host part; full keeps the\n"
                 "# address; none writes no address at all.\n"
                 "# privacy = \"anon\"\n"
                 "\n"
                 "# What a callback raised, with its class, message, backtrace, the\n"
                 "# request that led there and up to 4 KB of its body. That last part\n"
                 "# is whatever the app was sent - a form login puts a password in it -\n"
                 "# so the server creates this file readable by its owner alone, and\n"
                 "# follows no symlink to it.\n"
                 "# error_file = \"/var/log/webmachine/error.log\"\n"
                 "\n"
                 "# The ceiling on the access log, in bytes. 0 is no ceiling.\n"
                 "# max_bytes = 524288000        # 500 MB, the default\n"
                 "\n"
                 "[tune]\n"
                 "# Every value here is a property of the machine, not of the site.\n"
                 "# Measure before you change one: bench/ has the harnesses.\n"
                 "\n"
                 "# listen(2)'s backlog. Without it, SOMAXCONN.\n"
                 "# backlog = 4096\n"
                 "\n"
                 "# The submission queue this ring asks the kernel for. It is halved\n"
                 "# until the kernel agrees, so this is a wish and not a promise.\n"
                 "# sq_entries = %u\n"
                 "\n"
                 "# From this size up a body is lent to the kernel instead of copied\n"
                 "# into the send buffer. 0 is \"never lend\", which is a real answer.\n"
                 "# zero_copy_threshold = %zu     # %zu KiB, the default\n"
                 "\n"
                 "# From this size up a file is mapped and handed to one send instead\n"
                 "# of being read window by window. The default is one window: a file\n"
                 "# that small is one read, so a mapping would replace nothing and\n"
                 "# still cost the mmap/munmap pair. 0 is \"never map\".\n"
                 "# file_map_threshold = %zu      # %zu KiB, the default\n"
                 "\n"
                 "# How long a client may take over one thing, in seconds. Fractions\n"
                 "# are allowed (0.5).\n"
                 "# header_timeout = 60          # to finish sending a request head\n"
                 "# send_timeout = 60            # to take an answer this side wrote\n"
                 "# idle_timeout = 75            # to send the next request on a kept\n"
                 "                               # connection\n",
                 have_assets ? "" : "# ",
                 have_assets ? error_assets : "/usr/local/share/webmachine-mruby/error-assets.zip",
                 kSqWanted, kZeroCopyDefault, kZeroCopyDefault / 1024, kFileMapDefault,
                 kFileMapDefault / 1024);
    std::fclose(file);
    return true;
}

// TOML: parse and validate webmachine.toml through the VM the process carries.
void config_load(mrb_state *mrb, const char *path, Config &out_config)
{
    const ArenaGuard arena(mrb);
    out_config.path = path;
    const ConfigFile file = {mrb, path};
    const mrb_value document = toml_document_load(file);

    FoundTable server, log, tune;
    mrb_int port = 0, backlog = 0, sq = 0, maxb = 0, zct = -1, fmt = -1;
    section_take({document, "", "server"}, server, file);
    section_take({document, "", "log"}, log, file);
    section_take({document, "", "tune"}, tune, file);

    if (server.present) {
        const mrb_value table = server.table;
        setting_take_string({table, "server", "unix"}, out_config.unix_path, file);
        setting_take_int({table, "server", "port"}, {1, 65535}, &port, file);
        setting_take_string({table, "server", "app"}, out_config.app, file);
        setting_take_string({table, "server", "assets"}, out_config.assets, file);
        setting_take_string({table, "server", "docroot"}, out_config.docroot, file);
        setting_take_string({table, "server", "mime_types"}, out_config.mime_types, file);
        setting_take_string({table, "server", "error_assets"}, out_config.error_assets, file);
        setting_take_string({table, "server", "pidfile"}, out_config.pidfile, file);
        out_config.port = static_cast<int>(port);
        if (!out_config.unix_path.empty() && out_config.port != 0) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: server.unix and server.port - at most one",
                       path);
        }
    }

    if (log.present) {
        const mrb_value table = log.table;
        setting_take_string({table, "log", "file"}, out_config.log_file, file);
        setting_take_string({table, "log", "privacy"}, out_config.log_privacy, file);
        if (!out_config.log_privacy.empty() && out_config.log_privacy != "none" &&
            out_config.log_privacy != "anon" && out_config.log_privacy != "full") {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "%s: log.privacy '%s'? none, anon or full",
                       path, out_config.log_privacy.c_str());
        }
        if (!out_config.log_privacy.empty() && out_config.log_file.empty()) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                       "%s: log.privacy without log.file decides nothing", path);
        }
        setting_take_string({table, "log", "error_file"}, out_config.error_log_file, file);
        setting_take_int({table, "log", "max_bytes"}, {4096, 1LL << 40}, &maxb, file);
        out_config.log_max_bytes = static_cast<unsigned long long>(maxb);
    }

    if (tune.present) {
        const mrb_value table = tune.table;
        setting_take_int({table, "tune", "backlog"}, {1, 65535}, &backlog, file);
        setting_take_int({table, "tune", "sq_entries"}, {1, 32768}, &sq, file);
        // 0 is the operator saying "never lend, always copy" - a real answer,
        // which is why absence is -1 and not 0. bench/vm/zero_copy_advise.sh
        // measures the crossover on the machine that will run this.
        setting_take_int({table, "tune", "zero_copy_threshold"},
                         {0, static_cast<mrb_int>(kZeroCopyMax)}, &zct, file);
        // 0 is the operator saying "never map, always read" - a real answer,
        // which is why absence is -1 and not 0.
        setting_take_int({table, "tune", "file_map_threshold"},
                         {0, static_cast<mrb_int>(kFileMapMax)}, &fmt, file);
        setting_take_seconds({table, "tune", "header_timeout"}, &out_config.header_timeout, file);
        setting_take_seconds({table, "tune", "send_timeout"}, &out_config.send_timeout, file);
        setting_take_seconds({table, "tune", "idle_timeout"}, &out_config.idle_timeout, file);
        out_config.backlog = static_cast<int>(backlog);
        out_config.sq_entries = static_cast<unsigned>(sq);
        if (zct >= 0)
            out_config.zero_copy_threshold = static_cast<long long>(zct);
        if (fmt >= 0)
            out_config.file_map_threshold = static_cast<long long>(fmt);
    }
}
} // namespace webmachine
