#include <mruby.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/throw.h>
#include <mruby/variable.h>
#include <pthread.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <sys/uio.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>

#include "../../src/webmachine.hpp"


// What this invocation decided. The flags fill it, the config file fills
// what the flags left, and from there it is one thing travelling from the
// first argument to the last accept - see #std-first.
struct Invocation {
  webmachine::ServerOptions opts;
  webmachine::Config fc;
  int argc = 0;
  char** argv = nullptr;
  const char* pidfile = nullptr;
  const char* config_path = nullptr;
  const char* cli_unix = nullptr;
  const char* log_path = nullptr;
  const char* log_privacy = nullptr;
  // --write-config[=PATH]: write the file and stop. Nothing is served.
  const char* write_config = nullptr;
  const char* error_log_path = nullptr;
  long long log_max_bytes = -1;
  int cli_port = 0;
};

void usage(const char* me) {
  std::fprintf(stderr,
               "usage: %s [OPTIONS]\n"
               "\n"
               "  Every option is --key=value. There are two ways to serve:\n"
               "  an application (--app), or standalone (--standalone), which\n"
               "  serves files and enters no VM. One of the two, or no start.\n"
               "\n"
               "FILES\n"
               "  --mime-types=FILE        this media-type database, not the machine's\n"
               "\n"
               "LOG\n"
               "  --log=FILE               the access log\n"
               "  --log-privacy=MODE       none | anon | full                       (anon)\n"
               "  --error-log=FILE         what a callback raised; mrbc -g for line numbers\n"
               "  --log-max-bytes=N        ceiling on the access log, 0 = none    (500 MB)\n"
               "\n"
               "TUNE\n"
               "  --zero-copy-threshold=N  lend a body this big instead of copying (128 KiB)\n"
               "  --file-map-threshold=N   map a file this big instead of reading  (256 KiB)\n"
               "\n"
               "OTHER\n"
               "  --config=FILE.toml       these choices from a file; flags beat it.\n"
               "                           Without it: ./webmachine.toml, then\n"
               "                           /usr/local/etc/webmachine/, then /etc/webmachine/\n"
               "  --write-config[=PATH]    write that file with the defaults in it, and stop\n"
               "  --pidfile=PATH           write this pid, remove it on the way out\n"
               "\n"
               "AN APPLICATION\n"
               "  --app=FILE.mrb           the application, as bytecode - required\n"
               "  --error-assets=FILE.zip  what an error answer may hand over\n"
               "                           The listener, the pack and the docroot are the\n"
               "                           application's own: conf.port, conf.unix_path,\n"
               "                           conf.url, conf.assets, conf.docroot. One process\n"
               "                           serves any number of applications.\n"
               "\n"
               "STANDALONE - files only, and the folded graph answers them\n"
               "  --standalone             no app, no route, no VM entry per request\n"
               "  --unix=PATH              answer on a unix socket\n"
               "  --port=N                 answer on a TCP port\n"
               "  --assets=FILE.zip        answered first, from its mapping\n"
               "  --docroot=DIR            answered next, from disk; needs one of the two\n"
               "                           GET and HEAD; a directory takes its index.html\n"
               ,
               me);
}

// Every flag this build answers to. The parser accepts any well-formed
// key, so the set a typo is measured against has to be stated: it is
// this one, and it is also what the usage text above lists.
const char* const kFlags[] = {
    "unix", "port", "app", "standalone", "assets", "error-assets", "docroot", "mime-types",
    "write-config",
    "log", "log-privacy", "error-log", "log-max-bytes", "file-map-threshold",
    "zero-copy-threshold", "pidfile", "config",
};

// A path, or nullptr when the flag was not given. The string is the
// hash's, and the hash outlives this process's start-up (see below), so
// what is handed out here stays good for as long as anything reads it.
const char* text_of(mrb_state* mrb, mrb_value h, const char* key) {
  const mrb_value v = mrb_hash_get(mrb, h, mrb_str_new_cstr(mrb, key));
  if (mrb_nil_p(v)) return nullptr;
  if (!mrb_string_p(v)) mrb_raisef(mrb, E_ARGUMENT_ERROR, "--%s takes text", key);
  return mrb_string_cstr(mrb, v);
}

// A flag with no value: `--standalone`. TypedArgs answers true for one
// that was given, and nothing for one that was not.
bool flag_of(mrb_state* mrb, mrb_value h, const char* key) {
  const mrb_value v = mrb_hash_get(mrb, h, mrb_str_new_cstr(mrb, key));
  if (mrb_nil_p(v) || mrb_false_p(v)) return false;
  if (!mrb_true_p(v)) mrb_raisef(mrb, E_ARGUMENT_ERROR, "--%s takes no value", key);
  return true;
}

// A whole number, or `missing` when the flag was not given. TypedArgs
// has already decided that `--port=8080` is an Integer and `--port=x`
// is not one, so this only has to say which it wanted.
mrb_int number_of(mrb_state* mrb, mrb_value h, const char* key, mrb_int missing) {
  const mrb_value v = mrb_hash_get(mrb, h, mrb_str_new_cstr(mrb, key));
  if (mrb_nil_p(v)) return missing;
  if (!mrb_integer_p(v)) mrb_raisef(mrb, E_ARGUMENT_ERROR, "--%s takes a whole number", key);
  return mrb_integer(v);
}

// The CLI states what this invocation decides, and TypedArgs states what
// the CLI is: `--key=value`, parsed by the gem in Ruby, refused by the
// gem with a caret under the byte it choked on. False is a usage refusal,
// already spelled to the operator who typed it.
bool parse_argv(mrb_state* mrb, Invocation& in) {
  const int argc = in.argc;
  char** argv = in.argv;

  // TypedArgs reads flags and walks past everything else, which would
  // turn the old `--app foo.mrb` into `app=true` with the path dropped
  // on the floor. A bare word is a refusal here, so that spelling ends
  // loudly rather than serving the wrong thing.
  mrb_value av = mrb_ary_new_capa(mrb, argc > 1 ? argc - 1 : 0);
  for (int i = 1; i < argc; i++) {
    if (argv[i][0] != '-') {
      std::fprintf(stderr, "webmachine: '%s'? every option is --key=value\n", argv[i]);
      return false;
    }
    mrb_ary_push(mrb, av, mrb_str_new_static_frozen(mrb, argv[i], std::strlen(argv[i])));
  }
  mrb_obj_freeze(mrb, av);
  mrb_define_const_id(mrb, mrb->object_class, MRB_SYM(ARGV), av);

  const mrb_value h = mrb_funcall_id(mrb, mrb_obj_value(mrb_module_get(mrb, "TypedArgs")),
                                     MRB_SYM(opts), 0);
  // The paths below are borrowed out of this hash and read as late as the
  // last accept, so it is kept alive for the life of the process rather
  // than for the life of this call.
  mrb_gc_register(mrb, h);

  // Every flag given is one this program knows. The hash is walked in
  // place; the first unknown name ends the walk and the start.
  struct UnknownFlag {
    const char* name;
  } unknown = {nullptr};
  mrb_hash_foreach(
      mrb, mrb_hash_ptr(h),
      [](mrb_state* m, mrb_value k, mrb_value, void* ud) -> int {
        const char* name = mrb_string_cstr(m, k);
        for (const char* f : kFlags) {
          if (std::strcmp(name, f) == 0) return 0;
        }
        static_cast<UnknownFlag*>(ud)->name = name;
        return 1;
      },
      &unknown);
  if (unknown.name != nullptr) {
    std::fprintf(stderr, "webmachine: --%s?\n", unknown.name);
    usage(argv[0]);
    return false;
  }

  webmachine::ServerOptions& opts = in.opts;
  in.cli_unix = text_of(mrb, h, "unix");
  in.cli_port = static_cast<int>(number_of(mrb, h, "port", 0));
  opts.app_path = text_of(mrb, h, "app");
  opts.standalone = flag_of(mrb, h, "standalone");
  in.write_config = text_of(mrb, h, "write-config");
  if (in.write_config == nullptr && flag_of(mrb, h, "write-config")) {
    in.write_config = "webmachine.toml";
  }
  opts.standalone_assets_path = text_of(mrb, h, "assets");
  opts.error_assets_path = text_of(mrb, h, "error-assets");
  opts.standalone_docroot_path = text_of(mrb, h, "docroot");
  opts.mime_types_path = text_of(mrb, h, "mime-types");
  in.log_path = text_of(mrb, h, "log");
  in.log_privacy = text_of(mrb, h, "log-privacy");
  in.error_log_path = text_of(mrb, h, "error-log");
  in.pidfile = text_of(mrb, h, "pidfile");
  in.config_path = text_of(mrb, h, "config");

  in.log_max_bytes = number_of(mrb, h, "log-max-bytes", -1);
  if (in.log_max_bytes < -1) {
    std::fprintf(stderr, "webmachine: --log-max-bytes is a byte count, 0 for no ceiling\n");
    return false;
  }
  opts.file_map_threshold = number_of(mrb, h, "file-map-threshold", -1);
  if (opts.file_map_threshold < -1 ||
      opts.file_map_threshold > static_cast<long long>(webmachine::kFileMapMax)) {
    std::fprintf(stderr, "webmachine: --file-map-threshold is a byte count, 0 to never "
                         "map a served file\n");
    return false;
  }
  opts.zero_copy_threshold = number_of(mrb, h, "zero-copy-threshold", -1);
  if (opts.zero_copy_threshold < -1 ||
      opts.zero_copy_threshold > static_cast<long long>(webmachine::kZeroCopyMax)) {
    std::fprintf(stderr, "webmachine: --zero-copy-threshold is a byte count, 0 to copy "
                         "every body\n");
    return false;
  }

  if (in.cli_unix != nullptr && in.cli_port != 0) {
    std::fprintf(stderr, "at most one of --unix or --port\n");
    return false;
  }
  return true;
}

// From the config file to the last accept. Every step here refuses by
// raising, and main's catch is the frame it lands in.
int serve(mrb_state* mrb, Invocation& in) {
  webmachine::ServerOptions& opts = in.opts;
  webmachine::Config& fc = in.fc;
  const char*& pidfile = in.pidfile;
  const char*& config_path = in.config_path;
  const char*& cli_unix = in.cli_unix;
  const char*& log_path = in.log_path;
  const char*& log_privacy = in.log_privacy;
  const char*& error_log_path = in.error_log_path;
  long long& log_max_bytes = in.log_max_bytes;
  int& cli_port = in.cli_port;
  // Without --config: the file in the start directory, then the two
  // places the Filesystem Hierarchy Standard gives a package's own
  // configuration, locally installed first.
  if (config_path == nullptr) {
    static constexpr const char* const kConfigPlaces[] = {
        "webmachine.toml",
        "/usr/local/etc/webmachine/webmachine.toml",
        "/etc/webmachine/webmachine.toml",
    };
    for (const char* p : kConfigPlaces) {
      if (::access(p, R_OK) == 0) {
        config_path = p;
        break;
      }
    }
  }
  if (config_path != nullptr) {
    webmachine::config_load(mrb, config_path, fc);
    std::fprintf(stderr, "webmachine: config %s\n", config_path);
    if (cli_unix == nullptr && cli_port == 0) {
      if (!fc.unix_path.empty()) cli_unix = fc.unix_path.c_str();
      else if (fc.port != 0) cli_port = fc.port;
    }
    if (opts.app_path == nullptr && !fc.app.empty()) opts.app_path = fc.app.c_str();
    if (opts.standalone_assets_path == nullptr && !fc.assets.empty()) {
      opts.standalone_assets_path = fc.assets.c_str();
    }
    if (opts.standalone_docroot_path == nullptr && !fc.docroot.empty()) {
      opts.standalone_docroot_path = fc.docroot.c_str();
    }
    if (opts.mime_types_path == nullptr && !fc.mime_types.empty()) {
      opts.mime_types_path = fc.mime_types.c_str();
    }
    if (opts.error_assets_path == nullptr && !fc.error_assets.empty()) {
      opts.error_assets_path = fc.error_assets.c_str();
    }
    if (log_path == nullptr && !fc.log_file.empty()) log_path = fc.log_file.c_str();
    if (log_privacy == nullptr && !fc.log_privacy.empty()) log_privacy = fc.log_privacy.c_str();
    if (error_log_path == nullptr && !fc.error_log_file.empty()) {
      error_log_path = fc.error_log_file.c_str();
    }
    if (log_max_bytes < 0 && fc.log_max_bytes != 0) {
      log_max_bytes = static_cast<long long>(fc.log_max_bytes);
    }
    if (pidfile == nullptr && !fc.pidfile.empty()) pidfile = fc.pidfile.c_str();
    if (opts.zero_copy_threshold < 0 && fc.zero_copy_threshold >= 0) {
      opts.zero_copy_threshold = fc.zero_copy_threshold;
    }
    if (opts.file_map_threshold < 0 && fc.file_map_threshold >= 0) {
      opts.file_map_threshold = fc.file_map_threshold;
    }
    opts.sq_entries = fc.sq_entries;
    opts.backlog = fc.backlog;
    opts.header_timeout = fc.header_timeout;
    opts.send_timeout = fc.send_timeout;
    opts.idle_timeout = fc.idle_timeout;
  }

  opts.standalone_unix_path = cli_unix;
  opts.standalone_port = cli_port;

  if (pidfile != nullptr) {
    FILE* pf = std::fopen(pidfile, "we");
    if (pf == nullptr) {
      std::fprintf(stderr, "webmachine: cannot write pidfile %s\n", pidfile);
      return 1;
    }
    std::fprintf(pf, "%d\n", getpid());
    std::fclose(pf);
  }

  // main() blocked these before it made a thread. The fd is the only
  // reader; there is no handler anywhere in this process.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  opts.stop_fd = signalfd(-1, &mask, SFD_CLOEXEC);

  opts.log_path = log_path;
  opts.log_privacy = log_privacy;
  opts.error_log_path = error_log_path;
  if (log_max_bytes >= 0) opts.log_max_bytes = static_cast<unsigned long long>(log_max_bytes);

  if (in.write_config != nullptr) {
    if (!webmachine::config_write_default(in.write_config, opts.error_assets_path)) {
      std::fprintf(stderr, "webmachine: %s is already there - it is never written over\n",
                   in.write_config);
      return 1;
    }
    std::fprintf(stderr, "webmachine: wrote %s - it changes nothing until you change a line\n",
                 in.write_config);
    return 0;
  }

  // An application names its own listener, pack and docroot in its conf,
  // and one process serves any number of applications. On the command
  // line or in the config, those are a standalone server's.
  if (opts.app_path != nullptr) {
    const char* taken = nullptr;
    if (cli_unix != nullptr) taken = "--unix";
    else if (cli_port != 0) taken = "--port";
    else if (opts.standalone_assets_path != nullptr) taken = "--assets";
    else if (opts.standalone_docroot_path != nullptr) taken = "--docroot";
    if (taken != nullptr) {
      std::fprintf(stderr,
                   "webmachine: %s (and its line in the config's [server]) is a standalone "
                   "server's. An application names its own listener, pack and docroot in "
                   "its conf (conf.port, conf.unix_path, conf.url, conf.assets, "
                   "conf.docroot), and one process serves any number of applications\n",
                   taken);
      return 1;
    }
  }
  webmachine::server_options(opts);

  if (opts.standalone && opts.app_path != nullptr) {
    std::fprintf(stderr, "webmachine: --standalone enters no VM, so it cannot run --app. "
                         "Name one or the other\n");
    return 1;
  }
  if (opts.app_path != nullptr) {
    webmachine::app_load(mrb, opts.app_path);
  } else if (opts.standalone) {
    // Standalone: a pack, a docroot, or both, and no app. There is no
    // resource to enter, so the folded graph answers on its own - the
    // pack from its mapping, the docroot from disk, everything else 404.
    if (opts.standalone_assets_path == nullptr &&
        opts.standalone_docroot_path == nullptr) {
      std::fprintf(stderr, "webmachine: --standalone serves files, so it needs some: "
                           "--assets=FILE.zip, --docroot=DIR, or both\n");
      return 1;
    }
    webmachine::app_assets_only();
  } else {
    // A pack or a directory beside no app is not a server by itself any
    // more: --standalone is how an operator says that is what they meant.
    std::fprintf(stderr,
                 "webmachine: nothing to serve - name an application with --app=FILE.mrb "
                 "(or app = in the config)%s\n",
                 (opts.standalone_assets_path != nullptr ||
                  opts.standalone_docroot_path != nullptr)
                     ? ", or add --standalone to serve the files you named without one"
                     : ", or serve files with --standalone and --assets/--docroot");
    return 1;
  }

  if (webmachine::server_entered()) return 0;
  return webmachine::server_run(mrb);
}

// main owns the VM and the pidfile. Every step after mrb_open raises to
// refuse, and a raise is a C++ throw: mrb->jmp names the frame it lands
// in, and the catch below is that frame. What was refused goes to stderr,
// because a process that does not come up has no log yet.
int main(int argc, char** argv) {
  Invocation in;
  sigset_t stop_signals;
  mrb_state* mrb = nullptr;
  mrb_jmpbuf frame;
  int rc = 0;

  in.argc = argc;
  in.argv = argv;

  // A signalfd reads TERM and INT. Nothing else does, and this process
  // installs no signal handler. The block comes before the first thread:
  // a thread inherits the mask of the thread that makes it, mrb_open
  // makes one (the task HAL's ticker), and the kernel gives a signal to
  // any thread that does not block it. pthread_sigmask, not sigprocmask:
  // sigprocmask is unspecified once a process has threads.
  sigemptyset(&stop_signals);
  sigaddset(&stop_signals, SIGTERM);
  sigaddset(&stop_signals, SIGINT);
  pthread_sigmask(SIG_BLOCK, &stop_signals, nullptr);

  mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "webmachine: mrb_open failed\n");
    return 1;
  }
  mrb->jmp = &frame;
  try {
    // A gem init that raised leaves its exception in mrb->exc and the VM
    // standing. Such a VM serves nothing.
    if (mrb->exc != nullptr) mrb_exc_raise(mrb, mrb_obj_value(mrb->exc));
    if (!parse_argv(mrb, in)) {
      rc = 1;
    } else {
      rc = serve(mrb, in);
    }
  } catch (mrb_jmpbuf*) {
    mrb_print_error(mrb);
    mrb->exc = nullptr;
    rc = 1;
  } catch (const std::exception& e) {
    std::fprintf(stderr, "webmachine: %s\n", e.what());
    rc = 1;
  } catch (...) {
    std::fprintf(stderr, "webmachine: an unknown exception ended the start\n");
    rc = 1;
  }
  mrb->jmp = nullptr;
  mrb_close(mrb);
  if (in.pidfile != nullptr) ::unlink(in.pidfile);
  return rc;
}
