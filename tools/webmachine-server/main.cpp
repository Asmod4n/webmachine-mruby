// Design decisions live in .DESIGN.md, filed under what each comment names.
#include <mruby.h>
#include <mruby/array.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <pthread.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <sys/uio.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../../src/webmachine.hpp"


// What this invocation decided. The flags fill it, the config file fills
// what the flags left, and from there it is ONE thing travelling from the
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
  const char* error_log_path = nullptr;
  long long log_max_bytes = -1;
  int cli_port = 0;
};

void usage(const char* me) {
  std::fprintf(stderr,
               "usage: %s [OPTIONS]\n"
               "\n"
               "  Every option is --key=value. At least one of --app and --assets;\n"
               "  with nothing to serve, no start.\n"
               "\n"
               "LISTENER\n"
               "  --unix=PATH              answer on a unix socket; beats the app's conf\n"
               "  --port=N                 answer on a TCP port; beats the app's conf\n"
               "\n"
               "SERVE\n"
               "  --app=FILE.mrb           the application, as bytecode\n"
               "  --assets=FILE.zip        assets from one mapping; alone, 404s the rest\n"
               "  --error-assets=FILE.zip  what an error answer may hand over\n"
               "  --docroot=DIR            the only directory response.file may reach\n"
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
               "\n"
               "OTHER\n"
               "  --config=FILE.toml       these choices from a file; flags beat it\n"
               "  --pidfile=PATH           write this pid, remove it on the way out\n"
               ,
               me);
}

// Every flag this build answers to. The parser accepts any well-formed
// key, so the set a typo is measured against has to be stated: it is
// this one, and it is also what the usage text above lists.
const char* const kFlags[] = {
    "unix", "port", "app", "assets", "error-assets", "docroot", "mime-types",
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

// A whole number, or `missing` when the flag was not given. TypedArgs
// has already decided that `--port=8080` is an Integer and `--port=x`
// is not one, so this only has to say which it wanted.
mrb_int number_of(mrb_state* mrb, mrb_value h, const char* key, mrb_int missing) {
  const mrb_value v = mrb_hash_get(mrb, h, mrb_str_new_cstr(mrb, key));
  if (mrb_nil_p(v)) return missing;
  if (!mrb_integer_p(v)) mrb_raisef(mrb, E_ARGUMENT_ERROR, "--%s takes a whole number", key);
  return mrb_integer(v);
}

// The CLI states what this INVOCATION decides, and TypedArgs states what
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

  const mrb_value keys = mrb_hash_keys(mrb, h);
  for (mrb_int i = 0; i < RARRAY_LEN(keys); i++) {
    const mrb_value k = mrb_ary_entry(keys, i);
    const char* name = mrb_string_cstr(mrb, k);
    bool known = false;
    for (const char* f : kFlags) {
      if (std::strcmp(name, f) == 0) { known = true; break; }
    }
    if (!known) {
      std::fprintf(stderr, "webmachine: --%s?\n", name);
      usage(argv[0]);
      return false;
    }
  }

  webmachine::ServerOptions& opts = in.opts;
  in.cli_unix = text_of(mrb, h, "unix");
  in.cli_port = static_cast<int>(number_of(mrb, h, "port", 0));
  opts.app_path = text_of(mrb, h, "app");
  opts.assets_path = text_of(mrb, h, "assets");
  opts.error_assets_path = text_of(mrb, h, "error-assets");
  opts.docroot_path = text_of(mrb, h, "docroot");
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
// raising since #33, so it runs inside run_guarded's frame.
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
  if (config_path == nullptr && ::access("webmachine.toml", R_OK) == 0) {
    config_path = "webmachine.toml";
  }
  if (config_path != nullptr) {
    webmachine::config_load(mrb, config_path, fc);
    std::fprintf(stderr, "webmachine: config %s\n", config_path);
    if (cli_unix == nullptr && cli_port == 0) {
      if (!fc.unix_path.empty()) cli_unix = fc.unix_path.c_str();
      else if (fc.port != 0) cli_port = fc.port;
    }
    if (opts.app_path == nullptr && !fc.app.empty()) opts.app_path = fc.app.c_str();
    if (opts.assets_path == nullptr && !fc.assets.empty()) opts.assets_path = fc.assets.c_str();
    if (opts.docroot_path == nullptr && !fc.docroot.empty()) {
      opts.docroot_path = fc.docroot.c_str();
    }
    if (opts.mime_types_path == nullptr && !fc.mime_types.empty()) {
      opts.mime_types_path = fc.mime_types.c_str();
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

  opts.cli_unix = cli_unix;
  opts.cli_port = cli_port;

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

  webmachine::server_options(opts);

  if (opts.app_path != nullptr) {
    webmachine::app_load(mrb, opts.app_path);
  } else if (opts.assets_path != nullptr) {
    // A pack alone is something to serve. Everything it does not name is
    // a 404, because no resource stands behind it.
    webmachine::app_assets_only();
  } else {
    std::fprintf(stderr,
                 "webmachine: nothing to serve - name an application with --app=FILE.mrb "
                 "(or app = in the config), or a pack with --assets=FILE.zip\n");
    return 1;
  }

  if (webmachine::server_entered()) return 0;
  return webmachine::server_run(mrb);
}

// run_guarded's shape: the step it protects takes what it needs as void*.
// Reading the command line is inside the frame because the parser is the
// VM's, and a malformed flag comes back as a raise like every other
// start-up refusal (#33).
int serve_body(mrb_state* mrb, void* ud) {
  Invocation& in = *static_cast<Invocation*>(ud);
  if (!parse_argv(mrb, in)) return 2;
  return serve(mrb, in);
}

// `main` states what is served, and owns the VM and the pidfile: both
// outlive the step that raised, and both are cleaned up here.
int main(int argc, char** argv) {
  Invocation in;
  in.argc = argc;
  in.argv = argv;

  // A signalfd reads TERM and INT. Nothing else does, and this process
  // installs no signal handler.
  //
  // The block belongs HERE, before the first thread. A thread inherits
  // the mask of the thread that makes it, and mrb_open() below makes one:
  // the task HAL's ticker. The kernel gives a signal to any thread that
  // does not block it. With the block set later, the ticker was that
  // thread, it had no handler, and TERM killed the process at 143 with
  // the unix socket still on disk.
  //
  // pthread_sigmask and not sigprocmask: sigprocmask is unspecified once
  // a process has threads.
  sigset_t stop_signals;
  sigemptyset(&stop_signals);
  sigaddset(&stop_signals, SIGTERM);
  sigaddset(&stop_signals, SIGINT);
  pthread_sigmask(SIG_BLOCK, &stop_signals, nullptr);

  mrb_state* mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "webmachine: mrb_open failed\n");
    return 1;
  }
  const int rc = webmachine::run_guarded(mrb, {serve_body, &in});
  mrb_close(mrb);
  if (in.pidfile != nullptr) ::unlink(in.pidfile);
  return rc;
}
