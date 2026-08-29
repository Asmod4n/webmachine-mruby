// Design decisions live in .DESIGN.md, filed under what each comment names.
#include <mruby.h>
#include <mruby/variable.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <sys/uio.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "../../src/webmachine.hpp"

namespace {
// Does io_uring exist on THIS machine? Read from URING_AVAILABLE, which
// mruby-io-uring already answered during mrb_open().
bool uring_present(mrb_state* mrb) {
  const mrb_sym k = mrb_intern_lit(mrb, "URING_AVAILABLE");
  const mrb_value obj = mrb_obj_value(mrb->object_class);
  if (!mrb_const_defined(mrb, obj, k)) return false;
  return mrb_bool(mrb_const_get(mrb, obj, k));
}
}

// The CLI states what this INVOCATION decides; `main` states what is served.
int main(int argc, char** argv) {
  const char* pidfile = nullptr;
  webmachine::ServerOptions opts;
  const char* cli_unix = nullptr;
  const char* log_path = nullptr;
  const char* log_privacy = nullptr;
  const char* error_log_path = nullptr;
  long long log_max_bytes = -1;
  const char* config_path = nullptr;
  int cli_port = 0;
  for (int i = 1; i < argc; i++) {
    if (std::strcmp(argv[i], "--unix") == 0 && i + 1 < argc) {
      cli_unix = argv[++i];
    } else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      cli_port = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--app") == 0 && i + 1 < argc) {
      opts.app_path = argv[++i];
    } else if (std::strcmp(argv[i], "--assets") == 0 && i + 1 < argc) {
      opts.assets_path = argv[++i];
    } else if (std::strcmp(argv[i], "--docroot") == 0 && i + 1 < argc) {
      opts.docroot_path = argv[++i];
    } else if (std::strcmp(argv[i], "--mime-types") == 0 && i + 1 < argc) {
      opts.mime_types_path = argv[++i];
    } else if (std::strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
      log_path = argv[++i];
    } else if (std::strcmp(argv[i], "--log-privacy") == 0 && i + 1 < argc) {
      log_privacy = argv[++i];
    } else if (std::strcmp(argv[i], "--error-log") == 0 && i + 1 < argc) {
      error_log_path = argv[++i];
    } else if (std::strcmp(argv[i], "--log-max-bytes") == 0 && i + 1 < argc) {
      log_max_bytes = std::atoll(argv[++i]);
      if (log_max_bytes < 0) {
        std::fprintf(stderr, "webmachine: --log-max-bytes is a byte count, 0 for no ceiling\n");
        return 2;
      }
    } else if (std::strcmp(argv[i], "--file-map-threshold") == 0 && i + 1 < argc) {
      opts.file_map_threshold = std::atoll(argv[++i]);
      if (opts.file_map_threshold < 0 ||
          opts.file_map_threshold > static_cast<long long>(webmachine::kFileMapMax)) {
        std::fprintf(stderr, "webmachine: --file-map-threshold is a byte count, 0 to never "
                             "map a served file\n");
        return 2;
      }
    } else if (std::strcmp(argv[i], "--zero-copy-threshold") == 0 && i + 1 < argc) {
      opts.zero_copy_threshold = std::atoll(argv[++i]);
      if (opts.zero_copy_threshold < 0 ||
          opts.zero_copy_threshold > static_cast<long long>(webmachine::kZeroCopyMax)) {
        std::fprintf(stderr, "webmachine: --zero-copy-threshold is a byte count, 0 to copy "
                             "every body\n");
        return 2;
      }
    } else if (std::strcmp(argv[i], "--pidfile") == 0 && i + 1 < argc) {
      pidfile = argv[++i];
    } else if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config_path = argv[++i];
    } else {
      std::fprintf(stderr,
                   "usage: %s [--config FILE.toml] [--unix PATH | --port N] [--app FILE.mrb] "
                   "[--assets FILE.zip] [--docroot DIR] [--mime-types FILE] "
                   "[--log FILE [--log-privacy none|anon|full]] [--error-log FILE] "
                   "[--log-max-bytes N] "
                   "[--zero-copy-threshold N] [--pidfile PATH]\n"
                   "  --config reads the same choices from a TOML file; typed flags beat it,\n"
                   "  and both beat the app's conf. Without --config, a ./webmachine.toml is\n"
                   "  used when present (and announced).\n"
                   "  --unix/--port OVERRIDE the listener the app's conf named; without an\n"
                   "  app (or without a conf listener) one of them is required.\n"
                   "  --app or --assets is REQUIRED: a server with nothing to serve refuses\n"
                   "  to start. A pack alone answers what it holds and 404s the rest.\n"
                   "  --docroot is the ONE directory `response.file = \"rel/path\"` may\n"
                   "  reach. It is resolved to a canonical absolute path and opened once\n"
                   "  at startup, and every per-request open is an openat2(2) against\n"
                   "  THAT descriptor with RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS - so\n"
                   "  the kernel does the confinement and a '..', a symlink pointing out\n"
                   "  of the tree or a /proc magic-link all get the same 404 a name that\n"
                   "  was never there gets. Without it response.file= refuses by name; a\n"
                   "  default would be a directory nobody chose to serve.\n"
                   "  --mime-types names the media-type database the asset tier reads\n"
                   "  instead of hunting for the machine's own (/etc/mime.types, the apache\n"
                   "  paths, /usr/share/mime/globs2, then the list built in). The startup\n"
                   "  always says which one answered.\n"
                   "  --error-log is the SECOND log: what an app's callback raised, with\n"
                   "  the class, the message and the backtrace. Its own file and its own\n"
                   "  writer - an error line and an access line share no field. Compile the\n"
                   "  app with `mrbc -g` for frames that name a file and a line; without it\n"
                   "  the trace is one (unknown):0 and no build can recover it.\n"
                   "  --log-max-bytes is a hard ceiling on the ACCESS log: at the cap the\n"
                   "  oldest lines are dropped and the newest kept, in place. That log is a\n"
                   "  window - it answers what happened recently - so losing the oldest is\n"
                   "  what it is for. The default is 500 MB; 0 means no ceiling and the\n"
                   "  operator watches the disk. The ERROR log has no ceiling and ignores\n"
                   "  this: it carries 500s and exceptions, never ordinary traffic, so it\n"
                   "  only grows in a fault storm - where the FIRST entry names the cause\n"
                   "  and dropping it to keep the consequences would be the wrong half.\n"
                   "  --zero-copy-threshold is the body size at which a dynamic response is\n"
                   "  LENT to the writer - the handler's own String goes to the kernel\n"
                   "  instead of being copied into the send buffer. Below it, and at 0,\n"
                   "  every body is copied. The default is 128 KiB; bench/vm/zero_copy_advise.sh\n"
                   "  measures the crossover on the machine that will run this.\n"
                   "  --pidfile writes this process's pid and removes the file on the way out.\n",
                   argv[0]);
      return 2;
    }
  }
  if (cli_unix != nullptr && cli_port != 0) {
    std::fprintf(stderr, "at most one of --unix or --port\n");
    return 2;
  }

  mrb_state* mrb = mrb_open();
  if (mrb == nullptr) {
    std::fprintf(stderr, "webmachine: mrb_open failed\n");
    return 1;
  }

  webmachine::Config fc;
  if (config_path == nullptr && ::access("webmachine.toml", R_OK) == 0) {
    config_path = "webmachine.toml";
  }
  if (config_path != nullptr) {
    char cerr[512];
    if (!webmachine::config_load(mrb, config_path, fc, cerr, sizeof(cerr))) {
      std::fprintf(stderr, "webmachine: %s\n", cerr);
      mrb_close(mrb);
      return 2;
    }
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
      mrb_close(mrb);
      return 1;
    }
    std::fprintf(pf, "%d\n", getpid());
    std::fclose(pf);
  }

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigprocmask(SIG_BLOCK, &mask, nullptr);
  opts.stop_fd = signalfd(-1, &mask, SFD_CLOEXEC);

  opts.log_path = log_path;
  opts.log_privacy = log_privacy;
  opts.error_log_path = error_log_path;
  if (log_max_bytes >= 0) opts.log_max_bytes = static_cast<unsigned long long>(log_max_bytes);
  opts.have_uring = uring_present(mrb);

  webmachine::server_options(opts);

  if (opts.app_path != nullptr) {
    char err[512];
    if (!webmachine::app_load(mrb, opts.app_path, err, sizeof(err))) {
      std::fprintf(stderr, "webmachine: %s: %s\n", opts.app_path, err);
      mrb_close(mrb);
      return 1;
    }
  } else if (opts.assets_path != nullptr) {
    // A pack alone is something to serve. Everything it does not name is
    // a 404, because no resource stands behind it.
    webmachine::app_assets_only();
  } else {
    std::fprintf(stderr,
                 "webmachine: nothing to serve - name an application with --app FILE.mrb "
                 "(or app = in the config), or a pack with --assets FILE.zip\n");
    mrb_close(mrb);
    return 1;
  }

  int rc = 0;
  if (!webmachine::server_entered()) {
    char err[512] = "";
    rc = webmachine::server_run(mrb, err, sizeof(err));
    if (rc != 0) std::fprintf(stderr, "webmachine: %s\n", err);
  }
  mrb_close(mrb);
  if (pidfile != nullptr) ::unlink(pidfile);
  return rc;
}
