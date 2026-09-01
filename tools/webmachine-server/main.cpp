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
    } else if (std::strcmp(argv[i], "--error-assets") == 0 && i + 1 < argc) {
      opts.error_assets_path = argv[++i];
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
                   "usage: %s [OPTIONS]\n"
                   "\n"
                   "  At least one of --app and --assets. With nothing to serve, no start.\n"
                   "\n"
                   "LISTENER\n"
                   "  --unix PATH              answer on a unix socket; beats the app's conf\n"
                   "  --port N                 answer on a TCP port; beats the app's conf\n"
                   "\n"
                   "SERVE\n"
                   "  --app FILE.mrb           the application, as bytecode\n"
                   "  --assets FILE.zip        assets from one mapping; alone, 404s the rest\n"
                   "  --error-assets FILE.zip  what an error answer may hand over\n"
                   "  --docroot DIR            the only directory response.file may reach\n"
                   "  --mime-types FILE        this media-type database, not the machine's\n"
                   "\n"
                   "LOG\n"
                   "  --log FILE               the access log\n"
                   "  --log-privacy MODE       none | anon | full                       (anon)\n"
                   "  --error-log FILE         what a callback raised; mrbc -g for line numbers\n"
                   "  --log-max-bytes N        ceiling on the access log, 0 = none    (500 MB)\n"
                   "\n"
                   "TUNE\n"
                   "  --zero-copy-threshold N  lend a body this big instead of copying (128 KiB)\n"
                   "\n"
                   "OTHER\n"
                   "  --config FILE.toml       these choices from a file; flags beat it\n"
                   "  --pidfile PATH           write this pid, remove it on the way out\n"
                   ,
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
    if (!webmachine::config_load({mrb, {cerr, sizeof(cerr)}}, config_path, fc)) {
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

  webmachine::server_options(opts);

  if (opts.app_path != nullptr) {
    char err[512];
    if (!webmachine::app_load({mrb, {err, sizeof(err)}}, opts.app_path)) {
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
    rc = webmachine::server_run({mrb, {err, sizeof(err)}});
    if (rc != 0) std::fprintf(stderr, "webmachine: %s\n", err);
  }
  mrb_close(mrb);
  if (pidfile != nullptr) ::unlink(pidfile);
  return rc;
}
