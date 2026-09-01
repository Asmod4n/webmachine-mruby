// Design decisions live in .DESIGN.md, filed under what each comment names.
#include "webmachine.hpp"

#include <cstring>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <mruby/chrono.hpp>
#include <mruby/class.h>
#include <mruby/presym.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

namespace webmachine {
namespace {
ServerOptions opts_;
std::vector<AppSpec*> specs_;
std::vector<std::vector<const Resource*>> resources_;
std::vector<std::vector<const WsResource*>> ws_resources_;
std::vector<std::vector<const SseResource*>> sse_resources_;
int log_fd_ = -1;
int err_fd_ = -1;
Assets assets_;
// #210: not the operator's. The pictures an error page names, found
// wherever the system keeps shipped data, and answered under their own
// reserved prefix whether or not --assets was given.
Assets error_assets_;
bool error_assets_up_ = false;
MimeDb mime_;
std::unique_ptr<Http1> http_;
std::unique_ptr<Ring<Http1>> ring_;
bool built_ = false;
bool entered_ = false;

// One webmachine-logd over a socketpair, before the ring exists. Two
// streams take this road, and they do NOT share a ceiling - see the
// two call sites for why an access log is a window and an error log
// is not.
// One log process: which log it is (the word a refusal names), the file it
// writes, the privacy the operator chose - none for an error log - and the
// size at which it rolls.
struct LogdSpawn {
  const char* mode;
  const char* path;
  const char* privacy;
  unsigned long long max_bytes;
};

int spawn_logd(const LogdSpawn& log, Refusal why) {
  char* const err = why.buf;
  const size_t errlen = why.len;
  const char* const mode = log.mode;
  const char* const path = log.path;
  const char* const privacy = log.privacy;
  const unsigned long long max_bytes = log.max_bytes;
  int sp[2];
  if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) {
    std::snprintf(err, errlen, "--%s log socketpair: %s", mode, std::strerror(errno));
    return -1;
  }
  char self[4096];
  const ssize_t sl = ::readlink("/proc/self/exe", self, sizeof(self) - 1);
  std::string logd = "webmachine-logd";
  if (sl > 0) {
    self[sl] = '\0';
    if (char* slash = std::strrchr(self, '/')) {
      *slash = '\0';
      logd = std::string(self) + "/webmachine-logd";
    }
  }
  char cap[24];
  std::snprintf(cap, sizeof cap, "%llu", max_bytes);
  const pid_t pid = ::fork();
  if (pid < 0) {
    std::snprintf(err, errlen, "--%s log fork: %s", mode, std::strerror(errno));
    ::close(sp[0]);
    ::close(sp[1]);
    return -1;
  }
  if (pid == 0) {
    ::dup2(sp[0], 0);
    ::close(sp[0]);
    ::close(sp[1]);
    ::execl(logd.c_str(), "webmachine-logd", mode, path, cap, privacy, (char*)nullptr);
    std::fprintf(stderr, "webmachine: exec %s: %s\n", logd.c_str(), std::strerror(errno));
    ::_exit(127);
  }
  ::close(sp[0]);
  ::signal(SIGCHLD, SIG_IGN);
  return sp[1];
}

// The listener table, straight out of the registry: registration order
// IS listener order.
// The PEM bytes a TLS listener answers with. Read at boot and kept
// here because ListenerSpec only points at them and the ring outlives
// the call that filled it in. Two per listener, indexed by listener.
std::vector<std::string> pem_;

// A whole file, or false with the reason spelled. Small by nature: a
// certificate chain and a key, not a body.
// One PEM file: its path, and the conf key that named it - which is what a
// refusal has to say back to the operator.
struct PemFile {
  const std::string& path;
  const char* what;
};

bool read_pem(PemFile f, std::string& out, Refusal why) {
  char* const err = why.buf;
  const size_t errlen = why.len;
  const std::string& path = f.path;
  const char* const what = f.what;
  std::FILE* fp = std::fopen(path.c_str(), "rb");
  if (fp == nullptr) {
    std::snprintf(err, errlen, "conf.%s %s: %s", what, path.c_str(), std::strerror(errno));
    return false;
  }
  out.clear();
  char buf[4096];
  size_t n;
  while ((n = std::fread(buf, 1, sizeof buf, fp)) != 0) out.append(buf, n);
  const bool bad = std::ferror(fp) != 0;
  std::fclose(fp);
  if (bad) {
    std::snprintf(err, errlen, "conf.%s %s: read failed", what, path.c_str());
    return false;
  }
  if (out.empty()) {
    std::snprintf(err, errlen, "conf.%s %s is empty", what, path.c_str());
    return false;
  }
  return true;
}

// https, a certificate and a key are one decision spelled three ways, so
// naming any of them means naming all of them.
bool build_listener_tls(RingConfig& cfg, Refusal why) {
  char* const err = why.buf;
  const size_t errlen = why.len;
  pem_.assign(specs_.size() * 2, std::string());
  for (size_t i = 0; i < specs_.size(); i++) {
    const AppSpec& spec = *specs_[i];
    const bool named_files = !spec.cert_path.empty() || !spec.key_path.empty();
    if (!spec.tls && !named_files) continue;
    if (!spec.tls) {
      std::snprintf(err, errlen,
                    "application %zu names a certificate but its listener is not https - "
                    "conf.url = \"https://...\" is what turns TLS on",
                    i);
      return false;
    }
    if (spec.cert_path.empty() || spec.key_path.empty()) {
      std::snprintf(err, errlen,
                    "application %zu serves https and needs both conf.certificate and "
                    "conf.private_key; it named %s",
                    i, spec.cert_path.empty() ? "only the key" : "only the certificate");
      return false;
    }
    if (cfg.listeners[i].unix_path != nullptr) {
      std::snprintf(err, errlen,
                    "application %zu serves https on a unix socket. TLS there is a real "
                    "thing, but the kernel's record layer is a TCP ULP - setsockopt("
                    "IPPROTO_TCP, TCP_ULP) on AF_UNIX is ENOTSUP - and this server has no "
                    "record layer of its own to fall back to",
                    i);
      return false;
    }
    std::string& cert = pem_[i * 2];
    std::string& key = pem_[i * 2 + 1];
    if (!read_pem({spec.cert_path, "certificate"}, cert, why)) return false;
    if (!read_pem({spec.key_path, "private_key"}, key, why)) return false;
    cfg.listeners[i].cert_pem = cert.data();
    cfg.listeners[i].cert_len = cert.size();
    cfg.listeners[i].key_pem = key.data();
    cfg.listeners[i].key_len = key.size();
  }
  return true;
}

bool build_listeners(RingConfig& cfg, Refusal why) {
  char* const err = why.buf;
  const size_t errlen = why.len;
  cfg.nlisteners = static_cast<uint32_t>(specs_.size());
  cfg.stop_fd = opts_.stop_fd;
  const bool cli = opts_.cli_unix != nullptr || opts_.cli_port != 0;
  if (cli && specs_.size() > 1) {
    std::snprintf(err, errlen,
                  "--unix/--port names one listener and this file registered %zu "
                  "applications - drop the override and let each app's conf speak",
                  specs_.size());
    return false;
  }
  if (opts_.cli_unix != nullptr) {
    cfg.listeners[0].unix_path = opts_.cli_unix;
    return true;
  }
  if (opts_.cli_port != 0) {
    cfg.listeners[0].port = opts_.cli_port;
    return true;
  }
  for (size_t i = 0; i < specs_.size(); i++) {
    switch (specs_[i]->form) {
      case AppSpec::Form::kUnix:
        cfg.listeners[i].unix_path = specs_[i]->unix_path.c_str();
        break;
      case AppSpec::Form::kPort:
      case AppSpec::Form::kUrl: cfg.listeners[i].port = specs_[i]->port; break;
      case AppSpec::Form::kNone:
        std::snprintf(err, errlen,
                      "application %zu has no listener - its configure block names one "
                      "(conf.port / conf.unix_path / conf.url), or pass --port/--unix for "
                      "a file with a single app",
                      i);
        return false;
    }
  }
  return true;
}
}

#include "slipstream_syscall.h"

// Which side answers this process's rings, said at startup: liburing
// works either way now - the slipstream seam underneath it hands every
// call to the engine when the kernel refuses io_uring - and the banner
// is the receipt. Silence is the kernel side.
bool server_backend_ok() {
  if (slipstream_syscall_uses_engine()) {
    char why[192] = "the kernel is too old, or a seccomp profile or an LSM blocks it";
    char buf[32] = "";
    const int fd = ::open("/proc/sys/kernel/io_uring_disabled", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
      const ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
      ::close(fd);
      if (n > 0) {
        buf[n] = '\0';
        if (buf[0] == '2') {
          std::snprintf(why, sizeof(why),
                        "sysctl kernel.io_uring_disabled=2 - io_uring is off for every "
                        "process on this machine");
        } else if (buf[0] == '1') {
          char grp[32] = "";
          const int g = ::open("/proc/sys/kernel/io_uring_group", O_RDONLY | O_CLOEXEC);
          if (g >= 0) {
            const ssize_t m = ::read(g, grp, sizeof(grp) - 1);
            ::close(g);
            if (m > 0) grp[m] = '\0';
          }
          std::snprintf(why, sizeof(why),
                        "sysctl kernel.io_uring_disabled=1 - only members of group %s "
                        "(kernel.io_uring_group) may, and this process is not one",
                        grp[0] != '\0' ? grp : "?");
        }
      }
    }
    std::fprintf(stderr,
                 "webmachine: ================================================================\n"
                 "webmachine: == IO: slipstream's engine answers this process's rings\n"
                 "webmachine: == why: %s\n"
                 "webmachine: == cost: CORRECT, NOT FAST - every socket op is readiness plus\n"
                 "webmachine: ==   a classic syscall, files ride a worker thread\n"
                 "webmachine: == fast: the same binary, on a host that allows io_uring\n"
                 "webmachine: ================================================================\n",
                 why);
  }
  // NO runtime "is liburing here" question any more. With the seam it
  // is always here - mrbgem.rake aborts the BUILD when liburing cannot
  // be built, which is the moment that can still be acted on - and the
  // only open question is which side answers, which the banner above
  // has just said. The check that used to stand here asked a Ruby
  // constant that a since-removed gem defined, so it answered "no
  // liburing" for a binary that carries it.
  return true;
}

namespace {
// Everything between "main returned" and "the first accept", once.
bool build(Setup s) {
  mrb_state* const mrb = s.mrb;
  if (built_) return true;
  if (!server_backend_ok()) return false;

  if (!app_registered_all({specs_, kMaxListeners}, s.why)) return false;
  RingConfig cfg;
  cfg.sq_entries = opts_.sq_entries;
  // The gem is embedded: a reactor that has to give up raises into this
  // VM instead of ending someone else's process.
  cfg.mrb = mrb;
  cfg.backlog = opts_.backlog;
  cfg.header_timeout = opts_.header_timeout;
  cfg.send_timeout = opts_.send_timeout;
  cfg.idle_timeout = opts_.idle_timeout;
  if (!build_listeners(cfg, s.why)) return false;
  if (!build_listener_tls(cfg, s.why)) return false;

  // server.docroot: a typed flag beats [server], and both beat the app's
  // conf - the same order --unix and --port already follow. The canonical
  // path is settled ONCE, here, before the first accept: no request may race
  // the anchor RESOLVE_BENEATH is measured against. A configured docroot
  // that is missing or is not a directory refuses startup by name, because
  // an operator who asked for one and silently got a server without it would
  // find that out through 500s in production.
  {
    const char* dr = opts_.docroot_path;
    for (size_t i = 0; dr == nullptr && i < specs_.size(); i++) {
      if (!specs_[i]->docroot.empty()) dr = specs_[i]->docroot.c_str();
    }
    if (dr != nullptr) {
      if (!docroot_open(dr, s.why)) return false;
      std::fprintf(stderr, "webmachine: docroot %s\n", docroot_path());
    }
  }

  // conf.disable_http_cats: the first app with an opinion decides, the way
  // every other conf answer is taken. Asked BEFORE the pack is looked for,
  // because "off" means it is never opened, not opened and ignored.
  int8_t no_cats = -1;
  for (size_t i = 0; no_cats < 0 && i < specs_.size(); i++) {
    no_cats = specs_[i]->disable_http_cats;
  }
  const std::string error_assets_file =
      no_cats == 1 ? std::string() : error_assets_path(opts_.error_assets_path);
  if (opts_.assets_path != nullptr || !error_assets_file.empty()) {
    if (!mime_.load(opts_.mime_types_path, s.why)) return false;
    std::fprintf(stderr, "webmachine: media types from %s (%zu extensions)\n",
                 mime_.source().c_str(), mime_.size());
  }
  if (opts_.assets_path != nullptr) {
    if (!assets_.open(opts_.assets_path, mime_, s.why)) return false;
  }
  if (!error_assets_file.empty()) {
    // A picture is no reason not to start: an unreadable one is said
    // out loud and the pages render without it.
    char eerr[512] = "";
    if (error_assets_.open(error_assets_file.c_str(), mime_, {eerr, sizeof eerr})) {
      error_assets_up_ = true;
      std::fprintf(stderr, "webmachine: error assets from %s\n", error_assets_file.c_str());
    } else {
      std::fprintf(stderr, "webmachine: error assets at %s unusable (%s) - pages without "
                           "pictures\n",
                   error_assets_file.c_str(), eerr);
    }
  } else if (no_cats == 1) {
    // Asked for, so not a complaint: the pages still render, they just
    // show no picture, and nothing is mounted at /error_assets/.
    std::fprintf(stderr, "webmachine: conf.disable_http_cats - error pages without pictures\n");
  } else {
    // Silence here is what makes a server look like it is answering
    // errors wrong: it answers them in plain text because it never found
    // a page to render, and until now it did not say so. It is not a
    // reason to refuse to start - a server with no error assets is a
    // perfectly good server - but the operator hears it once.
    std::fprintf(stderr, "webmachine: no error assets found - errors answer in plain text. "
                         "Name a file with --error-assets FILE.zip, or install one as "
                         "<prefix>/share/webmachine-mruby/error-assets.zip\n");
  }

  if (opts_.log_path != nullptr) {
    if (opts_.log_privacy != nullptr && std::strcmp(opts_.log_privacy, "none") == 0) {
      std::fprintf(stderr,
                   "webmachine: --log-privacy none writes FULL client addresses to the log.\n"
                   "webmachine: an IP address is personal data (GDPR art. 4(1)); logging it\n"
                   "webmachine: needs a legal basis (art. 6). Security logging with short\n"
                   "webmachine: retention usually rides legitimate interest plus a privacy\n"
                   "webmachine: notice; using the addresses beyond that (analytics, tracking)\n"
                   "webmachine: needs consent. DNT/Sec-GPC peers are capped to anon either way.\n");
    }
    // The access log is a WINDOW - it answers what happened in the last
    // so-many bytes. Dropping the oldest is its semantics, not a loss.
    const LogdSpawn access = {
        "access", opts_.log_path,
        opts_.log_privacy != nullptr ? opts_.log_privacy : "anon", opts_.log_max_bytes};
    log_fd_ = spawn_logd(access, s.why);
    if (log_fd_ < 0) return false;
    cfg.log_fd = log_fd_;
  }
  if (opts_.error_log_path != nullptr) {
    // NO CEILING (0 disables the cap in webmachine-logd). An error log is
    // not a window: what lands here is a 500 or a Ruby exception with its
    // backtrace, never ordinary traffic, so it does not grow on its own.
    // It grows in a fault storm - and that is the one moment where the
    // FIRST entry is the one that names the cause and everything after it
    // is consequence. A ceiling that keeps the newest half would throw
    // away exactly the line worth having.
    err_fd_ = spawn_logd({"error", opts_.error_log_path, nullptr, 0}, s.why);
    if (err_fd_ < 0) return false;
    cfg.err_fd = err_fd_;
  }

  resources_.resize(specs_.size());
  ws_resources_.resize(specs_.size());
  sse_resources_.resize(specs_.size());
  std::vector<Http1::AppInput> inputs(specs_.size());
  for (size_t i = 0; i < specs_.size(); i++) {
    resources_[i].reserve(specs_[i]->resources.size());
    for (const auto& r : specs_[i]->resources) resources_[i].push_back(r.get());
    ws_resources_[i].reserve(specs_[i]->ws_resources.size());
    for (const auto& r : specs_[i]->ws_resources) ws_resources_[i].push_back(r.get());
    sse_resources_[i].reserve(specs_[i]->sse_resources.size());
    for (const auto& r : specs_[i]->sse_resources) sse_resources_[i].push_back(r.get());
    inputs[i] = Http1::AppInput{&specs_[i]->table,
                                resources_[i].data(),
                                resources_[i].size(),
                                &specs_[i]->ws_table,
                                ws_resources_[i].data(),
                                ws_resources_[i].size(),
                                &specs_[i]->sse_table,
                                sse_resources_[i].data(),
                                sse_resources_[i].size()};
  }
  http_.reset(new Http1(inputs.data(), inputs.size(),
                        opts_.assets_path != nullptr ? &assets_ : nullptr));
  // #210: the error pages render in the app's VM. A template the pack
  // carries and that does not parse is a startup refusal with a name -
  // the operator hears it here, not on the first 404.
  if (!http_->open_error_assets(s, error_assets_up_ ? &error_assets_ : nullptr)) {
    return false;
  }
  // #210: and the same assets under response.error_asset("404.jpg"),
  // so an app can answer with one of these pictures wherever it likes,
  // not only where the error resource does.
  response_bind_error_assets(error_assets_up_ ? &error_assets_ : nullptr);
  if (opts_.log_path != nullptr) http_->enable_access_log();
  if (opts_.error_log_path != nullptr) http_->enable_error_log();
  // A typed flag and [tune] beat the app's conf, and all three beat the
  // built-in default - the same order --unix and --port already follow.
  long long zct = opts_.zero_copy_threshold;
  for (size_t i = 0; zct < 0 && i < specs_.size(); i++) {
    zct = specs_[i]->zero_copy_threshold;
  }
  if (zct >= 0) http_->set_zero_copy_threshold(static_cast<size_t>(zct));
  long long fmt = opts_.file_map_threshold;
  for (size_t i = 0; fmt < 0 && i < specs_.size(); i++) {
    fmt = specs_[i]->file_map_threshold;
  }
  if (fmt >= 0) http_->set_file_map_threshold(static_cast<size_t>(fmt));

  ring_.reset(new Ring<Http1>(*http_));
  if (!ring_->init(cfg, s.why)) {
    ring_.reset();
    return false;
  }

  for (size_t i = 0; i < specs_.size(); i++) {
    app_mark_bound(*specs_[i], cfg.listeners[i].unix_path,
                   ring_->bound_port(static_cast<uint32_t>(i)));
    if (!app_ready_run(s, *specs_[i])) {
      ring_.reset();
      return false;
    }
  }

  std::fprintf(stderr, "webmachine: http/1.1 up, pid %d, %u listener(s)\n", getpid(),
               cfg.nlisteners);
  for (uint32_t i = 0; i < cfg.nlisteners; i++) {
    if (cfg.listeners[i].unix_path != nullptr) {
      std::fprintf(stderr, "webmachine:   [%u] unix %s\n", i, cfg.listeners[i].unix_path);
    } else {
      std::fprintf(stderr, "webmachine:   [%u] tcp port %d%s\n", i, ring_->bound_port(i),
                   cfg.listeners[i].cert_pem != nullptr ? ", tls" : "");
    }
  }
  built_ = true;
  return true;
}

// The Ruby doors all need the server standing; a failure to build raises.
void ensure(mrb_state* mrb) {
  char err[512] = "";
  if (!build({mrb, {err, sizeof(err)}})) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "webmachine: %s", err);
  }
  entered_ = true;
}

// Webmachine.run: block, serve, return when the stop signal lands.
mrb_value wm_run(mrb_state* mrb, mrb_value self) {
  ensure(mrb);
  ring_->run();
  return self;
}

// Webmachine.tick(budget): ONE bounded step - the budget bounds the WORK.
mrb_value wm_tick(mrb_state* mrb, mrb_value) {
  mrb_value budget = mrb_nil_value();
  mrb_get_args(mrb, "|o", &budget);
  ensure(mrb);
  if (mrb_nil_p(budget)) return mrb_bool_value(ring_->tick(nullptr));
  const auto ns = mrb_chrono::as<std::chrono::nanoseconds>(mrb, budget);
  if (ns.count() < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "Webmachine.tick wants a duration, not a negative one");
  }
  struct __kernel_timespec ts {ns.count() / 1000000000, ns.count() % 1000000000};
  return mrb_bool_value(ring_->tick(&ts));
}

// Webmachine.fd: what an embedder polls between ticks.
mrb_value wm_fd(mrb_state* mrb, mrb_value) {
  ensure(mrb);
  const int fd = ring_->fd();
  if (fd < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR,
              "this io backend has no pollable descriptor - drive it with "
              "Webmachine.tick(budget) instead of waiting on an fd");
  }
  return mrb_fixnum_value(fd);
}

// Webmachine.stop(grace): drain, then forget. Process-wide, and named so.
mrb_value wm_stop(mrb_state* mrb, mrb_value self) {
  mrb_value grace = mrb_nil_value();
  mrb_get_args(mrb, "|o", &grace);
  if (!built_) return self;
  int64_t ns = 0;
  if (!mrb_nil_p(grace)) {
    ns = mrb_chrono::as<std::chrono::nanoseconds>(mrb, grace).count();
    if (ns < 0) {
      mrb_raise(mrb, E_RUNTIME_ERROR, "Webmachine.stop wants a grace, not a negative one");
    }
  }
  ring_->drain(ns);
  return self;
}

// Did the stop signal's completion land?
mrb_value wm_stopped(mrb_state* mrb, mrb_value) {
  ensure(mrb);
  return mrb_bool_value(ring_->stopped());
}
}

// What the INVOCATION decides; not reachable from Ruby, deliberately.
void server_options(const ServerOptions& opts) { opts_ = opts; }

// Did `main` serve already through run or tick?
bool server_entered() { return entered_; }

// Webmachine.run / .tick / .fd / .stop, next to the Application.
void server_init(mrb_state* mrb, struct RClass* wm) {
  mrb_define_module_function_id(mrb, wm, MRB_SYM(run), wm_run, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, wm, MRB_SYM(tick), wm_tick, MRB_ARGS_OPT(1));
  mrb_define_module_function_id(mrb, wm, MRB_SYM(fd), wm_fd, MRB_ARGS_NONE());
  mrb_define_module_function_id(mrb, wm, MRB_SYM(stop), wm_stop, MRB_ARGS_OPT(1));
  struct RClass* app = mrb_class_get_under_id(mrb, wm, MRB_SYM(Application));
  mrb_define_method_id(mrb, app, MRB_SYM(stop), wm_stop, MRB_ARGS_OPT(1));
  mrb_define_module_function_id(mrb, wm, MRB_SYM_Q(stopped), wm_stopped, MRB_ARGS_NONE());
}

// The tool's entry: build if Ruby has not, then loop until the stop signal.
int server_run(Setup s) {
  if (!build(s)) return 1;
  entered_ = true;
  ring_->run();
  ring_.reset();
  return 0;
}
}
