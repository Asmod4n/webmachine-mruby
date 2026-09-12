#include "ruby_value.hpp"

#include "ring.hpp"

#include <cstring>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <mruby/chrono.hpp>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/string.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

namespace webmachine
{
namespace
{
ServerOptions opts_;
std::vector<AppSpec *> specs_;
std::vector<std::vector<const Resource *>> resources_;
std::vector<std::vector<const WsResource *>> ws_resources_;
std::vector<std::vector<const SseResource *>> sse_resources_;
int log_fd_ = -1;
int err_fd_ = -1;
Assets assets_;
// #210: not the operator's. The pictures an error page names, found
// wherever the system keeps shipped data, and answered under their own
// reserved prefix whether or not --assets was given.
Assets error_assets_;
bool error_assets_up_ = false;
// An unusable error pack is found before there is a log to say it in -
// the error log's fd is spawned further down and its Logger only turns on
// once Http1 exists. So the sentence waits here for its destination.
std::string error_assets_note_;

// Assets::open, and what it opens: the pack, its path, and the media
// types every entry's Content-Type comes from.
struct OpenPack {
    Assets *pack;
    const char *path;
    const MimeDb *mime;
};

mrb_value pack_open_in_protected_call(mrb_state *mrb, void *user_data)
{
    OpenPack *pack = static_cast<OpenPack *>(user_data);
    pack->pack->open(mrb, pack->path, *pack->mime);
    return mrb_nil_value();
}
MimeDb mime_;
std::unique_ptr<Http1> http_;
std::unique_ptr<Ring<Http1>> ring_;
bool built_ = false;
bool entered_ = false;

// One webmachine-logd over a socketpair, before the ring exists: which
// log it is, the file it writes, the privacy the operator chose (none
// for an error log), and the size at which it rolls. The two call
// sites say why an access log has a ceiling and an error log has none.
struct LogdSpawn {
    const char *mode;
    const char *path;
    const char *privacy;
    unsigned long long max_bytes;
};

int spawn_logd(mrb_state *mrb, const LogdSpawn &logd_spawn)
{
    const char *const mode = logd_spawn.mode;
    const char *const path = logd_spawn.path;
    const char *const privacy = logd_spawn.privacy;
    const unsigned long long max_bytes = logd_spawn.max_bytes;
    int socket_pair[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, socket_pair) != 0) {
        mrb_raisef(mrb, E_WM_ERROR(mrb), "%s log: socketpair: %s", mode, std::strerror(errno));
    }
    char self[4096];
    const ssize_t link_length = ::readlink("/proc/self/exe", self, sizeof(self) - 1);
    std::string logd = "webmachine-logd";
    if (link_length > 0) {
        self[link_length] = '\0';
        if (char *slash = std::strrchr(self, '/')) {
            *slash = '\0';
            logd = std::string(self) + "/webmachine-logd";
        }
    }
    char max_bytes_text[24];
    std::snprintf(max_bytes_text, sizeof max_bytes_text, "%llu", max_bytes);
    const pid_t child = ::fork();
    if (child < 0) {
        const int saved_errno = errno;
        ::close(socket_pair[0]);
        ::close(socket_pair[1]);
        mrb_raisef(mrb, E_WM_ERROR(mrb), "%s log: fork: %s", mode, std::strerror(saved_errno));
    }
    if (child == 0) {
        ::dup2(socket_pair[0], 0);
        ::close(socket_pair[0]);
        ::close(socket_pair[1]);
        ::execl(logd.c_str(), "webmachine-logd", mode, path, max_bytes_text, privacy,
                (char *)nullptr);
        std::fprintf(stderr, "webmachine: exec %s: %s\n", logd.c_str(), std::strerror(errno));
        ::_exit(127);
    }
    ::close(socket_pair[0]);
    ::signal(SIGCHLD, SIG_IGN);
    return socket_pair[1];
}

// The PEM bytes a TLS listener answers with. Read at boot and kept
// here because ListenerSpec only points at them and the ring outlives
// the call that filled it in. Two per listener, indexed by listener.
std::vector<std::string> pem_;

// One PEM file: its path, and the conf key that named it, which is what
// a refusal says back to the operator.
struct PemFile {
    const std::string &path;
    const char *what;
};

void pem_file_read(mrb_state *mrb, PemFile pem, std::string &out_pem)
{
    const std::string &path = pem.path;
    const char *const what = pem.what;
    std::FILE *stream = std::fopen(path.c_str(), "rb");
    if (stream == nullptr) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s %s: %s", what, path.c_str(),
                   std::strerror(errno));
    }
    out_pem.clear();
    char chunk[4096];
    size_t got;
    while ((got = std::fread(chunk, 1, sizeof chunk, stream)) != 0)
        out_pem.append(chunk, got);
    const bool too_large = std::ferror(stream) != 0;
    std::fclose(stream);
    if (too_large) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s %s: read failed", what, path.c_str());
    }
    if (out_pem.empty()) {
        mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb), "conf.%s %s is empty", what, path.c_str());
    }
}

// https, a certificate and a key are one decision spelled three ways, so
// naming any of them means naming all of them.
void listener_build_tls(mrb_state *mrb, RingConfig &ring_config)
{
    pem_.assign(specs_.size() * 2, std::string());
    for (size_t i = 0; i < specs_.size(); i++) {
        const AppSpec &spec = *specs_[i];
        const bool named_files = !spec.cert_path.empty() || !spec.key_path.empty();
        if (!spec.tls && !named_files)
            continue;
        if (!spec.tls) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                       "application %i names a certificate but its listener is not https - "
                       "conf.url = \"https://...\" is what turns TLS on",
                       static_cast<mrb_int>(i));
        }
        if (spec.cert_path.empty() || spec.key_path.empty()) {
            mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                       "application %i serves https and needs both conf.certificate and "
                       "conf.private_key; it named %s",
                       static_cast<mrb_int>(i),
                       spec.cert_path.empty() ? "only the key" : "only the certificate");
        }
        std::string &cert = pem_[i * 2];
        std::string &key_path = pem_[i * 2 + 1];
        pem_file_read(mrb, {spec.cert_path, "certificate"}, cert);
        pem_file_read(mrb, {spec.key_path, "private_key"}, key_path);
        ring_config.listeners[i].cert_pem = cert.data();
        ring_config.listeners[i].cert_len = cert.size();
        ring_config.listeners[i].key_pem = key_path.data();
        ring_config.listeners[i].key_len = key_path.size();
    }
}

// The listener table, in registration order. A standalone server has
// one application, made by app_assets_only, and --unix or --port is
// its listener; every other application names its own.
void listeners_build(mrb_state *mrb, RingConfig &ring_config)
{
    ring_config.nlisteners = static_cast<uint32_t>(specs_.size());
    ring_config.stop_fd = opts_.stop_fd;
    if (opts_.standalone_unix_path != nullptr) {
        ring_config.listeners[0].unix_path = opts_.standalone_unix_path;
        return;
    }
    if (opts_.standalone_port != 0) {
        ring_config.listeners[0].port = opts_.standalone_port;
        return;
    }
    for (size_t i = 0; i < specs_.size(); i++) {
        switch (specs_[i]->form) {
            case AppSpec::Form::kUnix:
                ring_config.listeners[i].unix_path = specs_[i]->unix_path.c_str();
                break;
            case AppSpec::Form::kPort:
            case AppSpec::Form::kUrl:
                ring_config.listeners[i].port = specs_[i]->port;
                break;
            case AppSpec::Form::kNone:
                mrb_raisef(mrb, E_WM_CONFIG_ERROR(mrb),
                           "application %i has no listener - its configure block names one "
                           "(conf.port / conf.unix_path / conf.url)",
                           static_cast<mrb_int>(i));
        }
    }
}
} // namespace

#include "slipstream_syscall.h"

// Which side answers this process's rings, said at startup. When the
// kernel refuses io_uring, slipstream's engine answers every call
// underneath liburing, and this banner says so. Silence is the kernel.
void server_say_which_backend()
{
    if (slipstream_syscall_uses_engine()) {
        char reason[192] = "the kernel is too old, or a seccomp profile or an LSM blocks it";
        char switch_text[32] = "";
        const int switch_fd = ::open("/proc/sys/kernel/io_uring_disabled", O_RDONLY | O_CLOEXEC);
        if (switch_fd >= 0) {
            const ssize_t got = ::read(switch_fd, switch_text, sizeof(switch_text) - 1);
            ::close(switch_fd);
            if (got > 0) {
                switch_text[got] = '\0';
                if (switch_text[0] == '2') {
                    std::snprintf(reason, sizeof(reason),
                                  "sysctl kernel.io_uring_disabled=2 - io_uring is off for every "
                                  "process on this machine");
                } else if (switch_text[0] == '1') {
                    char group_text[32] = "";
                    const int group_fd =
                        ::open("/proc/sys/kernel/io_uring_group", O_RDONLY | O_CLOEXEC);
                    if (group_fd >= 0) {
                        const ssize_t group_read =
                            ::read(group_fd, group_text, sizeof(group_text) - 1);
                        ::close(group_fd);
                        if (group_read > 0)
                            group_text[group_read] = '\0';
                    }
                    std::snprintf(reason, sizeof(reason),
                                  "sysctl kernel.io_uring_disabled=1 - only members of group %s "
                                  "(kernel.io_uring_group) may, and this process is not one",
                                  group_text[0] != '\0' ? group_text : "?");
                }
            }
        }
        std::fprintf(
            stderr,
            "webmachine: ================================================================\n"
            "webmachine: == IO: slipstream's engine answers this process's rings\n"
            "webmachine: == why: %s\n"
            "webmachine: == cost: correct, not fast - every socket op is readiness plus\n"
            "webmachine: ==   a classic syscall, files ride a worker thread\n"
            "webmachine: == fast: the same binary, on a host that allows io_uring\n"
            "webmachine: ================================================================\n",
            reason);
    }
}

namespace
{
// Everything before the first accept, once.
void server_build_ring_config(mrb_state *mrb)
{
    if (built_)
        return;
    server_say_which_backend();

    app_registered_all(mrb, {specs_, kMaxListeners});
    RingConfig ring_config;
    ring_config.sq_entries = opts_.sq_entries;
    // The gem is embedded: a reactor that has to give up raises into this
    // VM instead of ending someone else's process.
    ring_config.mrb = mrb;
    ring_config.backlog = opts_.backlog;
    ring_config.header_timeout = opts_.header_timeout;
    ring_config.send_timeout = opts_.send_timeout;
    ring_config.idle_timeout = opts_.idle_timeout;
    listeners_build(mrb, ring_config);
    listener_build_tls(mrb, ring_config);

    // The docroot: a standalone server's --docroot or [server] docroot, or
    // the first application that names one in its conf. The canonical path
    // is settled here, before the first accept, so no request can race the
    // anchor RESOLVE_BENEATH measures against. A docroot that is missing or
    // is not a directory refuses the start by name.
    {
        const char *docroot = opts_.standalone_docroot_path;
        for (size_t i = 0; docroot == nullptr && i < specs_.size(); i++) {
            if (!specs_[i]->docroot.empty())
                docroot = specs_[i]->docroot.c_str();
        }
        if (docroot != nullptr) {
            docroot_open(mrb, docroot);
            std::fprintf(stderr, "webmachine: docroot %s\n", docroot_path());
        }
    }

    // conf.spill_dir: where a request body that outgrows memory is
    // written. The first application that names one decides, the same
    // rule the docroot keeps. Nobody naming one leaves the platform's
    // own choice, which is TMPDIR and then /tmp - and /tmp is tmpfs on
    // most machines, so a large upload is memory there.
    {
        for (size_t i = 0; i < specs_.size(); i++) {
            if (specs_[i]->spill_dir.empty())
                continue;
            spill_dir_set(specs_[i]->spill_dir.c_str());
            std::fprintf(stderr, "webmachine: request bodies spill into %s\n", spill_dir_get());
            break;
        }
    }

    // conf.disable_http_cats: the first app with an opinion decides, the way
    // every other conf answer is taken. Asked before the pack is looked for,
    // because "off" means it is never opened, not opened and ignored.
    int8_t no_cats = -1;
    for (size_t i = 0; no_cats < 0 && i < specs_.size(); i++) {
        no_cats = specs_[i]->disable_http_cats;
    }
    const std::string error_assets_file =
        no_cats == 1 ? std::string() : error_assets_path(opts_.error_assets_path);
    const bool standalone = opts_.standalone;
    const char *assets_path = opts_.standalone_assets_path;
    for (size_t i = 0; assets_path == nullptr && i < specs_.size(); i++) {
        if (!specs_[i]->assets.empty())
            assets_path = specs_[i]->assets.c_str();
    }
    if (assets_path != nullptr || !error_assets_file.empty() || (standalone && docroot_fd() >= 0)) {
        mime_.load(mrb, opts_.mime_types_path);
        std::fprintf(stderr, "webmachine: media types from %s (%zu extensions)\n",
                     mime_.source().c_str(), mime_.size());
    }
    if (assets_path != nullptr)
        assets_.open(mrb, assets_path, mime_);
    if (!error_assets_file.empty()) {
        // Caught on purpose, the one start-up refusal that is not one: a
        // picture is no reason not to serve. The reason goes to the error
        // log, and the pages render without it.
        OpenPack pack{&error_assets_, error_assets_file.c_str(), &mime_};
        mrb_bool raised = FALSE;
        const mrb_value answer =
            mrb_protect_error(mrb, pack_open_in_protected_call, &pack, &raised);
        if (!raised) {
            error_assets_up_ = true;
            std::fprintf(stderr, "webmachine: error assets from %s\n", error_assets_file.c_str());
        } else {
            const mrb_value said = mrb_obj_as_string(mrb, answer);
            error_assets_note_ = "error assets at " + error_assets_file + " unusable (" +
                                 std::string(ruby_string_bytes(said)) +
                                 ") - pages without pictures";
        }
    } else if (no_cats == 1) {
        // Asked for, so not a complaint: the pages still render, they just
        // show no picture, and nothing is mounted at /error_assets/.
        std::fprintf(stderr, "webmachine: conf.disable_http_cats - error pages without pictures\n");
    } else {
        // Without a pack the errors answer in plain text. That is no reason
        // to refuse the start, but the operator hears it once.
        std::fprintf(stderr, "webmachine: no error assets found - errors answer in plain text. "
                             "Name a file with --error-assets=FILE.zip, or install one as "
                             "<prefix>/share/webmachine-mruby/error-assets.zip\n");
    }

    if (opts_.log_path != nullptr) {
        if (opts_.log_privacy != nullptr && std::strcmp(opts_.log_privacy, "none") == 0) {
            std::fprintf(
                stderr,
                "webmachine: --log-privacy=none writes full client addresses to the log.\n"
                "webmachine: an IP address is personal data (GDPR art. 4(1)); logging it\n"
                "webmachine: needs a legal basis (art. 6). Security logging with short\n"
                "webmachine: retention usually rides legitimate interest plus a privacy\n"
                "webmachine: notice; using the addresses beyond that (analytics, tracking)\n"
                "webmachine: needs consent. DNT/Sec-GPC peers are capped to anon either way.\n");
        }
        // The access log is a window - it answers what happened in the last
        // so-many bytes. Dropping the oldest is its semantics, not a loss.
        const LogdSpawn access = {"access", opts_.log_path,
                                  opts_.log_privacy != nullptr ? opts_.log_privacy : "anon",
                                  opts_.log_max_bytes};
        log_fd_ = spawn_logd(mrb, access);
        ring_config.log_fd = log_fd_;
    }
    if (opts_.error_log_path != nullptr) {
        // No ceiling (0 disables the cap in webmachine-logd). An error log is
        // not a window: what lands here is a 500 or a Ruby exception with its
        // backtrace, never ordinary traffic, so it does not grow on its own.
        // It grows in a fault storm - and that is the one moment where the
        // first entry is the one that names the cause and everything after it
        // is consequence. A ceiling that keeps the newest half would throw
        // away exactly the line worth having.
        err_fd_ = spawn_logd(mrb, {"error", opts_.error_log_path, nullptr, 0});
        ring_config.err_fd = err_fd_;
    }

    resources_.resize(specs_.size());
    ws_resources_.resize(specs_.size());
    sse_resources_.resize(specs_.size());
    std::vector<Http1::AppInput> inputs(specs_.size());
    for (size_t i = 0; i < specs_.size(); i++) {
        resources_[i].reserve(specs_[i]->resources.size());
        for (const auto &r : specs_[i]->resources)
            resources_[i].push_back(r.get());
        ws_resources_[i].reserve(specs_[i]->ws_resources.size());
        for (const auto &r : specs_[i]->ws_resources)
            ws_resources_[i].push_back(r.get());
        sse_resources_[i].reserve(specs_[i]->sse_resources.size());
        for (const auto &r : specs_[i]->sse_resources)
            sse_resources_[i].push_back(r.get());
        inputs[i] = Http1::AppInput{
            &specs_[i]->table,
            resources_[i].data(),
            resources_[i].size(),
            &specs_[i]->ws_table,
            ws_resources_[i].data(),
            ws_resources_[i].size(),
            &specs_[i]->sse_table,
            sse_resources_[i].data(),
            sse_resources_[i].size(),
            specs_[i]->tls,
            specs_[i]->max_body >= 0 ? static_cast<size_t>(specs_[i]->max_body) : kMaxBodyDefault};
    }
    http_.reset(
        new Http1(inputs.data(), inputs.size(), assets_path != nullptr ? &assets_ : nullptr));
    // Standalone: nobody wrote a resource, so the docroot answers through
    // the folded graph and the VM is never entered for a request.
    if (standalone && docroot_fd() >= 0) {
        http_->serve_docroot(&mime_);
        std::fprintf(stderr, "webmachine: standalone - the docroot answers, no app\n");
    }
    // #210: the error pages render in the app's VM. A template the pack
    // carries that does not parse refuses the start by name, here and not
    // on the first 404.
    http_->open_error_assets(mrb, error_assets_up_ ? &error_assets_ : nullptr);
    // #210: and the same assets under response.error_asset("404.jpg"),
    // so an app can answer with one of these pictures wherever it likes,
    // not only where the error resource does.
    response_bind_error_assets(error_assets_up_ ? &error_assets_ : nullptr);
    if (opts_.log_path != nullptr)
        http_->enable_access_log();
    if (opts_.error_log_path != nullptr)
        http_->enable_error_log();
    if (!error_assets_note_.empty()) {
        say_server_error(http_->error_log(), error_assets_note_);
        error_assets_note_.clear();
    }
    // A flag and [tune] beat the app's conf, and all three beat the
    // built-in default.
    long long lend_threshold = opts_.zero_copy_threshold;
    for (size_t i = 0; lend_threshold < 0 && i < specs_.size(); i++) {
        lend_threshold = specs_[i]->zero_copy_threshold;
    }
    if (lend_threshold >= 0)
        http_->set_zero_copy_threshold(static_cast<size_t>(lend_threshold));
    long long map_threshold = opts_.file_map_threshold;
    for (size_t i = 0; map_threshold < 0 && i < specs_.size(); i++) {
        map_threshold = specs_[i]->file_map_threshold;
    }
    if (map_threshold >= 0)
        http_->set_file_map_threshold(static_cast<size_t>(map_threshold));

    // Built into a local first: a refusal from init unwinds through this
    // one's destructor, and ring_ is only ever a ring that came up.
    auto ring = std::unique_ptr<Ring<Http1>>(new Ring<Http1>(*http_));
    ring->init(ring_config);
    ring_ = std::move(ring);

    for (size_t i = 0; i < specs_.size(); i++) {
        app_mark_bound(mrb, *specs_[i], ring_config.listeners[i].unix_path,
                       ring_->bound_port(static_cast<uint32_t>(i)));
        app_ready_run(mrb, *specs_[i]);
    }

    std::fprintf(stderr, "webmachine: up, pid %d, %u listener(s)\n", getpid(),
                 ring_config.nlisteners);
    for (uint32_t i = 0; i < ring_config.nlisteners; i++) {
        if (ring_config.listeners[i].unix_path != nullptr) {
            std::fprintf(stderr, "webmachine:   [%u] unix %s\n", i,
                         ring_config.listeners[i].unix_path);
        } else {
            std::fprintf(stderr, "webmachine:   [%u] tcp port %d%s\n", i, ring_->bound_port(i),
                         ring_config.listeners[i].cert_pem != nullptr ? ", tls" : "");
        }
    }
    built_ = true;
}

// Webmachine.run, .tick, .fd and .stopped need the server built. This
// builds it and marks it entered.
void server_ring_must_be_up(mrb_state *mrb)
{
    server_build_ring_config(mrb);
    entered_ = true;
}

// Webmachine.run: block, serve, return when the stop signal lands.
mrb_value server_method_run(mrb_state *mrb, mrb_value self)
{
    server_ring_must_be_up(mrb);
    ring_->run();
    return self;
}

// Webmachine.tick(budget): one bounded step - the budget bounds the work.
mrb_value server_method_tick(mrb_state *mrb, mrb_value)
{
    mrb_value budget = mrb_nil_value();
    mrb_get_args(mrb, "|o", &budget);
    server_ring_must_be_up(mrb);
    if (mrb_nil_p(budget))
        return mrb_bool_value(ring_->tick(nullptr));
    const auto nanoseconds = mrb_chrono::as<std::chrono::nanoseconds>(mrb, budget);
    if (nanoseconds.count() < 0) {
        mrb_raise(mrb, E_RUNTIME_ERROR, "Webmachine.tick wants a duration, not a negative one");
    }
    struct __kernel_timespec ts {
        nanoseconds.count() / 1000000000, nanoseconds.count() % 1000000000
    };
    return mrb_bool_value(ring_->tick(&ts));
}

// Webmachine.fd: what an embedder polls between ticks.
mrb_value server_method_fd(mrb_state *mrb, mrb_value)
{
    server_ring_must_be_up(mrb);
    const int ring_fd = ring_->fd();
    if (ring_fd < 0) {
        mrb_raise(mrb, E_RUNTIME_ERROR,
                  "this io backend has no pollable descriptor - drive it with "
                  "Webmachine.tick(budget) instead of waiting on an fd");
    }
    return mrb_fixnum_value(ring_fd);
}

// Webmachine.stop(grace): drain, then forget. Process-wide, and named so.
mrb_value server_method_stop(mrb_state *mrb, mrb_value self)
{
    mrb_value grace = mrb_nil_value();
    mrb_get_args(mrb, "|o", &grace);
    if (!built_)
        return self;
    int64_t nanoseconds = 0;
    if (!mrb_nil_p(grace)) {
        nanoseconds = mrb_chrono::as<std::chrono::nanoseconds>(mrb, grace).count();
        if (nanoseconds < 0) {
            mrb_raise(mrb, E_RUNTIME_ERROR, "Webmachine.stop wants a grace, not a negative one");
        }
    }
    ring_->drain(nanoseconds);
    return self;
}

// Did the stop signal's completion land?
mrb_value server_method_is_stopped(mrb_state *mrb, mrb_value)
{
    server_ring_must_be_up(mrb);
    return mrb_bool_value(ring_->stopped());
}
} // namespace

// What the invocation decides; not reachable from Ruby, deliberately.
void server_options(const ServerOptions &opts)
{
    opts_ = opts;
}

// Did `main` serve already through run or tick?
bool server_entered()
{
    return entered_;
}

// Webmachine.run / .tick / .fd / .stop, next to the Application.
void server_init(mrb_state *mrb, struct RClass *webmachine_module)
{
    mrb_define_module_function_id(mrb, webmachine_module, MRB_SYM(run), server_method_run,
                                  MRB_ARGS_NONE());
    mrb_define_module_function_id(mrb, webmachine_module, MRB_SYM(tick), server_method_tick,
                                  MRB_ARGS_OPT(1));
    mrb_define_module_function_id(mrb, webmachine_module, MRB_SYM(fd), server_method_fd,
                                  MRB_ARGS_NONE());
    mrb_define_module_function_id(mrb, webmachine_module, MRB_SYM(stop), server_method_stop,
                                  MRB_ARGS_OPT(1));
    struct RClass *app_class = mrb_class_get_under_id(mrb, webmachine_module, MRB_SYM(Application));
    mrb_define_method_id(mrb, app_class, MRB_SYM(stop), server_method_stop, MRB_ARGS_OPT(1));
    mrb_define_module_function_id(mrb, webmachine_module, MRB_SYM_Q(stopped),
                                  server_method_is_stopped, MRB_ARGS_NONE());
}

// The tool's entry: build if Ruby has not, then loop until the stop signal.
int server_run(mrb_state *mrb)
{
    server_build_ring_config(mrb);
    entered_ = true;
    ring_->run();
    server_release();
    return 0;
}

// Both die here, while the VM stands: the error pages hold a root in it,
// and a connection's watchers do. A file scope object dies at exit,
// after mrb_close, and its destructor then reads a state that is freed.
// The thread sanitizer named that on a run whose server raised: the
// raise carried the stack past the line above, main closed the VM, and
// ~ErrorPages called mrb_gc_unregister on it. The owner of the VM calls
// this before mrb_close, on every way out.
void server_release()
{
    ring_.reset();
    http_.reset();
}
} // namespace webmachine
