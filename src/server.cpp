#include "webmachine.hpp"
#include "ring.hpp"

#include <cstring>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <mruby/chrono.hpp>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/string.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <thread>
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
// What one Http1 is built from: the resource tables of every registered
// application, in a form the constructor reads. The acceptor has one set,
// and every answering thread that loads the application has its own.
struct AppInputs {
    std::vector<std::vector<const Resource *>> resources;
    std::vector<std::vector<const WsResource *>> ws_resources;
    std::vector<std::vector<const SseResource *>> sse_resources;
    std::vector<Http1::AppInput> inputs;
};
AppInputs main_inputs_;
// The thresholds the acceptor's Http1 was given, so a thread's is given
// the same. Below zero: the built-in default stands.
long long lend_threshold_ = -1;
long long map_threshold_ = -1;
bool assets_up_ = false;

void app_inputs_build(const std::vector<AppSpec *> &specs, AppInputs &out)
{
    out.resources.resize(specs.size());
    out.ws_resources.resize(specs.size());
    out.sse_resources.resize(specs.size());
    out.inputs.resize(specs.size());
    for (size_t i = 0; i < specs.size(); i++) {
        const AppSpec &spec = *specs.at(i);
        std::vector<const Resource *> &resources = out.resources.at(i);
        std::vector<const WsResource *> &ws_resources = out.ws_resources.at(i);
        std::vector<const SseResource *> &sse_resources = out.sse_resources.at(i);
        resources.reserve(spec.resources.size());
        for (const auto &r : spec.resources)
            resources.push_back(r.get());
        ws_resources.reserve(spec.ws_resources.size());
        for (const auto &r : spec.ws_resources)
            ws_resources.push_back(r.get());
        sse_resources.reserve(spec.sse_resources.size());
        for (const auto &r : spec.sse_resources)
            sse_resources.push_back(r.get());
        out.inputs.at(i) = Http1::AppInput{
            &spec.table,
            resources.data(),
            resources.size(),
            &spec.ws_table,
            ws_resources.data(),
            ws_resources.size(),
            &spec.sse_table,
            sse_resources.data(),
            sse_resources.size(),
            spec.tls,
            spec.max_body >= 0 ? static_cast<size_t>(spec.max_body) : kMaxBodyDefault};
    }
}
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
// --threads=N: one ring and one Http1 per thread, fed by the acceptor.
struct AnswerThread {
    std::unique_ptr<Http1> app;
    std::unique_ptr<Ring<Http1>> ring;
    // This thread's own VM. It loads the application when the server has
    // one, so a route with a callback runs here, on this thread, in this
    // VM. A raise from the ring unwinds inside it, and the sentence
    // reaches the acceptor.
    mrb_state *mrb = nullptr;
    std::vector<AppSpec *> specs;
    AppInputs app_inputs;
    std::atomic<int> ring_fd{-1};
    std::atomic<bool> failed{false};
    std::string why;
    std::thread thread;
    // What this thread calls itself, counted from 1 as an operator counts.
    int number = 0;

    ~AnswerThread()
    {
        app.reset();
        ring.reset();
        if (mrb != nullptr) {
            app_registry_release(mrb);
            mrb_close(mrb);
        }
    }
};

// The raise that mrb_protect_error caught, as one sentence.
// mrb_protect_error answers the exception as its value and leaves
// mrb->exc clear, so the value is what carries it.
std::string answer_thread_why(mrb_state *mrb, mrb_value thrown)
{
    if (!mrb_exception_p(thrown))
        return "the ring did not come up, and what was thrown is no exception";
    const int arena = mrb_gc_arena_save(mrb);
    const mrb_value text = mrb_inspect(mrb, thrown);
    std::string answer = mrb->exc == nullptr && mrb_string_p(text)
                             ? std::string(RSTRING_PTR(text), RSTRING_LEN(text))
                             : std::string("the exception could not be read");
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, arena);
    return answer;
}
std::vector<std::unique_ptr<AnswerThread>> answer_threads_;
std::vector<int> answer_ring_fds_;

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
    // The only fork in this tree. A ring cannot be forked and a thread
    // with its own ring and its own VM answers everything an application
    // can declare, so nothing else splits this process.
    const pid_t child = ::fork();
    if (child < 0) {
        const int saved_errno = errno;
        close_or_raise(mrb, "the log socket", socket_pair[0]);
        close_or_raise(mrb, "the log socket", socket_pair[1]);
        mrb_raisef(mrb, E_WM_ERROR(mrb), "%s log: fork: %s", mode, std::strerror(saved_errno));
    }
    if (child == 0) {
        // The child raises into no VM: it is a forked copy that is about
        // to become another program, and every one of these ends it.
        if (::dup2(socket_pair[0], 0) < 0) {
            std::fprintf(stderr, "webmachine: %s log: dup2: %s\n", mode, std::strerror(errno));
            ::_exit(127);
        }
        close_or_die("the log socket", socket_pair[0]);
        close_or_die("the log socket", socket_pair[1]);
        ::execl(logd.c_str(), "webmachine-logd", mode, path, max_bytes_text, privacy,
                (char *)nullptr);
        std::fprintf(stderr, "webmachine: exec %s: %s\n", logd.c_str(), std::strerror(errno));
        ::_exit(127);
    }
    close_or_raise(mrb, "the log socket", socket_pair[0]);
    if (::signal(SIGCHLD, SIG_IGN) == SIG_ERR)
        raise_errno(mrb, "signal(SIGCHLD)", errno);
    return socket_pair[1];
}

// TLS is not in this build. mruby-ktls is gone and mruby-tls is not
// ready, so nothing here can hold a record layer.
//
// The configuration still names TLS, and still parses: conf.url may say
// https, and conf.certificate, conf.private_key and conf.certificates
// are read into the AppSpec as they always were. A configuration written
// for TLS therefore survives this branch untouched.
//
// What a build without TLS may never do is accept that configuration and
// then speak cleartext. An operator who asked for https and was given
// http has no way to see it from inside the process, and the peer has no
// way to see it either. So the moment an application wants TLS, this
// says so and stops.
void listener_tls_refuse(mrb_state *mrb)
{
    for (size_t i = 0; i < specs_.size(); i++) {
        const AppSpec &spec = *specs_[i];
        const bool named_files =
            !spec.cert_path.empty() || !spec.key_path.empty() || !spec.named_pairs.empty();
        if (!spec.tls && !named_files)
            continue;
        mrb_raisef(mrb, E_NOTIMP_ERROR,
                   "application %i asks for TLS, and this build has none. The record layer "
                   "moves from mruby-ktls to mruby-tls, and until that lands a listener "
                   "serves cleartext only: drop the https from conf.url and put a proxy in "
                   "front, or build from a branch that has TLS",
                   static_cast<mrb_int>(i));
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
            close_or_die("/proc/sys/kernel/io_uring_disabled", switch_fd);
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
                        close_or_die("/proc/sys/kernel/io_uring_group", group_fd);
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
// One answering thread: its own Http1, its own ring, and nothing it
// shares with another thread but the docroot descriptor and the media
// type table, which are read only once the server is up.
// What the two protected bodies need, in one block: mrb_protect_error
// carries exactly one pointer.
struct AnswerThreadBoot {
    AnswerThread *self;
    RingConfig *base;
    Http1::AppInput *inputs;
    size_t ninputs;
    bool listings;
};

// The ring comes up here, under the thread's own VM.
mrb_value answer_thread_boot(mrb_state *mrb, void *user_data)
{
    AnswerThreadBoot &ask = *static_cast<AnswerThreadBoot *>(user_data);
    AnswerThread &self = *ask.self;
    if (opts_.app_path != nullptr) {
        // The same bytecode the acceptor's VM ran. Its main registers
        // into this VM's registry, and the tables it built are this
        // thread's. The listener is the acceptor's; the specs here only
        // carry the routes, the conf and the hooks.
        app_load(mrb, opts_.app_path);
        app_registered_all(mrb, {self.specs, kMaxListeners});
        app_inputs_build(self.specs, self.app_inputs);
        self.app.reset(new Http1(self.app_inputs.inputs.data(), self.app_inputs.inputs.size(),
                                 assets_up_ ? &assets_ : nullptr));
    } else {
        self.app.reset(new Http1(ask.inputs, ask.ninputs, nullptr));
    }
    if (docroot_fd() >= 0)
        self.app->serve_docroot(&mime_, ask.listings);
    self.app->open_error_assets(mrb, error_assets_up_ ? &error_assets_ : nullptr);
    if (lend_threshold_ >= 0)
        self.app->set_zero_copy_threshold(static_cast<size_t>(lend_threshold_));
    if (map_threshold_ >= 0)
        self.app->set_file_map_threshold(static_cast<size_t>(map_threshold_));
    auto ring = std::unique_ptr<Ring<Http1>>(new Ring<Http1>(*self.app));
    RingConfig base = *ask.base;
    base.mrb = mrb;
    base.nlisteners = 0;
    base.takes_no_listener = true;
    // The stop signal is the acceptor's. This ring hears the word
    // through its own queue, from the acceptor.
    base.stop_fd = -1;
    base.worker_ring_fds = nullptr;
    base.nworkers = 0;
    ring->init(base);
    self.ring = std::move(ring);
    for (AppSpec *spec : self.specs) {
        app_mark_bound(mrb, *spec, spec->form == AppSpec::Form::kUnix ? spec->unix_path.c_str() : nullptr,
                       spec->port);
        app_ready_run(mrb, *spec);
    }
    return mrb_nil_value();
}

// The serving loop, under the same VM.
mrb_value answer_thread_serve(mrb_state *, void *user_data)
{
    AnswerThreadBoot &ask = *static_cast<AnswerThreadBoot *>(user_data);
    ask.self->ring->run();
    return mrb_nil_value();
}

// One answering thread: its own VM, its own Http1, its own ring.
//
// The VM is why this is not a try block. Ring::init reports a refusal
// with mrb_raise, and mruby here is built with MRB_USE_CXX_EXCEPTION, so
// that raise is `throw (mrb_jmpbuf *)` - not a std::exception. A catch
// here would swallow the class, the message and the errno together, and
// said so: "the thread failed to start, and said nothing". Raising into
// the acceptor's VM is no answer either, because that writes mrb->exc
// from a second thread. So the thread carries a VM of its own and reads
// the exception back as a value.
// A thread carries the name of the work it does. Without one every
// thread of this process answers webmachine-serv, which names the
// program and not the thread, and a reader of top, of ps, or of the
// placement line in bench/floor.sh cannot tell the thread that accepts
// from the threads that answer. The kernel's own io-wq workers already
// say iou-wrk-<pid> and are not ours to name.
//
// Linux takes fifteen octets and cuts the rest. "wm-answer-10" is
// twelve, so the number fits as far as a thread count goes.
void thread_name_set(const std::string &name)
{
#ifdef __linux__
    ::prctl(PR_SET_NAME, name.c_str(), 0, 0, 0);
#else
    (void) name;
#endif
}

void answer_thread_run(AnswerThread &self, RingConfig base, Http1::AppInput *inputs, size_t ninputs,
                       bool listings)
{
    thread_name_set("wm-answer-" + std::to_string(self.number));
    mrb_state *const mrb = mrb_open();
    if (mrb == nullptr) {
        self.why = "no VM for the answering thread: out of memory";
        self.failed.store(true, std::memory_order_release);
        self.ring_fd.store(-2, std::memory_order_release);
        return;
    }
    self.mrb = mrb;
    AnswerThreadBoot ask{&self, &base, inputs, ninputs, listings};
    mrb_bool raised = FALSE;
    const mrb_value thrown = mrb_protect_error(mrb, answer_thread_boot, &ask, &raised);
    if (raised) {
        self.why = answer_thread_why(mrb, thrown);
        self.failed.store(true, std::memory_order_release);
        self.ring_fd.store(-2, std::memory_order_release);
        return;
    }
    self.ring_fd.store(self.ring->fd(), std::memory_order_release);
    const mrb_value stopped = mrb_protect_error(mrb, answer_thread_serve, &ask, &raised);
    if (raised) {
        std::fprintf(stderr, "webmachine: an answering thread stopped: %s\n",
                     answer_thread_why(mrb, stopped).c_str());
    }
}

// Start them, and wait until every one has a ring or has failed. The
// acceptor cannot arm an accept before it knows where to send a peer.
void answer_threads_start(mrb_state *mrb, const RingConfig &base, Http1::AppInput *inputs,
                          size_t ninputs, bool listings)
{
    for (int t = 0; t < opts_.threads; t++) {
        auto one = std::unique_ptr<AnswerThread>(new AnswerThread());
        AnswerThread &self = *one;
        self.number = t + 1;
        answer_threads_.push_back(std::move(one));
        self.thread =
            std::thread(answer_thread_run, std::ref(self), base, inputs, ninputs, listings);
    }
    for (const auto &one : answer_threads_) {
        int fd = -1;
        while ((fd = one->ring_fd.load(std::memory_order_acquire)) == -1)
            std::this_thread::yield();
        if (fd < 0) {
            // A thread that did come up is inside io_uring_wait_cqe and
            // leaves only when the acceptor sends the stop word. There is
            // no acceptor yet, so joining it here waits for something that
            // cannot happen - that hung the server instead of raising.
            //
            // Detaching alone is not enough either: the raise below unwinds
            // into server_release, which clears this vector, and every
            // AnswerThread it destroys takes a running thread's ring, its
            // app and its VM with it. That is a use after free in a thread
            // that is still serving, and it dumped core in mrb_ci_nregs
            // while this one was in obj_free.
            //
            // So the blocks are released rather than destroyed. Each
            // detached thread keeps what it holds for as long as it runs,
            // and the raise below ends the server.
            const std::string why = one->why;
            for (auto &other : answer_threads_) {
                if (other->thread.joinable())
                    other->thread.detach();
                (void)other.release();
            }
            answer_threads_.clear();
            answer_ring_fds_.clear();
            mrb_raisef(mrb, E_WM_ERROR(mrb), "an answering thread did not start: %s", why.c_str());
        }
        answer_ring_fds_.push_back(fd);
    }
}

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
    listener_tls_refuse(mrb);

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
                                 std::string(std::string_view(RSTRING_PTR(said), static_cast<size_t>(RSTRING_LEN(said)))) +
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

    app_inputs_build(specs_, main_inputs_);
    std::vector<Http1::AppInput> &inputs = main_inputs_.inputs;
    assets_up_ = assets_path != nullptr;
    http_.reset(
        new Http1(inputs.data(), inputs.size(), assets_path != nullptr ? &assets_ : nullptr));
    // Standalone: nobody wrote a resource, so the docroot answers through
    // the folded graph and the VM is never entered for a request.
    if (standalone && docroot_fd() >= 0) {
        http_->serve_docroot(&mime_, opts_.standalone_listings);
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
    lend_threshold_ = lend_threshold;
    if (lend_threshold >= 0)
        http_->set_zero_copy_threshold(static_cast<size_t>(lend_threshold));
    long long map_threshold = opts_.file_map_threshold;
    for (size_t i = 0; map_threshold < 0 && i < specs_.size(); i++) {
        map_threshold = specs_[i]->file_map_threshold;
    }
    map_threshold_ = map_threshold;
    if (map_threshold >= 0)
        http_->set_file_map_threshold(static_cast<size_t>(map_threshold));

    // --threads=N: the threads that answer come up before the acceptor,
    // because the acceptor has to know their rings before it takes the
    // first peer.
    if (opts_.threads > 1) {
        // The rings are locked memory and the limit is this process's. It
        // opens one per answering thread and one that accepts, and they
        // share three quarters of that limit.
        ring_config.rings_in_process = static_cast<uint32_t>(opts_.threads) + 1;
        answer_threads_start(mrb, ring_config, inputs.data(), inputs.size(),
                             opts_.standalone_listings);
        ring_config.worker_ring_fds = answer_ring_fds_.data();
        ring_config.nworkers = static_cast<uint32_t>(answer_ring_fds_.size());
    }

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

    std::fprintf(stderr, "webmachine: up, pid %d, %u listener(s)%s\n", getpid(),
                 ring_config.nlisteners, opts_.threads > 1 ? ", answered by threads" : "");
    if (opts_.threads > 1) {
        std::fprintf(stderr, "webmachine: %d threads answer, one ring each; this one accepts\n",
                     opts_.threads);
    }
    for (uint32_t i = 0; i < ring_config.nlisteners; i++) {
        if (ring_config.listeners[i].unix_path != nullptr) {
            std::fprintf(stderr, "webmachine:   [%u] unix %s\n", i,
                         ring_config.listeners[i].unix_path);
        } else {
            std::fprintf(stderr, "webmachine:   [%u] tcp port %d\n", i, ring_->bound_port(i));
        }
    }
    // Where this server answers, on stdout and nowhere else. Every other
    // start line goes to stderr, so this one line is what a script reads
    // and what an operator copies into a browser. A port the kernel chose
    // (port = 0) is only knowable here, and this is how it is said.
    for (uint32_t i = 0; i < ring_config.nlisteners; i++) {
        if (ring_config.listeners[i].unix_path != nullptr) {
            // A unix socket has no authority to write in a URL. curl takes
            // it as --unix-socket, and this line spells that.
            std::printf("http://localhost/ (unix socket %s)\n",
                        ring_config.listeners[i].unix_path);
        } else {
            std::printf("http://localhost:%d/\n", ring_->bound_port(i));
        }
    }
    std::fflush(stdout);
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
    docroot_init(mrb, webmachine_module);
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
    // The threads first: each one holds a ring that names connections,
    // and the acceptor's own teardown must not run beside them.
    if (ring_ != nullptr)
        ring_->stop_the_workers();
    for (const auto &one : answer_threads_) {
        if (one->thread.joinable())
            one->thread.join();
    }
    answer_threads_.clear();
    answer_ring_fds_.clear();
    ring_.reset();
    http_.reset();
}
} // namespace webmachine
