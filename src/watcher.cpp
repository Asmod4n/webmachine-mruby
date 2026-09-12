#include <cstdio>

#include "http1.hpp"

#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/error.h>
#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/variable.h>
#include <mruby/string.h>

#include <liburing.h>
#include <poll.h>

namespace webmachine
{
namespace
{

// Nothing here is a Ruby object; `source` and `block` are, and live in
// the iv table. RData carries both (mruby/data.h).
struct WatcherData {
    // Taken once in initialize; the destructor cannot ask a sweeping GC
    // for it. int, not a handle type - Windows CRT hands out int fds too.
    int descriptor = -1;
    // #30: the key on Http1::Conn's hash, and bits 48..55 of the tag.
    int slot = -1;
    // #30: which job of the round this watcher answers. A round waits on
    // several at once, and each answer has its own place.
    int job_number = 0;
    // #30: the state of the run this watcher belongs to. It lives in the
    // coroutine frame that parked, and the frame outlives every wait it
    // started.
    Resource::RunState *run_state = nullptr;
    // #30: the round of that run - where this watcher leaves its answer.
    Http1::Conn::Round *round = nullptr;
    // #30: the whole second this watcher may stay quiet until, or 0.
    int64_t deadline_at = 0;
    // POLLIN, POLLOUT or both.
    unsigned events = POLLIN;
    // Set by watcher.abort, read after the block returns.
    bool aborted = false;
    // #30: how many seconds this watcher may stay quiet. A descriptor
    // that says nothing is the usual end of a wait, so a watcher owes a
    // deadline the same way a compute task owes max_runtime. What the two
    // do at the deadline differs, and only that.
    double timeout = 0.0;
    struct io_uring *ring = nullptr;
    // The tag the armed poll carries, so a cancel names exactly it and
    // never another watcher's poll on the same descriptor.
    uint64_t poll_tag = 0;
    bool armed = false;
};

// Reached only when nobody disarmed first - a raise out of a callback.
// Http1::Conn::watchers_drop empties the CDATA, so the usual sweep finds
// nothing here.
void watcher_free(mrb_state *, void *raw)
{
    auto *watcher = static_cast<WatcherData *>(raw);
    if (watcher == nullptr)
        return;
    // No VM to raise into here: the GC is freeing this. A full queue is
    // submitted and tried once more, and a cancel that still finds no
    // room is said on stderr.
    if (watcher->armed && watcher->ring != nullptr) {
        struct io_uring_sqe *symbol_name = io_uring_get_sqe(watcher->ring);
        if (symbol_name == nullptr) {
            io_uring_submit(watcher->ring);
            symbol_name = io_uring_get_sqe(watcher->ring);
        }
        if (symbol_name == nullptr) {
            std::fprintf(stderr, "webmachine: watcher on fd %d could not be cancelled: SQ full\n",
                         watcher->descriptor);
        } else {
            io_uring_prep_poll_remove(symbol_name, watcher->poll_tag);
            io_uring_sqe_set_data64(symbol_name, 0);
            io_uring_submit(watcher->ring);
        }
    }
    delete watcher;
}

const struct mrb_data_type watcher_type = {"Webmachine::Watcher", watcher_free};

WatcherData *watcher_data_or_raise(mrb_state *mrb, mrb_value self)
{
    auto *watcher = static_cast<WatcherData *>(DATA_PTR(self));
    if (watcher == nullptr)
        mrb_raise(mrb, E_WM_ERROR(mrb), "this watcher was never initialized");
    return watcher;
}

// What may be ordered. What arrives (revents) is a wider set. Each
// direction has two names: :r or :in, :w or :out, :rw or :inout.
unsigned events_mask_of_symbol(mrb_state *mrb, mrb_value value)
{
    if (!mrb_symbol_p(value)) {
        mrb_raisef(mrb, E_ARGUMENT_ERROR,
                   "a watcher waits for :r (:in), :w (:out) or :rw (:inout), not %v", value);
    }
    const mrb_sym symbol_name = mrb_symbol(value);
    if (symbol_name == MRB_SYM(r) || symbol_name == MRB_SYM(in))
        return POLLIN;
    if (symbol_name == MRB_SYM(w) || symbol_name == MRB_SYM(out))
        return POLLOUT;
    if (symbol_name == MRB_SYM(rw) || symbol_name == MRB_SYM(inout))
        return POLLIN | POLLOUT;
    mrb_raisef(mrb, E_ARGUMENT_ERROR,
               "a watcher waits for :r (:in), :w (:out) or :rw (:inout), not %v", value);
    return 0;
}

mrb_value events_symbol_of_mask(mrb_state *mrb, unsigned mask)
{
    const unsigned read_and_write = mask & (POLLIN | POLLOUT);
    if (read_and_write == (POLLIN | POLLOUT))
        return mrb_symbol_value(MRB_SYM(rw));
    if (read_and_write == POLLOUT)
        return mrb_symbol_value(MRB_SYM(w));
    return mrb_symbol_value(MRB_SYM(r));
}

// Watcher.new(source, :r, timeout: 5.0) { |revents, watcher| ... } - a
// description. Arming happens when a resource hands one back; see #30.
//: (untyped, ?untyped) { (Webmachine::Watcher) -> void } -> Webmachine::Watcher
mrb_value watcher_init(mrb_state *mrb, mrb_value self)
{
    mrb_value source;
    mrb_value events = mrb_symbol_value(MRB_SYM(r));
    mrb_value block = mrb_nil_value();
    // mruby checks keywords against a declared table. timeout is declared
    // optional, so the refusal below is ours and says why a deadline is
    // owed. The slot starts as undef, because mrb_get_args leaves a key
    // that was not given untouched.
    const mrb_sym kw_names[] = {MRB_SYM(timeout)};
    mrb_value kw_values[1] = {mrb_undef_value()};
    const mrb_kwargs kwargs = {1, 0, kw_names, kw_values, nullptr};
    mrb_get_args(mrb, "o|o:&", &source, &events, &kwargs, &block);

    if (mrb_nil_p(block)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "a watcher without a block would have nothing to do when it fires");
    }

    const mrb_value wait = mrb_undef_p(kw_values[0]) ? mrb_nil_value() : kw_values[0];
    if (mrb_nil_p(wait)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "a watcher wants timeout: - without a deadline it waits for a wakeup that "
                  "can stop coming, and the run waits with it");
    }
    const mrb_float secs = mrb_as_float(mrb, wait);
    if (!(secs > 0.0)) {
        mrb_raisef(mrb, E_ARGUMENT_ERROR, "timeout: %v is not a time a watcher could wait", wait);
    }

    // An Integer passes through; anything else is asked for fileno.
    // mruby-hiredis hands its event callbacks a bare int.
    const mrb_int descriptor =
        mrb_integer(mrb_type_convert(mrb, source, MRB_TT_INTEGER, MRB_SYM(fileno)));
    if (descriptor < 0) {
        mrb_raisef(mrb, E_ARGUMENT_ERROR, "a watcher needs a descriptor, and this one is %i",
                   descriptor);
    }

    auto *watcher = new WatcherData();
    watcher->descriptor = static_cast<int>(descriptor);
    watcher->events = events_mask_of_symbol(mrb, events);
    watcher->timeout = static_cast<double>(secs);
    mrb_data_init(self, watcher, &watcher_type);

    // The only two the GC has to see.
    mrb_iv_set(mrb, self, MRB_IVSYM(source), source);
    mrb_iv_set(mrb, self, MRB_IVSYM(block), block);
    return self;
}

mrb_value watcher_method_source(mrb_state *mrb, mrb_value self)
{
    return mrb_iv_get(mrb, self, MRB_IVSYM(source));
}

//: () -> Proc
mrb_value watcher_method_block(mrb_state *mrb, mrb_value self)
{
    return mrb_iv_get(mrb, self, MRB_IVSYM(block));
}

//: () -> Symbol
mrb_value watcher_method_events(mrb_state *mrb, mrb_value self)
{
    return events_symbol_of_mask(mrb, watcher_data_or_raise(mrb, self)->events);
}

// IORING_POLL_UPDATE_EVENTS on the armed poll; no re-registration.
//: (Symbol) -> Symbol
mrb_value watcher_method_events_set(mrb_state *mrb, mrb_value self)
{
    mrb_value value;
    mrb_get_args(mrb, "o", &value);
    watcher_data_or_raise(mrb, self)->events = events_mask_of_symbol(mrb, value);
    return value;
}

//: () -> Webmachine::Watcher
mrb_value watcher_method_abort(mrb_state *mrb, mrb_value self)
{
    watcher_data_or_raise(mrb, self)->aborted = true;
    return self;
}

//: () -> (TrueClass | FalseClass)
mrb_value watcher_method_is_aborted(mrb_state *mrb, mrb_value self)
{
    return mrb_bool_value(watcher_data_or_raise(mrb, self)->aborted);
}

//: () -> Float
mrb_value watcher_method_timeout(mrb_state *mrb, mrb_value self)
{
    return mrb_float_value(mrb, watcher_data_or_raise(mrb, self)->timeout);
}

// #30: the peer said nothing for `timeout` seconds. That is the world
// and not a fault of the application, so it arrives at the block as an
// event, exactly as a readable descriptor does. `:timeout` is a value
// that arrives and cannot be ordered, which is why revents and events
// do not share a menu.
//
// The block answers with what it does: it calls abort to give up, or it
// returns and waits again. The reactor reads that answer here.
//: () -> (TrueClass | FalseClass)
mrb_value watcher_method_deadline_passed(mrb_state *mrb, mrb_value self)
{
    watcher_data_or_raise(mrb, self);
    const mrb_value block = mrb_iv_get(mrb, self, MRB_IVSYM(block));
    const mrb_value argv[2] = {mrb_symbol_value(MRB_SYM(timeout)), self};
    mrb_yield_argv(mrb, block, 2, argv);
    // The block can abort, and abort frees nothing - the CDATA is still
    // here, so it is read after the call and not before.
    return mrb_bool_value(!watcher_data_or_raise(mrb, self)->aborted);
}

} // namespace

bool value_is_watcher(mrb_state *mrb, mrb_value value)
{
    return mrb_data_p(value) && DATA_TYPE(value) == &watcher_type;
}

unsigned watcher_events_mask(mrb_value value)
{
    return static_cast<const WatcherData *>(DATA_PTR(value))->events;
}

bool watcher_is_aborted(mrb_value value)
{
    return static_cast<const WatcherData *>(DATA_PTR(value))->aborted;
}

double watcher_timeout(mrb_value value)
{
    const auto *watcher = static_cast<const WatcherData *>(DATA_PTR(value));
    return watcher != nullptr ? watcher->timeout : 0.0;
}

// The block, run under mrb_protect_error: a raise inside it comes back
// as a value and never unwinds through the reactor. A block that raised
// has given up, so the watcher is aborted and the exception is its
// answer. The run that resumes raises it again, and the 500 page and
// the error log carry the message.
namespace
{
struct BlockRun {
    mrb_value block;
    mrb_value argv[2];
};

mrb_value block_call_in_protected_call(mrb_state *mrb, void *user_data)
{
    const BlockRun *block_ask = static_cast<const BlockRun *>(user_data);
    return mrb_yield_argv(mrb, block_ask->block, 2, block_ask->argv);
}

mrb_value block_run(mrb_state *mrb, mrb_value watcher, mrb_value event)
{
    BlockRun b{mrb_iv_get(mrb, watcher, MRB_IVSYM(block)), {event, watcher}};
    mrb_bool raised = FALSE;
    const mrb_value answer = mrb_protect_error(mrb, block_call_in_protected_call, &b, &raised);
    if (raised)
        watcher_data_or_raise(mrb, watcher)->aborted = true;
    return answer;
}
} // namespace

// The deadline, delivered. The answer says whether the wait goes on, and
// `said` takes the block's own value - a watcher that gives up still has
// something to say, and dropping it would make every timeout answer nil.
bool watcher_deadline_passed(mrb_state *mrb, mrb_value value, mrb_value *said)
{
    const mrb_value answer = block_run(mrb, value, mrb_symbol_value(MRB_SYM(timeout)));
    if (said != nullptr)
        *said = answer;
    // The block can abort, and abort frees nothing - the CDATA is still
    // here, so it is read after the call and not before.
    return !watcher_data_or_raise(mrb, value)->aborted;
}

int watcher_fd(mrb_value value)
{
    const auto *watcher = static_cast<const WatcherData *>(DATA_PTR(value));
    return watcher != nullptr ? watcher->descriptor : -1;
}

int watcher_slot(mrb_value value)
{
    const auto *watcher = static_cast<const WatcherData *>(DATA_PTR(value));
    return watcher != nullptr ? watcher->slot : -1;
}

int64_t watcher_deadline_at(mrb_value value)
{
    const WatcherData *const watcher = static_cast<WatcherData *>(DATA_PTR(value));
    return watcher != nullptr ? watcher->deadline_at : 0;
}

void watcher_set_deadline_at(mrb_value value, int64_t deadline_at)
{
    static_cast<WatcherData *>(DATA_PTR(value))->deadline_at = deadline_at;
}

// #30: the round this watcher answers into. Both stay in this file:
// nothing outside it asks a watcher which round it belongs to.
Http1::Conn::Round *watcher_round(mrb_value value)
{
    WatcherData *const watcher = static_cast<WatcherData *>(DATA_PTR(value));
    return watcher != nullptr ? watcher->round : nullptr;
}

void watcher_set_round(mrb_value value, Http1::Conn::Round *round)
{
    static_cast<WatcherData *>(DATA_PTR(value))->round = round;
}

Resource::RunState *watcher_run(mrb_value value)
{
    WatcherData *const watcher = static_cast<WatcherData *>(DATA_PTR(value));
    return watcher != nullptr ? watcher->run_state : nullptr;
}

void watcher_set_run(mrb_value value, Resource::RunState *run_state)
{
    static_cast<WatcherData *>(DATA_PTR(value))->run_state = run_state;
}

int watcher_job(mrb_value value)
{
    const WatcherData *const watcher = static_cast<WatcherData *>(DATA_PTR(value));
    return watcher != nullptr ? watcher->job_number : 0;
}

void watcher_set_job(mrb_value value, int job_number)
{
    static_cast<WatcherData *>(DATA_PTR(value))->job_number = job_number;
}

void watcher_set_slot(mrb_value value, int slot)
{
    static_cast<WatcherData *>(DATA_PTR(value))->slot = slot;
}

void watcher_armed(mrb_value value, struct io_uring *ring, uint64_t poll_tag)
{
    auto *watcher = static_cast<WatcherData *>(DATA_PTR(value));
    watcher->ring = ring;
    watcher->poll_tag = poll_tag;
    watcher->armed = true;
}

// The poll completed, or was removed: nothing is in the ring for it.
void watcher_unarmed(mrb_value value)
{
    auto *watcher = static_cast<WatcherData *>(DATA_PTR(value));
    if (watcher != nullptr)
        watcher->armed = false;
}

uint64_t watcher_armed_tag(mrb_value value)
{
    const auto *watcher = static_cast<const WatcherData *>(DATA_PTR(value));
    return watcher != nullptr && watcher->armed ? watcher->poll_tag : 0;
}

// Empties the CDATA after the caller has cancelled, so watcher_free
// finds nothing.
void watcher_disarm(mrb_value value)
{
    auto *watcher = static_cast<WatcherData *>(DATA_PTR(value));
    if (watcher == nullptr)
        return;
    delete watcher;
    DATA_PTR(value) = nullptr;
    DATA_TYPE(value) = nullptr;
}

mrb_value watcher_source_of(mrb_state *mrb, mrb_value value)
{
    return mrb_iv_get(mrb, value, MRB_IVSYM(source));
}

mrb_value watcher_block_of(mrb_state *mrb, mrb_value value)
{
    return mrb_iv_get(mrb, value, MRB_IVSYM(block));
}

void watcher_init_class(mrb_state *mrb, struct RClass *webmachine_module)
{
    struct RClass *watcher_class =
        mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(Watcher), mrb->object_class);
    MRB_SET_INSTANCE_TT(watcher_class, MRB_TT_CDATA);
    mrb_define_method_id(mrb, watcher_class, MRB_SYM(initialize), watcher_init,
                         MRB_ARGS_ARG(1, 1) | MRB_ARGS_KEY(1, 0) | MRB_ARGS_BLOCK());
    mrb_define_method_id(mrb, watcher_class, MRB_SYM(source), watcher_method_source,
                         MRB_ARGS_NONE());
    mrb_define_method_id(mrb, watcher_class, MRB_SYM(block), watcher_method_block, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, watcher_class, MRB_SYM(events), watcher_method_events,
                         MRB_ARGS_NONE());
    mrb_define_method_id(mrb, watcher_class, MRB_SYM_E(events), watcher_method_events_set,
                         MRB_ARGS_REQ(1));
    mrb_define_method_id(mrb, watcher_class, MRB_SYM(abort), watcher_method_abort, MRB_ARGS_NONE());
    mrb_define_method_id(mrb, watcher_class, MRB_SYM_Q(aborted), watcher_method_is_aborted,
                         MRB_ARGS_NONE());
    mrb_define_method_id(mrb, watcher_class, MRB_SYM(timeout), watcher_method_timeout,
                         MRB_ARGS_NONE());
    mrb_define_method_id(mrb, watcher_class, MRB_SYM(deadline_passed),
                         watcher_method_deadline_passed, MRB_ARGS_NONE());
}

} // namespace webmachine

// #30: the reactor's half. Everything above describes a watcher; this
// is what the server does with one, and it runs on the reactor's thread
// with the reactor's VM - the same rule the compute task follows.
namespace webmachine
{

// The watcher a stopped run left, filed under a slot on the connection.
// The connection's hash is what roots it: the run's own frame is gone
// one line later, and a watcher nobody holds is collected while the
// descriptor is still in the ring.
bool Http1::watch_hand_over(Conn &conn, Conn::Round &round, int park, const Resource &resource)
{
    (void)park;
    if (resource.run.watch_count == 0)
        return false;
    // Every watcher of the round takes a job of its own, after the tasks
    // a worker answers. A connection that can hold no more says so, and
    // the run is answered rather than left waiting.
    for (uint8_t i = 0; i < resource.run.watch_count; i++) {
        const int slot = conn.watchers_add(resource.mrb, resource.run.watch[i]);
        if (slot < 0)
            return false;
        const int job_number = static_cast<int>(round.jobs_owed);
        if (job_number >= Conn::kJobSlots)
            return false;
        watcher_set_job(resource.run.watch[i], job_number);
        watcher_set_round(resource.run.watch[i], &round);
        round.w_slot.at(job_number) = slot;
        round.job_what.at(job_number) = resource.run.watch_what[i];
        round.jobs_owed = static_cast<uint8_t>(job_number + 1);
    }
    return true;
}

// #30: one job of the round answered. The run goes on when the last one
// does - a single watcher ends its round at once.
void Http1::round_answered(Conn::Round &round, int job_number, mrb_value value)
{
    if (job_number < 0 || job_number >= Conn::kJobSlots)
        return;
    round.answer_value.at(job_number) = value;
    if (round.jobs_answered < round.jobs_owed)
        round.jobs_answered++;
    round.answer_ready = round.jobs_owed == 0 || round.jobs_answered >= round.jobs_owed;
}

// #30: every watcher of this stop, told where its run waits. The frame
// says so after the park, because only then does it hold its own state.
void Http1::watch_run_is(Conn &conn, Conn::Round &round, Resource::RunState *run_state)
{
    for (const int slot : round.w_slot) {
        if (slot < 0)
            continue;
        const mrb_value watcher_value = conn.watchers_at(slot);
        if (!mrb_nil_p(watcher_value))
            watcher_set_run(watcher_value, run_state);
    }
}

int Http1::watcher_descriptor(Conn &conn, int slot)
{
    const mrb_value watcher_value = conn.watchers_at(slot);
    return mrb_nil_p(watcher_value) ? -1 : watcher_fd(watcher_value);
}

void Http1::watcher_is_armed(Conn &conn, int slot, struct io_uring *ring, uint64_t poll_tag)
{
    const mrb_value watcher_value = conn.watchers_at(slot);
    if (!mrb_nil_p(watcher_value))
        watcher_armed(watcher_value, ring, poll_tag);
}

void Http1::watcher_is_unarmed(Conn &conn, int slot)
{
    const mrb_value watcher_value = conn.watchers_at(slot);
    if (!mrb_nil_p(watcher_value))
        watcher_unarmed(watcher_value);
}

uint64_t Http1::watcher_poll_tag(Conn &conn, int slot)
{
    const mrb_value watcher_value = conn.watchers_at(slot);
    return mrb_nil_p(watcher_value) ? 0 : watcher_armed_tag(watcher_value);
}

// The wait is over, however it ended. The watcher goes, and with it the
// descriptor's place in the ring.
void Http1::watchers_drop_slot(Conn &conn, int slot)
{
    // The round this watcher answered stops naming it. Which round that
    // is, the watcher itself says - a connection can hold several.
    const mrb_value watcher_value = conn.watchers_at(slot);
    Conn::Round *const round = mrb_nil_p(watcher_value) ? nullptr : watcher_round(watcher_value);
    if (round != nullptr) {
        for (int &at : round->w_slot) {
            if (at == slot)
                at = -1;
        }
    }
    conn.watchers_drop(slot);
}

void Http1::watcher_armed_at(Conn &conn, int slot, int64_t deadline_at)
{
    const mrb_value watcher_value = conn.watchers_at(slot);
    if (!mrb_nil_p(watcher_value))
        watcher_set_deadline_at(watcher_value, deadline_at);
}

int64_t Http1::watchers_soonest_deadline(Conn &conn)
{
    int64_t soonest = 0;
    for (int i = 0; i < static_cast<int>(kMaxWatchers); i++) {
        const mrb_value watcher_value = conn.watchers_at(i);
        if (mrb_nil_p(watcher_value))
            continue;
        const int64_t deadline_at = watcher_deadline_at(watcher_value);
        if (deadline_at != 0 && (soonest == 0 || deadline_at < soonest))
            soonest = deadline_at;
    }
    return soonest;
}

size_t Http1::watchers_over_deadline(Conn &conn, int64_t now_seconds, int *slots, size_t slots_max)
{
    size_t found = 0;
    for (int i = 0; i < static_cast<int>(kMaxWatchers) && found < slots_max; i++) {
        const mrb_value watcher_value = conn.watchers_at(i);
        if (mrb_nil_p(watcher_value))
            continue;
        const int64_t deadline_at = watcher_deadline_at(watcher_value);
        if (deadline_at == 0 || deadline_at >= now_seconds)
            continue;
        watcher_set_deadline_at(watcher_value, 0);
        slots[found++] = i;
    }
    return found;
}

unsigned Http1::watcher_mask(Conn &conn, int slot)
{
    const mrb_value watcher_value = conn.watchers_at(slot);
    if (mrb_nil_p(watcher_value))
        return 0;
    return watcher_events_mask(watcher_value);
}

double Http1::watcher_quiet_seconds(Conn &conn, int slot)
{
    const mrb_value watcher_value = conn.watchers_at(slot);
    if (mrb_nil_p(watcher_value))
        return 0.0;
    return watcher_timeout(watcher_value);
}

// #30: the run this watcher belongs to, for as long as its block runs.
// The block is written inside the resource, so `response` and `request`
// are already in its scope - what they need is the walk's state, and
// that waits on the connection while the run is parked.
//
// It is lent, not copied: the block writes a header or keeps a value,
// and the run that resumes finds it. The reactor answers no other
// connection in the middle of a block, so one run at a time holds it.
struct RunLent {
    const Resource *resource = nullptr;
    Resource::RunState *from = nullptr;
    RunLent(const Resource *round, Resource::RunState *parked)
    {
        if (round == nullptr || parked == nullptr)
            return;
        resource = round;
        from = parked;
        // What the last request on this route left here. The move below
        // takes it away and the destructor zeroes what is left, so the
        // root it holds would never be given back - one object pinned for
        // the life of the process, per watcher event.
        resource_forget_userdata(*resource);
        resource->run = std::move(*from);
        request_bind(resource->run.req);
        response_bind(resource);
    }
    ~RunLent()
    {
        if (resource == nullptr)
            return;
        request_bind(nullptr);
        response_bind(nullptr);
        *from = std::move(resource->run);
        resource->run = Resource::RunState{};
    }
    RunLent(const RunLent &) = delete;
    RunLent &operator=(const RunLent &) = delete;
};

Http1::WatchStep Http1::watcher_event(Conn &conn, int slot, unsigned revents)
{
    const mrb_value watcher_value = conn.watchers_at(slot);
    if (mrb_nil_p(watcher_value))
        return WatchStep::kDone;
    mrb_state *const mrb = conn.w_mrb;
    const int arena = mrb_gc_arena_save(mrb);
    const unsigned before = watcher_events_mask(watcher_value);
    // #30: the block belongs to a run that is parked, and `response[:key]`
    // is that run's scratch. It lives on the connection for this reason -
    // the run's own state travelled with the frame.
    mrb_value said;
    {
        const Conn::Round *const owned = watcher_round(watcher_value);
        const RunLent lent(owned != nullptr ? owned->job_res : nullptr, watcher_run(watcher_value));
        said = block_run(mrb, watcher_value, events_symbol_of_mask(mrb, revents));
    }
    if (watcher_is_aborted(watcher_value)) {
        // Root it first. The block's answer is held by the arena and by
        // nothing else; restoring the arena before registering it hands the
        // collector a value the run is about to read.
        Conn::Round *const round = watcher_round(watcher_value);
        if (round != nullptr)
            round_answered(*round, watcher_job(watcher_value), said);
        mrb_gc_register(mrb, said);
        mrb_gc_arena_restore(mrb, arena);
        return WatchStep::kDone;
    }
    mrb_gc_arena_restore(mrb, arena);
    return watcher_events_mask(watcher_value) != before ? WatchStep::kRearm : WatchStep::kWait;
}

Http1::WatchStep Http1::watcher_deadline(Conn &conn, int slot)
{
    const mrb_value watcher_value = conn.watchers_at(slot);
    if (mrb_nil_p(watcher_value))
        return WatchStep::kDone;
    mrb_state *const mrb = conn.w_mrb;
    const int arena = mrb_gc_arena_save(mrb);
    const unsigned before = watcher_events_mask(watcher_value);
    // The block hears :timeout and answers whether the wait goes on. A
    // watcher over its deadline is usually the world - the peer said
    // nothing - and that is a fact the application has to learn, not a
    // failure of its own.
    mrb_value said = mrb_nil_value();
    bool again;
    {
        const Conn::Round *const owned = watcher_round(watcher_value);
        const RunLent lent(owned != nullptr ? owned->job_res : nullptr, watcher_run(watcher_value));
        again = watcher_deadline_passed(mrb, watcher_value, &said);
    }
    if (!again) {
        Conn::Round *const round = watcher_round(watcher_value);
        if (round != nullptr)
            round_answered(*round, watcher_job(watcher_value), said);
        mrb_gc_register(mrb, said);
        mrb_gc_arena_restore(mrb, arena);
        return WatchStep::kDone;
    }
    mrb_gc_arena_restore(mrb, arena);
    return watcher_events_mask(watcher_value) != before ? WatchStep::kRearm : WatchStep::kWait;
}

} // namespace webmachine
