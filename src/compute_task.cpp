//
// #80: the compute pool that answers a ComputeTask.
//
// A compute task is asked once and answered once, and a thread answers
// it. The work is arithmetic, not waiting: argon2 takes about 40 ms,
// and the reactor's core would stop for that long.
//
// The queue is io_uring's own. A worker blocks on a ring of its own,
// the reactor posts work into it with IORING_OP_MSG_RING, and the
// answer comes back the same way - an ordinary completion, like a
// disk's.
//
// Watcher is this file's sibling: it answers the same question again,
// and it watches a descriptor.
#include "http1.hpp"
#include "ruby_value.hpp"
#include "ring_setup.hpp"

#include <liburing.h>

#include <mruby/array.h>
#include <mruby/cbor.h>
#include <mruby/irep.h>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/proc_irep_ext.h>
#include <mruby/string.h>
#include <mruby/variable.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

// The thread sanitizer models pthreads, and this file hands a slot from
// one thread to another through io_uring. The sanitizer sees a write on
// one thread and a read on another with nothing between them, and calls
// it a race. The order is real: the sender writes the slot, then makes a
// syscall that gives the message to the kernel, and the reader takes it
// out of the kernel and only then reads the slot.
//
// The two calls below say that to the sanitizer, and to nobody else.
// Without -fsanitize=thread they compile to nothing.
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define WM_TSAN_ON 1
#endif
#endif
#if defined(WM_TSAN_ON)
extern "C" void __tsan_acquire(void *addr);
extern "C" void __tsan_release(void *addr);
// The slot goes to the other thread after this line.
#define WM_HANDOVER_SEND(p) __tsan_release(p)
// The slot came from the other thread before this line.
#define WM_HANDOVER_TAKE(p) __tsan_acquire(p)
#else
#define WM_HANDOVER_SEND(p) ((void)(p))
#define WM_HANDOVER_TAKE(p) ((void)(p))
#endif

namespace webmachine
{
namespace
{

// What crosses MSG_RING is user_data (64 bits) and a 32-bit result, and
// nothing else - no payload. So a job is named by its slot, and the slot
// carries the work. The slots are allocated once; a compute task never
// allocates while the server is answering.
struct Slot {
    // Which declared callback, by its place in the registry.
    unsigned code_id = 0;
    // The argument as CBOR on the way in, the answer as CBOR on the way
    // out. Bytes both ways, because an mrb_value belongs to one VM.
    std::string arg;
    std::string out_ask;
    // #30: response.userdata, in and out. The worker reads what the run
    // put there and can leave something else - the reactor only looks
    // when the bytes came back different.
    std::string user_in;
    std::string user_out;
    bool user_changed = false;
    // Seconds of execution. The reactor arms a timeout for this and
    // interrupts the worker's VM when it passes.
    double deadline = 0.0;
    // Whether the reactor asked this job to stop is one atomic per slot,
    // and it lives beside the slots rather than inside one: an atomic
    // cannot be copied, and a vector of Slot has to be able to grow.
    bool raised = false;
    // The task was ended because it passed its deadline. A different
    // answer from a raise: the author's number was wrong, and a retry
    // would take just as long.
    bool over_deadline = false;
    // What the worker raised, as CBOR (mrblib registers Exception), and
    // the step of the job it raised in. The reactor decodes the same
    // exception in its own VM.
    std::string exception;
    std::string step;
    // Which worker ran it, as the name its thread carries, and as the
    // number the pool addresses it by.
    std::string worker_name;
    unsigned worker = 0;
    // Which taking of this slot: a deadline names a slot and this, so a
    // timer armed for a job that answered finds a number that moved on.
    uint16_t gen = 0;
    // The reactor's own tag for this compute task: what its completion will
    // carry, so the reactor knows whose answer arrived. The pool never
    // looks inside it.
    uint64_t answer = 0;
    bool busy = false;
};

// user_data on the worker's ring. Not a webmachine tag - this side is
// the pool's own, and the only two things it says are "here is slot i"
// and "stop".
constexpr uint64_t kStopJob = ~static_cast<uint64_t>(0);
// MSG_RING answers twice: the target ring gets the message, and the
// sender's own ring gets a completion for having sent it. A worker
// therefore sees its own answer come back, and anything that is not a
// job index has to be stepped over rather than used as one.
constexpr uint64_t kSent = ~static_cast<uint64_t>(1);

// The declared blocks of this process. The reactor appends to it - once
// per block, the first time one is seen - and workers read it. Both
// under one mutex, which is only ever taken on a cold path: the
// reactor takes it once per block for the life of the process, and a
// worker takes it once per block it has not loaded yet.
struct Registry {
    std::mutex mtx;
    std::vector<ComputeTaskCode> codes;
    // Which irep is already interned. The same code at the same place
    // carries the same irep, so this is what makes "dump once" true.
    std::unordered_map<const void *, unsigned> by_irep;
};

Registry &registry_of_this_vm()
{
    static Registry reg;
    return reg;
}

} // namespace

// #80: Webmachine::ComputeTask. It holds three things and does
// nothing: the block a worker will run, the arguments it is called
// with, and how long it may take. It is built on the reactor by a
// callback, and read by the reactor right after.
//
// It is deliberately not a thing that runs. A ComputeTask that could start
// its own work would be a second way to reach a worker, and there is
// one way: a flow node the resource declared.
namespace
{

mrb_value compute_task_initialize(mrb_state *mrb, mrb_value self)
{
    // mruby checks keywords against a declared table, and a null table
    // means "this call takes none". max_runtime is declared here, and
    // declared optional so the refusal below is ours: mruby's own would
    // say the keyword is missing, and not why a deadline is owed.
    const mrb_sym kw_names[] = {MRB_SYM(max_runtime)};
    // Initialised, because mrb_get_args leaves a key that was not given
    // untouched: an uninitialised slot would be read as whatever the
    // stack held.
    mrb_value kw_values[1] = {mrb_undef_value()};
    const mrb_kwargs kwargs = {1, 0, kw_names, kw_values, nullptr};
    const mrb_value *argv = nullptr;
    mrb_int argc = 0;
    mrb_value blk = mrb_nil_value();
    mrb_get_args(mrb, "*:&", &argv, &argc, &kwargs, &blk);
    if (!mrb_proc_p(blk)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "Webmachine::ComputeTask wants the block a worker runs, and got none");
    }
    const mrb_value run = mrb_undef_p(kw_values[0]) ? mrb_nil_value() : kw_values[0];
    if (mrb_nil_p(run)) {
        mrb_raise(mrb, E_ARGUMENT_ERROR,
                  "Webmachine::ComputeTask wants max_runtime: - work with no deadline cannot "
                  "be admitted, because admission is arithmetic over one");
    }
    const mrb_float secs = mrb_as_float(mrb, run);
    if (!(secs > 0.0)) {
        mrb_raisef(mrb, E_ARGUMENT_ERROR, "max_runtime: %v is not a time a job could take", run);
    }
    mrb_iv_set(mrb, self, MRB_IVSYM(block), blk);
    mrb_iv_set(mrb, self, MRB_IVSYM(args), mrb_ary_new_from_values(mrb, argc, argv));
    mrb_iv_set(mrb, self, MRB_IVSYM(max_runtime), mrb_float_value(mrb, secs));
    return self;
}

} // namespace

// #80: Webmachine::Workers::Registry. What a worker keeps between
// jobs, and the only way it can keep anything: a block carries no
// environment, so a database or a connection has to be built inside
// the worker's own VM.
//
// The main VM registers a proc. Every worker runs it once when it
// opens, and keeps what it answers under the same key. The key travels
// as a string, because an mrb_sym is a number one VM handed out.
namespace
{

std::mutex &worker_builds_mutex()
{
    static std::mutex m;
    return m;
}

std::vector<WorkerBuild> &worker_builds_list()
{
    static std::vector<WorkerBuild> value;
    return value;
}

bool builds_closed_ = false;

// The table a worker built for itself, under the same keys. Read by a
// block through Registry[], and by nothing else.
mrb_value worker_table_of_this_vm(mrb_state *mrb)
{
    struct RClass *const workers =
        mrb_module_get_under_id(mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(Workers));
    return mrb_iv_get(mrb, mrb_obj_value(workers), MRB_IVSYM(built));
}

// Registry[key] - inside a worker, this worker's own value.
mrb_value registry_get(mrb_state *mrb, mrb_value self)
{
    (void)self;
    mrb_value key_name;
    mrb_get_args(mrb, "o", &key_name);
    const mrb_value table = worker_table_of_this_vm(mrb);
    if (!mrb_hash_p(table)) {
        mrb_raise(mrb, E_WM_ERROR(mrb),
                  "Webmachine::Workers::Registry answers inside a worker only - the values are "
                  "built there, one per worker, and this VM has none");
    }
    return mrb_hash_get(mrb, table, key_name);
}

// Registry[key] = proc - in the main VM, at startup.
mrb_value registry_set(mrb_state *mrb, mrb_value self)
{
    (void)self;
    mrb_value key_name;
    mrb_value block;
    mrb_get_args(mrb, "oo", &key_name, &block);
    if (!mrb_proc_p(block)) {
        mrb_raise(mrb, E_WM_ERROR(mrb),
                  "Webmachine::Workers::Registry takes a proc that builds the value, not the "
                  "value - an object cannot cross into a worker, and how to build one can");
    }
    const mrb_value name = mrb_obj_as_string(mrb, key_name);
    if (!worker_build_register(mrb, std::string(ruby_string_bytes(name)), block)) {
        if (mrb->exc != nullptr)
            rethrow(mrb);
        mrb_raisef(mrb, E_WM_ERROR(mrb),
                   "Webmachine::Workers::Registry[%v] was set after the workers started - they "
                   "were built already, so this key exists in none of them",
                   key_name);
    }
    return block;
}

} // namespace

bool worker_build_register(mrb_state *mrb, std::string key_name, mrb_value block)
{
    std::lock_guard<std::mutex> hold(worker_builds_mutex());
    if (builds_closed_)
        return false;
    // A failed dump leaves its exception in place, and registry_set raises it.
    const mrb_value bytes = mrb_proc_to_irep(mrb, mrb_proc_ptr(block));
    if (mrb->exc != nullptr || !mrb_string_p(bytes))
        return false;
    WorkerBuild build;
    build.key = std::move(key_name);
    build.irep.assign(ruby_string_bytes(bytes));
    worker_builds_list().push_back(std::move(build));
    return true;
}

const std::vector<WorkerBuild> &worker_builds()
{
    return worker_builds_list();
}

void worker_builds_close()
{
    std::lock_guard<std::mutex> hold(worker_builds_mutex());
    builds_closed_ = true;
}

void compute_task_init_class(mrb_state *mrb, struct RClass *webmachine_module)
{
    struct RClass *const task =
        mrb_define_class_under_id(mrb, webmachine_module, MRB_SYM(ComputeTask), mrb->object_class);
    mrb_define_method_id(mrb, task, MRB_SYM(initialize), compute_task_initialize,
                         MRB_ARGS_ANY() | MRB_ARGS_BLOCK());

    struct RClass *workers = mrb_define_module_under_id(mrb, webmachine_module, MRB_SYM(Workers));
    struct RClass *registry = mrb_define_module_under_id(mrb, workers, MRB_SYM(Registry));
    mrb_define_class_method_id(mrb, registry, MRB_OPSYM(aref), registry_get, MRB_ARGS_REQ(1));
    mrb_define_class_method_id(mrb, registry, MRB_OPSYM(aset), registry_set, MRB_ARGS_REQ(2));
}

bool compute_task_read_from_value(mrb_state *mrb, mrb_value value, ComputeTaskAsk *out_ask)
{
    // The class is looked up in the VM that holds v. Every VM in this
    // process runs the gem init, workers included, so a pointer kept at
    // file scope would name whichever VM opened last.
    struct RClass *const klass = mrb_class_get_under_id(
        mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(ComputeTask));
    if (!mrb_obj_is_kind_of(mrb, value, klass))
        return false;
    out_ask->block = mrb_iv_get(mrb, value, MRB_IVSYM(block));
    out_ask->args = mrb_iv_get(mrb, value, MRB_IVSYM(args));
    out_ask->max_runtime = mrb_as_float(mrb, mrb_iv_get(mrb, value, MRB_IVSYM(max_runtime)));
    return true;
}

// #80: the way back. Only this thread may build a value in the
// reactor's VM, so the decode happens here and nowhere else.
void Http1::compute_task_answered(Conn &conn, int park, int slot, const ComputeAnswer &answered)
{
    Conn::Round *const round = conn.park_at(park);
    if (round == nullptr || slot < 0 || slot >= Conn::kJobSlots)
        return;
    // The round goes on when the last job of it answered. One job is the
    // ordinary case and ends the round at once.
    if (round->jobs_answered < round->jobs_owed)
        round->jobs_answered++;
    round->answer_ready = round->jobs_answered >= round->jobs_owed;
    round->answer_value.at(slot) = mrb_nil_value();
    round->compute_task_over_deadline = answered.over_deadline;
    // A raise and a deadline are told apart, because the answers are not
    // the same one: 503 says come back, 500 says nothing will change.
    round->compute_task_raised = answered.raised && !answered.over_deadline;
    const Resource *const resource = round->job_res;
    if (resource == nullptr || answered.raised)
        return;
    mrb_state *const mrb = resource->mrb;
    // What a decode leaves behind. The string the bytes arrive in and the
    // value they become are both the arena's, and this arena grows: every
    // answer left three entries in it that no collection could ever take,
    // for the life of the process. What the round keeps is registered, so
    // it outlives the restore.
    const int arena = mrb_gc_arena_save(mrb);
    // #30: response.userdata, when the worker left something else there.
    round->user_have.at(slot) = false;
    if (answered.user_changed && !answered.user_bytes.empty()) {
        const mrb_value decoded = mrb_cbor_decode_fast(
            mrb, mrb_str_new(mrb, answered.user_bytes.data(), answered.user_bytes.size()));
        if (mrb->exc != nullptr) {
            // The exception is the round's answer: the run raises it as its
            // own, and nothing here rewrites what the VM said.
            round->answer_value.at(slot) = mrb_obj_value(mrb->exc);
            mrb_gc_register(mrb, round->answer_value.at(slot));
            mrb->exc = nullptr;
            mrb_gc_arena_restore(mrb, arena);
            return;
        } else {
            round->user_value.at(slot) = decoded;
            mrb_gc_register(mrb, decoded);
            round->user_have.at(slot) = true;
        }
    }
    if (answered.bytes.empty()) {
        mrb_gc_arena_restore(mrb, arena);
        return;
    }
    const mrb_value value =
        mrb_cbor_decode_fast(mrb, mrb_str_new(mrb, answered.bytes.data(), answered.bytes.size()));
    if (mrb->exc != nullptr) {
        round->answer_value.at(slot) = mrb_obj_value(mrb->exc);
        mrb_gc_register(mrb, round->answer_value.at(slot));
        mrb->exc = nullptr;
        mrb_gc_arena_restore(mrb, arena);
        return;
    }
    round->answer_value.at(slot) = value;
    mrb_gc_register(mrb, value);
    mrb_gc_arena_restore(mrb, arena);
}

// #80: the crossing, done by the frame at the stop. It runs on the
// reactor's thread with the reactor's VM live, which is the only place
// either half is possible: the block is interned to an id, and the
// arguments are encoded to CBOR.
//
// It happens here and not when the reactor arms the work, because the
// frame takes the run's state with it one line later - res.run belongs
// to the route, and a second request would write over it.
//
// Both halves can fail: a block mruby cannot dump, or a value CBOR
// cannot carry. Either is the application's fault and is raised with
// its reason, so the 500 page and the error log say what did not cross.
namespace
{
// The trampoline mrb_protect_error takes. It carries the four arguments
// of the crossing and the answer it gives.
struct CrossAsk {
    Http1 *server;
    Http1::Conn *conn;
    Http1::Conn::Round *round;
    int park;
    const Resource *resource;
    bool crossed;
};
mrb_value cross_in_protected_call(mrb_state *, void *user_data)
{
    auto *const cross_ask = static_cast<CrossAsk *>(user_data);
    cross_ask->crossed = cross_ask->server->compute_task_cross(
        *cross_ask->conn, *cross_ask->round, cross_ask->park, *cross_ask->resource);
    return mrb_nil_value();
}
} // namespace

bool Http1::compute_task_hand_over(Conn &conn, Conn::Round &round, int park,
                                   const Resource &resource)
{
    mrb_state *const mrb = resource.mrb;
    CrossAsk ask{this, &conn, &round, park, &resource, false};
    mrb_bool raised = FALSE;
    const mrb_value thrown = mrb_protect_error(mrb, cross_in_protected_call, &ask, &raised);
    if (mrb_likely(raised == FALSE))
        return ask.crossed;
    // Nothing crossed, so nothing is owed an answer. The round is refused
    // with a 500 and the error log carries what did not cross - the same
    // place a worker's own raise is written.
    for (Conn::Round::Job &j : round.job)
        j.waiting = false;
    round.jobs_owed = 0;
    round.jobs_answered = 0;
    round.compute_task_not_crossed = true;
    round.answer_ready = true;
    if (mrb_exception_p(thrown))
        mrb->exc = mrb_obj_ptr(thrown);
    fault_report(error_log(), mrb, {{}, "the crossing into a worker", {}, {}, 500});
    return false;
}

bool Http1::compute_task_cross(Conn &conn, Conn::Round &round, int park, const Resource &resource)
{
    for (Conn::Round::Job &j : round.job)
        j.waiting = false;
    round.jobs_owed = 0;
    round.jobs_answered = 0;
    round.job_res = &resource;
    if (resource.run.compute_task_count == 0)
        return false;

    mrb_state *const mrb = resource.mrb;
    // #30: response.userdata crosses with the job. Undef is "the run put
    // nothing there", and then nothing is encoded and nothing is sent.
    std::string user;
    if (!mrb_undef_p(resource.run.userdata) && !mrb_nil_p(resource.run.userdata)) {
        const int uai = mrb_gc_arena_save(mrb);
        const mrb_value encoded = mrb_cbor_encode_fast(mrb, resource.run.userdata);
        if (mrb->exc != nullptr || !mrb_string_p(encoded)) {
            mrb_gc_arena_restore(mrb, uai);
            if (mrb->exc != nullptr)
                rethrow(mrb);
            mrb_raise(
                mrb, E_WM_ERROR(mrb),
                "response.userdata cannot cross to a worker - CBOR carries what a compute task "
                "takes with it, and this is not one of those");
            WM_UNREACHABLE();
        }
        user.assign(ruby_string_bytes(encoded));
        mrb_gc_arena_restore(mrb, uai);
    }
    // Every task of the round crosses here, or none does. A round that
    // loses one job would wait for an answer nobody owes.
    for (uint8_t i = 0; i < resource.run.compute_task_count; i++) {
        const Resource::RunState::HeldTask &task = resource.run.compute_task[i];
        const int arena = mrb_gc_arena_save(mrb);
        const unsigned task_id = compute_task_intern(mrb, task.block, task.deadline);
        if (task_id == kComputeTaskNoCode) {
            mrb_gc_arena_restore(mrb, arena);
            for (Conn::Round::Job &j : round.job)
                j.waiting = false;
            round.jobs_owed = 0;
            if (mrb->exc != nullptr)
                rethrow(mrb);
            mrb_raise(mrb, E_WM_ERROR(mrb),
                      "a compute task's block cannot cross to a worker - mruby could not dump it");
            WM_UNREACHABLE();
        }
        const mrb_value encoded = mrb_cbor_encode_fast(mrb, task.args);
        if (mrb->exc != nullptr || !mrb_string_p(encoded)) {
            mrb_gc_arena_restore(mrb, arena);
            for (Conn::Round::Job &j : round.job)
                j.waiting = false;
            round.jobs_owed = 0;
            if (mrb->exc != nullptr)
                rethrow(mrb);
            mrb_raisef(mrb, E_WM_ERROR(mrb),
                       "a compute task's arguments cannot cross to a worker - CBOR carries what a "
                       "task takes with it, and %v is not one of those",
                       task.args);
            WM_UNREACHABLE();
        }
        Conn::Round::Job &j = round.job.at(i);
        j.bytes.assign(ruby_string_bytes(encoded));
        mrb_gc_arena_restore(mrb, arena);
        j.user_bytes = user;
        j.code = task_id;
        j.deadline = task.deadline;
        round.job_what.at(i) = task.what;
        j.waiting = true;
        round.jobs_owed = static_cast<uint8_t>(i + 1);
    }
    round.jobs_answered = 0;
    // The reactor arms what this stop handed over. It finds the run by
    // its park slot, which is what the completion tag will carry back.
    conn.park_wants_arming(park);
    // A new round, so nothing of the last one speaks for it.
    round.compute_task_full = false;
    round.compute_task_over_deadline = false;
    round.compute_task_raised = false;
    return true;
}

unsigned compute_task_intern(mrb_state *mrb, mrb_value block, double max_runtime)
{
    struct RProc *const proc = mrb_proc_ptr(block);
    const void *const key_name = proc->body.irep;
    Registry &reg = registry_of_this_vm();
    std::lock_guard<std::mutex> hold(reg.mtx);
    const auto seen = reg.by_irep.find(key_name);
    if (seen != reg.by_irep.end())
        return seen->second;

    ComputeTaskCode code;
    // A failed dump leaves the exception in place: the caller raises it.
    const mrb_value bytes = mrb_proc_to_irep(mrb, proc);
    if (mrb->exc != nullptr || !mrb_string_p(bytes))
        return kComputeTaskNoCode;
    code.irep.assign(ruby_string_bytes(bytes));
    code.max_runtime = max_runtime;
    reg.codes.push_back(std::move(code));
    const unsigned task_id = static_cast<unsigned>(reg.codes.size() - 1);
    // The key is the address of the irep, and the registry holds it for the
    // life of the process. So the irep has to live that long as well: a
    // freed one would let the next irep land on the same address and answer
    // to this entry. One reference, never given back.
    mrb_irep_incref(mrb, const_cast<struct mrb_irep *>(proc->body.irep));
    reg.by_irep.emplace(key_name, task_id);
    return task_id;
}

bool compute_task_code_of(unsigned task_id, std::string *irep, double *max_runtime)
{
    Registry &reg = registry_of_this_vm();
    std::lock_guard<std::mutex> hold(reg.mtx);
    if (task_id >= reg.codes.size())
        return false;
    *irep = reg.codes[task_id].irep;
    *max_runtime = reg.codes[task_id].max_runtime;
    return true;
}

struct ComputePool::Impl {
    std::vector<struct io_uring> rings;
    std::vector<std::thread> threads;
    std::vector<Slot> slots;
    // Each worker's VM, published by the worker itself once mrb_open
    // answered. The reactor reads it to call mrb_vm_interrupt, which
    // writes one word and reads none - the only thing one thread may do
    // to another thread's mrb_state.
    std::vector<std::atomic<mrb_state *>> vms;
    // Which job each worker is on. The reactor arms a timeout per job and
    // the number tells a late timeout from a live one: an answer bumps it,
    // so a timeout for a job that already answered interrupts nothing.
    // The slot each worker runs right now, or the slot count for none.
    std::vector<std::atomic<unsigned>> running;
    // One per slot: the reactor sets it before it interrupts, the worker
    // reads it after its block returned.
    std::vector<std::atomic<bool>> asked_stop;
    // Round-robin, and that is enough: every job in this pool is a
    // password hash with fixed m and t, so they all cost the same. A
    // shortest-queue choice would compute an answer the caller already
    // knows - the counts would differ by at most one.
    unsigned next = 0;
    // The pool starts one worker at a time. A worker opens its own fresh
    // VM, and the gems in this build write file-scope statics while they
    // initialise: a second mrb_open that runs beside the first one writes
    // what a running VM reads. So the starter waits here until worker A
    // says its VM stands, and only then makes worker B.
    std::mutex boot_lock;
    std::condition_variable boot_ready;
    unsigned booted = 0;
    struct io_uring *home = nullptr;
    bool up = false;
};

// One worker's VM, and the declared callbacks loaded into it. Each
// worker builds this once at start, so a request never pays for a
// mrb_open or for loading an irep.
//
// The VM is this thread's alone. mruby is not thread-safe, and that is
// not a limit here: nothing of the reactor's VM is ever touched from a
// worker, and nothing of a worker's VM ever leaves it. Only bytes
// cross, both ways.

// #30: `response` inside a worker. The block is written in a resource,
// where `response` is a method of the run - so the worker VM answers
// the same word with its own object, and the block needs no change.
mrb_value worker_response(mrb_state *mrb, mrb_value self)
{
    (void)self;
    mrb_value webmachine_module =
        mrb_const_get(mrb, mrb_obj_value(mrb->object_class), MRB_SYM(Webmachine));
    webmachine_module = mrb_const_get(mrb, webmachine_module, MRB_SYM(Workers));
    return mrb_funcall_argv(mrb, webmachine_module, MRB_SYM(response), 0, nullptr);
}

struct WorkerVm {
    mrb_state *mrb = nullptr;
    std::vector<mrb_value> procs;
    // Webmachine::Workers, which holds `wrap`: a block and its arguments
    // made into a proc that takes none. mrblib carries it, so mrbc
    // translated it at build time and every VM that opens has it. A ship
    // build has no mruby-compiler, so nothing may be translated here.
    mrb_value workers = {};
    // Webmachine::Workers.response, held for the life of the VM.
    mrb_value response = {};
    bool open()
    {
        mrb = open_vm_or_say("webmachine compute worker");
        if (mrb == nullptr)
            return false;
        // Webmachine::Workers, looked up once. A module is rooted by the
        // constant that names it, so nothing else has to hold it.
        workers = mrb_const_get(mrb, mrb_obj_value(mrb->object_class), MRB_SYM(Webmachine));
        if (mrb->exc == nullptr)
            workers = mrb_const_get(mrb, workers, MRB_SYM(Workers));
        if (mrb->exc != nullptr) {
            std::fprintf(stderr,
                         "webmachine compute worker: Webmachine::Workers is not in this VM\n");
            mrb_print_error(mrb);
            mrb->exc = nullptr;
            return false;
        }
        // Every self in this VM answers `response` - the block's own self is
        // whatever mruby gave the re-loaded proc, and it must not matter.
        mrb_define_method_id(mrb, mrb->object_class, MRB_SYM(response), worker_response,
                             MRB_ARGS_NONE());
        response = mrb_funcall_argv(mrb, workers, MRB_SYM(response), 0, nullptr);
        if (mrb->exc != nullptr) {
            std::fprintf(stderr,
                         "webmachine compute worker: Webmachine::Workers.response raised\n");
            mrb_print_error(mrb);
            mrb->exc = nullptr;
            return false;
        }
        mrb_gc_register(mrb, response);
        return build_registry();
    }

    // What the application registered, built here, once, in this VM. A
    // handle belongs to the VM that opened it, so every worker opens its
    // own - and reads it back without a lock, because nothing is shared.
    //
    // A build that fails takes the worker with it. That is the same rule
    // every other startup failure follows: a path that cannot be opened
    // is said at the start, never on the first request.
    // One key of the registry, as the body mrb_protect_error runs.
    struct BuildOne {
        const WorkerBuild *build;
        mrb_value table;
    };
    static mrb_value build_one(mrb_state *mrb, void *user_data)
    {
        BuildOne &build = *static_cast<BuildOne *>(user_data);
        const mrb_value proc =
            mrb_proc_from_irep(mrb, build.build->irep.data(), build.build->irep.size());
        if (!mrb_proc_p(proc))
            mrb_raise(mrb, E_WM_ERROR(mrb), "the build proc could not be loaded");
        const mrb_value value = mrb_yield_argv(mrb, proc, 0, nullptr);
        mrb_hash_set(
            mrb, build.table,
            mrb_symbol_value(mrb_intern(mrb, build.build->key.data(), build.build->key.size())),
            value);
        return mrb_nil_value();
    }
    bool build_registry()
    {
        const mrb_value table = mrb_hash_new(mrb);
        struct RClass *const workers_mod = mrb_module_get_under_id(
            mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(Workers));
        mrb_iv_set(mrb, mrb_obj_value(workers_mod), MRB_IVSYM(built), table);
        for (const WorkerBuild &b : worker_builds()) {
            BuildOne one{&b, table};
            mrb_bool raised = FALSE;
            const mrb_value thrown = mrb_protect_error(mrb, build_one, &one, &raised);
            if (raised) {
                std::fprintf(stderr, "webmachine compute worker: Registry[%s] could not be built\n",
                             b.key.c_str());
                if (mrb_exception_p(thrown)) {
                    mrb->exc = mrb_obj_ptr(thrown);
                    mrb_print_error(mrb);
                    mrb->exc = nullptr;
                }
                return false;
            }
        }
        return true;
    }

    // The block behind an id, loaded the first time this worker meets it
    // and kept for the life of the VM. A request pays this once per block
    // per worker, never per call.
    mrb_value proc_for(unsigned task_id)
    {
        if (task_id < procs.size() && !mrb_nil_p(procs[task_id]))
            return procs[task_id];
        std::string irep;
        double deadline = 0.0;
        if (!compute_task_code_of(task_id, &irep, &deadline))
            return mrb_nil_value();
        const mrb_value raw = mrb_proc_from_irep(mrb, irep.data(), irep.size());
        if (mrb->exc != nullptr || !mrb_proc_p(raw)) {
            std::fprintf(stderr, "webmachine compute worker: compute task %u could not be loaded\n",
                         task_id);
            if (mrb->exc != nullptr)
                mrb_print_error(mrb);
            mrb->exc = nullptr;
            return mrb_nil_value();
        }
        if (task_id >= procs.size())
            procs.resize(task_id + 1, mrb_nil_value());
        procs[task_id] = raw;
        mrb_gc_register(mrb, raw);
        return raw;
    }

    void close()
    {
        if (mrb == nullptr)
            return;
        mrb_close(mrb);
        mrb = nullptr;
    }
};

void fault_report(Logger *logger, mrb_state *mrb, const ComputeFault &fault)
{
    const int arena = mrb_gc_arena_save(mrb);
    if (!fault.exception.empty()) {
        const mrb_value entry = mrb_cbor_decode_fast(
            mrb, mrb_str_new(mrb, fault.exception.data(), fault.exception.size()));
        if (mrb->exc == nullptr && mrb_exception_p(entry))
            mrb->exc = mrb_obj_ptr(entry);
    }
    std::string where(fault.step);
    if (!fault.worker_name.empty())
        where.append(" (").append(fault.worker_name).append(")");
    if (mrb->exc != nullptr) {
        if (logger != nullptr && logger->enabled) {
            ErrFacts facts;
            std::string backtrace;
            facts.status_code = fault.status;
            facts.peer = fault.peer.data();
            facts.peer_len = fault.peer.size();
            facts.steering = where.data();
            facts.steering_len = where.size();
            exception_facts(mrb, {facts, backtrace});
            if (facts.exception_class != nullptr)
                log_error(*logger, facts);
        }
        if (kDebugBuild)
            mrb_print_error(mrb);
        mrb->exc = nullptr;
    } else if (logger != nullptr && logger->enabled) {
        // Nothing decodable crossed: the step alone is the record.
        log_internal_error(*logger, {fault.peer, {}, where, fault.status});
    }
    mrb_gc_arena_restore(mrb, arena);
}

// One failure inside a worker: the exception itself, as CBOR, and the
// step of the job it happened in. The exception is cleared here and
// nowhere else: a VM that keeps one raises it again on the next job,
// and the next job belongs to another request.
void slot_note_raise(mrb_state *mrb, Slot &slot, const char *step)
{
    slot.raised = true;
    slot.step = step;
    slot.exception.clear();
    if (mrb->exc == nullptr)
        return;
    const mrb_value exc = mrb_obj_value(mrb->exc);
    mrb->exc = nullptr;
    const int arena = mrb_gc_arena_save(mrb);
    const mrb_value bytes = mrb_cbor_encode_fast(mrb, exc);
    if (mrb->exc == nullptr && mrb_string_p(bytes)) {
        slot.exception.assign(ruby_string_bytes(bytes));
    } else {
        // The exception itself could not cross. Its text still can.
        mrb->exc = nullptr;
        const mrb_value text = mrb_inspect(mrb, exc);
        slot.step.append(": ").append(ruby_string_bytes(text));
    }
    mrb_gc_arena_restore(mrb, arena);
}

// #30: the worker's own response.userdata. mrblib carries the object -
// Webmachine::Workers.response - and the worker holds it from open, so
// a job reads and writes the ivar and calls nothing.
void worker_userdata_set(WorkerVm &worker_vm, mrb_value value)
{
    mrb_iv_set(worker_vm.mrb, worker_vm.response, MRB_IVSYM(userdata), value);
}

mrb_value worker_userdata(WorkerVm &worker_vm)
{
    return mrb_iv_get(worker_vm.mrb, worker_vm.response, MRB_IVSYM(userdata));
}

// One job, as the body mrb_protect_error runs. A raise anywhere in here
// comes back to run_job as a value, and `step` says where it was.
struct JobBody {
    WorkerVm &worker_vm;
    Slot &slot;
    const char *step;
};

mrb_value job_run_in_protected_call(mrb_state *mrb, void *user_data)
{
    JobBody &build = *static_cast<JobBody *>(user_data);
    Slot &slot = build.slot;
    WorkerVm &worker_vm = build.worker_vm;

    build.step = "decoding the arguments of a compute task";
    mrb_value arg = mrb_nil_value();
    if (!slot.arg.empty()) {
        arg = mrb_cbor_decode_fast(mrb, mrb_str_new(mrb, slot.arg.data(), slot.arg.size()));
    }
    // The arguments arrive as one Array, because that is what
    // ComputeTask.new(*args, max_runtime:) collected.
    build.step = "loading the block of a compute task";
    const mrb_value block = worker_vm.proc_for(slot.code_id);
    if (mrb_nil_p(block)) {
        mrb_raise(mrb, E_WM_ERROR(mrb), "the worker has no block under this id");
    }
    // #30: what the run put in response.userdata, into this VM's own
    // response - the block reads and writes it the way it does at home.
    build.step = "decoding response.userdata of a compute task";
    mrb_value user_before = mrb_nil_value();
    if (!slot.user_in.empty()) {
        user_before =
            mrb_cbor_decode_fast(mrb, mrb_str_new(mrb, slot.user_in.data(), slot.user_in.size()));
    }
    worker_userdata_set(worker_vm, user_before);

    build.step = "running a compute task";
    const mrb_value args = mrb_array_p(arg) ? arg : mrb_ary_new(mrb);
    const mrb_value answer = mrb_yield_argv(
        mrb, block, static_cast<mrb_int>(ruby_array_length(args)), ruby_array_items(args));

    build.step = "encoding the answer of a compute task";
    const mrb_value bytes = mrb_cbor_encode_fast(mrb, answer);
    if (!mrb_string_p(bytes)) {
        mrb_raisef(mrb, E_WM_ERROR(mrb), "CBOR cannot carry %v", answer);
    }
    slot.out_ask.assign(ruby_string_bytes(bytes));

    // #30: and response.userdata as the block left it. The reactor is
    // told only when the bytes came back different - a job that never
    // touched the slot costs the reactor nothing.
    build.step = "encoding response.userdata of a compute task";
    const mrb_value user_after = worker_userdata(worker_vm);
    if (!mrb_nil_p(user_after)) {
        const mrb_value userdata_bytes = mrb_cbor_encode_fast(mrb, user_after);
        if (!mrb_string_p(userdata_bytes)) {
            mrb_raisef(mrb, E_WM_ERROR(mrb), "CBOR cannot carry response.userdata %v", user_after);
        }
        const std::string_view after = ruby_string_bytes(userdata_bytes);
        if (after.size() != slot.user_in.size() ||
            std::memcmp(after.data(), slot.user_in.data(), slot.user_in.size()) != 0) {
            slot.user_out.assign(after);
            slot.user_changed = true;
        }
    } else if (!slot.user_in.empty()) {
        // The block cleared it. That is a change too.
        slot.user_changed = true;
    }
    return mrb_nil_value();
}

// What a worker does with one slot: decode the argument, run the
// callback, encode the answer. Every step stays inside this VM, and
// every step runs under mrb_protect_error, so a raise is a value here
// and never a C++ throw through this frame.
//
// What bounds the block is mrb_vm_interrupt: the reactor holds this
// VM's address and calls it when the deadline passes, the VM reads that
// flag at a send and at the four jumps, and the raise lands in the
// code that was running (mruby a9151d77). The flag is cleared first,
// because an interrupt that arrived after the last job answered is not
// this job's to carry.
//
// Under Ruby there is C, and a C function stops for nothing the VM
// can do. So the deadline holds for what mruby executes, and
// admission holds for the rest.
void job_run(WorkerVm &worker_vm, Slot &slot, std::atomic<bool> &asked_stop)
{
    mrb_state *const mrb = worker_vm.mrb;
    const int arena = mrb_gc_arena_save(mrb);
    slot.raised = false;
    slot.over_deadline = false;
    slot.out_ask.clear();
    slot.exception.clear();
    slot.step.clear();
    mrb->vm_interrupt = FALSE;
    asked_stop.store(false, std::memory_order_relaxed);

    JobBody body{worker_vm, slot, "starting a compute task"};
    mrb_bool raised = FALSE;
    const mrb_value thrown = mrb_protect_error(mrb, job_run_in_protected_call, &body, &raised);
    if (raised) {
        // The reactor asked for the stop, so the raise is the deadline and
        // not the application's. It is read after the call: the reactor
        // sets it before it interrupts.
        // The VM's own exception is kept either way. When the reactor asked
        // for the stop, the step says so beside it.
        if (mrb_exception_p(thrown))
            mrb->exc = mrb_obj_ptr(thrown);
        if (asked_stop.load(std::memory_order_acquire)) {
            mrb->vm_interrupt = FALSE;
            slot.over_deadline = true;
            slot_note_raise(mrb, slot,
                            "the compute task ran past its max_runtime and the reactor stopped it");
        } else {
            slot_note_raise(mrb, slot, body.step);
        }
    } else if (mrb_unlikely(asked_stop.load(std::memory_order_acquire))) {
        // The reactor stopped this job and the block swallowed the raise - a
        // rescue around the work, or a retry that ran to the end. The
        // deadline passed all the same, and what the block answered after it
        // is not this request's answer: the round owes a 500 and this says
        // so. A block that rescues and loops for good still holds its
        // worker; nothing here can reach inside that loop.
        mrb->vm_interrupt = FALSE;
        slot.over_deadline = true;
        slot.out_ask.clear();
    }
    // The next job on this worker starts with an empty slot.
    worker_userdata_set(worker_vm, mrb_nil_value());
    mrb_gc_arena_restore(mrb, arena);
}

// One worker: block, run what the slot names, answer, repeat.
void ComputePool::worker(Impl *impl, unsigned worker_number)
{
    struct io_uring *ring = &impl->rings[worker_number];
    // The name an error record gives this worker. It is not the OS
    // thread's name: the workers are std::thread, and C++ has no call for
    // that.
    char thread_name[16];
    std::snprintf(thread_name, sizeof(thread_name), "wm-compute%u", worker_number);
    // The VM this worker answers in, built once. A worker that cannot
    // open one answers nothing: it goes, and the pool is short one
    // thread rather than quietly running a job on the wrong VM.
    // No key may be added once a worker has read the list: it would
    // exist in this worker and in no other.
    worker_builds_close();

    // This worker's own VM. The pool makes one worker at a time, so no
    // other mrb_open runs while this one does.
    WorkerVm worker_vm;
    // A worker whose VM did not open stays at its ring and answers every
    // job it is sent as a fault, so the run behind it gets its 503 and
    // the error log names this worker. Leaving would strand each job
    // sent here with no answer and no deadline, because the clock starts
    // when a job starts.
    bool boot_failed = false;
    if (!worker_vm.open()) {
        worker_vm.close();
        boot_failed = true;
    }
    // The address the reactor interrupts. It is published only after the
    // VM stands, and taken back before it closes, so the reactor never
    // holds a pointer to a VM that is being built or torn down.
    if (!boot_failed)
        impl->vms[worker_number].store(worker_vm.mrb, std::memory_order_release);

    // The starter waits for this word. It comes after a good open and
    // after a bad one, so a worker that has no VM does not hold the pool.
    {
        const std::lock_guard<std::mutex> hold(impl->boot_lock);
        impl->booted++;
    }
    impl->boot_ready.notify_all();

    for (;;) {
        struct io_uring_cqe *first = nullptr;
        const int status = io_uring_wait_cqe(ring, &first);
        if (status < 0) {
            if (status == -EINTR)
                continue;
            impl->vms[worker_number].store(nullptr, std::memory_order_release);
            worker_vm.close();
            return;
        }
        // Every completion the wait woke up to, in one pass. The answers
        // are submitted once, after the pass.
        unsigned head = 0;
        unsigned seen = 0;
        unsigned answers = 0;
        bool told_to_stop = false;
        struct io_uring_cqe *cqe = nullptr;
        io_uring_for_each_cqe(ring, head, cqe)
        {
            seen++;
            const uint64_t job = cqe->user_data;
            if (job == kStopJob) {
                told_to_stop = true;
                break;
            }
            // Our own send, or anything else that is not one of our slots.
            if (job >= impl->slots.size())
                continue;

            Slot &slot = impl->slots[static_cast<size_t>(job)];
            WM_HANDOVER_TAKE(&slot);
            // The reader of an error record asks where it ran before anything
            // else, so the name goes in beside the answer.
            slot.worker_name = thread_name;
            // The reactor arms the deadline from this message: the clock
            // starts when the job starts, not when it was queued.
            impl->running[worker_number].store(static_cast<unsigned>(job),
                                               std::memory_order_release);
            if (slot.deadline > 0.0) {
                struct io_uring_sqe *began = nullptr;
                while ((began = io_uring_get_sqe(ring)) == nullptr)
                    io_uring_submit(ring);
                io_uring_prep_msg_ring(
                    began, impl->home->ring_fd, 0,
                    detail::compute_started_tag(static_cast<unsigned>(job), slot.gen), 0);
                io_uring_sqe_set_data64(began, kSent);
                io_uring_submit(ring);
            }
            if (boot_failed) {
                slot.raised = true;
                slot.over_deadline = false;
                slot.exception.clear();
                slot.step =
                    "the worker could not open its VM at start, and this job was sent to it";
                slot.out_ask.clear();
            } else {
                job_run(worker_vm, slot, impl->asked_stop[static_cast<size_t>(job)]);
            }
            impl->running[worker_number].store(static_cast<unsigned>(impl->slots.size()),
                                               std::memory_order_release);

            // The answer goes home as a completion. The reactor wrote the slot
            // before the job was sent and reads it after this arrives, so the
            // ring's ordering is the whole synchronisation. There is no lock
            // because no two threads touch anything at the same time.
            struct io_uring_sqe *sqe = nullptr;
            while ((sqe = io_uring_get_sqe(ring)) == nullptr)
                io_uring_submit(ring);
            // The name of the answer is read before the handover, because the
            // handover is the last thing this thread does with the slot.
            const uint64_t answer_name = slot.answer;
            WM_HANDOVER_SEND(&slot);
            io_uring_prep_msg_ring(sqe, impl->home->ring_fd, 0, answer_name, 0);
            io_uring_sqe_set_data64(sqe, kSent);
            answers++;
        }
        io_uring_cq_advance(ring, seen);
        if (answers != 0)
            io_uring_submit(ring);
        if (told_to_stop) {
            impl->vms[worker_number].store(nullptr, std::memory_order_release);
            worker_vm.close();
            return;
        }
    }
}

// Ready, or a reason. A pool that cannot be built is a startup refusal,
// not a degraded mode: the alternative is hashing a password on the
// reactor's core, which is worse than not starting.
const char *ComputePool::start(unsigned workers, unsigned depth, struct io_uring *home)
{
    if (impl_ != nullptr)
        return "the pool is already up";
    if (workers == 0 || home == nullptr)
        return "a pool needs a worker and a ring to answer to";

    auto *impl = new Impl();
    impl->home = home;
    impl->rings.resize(workers);
    impl->slots.resize(static_cast<size_t>(workers) * depth);
    // An atomic is not copyable, so these two are sized once and never
    // grow: a vector that reallocates would move what another thread
    // reads.
    std::vector<std::atomic<mrb_state *>>(workers).swap(impl->vms);
    std::vector<std::atomic<unsigned>>(workers).swap(impl->running);
    std::vector<std::atomic<bool>>(impl->slots.size()).swap(impl->asked_stop);
    for (std::atomic<bool> &a : impl->asked_stop)
        a.store(false, std::memory_order_relaxed);
    for (unsigned i = 0; i < workers; i++) {
        impl->vms[i].store(nullptr, std::memory_order_relaxed);
        impl->running[i].store(static_cast<unsigned>(impl->slots.size()),
                               std::memory_order_relaxed);
    }

    for (unsigned i = 0; i < workers; i++) {
        const int status = io_uring_queue_init(depth < 8 ? 8 : depth, &impl->rings[i], 0);
        if (status < 0) {
            for (unsigned j = 0; j < i; j++)
                io_uring_queue_exit(&impl->rings[j]);
            delete impl;
            return std::strerror(-status);
        }
    }
    // One thread at a time: make worker i, wait until its VM stands, then
    // make worker i + 1.
    for (unsigned i = 0; i < workers; i++) {
        impl->threads.emplace_back([impl, i] { ComputePool::worker(impl, i); });
        std::unique_lock<std::mutex> hold(impl->boot_lock);
        impl->boot_ready.wait(hold, [impl, i] { return impl->booted > i; });
    }
    impl->up = true;
    impl_ = impl;
    return nullptr;
}

// The stop word goes to each worker through the reactor's own ring,
// the way a job does: a worker's ring is submitted by the worker only.
// A worker that could not be told is not joined, because it would
// never come, and its ring is left standing: the process is ending.
void ComputePool::stop()
{
    if (impl_ == nullptr)
        return;
    Impl *impl = impl_;
    std::vector<bool> told(impl->rings.size(), false);
    for (size_t i = 0; i < impl->rings.size(); i++) {
        struct io_uring_sqe *sqe = nullptr;
        while ((sqe = io_uring_get_sqe(impl->home)) == nullptr) {
            if (io_uring_submit(impl->home) < 0)
                break;
        }
        if (sqe == nullptr) {
            std::fprintf(stderr, "webmachine: compute worker %zu cannot be told to stop: no sqe\n",
                         i);
            continue;
        }
        io_uring_prep_msg_ring(sqe, impl->rings[i].ring_fd, 0, kStopJob, 0);
        io_uring_sqe_set_data64(sqe, detail::tag(detail::kComputeTask, 0, 0));
        const int status = io_uring_submit(impl->home);
        if (status < 0) {
            std::fprintf(stderr, "webmachine: compute worker %zu cannot be told to stop: %s\n", i,
                         std::strerror(-status));
            continue;
        }
        told[i] = true;
    }
    for (size_t i = 0; i < impl->threads.size(); i++) {
        std::thread &task = impl->threads[i];
        if (!task.joinable())
            continue;
        if (told[i]) {
            task.join();
        } else {
            task.detach();
        }
    }
    for (size_t i = 0; i < impl->rings.size(); i++) {
        if (told[i])
            io_uring_queue_exit(&impl->rings[i]);
    }
    delete impl;
    impl_ = nullptr;
}

double ComputePool::started(unsigned slot, uint16_t gen)
{
    if (impl_ == nullptr || slot >= impl_->slots.size())
        return 0.0;
    const Slot &s = impl_->slots[slot];
    if (!s.busy || s.gen != gen)
        return 0.0;
    return s.deadline;
}

void ComputePool::interrupt(unsigned slot, uint16_t gen)
{
    if (impl_ == nullptr || slot >= impl_->slots.size())
        return;
    Slot &s = impl_->slots[slot];
    // The job answered, or the slot holds a later job: this timer is not
    // its. And a job still queued behind another is not interrupted
    // either; its own clock starts when it starts.
    if (!s.busy || s.gen != gen)
        return;
    if (impl_->running[s.worker].load(std::memory_order_acquire) != slot)
        return;
    mrb_state *const mrb = impl_->vms[s.worker].load(std::memory_order_acquire);
    if (mrb == nullptr)
        return;
    // Set before the interrupt: the worker reads it only after its block
    // returned, and it is what makes the answer "the deadline" and not
    // "it raised".
    impl_->asked_stop[slot].store(true, std::memory_order_release);
    mrb_vm_interrupt(mrb);
}

bool ComputePool::submit(mrb_state *mrb, unsigned code_id, std::string_view arg,
                         std::string_view user, double deadline, uint64_t answer)
{
    if (impl_ == nullptr)
        return false;
    Impl *impl = impl_;
    // A free slot, or no. Full means every worker is busy with a full
    // queue behind it, and the caller decides what that means - this
    // layer does not invent a refusal for it.
    size_t slot_index = impl->slots.size();
    for (size_t i = 0; i < impl->slots.size(); i++) {
        if (!impl->slots[i].busy) {
            slot_index = i;
            break;
        }
    }
    if (slot_index == impl->slots.size())
        return false;

    Slot &slot = impl->slots[slot_index];
    impl->asked_stop[slot_index].store(false, std::memory_order_relaxed);
    slot.code_id = code_id;
    slot.deadline = deadline;
    slot.arg.assign(arg.data(), arg.size());
    slot.user_in.assign(user.data(), user.size());
    slot.user_out.clear();
    slot.user_changed = false;
    slot.out_ask.clear();
    slot.raised = false;
    slot.answer = answer;
    slot.gen++;
    slot.busy = true;

    const unsigned target_ring = impl->next++ % static_cast<unsigned>(impl->rings.size());
    struct io_uring_sqe *sqe = nullptr;
    try {
        sqe = sqe_or_raise(mrb, impl->home);
    } catch (...) {
        slot.busy = false;
        throw;
    }
    slot.worker = target_ring;
    WM_HANDOVER_SEND(&slot);
    io_uring_prep_msg_ring(sqe, impl->rings[target_ring].ring_fd, 0,
                           static_cast<uint64_t>(slot_index), 0);
    // The submission itself owes no completion to anyone: the answer comes
    // from the worker, not from the act of sending.
    io_uring_sqe_set_data64(sqe, detail::tag(detail::kComputeTask, 0, 0));
    return true;
}

// The answer, handed over once. Taking it frees the slot, so a second
// read finds nothing - which is what makes "the run reads its answer
// exactly once" a property of this layer rather than of its callers.
bool ComputePool::take(uint64_t answer, ComputeAnswer *out_ask)
{
    if (impl_ == nullptr)
        return false;
    for (Slot &s : impl_->slots) {
        if (s.busy && s.answer == answer) {
            WM_HANDOVER_TAKE(&s);
            out_ask->bytes.swap(s.out_ask);
            out_ask->user_bytes.swap(s.user_out);
            out_ask->user_changed = s.user_changed;
            out_ask->raised = s.raised;
            out_ask->over_deadline = s.over_deadline;
            out_ask->exception.swap(s.exception);
            out_ask->step.swap(s.step);
            out_ask->worker_name = s.worker_name;
            s.busy = false;
            s.arg.clear();
            s.out_ask.clear();
            s.user_in.clear();
            s.user_out.clear();
            s.exception.clear();
            s.step.clear();
            return true;
        }
    }
    return false;
}

unsigned ComputePool::workers() const
{
    return impl_ == nullptr ? 0 : static_cast<unsigned>(impl_->rings.size());
}

} // namespace webmachine
