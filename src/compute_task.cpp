// Design decisions live in .DESIGN.md, filed under what each comment names.
//
// #80: the compute pool a ComputeTask is answered by.
//
// Watcher is this file's sibling and the other half of the same idea: a
// watcher answers the SAME question again until somebody disarms it, and
// it watches a descriptor. A compute task is asked once, it is answered once,
// and what answers it is a thread - because the work is not waiting for
// a descriptor, it is arithmetic that would otherwise be done on the
// reactor's core. argon2 is the first of it: ~40 ms, which is every
// other connection on this core stopped for that long.
//
// The queue between the two is io_uring's own. A worker blocks in
// io_uring_wait_cqe on a ring of its own; the reactor posts work into it
// with IORING_OP_MSG_RING, and the worker posts the answer back the same
// way. So there is no ring buffer here to get the memory ordering right
// in, no condition variable, no eventfd beside the queue to wake anyone
// - and the answer arrives at the reactor as an ORDINARY completion,
// which is what makes a compute task answered by a thread indistinguishable
// from one resolved by a disk.
#include "webmachine.hpp"

#include <mruby/task_hal_webmachine.h>


#include <liburing.h>
#include <pthread.h>

#include <mruby/array.h>
#include <mruby/cbor.h>
#include <mruby/class.h>
#include <mruby/error.h>
#include <mruby/hash.h>
#include <mruby/presym.h>
#include <mruby/proc.h>
#include <mruby/proc_irep_ext.h>
#include <mruby/string.h>
#include <mruby/variable.h>

// mruby-task's own header. A worker runs every declared block as a
// Task, so it needs the creation, the scheduler loop and the abort.
// Named here and not in webmachine.hpp: only this file opens a VM.
#include <task.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

namespace webmachine {
namespace {

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
  std::string out;
  // Seconds of EXECUTION. The worker ends a task that runs past it.
  double deadline = 0.0;
  bool raised = false;
  // The task was ended because it passed its deadline. A different
  // answer from a raise: the author's number was wrong, and a retry
  // would take just as long (.DESIGN.md #promise-bound).
  bool over_deadline = false;
  // What the raise said, in text. An exception object belongs to the
  // worker's VM and cannot cross, so the worker reads it here and the
  // reactor writes it to the error log.
  std::string exception_class;
  std::string message;
  std::string backtrace;
  // Which worker ran it, as the name its thread carries.
  std::string worker_name;
  // The reactor's own tag for this compute task: what its completion will
  // carry, so the reactor knows whose answer arrived. The pool never
  // looks inside it.
  uint64_t answer = 0;
  bool busy = false;
};

// user_data on the WORKER's ring. Not a webmachine tag - this side is
// the pool's own, and the only two things it says are "here is slot i"
// and "stop".
constexpr uint64_t kStopJob = ~static_cast<uint64_t>(0);
// MSG_RING answers TWICE: the target ring gets the message, and the
// sender's own ring gets a completion for having sent it. A worker
// therefore sees its own answer come back, and anything that is not a
// job index has to be stepped over rather than used as one.
constexpr uint64_t kSent = ~static_cast<uint64_t>(1);

// The declared blocks of this process. The reactor appends to it - once
// per block, the first time one is seen - and workers read it. Both
// under one mutex, which is only ever taken on a COLD path: the
// reactor takes it once per block for the life of the process, and a
// worker takes it once per block it has not loaded yet.
struct Registry {
  std::mutex mtx;
  std::vector<ComputeTaskCode> codes;
  // Which irep is already interned. The same code at the same place
  // carries the same irep, so this is what makes "dump once" true.
  std::unordered_map<const void*, unsigned> by_irep;
};

Registry& registry() {
  static Registry reg;
  return reg;
}

}  // namespace

// #80: Webmachine::ComputeTask. It holds three things and does
// nothing: the block a worker will run, the arguments it is called
// with, and how long it may take. It is built on the reactor by a
// callback, and read by the reactor right after.
//
// It is deliberately NOT a thing that runs. A ComputeTask that could start
// its own work would be a second way to reach a worker, and there is
// one way: a flow node the resource declared.
namespace {

struct RClass* compute_task_class_ = nullptr;

mrb_value compute_task_initialize(mrb_state* mrb, mrb_value self) {
  // mruby checks keywords against a DECLARED table, and a null table
  // means "this call takes none". max_runtime is declared here, and
  // declared optional so the refusal below is ours: mruby's own would
  // say the keyword is missing, and not why a deadline is owed.
  const mrb_sym kw_names[] = {MRB_SYM(max_runtime)};
  // Initialised, because mrb_get_args leaves a key that was not given
  // untouched: an uninitialised slot would be read as whatever the
  // stack held.
  mrb_value kw_values[1] = {mrb_undef_value()};
  const mrb_kwargs kwargs = {1, 0, kw_names, kw_values, nullptr};
  const mrb_value* argv = nullptr;
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

}  // namespace

// #80: Webmachine::Workers::Registry. What a worker keeps between
// jobs, and the only way it can keep anything: a block carries no
// environment, so a database or a connection has to be built inside
// the worker's own VM.
//
// The main VM registers a proc. Every worker runs it once when it
// opens, and keeps what it answers under the same key. The key travels
// as a string, because an mrb_sym is a number one VM handed out.
namespace {

std::mutex& builds_mutex() {
  static std::mutex m;
  return m;
}

std::vector<WorkerBuild>& builds() {
  static std::vector<WorkerBuild> v;
  return v;
}

bool builds_closed_ = false;

// The table a worker built for itself, under the same keys. Read by a
// block through Registry[], and by nothing else.
mrb_value worker_table(mrb_state* mrb) {
  struct RClass* const workers = mrb_module_get_under_id(
      mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(Workers));
  return mrb_iv_get(mrb, mrb_obj_value(workers), MRB_IVSYM(built));
}

// Registry[key] - inside a worker, this worker's own value.
mrb_value registry_get(mrb_state* mrb, mrb_value self) {
  (void)self;
  mrb_value key;
  mrb_get_args(mrb, "o", &key);
  const mrb_value table = worker_table(mrb);
  if (!mrb_hash_p(table)) {
    mrb_raise(mrb, E_WM_ERROR(mrb),
              "Webmachine::Workers::Registry answers inside a worker only - the values are "
              "built there, one per worker, and this VM has none");
  }
  return mrb_hash_get(mrb, table, key);
}

// Registry[key] = proc - in the main VM, at startup.
mrb_value registry_set(mrb_state* mrb, mrb_value self) {
  (void)self;
  mrb_value key;
  mrb_value block;
  mrb_get_args(mrb, "oo", &key, &block);
  if (!mrb_proc_p(block)) {
    mrb_raise(mrb, E_WM_ERROR(mrb),
              "Webmachine::Workers::Registry takes a proc that BUILDS the value, not the "
              "value - an object cannot cross into a worker, and how to build one can");
  }
  const mrb_value name = mrb_obj_as_string(mrb, key);
  if (!worker_build_register(mrb, std::string(RSTRING_PTR(name), RSTRING_LEN(name)), block)) {
    mrb_raisef(mrb, E_WM_ERROR(mrb),
               "Webmachine::Workers::Registry[%v] was set after the workers started - they "
               "were built already, so this key exists in none of them",
               key);
  }
  return block;
}

}  // namespace

bool worker_build_register(mrb_state* mrb, std::string key, mrb_value block) {
  std::lock_guard<std::mutex> hold(builds_mutex());
  if (builds_closed_) return false;
  const mrb_value bytes = mrb_proc_to_irep(mrb, mrb_proc_ptr(block));
  if (mrb->exc != nullptr || !mrb_string_p(bytes)) {
    mrb->exc = nullptr;
    return false;
  }
  WorkerBuild b;
  b.key = std::move(key);
  b.irep.assign(RSTRING_PTR(bytes), static_cast<size_t>(RSTRING_LEN(bytes)));
  builds().push_back(std::move(b));
  return true;
}

const std::vector<WorkerBuild>& worker_builds() { return builds(); }

void worker_builds_close() {
  std::lock_guard<std::mutex> hold(builds_mutex());
  builds_closed_ = true;
}

void compute_task_init_class(mrb_state* mrb, struct RClass* wm) {
  compute_task_class_ = mrb_define_class_under_id(mrb, wm, MRB_SYM(ComputeTask),
                                                 mrb->object_class);
  mrb_define_method_id(mrb, compute_task_class_, MRB_SYM(initialize), compute_task_initialize,
                       MRB_ARGS_ANY() | MRB_ARGS_BLOCK());

  struct RClass* workers = mrb_define_module_under_id(mrb, wm, MRB_SYM(Workers));
  struct RClass* registry = mrb_define_module_under_id(mrb, workers, MRB_SYM(Registry));
  mrb_define_class_method_id(mrb, registry, MRB_OPSYM(aref), registry_get, MRB_ARGS_REQ(1));
  mrb_define_class_method_id(mrb, registry, MRB_OPSYM(aset), registry_set, MRB_ARGS_REQ(2));
}

bool compute_task_of(mrb_state* mrb, mrb_value v, ComputeTaskAsk* out) {
  if (compute_task_class_ == nullptr) return false;
  if (!mrb_obj_is_kind_of(mrb, v, compute_task_class_)) return false;
  out->block = mrb_iv_get(mrb, v, MRB_IVSYM(block));
  out->args = mrb_iv_get(mrb, v, MRB_IVSYM(args));
  out->max_runtime = mrb_as_float(mrb, mrb_iv_get(mrb, v, MRB_IVSYM(max_runtime)));
  return true;
}

// #80: the way back. Only this thread may build a value in the
// reactor's VM, so the decode happens here and nowhere else.
void Http1::compute_task_answered(Conn& st, const ComputeAnswer& answered) {
  st.compute_task_ready = true;
  st.compute_task_answer = mrb_nil_value();
  st.compute_task_over_deadline = answered.over_deadline;
  // A raise and a deadline are told apart, because the answers are not
  // the same one: 503 says come back, 500 says nothing will change.
  st.compute_task_raised = answered.raised && !answered.over_deadline;
  const Resource* const res = st.job_res;
  if (res == nullptr || answered.raised || answered.bytes.empty()) return;
  mrb_state* const mrb = res->mrb;
  const mrb_value v =
      mrb_cbor_decode_fast(mrb, mrb_str_new(mrb, answered.bytes.data(), answered.bytes.size()));
  if (mrb->exc != nullptr) {
    mrb->exc = nullptr;
    return;
  }
  st.compute_task_answer = v;
  mrb_gc_register(mrb, v);
}

// #80: the crossing, done by the frame at the stop. It runs on the
// reactor's thread with the reactor's VM live, which is the only place
// either half is possible: the block is interned to an id, and the
// arguments are encoded to CBOR.
//
// It happens HERE and not when the reactor arms the work, because the
// frame takes the run's state with it one line later - res.run belongs
// to the route, and a second request would write over it.
//
// Both halves can refuse: a block mruby cannot dump, or a value CBOR
// cannot carry. Either leaves job_waiting false, and the run is told
// the same thing a full pool tells it.
bool Http1::compute_task_hand_over(Conn& st, const Resource& res) {
  st.job_waiting = false;
  st.job_res = &res;
  if (!res.run.compute_task_held) return false;

  mrb_state* const mrb = res.mrb;
  const int ai = mrb_gc_arena_save(mrb);
  const unsigned id =
      compute_task_intern(mrb, res.run.compute_task_block, res.run.compute_task_deadline);
  if (id == kComputeTaskNoCode) {
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  const mrb_value enc = mrb_cbor_encode_fast(mrb, res.run.compute_task_args);
  if (mrb->exc != nullptr || !mrb_string_p(enc)) {
    mrb->exc = nullptr;
    mrb_gc_arena_restore(mrb, ai);
    return false;
  }
  st.job_bytes.assign(RSTRING_PTR(enc), static_cast<size_t>(RSTRING_LEN(enc)));
  mrb_gc_arena_restore(mrb, ai);
  st.job_code = id;
  st.job_deadline = res.run.compute_task_deadline;
  st.job_waiting = true;
  // A new job, so nothing of the last one speaks for it.
  st.compute_task_full = false;
  st.compute_task_over_deadline = false;
  st.compute_task_raised = false;
  return true;
}

unsigned compute_task_intern(mrb_state* mrb, mrb_value block, double max_runtime) {
  struct RProc* const proc = mrb_proc_ptr(block);
  const void* const key = proc->body.irep;
  Registry& reg = registry();
  std::lock_guard<std::mutex> hold(reg.mtx);
  const auto seen = reg.by_irep.find(key);
  if (seen != reg.by_irep.end()) return seen->second;

  ComputeTaskCode code;
  const mrb_value bytes = mrb_proc_to_irep(mrb, proc);
  if (mrb->exc != nullptr || !mrb_string_p(bytes)) {
    mrb->exc = nullptr;
    return kComputeTaskNoCode;
  }
  code.irep.assign(RSTRING_PTR(bytes), static_cast<size_t>(RSTRING_LEN(bytes)));
  code.max_runtime = max_runtime;
  reg.codes.push_back(std::move(code));
  const unsigned id = static_cast<unsigned>(reg.codes.size() - 1);
  reg.by_irep.emplace(key, id);
  return id;
}

bool compute_task_code_of(unsigned id, std::string* irep, double* max_runtime) {
  Registry& reg = registry();
  std::lock_guard<std::mutex> hold(reg.mtx);
  if (id >= reg.codes.size()) return false;
  *irep = reg.codes[id].irep;
  *max_runtime = reg.codes[id].max_runtime;
  return true;
}

struct ComputePool::Impl {
  std::vector<struct io_uring> rings;
  std::vector<std::thread> threads;
  std::vector<Slot> slots;
  // Round-robin, and that is enough: every job in this pool is a
  // password hash with fixed m and t, so they all cost the same. A
  // shortest-queue choice would compute an answer the caller already
  // knows - the counts would differ by at most one.
  unsigned next = 0;
  struct io_uring* home = nullptr;
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

struct WorkerVm {
  mrb_state* mrb = nullptr;
  std::vector<mrb_value> procs;
  // Webmachine::Workers, which holds `wrap`: a block and its arguments
  // made into a proc that takes none. mrblib carries it, so mrbc
  // translated it at build time and every VM that opens has it. A ship
  // build has no mruby-compiler, so nothing may be translated here.
  mrb_value workers = {};
  bool open() {
    mrb = mrb_open();
    if (mrb == nullptr) return false;
    // Every mrb_state in this process, and a worker's is one: mruby-task
    // caches VM-owned objects in file-scope statics, so a queue built in
    // one VM answers with another VM's objects. The HAL header says why
    // it can only happen here, after mrb_open.
    mrb_hal_task_drop_queue(mrb);
    // Webmachine::Workers, looked up ONCE. A module is rooted by the
    // constant that names it, so nothing else has to hold it.
    workers = mrb_const_get(mrb, mrb_obj_value(mrb->object_class), MRB_SYM(Webmachine));
    if (mrb->exc == nullptr) workers = mrb_const_get(mrb, workers, MRB_SYM(Workers));
    if (mrb->exc != nullptr) {
      mrb->exc = nullptr;
      return false;
    }
    // The scheduler STAYS on. Every declared block runs as a Task, which
    // is what makes a deadline enforceable: mruby preempts Ruby at a
    // safe point, and mrb_terminate_task ends a run that is over its
    // max_runtime. A worker VM with the scheduler off could not do that.
    return build_registry();
  }

  // What the application registered, built HERE, once, in this VM. A
  // handle belongs to the VM that opened it, so every worker opens its
  // own - and reads it back without a lock, because nothing is shared.
  //
  // A build that fails takes the worker with it. That is the same rule
  // every other startup failure follows: a path that cannot be opened
  // is said at the start, never on the first request.
  bool build_registry() {
    const mrb_value table = mrb_hash_new(mrb);
    struct RClass* const workers = mrb_module_get_under_id(
        mrb, mrb_module_get_id(mrb, MRB_SYM(Webmachine)), MRB_SYM(Workers));
    mrb_iv_set(mrb, mrb_obj_value(workers), MRB_IVSYM(built), table);
    for (const WorkerBuild& b : worker_builds()) {
      const mrb_value proc = mrb_proc_from_irep(mrb, b.irep.data(), b.irep.size());
      if (mrb->exc != nullptr || !mrb_proc_p(proc)) {
        mrb->exc = nullptr;
        return false;
      }
      const mrb_value v = mrb_funcall_argv(mrb, proc, MRB_SYM(call), 0, nullptr);
      if (mrb->exc != nullptr) {
        mrb->exc = nullptr;
        return false;
      }
      mrb_hash_set(mrb, table, mrb_symbol_value(mrb_intern(mrb, b.key.data(), b.key.size())), v);
    }
    return true;
  }

  // The block behind an id, loaded the first time this worker meets it
  // and kept for the life of the VM. A request pays this once per block
  // per worker, never per call.
  mrb_value proc_for(unsigned id) {
    if (id < procs.size() && !mrb_nil_p(procs[id])) return procs[id];
    std::string irep;
    double deadline = 0.0;
    if (!compute_task_code_of(id, &irep, &deadline)) return mrb_nil_value();
    const mrb_value p = mrb_proc_from_irep(mrb, irep.data(), irep.size());
    if (mrb->exc != nullptr || !mrb_proc_p(p)) {
      mrb->exc = nullptr;
      return mrb_nil_value();
    }
    if (id >= procs.size()) procs.resize(id + 1, mrb_nil_value());
    procs[id] = p;
    mrb_gc_register(mrb, p);
    return p;
  }

  void close() {
    if (mrb == nullptr) return;
    mrb_close(mrb);
    mrb = nullptr;
  }
};

// Seconds since a fixed point, monotonic. A deadline is a duration, so
// the clock behind it must not step.
double now_seconds() {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<double>(t.tv_sec) + static_cast<double>(t.tv_nsec) * 1e-9;
}


// One failure inside a worker, written down before the VM forgets it.
// The exception is cleared here and nowhere else: a VM that keeps an
// exception raises it again on the next job, and the next job belongs
// to another request.
//
// `step` names the part of the job that failed - decode, build, run,
// encode. The class and the message speak about the Ruby; `step` says
// which of the four steps was running when it broke.
void note_raise(mrb_state* mrb, Slot& s, const char* step) {
  s.raised = true;
  ErrFacts f;
  std::string backtrace;
  exception_facts(mrb, {f, backtrace});
  if (f.exception_class != nullptr) {
    s.exception_class.assign(f.exception_class, f.exception_class_len);
    if (f.message != nullptr) s.message.assign(f.message, f.message_len);
    s.backtrace.swap(backtrace);
  } else {
    // Nothing raised, and the step still refused: a block that is not
    // there, a value CBOR cannot carry. It is the server's own fault
    // and it carries the server's own class.
    s.exception_class = "Webmachine::Error";
  }
  if (!s.message.empty()) s.message.append(" - ");
  s.message.append(step);
  mrb->exc = nullptr;
}

// What a worker does with one slot: decode the argument, run the
// callback, encode the answer. Every step stays inside this VM.
void run_job(WorkerVm& vm, Slot& s) {
  mrb_state* const mrb = vm.mrb;
  const int ai = mrb_gc_arena_save(mrb);
  s.raised = false;
  s.over_deadline = false;
  s.out.clear();
  s.exception_class.clear();
  s.message.clear();
  s.backtrace.clear();

  mrb_value arg = mrb_nil_value();
  if (!s.arg.empty()) {
    arg = mrb_cbor_decode_fast(mrb, mrb_str_new(mrb, s.arg.data(), s.arg.size()));
    if (mrb->exc != nullptr) {
      note_raise(mrb, s, "decoding the arguments of a compute task");
      mrb_gc_arena_restore(mrb, ai);
      return;
    }
  }
  // The arguments arrive as one Array, because that is what
  // ComputeTask.new(*args, max_runtime:) collected. A C function is not a second kind of
  // job here: the block calls one, the way argon2 is called, and the
  // pointer runs inside this VM like any other method.
  const mrb_value block = vm.proc_for(s.code_id);
  if (mrb_nil_p(block)) {
    note_raise(mrb, s, "the worker has no block under this id");
    mrb_gc_arena_restore(mrb, ai);
    return;
  }
  // The block runs as a TASK, which is the whole reason this VM keeps
  // its scheduler. mruby preempts Ruby at a safe point, so a run that
  // passes its max_runtime is ended where it stands - and that is what
  // makes a deadline a promise this tree can keep for Ruby.
  //
  // Under Ruby there is C, and C stops for one thing only: a signal
  // while the thread sits in a syscall that answers EINTR. argon2 sits
  // in none. So the deadline holds for what mruby can preempt, and
  // admission holds for the rest (.DESIGN.md #promise-bound).
  // A task body has to be Ruby: task_init_context reads
  // proc->body.irep, so a proc built from a C function has nothing the
  // scheduler could run. The wrapper makes a Ruby one.
  const mrb_value wrapped[2] = {block, mrb_array_p(arg) ? arg : mrb_ary_new(mrb)};
  const mrb_value task_proc = mrb_funcall_argv(mrb, vm.workers, MRB_SYM(wrap), 2, wrapped);
  if (mrb->exc != nullptr || !mrb_proc_p(task_proc)) {
    note_raise(mrb, s, "building the proc of a compute task");
    mrb_gc_arena_restore(mrb, ai);
    return;
  }
  const mrb_value task = mrb_create_task(mrb, mrb_proc_ptr(task_proc), mrb_nil_value(),
                                         mrb_nil_value(), mrb_nil_value());
  if (mrb->exc != nullptr || mrb_nil_p(task)) {
    note_raise(mrb, s, "starting the task of a compute task");
    mrb_gc_arena_restore(mrb, ai);
    return;
  }
  // The WORKER decides when the VM runs, never the VM. Task.run hands
  // the thread to the scheduler until every queue is empty, and while
  // any task waits it sits in the idle hook - this thread has its own
  // loop and could not serve it again. mrb_hal_task_step is one step
  // plus an answer: when to come back. mruby-task/ports/glib drives a
  // GTK loop the same way.
  //
  // The deadline is checked HERE, between steps, because this loop is
  // the host's. max_runtime is EXECUTION time, so the mark is taken
  // now - the wait in the queue was not this task's to pay.
  const double mark = s.deadline > 0.0 ? now_seconds() + s.deadline : 0.0;
  for (;;) {
    const int64_t next_us = mrb_hal_task_step();
    if (mrb->exc != nullptr) break;
    if (mrb_symbol(mrb_task_status(mrb, task)) == MRB_SYM(DORMANT)) break;
    if (mark != 0.0 && now_seconds() >= mark) {
      mrb_terminate_task(mrb, task);
      s.over_deadline = true;
      s.raised = true;
      s.exception_class = "Webmachine::Error";
      s.message = "the compute task ran past its max_runtime and the worker ended it";
      // One more step, so the scheduler sees the task end and every
      // queue empties. Without it the task stays in a queue and the
      // next job on this worker would find it there.
      mrb_hal_task_step();
      break;
    }
    // Nothing is ready and nothing sleeps, yet the task is not done:
    // it waits on something this loop cannot see. A worker has no
    // such thing to offer, so this is the end of it.
    if (next_us < 0) break;
    if (next_us > 0) {
      const int64_t left = mark == 0.0 ? next_us
                                       : static_cast<int64_t>((mark - now_seconds()) * 1e6);
      const int64_t wait = (mark != 0.0 && left < next_us) ? left : next_us;
      if (wait > 0) mrb_hal_task_sleep_us(mrb, static_cast<mrb_int>(wait));
    }
  }
  if (mrb->exc != nullptr) {
    note_raise(mrb, s, "running a compute task");
    mrb_gc_arena_restore(mrb, ai);
    return;
  }
  if (s.over_deadline) {
    mrb_gc_arena_restore(mrb, ai);
    return;
  }
  const mrb_value answer = mrb_task_value(mrb, task);
  if (mrb->exc != nullptr) {
    note_raise(mrb, s, "reading the answer of a compute task");
    mrb_gc_arena_restore(mrb, ai);
    return;
  }
  // A task that raised does NOT leave the exception in mrb->exc: the
  // scheduler moves it to the task's result and clears the VM
  // (mruby-task/src/task.c:424). So the result IS the raise, and asking
  // mrb->exc would say the run went well and then hand an Exception to
  // CBOR - which the reactor cannot read back.
  if (mrb_obj_is_kind_of(mrb, answer, mrb->eException_class)) {
    // note_raise reads the VM, so the exception goes back for the one
    // call that needs it. It clears it again.
    mrb->exc = mrb_obj_ptr(answer);
    note_raise(mrb, s, "running a compute task");
    mrb_gc_arena_restore(mrb, ai);
    return;
  }
  const mrb_value bytes = mrb_cbor_encode_fast(mrb, answer);
  if (mrb->exc != nullptr || !mrb_string_p(bytes)) {
    note_raise(mrb, s, "encoding the answer of a compute task");
    mrb_gc_arena_restore(mrb, ai);
    return;
  }
  s.out.assign(RSTRING_PTR(bytes), static_cast<size_t>(RSTRING_LEN(bytes)));
  mrb_gc_arena_restore(mrb, ai);
}

unsigned compute_worker_ceiling() {
  // The reactor's VM is one of them and it is always there, so the pool
  // may have the rest. Never zero: a build with MRB_TASK_MAX_VMS 1 has
  // no room for a worker, and one worker that refuses to open says so
  // at startup - better than a pool that silently answers nothing.
  return MRB_TASK_MAX_VMS > 1 ? static_cast<unsigned>(MRB_TASK_MAX_VMS - 1) : 1;
}

// One worker: block, run what the slot names, answer, repeat.
void ComputePool::worker(Impl* impl, unsigned me) {
  struct io_uring* ring = &impl->rings[me];
  // A thread with no name is a number in a backtrace, and a backtrace
  // taken while a compute task is being answered is exactly the one that has
  // to say WHICH worker. Linux takes 16 bytes with the terminator, so
  // the number has to fit inside that - it is not a place to be
  // generous with words.
  char thread_name[16];
  std::snprintf(thread_name, sizeof(thread_name), "wm-compute%u", me);
#if defined(__linux__)
  pthread_setname_np(pthread_self(), thread_name);
#endif
  // The VM this worker answers in, built ONCE. A worker that cannot
  // open one answers nothing: it goes, and the pool is short one
  // thread rather than quietly running a job on the wrong VM.
  // No key may be added once a worker has read the list: it would
  // exist in this worker and in no other.
  worker_builds_close();

  // ONE VM at a time, whatever the pool's size. mrb_open is safe per VM,
  // but the gems in this build are not all safe against each other:
  // mruby-task keeps file-scope statics and takes a process-wide lock in
  // its init, and a core dump from a 28-core machine showed twenty-eight
  // threads inside mrb_init_mrbgems together, with three of them aborting
  // in a name lookup that had no protect frame.
  //
  // This costs startup time once per worker and nothing afterwards: a
  // worker opens its VM before it takes its first job.
  WorkerVm vm;
  {
    static std::mutex opening;
    const std::lock_guard<std::mutex> hold(opening);
    if (!vm.open()) {
      vm.close();
      return;
    }
  }

  for (;;) {
    struct io_uring_cqe* cqe = nullptr;
    const int rc = io_uring_wait_cqe(ring, &cqe);
    if (rc < 0) {
      if (rc == -EINTR) continue;
      vm.close();
      return;
    }
    const uint64_t job = cqe->user_data;
    io_uring_cqe_seen(ring, cqe);
    if (job == kStopJob) {
      vm.close();
      return;
    }
    // Our own send, or anything else that is not one of our slots.
    if (job >= impl->slots.size()) continue;

    Slot& s = impl->slots[static_cast<size_t>(job)];
    // The reader of an error record asks WHERE it ran before anything
    // else, so the name goes in beside the answer.
    s.worker_name = thread_name;
    run_job(vm, s);

    // The answer goes home as a completion. The reactor reads the slot
    // only after this arrives, and wrote it only before the job was
    // sent, so the ring's own ordering is the whole synchronisation -
    // there is no lock here because there is nothing two threads touch
    // at the same time.
    struct io_uring_sqe* sqe = nullptr;
    while ((sqe = io_uring_get_sqe(ring)) == nullptr) io_uring_submit(ring);
    io_uring_prep_msg_ring(sqe, impl->home->ring_fd, 0, s.answer, 0);
    io_uring_sqe_set_data64(sqe, kSent);
    io_uring_submit(ring);
  }
}

// Ready, or a reason. A pool that cannot be built is a startup refusal,
// not a degraded mode: the alternative is hashing a password on the
// reactor's core, which is worse than not starting.
const char* ComputePool::start(unsigned workers, unsigned depth, struct io_uring* home) {
  if (impl_ != nullptr) return "the pool is already up";
  if (workers == 0 || home == nullptr) return "a pool needs a worker and a ring to answer to";

  auto* impl = new Impl();
  impl->home = home;
  impl->rings.resize(workers);
  impl->slots.resize(static_cast<size_t>(workers) * depth);

  for (unsigned i = 0; i < workers; i++) {
    const int rc = io_uring_queue_init(depth < 8 ? 8 : depth, &impl->rings[i], 0);
    if (rc < 0) {
      for (unsigned j = 0; j < i; j++) io_uring_queue_exit(&impl->rings[j]);
      delete impl;
      return std::strerror(-rc);
    }
  }
  for (unsigned i = 0; i < workers; i++) {
    impl->threads.emplace_back([impl, i] { ComputePool::worker(impl, i); });
  }
  impl->up = true;
  impl_ = impl;
  return nullptr;
}

void ComputePool::stop() {
  if (impl_ == nullptr) return;
  Impl* impl = impl_;
  for (size_t i = 0; i < impl->rings.size(); i++) {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&impl->rings[i]);
    if (sqe != nullptr) {
      // A ring may message itself, which is how a worker is told to go
      // without a second channel for the telling.
      io_uring_prep_msg_ring(sqe, impl->rings[i].ring_fd, 0, kStopJob, 0);
      io_uring_submit(&impl->rings[i]);
    }
  }
  for (std::thread& t : impl->threads) {
    if (t.joinable()) t.join();
  }
  for (struct io_uring& r : impl->rings) io_uring_queue_exit(&r);
  delete impl;
  impl_ = nullptr;
}

bool ComputePool::submit(unsigned code_id, std::string_view arg, double deadline,
                         uint64_t answer) {
  if (impl_ == nullptr) return false;
  Impl* impl = impl_;
  // A free slot, or no. Full means every worker is busy with a full
  // queue behind it, and the caller decides what that means - this
  // layer does not invent a refusal for it.
  size_t at = impl->slots.size();
  for (size_t i = 0; i < impl->slots.size(); i++) {
    if (!impl->slots[i].busy) {
      at = i;
      break;
    }
  }
  if (at == impl->slots.size()) return false;

  Slot& s = impl->slots[at];
  s.code_id = code_id;
  s.deadline = deadline;
  s.arg.assign(arg.data(), arg.size());
  s.out.clear();
  s.raised = false;
  s.answer = answer;
  s.busy = true;

  const unsigned to = impl->next++ % static_cast<unsigned>(impl->rings.size());
  struct io_uring_sqe* sqe = io_uring_get_sqe(impl->home);
  if (sqe == nullptr) {
    s.busy = false;
    return false;
  }
  io_uring_prep_msg_ring(sqe, impl->rings[to].ring_fd, 0, static_cast<uint64_t>(at), 0);
  // The submission itself owes no completion to anyone: the answer comes
  // from the worker, not from the act of sending.
  io_uring_sqe_set_data64(sqe, detail::tag(detail::kComputeTask, 0, 0));
  return true;
}

// The answer, handed over once. Taking it frees the slot, so a second
// read finds nothing - which is what makes "the run reads its answer
// exactly once" a property of this layer rather than of its callers.
bool ComputePool::take(uint64_t answer, ComputeAnswer* out) {
  if (impl_ == nullptr) return false;
  for (Slot& s : impl_->slots) {
    if (s.busy && s.answer == answer) {
      out->bytes.swap(s.out);
      out->raised = s.raised;
      out->over_deadline = s.over_deadline;
      out->exception_class.swap(s.exception_class);
      out->message.swap(s.message);
      out->backtrace.swap(s.backtrace);
      out->worker_name = s.worker_name;
      s.busy = false;
      s.arg.clear();
      s.out.clear();
      s.exception_class.clear();
      s.message.clear();
      s.backtrace.clear();
      return true;
    }
  }
  return false;
}

unsigned ComputePool::workers() const {
  return impl_ == nullptr ? 0 : static_cast<unsigned>(impl_->rings.size());
}

}  // namespace webmachine
