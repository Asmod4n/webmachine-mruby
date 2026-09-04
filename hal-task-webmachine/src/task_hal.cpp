/*
** mruby-task HAL for a threaded io_uring server.
**
** mruby-task/ports/posix cannot be used here, and not by a little: it
** drives the tick from SIGALRM, protects the scheduler's state with
** sigprocmask(), and ticks EVERY registered VM from the handler. In a
** process with a worker pool that is three separate faults - sigprocmask
** is undefined in a threaded program (pthread_sigmask is the one that is
** defined), the signal lands on whichever thread the kernel picks, and
** mrb_tick is not async-signal-safe. This server runs one VM per worker
** thread plus the reactor's own, so it needs a HAL that knows what a
** thread is.
**
** The shape is the one mruby-task/ports/glib arrived at, in the standard
** library rather than in GLib:
**
**   - Per-thread state, in thread_local storage: the VMs opened on this
**     thread, one mutex, one condition variable. A thread only ever
**     touches its own, which is what the locking needs - but the CEILING
**     is the process's. MRB_TASK_MAX_VMS is what a build asked for, and
**     reading it per thread would quietly grant a multiple of it. A pool
**     sizes itself from that number instead: workers = MAX_VMS - 1, the
**     reactor's own VM being the one that must always fit.
**   - One ticker thread for the process, started with the first VM and
**     joined with the last. It is what makes preemption possible at all:
**     a worker blocked inside mrb_vm_exec cannot tick itself, and the
**     reactor may be just as busy. The ticker walks the registered
**     threads and calls mrb_tick under each thread's own mutex.
**   - The IRQ pair is that mutex. The header says the primitives need not
**     nest (the scheduler counts for itself in mrb_task_excl_enter), so a
**     plain mutex is enough, and mrb_hal_task_idle_cpu is called OUTSIDE
**     the exclusion (task.c, after excl_exit) so it may block.
**
** The ticker parks when no VM anywhere has a task, so a server that is
** not running any is not woken 250 times a second for nothing. What
** re-arms it is mrb_task_enable_irq: the scheduler calls it after every
** state change, which is exactly when work may have appeared.
**
** Lock order, the one rule to keep: a thread's mutex is never held while
** taking the registry's. enable_irq reads what it needs, releases the
** thread's mutex, and only then wakes the ticker.
*/

#include <mruby.h>
#include <mruby/class.h>
#include <mruby/presym.h>
#include <mruby/variable.h>

#include "mruby/task_hal_webmachine.h"

#include "task.h"
#include "task_hal.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <pthread.h>
#include <signal.h>
#include <stddef.h>

namespace {

struct ThreadState {
  mrb_state* vms[MRB_TASK_MAX_VMS] = {};
  int nvms = 0;
  std::mutex irq;
  std::condition_variable idle;
  ThreadState* next = nullptr;
};

// The registry the ticker walks, and the ticker's own life. Nothing here
// is touched while a thread's own mutex is held.
//
// LEAKED ON PURPOSE, and the reason is a deadlock this cost:
//
//   mruby -h prints its usage and calls exit(0). It never calls
//   mrb_close(). exit() runs the static destructors. One of them
//   destroys the condition variable that the ticker still waits on.
//   pthread_cond_destroy then blocks, and the process hangs with two
//   threads waiting on each other.
//
// An embedder may end a process without closing every VM. That is
// normal. So the state a live thread touches must outlive every static
// destructor. It is allocated once and never freed, and the ticker is
// detached rather than joined.
struct Globals {
  std::mutex reg;
  ThreadState* threads = nullptr;
  int vm_total = 0;
  std::thread ticker;
  bool ticker_up = false;

  // Parked until somebody has a task. Woken by enable_irq, and by the
  // last VM going away.
  std::mutex wake;
  std::condition_variable work;
  bool has_work = false;
  bool stop = false;
};

Globals& g() {
  static Globals* const state = new Globals();
  return *state;
}

thread_local ThreadState* ts = nullptr;

// A tick is only worth firing while something can be woken by it. Both
// queues, because a WAITING task is what a tick promotes.
bool vm_has_tasks(mrb_state* vm) {
  return vm->task.queues[MRB_TASK_QUEUE_READY] != nullptr ||
         vm->task.queues[MRB_TASK_QUEUE_WAITING] != nullptr;
}

bool thread_has_tasks(ThreadState* s) {
  for (int i = 0; i < s->nvms; i++) {
    if (s->vms[i] != nullptr && vm_has_tasks(s->vms[i])) return true;
  }
  return false;
}

void wake_ticker() {
  {
    std::lock_guard<std::mutex> lk(g().wake);
    g().has_work = true;
  }
  g().work.notify_one();
}

// One tick for every VM on every registered thread, each under the mutex
// that thread's own scheduler takes. A VM whose thread is inside
// mrb_vm_exec is exactly the one this exists for: the flag mrb_tick sets
// is read at the VM's next safe point.
bool tick_all() {
  bool any = false;
  std::lock_guard<std::mutex> reg(g().reg);
  for (ThreadState* s = g().threads; s != nullptr; s = s->next) {
    {
      std::lock_guard<std::mutex> lk(s->irq);
      for (int i = 0; i < s->nvms; i++) {
        if (s->vms[i] != nullptr) mrb_tick(s->vms[i]);
      }
      if (thread_has_tasks(s)) any = true;
    }
    // A task the tick made ready is what an idling scheduler waits for.
    s->idle.notify_all();
  }
  return any;
}

void ticker_main() {
  // Named, so a backtrace says which thread this is. A tick that fires
  // in the wrong place is found by reading a stack, and a stack that
  // only says "Thread 3" hides the one fact worth having.
#if defined(__linux__)
  pthread_setname_np(pthread_self(), "wm-task-tick");
#endif
  for (;;) {
    {
      std::unique_lock<std::mutex> lk(g().wake);
      g().work.wait(lk, [] { return g().has_work || g().stop; });
      if (g().stop) return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(MRB_TICK_UNIT));
    if (!tick_all()) {
      // Nothing left to wake anywhere: park until enable_irq says
      // otherwise. The re-arm is a wake, not a poll.
      std::lock_guard<std::mutex> lk(g().wake);
      g().has_work = false;
    }
  }
}

}  // namespace

MRB_BEGIN_DECL

void mrb_hal_task_init(mrb_state* mrb) {
  for (int i = 0; i < MRB_NUM_TASK_QUEUE; i++) mrb->task.queues[i] = nullptr;
  mrb->task.tick = 0;
  mrb->task.wakeup_tick = UINT32_MAX;
  mrb->task.switching = FALSE;

  bool first_on_thread = false;
  if (ts == nullptr) {
    ts = new ThreadState();
    first_on_thread = true;
  }

  bool start_ticker = false;
  {
    std::lock_guard<std::mutex> reg(g().reg);
    bool known = false;
    for (int i = 0; i < ts->nvms; i++) {
      if (ts->vms[i] == mrb) { known = true; break; }
    }
    if (!known) {
      // The operator's number, read and never raised, and counted where
      // they meant it: over the process. Per thread it would be a
      // multiple of what the build asked for.
      if (g().vm_total >= MRB_TASK_MAX_VMS || ts->nvms >= MRB_TASK_MAX_VMS) {
        mrb_raisef(mrb, E_RUNTIME_ERROR,
                   "too many mrb_states with task scheduler (max: %d)",
                   MRB_TASK_MAX_VMS);
      }
      ts->vms[ts->nvms++] = mrb;
      g().vm_total++;
    }
    if (first_on_thread) {
      ts->next = g().threads;
      g().threads = ts;
    }
    if (!g().ticker_up) {
      g().stop = false;
      g().has_work = false;
      // The ticker must never receive a signal. An embedder installs
      // its handlers for the thread it runs on, and it may block a
      // signal there and read it from a signalfd. The kernel then picks
      // any thread that does not block the signal, and the ticker is
      // one - with no handler, so the default action kills the process.
      // A new thread inherits the mask of the thread that makes it, so
      // it is made with every signal blocked.
      //
      // This tree lost a TERM to exactly that: the server blocked TERM
      // after mrb_open(), the ticker already existed with TERM open, and
      // the process died at 143 instead of removing its socket.
      sigset_t all;
      sigset_t prev;
      sigfillset(&all);
      pthread_sigmask(SIG_SETMASK, &all, &prev);
      g().ticker = std::thread(ticker_main);
      pthread_sigmask(SIG_SETMASK, &prev, nullptr);
      g().ticker_up = true;
      start_ticker = true;
    }
  }
  (void)start_ticker;
}

void mrb_hal_task_final(mrb_state* mrb) {
  if (ts == nullptr) return;

  bool last_on_thread = false;
  bool stop_ticker = false;
  {
    std::lock_guard<std::mutex> reg(g().reg);
    for (int i = 0; i < ts->nvms; i++) {
      if (ts->vms[i] != mrb) continue;
      for (int j = i; j < ts->nvms - 1; j++) ts->vms[j] = ts->vms[j + 1];
      ts->vms[--ts->nvms] = nullptr;
      g().vm_total--;
      break;
    }
    if (ts->nvms == 0) {
      ThreadState** link = &g().threads;
      while (*link != nullptr && *link != ts) link = &(*link)->next;
      if (*link == ts) *link = ts->next;
      last_on_thread = true;
    }
    if (g().vm_total == 0 && g().ticker_up) {
      g().ticker_up = false;
      stop_ticker = true;
    }
  }

  if (stop_ticker) {
    {
      std::lock_guard<std::mutex> lk(g().wake);
      g().stop = true;
      g().has_work = true;
    }
    g().work.notify_one();
    g().ticker.join();
  }

  if (last_on_thread) {
    delete ts;
    ts = nullptr;
  }
}

void mrb_task_disable_irq(void) {
  if (ts != nullptr) ts->irq.lock();
}

void mrb_task_enable_irq(void) {
  ThreadState* s = ts;
  if (s == nullptr) return;
  // Read what decides the wake while the lock still holds it still, then
  // let go BEFORE touching the registry's side: a thread's mutex is
  // never held while another lock is taken.
  const bool work = thread_has_tasks(s);
  s->irq.unlock();
  s->idle.notify_all();
  if (work) wake_ticker();
}

void mrb_hal_task_idle_cpu(mrb_state* mrb) {
  (void)mrb;
  ThreadState* s = ts;
  if (s == nullptr) {
    std::this_thread::sleep_for(std::chrono::milliseconds(MRB_TICK_UNIT));
    return;
  }
  // Called outside the exclusion, so this takes the mutex itself. The
  // timeout is what a missed wake costs; the ticker notifies on every
  // tick, so the usual path is woken rather than timed out.
  std::unique_lock<std::mutex> lk(s->irq);
  s->idle.wait_for(lk, std::chrono::milliseconds(MRB_TICK_UNIT));
}

// This gem has no Ruby surface: the HAL's life is per mrb_state and
// mruby-task drives it through mrb_hal_task_init / _final. mruby asks
// every gem for these two, so they are here and empty.
void mrb_hal_task_webmachine_gem_init(mrb_state*) {}
void mrb_hal_task_webmachine_gem_final(mrb_state*) {}

// Why this exists, and why it cannot be gem_init's job: see
// include/mruby/task_hal_webmachine.h.
void mrb_hal_task_drop_queue(mrb_state* mrb) {
  struct RClass* task = mrb_class_get_id(mrb, MRB_SYM(Task));
  mrb_const_remove(mrb, mrb_obj_value(task), MRB_SYM(Queue));
}

void mrb_hal_task_sleep_us(mrb_state* mrb, mrb_int usec) {
  (void)mrb;
  if (usec <= 0) return;
  std::this_thread::sleep_for(std::chrono::microseconds(usec));
}

MRB_END_DECL
