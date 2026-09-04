#pragma once

#include <mruby.h>

#include <stdint.h>

MRB_BEGIN_DECL

/*
 * Call this on every mrb_state, right after mrb_open().
 *
 * mruby-task's queue caches VM-owned objects in file-scope statics
 * (task_queue.c:27-29: wait_retry_, wait_timeout_, task_error_class_),
 * written by mrb_init_task_queue on EVERY mrb_open. With more than one VM
 * in a process the last one to open wins, and a queue used from any other
 * VM raises with a foreign Task::Error and compares against foreign
 * sentinels - objects of a heap it does not own, which may already be
 * freed. Two VMs opened one after the other on one thread are enough; it
 * is not a threading fault.
 *
 * So Task::Queue is taken away until the gem stops caching them. It has to
 * happen HERE and not in a gem's init: mruby-task's own mrblib reopens
 * `class Queue` under Task after every C init has run, so anything removed
 * earlier comes back. After mrb_open there is nothing left to undo it.
 */
MRB_API void mrb_hal_task_drop_queue(mrb_state *mrb);

/*
 * Advance the schedulers of every VM this thread opened, by ONE step
 * each, and answer when the caller has to come back.
 *
 * This is what a host loop calls. It is the whole reason it exists: a
 * VM must not decide when it runs. Task.run hands the thread to the
 * scheduler until every queue is empty, and while any task waits it
 * sits in the idle hook - a thread that has its own loop, an io_uring
 * worker among them, cannot do that and still serve its own work.
 * mruby-task/ports/glib arrived at the same shape from a GTK main
 * loop; this is that shape without GLib.
 *
 * The answer is microseconds:
 *
 *   0   a task is ready. Call again at once.
 *   > 0 every task is asleep. Call again after this long, or sooner if
 *       the loop has other work - calling early is always allowed.
 *   -1  no VM on this thread has a task. Nothing to come back for.
 *
 * The caller may wait on its own descriptors for that long, which is
 * what makes one loop serve both.
 */
MRB_API int64_t mrb_hal_task_step(void);

MRB_END_DECL
