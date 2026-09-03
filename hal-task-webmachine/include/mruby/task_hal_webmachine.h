#pragma once

#include <mruby.h>

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

MRB_END_DECL
