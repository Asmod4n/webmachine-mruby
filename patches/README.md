# Patches this tree carries until upstream has them

## mruby-task-scheduler-disable.patch

Three commits against mruby `4e2bc5c`. They add
`mrb_disable_task_scheduler()` and `mrb_task_scheduler_enabled_p()`, so
an embedder can turn the scheduler off for ONE `mrb_state`.

This tree needs it because a build has `MRB_USE_TASK_SCHEDULER` for the
WORKERS, and the define reaches every VM: `mrb_vm_exec` then evaluates
`RETURN_IF_TASK_STOPPED` at every opcode (`mruby/src/vm.c:2267`), and
only `task.enabled` can turn that off at run time. The reactor's VM runs
no task and pays that check on every request.

`run_guarded` (`src/application.cpp`) calls it right after `mrb_open`.

Upstream: mruby/mruby#7491. When it is merged, delete this patch and the
fork branch with it.

Apply it to a plain mruby checkout with:

    git -C mruby am ../patches/mruby-task-scheduler-disable.patch
