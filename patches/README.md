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

`run_guarded` (`src/application.cpp`) calls it right after `mrb_open`,
but only when the checkout HAS it: mrbgem.rake reads mruby-task's header
and defines `WM_TASK_SCHEDULER_CAN_BE_DISABLED` when the name is there.
So a plain checkout builds and answers requests - it keeps the check and
is slower.

`enabled` sits beside `switching` and not at the front of the struct.
matz asked for that on the pull request, and it is measurably better
here as well: at the front it opened a fresh hole and mrb_state was
24768 bytes, beside `switching` it lands in padding that was already
wasted and mrb_state is 24760. The check loads that word first anyway.

Upstream: mruby/mruby#7491. matz reproduced the slowdown with `-O3
-march=native` and would take the patch. The open question there is not
this flag: the check reads `mrb->task.switching`, then `mrb->c`, then
`mrb->c->status`, and folding those dependent loads would serve every
build rather than the ones that call `mrb_disable_task_scheduler()`.
When it is merged, delete this patch and the fork branch with it.

Apply it to a plain mruby checkout with:

    git -C mruby am -3 ../patches/mruby-task-scheduler-disable.patch

The three commits sit on `4e2bc5c`. On a newer mruby `-3` lets git merge
them.
