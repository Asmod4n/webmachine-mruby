#!/bin/bash
# The bench gets the machine where it can, and asks nothing where it
# cannot.
#
# On a machine that is otherwise idle this does nothing worth having:
# the numbers repeat without it. It exists for a machine that is not
# idle - an agent building and testing in the background is enough to
# move a median, and it moves it for one arm of a comparison and not
# the others.
#
# Where it works, the gap is thirty points: -15 for this run, +15 for
# everything else this user runs. Ten does not do it, and +19 is the
# ceiling, so the gap cannot be built from above alone.
#
# Both numbers are deliberate. -15 does not take the machine from the
# system, and +15 does not stop the other work of this user: each side
# still does its job, and the bench goes first at every point where
# they meet. +19 for everything else would starve it instead, which
# buys no accuracy and costs a usable machine.
#
# No sudo, ever. A negative nice value needs RLIMIT_NICE, which is
# granted once to a user and never per run:
#
#   echo 'YOU  -  nice  -15' | sudo tee /etc/security/limits.d/90-bench-nice.conf
#   # log out and in;  ulimit -e  must say 35
#
# Without that grant this is a no-op, not a refusal: the run goes ahead
# and $BENCH_NICE stays 0, which is what the harness line records. A row
# taken at even priority is honest as long as it says so.
#
# What is skipped: the bench's own ancestors. Your login shell is one of
# them, and a nice value raised beyond the limit cannot be lowered
# again. Processes of other users are skipped by the kernel.
bench_priority() {
  BENCH_NICE=0
  renice -n -15 -p $$ >/dev/null 2>&1 || return 0
  BENCH_NICE=1

  local me=$$ p skip=" "
  p=$me
  while [ -n "$p" ] && [ "$p" != "0" ]; do
    skip="$skip$p "
    p=$(awk '{ n = index($0, ") "); rest = substr($0, n + 2); split(rest, f, " "); print f[2] }' \
        "/proc/$p/stat" 2>/dev/null)
  done

  for p in $(ps -u "$(id -u)" -o pid= 2>/dev/null); do
    case "$skip" in *" $p "*) continue ;; esac
    renice -n 15 -p "$p" >/dev/null 2>&1 || true
  done
}
