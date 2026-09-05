#!/bin/bash
# The bench owns the machine for as long as it runs.
#
# A number taken beside whatever else the machine was doing is not a
# number: the server and the client are both one thread, and one
# stranger on their core moves the result more than most changes this
# tree makes. So every process that is not this one goes to +10, and
# this one goes to -10. Children inherit it, which is what puts the
# server and the generator there too.
#
# It REFUSES rather than warns. A run that could not take priority
# produces a line that looks like every other line in the log and is
# not comparable with any of them.
#
# Sourced by bench/assets.sh, bench/floor.sh, bench/h2.sh,
# bench/pipeline.sh and the three foreign-server asset benches.
bench_priority() {
  local self=$$ p
  for p in $(ps -eo pid= 2>/dev/null); do
    [ "$p" = "$self" ] && continue
    renice -n 10 -p "$p" >/dev/null 2>&1
  done
  renice -n -10 -p "$self" >/dev/null 2>&1 || {
    echo "REFUSED: cannot renice (need root or CAP_SYS_NICE). A number taken beside" >&2
    echo "  whatever else this machine was doing is not a number - see bench/priority.sh." >&2
    exit 1
  }
}
