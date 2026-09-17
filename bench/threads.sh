#!/bin/bash
# Where the scaling curve bends: N answering threads against a client of
# N threads, for N from 1 to MAX.
#
# One number per thread count is not the answer - the answer is the
# shape. A server that reads 2.0 times at two threads and 2.1 times at
# eight has found its limit somewhere between, and the bend is the
# thing worth knowing. So this runs the whole ladder and prints the
# factor against one thread beside every rung.
#
# The rungs above the cpu count are the point, not an afterthought. An
# operator who came from a server that spends one thread per connection
# types a number in the hundreds out of habit, and what this server
# does then has to be one of two things: answer more slowly, or refuse
# and say why. Becoming quietly worse is the outcome this ladder is
# built to catch, so every rung records whether the server started at
# all beside what it achieved.
#
# Both sides grow together, which is the only shape that stays fair as
# N rises: a fixed client becomes the limit long before the server
# does. On a host with C logical cpus the run holds 2N of them, so
# N > C/2 is oversubscribed on purpose - that rung says what happens
# when the machine runs out, and it is part of the curve.
#
# Knobs: LADDER (the rungs, default "1 2 3 4 6 8"), RUNS per rung
# (default 5), and every knob bench/floor.sh takes (PROTO, MULTI,
# CONNS, APP, TRANSPORT, DURATION). CONNS stays mandatory, as it is
# there.
#
#   PROTO=h2 MULTI=128 CONNS=62 APP=bench/apps/hello.rb bench/threads.sh
#   LADDER="1 4 16 64 256" CONNS=62 ... bench/threads.sh
#
# Name the rungs rather than a maximum, because a ladder to hundreds is
# a doubling one: 256 rungs of five runs is a night, and a rung at 200
# says nothing a rung at 256 does not.
#
# Three walls stand between here and hundreds, and each one bends the
# curve for its own reason rather than the scheduler's. Read them off
# the harness line before blaming contention:
#
#   Locked memory. Each htgen thread registers a buffer ring of 8 MiB,
#   and the server's rings are charged to the same user. The line says
#   memlock=; when the client's N rings no longer fit, it fails to start
#   and the rung is not a measurement.
#   The submission queue. derive_sq_entries divides the memlock budget
#   by the number of rings, so each ring's queue shrinks as N rises -
#   512 entries up to about 128 rings, 64 at 512 rings with an 8 MiB
#   budget, and no floor under that. A queue that small is a different
#   server, not a busier one.
#   Memory per thread. Each answering thread holds its own VM, its own
#   Http1 and its own provided-buffer pool of kBufCount * kBufSize =
#   8 MiB. At 256 threads that is 2 GiB of buffers before a single
#   request arrives.
#
# Each rung's runs go through floor.sh, so every one of them lands in
# bench/results/$(hostname).log with its own harness line, its two cpu
# numbers and the cpus its threads ran on. This script adds the summary
# table at the end and nothing else: it measures nothing itself.
set -eu
cd "$(dirname "$0")/.."

LADDER="${LADDER:-1 2 3 4 6 8}"
RUNS="${RUNS:-5}"
[ -n "${CONNS:-}" ] || {
  echo "CONNS= is mandatory - the harness is part of the number" >&2
  exit 2
}

RESULTS="bench/results/$(hostname).log"
SUMMARY=$(mktemp)
trap 'rm -f "$SUMMARY" "$SUMMARY.why"' EXIT

# The median of a rung, and its spread as max minus min over the
# median. Five runs are five numbers; one of them is not a measurement.
summarize() {
  sort -n | awk -v n="$1" '
    { v[NR] = $1 }
    END {
      if (NR == 0) { printf "%s\t-\t-\n", n; exit }
      med = (NR % 2) ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2
      printf "%s\t%d\t%.0f\n", n, med, (v[NR] - v[1]) * 100 / med
    }'
}

for n in $LADDER; do
  rungs=$(mktemp)
  refused=0
  broken=0
  for _ in $(seq "$RUNS"); do
    out=$(THREADS="$n" CLIENT_THREADS="$n" bench/floor.sh 2>&1) || true
    printf '%s\n' "$out" | grep -q REFUSED && refused=$((refused + 1))
    got=$(printf '%s\n' "$out" | grep -oE '^responses=[0-9]+ .*rps=[0-9]+' |
      grep -oE 'rps=[0-9]+' | cut -d= -f2)
    if [ -n "$got" ]; then
      printf '%s\n' "$got" >> "$rungs"
    else
      # No rate at all: the server died, the clients did not start, or
      # the run produced nothing. Whatever the reason, the operator who
      # typed this number gets no server, and the rung must say so
      # rather than leave a gap that reads like a missing sample.
      broken=$((broken + 1))
      printf '%s\n' "$out" | tail -3 >> "$SUMMARY.why"
      printf 'rung %s: no rate\n' "$n" >> "$SUMMARY.why"
    fi
  done
  printf '%s\t%s\t%s\n' "$(summarize "$n" < "$rungs")" "$refused" "$broken" >> "$SUMMARY"
  rm -f "$rungs"
done

{
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD) threads ladder ===="
  echo "harness: threads.sh ladder=\"$LADDER\" runs=$RUNS conns=$CONNS proto=${PROTO:-h1} streams=${MULTI:-1} app=${APP:-none} transport=${TRANSPORT:-unix} duration=${DURATION:-10}s"
  echo "host: $(nproc) cpus online"
  echo "threads/clients  median rps  spread  factor  client-bound  no-rate runs"
  awk -F'\t' '
    NR == 1 { base = $2 }
    { printf "%15s  %10s  %5s%%  %5.2f  %12s  %s\n", $1, $2, $3, base ? $2 / base : 0, $4, $5 }
  ' "$SUMMARY"
  [ -s "$SUMMARY.why" ] && { echo "-- what the runs without a rate said --"; cat "$SUMMARY.why"; }
} | tee -a "$RESULTS"
