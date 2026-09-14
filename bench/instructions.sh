#!/bin/bash
# Instructions per response, counted by callgrind. A clock on a shared
# host swings 15 percent between two runs of one binary; an instruction
# count of the same run does not move, so a change of 2 percent shows.
#
#   BIN=path/to/webmachine-server bench/instructions.sh
#
# The binary has to be built without AVX-512, because valgrind does not
# decode it, and with line tables if the per-line table is wanted:
#
#   WM_MARCH=x86-64-v3 CFLAGS=-g1 CXXFLAGS=-g1 rake compile
#
# One run with no requests takes the start-up out of the count. The
# profile is left where the last line says, for callgrind_annotate.
#
#   APP        the app, default bench/apps/hello.rb
#   SECONDS_   how long the client runs, default 8
#   CONNS      client connections, default 4
#   STREAMS    h2 streams per connection, default 16
set -u
cd "$(dirname "$0")/.."
. bench/_app.sh
BIN="${BIN:-mruby/build/host/bin/webmachine-server}"
SECS="${SECONDS_:-8}"
CONNS="${CONNS:-4}"
STREAMS="${STREAMS:-16}"
export APP="${APP:-bench/apps/hello.rb}"
export MRBC="${MRBC:-mruby/build/host/mrbc/bin/mrbc}"
command -v valgrind >/dev/null || { echo "valgrind is not installed" >&2; exit 2; }
# valgrind decodes a subset of the instruction set. -march=native builds
# past it, and the server then dies on its first unknown instruction
# with no socket ever opened. The build this wants:
#
#   WM_MARCH=x86-64-v3 CFLAGS=-g1 CXXFLAGS=-g1 rake compile
#
# It is slower than the shipped build, so its count is compared with
# another count of the same kind, never with a rate.
command -v htgen >/dev/null || { echo "htgen is not on PATH" >&2; exit 2; }
WORK=$(mktemp -d /tmp/wm-ir.XXXXXX)
SOCK="$WORK/bench.sock"
bench_config "$WORK"
bench_app "$WORK" "{ unix_path: \"$SOCK\" }"

# count SECONDS -> "instructions responses"; 0 seconds sends nothing.
count() {
  echo "counting: the server starts under callgrind, and $1 seconds of requests follow" >&2
  valgrind --tool=callgrind --callgrind-out-file="$WORK/cg.$1" "$BIN" "${CONF_ARGS[@]}" "${APP_ARGS[@]}" \
    >"$WORK/srv.$1" 2>&1 & local srv=$!
  # callgrind makes the start slow, so the wait is long. A server that
  # died waits for nothing, and a wait that ends with no socket says
  # what the server said - neither is left silent.
  local waited=0
  while [ ! -S "$SOCK" ]; do
    if ! kill -0 "$srv" 2>/dev/null; then
      echo "the server under callgrind ended before it listened:" >&2
      cat "$WORK/srv.$1" >&2
      exit 1
    fi
    sleep 0.5
    waited=$((waited + 1))
    [ $((waited % 20)) -eq 0 ] && echo "  waiting for $SOCK ($((waited / 2))s)" >&2
    if [ "$waited" -ge 600 ]; then
      echo "no socket at $SOCK after 300s. The server said:" >&2
      cat "$WORK/srv.$1" >&2
      kill -TERM "$srv" 2>/dev/null
      exit 1
    fi
  done
  echo "  listening after $((waited / 2))s" >&2
  local responses=0
  if [ "$1" != 0 ]; then
    local out
    out=$(htgen --sock "$SOCK" --conns "$CONNS" --seconds "$1" --path / --h2 --streams "$STREAMS" 2>&1)
    responses=$(echo "$out" | grep -o 'responses=[0-9]*' | cut -d= -f2)
  else
    sleep 2
  fi
  kill -TERM "$srv"; wait "$srv"
  local ir
  ir=$(callgrind_annotate "$WORK/cg.$1" 2>/dev/null | grep -m1 -E "^ *[0-9,]+ .*PROGRAM TOTALS" |
       awk '{gsub(",","",$1); print $1}')
  echo "$ir ${responses:-0}"
}
read -r base _ < <(count 0)
read -r total responses < <(count "$SECS")
[ "${responses:-0}" -gt 0 ] || { echo "no responses - read $WORK/srv.$SECS" >&2; exit 1; }
ROW="bin=$BIN responses=$responses instructions_per_response=$(( (total - base) / responses ))"
echo "$ROW"
echo "profile=$WORK/cg.$SECS"

# This count is the only number of this tree that may be read beside a
# run from another session: a rate belongs to one machine and one build,
# an instruction count does not move between runs of one binary, and
# WM_MARCH pins the ISA so two sessions compile the same one. Written
# down for exactly that reason - a comparison across sessions needs the
# older row to still exist.
RESULTS="bench/results/$(hostname)-instructions.log"
mkdir -p "$(dirname "$RESULTS")"
{
  echo
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD 2>/dev/null) ===="
  echo "harness: htgen --conns $CONNS --streams $STREAMS --seconds $SECS h2 (callgrind) WM_MARCH=${WM_MARCH:-unset}"
  . bench/buildline.sh
  wm_build_line "$BIN"
  echo "$ROW"
} >> "$RESULTS"
echo "recorded in $RESULTS"
