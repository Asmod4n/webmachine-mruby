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
command -v htgen >/dev/null || { echo "htgen is not on PATH" >&2; exit 2; }
WORK=$(mktemp -d /tmp/wm-ir.XXXXXX)
SOCK="$WORK/bench.sock"
bench_app "$WORK" "{ unix_path: \"$SOCK\" }"

# count SECONDS -> "instructions responses"; 0 seconds sends nothing.
count() {
  valgrind --tool=callgrind --callgrind-out-file="$WORK/cg.$1" "$BIN" "${APP_ARGS[@]}" \
    2>"$WORK/srv.$1" & local srv=$!
  for _ in $(seq 1 600); do [ -S "$SOCK" ] && break; sleep 0.1; done
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
echo "bin=$BIN responses=$responses instructions_per_response=$(( (total - base) / responses ))"
echo "profile=$WORK/cg.$SECS"
