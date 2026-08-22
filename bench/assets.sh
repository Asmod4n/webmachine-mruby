#!/bin/bash
# The verdict on splice (#168): pool N against pool 0 (pure iovec),
# same server, same big asset, same client budget - "der Fall 'jeder
# Request wird gespliced' IST der Benchmark". If nothing moves, splice
# leaves the tree (Gebot 10; was nicht gebraucht wird, darf nicht
# existieren). TCP only - AF_UNIX has no splice_write, so a unix leg
# would measure the fallback twice.
#
# Knobs: THREADS/CONNS mandatory (the harness is part of the number),
# DURATION (default 10), REPS (default 1), SIZE (asset bytes, default
# 1048576 - must exceed 65536 or no transfer ever starts), PIN_SRV/
# PIN_CLI (cpu lists for taskset; empty = unpinned), PORT (default
# 8123). Appends to bench/results/$(hostname).log; failed runs write
# nothing.
set -u
cd "$(dirname "$0")/.." || exit 1

[ -n "${THREADS:-}" ] && [ -n "${CONNS:-}" ] || {
  echo "THREADS= and CONNS= are mandatory - the harness is part of the number" >&2
  exit 2
}
DURATION="${DURATION:-10}"
REPS="${REPS:-1}"
SIZE="${SIZE:-1048576}"
PIN_SRV="${PIN_SRV:-}"
PIN_CLI="${PIN_CLI:-}"
PORT="${PORT:-8123}"
BIN=mruby/build/host/bin/webmachine-server
command -v h2load >/dev/null || { echo "h2load not found (nghttp2 package)" >&2; exit 1; }
command -v zip >/dev/null || { echo "zip not found" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }
[ "$SIZE" -gt 65536 ] || { echo "SIZE must exceed one delivery chunk (65536)" >&2; exit 2; }

# One incompressible stored entry: the whole body is the file-backed
# span, so every request past the head is splice (or its iovec twin).
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; kill $SRV 2>/dev/null' EXIT
head -c "$SIZE" /dev/urandom > "$WORK/asset.bin"
(cd "$WORK" && zip -q -0 -X assets.zip asset.bin)

SRV_WRAP=()
[ -n "$PIN_SRV" ] && SRV_WRAP=(taskset -c "$PIN_SRV")
CLI_WRAP=()
[ -n "$PIN_CLI" ] && CLI_WRAP=(taskset -c "$PIN_CLI")

LOG="bench/results/$(hostname).log"
mkdir -p bench/results

steal_ticks() { awk '/^cpu /{print $9}' /proc/stat; }

SRV=
leg() {  # leg <label> <--pipes value or ""> <port>
  local label=$1 pipes=$2 port=$3
  local URL="http://127.0.0.1:$port/asset.bin"
  local args=(--port "$port" --assets "$WORK/assets.zip")
  [ -n "$pipes" ] && args+=(--pipes "$pipes")
  "${SRV_WRAP[@]}" "$BIN" "${args[@]}" >/dev/null 2>"$WORK/srv.log" &
  SRV=$!
  sleep 0.5
  kill -0 $SRV 2>/dev/null || { echo "server died:" >&2; cat "$WORK/srv.log" >&2; exit 1; }
  # Byte proof before any number: both legs must serve the same asset.
  curl -s --max-time 20 "$URL" | cmp -s - "$WORK/asset.bin" || {
    echo "leg '$label': served bytes differ from the asset - no number is written" >&2
    exit 1
  }
  echo "== $label =="
  local vals=()
  for _ in $(seq "$REPS"); do
    local s0 s1 line rps
    s0=$(steal_ticks)
    line=$("${CLI_WRAP[@]}" h2load --h1 -m1 -D"$DURATION" -t"$THREADS" -c"$CONNS" "$URL" 2>&1 |
      grep '^finished')
    s1=$(steal_ticks)
    rps=$(echo "$line" | grep -o '[0-9.]* req/s' | grep -o '^[0-9.]*')
    echo "  $line (steal +$((s1 - s0)) ticks)"
    vals+=("$rps")
  done
  if [ "$REPS" -gt 1 ]; then
    printf '%s\n' "${vals[@]}" | sort -n | awk -v n="$REPS" \
      'NR==int((n+1)/2){m=$1} NR==1{lo=$1} END{printf "  median %.0f req/s (min %.0f, max %.0f)\n", m, lo, $1}'
  fi
  kill $SRV 2>/dev/null
  wait $SRV 2>/dev/null
  SRV=
}

{
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD) mruby=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?') ===="
  echo "harness: assets h2load --h1 -m1 -t$THREADS -c$CONNS -D${DURATION} reps=$REPS size=$SIZE pin_srv=${PIN_SRV:-no} pin_cli=${PIN_CLI:-no} port=$PORT $(uname -mr)"
  leg "spliced (pool derived)" "" "$PORT"
  leg "iovec baseline (--pipes 0)" 0 "$((PORT + 1))"
} | tee -a "$LOG"
