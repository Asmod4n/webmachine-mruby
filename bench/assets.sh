#!/bin/bash
# The verdict on splice (#168): pool N against pool 0 (pure iovec),
# same server, same assets, same client budget - "der Fall 'jeder
# Request wird gespliced' IST der Benchmark". If nothing moves, splice
# leaves the tree (Gebot 10). TCP only - AF_UNIX has no splice_write.
#
# CONCURRENCY IS NOT OPTIONAL HERE, and that is the whole methodology.
# IORING_OP_SPLICE has no non-blocking fast path: io_uring hands it to
# an io-wq worker, so splice buys a SECOND CORE moving bytes while the
# loop thread parses the next request. With one connection there is
# nothing to overlap and the worker hop is pure latency - measured on
# this container at -c1: splice 880 req/s against 2543 for iovec, the
# exact inverse of what the previous tree measured at -c48 (crossover
# at 4 KiB, 16 KiB already 17% behind). A single-connection run of this
# script would produce a number that means the opposite of what it
# looks like, so it refuses below kMinConns.
#
# SPREAD, measured on this container: the size axis resolves (256 KiB
# gave 4.25x for splice, well outside noise), the WARM axis did not -
# a sweep produced arms disagreeing by 2x with no ordering, including
# at settings where the two arms are identical by construction. So use
# REPS>=5 and read the median, and treat a ratio near 1 as "no answer
# here" rather than "no difference".
#
# Knobs: THREADS/CONNS mandatory (the harness is part of the number),
# SIZES (space-separated asset byte sizes, default "4096 32768 262144
# 1048576"), DURATION (default 10), REPS (default 1), WARM (passed as
# WM_WARM_BUDGET; empty = the built-in default), PORT
# (default 8123). Appends to bench/results/$(hostname).log; failed runs
# write nothing.
# SPREAD, measured here: two runs of the IDENTICAL configuration
# (reps=5, medians) disagreed by 20% on the same asset - 2.79x against
# 2.32x at 256 KiB. So a ratio is a finding only when it is far outside
# that, which 256 KiB is (splice wins) and 32 KiB is not. Use REPS>=5,
# read the median, and treat anything within a quarter of 1.0 as "not
# answerable on this machine".
#
# NO PINNING - and here the reason is structural, not statistical: the
# moment a server touches a FILE, io_uring spawns an io-wq pool, and
# those workers inherit the issuing thread's affinity. Pinning locks
# the pool that exists to use OTHER cores onto the loop's core. A
# server that never touches a file could be pinned - and would not be
# a web server. It was also measured twice, and lost twice. The previous tree removed
# every taskset it had ("handing the scheduler one core was slower than
# letting it choose"; widening the CLIENT mask 2 -> 15 -> 30 cpus raised
# throughput monotonically in the MEDIAN). And io-wq workers inherit the
# issuing thread's affinity, so pinning the server pins the pool that
# carries splice: a 32 KiB asset measured 0.07x its unspliced twin under
# `taskset -c 0`. The knobs are gone rather than defaulted off - they
# are not something anyone should turn on.
#
set -u
cd "$(dirname "$0")/.." || exit 1

MIN_CONNS=8

[ -n "${THREADS:-}" ] && [ -n "${CONNS:-}" ] || {
  echo "THREADS= and CONNS= are mandatory - the harness is part of the number" >&2
  exit 2
}
[ "$CONNS" -ge "$MIN_CONNS" ] || {
  echo "REFUSED: CONNS=$CONNS is below $MIN_CONNS. splice buys parallelism (io-wq)," >&2
  echo "  and with too few connections there is nothing to overlap - the number would" >&2
  echo "  say the opposite of what it looks like. See the header of this file." >&2
  exit 2
}
DURATION="${DURATION:-10}"
REPS="${REPS:-1}"
SIZES="${SIZES:-4096 32768 262144 1048576}"
WARM="${WARM:-}"
PORT="${PORT:-8123}"
BIN=mruby/build/host/bin/webmachine-server
command -v h2load >/dev/null || { echo "h2load not found (nghttp2 package)" >&2; exit 1; }
command -v zip >/dev/null || { echo "zip not found" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }

# One incompressible stored entry per size: the whole body is the
# file-backed span, so every request past the head is splice (or its
# iovec twin) - no deflate middle to muddy the comparison.
WORK=$(mktemp -d)
SRV=
trap 'kill $SRV 2>/dev/null; rm -rf "$WORK"' EXIT
for sz in $SIZES; do
  head -c "$sz" /dev/urandom > "$WORK/a$sz.bin"
done
(cd "$WORK" && zip -q -0 -X assets.zip a*.bin)


LOG="bench/results/$(hostname).log"
mkdir -p bench/results
steal_ticks() { awk '/^cpu /{print $9}' /proc/stat; }
# utime+stime of a pid, in ticks. Split after the ") " that ends the
# comm field, so a process name containing spaces cannot shift the
# fields - utime/stime are then items 12 and 13 of the remainder.
cpu_ticks() {
  awk '{ n = index($0, ") "); rest = substr($0, n + 2); split(rest, f, " "); print f[12] + f[13] }' \
    "/proc/$1/stat" 2>/dev/null || echo 0
}
HZ=$(getconf CLK_TCK 2>/dev/null || echo 100)

start_srv() {  # start_srv <--pipes value or ""> <port>
  local pipes=$1 port=$2
  local args=(--port "$port" --assets "$WORK/assets.zip")
  [ -n "$pipes" ] && args+=(--pipes "$pipes")
  local env_pfx=()
  [ -n "$WARM" ] && env_pfx=(env "WM_WARM_BUDGET=$WARM")
  "${env_pfx[@]}" "$BIN" "${args[@]}" >/dev/null 2>"$WORK/srv.log" &
  SRV=$!
  sleep 0.5
  kill -0 $SRV 2>/dev/null || { echo "server died:" >&2; cat "$WORK/srv.log" >&2; exit 1; }
  grep -q "select(2) SHIM" "$WORK/srv.log" 2>/dev/null && {
    echo "REFUSED: the server runs the select shim - a lazy-path number must never enter bench/results/" >&2
    exit 1
  }
}

stop_srv() { kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; SRV=; }

measure() {  # measure <port> <size> -> "rps"
  local port=$1 sz=$2
  local url="http://127.0.0.1:$port/a$sz.bin"
  # Byte proof before any number.
  curl -s --max-time 30 "$url" | cmp -s - "$WORK/a$sz.bin" || {
    echo "size $sz: served bytes differ from the asset - no number is written" >&2
    exit 1
  }
  local vals=()
  for _ in $(seq "$REPS"); do
    local rps s0 s1 c0 c1 cli threads_running
    s0=$(cpu_ticks "$SRV")
    h2load --h1 -m1 -D"$DURATION" -t"$THREADS" -c"$CONNS" "$url" >"$WORK/cli.out" 2>&1 &
    cli=$!
    c0=$(cpu_ticks "$cli")
    # One mid-run sample: a client on a single running thread is
    # measuring itself, whatever -t claimed.
    sleep 1
    threads_running=$(ps -L -p "$cli" -o stat= 2>/dev/null | grep -c '^R' || echo 0)
    wait "$cli" 2>/dev/null
    c1=$(cpu_ticks "$cli")
    s1=$(cpu_ticks "$SRV")
    rps=$(grep '^finished' "$WORK/cli.out" | grep -o '[0-9.]* req/s' | grep -o '^[0-9.]*')
    [ -n "$rps" ] || { echo "h2load produced no number:" >&2; cat "$WORK/cli.out" >&2; exit 1; }
    # THE CLIENT MUST NOT BE THE BOTTLENECK. If h2load burned as much
    # cpu as the server, the figure describes h2load. Named refusal,
    # because a client-bound number in bench/results/ is worse than no
    # number - it looks like a verdict forever after.
    local cu=$((c1 - c0)) su=$((s1 - s0))
    if [ "$su" -gt 0 ] && [ "$cu" -ge "$su" ]; then
      echo "REFUSED: the client spent $((cu * 100 / HZ / DURATION))% of a core against the server's $((su * 100 / HZ / DURATION))%, on $threads_running running client threads." >&2
      echo "  This measures h2load, not webmachine. Raise THREADS, or drive the load from a second machine." >&2
      exit 1
    fi
    vals+=("$rps")
  done
  printf '%s\n' "${vals[@]}" | sort -n | awk -v n="$REPS" 'NR==int((n+1)/2){printf "%.0f", $1}'
}

{
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD) mruby=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?') ===="
  echo "harness: assets h2load --h1 -m1 -t$THREADS -c$CONNS -D${DURATION} reps=$REPS warm=${WARM:-default} $(uname -mr)"
  s0=$(steal_ticks)
  printf '%10s %14s %14s %8s\n' "size" "spliced" "iovec(-p0)" "ratio"
  for sz in $SIZES; do
    start_srv "" "$PORT";        a=$(measure "$PORT" "$sz");        stop_srv
    start_srv 0 "$((PORT + 1))"; b=$(measure "$((PORT + 1))" "$sz"); stop_srv
    printf '%10s %14s %14s %8s\n' "$sz" "$a" "$b" \
      "$(awk -v x="$a" -v y="$b" 'BEGIN{ if (y+0>0) printf "%.2fx", x/y; else print "-" }')"
  done
  s1=$(steal_ticks)
  echo "steal +$((s1 - s0)) ticks over the whole sweep"
} | tee -a "$LOG"
