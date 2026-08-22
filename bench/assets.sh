#!/bin/bash
# Asset delivery (#168): how fast does a body that already exists in
# a mapping reach the wire, per size. ONE arm - there is no second one
# left to compare against, and that is the finding this file records.
#
# WHAT WAS TRIED AND LOST, so nobody re-runs it:
#   - splice through a pipe (pool N against pool 0): 0.99x / 1.01x /
#     0.63x / 0.79x at 4 KiB / 32 KiB / 256 KiB / 1 MiB once the iovec
#     arm stopped copying into the sink first. Every earlier number
#     that favoured splice had compared it against a path that copied
#     TWICE. IORING_OP_SPLICE also has no non-blocking fast path: it
#     is always dispatched to an io-wq worker, so it pays a hop that
#     sendmsg does not.
#   - MSG_SPLICE_PAGES on the sendmsg: no effect at all. 2 GiB in
#     256 KiB chunks, flag on against off, three rounds each: 2001 /
#     2025 / 2147 MB/s against 2158 / 2064 / 2080, system time equal
#     to three decimals. It is an internal kernel sendmsg flag for
#     callers whose iterators are already bvec/kvec; a userspace iovec
#     does not qualify.
#   - IORING_OP_SEND_ZC: not measured, refused on shape - it buys the
#     copy back with a ubuf_info and a SECOND completion per send, and
#     caps in-flight bytes at the RLIMIT_MEMLOCK account (~8 MB).
# So: one kernel copy per body, out of the mapping, in one sendmsg.
#
# Knobs: THREADS/CONNS mandatory (the harness is part of the number),
# SIZES (space-separated asset byte sizes, default "4096 32768 262144
# 1048576"), DURATION (default 10), REPS (default 1), WARM (passed as
# WM_WARM_BUDGET; empty = the built-in default), PORT (default 8123).
# Appends to bench/results/$(hostname).log; failed runs write nothing.
#
# SPREAD, measured on this container: two runs of the IDENTICAL
# configuration (reps=5, medians) disagreed by 20% on the same asset.
# Use REPS>=5 and read the median; a difference under a quarter is
# not answerable here.
#
# NO PINNING - and here the reason is structural, not statistical: the
# moment a server touches a FILE, io_uring spawns an io-wq pool, and
# those workers inherit the issuing thread's affinity. Pinning locks
# the pool that exists to use OTHER cores onto the loop's core. A
# server that never touches a file could be pinned - and would not be
# a web server. It was also measured twice, and lost twice: the
# previous tree removed every taskset it had ("handing the scheduler
# one core was slower than letting it choose"; widening the CLIENT
# mask 2 -> 15 -> 30 cpus raised throughput monotonically in the
# MEDIAN), and back when bodies went through splice a 32 KiB asset
# measured 0.07x its unspliced twin under `taskset -c 0`. The knobs
# are gone rather than defaulted off - they are not something anyone
# should turn on.
#
set -u
cd "$(dirname "$0")/.." || exit 1

[ -n "${THREADS:-}" ] && [ -n "${CONNS:-}" ] || {
  echo "THREADS= and CONNS= are mandatory - the harness is part of the number" >&2
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
# file-backed span, so everything past the head is delivered as
# pointers into the mapping - no deflate middle to muddy the number.
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

start_srv() {  # start_srv <port>
  local port=$1
  local args=(--port "$port" --assets "$WORK/assets.zip")
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

measure() {  # measure <port> <size> -> "rps MB/s"
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
    # h2load switches unit on its own (KB/MB/GB per second), so the
    # column would silently go blank at exactly the sizes it matters
    # for. Normalise to MB/s here rather than trusting the spelling.
    mbs=$(grep '^finished' "$WORK/cli.out" | grep -o '[0-9.]*[KMG]B/s' |
      awk '{ u = substr($0, length($0) - 3, 1); v = substr($0, 1, length($0) - 4) + 0;
             if (u == "K") v /= 1024; else if (u == "G") v *= 1024;
             printf "%.2f", v }')
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
    vals+=("$rps $mbs")
  done
  # median by req/s, carrying its own MB/s along - the two belong to
  # the same run and must not be medianed apart.
  printf '%s\n' "${vals[@]}" | sort -n -k1 | \
    awk -v n="$REPS" 'NR==int((n+1)/2){printf "%.0f %s", $1, ($2 == "" ? "-" : $2)}'
}

{
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD) mruby=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?') ===="
  echo "harness: assets h2load --h1 -m1 -t$THREADS -c$CONNS -D${DURATION} reps=$REPS warm=${WARM:-default} $(uname -mr)"
  s0=$(steal_ticks)
  printf '%10s %14s %12s\n' "size" "req/s" "MB/s"
  # A FRESH PORT PER SIZE. stop_srv reaps the process, but the listening
  # socket is not guaranteed gone by the time the next one binds, and
  # the server refuses a taken port by name (it does not fall back to
  # anything) - so reusing one port turns the sweep into a coin flip.
  port=$PORT
  for sz in $SIZES; do
    start_srv "$port"
    read -r rps mbs <<< "$(measure "$port" "$sz")"
    stop_srv
    port=$((port + 1))
    printf '%10s %14s %12s\n' "$sz" "$rps" "$mbs"
  done
  s1=$(steal_ticks)
  echo "steal +$((s1 - s0)) ticks over the whole sweep"
} | tee -a "$LOG"
