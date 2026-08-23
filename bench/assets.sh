#!/bin/bash
# Asset delivery (#168): how fast does a body that already exists in
# a mapping reach the wire, per size and per DELIVERY SHAPE.
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
# THE ARMS are the four shapes the tier actually serves, and they are
# different code, not the same code at different sizes:
#   stored  method 0, identity - ONE span, the mapping straight out.
#   gzip    method 8 - THREE segments (constant gzip header, the
#           deflate bytes where they lie, the trailer). Its wire is
#           the compressed size, so its MB/s is not comparable to
#           stored's at the same nominal size: read the wire column.
#   304     If-None-Match hit - header section only, no body at all.
#           The upper bound of the tier: everything past the head is
#           gone, so what is left is parse + verdict + one send.
#   206     Range over the stored entry - the only per-request BUILT
#           head in the tier (three request-dependent numbers no
#           prebuild can hold), against a prebuilt one at the same
#           size in the stored row.
# ARMS picks them ("stored gzip 304 206"); ARMS=stored reproduces the
# single-arm sweep this file used to be.
#
# SETUP is the other half, and nothing else measures it: Assets::open
# runs ONCE per process over the whole Central Directory. Timed as a
# difference of two boots (many entries against one), so mruby boot
# and ring init cancel out and what remains is per-entry setup.
#
# Knobs: THREADS/CONNS mandatory (the harness is part of the number),
# SIZES (space-separated asset byte sizes, default "4096 32768 262144
# 1048576"), ARMS (default all four), DURATION (default 10), REPS
# (default 1), WARM (passed as WM_WARM_BUDGET; empty = the built-in
# default), PORT (default 8123), SETUP_ENTRIES (default 5000, 0 skips).
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
ARMS="${ARMS:-stored gzip 304 206}"
WARM="${WARM:-}"
PORT="${PORT:-8123}"
SETUP_ENTRIES="${SETUP_ENTRIES:-5000}"
BIN=mruby/build/host/bin/webmachine-server
command -v h2load >/dev/null || { echo "h2load not found (nghttp2 package)" >&2; exit 1; }
command -v zip >/dev/null || { echo "zip not found" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }
for a in $ARMS; do
  case "$a" in
    stored|gzip|304|206) ;;
    *) echo "unknown arm '$a' - pick from: stored gzip 304 206" >&2; exit 2 ;;
  esac
done

WORK=$(mktemp -d)
SRV=
trap 'kill $SRV 2>/dev/null; rm -rf "$WORK"' EXIT

# Two entries per size, because the two delivery shapes need two
# different bodies and the ZIP METHOD is what selects the shape:
#   a$sz.bin  urandom, forced stored (-0) - the whole body is the
#             file-backed span, nothing deflate-shaped in the middle.
#   t$sz.txt  this tree's own sources, repeated to length, deflated
#             (-9). Real text, so the ratio is a ratio an asset pack
#             actually gets - not the 1000:1 a repeated line would
#             flatter the gzip arm with.
cat src/*.cpp src/*.hpp > "$WORK/corpus" 2>/dev/null
[ -s "$WORK/corpus" ] || { echo "no src/ corpus to build a compressible fixture from" >&2; exit 1; }
CORPUS_LEN=$(wc -c < "$WORK/corpus")
for sz in $SIZES; do
  head -c "$sz" /dev/urandom > "$WORK/a$sz.bin"
  n=$(( (sz + CORPUS_LEN - 1) / CORPUS_LEN ))
  for _ in $(seq "$n"); do cat "$WORK/corpus"; done | head -c "$sz" > "$WORK/t$sz.txt"
done
(cd "$WORK" && zip -q -0 -X assets.zip a*.bin && zip -q -9 -X assets.zip t*.txt)

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

start_srv() {  # start_srv <port> [zip]
  local port=$1 zip=${2:-$WORK/assets.zip}
  local args=(--port "$port" --assets "$zip")
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

# arm_setup <port> <arm> <size> - fills ARM_URL / ARM_HDRS / ARM_WIRE
# and PROVES the shape before any number is taken. Every arm proves
# something the next arm cannot: identity bytes, gzip bytes AND the
# coding, the 304 status, the 206 status AND the slice.
ARM_URL= ARM_WIRE=0
ARM_HDRS=()
arm_setup() {
  local port=$1 arm=$2 sz=$3
  local base="http://127.0.0.1:$port"
  ARM_HDRS=()
  case "$arm" in
    stored)
      ARM_URL="$base/a$sz.bin"
      curl -s --max-time 30 "$ARM_URL" | cmp -s - "$WORK/a$sz.bin" || {
        echo "size $sz stored: served bytes differ from the asset - no number is written" >&2
        exit 1
      }
      ;;
    gzip)
      ARM_URL="$base/t$sz.txt"
      # The coding first: without this the arm silently degrades into
      # a second, slower stored row and nobody would see it.
      curl -s --max-time 30 -D "$WORK/h" -o /dev/null -H 'accept-encoding: gzip' "$ARM_URL"
      grep -qi '^content-encoding: *gzip' "$WORK/h" || {
        echo "size $sz gzip: no Content-Encoding: gzip - the entry was not stored as method 8" >&2
        exit 1
      }
      curl -s --max-time 30 --compressed "$ARM_URL" | cmp -s - "$WORK/t$sz.txt" || {
        echo "size $sz gzip: decoded bytes differ from the asset - no number is written" >&2
        exit 1
      }
      ARM_HDRS=(-H 'accept-encoding: gzip')
      ;;
    304)
      ARM_URL="$base/a$sz.bin"
      # Ask the server for its own ETag rather than recomputing the
      # CRC here - the header under test is the one that must match.
      local etag code
      etag=$(curl -s --max-time 30 -o /dev/null -D - "$ARM_URL" |
             awk 'tolower($1) == "etag:" { print $2 }' | tr -d '\r')
      [ -n "$etag" ] || { echo "size $sz 304: the 200 carried no ETag" >&2; exit 1; }
      code=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
             -H "if-none-match: $etag" "$ARM_URL")
      [ "$code" = 304 ] || { echo "size $sz 304: If-None-Match returned $code" >&2; exit 1; }
      ARM_HDRS=(-H "if-none-match: $etag")
      ;;
    206)
      ARM_URL="$base/a$sz.bin"
      local half=$((sz / 2)) code
      head -c "$half" "$WORK/a$sz.bin" > "$WORK/slice"
      code=$(curl -s --max-time 30 -o "$WORK/got" -w '%{http_code}' \
             -H "range: bytes=0-$((half - 1))" "$ARM_URL")
      [ "$code" = 206 ] || { echo "size $sz 206: Range returned $code" >&2; exit 1; }
      cmp -s "$WORK/got" "$WORK/slice" || {
        echo "size $sz 206: the served window is not the asset's first $half bytes" >&2
        exit 1
      }
      ARM_HDRS=(-H "range: bytes=0-$((half - 1))")
      ;;
  esac
  # The wire body, asked of the server instead of derived: curl without
  # --compressed does not decode, so size_download IS what crossed the
  # socket. 304 answers 0 and that is the point of the row.
  ARM_WIRE=$(curl -s --max-time 30 -o /dev/null -w '%{size_download}' \
             "${ARM_HDRS[@]}" "$ARM_URL")
}

measure() {  # measure <arm> <size> -> "rps MB/s"
  local arm=$1 sz=$2
  local vals=()
  for _ in $(seq "$REPS"); do
    local rps s0 s1 c0 c1 cli threads_running
    s0=$(cpu_ticks "$SRV")
    h2load --h1 -m1 -D"$DURATION" -t"$THREADS" -c"$CONNS" "${ARM_HDRS[@]}" "$ARM_URL" \
      >"$WORK/cli.out" 2>&1 &
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
    # number - it looks like a verdict forever after. The bodyless arms
    # (304, and 206 at small sizes) hit this first: they are where the
    # server has least to do, so they need the most client threads.
    local cu=$((c1 - c0)) su=$((s1 - s0))
    if [ "$su" -gt 0 ] && [ "$cu" -ge "$su" ]; then
      echo "REFUSED on arm $arm, size $sz: the client spent $((cu * 100 / HZ / DURATION))% of a core against the server's $((su * 100 / HZ / DURATION))%, on $threads_running running client threads." >&2
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

# boot_ns <zip> <port> - "min max" nanoseconds from exec to the first
# accepted connection, over five tries. Both ends, because the SPREAD
# is what says whether a difference of two boots means anything.
boot_ns() {
  local zip=$1 port=$2 lo= hi= t0 t1 d
  for _ in 1 2 3 4 5; do
    t0=$(date +%s%N)
    "$BIN" --port "$port" --assets "$zip" >/dev/null 2>"$WORK/boot.log" &
    SRV=$!
    # Busy poll, no sleep: the whole quantity being measured is smaller
    # than the shortest sleep this shell can take.
    while ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do
      kill -0 $SRV 2>/dev/null || { echo "server died during boot timing:" >&2; cat "$WORK/boot.log" >&2; exit 1; }
    done
    t1=$(date +%s%N)
    stop_srv
    d=$((t1 - t0))
    [ -n "$lo" ] || { lo=$d; hi=$d; }
    [ "$d" -lt "$lo" ] && lo=$d
    [ "$d" -gt "$hi" ] && hi=$d
    port=$((port + 1))
  done
  echo "$lo $hi"
}

{
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD) mruby=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?') ===="
  echo "harness: assets h2load --h1 -m1 -t$THREADS -c$CONNS -D${DURATION} reps=$REPS warm=${WARM:-default} $(uname -mr)"
  s0=$(steal_ticks)
  printf '%10s %8s %14s %12s %12s\n' "size" "arm" "req/s" "MB/s" "wire"
  # A FRESH PORT PER SIZE. stop_srv reaps the process, but the listening
  # socket is not guaranteed gone by the time the next one binds, and
  # the server refuses a taken port by name (it does not fall back to
  # anything) - so reusing one port turns the sweep into a coin flip.
  port=$PORT
  for sz in $SIZES; do
    for arm in $ARMS; do
      start_srv "$port"
      arm_setup "$port" "$arm" "$sz"
      read -r rps mbs <<< "$(measure "$arm" "$sz")"
      stop_srv
      port=$((port + 1))
      printf '%10s %8s %14s %12s %12s\n' "$sz" "$arm" "$rps" "$mbs" "$ARM_WIRE"
    done
  done
  s1=$(steal_ticks)
  echo "steal +$((s1 - s0)) ticks over the whole sweep"

  if [ "$SETUP_ENTRIES" -gt 0 ]; then
    # Assets::open, the once-per-process half. One entry against many,
    # subtracted: mruby boot, ring init and bind are identical in both
    # legs, so the difference is the Central Directory walk plus the
    # per-entry prebuild (heads, ETag, gzip framing) and nothing else.
    mkdir -p "$WORK/many"
    i=0
    while [ "$i" -lt "$SETUP_ENTRIES" ]; do
      printf 'e%d' "$i" > "$WORK/many/e$i.txt"
      i=$((i + 1))
    done
    printf 'one' > "$WORK/one.txt"
    (cd "$WORK" && zip -q -0 -X one.zip one.txt && cd many && zip -q -0 -X ../many.zip e*.txt >/dev/null) || {
      echo "could not build the setup fixtures" >&2; exit 1; }
    read -r one_lo one_hi <<< "$(boot_ns "$WORK/one.zip" "$port")"; port=$((port + 8))
    read -r many_lo _ <<< "$(boot_ns "$WORK/many.zip" "$port")"; port=$((port + 8))
    delta=$((many_lo - one_lo))
    jitter=$((one_hi - one_lo))
    printf 'setup: 1 entry %dus, %d entries %dus (boot floor, min of 5; floor jitter %dus)\n' \
      $((one_lo / 1000)) "$SETUP_ENTRIES" $((many_lo / 1000)) $((jitter / 1000))
    # Divide only when the difference outruns the floor's own spread.
    # At a few hundred entries it does not, and a per-entry figure
    # computed there is jitter with a unit attached - it came out
    # NEGATIVE at 200 entries on this container, which is the whole
    # reason this refusal exists.
    if [ "$delta" -gt "$jitter" ]; then
      echo "setup: => $((delta / (SETUP_ENTRIES - 1)))ns per entry"
    else
      echo "setup: => not separable - the difference (${delta}ns) is inside the floor's jitter." \
           "Raise SETUP_ENTRIES until it is not."
    fi
  fi
} | tee -a "$LOG"
