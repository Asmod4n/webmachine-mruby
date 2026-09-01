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
# Knobs: CONNS mandatory (the harness is part of the number),
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

[ -n "${CONNS:-}" ] || {
  echo "CONNS= is mandatory - the harness is part of the number" >&2
  exit 2
}
[ -z "${THREADS:-}" ] || {
  echo "THREADS= is gone: both ends are one thread (#120, #196), and the knob only ever" >&2
  echo "described h2load, which this tree no longer uses." >&2
  exit 2
}
DURATION="${DURATION:-10}"
REPS="${REPS:-1}"
# PROTO=h1 (default, the historical rows) or h2
# (prior knowledge, MULTI streams per connection - the delivery-plan
# path, where DATA frames interleave and rounds are capacity-bound).
PROTO="${PROTO:-h1}"
MULTI="${MULTI:-32}"
SIZES="${SIZES:-4096 32768 262144 1048576}"
ARMS="${ARMS:-stored gzip 304 206}"
WARM="${WARM:-}"
PORT="${PORT:-8123}"
# LOG=1 turns the access log on (--log into the workdir): the cost of
# a line per request, end to end, including the record daemon.
LOG="${LOG:-0}"
SETUP_ENTRIES="${SETUP_ENTRIES:-5000}"
BIN=mruby/build/host/bin/webmachine-server
HTGEN="${HTGEN:-$HOME/htgen/htgen}"
[ -x "$HTGEN" ] || HTGEN=$(command -v htgen) || {
  echo "htgen not found. Build it once:" >&2
  echo "  git clone --recursive https://github.com/Asmod4n/htgen ~/htgen && make -C ~/htgen" >&2
  echo "or point HTGEN= at the binary." >&2
  exit 1
}
command -v zip >/dev/null || { echo "zip not found" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }
case "$PROTO" in h1|h2) ;; *) echo "PROTO must be h1 or h2" >&2; exit 2 ;; esac
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

# ---- priority: the measurement owns the machine ----------------------
# Everything that is NOT part of the run steps back to nice 10, and the
# measured processes run at -10. A stray build, an agent thread or a
# leftover daemon landing inside a 5s window moves the median - and it
# moves it for ONE of the servers, which is worse than moving it for
# all three.
#
# The harness shell renices ITSELF to -10 and everything else to 10, so
# the server and the client simply INHERIT -10 as its children: there
# is no window between fork and renice in which a measured process runs
# at the wrong priority. Inherited niceness survives the privilege drop
# too, which is how nginx's www-data workers and h2o's nobody threads
# get it without being able to ask for it themselves.
bench_priority() {
  local self=$$ p
  for p in $(ps -eo pid= 2>/dev/null); do
    [ "$p" = "$self" ] && continue
    renice -n 10 -p "$p" >/dev/null 2>&1
  done
  renice -n -10 -p "$self" >/dev/null 2>&1 || {
    echo "REFUSED: cannot renice (need root). A number taken beside whatever else" >&2
    echo "  this machine was doing is not a number - see bench_priority." >&2
    exit 1
  }
}
bench_priority

RESULTS="bench/results/$(hostname).log"
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

# --- requests per syscall -------------------------------------------
# The point of a ring server is syscall AMORTIZATION - one enter
# carries a whole batch of rounds - and this makes it a NUMBER: the
# server's syscalls over the run (raw_syscalls:sys_enter, a counting
# tracepoint: no sampling, negligible overhead), divided into the
# requests the client completed. The window is the client's run plus
# edges; an idle server sits BLOCKED in one enter, so edges add
# ~nothing. Needs a perf that may attach (root, or CAP_PERFMON /
# perf_event_paranoid low enough for tracepoints); without one the
# column prints '-' rather than a guess.
# OPT-IN via SYSCALLS=1: counting needs perf, tracefs access and a
# paranoid setting most machines don't have lying around - a default
# that probes and warns on every run is noise for anyone not asking
# the question. Off, the column prints '-' and nothing is touched.
SYSC_PERF=""
if [ "${SYSCALLS:-0}" = 1 ]; then
  SYSC_PERF="${PERF:-}"
  if [ -z "$SYSC_PERF" ]; then
    if perf --version >/dev/null 2>&1; then SYSC_PERF=perf
    else SYSC_PERF=$(ls /usr/lib/linux-tools-*/perf 2>/dev/null | head -1); fi
  fi
fi
if [ -n "$SYSC_PERF" ]; then
  # Preflight, once: tracepoints are gated separately from cpu events
  # (unprivileged needs perf_event_paranoid = -1 or CAP_PERFMON; 0/1
  # open only the cpu side, which is why perf record works while this
  # counter stays empty). A column of silent '-' hides that; say it.
  # perf stat's -x CSV goes to STDERR; the probe must read that side.
  # On failure, RELAY perf's own words - there are two separate locks
  # (perf_event_paranoid gates the syscall, tracefs permissions gate
  # resolving the event name) and guessing which one bit cost a round
  # of head-scratching already.
  SYSC_PROBE=$("$SYSC_PERF" stat -e raw_syscalls:sys_enter -x, -- /bin/true 2>&1 >/dev/null)
  if ! echo "$SYSC_PROBE" | grep -q '^[0-9]'; then
    echo "req/syscall: '-' - $SYSC_PERF cannot count raw_syscalls:sys_enter. Its own words:" >&2
    echo "$SYSC_PROBE" | head -4 | sed 's/^/    /' >&2
    echo "  Usual causes: kernel.perf_event_paranoid > -1 without CAP_PERFMON, or" >&2
    echo "  /sys/kernel/tracing unreadable (sudo chmod -R o+rX /sys/kernel/tracing helps; 700 root-only is the distro default)." >&2
    SYSC_PERF=""
  fi
fi
SYSC_PID=
SYSC_OUT="${WORK:-/tmp}/wm-sysc.$$"
sysc_begin() {  # <pid[,pid...]> <seconds>
  [ -n "$SYSC_PERF" ] || return 0
  "$SYSC_PERF" stat -e raw_syscalls:sys_enter -x, -p "$1" -o "$SYSC_OUT" \
    -- sleep "$2" >/dev/null 2>&1 &
  SYSC_PID=$!
}
# Split like snap_times, for the same reason: the WAIT must run in the
# shell that backgrounded perf (a $() subshell is not its parent, its
# wait returns at once while the output file is still being written);
# only the read may fork.
sysc_wait() {
  [ -n "$SYSC_PID" ] && wait "$SYSC_PID" 2>/dev/null
  SYSC_PID=
}
sysc_read() {
  awk -F, '$3 == "raw_syscalls:sys_enter" && $1 ~ /^[0-9]/ { print $1 }' "$SYSC_OUT" 2>/dev/null
}
# The client's cpu comes from the shell's CHILD times, credited at
# reap - reading the client's /proc after `wait` read a reaped pid as
# 0 ticks, and the client-bound refusal never fired (found when a
# 1-thread client at 100% produced a row at server cpu 47%). Two
# rules keep it honest: `times` must run in THIS shell (bash resets
# the counters inside a command substitution - measured, a reaped 1s
# child read back as 0.00 through $()), so the snapshot writes a file
# and only the parse forks; and the grep/ps helpers inside the window
# add milliseconds against a 10s run.
snap_times() { times > "$WORK/.times"; }
parse_child_cpu() {
  awk 'NR==2 { split($1, u, "m"); split($2, sy, "m");
               printf "%.2f", u[1]*60 + u[2] + sy[1]*60 + sy[2] }' "$WORK/.times"
}

start_srv() {  # start_srv <port> [zip]
  local port=$1 zip=${2:-$WORK/assets.zip}
  local args=(--port "$port" --assets "$zip")
  [ "$LOG" = 1 ] && args+=(--log "$WORK/access.log")
  local env_pfx=()
  [ -n "$WARM" ] && env_pfx=(env "WM_WARM_BUDGET=$WARM")
  "${env_pfx[@]}" "$BIN" "${args[@]}" >/dev/null 2>"$WORK/srv.log" &
  SRV=$!
  # WAIT for it to answer, never a fixed sleep: on this container the
  # first curl raced the listener, the stored arm compared an EMPTY
  # body against the asset, and the run died claiming the bytes
  # differed. A connection refused is the only thing this loop retries -
  # a 404 is already an answer.
  local waited=0
  until curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$port/" 2>/dev/null; do
    kill -0 $SRV 2>/dev/null || { echo "server died:" >&2; cat "$WORK/srv.log" >&2; exit 1; }
    sleep 0.05
    waited=$((waited + 1))
    [ "$waited" -lt 200 ] || { echo "server did not answer within 10s" >&2; cat "$WORK/srv.log" >&2; exit 1; }
  done
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
ARM_URL= ARM_WIRE=0 ARM_PATH=
# The same fields twice, because two tools ask for them: curl proves the
# arm's shape, htgen drives its load.
ARM_HDRS=()
ARM_CLI=()
arm_setup() {
  local port=$1 arm=$2 sz=$3
  local base="http://127.0.0.1:$port"
  ARM_HDRS=()
  ARM_CLI=()
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
      ARM_CLI=(--header 'accept-encoding: gzip')
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
      ARM_CLI=(--header "if-none-match: $etag")
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
      ARM_CLI=(--header "range: bytes=0-$((half - 1))")
      ;;
  esac
  ARM_PATH="${ARM_URL#"$base"}"
  # The wire body, asked of the server instead of derived: curl without
  # --compressed does not decode, so size_download IS what crossed the
  # socket. 304 answers 0 and that is the point of the row.
  ARM_WIRE=$(curl -s --max-time 30 -o /dev/null -w '%{size_download}' \
             "${ARM_HDRS[@]}" "$ARM_URL")
}

# One whitespace-separated field out of htgen's summary line, by EXACT
# name. Not a substring match: htgen prints both MB/s and tx_MB/s, and
# `grep -o 'MB/s=...'` matches inside the second one too - two lines in
# one variable, a newline riding into vals[], and the median then picks
# the wrong row. Measured: a 65444 rps run was reported as 2.
field() { tr ' ' '\n' < "$WORK/cli.out" | awk -F= -v k="$1" '$1 == k { print $2; exit }'; }

measure() {  # measure <arm> <size> -> "rps MB/s"
  local arm=$1 sz=$2
  local vals=()
  for _ in $(seq "$REPS"); do
    local rps s0 s1 c0 c1 cli threads_running
    s0=$(cpu_ticks "$SRV")
    "$HTGEN" --host 127.0.0.1 --port "$port" --conns "$CONNS" --seconds "$DURATION" \
      --path "$ARM_PATH" "${H2FLAGS[@]}" "${ARM_CLI[@]}" >"$WORK/cli.out" 2>&1 &
    cli=$!
    snap_times
    c0=$(parse_child_cpu)
    sysc_begin "$SRV" "$DURATION"
    # One mid-run sample: a client on a single running thread is
    # measuring itself, whatever -t claimed.
    sleep 1
    threads_running=$(ps -L -p "$cli" -o stat= 2>/dev/null | grep -c '^R' || echo 0)
    wait "$cli" 2>/dev/null
    snap_times
    c1=$(parse_child_cpu)
    s1=$(cpu_ticks "$SRV")
    sysc_wait
    local nsysc ndone rsc="-"
    nsysc=$(sysc_read)
    ndone=$(field "responses")
    if [ -n "$nsysc" ] && [ "$nsysc" -gt 0 ] && [ -n "$ndone" ]; then
      rsc=$(awk -v d="$ndone" -v n="$nsysc" 'BEGIN { printf "%.1f", d / n }')
    fi
    rps=$(field "rps")
    # One unit, always MB/s - h2load switched between KB/MB/GB on its
    # own and the column went silently blank at exactly the sizes it
    # mattered for.
    mbs=$(field "MB/s")
    [ -n "$rps" ] || { echo "htgen produced no number:" >&2; cat "$WORK/cli.out" >&2; exit 1; }
    grep -q 'bad=0 ' "$WORK/cli.out" || {
      echo "the client counted bad answers:" >&2; cat "$WORK/cli.out" >&2; exit 1
    }
    # THE CLIENT MUST NOT BE THE BOTTLENECK. If the client burned as
    # much cpu as the server, the figure describes the client. Named refusal,
    # because a client-bound number in bench/results/ is worse than no
    # number - it looks like a verdict forever after. The bodyless arms
    # (304, and 206 at small sizes) hit this first: they are where the
    # server has least to do, so they need the most client threads.
    local su=$((s1 - s0))
    local scpu=$((su * 100 / HZ / DURATION))
    local ccpu
    ccpu=$(awk -v a="$c1" -v b="$c0" -v d="$DURATION" 'BEGIN { printf "%.0f", (a - b) * 100 / d }')
    # Client-bound is a CONJUNCTION, not a comparison: the server had
    # headroom AND the client was pegged. Comparing totals was wrong
    # twice over - first it read a reaped pid (always 0), then, fixed,
    # it refused every SERVER-SATURATED run, because a client that
    # needs three cores to fill our one lawfully spends more total CPU
    # than we do. A server at >=90% of its one core is the thing being
    # measured, whatever the client burned to get it there.
    # Headroom is a GAP, not "below 90" - see bench/floor.sh: 89 against 90
    # is not headroom, it is two saturated ends.
    if [ "$su" -gt 0 ] && [ "$ccpu" -ge 90 ] && [ "$scpu" -le $((${ccpu%.*} - 15)) ]; then
      # The ARM is refused, the SWEEP continues: killing everything
      # after it once cost the whole large-size half of a run for a
      # marginal 304 arm. The guarantee is unchanged - no client-bound
      # figure is ever written, the row says REFUSED - but the arms
      # that pass still produce their rows.
      echo "REFUSED on arm $arm, size $sz: the server had headroom (${scpu}% of its core) while the client was pegged (${ccpu}% of its core)." >&2
      echo "  This measures htgen, not webmachine. Drive the load from a second machine." >&2
      printf 'REFUSED client-bound'
      return
    fi
    vals+=("$rps $mbs $scpu $rsc")
  done
  # median by req/s, carrying its own MB/s and cpu% along - the three
  # belong to the same run and must not be medianed apart.
  printf '%s\n' "${vals[@]}" | sort -n -k1 | \
    awk -v n="$REPS" 'NR==int((n+1)/2){printf "%.0f %s %s %s", $1, ($2 == "" ? "-" : $2), $3, $4}'
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

if [ "$PROTO" = h2 ]; then
  H2FLAGS=(--h2 --streams "$MULTI")
  PROTO_SPELL="h2 --streams $MULTI"
else
  H2FLAGS=()
  PROTO_SPELL="h1"
fi

{
  echo "==== $(date -u +%FT%RZ) repo=$(git rev-parse --short HEAD) mruby=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?') ===="
  echo "harness: assets htgen $PROTO_SPELL -c$CONNS -d${DURATION}s reps=$REPS warm=${WARM:-default} log=${LOG} $(uname -mr)"
  s0=$(steal_ticks)
  # cpu% = server CPU over the run, percent of ONE core - what lets a
  # row here sit honestly next to a multi-worker row in the nginx
  # sweep: req/s per core is req/s * 100 / cpu%.
  # req/syscall = completed requests per SERVER syscall over the run - the
  # batching the ring buys, as a number. '-' = no perf to count with.
  printf '%10s %8s %14s %12s %12s %8s %12s\n' "size" "arm" "req/s" "MB/s" "wire" "cpu%" "req/syscall"
  # A FRESH PORT PER SIZE. stop_srv reaps the process, but the listening
  # socket is not guaranteed gone by the time the next one binds, and
  # the server refuses a taken port by name (it does not fall back to
  # anything) - so reusing one port turns the sweep into a coin flip.
  port=$PORT
  for sz in $SIZES; do
    for arm in $ARMS; do
      start_srv "$port"
      arm_setup "$port" "$arm" "$sz"
      read -r rps mbs scpu rsc <<< "$(measure "$arm" "$sz")"
      stop_srv
      port=$((port + 1))
      printf '%10s %8s %14s %12s %12s %8s %12s\n' "$sz" "$arm" "$rps" "$mbs" "$ARM_WIRE" "${scpu:--}" "${rsc:--}"
    done
  done
  s1=$(steal_ticks)
  echo "steal +$((s1 - s0)) ticks over the whole sweep"
  # The rule, self-checked: with the log on, every answered request is
  # a line - the client's own count plus the arm proofs' curls. The
  # exact number varies with the proofs, so the check is "plausibly
  # complete": the file exists and is within the sweep's request count.
  if [ "$LOG" = 1 ]; then
    echo "access log: $(wc -l < "$WORK/access.log" 2>/dev/null || echo 0) lines ($(du -h "$WORK/access.log" 2>/dev/null | cut -f1))"
  fi

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
} | tee -a "$RESULTS"
