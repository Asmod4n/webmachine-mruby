#!/bin/bash
# The SAME asset sweep as bench/assets.sh, served by h2o with
# file.send-gzip - the second production equivalent of this tree's
# asset tier, beside bench/nginx-assets.sh. One log, same columns, same
# refusals, so all three sets of rows sit next to each other and mean
# the same thing.
#
# WHAT H2O GETS, deliberately its best foot:
#   num-threads WORKERS (default 1 - apples to our one thread; h2o's
#     workers are THREADS in one process, so the cpu column is that
#     one pid and needs no summing),
#   no access-log at all (h2o has no "off" - the directive is simply
#     absent), file.send-gzip ON (serve t*.txt.gz as-is, no runtime
#     deflate), max-connections raised past CONNS, and h2o's own
#     per-thread open-file cache, which is on by default and is the
#     thing nginx needs open_file_cache for.
#
# ARM MAPPING: stored = the plain file, identity. gzip = t*.txt with
# Accept-Encoding and a .gz sibling (gzip -9, same corpus as
# bench/assets.sh: this tree's sources repeated). 304 = If-None-Match
# with h2o's own ETag. 206 = first-half Range on the stored file.
#
# ONE h2o instance serves the whole sweep, as with nginx.
#
# RUNS AS nobody: h2o started as root drops to nobody unless `user`
# says otherwise, so the docroot is made world-traversable. Same shape
# as the nginx arm dropping to www-data.
#
# Knobs as in assets.sh: CONNS mandatory, SIZES, ARMS, PROTO
# (h1 default, h2 = prior knowledge with --streams MULTI), MULTI,
# DURATION, REPS, PORT, WORKERS, H2O (binary override).
set -u
cd "$(dirname "$0")/.." || exit 1

[ -n "${CONNS:-}" ] || {
  echo "CONNS= is mandatory - the harness is part of the number" >&2
  exit 2
}
DURATION="${DURATION:-10}"
REPS="${REPS:-1}"
SIZES="${SIZES:-4096 32768 262144 1048576}"
ARMS="${ARMS:-stored gzip 304 206}"
PROTO="${PROTO:-h1}"
MULTI="${MULTI:-32}"
PORT="${PORT:-8123}"
WORKERS="${WORKERS:-1}"
H2O="${H2O:-h2o}"
command -v "$H2O" >/dev/null || { echo "h2o not found (set H2O=)" >&2; exit 1; }
[ -z "${THREADS:-}" ] || {
  echo "THREADS= is gone: the client is one thread (#196), and the knob only ever" >&2
  echo "described h2load, which this tree no longer uses." >&2
  exit 2
}
HTGEN="${HTGEN:-$HOME/htgen/htgen}"
[ -x "$HTGEN" ] || HTGEN="$PWD/../htgen/htgen"   # a clone beside this one
[ -x "$HTGEN" ] || HTGEN=$(command -v htgen) || {
  echo "htgen not found. Build it once:" >&2
  echo "  git clone --recursive https://github.com/Asmod4n/htgen ~/htgen && make -C ~/htgen" >&2
  echo "or point HTGEN= at the binary." >&2
  exit 1
}
command -v gzip >/dev/null || { echo "gzip not found" >&2; exit 1; }
case "$PROTO" in h1|h2) ;; *) echo "PROTO must be h1 or h2" >&2; exit 2 ;; esac
for a in $ARMS; do case "$a" in stored|gzip|304|206) ;; *) echo "unknown arm '$a'" >&2; exit 2 ;; esac; done

H2OV=$("$H2O" --version 2>&1 | awk '/^h2o version/ { print $3; exit }')

WORK=$(mktemp -d)
# mktemp gives 700; h2o started as root runs as nobody and must
# traverse into the docroot - 403 on every file otherwise.
chmod 755 "$WORK"
H2PID=""
trap '[ -n "$H2PID" ] && kill "$H2PID" 2>/dev/null; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/root" "$WORK/tmp"
cat src/*.cpp src/*.hpp > "$WORK/corpus" 2>/dev/null
[ -s "$WORK/corpus" ] || { echo "no src/ corpus" >&2; exit 1; }
CORPUS_LEN=$(wc -c < "$WORK/corpus")
for sz in $SIZES; do
  head -c "$sz" /dev/urandom > "$WORK/root/a$sz.bin"
  n=$(( (sz + CORPUS_LEN - 1) / CORPUS_LEN ))
  for _ in $(seq "$n"); do cat "$WORK/corpus"; done | head -c "$sz" > "$WORK/root/t$sz.txt"
  gzip -9 -k "$WORK/root/t$sz.txt"
done
chmod -R a+rX "$WORK/root"

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

# h2c is prior knowledge on a plain listener; h2o answers both on the
# same port, so there is no listener flag to switch. The curl proofs
# speak the same proto as the measurement either way.
CURLP=()
[ "$PROTO" = h2 ] && CURLP=(--http2-prior-knowledge)
cat > "$WORK/h2o.conf" <<CONF
listen:
  host: 127.0.0.1
  port: $PORT
num-threads: $WORKERS
max-connections: $((CONNS > 1024 ? CONNS * 2 : 8192))
file.send-gzip: ON
http2-max-concurrent-requests-per-connection: $((MULTI > 100 ? MULTI : 100))
hosts:
  "127.0.0.1:$PORT":
    paths:
      "/":
        file.dir: $WORK/root
CONF
"$H2O" -m test -c "$WORK/h2o.conf" >/dev/null 2>&1 || {
  echo "h2o refused the config:" >&2
  "$H2O" -m test -c "$WORK/h2o.conf" >&2
  exit 1
}
"$H2O" -c "$WORK/h2o.conf" > "$WORK/h2o.log" 2>&1 &
H2PID=$!
  # WAIT for it to answer, never a fixed sleep: on this container the
# first curl raced the listener, the stored arm compared an EMPTY
# body against the asset, and the run died claiming the bytes
# differed. A connection refused is the only thing this loop retries -
# a 404 is already an answer.
waited=0
until curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$PORT/" 2>/dev/null; do
  kill -0 "$H2PID" 2>/dev/null || { echo "h2o died:" >&2; cat "$WORK/h2o.log" >&2; exit 1; }
  sleep 0.05
  waited=$((waited + 1))
  [ "$waited" -lt 200 ] || { echo "h2o did not answer within 10s" >&2; cat "$WORK/h2o.log" >&2; exit 1; }
done

RESULTS="bench/results/$(hostname).log"
mkdir -p bench/results
steal_ticks() { awk '/^cpu /{print $9}' /proc/stat; }
cpu_ticks() {
  awk '{ n = index($0, ") "); rest = substr($0, n + 2); split(rest, f, " "); print f[12] + f[13] }' \
    "/proc/$1/stat" 2>/dev/null || echo 0
}
# h2o's workers are THREADS of one process, and /proc/PID/stat already
# sums the whole thread group - so unlike nginx there is nothing to
# add up.
srv_ticks() { cpu_ticks "$H2PID"; }
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
h2o_pids() { echo "$H2PID"; }
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

ARM_URL= ARM_WIRE=0 ARM_PATH=
ARM_HDRS=()
ARM_CLI=()
arm_setup() {
  local arm=$1 sz=$2
  local base="http://127.0.0.1:$PORT"
  ARM_HDRS=()
  ARM_CLI=()
  case "$arm" in
    stored)
      ARM_URL="$base/a$sz.bin"
      curl -s --max-time 30 "${CURLP[@]}" "$ARM_URL" | cmp -s - "$WORK/root/a$sz.bin" || {
        echo "size $sz stored: bytes differ" >&2; exit 1; }
      ;;
    gzip)
      ARM_URL="$base/t$sz.txt"
      curl -s --max-time 30 "${CURLP[@]}" -D "$WORK/h" -o /dev/null -H 'accept-encoding: gzip' "$ARM_URL"
      grep -qi '^content-encoding: *gzip' "$WORK/h" || {
        echo "size $sz gzip: send-gzip did not serve the sibling" >&2; exit 1; }
      curl -s --max-time 30 "${CURLP[@]}" --compressed "$ARM_URL" | cmp -s - "$WORK/root/t$sz.txt" || {
        echo "size $sz gzip: decoded bytes differ" >&2; exit 1; }
      ARM_HDRS=(-H 'accept-encoding: gzip')
      ARM_CLI=(--header 'accept-encoding: gzip')
      ;;
    304)
      ARM_URL="$base/a$sz.bin"
      local etag code
      etag=$(curl -s --max-time 30 "${CURLP[@]}" -o /dev/null -D - "$ARM_URL" |
             awk 'tolower($1) == "etag:" { print $2 }' | tr -d '\r')
      [ -n "$etag" ] || { echo "size $sz 304: no ETag from h2o" >&2; exit 1; }
      code=$(curl -s --max-time 30 "${CURLP[@]}" -o /dev/null -w '%{http_code}' \
             -H "if-none-match: $etag" "$ARM_URL")
      [ "$code" = 304 ] || { echo "size $sz 304: got $code" >&2; exit 1; }
      ARM_HDRS=(-H "if-none-match: $etag")
      ARM_CLI=(--header "if-none-match: $etag")
      ;;
    206)
      ARM_URL="$base/a$sz.bin"
      local half=$((sz / 2)) code
      head -c "$half" "$WORK/root/a$sz.bin" > "$WORK/slice"
      code=$(curl -s --max-time 30 "${CURLP[@]}" -o "$WORK/got" -w '%{http_code}' \
             -H "range: bytes=0-$((half - 1))" "$ARM_URL")
      [ "$code" = 206 ] || { echo "size $sz 206: got $code" >&2; exit 1; }
      cmp -s "$WORK/got" "$WORK/slice" || { echo "size $sz 206: wrong window" >&2; exit 1; }
      ARM_HDRS=(-H "range: bytes=0-$((half - 1))")
      ARM_CLI=(--header "range: bytes=0-$((half - 1))")
      ;;
  esac
  ARM_PATH="${ARM_URL#"$base"}"
  ARM_WIRE=$(curl -s --max-time 30 "${CURLP[@]}" -o /dev/null -w '%{size_download}' \
             "${ARM_HDRS[@]}" "$ARM_URL")
}

# One whitespace-separated field out of htgen's summary line, by EXACT
# name. Not a substring match: htgen prints both MB/s and tx_MB/s, and
# `grep -o 'MB/s=...'` matches inside the second one too - two lines in
# one variable, a newline riding into vals[], and the median then picks
# the wrong row. Measured: a 65444 rps run was reported as 2.
field() { tr ' ' '\n' < "$WORK/cli.out" | awk -F= -v k="$1" '$1 == k { print $2; exit }'; }

measure() {
  local arm=$1 sz=$2
  local vals=()
  for _ in $(seq "$REPS"); do
    local rps s0 s1 c0 c1 cli threads_running
    s0=$(srv_ticks)
    "$HTGEN" --host 127.0.0.1 --port "$PORT" --conns "$CONNS" --seconds "$DURATION" \
      --path "$ARM_PATH" "${H2FLAGS[@]}" "${ARM_CLI[@]}" >"$WORK/cli.out" 2>&1 &
    cli=$!
    snap_times
    c0=$(parse_child_cpu)
    sysc_begin "$(h2o_pids)" "$DURATION"
    # One mid-run sample: a client on a single running thread is
    # measuring itself, whatever -t claimed.
    sleep 1
    threads_running=$(ps -L -p "$cli" -o stat= 2>/dev/null | grep -c '^R' || echo 0)
    wait "$cli" 2>/dev/null
    snap_times
    c1=$(parse_child_cpu)
    s1=$(srv_ticks)
    sysc_wait
    local nsysc ndone rsc="-"
    nsysc=$(sysc_read)
    ndone=$(field "responses")
    if [ -n "$nsysc" ] && [ "$nsysc" -gt 0 ] && [ -n "$ndone" ]; then
      rsc=$(awk -v d="$ndone" -v n="$nsysc" 'BEGIN { printf "%.1f", d / n }')
    fi
    rps=$(field "rps")
    mbs=$(field "MB/s")
    [ -n "$rps" ] || { echo "htgen produced no number:" >&2; cat "$WORK/cli.out" >&2; exit 1; }
    grep -q 'bad=0 ' "$WORK/cli.out" || {
      echo "the client counted bad answers:" >&2; cat "$WORK/cli.out" >&2; exit 1
    }
    local su=$((s1 - s0))
    local scpu=$((su * 100 / HZ / DURATION))
    local ccpu
    ccpu=$(awk -v a="$c1" -v b="$c0" -v d="$DURATION" 'BEGIN { printf "%.0f", (a - b) * 100 / d }')
    # Client-bound = the server had headroom against its BUDGET
    # (WORKERS cores) while the client was pegged - see bench/assets.sh
    # for why comparing totals was wrong.
    if [ "$su" -gt 0 ] && [ "$scpu" -lt $((WORKERS * 90)) ] && [ "$ccpu" -ge 90 ]; then
      echo "REFUSED on arm $arm, size $sz: h2o had headroom (${scpu}% of ${WORKERS}00%) while the client was pegged (${ccpu}% of its core)." >&2
      echo "  This measures htgen, not h2o. Use a second machine." >&2
      printf 'REFUSED client-bound'
      return
    fi
    vals+=("$rps $mbs $scpu $rsc")
  done
  printf '%s\n' "${vals[@]}" | sort -n -k1 | \
    awk -v n="$REPS" 'NR==int((n+1)/2){printf "%.0f %s %s %s", $1, ($2 == "" ? "-" : $2), $3, $4}'
}

if [ "$PROTO" = h2 ]; then
  H2FLAGS=(--h2 --streams "$MULTI")
  PROTO_SPELL="h2 --streams $MULTI"
else
  H2FLAGS=()
  PROTO_SPELL="h1"
fi

{
  echo "==== $(date -u +%FT%RZ) h2o/$H2OV file.send-gzip ===="
  echo "harness: h2o-assets htgen $PROTO_SPELL -c$CONNS -d${DURATION}s reps=$REPS threads=$WORKERS $(uname -mr)"
  s0=$(steal_ticks)
  # cpu% = server CPU over the run, in percent of ONE core - the
  # column that lets a workers=16 row sit honestly next to a
  # one-thread row: req/s per core is req/s * 100 / cpu%.
  printf '%10s %8s %14s %12s %12s %8s %12s\n' "size" "arm" "req/s" "MB/s" "wire" "cpu%" "req/syscall"
  for sz in $SIZES; do
    for arm in $ARMS; do
      arm_setup "$arm" "$sz"
      read -r rps mbs scpu rsc <<< "$(measure "$arm" "$sz")"
      printf '%10s %8s %14s %12s %12s %8s %12s\n' "$sz" "$arm" "$rps" "$mbs" "$ARM_WIRE" "${scpu:--}" "${rsc:--}"
    done
  done
  s1=$(steal_ticks)
  echo "steal +$((s1 - s0)) ticks over the whole sweep"
} | tee -a "$RESULTS"
