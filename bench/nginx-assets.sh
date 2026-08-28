#!/bin/bash
# The SAME asset sweep as bench/assets.sh, served by nginx with
# gzip_static - the closest production equivalent of this tree's asset
# tier (pre-compressed siblings served as-is, no runtime deflate). One
# log, same columns, same refusals, so the rows sit next to ours and
# mean the same thing.
#
# WHAT NGINX GETS, deliberately its best foot:
#   worker_processes WORKERS (default 1 - apples to our one thread;
#     raise it to measure nginx's scaling, the harness line records it),
#   sendfile + tcp_nopush + tcp_nodelay, access_log off, gzip off +
#   gzip_static on (serve t*.txt.gz as-is), open_file_cache (our tier
#   maps once at boot; without the cache nginx would pay open/close
#   per request), keepalive/h2 request limits raised to 1e6 (defaults
#   recycle the connection every 1000 requests - our server never does,
#   and the reconnect would be the harness measuring itself).
#
# ARM MAPPING: stored = the plain file, identity. gzip = t*.txt with
# Accept-Encoding and a .gz sibling (gzip -9, same corpus as
# bench/assets.sh: this tree's sources repeated). 304 = If-None-Match
# with nginx's own ETag. 206 = first-half Range on the stored file.
#
# ONE nginx instance serves the whole sweep (its own architecture; a
# restart per size would penalize a server that is built to stay up).
#
# Knobs as in assets.sh: CONNS mandatory, SIZES, ARMS, PROTO
# (h1 default, h2 = prior knowledge with --streams MULTI), MULTI,
# DURATION, REPS, PORT, WORKERS, NGINX (binary override).
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
# NGINX_BIN, not NGINX: nginx itself uses the NGINX environment
# variable for binary-upgrade socket inheritance, and a path in it
# produces "[emerg] invalid socket number". The old name still works -
# it is scrubbed from the environment before exec either way.
NGINX="${NGINX_BIN:-${NGINX:-nginx}}"
command -v "$NGINX" >/dev/null || { echo "nginx not found (set NGINX=)" >&2; exit 1; }
[ -z "${THREADS:-}" ] || {
  echo "THREADS= is gone: the client is one thread (#196), and the knob only ever" >&2
  echo "described h2load, which this tree no longer uses." >&2
  exit 2
}
HTGEN="${HTGEN:-$HOME/htgen/htgen}"
[ -x "$HTGEN" ] || HTGEN=$(command -v htgen) || {
  echo "htgen not found. Build it once:" >&2
  echo "  git clone --recursive https://github.com/Asmod4n/htgen ~/htgen && make -C ~/htgen" >&2
  echo "or point HTGEN= at the binary." >&2
  exit 1
}
command -v gzip >/dev/null || { echo "gzip not found" >&2; exit 1; }
"$NGINX" -V 2>&1 | grep -q http_v2_module || { echo "this nginx lacks http_v2" >&2; exit 1; }
"$NGINX" -V 2>&1 | grep -q http_gzip_static_module || { echo "this nginx lacks gzip_static" >&2; exit 1; }
case "$PROTO" in h1|h2) ;; *) echo "PROTO must be h1 or h2" >&2; exit 2 ;; esac
for a in $ARMS; do case "$a" in stored|gzip|304|206) ;; *) echo "unknown arm '$a'" >&2; exit 2 ;; esac; done

NGV=$("$NGINX" -v 2>&1 | grep -o '[0-9]*\.[0-9]*' | head -1)
NGMAJ=${NGV%%.*}; NGMIN=${NGV##*.}

WORK=$(mktemp -d)
# mktemp gives 700; the nginx WORKER drops privileges (user www-data)
# and must traverse into the docroot - 403 on every file otherwise.
chmod 755 "$WORK"
NGPID=""
trap '[ -n "$NGPID" ] && kill "$NGPID" 2>/dev/null; rm -rf "$WORK"' EXIT

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

# The listener must MATCH the proto: a plain listener with the http2
# flag is h2c-only on 1.24 (an h1 request gets silence, measured), and
# 1.25 renamed the switch. The curl proofs speak the same proto as the
# measurement, for the same reason.
CURLP=()
LISTEN="listen 127.0.0.1:$PORT;"
H2ON=""
REQCAP="keepalive_requests 1000000;"
if [ "$PROTO" = h2 ]; then
  CURLP=(--http2-prior-knowledge)
  if [ "$NGMAJ" -gt 1 ] || [ "$NGMIN" -ge 25 ]; then
    H2ON="http2 on;"
  else
    LISTEN="listen 127.0.0.1:$PORT http2;"
    REQCAP="keepalive_requests 1000000; http2_max_requests 1000000;"
  fi
fi
cat > "$WORK/nginx.conf" <<CONF
worker_processes $WORKERS;
daemon off;
pid $WORK/nginx.pid;
error_log $WORK/error.log warn;
worker_rlimit_nofile 16384;
events { worker_connections 8192; }
http {
  access_log off;
  default_type application/octet-stream;
  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  $REQCAP
  gzip off;
  gzip_static on;
  open_file_cache max=1024 inactive=300s;
  open_file_cache_valid 300s;
  client_body_temp_path $WORK/tmp;
  proxy_temp_path $WORK/tmp;
  fastcgi_temp_path $WORK/tmp;
  uwsgi_temp_path $WORK/tmp;
  scgi_temp_path $WORK/tmp;
  server {
    $LISTEN
    $H2ON
    root $WORK/root;
  }
}
CONF
# -e: without it nginx opens its COMPILED-IN error log path before
# reading the config - a permission alert on any system nginx. env -u:
# see the NGINX_BIN note above.
env -u NGINX "$NGINX" -e "$WORK/error.log" -t -c "$WORK/nginx.conf" >/dev/null 2>&1 || {
  echo "nginx refused the config:" >&2
  env -u NGINX "$NGINX" -e "$WORK/error.log" -t -c "$WORK/nginx.conf" >&2
  exit 1
}
env -u NGINX "$NGINX" -e "$WORK/error.log" -c "$WORK/nginx.conf" &
NGPID=$!
sleep 0.5
kill -0 "$NGPID" 2>/dev/null || { echo "nginx died:" >&2; cat "$WORK/error.log" >&2; exit 1; }

RESULTS="bench/results/$(hostname).log"
mkdir -p bench/results
steal_ticks() { awk '/^cpu /{print $9}' /proc/stat; }
cpu_ticks() {
  awk '{ n = index($0, ") "); rest = substr($0, n + 2); split(rest, f, " "); print f[12] + f[13] }' \
    "/proc/$1/stat" 2>/dev/null || echo 0
}
# nginx is master + workers; the server's cost is the sum.
srv_ticks() {
  local sum
  sum=$(cpu_ticks "$NGPID")
  for w in $(pgrep -P "$NGPID" 2>/dev/null); do
    sum=$((sum + $(cpu_ticks "$w")))
  done
  echo "$sum"
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
nginx_pids() {
  local pids=$NGPID
  for w in $(pgrep -P "$NGPID" 2>/dev/null); do pids="$pids,$w"; done
  echo "$pids"
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
        echo "size $sz gzip: gzip_static did not serve the sibling" >&2; exit 1; }
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
      [ -n "$etag" ] || { echo "size $sz 304: no ETag from nginx" >&2; exit 1; }
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
    sysc_begin "$(nginx_pids)" "$DURATION"
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
    ndone=$(grep -o 'responses=[0-9]*' "$WORK/cli.out" | cut -d= -f2)
    if [ -n "$nsysc" ] && [ "$nsysc" -gt 0 ] && [ -n "$ndone" ]; then
      rsc=$(awk -v d="$ndone" -v n="$nsysc" 'BEGIN { printf "%.1f", d / n }')
    fi
    rps=$(grep -o 'rps=[0-9]*' "$WORK/cli.out" | cut -d= -f2)
    mbs=$(grep -o 'MB/s=[0-9.]*' "$WORK/cli.out" | cut -d= -f2)
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
      echo "REFUSED on arm $arm, size $sz: nginx had headroom (${scpu}% of ${WORKERS}00%) while the client was pegged (${ccpu}% of its core)." >&2
      echo "  This measures htgen, not nginx. Use a second machine." >&2
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
  echo "==== $(date -u +%FT%RZ) nginx/$("$NGINX" -v 2>&1 | grep -o '[0-9][0-9.]*' | head -1) gzip_static ===="
  echo "harness: nginx-assets htgen $PROTO_SPELL -c$CONNS -d${DURATION}s reps=$REPS workers=$WORKERS sendfile=on $(uname -mr)"
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
