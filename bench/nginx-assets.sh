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
# Knobs as in assets.sh: THREADS/CONNS mandatory, SIZES, ARMS, PROTO
# (h1 = h2load --h1 -m1, h2 = prior knowledge -mMULTI), MULTI,
# DURATION, REPS, PORT, WORKERS, NGINX (binary override).
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
command -v h2load >/dev/null || { echo "h2load not found (nghttp2 package)" >&2; exit 1; }
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

LOG="bench/results/$(hostname).log"
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

ARM_URL= ARM_WIRE=0
ARM_HDRS=()
arm_setup() {
  local arm=$1 sz=$2
  local base="http://127.0.0.1:$PORT"
  ARM_HDRS=()
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
      ;;
  esac
  ARM_WIRE=$(curl -s --max-time 30 "${CURLP[@]}" -o /dev/null -w '%{size_download}' \
             "${ARM_HDRS[@]}" "$ARM_URL")
}

measure() {
  local arm=$1 sz=$2
  local vals=()
  for _ in $(seq "$REPS"); do
    local rps s0 s1 c0 c1 cli threads_running
    s0=$(srv_ticks)
    h2load "${H2FLAGS[@]}" -D"$DURATION" -t"$THREADS" -c"$CONNS" "${ARM_HDRS[@]}" "$ARM_URL" \
      >"$WORK/cli.out" 2>&1 &
    cli=$!
    snap_times
    c0=$(parse_child_cpu)
    # One mid-run sample: a client on a single running thread is
    # measuring itself, whatever -t claimed.
    sleep 1
    threads_running=$(ps -L -p "$cli" -o stat= 2>/dev/null | grep -c '^R' || echo 0)
    wait "$cli" 2>/dev/null
    snap_times
    c1=$(parse_child_cpu)
    s1=$(srv_ticks)
    rps=$(grep '^finished' "$WORK/cli.out" | grep -o '[0-9.]* req/s' | grep -o '^[0-9.]*')
    mbs=$(grep '^finished' "$WORK/cli.out" | grep -o '[0-9.]*[KMG]B/s' |
      awk '{ u = substr($0, length($0) - 3, 1); v = substr($0, 1, length($0) - 4) + 0;
             if (u == "K") v /= 1024; else if (u == "G") v *= 1024;
             printf "%.2f", v }')
    [ -n "$rps" ] || { echo "h2load produced no number:" >&2; cat "$WORK/cli.out" >&2; exit 1; }
    local su=$((s1 - s0))
    local scpu=$((su * 100 / HZ / DURATION))
    local ccpu
    ccpu=$(awk -v a="$c1" -v b="$c0" -v d="$DURATION" 'BEGIN { printf "%.0f", (a - b) * 100 / d }')
    if [ "$su" -gt 0 ] && [ "$ccpu" -ge "$scpu" ]; then
      echo "REFUSED on arm $arm, size $sz: client ${ccpu}% vs server ${scpu}% of a core, $threads_running running client threads." >&2
      echo "  This measures h2load, not nginx. Raise THREADS or use a second machine." >&2
      printf 'REFUSED client-bound'
      return
    fi
    vals+=("$rps $mbs $scpu")
  done
  printf '%s\n' "${vals[@]}" | sort -n -k1 | \
    awk -v n="$REPS" 'NR==int((n+1)/2){printf "%.0f %s %s", $1, ($2 == "" ? "-" : $2), $3}'
}

if [ "$PROTO" = h2 ]; then
  H2FLAGS=(-m"$MULTI")
  PROTO_SPELL="h2 -m$MULTI"
else
  H2FLAGS=(--h1 -m1)
  PROTO_SPELL="--h1 -m1"
fi

{
  echo "==== $(date -u +%FT%RZ) nginx/$("$NGINX" -v 2>&1 | grep -o '[0-9][0-9.]*' | head -1) gzip_static ===="
  echo "harness: nginx-assets h2load $PROTO_SPELL -t$THREADS -c$CONNS -D${DURATION} reps=$REPS workers=$WORKERS sendfile=on $(uname -mr)"
  s0=$(steal_ticks)
  # cpu% = server CPU over the run, in percent of ONE core - the
  # column that lets a workers=16 row sit honestly next to a
  # one-thread row: req/s per core is req/s * 100 / cpu%.
  printf '%10s %8s %14s %12s %12s %8s\n' "size" "arm" "req/s" "MB/s" "wire" "cpu%"
  for sz in $SIZES; do
    for arm in $ARMS; do
      arm_setup "$arm" "$sz"
      read -r rps mbs scpu <<< "$(measure "$arm" "$sz")"
      printf '%10s %8s %14s %12s %12s %8s\n' "$sz" "$arm" "$rps" "$mbs" "$ARM_WIRE" "${scpu:--}"
    done
  done
  s1=$(steal_ticks)
  echo "steal +$((s1 - s0)) ticks over the whole sweep"
} | tee -a "$LOG"
