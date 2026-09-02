#!/bin/bash
# The pipelined h1 floor: what the framer costs when the per-round-trip
# price is amortized away. This is TechEmpower's "Plaintext" shape -
# DEPTH requests in one write, one batch of answers back - and it is
# explicitly NOT a shape any real user agent sends (RFC 9112 9.3 allows
# pipelining; browsers abandoned it over head-of-line blocking). It
# exists here for ONE reason: the -m1 numbers are round-trip bound
# (perf showed 25-34% of the profile in kernel scheduling/TCP), so this
# is the counter-measurement that shows what the SERVER costs per
# request once syscall and scheduling overhead are divided across
# DEPTH requests instead of paid per request.
#
# Read the number as "the framer's amortized cost", never as "our
# req/s" - the comparison it belongs to is TechEmpower's Plaintext
# column (Round 23: the top of that chart sits near 28M on their
# 40GbE multi-machine rig, h2o itself at 9.5M), not to bench/h2.sh's
# round-trip figures.
#
#   CONNS=400 bench/pipeline.sh                    # AF_UNIX (default)
#   CONNS=400 DEPTH=32 bench/pipeline.sh
#   CONNS=400 TRANSPORT=tcp bench/pipeline.sh
# NO PINNING - measured twice, lost twice. The previous tree removed
# every taskset it had ("handing the scheduler one core was slower than
# letting it choose"; widening the CLIENT mask 2 -> 15 -> 30 cpus raised
# throughput monotonically in the MEDIAN). And io-wq workers inherit the
# issuing thread's affinity, so pinning the server pins the pool that
# carries splice: a 32 KiB asset measured 0.07x its unspliced twin under
# `taskset -c 0`. The knobs are gone rather than defaulted off - they
# are not something anyone should turn on.
#
set -u
[ -n "${CONNS:-}" ] || {
  echo "CONNS= is mandatory - the harness is part of the number" >&2
  exit 2
}
[ -z "${THREADS:-}" ] || {
  echo "THREADS= is gone: both ends are one thread (#120, #196)." >&2
  exit 2
}
DURATION="${DURATION:-10}"
DEPTH="${DEPTH:-16}"
TRANSPORT="${TRANSPORT:-unix}"
PORT="${PORT:-8123}"
APP="${APP-examples/hello.rb}"
cd "$(dirname "$0")/.." || exit 1

BIN=mruby/build/host/bin/webmachine-server
[ -x "$BIN" ] || { echo "$BIN missing - run: rake compile" >&2; exit 1; }

HTGEN="${HTGEN:-$HOME/htgen/htgen}"
[ -x "$HTGEN" ] || HTGEN="$PWD/../htgen/htgen"   # a clone beside this one
[ -x "$HTGEN" ] || HTGEN=$(command -v htgen) || {
  echo "htgen not found. Build it once:" >&2
  echo "  git clone --recursive https://github.com/Asmod4n/htgen ~/htgen && make -C ~/htgen" >&2
  echo "or point HTGEN= at the binary." >&2
  exit 1
}

# The server loads bytecode only (#100). A .rb APP is compiled here
# with the tree's own mrbc into a scratch .mrb; the harness line keeps
# naming the .rb source. An .mrb APP (or none) passes through as-is.
APP_ARGS=()
if [ -n "${APP:-}" ]; then
  case "$APP" in
    *.rb)
      MRBC="${MRBC:-mruby/bin/mrbc}"
      [ -x "$MRBC" ] || { echo "mrbc not found at $MRBC - rake compile builds it, or set MRBC=" >&2; exit 1; }
      APP_MRB=/tmp/wm-pipeline-app.mrb
      "$MRBC" -o "$APP_MRB" "$APP" || exit 1
      APP_ARGS=(--app="$APP_MRB")
      ;;
    *) APP_ARGS=(--app="$APP") ;;
  esac
fi

SOCK=/tmp/wm-pipeline-bench.sock
if [ "$TRANSPORT" = unix ]; then
  rm -f "$SOCK"
  "$BIN" --unix="$SOCK" "${APP_ARGS[@]}" 2>/tmp/wm-pipeline-srv.log & SRV=$!
else
  "$BIN" --port="$PORT" "${APP_ARGS[@]}" 2>/tmp/wm-pipeline-srv.log & SRV=$!
fi
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; rm -f "$SOCK"' EXIT
sleep 0.5
kill -0 $SRV 2>/dev/null || { echo "server died:"; cat /tmp/wm-pipeline-srv.log; exit 1; }
grep -q "select(2) SHIM" /tmp/wm-pipeline-srv.log 2>/dev/null && {
  echo "REFUSED: the server runs the select shim - a lazy-path number must never enter bench/results/" >&2
  exit 1
}


RESULTS="bench/results/$(hostname).log"
mkdir -p bench/results
REPO_REV=$(git rev-parse --short HEAD 2>/dev/null || echo '?')
MRUBY_REV=$(git -C mruby rev-parse --short HEAD 2>/dev/null || echo '?')
RAW=$(mktemp)
if [ "$TRANSPORT" = unix ]; then
  "$HTGEN" --sock "$SOCK" --conns "$CONNS" --seconds "$DURATION" \
    --pipeline "$DEPTH" > "$RAW" 2>&1
else
  "$HTGEN" --host 127.0.0.1 --port "$PORT" --conns "$CONNS" --seconds "$DURATION" \
    --pipeline "$DEPTH" > "$RAW" 2>&1
fi

# htgen counts what a load generator must never quietly absorb in `bad`:
# a non-2xx answer, an unparseable response, a decoder out of sync. Its
# absence is not assumed - the line is read, and a run with bad above
# zero is not a number.
LINE=$(grep '^responses=' "$RAW" || true)
if [ -z "$LINE" ]; then
  echo "htgen produced no result - its own words:" >&2
  sed 's/^/  /' "$RAW" >&2
  rm -f "$RAW"
  exit 1
fi
BAD=$(echo "$LINE" | grep -o 'bad=[0-9]*' | cut -d= -f2)

OUT=$(mktemp)
{
  echo "==== $(date -u +%Y-%m-%dT%H:%MZ) repo=$REPO_REV mruby=$MRUBY_REV ===="
  echo "harness: htgen -c$CONNS -d${DURATION}s PIPELINED depth=$DEPTH transport=$TRANSPORT app=${APP:-none} $(uname -mr)"
  echo "$LINE"
  # The bytes must account for every request. A batch that silently lost
  # answers would still report a throughput, which is why the division
  # is printed rather than trusted.
  echo "$LINE" | awk '{
    for (i = 1; i <= NF; i++) {
      split($i, kv, "=")
      if (kv[1] == "responses") n = kv[2]
      if (kv[1] == "bytes") b = kv[2]
    }
    if (n > 0) printf "  bytes/response: %.1f (must equal the response size - a batch that lost answers still reports throughput)\n", b / n
  }'
} | tee "$OUT"

if [ "$BAD" != 0 ]; then
  echo "bad=$BAD - this run is not a number, nothing logged" >&2
  rm -f "$OUT" "$RAW"
  exit 1
fi
cat "$OUT" >> "$RESULTS"
rm -f "$OUT" "$RAW"
