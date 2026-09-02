#!/bin/bash
# The coverage-guided campaign (#206): libFuzzer, the real listener, the
# real reactor. What is fuzzed is the SERVER through a socket - the same
# door an attacker has - and not one of its functions.
#
#   tools/fuzz-run.sh                 # until you stop it
#   RUNS=100000 tools/fuzz-run.sh     # a bounded run, for CI or a bisect
#   JOBS=8 tools/fuzz-run.sh          # -fork, one corpus, N children
#
# The corpus and the dictionary live beside the harness and are
# COMMITTED: a fuzzer starting from nothing spends its first thousands of
# runs arriving at "GET / ", which is not a discovery. New inputs land in
# the same directory - that is libFuzzer's own doing - so run
# tools/fuzz-merge.sh before committing what a campaign found.
set -eu
cd "$(dirname "$0")/.."

BIN=mruby/build/libfuzzer/bin/webmachine-fuzz
DICT=tools/webmachine-fuzz/webmachine.dict
CORPUS=tools/webmachine-fuzz/corpus
APP="${WM_FUZZ_APP:-}"

if [ ! -x "$BIN" ]; then
  echo "no $BIN - build it first:" >&2
  echo "  MRUBY_CONFIG=build_config_libfuzzer.rb rake compile" >&2
  exit 2
fi
[ -d "$CORPUS" ] || python3 tools/fuzz-seeds.py "$CORPUS"

# An app is what makes the flow engine reachable: without one the server
# refuses to start (it has nothing to serve), so this compiles the
# example the same way the server would be given one - bytecode, never
# source (#100).
if [ -z "$APP" ]; then
  MRBC=mruby/build/libfuzzer/bin/mrbc
  [ -x "$MRBC" ] || MRBC=mruby/bin/mrbc
  APP=build/fuzz/hello.mrb
  mkdir -p build/fuzz
  [ "$APP" -nt examples/hello.rb ] || "$MRBC" -o "$APP" examples/hello.rb
fi
export WM_FUZZ_APP="$APP"


# Crashes and slow units go to a findings directory, not into the tree
# libFuzzer happens to be started from.
FINDINGS="${FINDINGS:-build/fuzz/findings}"
mkdir -p "$FINDINGS"

ARGS=(-dict="$DICT" -max_len="${MAX_LEN:-65536}" -rss_limit_mb="${RSS_LIMIT:-4096}"
      -artifact_prefix="$FINDINGS/")
[ -n "${RUNS:-}" ] && ARGS+=(-runs="$RUNS")
[ -n "${JOBS:-}" ] && ARGS+=(-fork="$JOBS")
[ -n "${TIMEOUT:-}" ] && ARGS+=(-max_total_time="$TIMEOUT")

echo "app=$APP corpus=$(ls "$CORPUS" | wc -l) files dict=$DICT"
exec "$BIN" "${ARGS[@]}" "$CORPUS"
