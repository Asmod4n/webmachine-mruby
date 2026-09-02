#!/bin/bash
# Shrink the corpus to the smallest set with the SAME coverage (#88).
#
#   tools/fuzz-merge.sh
#
# A campaign keeps every input that reached one new edge, so a corpus
# grows for hours and most of what it holds is a longer way of saying
# what a shorter entry already says. libFuzzer's -merge=1 answers exactly
# that: it replays a corpus into an empty directory and keeps only the
# inputs that ADD coverage, in order of increasing size.
#
# WHY IT IS WORTH RUNNING and not just tidiness: every run starts by
# replaying the whole corpus before it mutates anything, so a corpus with
# ten thousand redundant entries costs that replay on every restart and
# on every child of a -fork campaign. The minimal set has the same reach
# and starts in a fraction of the time. It is also what makes the corpus
# committable: the tree carries the reach, not the history.
#
# SAFE BY CONSTRUCTION: the merge writes into a NEW directory and the old
# one is only replaced once libFuzzer has exited successfully. A merge
# that dies halfway leaves the corpus it was called on untouched - which
# matters, because that corpus may be the only copy of hours of work.
set -eu
cd "$(dirname "$0")/.."

BIN=mruby/build/libfuzzer/bin/webmachine-fuzz
CORPUS="${CORPUS:-tools/webmachine-fuzz/corpus}"
RSS_LIMIT="${RSS_LIMIT:-4096}"
LOG=build/fuzz/merge.log

if [ ! -x "$BIN" ]; then
  echo "no $BIN - build it first:" >&2
  echo "  MRUBY_CONFIG=build_config_libfuzzer.rb rake compile" >&2
  exit 2
fi
[ -d "$CORPUS" ] || { echo "no corpus at $CORPUS" >&2; exit 2; }

# The same app and the same suppressions the campaign runs with: a merge
# replays real payloads through the real reactor, so it needs both.
MRBC=mruby/build/libfuzzer/bin/mrbc
[ -x "$MRBC" ] || MRBC=mruby/bin/mrbc
mkdir -p build/fuzz
if [ -z "${WM_FUZZ_APP:-}" ]; then
  WM_FUZZ_APP=build/fuzz/hello.mrb
  [ "$WM_FUZZ_APP" -nt examples/hello.rb ] || "$MRBC" -o "$WM_FUZZ_APP" examples/hello.rb
fi
export WM_FUZZ_APP
export UBSAN_OPTIONS="suppressions=$PWD/tools/webmachine-fuzz/ubsan.supp${UBSAN_OPTIONS:+:$UBSAN_OPTIONS}"

before=$(ls "$CORPUS" | wc -l)
bytes_before=$(du -sk "$CORPUS" | cut -f1)
fresh="$CORPUS.merged"
rm -rf "$fresh"
mkdir -p "$fresh"
# -merge=1 <destination> <source>: replay source, keep what adds
# coverage. The dictionary is not passed - a merge mutates nothing, so it
# has nothing to mutate WITH.
if "$BIN" -merge=1 -rss_limit_mb="$RSS_LIMIT" "$fresh" "$CORPUS" > "$LOG" 2>&1; then
  after=$(ls "$fresh" | wc -l)
  bytes_after=$(du -sk "$fresh" | cut -f1)
  rm -rf "$CORPUS"
  mv "$fresh" "$CORPUS"
  # The seeds are the shapes a cold start needs and a merge drops any of
  # them that a longer find already covers. They are cheap and they are
  # the documentation of what this server speaks, so they come back.
  python3 tools/fuzz-seeds.py "$CORPUS" >/dev/null
  printf '%6s -> %-6s files   %6s -> %-6s KiB   (seeds restored)\n' \
    "$before" "$(ls "$CORPUS" | wc -l)" "$bytes_before" "$bytes_after"
else
  rm -rf "$fresh"
  echo "merge FAILED, corpus left as it was (see $LOG)" >&2
  exit 1
fi
