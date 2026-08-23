#!/bin/bash
# EVERY framer in this tree under libFuzzer + ASan + UBSan (#88).
#
#   tools/fuzz.sh              all targets, all workers, until Ctrl-C
#   tools/fuzz.sh 60           the same, capped - a smoke test
#   WORKERS=30 tools/fuzz.sh   thirty cores, split across the targets
#
# THERE IS NO TARGET ARGUMENT, on purpose. A campaign that runs one
# framer is a campaign that leaves the others at whatever they were,
# and the tree has no way to tell which of them was last looked at.
# Everything runs; WORKERS decides how much of the machine it gets.
#
# NO SECONDS MEANS NO LIMIT - the default, because the calibration
# below says findings arrive after HOURS. libFuzzer handles the
# interrupt itself and writes each corpus out before it goes, so
# stopping a campaign is a Ctrl-C and nothing else.
#
# WHAT RUNS, and why each one is its own target rather than a corner
# of a bigger one - the rule is: bytes a stranger chose that get
# TRANSFORMED, not merely forwarded.
#
#   ws          RFC 6455 framing, the close payload read back, and
#               the handshake key - SHA-1 and base64 over sixty bytes
#               a peer chose, before anything has authenticated.
#   wsdeflate   RFC 7692's negotiation and its zlib streams.
#   http        the 9110 VALUE parsers - a range window measured
#               against a length, ETag lists, q-values, decimals with
#               overflow builtins. Unreachable from feed (see below).
#   feed        h1 heads and h2 frames through Http1::feed: the
#               framer, the stream machine, HPACK.
#   assets      the ZIP reader - the one whole FILE FORMAT here, and
#               the shape every zip CVE has ever had.
#
# The http target exists because feed cannot reach those functions at
# all: it builds a konst Resource and no asset table, so `bound_` is
# false and `assets_` is null, and every one of those parsers sits
# behind one of the two. Eight hours of feed would not execute a line
# of them.
#
# clang, not the tree's gcc: libFuzzer is clang's. The targets INCLUDE
# the sources they test (see their heads) so ASan instruments them,
# and link libmruby.a for everything else - its members are not pulled
# for symbols the target already defines.
#
# -no-pie, and it is the LINKER's problem not the compiler's:
# libmruby.a is built by the tree's gcc without -fPIE (a static
# library for a non-PIE binary has no reason to be), while clang
# defaults to PIE on most distributions - so the link fails with
# "relocation R_X86_64_32 against `.rodata' can not be used when
# making a PIE object" on the first archive member that has one. The
# narrow fix belongs here: this is the only consumer that links that
# archive with clang, and making the PRODUCT position-independent to
# please a test tool would be paying for it on every request.
#
# -fno-sanitize=alignment: ls-hpack and phr read unaligned on purpose,
# and they are not what this run is about.
#
# EVERY TARGET GETS A DICTIONARY AND A SEED CORPUS, and both are the
# same idea said twice: a mutator that has to DISCOVER a protocol's
# fixed bytes spends its whole budget in front of the code worth
# testing. "PRI * HTTP/2.0" is 24 bytes it will never find by flipping
# bits; "permessage-deflate" is 18; a zip is not a zip without
# "PK\x05\x06" somewhere near its end.
#
# WHAT THAT BOUGHT, measured cold - empty corpus, both arms the same
# seconds, same container. Coverage, not throughput, so this is a fact
# about REACH and not a number Gebot 10 would send to real hardware:
#
#                        bare              dict + seeds
#   feed (20s)     cov  714, ft 1859   cov 1124, ft 3456   +57% blocks
#   wsdeflate (30s) cov 135, ft  869   cov  292, ft 1228  +116% blocks
#   ws (25s)       cov   65, ft  266   cov   65, ft  283   +6% features
#
# The spread tracks how many fixed bytes stand in front of the code.
# wsdeflate has to say "permessage-deflate" before ANY of its
# parameter parser or its zlib loop is reachable, and in 5.3 million
# bare runs the mutator never once said it. The websocket framer has
# no such gate, so its numbers do not move, and its dictionary earns
# its place by being the same discipline everywhere rather than by a
# number. The weak row is here too; a measurement that only gets
# published when it flatters is not one.
#
# MEMORY IS SHOWN, NOT PREDICTED. It was predicted once and the
# prediction was wrong by half: ~183 MB per -fork child, measured on
# wsdeflate alone - the SMALLEST target - and then generalised to all
# five. A real 30-worker run across all of them came back at ~400 MB
# per worker, because feed and assets carry far more instrumented
# code and therefore far more shadow map. The estimate also cannot
# know the toolchain: what a child costs depends on the clang and the
# ASan defaults it was built with.
#
# So the footer sums the RSS of this run's own processes every
# refresh. A number on the screen from the machine it is running on
# beats an estimate in a comment, and it is the same rule the rest of
# this tree lives by.
#
# Rough planning figure, and it is a PEAK not an average because
# fork-mode RSS breathes (children are replaced, the parent merges
# between rounds): about 0.5 GB per worker. Two measurements agree on
# the order - 292 MB/worker peak in a container across all five
# targets, 400-500 MB/worker reported on a 32-thread host running
# thirty. So thirty workers wants ~15 GB with room to breathe.
# Check the footer, not this line.
#
# RSS_LIMIT stays at 4 GB per PROCESS and is deliberately not a knob
# to turn up - a child that crosses it is an OOM FINDING, so raising
# it hides what it should show. UNIT_TIMEOUT makes a hang a finding
# too, instead of something indistinguishable from a slow input.
#
# AND WHAT A SHORT RUN PROVES, written down because it is less than it
# looks: the calibration this project has is a CBOR decoder in a
# neighbouring tree that took seven to eight hours across four cores
# before its first finding surfaced. A three-minute run on one core is
# three orders of magnitude short of that, so "22 million runs, no
# crash" says only that nothing surfaced IN THAT WINDOW. A run in a
# container is a smoke test - targets build, dictionaries parse, seeds
# are accepted, obvious paths do not fault. The campaign is a
# different act and belongs on a machine with cores to spare.
#
# The corpus is kept and reused, so a second campaign does not start
# from nothing. tools/fuzz-merge.sh shrinks it back to the smallest
# set with the same coverage when it has grown past what is useful.
set -eu
cd "$(dirname "$0")/.."

TARGETS="ws wsdeflate http feed assets"
SECONDS_TO_RUN="${1:-0}"
WORKERS="${WORKERS:-1}"
RSS_LIMIT="${RSS_LIMIT:-4096}"
UNIT_TIMEOUT="${UNIT_TIMEOUT:-25}"
# HOW LONG IS TOO QUIET, and WHAT COUNTS AS QUIET - the second half
# matters more than the first.
#
# A PLATEAU IS NOT A SLOW RUN. Coverage (cov: basic blocks) flattens
# early and then sits still for hours while the run is very much
# still learning: what keeps moving is FEATURES (ft: edge counters
# bucketed by hit count, plus the value profile) and the CORPUS that
# grows with them. A target grinding through deep, expensive inputs
# at four thousand exec/s with flat cov and climbing ft is working,
# not stuck, and waking somebody for it is how an alert gets ignored.
#
# So staleness here means NONE of the three moved - not cov, not ft,
# not the corpus. That is a plateau: the mutator is producing nothing
# the target has not already seen.
#
# Twenty minutes: long enough that a deep target is not interrupted
# for catching its breath, short enough that a dead harness does not
# burn a night.
STALE_ALERT="${STALE_ALERT:-1200}"

LIBMRUBY=mruby/build/host/lib/libmruby.a
[ -f "$LIBMRUBY" ] || { echo "$LIBMRUBY missing - run: rake compile" >&2; exit 1; }
command -v clang++ >/dev/null || { echo 'clang++ not found (libFuzzer is clang only)' >&2; exit 1; }

OUT=build/fuzz
mkdir -p "$OUT"

build_target() {
  t=$1
  clang++ -g -O1 -std=c++20 -no-pie \
    -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
    -fno-sanitize=alignment \
    -Imruby/include -Imruby/build/host/include \
    -Imruby/build/repos/host/mruby-phr/deps/picohttpparser \
    -Ideps/ls-hpack -Imruby/build/repos/host/mruby-string-is-utf8/include \
    "test/fuzz/${t}_fuzz.cpp" "$LIBMRUBY" \
    mruby/build/host/mrbgems/mruby-io-uring/build/lib/liburing.a \
    -lz -lcrypto -lpthread -lm -o "$OUT/$t"
}

# One conformant input per shape a target has. Idempotent: fixed
# names, so re-running neither duplicates nor overwrites what
# libFuzzer has since found, and it merges them with the rest.
#
# The seeds are RFC EXAMPLES where the RFC has one - the websocket
# text seed is byte-for-byte 6455 5.7's masked "Hello" - and
# hand-built minimal cases where it does not. They are planted here
# rather than committed as blobs so the bytes sit next to the citation
# that explains them, and a reader can check them against the spec
# instead of trusting a binary file.
plant_seeds() {
  t=$1
  c="$OUT/corpus-$t"
  case "$t" in
  ws)
    # RFC 6455 5.7's own worked example: a single-frame masked text
    # message carrying "Hello".
    printf '\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58' > "$c/seed-text"
    # 5.4: the same five bytes as two fragments, "Hel" then "lo".
    printf '\x01\x83\x37\xfa\x21\x3d\x7f\x9f\x4d\x80\x82\x37\xfa\x21\x3d\x5b\x95' \
      > "$c/seed-fragmented"
    # 5.5.2: a ping carrying the same payload, masked as 5.1 requires.
    printf '\x89\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58' > "$c/seed-ping"
    # 5.5.1 with 7.4.1: a close carrying 1000, masked.
    printf '\x88\x82\x37\xfa\x21\x3d\x34\x12' > "$c/seed-close"
    # 5.2: the 16-bit length form, at its smallest legal value (126).
    { printf '\x82\xfe\x00\x7e\x00\x00\x00\x00'; head -c 126 /dev/zero; } > "$c/seed-len16"
    # 7692 6: the same text message, flagged compressed.
    printf '\xc1\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58' > "$c/seed-rsv1"
    # 4.2.2's own key, so accept_key gets a 24-character base64 input
    # rather than having to grow one.
    printf 'dGhlIHNhbXBsZSBub25jZQ==' > "$c/seed-key"
    ;;
  wsdeflate)
    # Byte 0 is where the header ends (the target's own split), so
    # each seed names its header's length, then the header, then a
    # DEFLATE stream. 0x12 = 18 = len("permessage-deflate").
    #
    # The stream is RFC 1951 3.2.4's stored block: BTYPE 00, LEN 5,
    # ~LEN, then "hello". 7692 7.2.2's four-byte tail is what the
    # target appends itself, so this is one whole compressed message.
    printf '\x12permessage-deflate\x00\x05\x00\xfa\xffhello' > "$c/seed-bare"
    printf '\x2apermessage-deflate; server_no_context_takeover\x00\x05\x00\xfa\xffhello' \
      > "$c/seed-snct"
    printf '\x29permessage-deflate; server_max_window_bits=9\x00\x05\x00\xfa\xffhello' \
      > "$c/seed-window"
    printf '\x26permessage-deflate; client_max_window_bits\x00\x00\x00\xff\xff' \
      > "$c/seed-empty-message"
    ;;
  http)
    # Byte 0 splits name from value, byte 1 scales the representation
    # length a range is measured against. 0x05 = len("range").
    printf '\x05\x10rangebytes=0-499' > "$c/seed-range"
    printf '\x05\x00rangebytes=-500' > "$c/seed-range-suffix-empty"
    printf '\x08\x10if-rangeW/\"abc\"' > "$c/seed-if-range"
    printf '\x0d\x10if-none-match\"a\", W/\"b\", \"c\"' > "$c/seed-etag-list"
    printf '\x0f\x10accept-encodingdeflate, gzip;q=0.8, *;q=0.1' > "$c/seed-accept-encoding"
    printf '\x0e\x10content-length18446744073709551615' > "$c/seed-content-length"
    printf '\x11\x10if-modified-sinceSun, 06 Nov 1994 08:49:37 GMT' > "$c/seed-imf-date"
    ;;
  feed)
    # Byte 0 picks the protocol, byte 1 is the chunk width; 0xff means
    # "hand it over whole", which is the shape a real receive has.
    printf '\x00\xffGET / HTTP/1.1\r\nHost: x\r\n\r\n' > "$c/seed-h1-get"
    printf '\x00\xffHEAD / HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\n\r\n' \
      > "$c/seed-h1-conditional"
    printf '\x00\xffGET / HTTP/1.1\r\nHost: x\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n' \
      > "$c/seed-h1-pipelined"
    # RFC 6455 4.1's handshake, where the websocket half of feed()
    # begins.
    printf '\x00\xffGET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' \
      > "$c/seed-h1-upgrade"
    # Mode 1 prepends RFC 9113 3.4's preface itself; what follows is
    # the empty SETTINGS a client opens with (6.5), then a HEADERS
    # carrying RFC 7541 Appendix A's indexed :method/:path/:scheme and
    # a literal :authority.
    printf '\x01\xff\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x07\x01\x05\x00\x00\x00\x01\x82\x84\x86\x41\x01x' \
      > "$c/seed-h2-request"
    ;;
  assets)
    # APPNOTE 4.3.16: the smallest legal zip there is - an End of
    # Central Directory record with no entries. Everything the target
    # can reach is found by scanning BACKWARDS for this signature, so
    # without it the whole run stops at the first check.
    printf 'PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
      > "$c/seed-empty-zip"
    # A real one-entry archive, built by zip(1) if it is here - the
    # format has too many cross-references between its three records
    # for a hand-written literal to be worth trusting.
    if command -v zip >/dev/null; then
      d=$(mktemp -d)
      printf '<!doctype html><title>x</title>' > "$d/index.html"
      # zip writes the archive, then it is COPIED - not piped. Not
      # because a pipe breaks it (measured: the general-purpose flags
      # come out 0x0000 either way, so zip does not fall back to a
      # data descriptor here), but because an archive that arrives
      # through a pipe invites exactly that question, and the answer
      # cost an hour once. A file is a file.
      (cd "$d" && zip -q -X one.zip index.html && zip -q -X -0 stored.zip index.html)
      cp "$d/one.zip" "$c/seed-one-entry" 2>/dev/null || true
      cp "$d/stored.zip" "$c/seed-stored" 2>/dev/null || true
      rm -rf "$d"
    fi
    ;;
  esac
}

# --- build everything first: a campaign that dies on the third
# target's compile error after two are already running is worse than
# one that has not started.
n=0
for t in $TARGETS; do
  n=$((n + 1))
  printf 'building %-10s ' "$t"
  build_target "$t"
  mkdir -p "$OUT/corpus-$t" "$OUT/crashes-$t"
  plant_seeds "$t"
  echo "ok ($(ls "$OUT/corpus-$t" | wc -l) corpus files)"
done

per=$((WORKERS / n))
[ "$per" -lt 1 ] && per=1
fork_flag=""
[ "$per" -gt 1 ] && fork_flag="-fork=$per"

time_flag=""
if [ "$SECONDS_TO_RUN" -gt 0 ]; then
  time_flag="-max_total_time=$SECONDS_TO_RUN"
  echo "capped at ${SECONDS_TO_RUN}s - a smoke test, not a campaign (see the head)"
else
  echo "no time limit: runs until Ctrl-C"
fi
echo "$n targets x $per workers = $((n * per)) (~$(((n * per) / 2)) GB at 0.5 GB/worker peak - the footer measures the real figure)"
echo "findings -> $OUT/crashes-<target>/   corpus -> $OUT/corpus-<target>/   logs -> $OUT/<target>.log"
echo

pids=""
for t in $TARGETS; do
  # shellcheck disable=SC2086  # each flag is empty or one word, on purpose
  "$OUT/$t" "$OUT/corpus-$t" -dict="test/fuzz/$t.dict" $fork_flag $time_flag \
    -artifact_prefix="$OUT/crashes-$t/" -timeout="$UNIT_TIMEOUT" \
    -print_final_stats=1 -rss_limit_mb="$RSS_LIMIT" > "$OUT/$t.log" 2>&1 &
  pids="$pids $!"
done

# Ctrl-C reaches the children through the process group already; this
# is here so the summary below is printed on the way out rather than
# the shell simply ending.
stop() { kill $pids 2>/dev/null || true; }
trap stop INT TERM

# WHAT A CAMPAIGN LOOKS LIKE WHILE IT RUNS. Five interleaved
# libFuzzer streams are unreadable and a table appended every thirty
# seconds is just a slower log - after six hours it is four hundred
# tables nobody scrolls back through. So on a terminal this draws ONE
# table IN PLACE and keeps it current.
#
# The columns answer the one question a long run actually asks: is it
# still learning? NEW says what moved since the last refresh - c for
# coverage, f for features, + for a corpus entry - and STALE is how
# long since ANY of them did. Watching cov alone would call a healthy
# run stuck, because cov flattens early and stays flat while ft
# climbs for hours; watching all three is what makes STALE mean
# plateau instead of "this target is expensive".
#
# A target that really has plateaued is telling you one of two things
# and they look identical in a log: it is done, or its harness cannot
# reach further. That ambiguity is what made the ws target's
# 62-of-137 blocks read as saturation for an afternoon - so past
# STALE_ALERT the tool stops watching and goes and asks
# (see stall_report).
#
# Piped or redirected (nohup, CI, tee), it falls back to appending -
# cursor motion into a file is noise.
declare -A prev_cov prev_ft prev_corp last_new seen_crash alerted
pending_stall=""
now() { date +%s; }
PEAK_KIB=0
START=$(now)

read_stat() {  # $1 target -> sets R_EXEC R_COV R_FT R_CORP R_EPS R_OTC
  # The last progress line, whichever shape it has: -fork prints
  # "oom/timeout/crash", a single process does not, and both carry
  # "cov: ". The final-stats block at the end carries neither, so
  # anchoring on tail -1 would go blank exactly when it matters.
  local line
  line=$(grep -a 'cov: ' "$OUT/$1.log" 2>/dev/null | tail -1)
  R_EXEC=$(printf '%s' "$line" | sed -n 's/^#\([0-9]*\).*/\1/p')
  R_COV=$(printf '%s' "$line" | sed -n 's/.*cov: \([0-9]*\).*/\1/p')
  R_FT=$(printf '%s' "$line" | sed -n 's/.*ft: \([0-9]*\).*/\1/p')
  R_CORP=$(printf '%s' "$line" | sed -n 's/.*corp: \([0-9]*\).*/\1/p')
  R_EPS=$(printf '%s' "$line" | sed -n 's/.*exec\/s: \([0-9]*\).*/\1/p')
  R_OTC=$(printf '%s' "$line" | sed -n 's/.*oom\/timeout\/crash: \([0-9\/]*\).*/\1/p')
}

human() {  # seconds -> 4m12s
  local s=$1
  if [ "$s" -lt 60 ]; then printf '%ds' "$s"
  elif [ "$s" -lt 3600 ]; then printf '%dm%02ds' $((s / 60)) $((s % 60))
  else printf '%dh%02dm' $((s / 3600)) $(((s % 3600) / 60)); fi
}

# A finding is the entire reason the machine is running. It does not
# get a row in a table - it gets the screen, once, with the bytes.
announce_crashes() {
  local t f
  for t in $TARGETS; do
    for f in "$OUT/crashes-$t"/*; do
      [ -e "$f" ] || continue
      [ -n "${seen_crash[$f]:-}" ] && continue
      seen_crash[$f]=1
      printf '\n\033[1;31m=== FINDING: %s (%s) ===\033[0m\n' "$t" "$f"
      head -c 256 "$f" | od -An -tx1z | head -8
      printf 'reproduce: %s %s\n\n' "$OUT/$t" "$f"
    done
  done
}

# WHY IT STOPPED, asked instead of guessed. A target that has gone
# STALE_ALERT without a new edge, a new feature OR a new corpus entry
# is saying one of exactly two things, and they look identical from
# the outside:
#
#   1. it is done - every branch the harness can reach is reached;
#   2. the HARNESS cannot reach any further, and no number of cores
#      will change that.
#
# libFuzzer can tell them apart: -print_coverage=1 replays the corpus
# and NAMES the functions, covered and not, with the fraction of each
# one's edges taken. That is the difference between "coverage
# plateaued" and "half this file is not being tested" - which is
# exactly the reading that took an afternoon to notice on the ws
# target by eye.
#
# It runs on a COPY of the work already done: -runs=0 over the
# existing corpus, one short process, nothing mutated and the
# campaign untouched.
stall_report() {
  local t=$1 for_secs=$2 probe
  probe=$(timeout 120 "$OUT/$t" "$OUT/corpus-$t" -runs=0 -print_coverage=1 \
            -rss_limit_mb="$RSS_LIMIT" 2>&1 || true)
  printf '\n\033[1;33m=== %s: PLATEAU - no new coverage, feature or corpus entry in %s ===\033[0m\n' \
    "$t" "$(human "$for_secs")"
  printf '%s\n' "$probe" | grep -a 'inline 8-bit counters' | head -1

  # OUR OWN SOURCES ONLY. An uninstrumented run reports every
  # std::vector and basic_string method the target dragged in, and
  # forty lines of libstdc++ bury the two lines that matter. What is
  # asked here is whether THIS TREE's code is reached, so the filter
  # is src/ and test/fuzz/ and nothing else.
  local mine='(/src/|/test/fuzz/)'
  local short='s@[^ ]*/(src|test)/@\1/@'

  # Functions the corpus never entered at all. The caveat is real and
  # is printed with them: at -O1 a small function called once gets
  # INLINED, and its out-of-line copy is then legitimately dead - so a
  # name here means "look", not "bug".
  local unc
  unc=$(printf '%s\n' "$probe" | grep -aE "^UNCOVERED_FUNC.*$mine" \
        | sed -E "s/^UNCOVERED_FUNC: hits: [0-9]+ edges: 0\/([0-9]+) /\1 edges  /; $short")
  if [ -n "$unc" ]; then
    printf '\nnever entered (some of these are just inlined - check the source):\n'
    printf '%s\n' "$unc" | sort -rn | head -10 | sed 's/^/  /'
  fi

  # Covered, but with branches left. Sorted by how much is still
  # unexplored, because that is where more cores would actually go.
  printf '\nleast-explored (edges taken of edges present):\n'
  printf '%s\n' "$probe" | grep -aE "^COVERED_FUNC.*$mine" \
    | sed -E 's/^COVERED_FUNC: hits: [0-9]+ edges: ([0-9]+)\/([0-9]+) /\1 \2 /' \
    | awk '{ pct = ($2 > 0) ? int($1 * 100 / $2) : 100
             if (pct < 90) { name = ""
                             for (i = 3; i <= NF; i++) name = name (i > 3 ? " " : "") $i
                             printf "%3d%% %5s/%-5s %s\n", pct, $1, $2, name } }' \
    | sort -n | head -10 | sed -E "$short" | sed 's/^/  /'

  if [ -n "$unc" ]; then
    printf '\nreading: a function nothing entered is a HARNESS question, not a\n'
    printf 'core question - more workers will not reach it. Widen the target.\n\n'
  else
    printf '\nreading: everything is entered. A LOW FRACTION IS NOT AUTOMATICALLY\n'
    printf 'a missing branch - counters get attributed to a function from code\n'
    printf 'inlined into it, so a straight-line function can sit at 4 of 14 no\n'
    printf 'matter what it is fed (measured: spell_content_length does exactly\n'
    printf 'that). Before widening the target, check the SOURCE for a branch\n'
    printf 'that could take the missing edges, and test the guess on a handful\n'
    printf 'of crafted inputs with -runs=0 -print_coverage=1. If they reach\n'
    printf 'less than the corpus already does, the corpus was not the problem.\n\n'
  fi
}

render() {
  local t elapsed stale
  elapsed=$(( $(now) - START ))
  printf '%-11s %8s %9s %8s %7s %8s %9s %9s   %s\n' \
    TARGET COV FEATURES CORPUS NEW STALE EXEC/S TOTAL 'oom/to/crash'
  for t in $TARGETS; do
    read_stat "$t"
    local cov=${R_COV:-0} ft=${R_FT:-0} corp=${R_CORP:-0}
    # ANY of the three moving is progress. cov alone is the coarse
    # one and it is flat most of the time on a healthy run.
    local moved=''
    [ "$cov"  -gt "${prev_cov[$t]:-0}"  ] && moved="${moved}c"
    [ "$ft"   -gt "${prev_ft[$t]:-0}"   ] && moved="${moved}f"
    [ "$corp" -gt "${prev_corp[$t]:-0}" ] && moved="${moved}+"
    prev_cov[$t]=$cov; prev_ft[$t]=$ft; prev_corp[$t]=$corp
    if [ -n "$moved" ]; then
      last_new[$t]=$(now)
      alerted[$t]=''
    fi
    local stale_secs=$(( $(now) - ${last_new[$t]:-$START} ))
    stale=$(human "$stale_secs")
    # Once per quiet spell, not once per refresh: any progress re-arms.
    if [ "$stale_secs" -ge "$STALE_ALERT" ] && [ -z "${alerted[$t]:-}" ]; then
      alerted[$t]=1
      pending_stall="$pending_stall $t:$stale_secs"
    fi
    printf '%-11s %8s %9s %8s %7s %8s %9s %9s   %s\n' \
      "$t" "${R_COV:--}" "${R_FT:--}" "${R_CORP:--}" "${moved:--}" "$stale" \
      "${R_EPS:--}" "${R_EXEC:--}" "${R_OTC:--}"
  done
  # This run's own footprint, from the machine it is on. Everything
  # libFuzzer forked lives under $OUT/, so the binary path is the
  # whole filter.
  # RSS BREATHES in fork mode - children are replaced as they go and
  # the parent runs a merge between rounds - so the momentary figure
  # is not the one to reserve against. The PEAK is, and it is kept.
  local kib procs
  kib=$(ps -eo rss,cmd 2>/dev/null | grep -a "[ ]*[0-9]* $OUT/" | awk '{s += $1} END {print s + 0}')
  procs=$(ps -eo rss,cmd 2>/dev/null | grep -ac "[ ]*[0-9]* $OUT/" || true)
  [ "$kib" -gt "$PEAK_KIB" ] && PEAK_KIB=$kib
  printf '\nrunning %s   %d x %d workers   memory %s now, %s peak   (%s procs, %s per worker at peak)\n' \
    "$(human "$elapsed")" "$n" "$per" \
    "$(awk -v k="$kib" 'BEGIN{printf "%.1f GB", k/1048576}')" \
    "$(awk -v k="$PEAK_KIB" 'BEGIN{printf "%.1f GB", k/1048576}')" \
    "$procs" \
    "$(awk -v k="$PEAK_KIB" -v w=$((n * per)) 'BEGIN{printf "%.0f MB", (w ? k/w/1024 : 0)}')"
  printf 'findings -> %s/crashes-<target>/\n' "$OUT"
}

rows=$((n + 4))
if [ -t 1 ]; then
  printf '\033[?25l'                       # the cursor has nothing to say here
  trap 'printf "\033[?25h"; stop' INT TERM EXIT
  first=1
  while :; do
    announce_crashes
    [ "$first" -eq 1 ] || printf '\033[%dA' "$rows"
    first=0
    pending_stall=""
    render
    # Reports print BELOW the table and then the table starts fresh -
    # a stall report is something to read, not something to overwrite
    # two seconds later.
    if [ -n "$pending_stall" ]; then
      for entry in $pending_stall; do
        stall_report "${entry%%:*}" "${entry##*:}"
      done
      first=1
    fi
    alive=0
    for p in $pids; do kill -0 "$p" 2>/dev/null && alive=$((alive + 1)); done
    [ "$alive" -eq 0 ] && break
    sleep 2
  done
  printf '\033[?25h'
else
  while :; do
    sleep 30
    announce_crashes
    echo
    pending_stall=""
    render
    for entry in $pending_stall; do
      stall_report "${entry%%:*}" "${entry##*:}"
    done
    alive=0
    for p in $pids; do kill -0 "$p" 2>/dev/null && alive=$((alive + 1)); done
    [ "$alive" -eq 0 ] && break
  done
fi

wait || true
announce_crashes
echo
echo "done. Findings, if any, are in $OUT/crashes-<target>/ - and a file there is the run's whole point."
