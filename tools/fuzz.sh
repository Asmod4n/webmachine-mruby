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
# MEMORY, measured rather than guessed, and the two modes differ by
# more than three times: a long single process peaks at 466-625 MB, a
# -fork child sits at ~183 MB, because a child is short-lived and
# never accumulates the corpus and the quarantine. Budget ~0.2 GB per
# worker: 30 workers is about 7 GB no matter how they are split across
# targets. RSS_LIMIT stays at 4 GB per process and is deliberately not
# a knob to turn up - a child that crosses it is an OOM FINDING, so
# raising it hides what it should show. UNIT_TIMEOUT makes a hang a
# finding too, instead of something indistinguishable from a slow
# input.
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
      (cd "$d" && zip -q -X - index.html) > "$c/seed-one-entry" 2>/dev/null || \
        rm -f "$c/seed-one-entry"
      (cd "$d" && zip -q -X -0 - index.html) > "$c/seed-stored" 2>/dev/null || \
        rm -f "$c/seed-stored"
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
echo "$n targets x $per workers = $((n * per)), ~$(((n * per) / 5 + 1)) GB expected (0.2 GB/child measured)"
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

# ONE STATUS LINE PER TARGET, not five interleaved streams. The full
# output of each is in its own log; what belongs on a screen somebody
# watches for hours is the three numbers that decide whether to keep
# going: coverage, corpus size, and the findings counter.
status() {
  printf '\n%-11s %8s %8s %8s   %s\n' TARGET COV CORPUS EXEC/S 'oom/timeout/crash'
  for t in $TARGETS; do
    # The last progress line, whichever shape it has: -fork prints
    # "oom/timeout/crash", a single process does not, and both carry
    # "cov: ". The final-stats block at the end of a run carries
    # neither, so anchoring on tail -1 would show nothing exactly when
    # the numbers matter most.
    line=$(grep -a 'cov: ' "$OUT/$t.log" 2>/dev/null | tail -1)
    cov=$(printf '%s' "$line" | sed -n 's/.*cov: \([0-9]*\).*/\1/p')
    corp=$(printf '%s' "$line" | sed -n 's/.*corp: \([0-9]*\).*/\1/p')
    eps=$(printf '%s' "$line" | sed -n 's/.*exec\/s: \([0-9]*\).*/\1/p')
    otc=$(printf '%s' "$line" | sed -n 's/.*oom\/timeout\/crash: \([0-9\/]*\).*/\1/p')
    found=$(ls "$OUT/crashes-$t" 2>/dev/null | wc -l)
    [ "$found" -gt 0 ] && otc="$otc  <-- $found FILE(S) IN crashes-$t/"
    printf '%-11s %8s %8s %8s   %s\n' "$t" "${cov:--}" "${corp:--}" "${eps:--}" "${otc:--}"
  done
}

while :; do
  sleep 30
  alive=0
  for p in $pids; do kill -0 "$p" 2>/dev/null && alive=$((alive + 1)); done
  status
  [ "$alive" -eq 0 ] && break
done

wait || true
status
echo
echo "done. Findings, if any, are in $OUT/crashes-<target>/ - and a file there is the run's whole point."
