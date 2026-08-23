#!/bin/bash
# The framers under libFuzzer + ASan + UBSan (#88).
#
#   tools/fuzz.sh ws [seconds]         the websocket framing alone
#   tools/fuzz.sh wsdeflate [seconds]  RFC 7692's negotiation and codec
#   tools/fuzz.sh feed [seconds]       h1 heads and h2 frames through Http1::feed
#
#   WORKERS=24 tools/fuzz.sh wsdeflate 28800    a real campaign
#
# clang, not the tree's gcc: libFuzzer is clang's. The targets INCLUDE
# the sources they test (see their heads) so ASan instruments them,
# and link libmruby.a for everything else - its members are not pulled
# for symbols the target already defines.
#
# EVERY TARGET GETS A DICTIONARY AND A SEED CORPUS, and both are the
# same idea said twice: a mutator that has to DISCOVER a protocol's
# fixed bytes spends its whole budget in front of the code worth
# testing. "PRI * HTTP/2.0" is 24 bytes it will never find by
# flipping bits; "permessage-deflate" is 18; a legal websocket first
# byte is five bits it gets wrong 31 times out of 32.
#
#   test/fuzz/<target>.dict   the protocol's own alphabet, RFC-cited
#   plant_seeds()             one conformant input per shape, below
#
# The seeds are RFC EXAMPLES where the RFC has one (6455 5.7's masked
# "Hello" is byte-for-byte the spec's), and hand-built minimal cases
# where it does not. They are planted into the corpus rather than
# committed as blobs: the bytes are DERIVED here, next to the citation
# that explains them, so a reader can check them against the RFC
# instead of trusting a binary file.
#
# WHAT IT BOUGHT, measured cold - empty corpus, both arms the same
# seconds, same container. Coverage, not throughput, so this is a fact
# about REACH and not a number Gebot 10 would send to real hardware:
#
#                        bare              dict + seeds
#   feed (20s)     cov  714, ft 1859   cov 1124, ft 3456   +57% blocks
#   wsdeflate (30s) cov 135, ft  869   cov  292, ft 1228  +116% blocks
#   ws (25s)       cov   65, ft  266   cov   65, ft  283   +6% features
#
# The spread across those three rows is the whole argument, and it
# lines up exactly with how many fixed bytes stand in front of the
# code. wsdeflate has to say "permessage-deflate" before ANY of its
# parameter parser or its zlib loop is reachable, and in 5.3 million
# bare runs the mutator never once said it - more than half the target
# was dead code to the fuzzer. feed has to produce a request line or
# 24 bytes of h2 preface. The websocket framer has no such gate at
# all: five bits of opcode is something random bytes hit constantly,
# so its numbers do not move, and the dictionary there earns its place
# by being the same discipline everywhere rather than by a number.
set -eu
cd "$(dirname "$0")/.."

TARGET="${1:-ws}"
SECONDS_TO_RUN="${2:-60}"
# ONE PROCESS FINDS NOTHING IN AN AFTERNOON. A real run is every core
# for a working day, and libFuzzer's own answer to that is -fork: N
# children, one shared corpus, and a child that crashes or runs out of
# memory is REPLACED rather than ending the run - which is the whole
# difference between a campaign and a demo.
#
#   WORKERS=24 tools/fuzz.sh wsdeflate 28800     # 24 cores, 8 hours
#
# HOW MUCH MEMORY THAT IS, measured rather than guessed - and the two
# modes differ by more than three times, so the number that matters is
# the one for the mode being run:
#
#   one long process   466-625 MB peak   (-print_final_stats)
#   -fork child        ~183 MB steady    (RSS summed over live children)
#
# The gap is the point of fork mode: a child is short-lived and
# REPLACED, so it never accumulates the corpus and the quarantine the
# way a process running for eight hours does. Budget ~0.2 GB per
# worker plus a little for the merges the parent runs between rounds:
#
#   WORKERS=24  ~5 GB       WORKERS=32  ~7 GB
#
# Which means 32 threads and 28 GB can run all three targets at once
# and still not be the constraint - cores are.
#
# WHAT A SHORT RUN PROVES, and it is less than it looks. The
# calibration this project actually has: a CBOR decoder in a
# neighbouring tree took SEVEN TO EIGHT HOURS across four cores before
# its first finding surfaced. Against that, a three-minute run on one
# core is three orders of magnitude short, and "22 million runs, no
# crash" says only that nothing surfaced IN THAT WINDOW. It is not
# evidence of absence and must never be reported as if it were.
#
# So the runs in this container are a SMOKE TEST - they prove the
# target builds, the dictionary parses, the seeds are accepted and the
# obvious paths do not fault. The campaign is a different act, it
# belongs on a machine with cores to spare, and its numbers belong
# with it: hours, workers, total runs, and the three counters -fork
# prints (oom/timeout/crash). A campaign that found nothing is worth
# recording precisely because the next one has to beat it.
#
# RSS_LIMIT is the PER-PROCESS ceiling libFuzzer enforces, not the
# total - a child that crosses it is reported as an OOM finding, which
# is a bug in the target, so raising it hides exactly what it should
# show. 4 GB against a 0.6 GB peak is deliberate headroom.
WORKERS="${WORKERS:-1}"
RSS_LIMIT="${RSS_LIMIT:-4096}"
# A hang is a finding too, and an unbounded one is indistinguishable
# from a slow input - twenty-five seconds is far past anything these
# framers do on a legal input.
UNIT_TIMEOUT="${UNIT_TIMEOUT:-25}"
LIBMRUBY=mruby/build/host/lib/libmruby.a
[ -f "$LIBMRUBY" ] || { echo "$LIBMRUBY missing - run: rake compile" >&2; exit 1; }
command -v clang++ >/dev/null || { echo 'clang++ not found (libFuzzer is clang only)' >&2; exit 1; }

OUT=build/fuzz
CORPUS="$OUT/corpus-$TARGET"
mkdir -p "$CORPUS"

# One conformant input per shape this target has. Idempotent: fixed
# names, so re-running neither duplicates nor overwrites what libFuzzer
# has since found. libFuzzer merges them with the rest of the corpus.
plant_seeds() {
  case "$TARGET" in
  ws)
    # RFC 6455 5.7's own worked example: a single-frame masked text
    # message carrying "Hello".
    printf '\x81\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58' > "$CORPUS/seed-text"
    # 5.4: the same five bytes as two fragments, "Hel" then "lo".
    printf '\x01\x83\x37\xfa\x21\x3d\x7f\x9f\x4d\x80\x82\x37\xfa\x21\x3d\x5b\x95' \
      > "$CORPUS/seed-fragmented"
    # 5.5.2: a ping carrying the same payload, masked as 5.1 requires.
    printf '\x89\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58' > "$CORPUS/seed-ping"
    # 5.5.1 with 7.4.1: a close carrying 1000, masked.
    printf '\x88\x82\x37\xfa\x21\x3d\x34\x12' > "$CORPUS/seed-close"
    # 5.2: the 16-bit length form, at its smallest legal value (126).
    { printf '\x82\xfe\x00\x7e\x00\x00\x00\x00'
      head -c 126 /dev/zero; } > "$CORPUS/seed-len16"
    # 7692 6: the same text message, flagged compressed.
    printf '\xc1\x85\x37\xfa\x21\x3d\x7f\x9f\x4d\x51\x58' > "$CORPUS/seed-rsv1"
    ;;
  wsdeflate)
    # Byte 0 is where the header ends (the target's own split), so each
    # seed names its header's length, then the header, then a DEFLATE
    # stream. 0x12 = 18 = len("permessage-deflate").
    #
    # The stream is RFC 1951 3.2.4's stored block: BTYPE 00, LEN 5,
    # ~LEN, then "hello". 7692 7.2.2's four-byte tail is what the
    # target appends itself, so this is one whole compressed message.
    printf '\x12permessage-deflate\x00\x05\x00\xfa\xffhello' > "$CORPUS/seed-bare"
    printf '\x2apermessage-deflate; server_no_context_takeover\x00\x05\x00\xfa\xffhello' \
      > "$CORPUS/seed-snct"
    printf '\x29permessage-deflate; server_max_window_bits=9\x00\x05\x00\xfa\xffhello' \
      > "$CORPUS/seed-window"
    printf '\x26permessage-deflate; client_max_window_bits\x00\x00\x00\xff\xff' \
      > "$CORPUS/seed-empty-message"
    ;;
  feed)
    # Byte 0 picks the protocol, byte 1 is the chunk width; 0xff means
    # "hand it over whole", which is the shape a real receive has.
    printf '\x00\xffGET / HTTP/1.1\r\nHost: x\r\n\r\n' > "$CORPUS/seed-h1-get"
    printf '\x00\xffHEAD / HTTP/1.1\r\nHost: x\r\nIf-None-Match: *\r\n\r\n' \
      > "$CORPUS/seed-h1-conditional"
    printf '\x00\xffGET / HTTP/1.1\r\nHost: x\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n' \
      > "$CORPUS/seed-h1-pipelined"
    # RFC 6455 4.1's handshake, which is where the websocket half of
    # feed() begins.
    printf '\x00\xffGET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' \
      > "$CORPUS/seed-h1-upgrade"
    # Mode 1 prepends RFC 9113 3.4's preface itself; what follows is
    # the empty SETTINGS a client opens with (6.5), then a HEADERS
    # carrying RFC 7541 Appendix A's indexed :method/:path/:scheme and
    # a literal :authority.
    printf '\x01\xff\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x07\x01\x05\x00\x00\x00\x01\x82\x84\x86\x41\x01x' \
      > "$CORPUS/seed-h2-request"
    ;;
  esac
}
plant_seeds

# -fno-sanitize=alignment: ls-hpack and phr read unaligned on purpose,
# and they are not what this run is about.
clang++ -g -O1 -std=c++20 \
  -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined \
  -fno-sanitize=alignment \
  -Imruby/include -Imruby/build/host/include \
  -Imruby/build/repos/host/mruby-phr/deps/picohttpparser \
  -Ideps/ls-hpack -Imruby/build/repos/host/mruby-string-is-utf8/include \
  "test/fuzz/${TARGET}_fuzz.cpp" "$LIBMRUBY" \
  mruby/build/host/mrbgems/mruby-io-uring/build/lib/liburing.a \
  -lz -lcrypto -lpthread -lm -o "$OUT/$TARGET"

DICT="test/fuzz/$TARGET.dict"
[ -f "$DICT" ] || { echo "$DICT missing - every target carries one (see the head)" >&2; exit 1; }

# Findings go where findings belong. Without this libFuzzer writes
# crash-<sha1> into the CURRENT DIRECTORY, which is the repository root
# - a crash would arrive as an untracked binary next to the source.
CRASHES="$OUT/crashes-$TARGET"
mkdir -p "$CRASHES"

fork_flag=""
if [ "$WORKERS" -gt 1 ]; then
  fork_flag="-fork=$WORKERS"
  echo "$WORKERS workers, ~$((WORKERS / 5 + 1)) GB expected (0.2 GB/child measured)"
fi

# shellcheck disable=SC2086  # fork_flag is empty or one word, on purpose
"$OUT/$TARGET" "$CORPUS" -dict="$DICT" $fork_flag \
  -artifact_prefix="$CRASHES/" -timeout="$UNIT_TIMEOUT" \
  -max_total_time="$SECONDS_TO_RUN" -print_final_stats=1 -rss_limit_mb="$RSS_LIMIT"
