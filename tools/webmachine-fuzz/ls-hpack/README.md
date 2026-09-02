# Two pull requests for ls-hpack, ready to send

`deps/ls-hpack` is a submodule pinned at v2.3.5 (cf0f70d), which is
upstream HEAD. Three pieces of undefined behaviour live in it, all of
them on the decode path every HTTP/2 connection walks. The patches here
fix them; they are not applied to the submodule, because a submodule
carries a pin and not a diff.

## What each one is

`0001` **`lshpack_arr_push`, a memcpy from NULL.** `lshpack_arr_init` is
a memset, so a fresh array has `els == NULL`; the first push takes the
malloc path and copies `arr->els + arr->off` — `NULL + 0` — for zero
bytes. Undefined as arithmetic and again as memcpy's non-null argument.
Reached on the first dynamic-table insert of every decoder.

`0002` **`lshpack_dec_dec_int`, a shift by 35.** The continuation loop is
bounded by the buffer, not by the encoding, so a peer that keeps setting
the high bit gets a sixth continuation octet added at `M == 35` on a
32-bit type. `LSHPACK_UINT32_ENC_SZ` already names the limit; it was only
consulted when the buffer ran out.

`0003` **`lshpack_dec_dec_int`, a signed shift that overflows.** The
six-octet arm computes `val - (src[-1] << 28)`; `src[-1]` promotes to
`int`, and the arm is guarded by `src[-1] <= 0xF`, so it overflows for
exactly the values it sees.

## How they were found and what they were checked against

`0001` and `0002` came out of `tools/fuzz-run.sh`. `0003` came out of
ls-hpack's OWN test suite, which is the part worth saying in the PR: with
`-fsanitize=address,undefined` (and `-fno-sanitize=alignment`, because
the bundled xxhash reads unaligned by design) all three report from
`make && ctest` alone, no fuzzer required.

    before   test_hpack_hash{0,1}_http{0,1}   lshpack.c:236   (0001)
             test_int                          lshpack.c:1329  (0002)
             test_int                          lshpack.c:1339  (0003)
    after    all five tests, zero reports, same exit codes

Then, applied to this tree one at a time, each with the whole gate:

| after | ls-hpack tests | webmachine | h2spec | fuzz |
|-------|----------------|------------|--------|------|
| 0001  | 4 clean, test_int still reports 1329/1339 | — | — | 30k runs, next find is 1329 |
| 0002  | only 1339 left | — | — | 40k runs clean |
| 0003  | all five clean | 2369/306, KO 0 | 145/146 | 40k runs clean |

h2spec's one failure is the refusal `tools/conformance.sh` documents:
3.5/2, an invalid preface answered by HTTP/1.1's 400 because this
listener speaks both protocols. It is the same before and after.

## The second PR: turn the sanitizer on

`PR2-ubsan.md` and `pr2-0001-*.patch`. The non-Release build already
carries `-fsanitize=address` and both CI configurations build exactly
that way, so the undefined-behaviour one goes beside it and runs on every
push - with `-fno-sanitize-recover=undefined`, because a report that only
prints leaves the suite green while it runs undefined behaviour. That is
what happened here: test_int has had the shift-by-35 case since forever
and passed on it.

It DEPENDS on the first PR - on master it turns the suite red, since all
three defects are reachable from those five tests. Send it second, or
send it first and say so; either way it is the thing that stops the next
three.

Verified: 5/5 with it, and red again if any one fix is put back.

## What is left, and it needs a person

This session cannot fork or open a pull request - its GitHub access is
scoped to asmod4n repositories and cross-owner attachment is refused. So:

1. Fork `litespeedtech/ls-hpack` (the button, or `gh repo fork`).
2. `git am tools/webmachine-fuzz/ls-hpack/pr1-*.patch` on a branch of the
   fork. They apply cleanly to cf0f70d.
3. PR to `litespeedtech/ls-hpack`, body from `PR1-fixes.md`. The three
   commits stand on their own and each names the test that reports it.
   Then a second branch with `pr2-*.patch` and `PR2-ubsan.md`.
4. Repin `deps/ls-hpack` to the fork's branch until upstream merges. Then
   `H2State`'s pre-allocated dynamic table (webmachine.hpp, the one that
   works around 0001 from our side) can go, and
   `tools/webmachine-fuzz/findings/lshpack-dec-int-shift-35.raw` moves
   into the corpus - a fixed bug wants an input that proves it stays
   fixed.
