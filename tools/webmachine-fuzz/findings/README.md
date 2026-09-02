# Inputs that still crash

These are NOT in the corpus, on purpose: libFuzzer replays the whole
corpus before it mutates anything, so a crasher in there would end every
campaign and every merge at startup. They live here until the defect
behind them is fixed, and then they move into the corpus - a fixed bug
with no input to prove it stays fixed is a bug waiting to come back.

Reproduce one with:

    WM_FUZZ_APP=<app.mrb> mruby/build/libfuzzer/bin/webmachine-fuzz FILE

## lshpack-dec-int-shift-35.raw

ls-hpack, `lshpack_dec_dec_int`, lshpack.c:1329:

    val = val + ((B & 0x7f) << M);

`B` is `uint32_t` and `M` reaches 35: `LSHPACK_UINT32_ENC_SZ` is 6, so the
loop reads a prefix octet and up to five continuation octets, and the
sixth shifts by 35. A shift wider than the type is undefined, and the
post-loop check that names `M == 35` explicitly shows the sixth octet is
intended - it is the arithmetic that is wrong, not the bound.

It is not preventable at our handover, which is what makes it different
from the five in .DESIGN.md's RFC 7541 section: a six-octet HPACK integer
is legal wire input that a decoder has to reject cleanly, and we cannot
pre-validate one without decoding HPACK ourselves.

It matters outside the sanitizer. In the shipped build there is no abort:
x86 masks the shift count to five bits, so `<< 35` becomes `<< 3` and the
octet lands at bit 3 instead. The check that follows subtracts
`src[-1] << 28`, a different bit position again, so a six-octet integer -
a header index, a string length - can be accepted with a value neither
the peer nor the decoder meant.

Pinned at v2.3.5 (cf0f70d), which is upstream HEAD. Found 2026-09-02 by
tools/fuzz-run.sh, four-way fork, at ~7500 units.

### Upstream, as of 2026-09-02

Nobody has reported either this or the `lshpack_arr_push` NULL + 0, and
nobody has sent a patch. Checked: all 8 issues (open: #24 the fast Huffman
decoder accepting over-long padding, #21 CMake packaging, #15 vcpkg) and
all 16 pull requests. The only open PR is #25, the maintainer's own draft
removing a `FALL_THROUGH;` in the Huffman decoder, marked "just a marker"
and "has to be finished".

lighttpd vendors ls-hpack at `src/ls-hpack/lshpack.c`, and its copy of
both functions is byte-identical to ours - so the largest downstream
consumer has not patched around either defect. That is worth knowing
before assuming somebody has already thought this through: nobody has.

#24 has been open since June 2026 for a decoder-correctness bug, which is
the response time to expect from a report.
