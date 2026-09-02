# Fix three pieces of undefined behaviour on the decode path

All three are reported by this project's own test suite under
`-fsanitize=undefined`, so nothing here needs a fuzzer to reproduce:

```sh
cmake -S . -B build-ubsan -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-sanitize=alignment -g" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build build-ubsan -j
for t in build-ubsan/test/test_*; do "$t"; done
```

`-fno-sanitize=alignment` only silences the bundled xxhash, which reads
unaligned on purpose; it is not part of this PR.

On master (cf0f70d) that prints:

```
test_hpack_hash0_http0   lshpack.c:236:5   null pointer passed as argument 2,
                                           which is declared to never be null
test_hpack_hash0_http1   lshpack.c:236:5   (same)
test_hpack_hash1_http0   lshpack.c:236:5   (same)
test_hpack_hash1_http1   lshpack.c:236:5   (same)
test_int                 lshpack.c:1329:37 shift exponent 35 is too large for
                                           32-bit type 'unsigned int'
test_int                 lshpack.c:1339:65 left shift of 15 by 28 places cannot
                                           be represented in type 'int'
```

With this branch all five tests run clean, with the same exit codes and
the same decoded values.

## 1 — `lshpack_arr_push` copies from a NULL pointer

`lshpack_arr_init` is a `memset`, so a fresh `lshpack_arr` has
`els == NULL`, `off == 0`, `nelem == 0`. The first `lshpack_arr_push`
therefore takes the `malloc` path and calls

```c
memcpy(new_els, arr->els + arr->off, sizeof(arr->els[0]) * arr->nelem);
```

which is `memcpy(new_els, NULL + 0, 0)`. Nothing is copied, but `NULL + 0`
is undefined arithmetic (C17 6.5.6p8) and `memcpy`'s source is declared
non-null, so it is undefined twice over.

It is reached on the first dynamic-table insert of every decoder — in
practice, on the first request an HTTP/2 connection carries that has a
field with incremental indexing.

The fix guards the copy on `nelem`. When the array has elements, `els` is
not NULL and the copy runs exactly as before.

## 2 — `lshpack_dec_dec_int` shifts a `uint32_t` by 35

The continuation loop is bounded by the buffer, not by the encoding:

```c
    M = 0;
    do
    {
        if (src < src_end)
        {
            B = *src++;
            val = val + ((B & 0x7f) << M);
            M += 7;
        }
        else if (src - orig_src < LSHPACK_UINT32_ENC_SZ)
            return -1;
        else
            return -2;
    }
    while (B & 0x80);
```

A peer that keeps setting the high bit gets a sixth continuation octet
added at `M == 35`, and `B` is a `uint32_t`. A shift wider than the type
is undefined (C17 6.5.7p3).

`LSHPACK_UINT32_ENC_SZ` already names the limit — six octets, the prefix
and five continuations, the last shifted by 28 — but it is only consulted
when the *buffer* runs out, not when the *encoding* does.

`test/test_int.c` reaches it with a case that is already in the suite:

```c
{   .it_lineno      = __LINE__,
    .it_prefix_bits = 7,
    .it_encoded     = { 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, },
    .it_enc_sz      = 11,
    .it_dec_retval  = -2,
},
```

The fix checks the bound before the octet is consumed. An encoding of six
or more continuations returns `-2` without shifting — which is the value
the post-loop check already produced for those inputs, since `M` would be
42 or more and it accepts only `M <= 28` or `M == 35`. No accepted
encoding changes; the six-octet `UINT32_MAX` case in `test_int` still
decodes to `UINT32_MAX`.

## 3 — the range check shifts a promoted `int`

The six-octet arm of the same function computes

```c
if (M <= 28 || (M == 35 && src[-1] <= 0xF && val - (src[-1] << 28) < val))
```

`src[-1]` is an `unsigned char` and promotes to `int`, so `src[-1] << 28`
is a **signed** shift. It overflows for any value above 7, and the arm is
guarded by `src[-1] <= 0xF` — so 8 through 0xF are exactly the values
that reach it. Signed overflow is undefined (C17 6.5p5), and the
expression is an unsigned wrap comparison to begin with.

`test_int` reports it on the case that decodes `UINT32_MAX`, whose last
octet is `0x0F`.

Casting to `uint32_t` says what was meant. On the usual two's-complement
target the bits were already right; this makes them right by the standard
rather than by the compiler's mood.

## Provenance

1 and 2 came out of fuzzing an HTTP/2 server that uses ls-hpack, through
a real socket with libFuzzer and ASan+UBSan; 3 turned up when that
server's maintainers ran your test suite under the same flags while
checking the first two. Each fix was then applied on its own and the
server re-fuzzed and re-run against h2spec (145/146, its one failure
unrelated and unchanged) after each.
