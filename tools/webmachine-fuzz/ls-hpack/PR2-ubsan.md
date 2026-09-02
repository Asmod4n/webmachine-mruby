# Run the tests under UndefinedBehaviorSanitizer, and stop on a report

Depends on the three decode-path fixes; on master this turns the suite
red, because all three are reachable from these five tests. Merge that
one first and this becomes what stops the next three.

## What changes

One branch of `CMakeLists.txt`, the non-Release one that already carries
`-fsanitize=address`:

```cmake
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -g3 -O0 -fsanitize=address")
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fsanitize=undefined")
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fno-sanitize-recover=undefined")
SET(MY_CMAKE_FLAGS "${MY_CMAKE_FLAGS} -fno-sanitize=alignment")
```

Both CI configurations build exactly this way — `cmake . && make && make
test`, no `CMAKE_BUILD_TYPE` — so the address sanitizer already runs on
every push and the undefined-behaviour one now runs beside it. Nothing
about the Release build changes.

## Why `-fno-sanitize-recover=undefined`

Without it a report is printed and the run continues, ctest still says
PASSED, and the suite is green while it exercises undefined behaviour.
That is not hypothetical here: the shift by 35 in `lshpack_dec_dec_int`
is executed by a case that has been in `test_int` all along —

```c
{   .it_prefix_bits = 7,
    .it_encoded     = { 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, },
    .it_enc_sz      = 11,
    .it_dec_retval  = -2,
},
```

— and the test passed the whole time, because on x86 the shift count is
masked to five bits and the wrong answer happened to still be rejected.
A sanitizer that cannot fail the build only tells you something after
somebody reads the log.

## Why `-fno-sanitize=alignment` is the one exception

`deps/xxhash/xxhash.c` reads unaligned on purpose and is compiled
directly into every test and every tool in `bin/`. With the check on it
reports `member access within misaligned address ... for type 'struct
U32_S'` from that file and from nothing else in the tree. Excluding the
one check is narrower than excluding the file, and every other check —
including all of the integer, shift and pointer ones — stays on for
`lshpack.c`.

## Verified

`cmake . && make && make test`: 5/5 pass.

Put any one of the three defects back and the run turns red, which is the
property being bought. With the `(uint32_t)` cast reverted, for instance:

```
The following tests FAILED:
	  5 - int (Failed)
```
