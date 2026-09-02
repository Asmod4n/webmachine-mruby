# Handoff — #33 done, and two pull requests waiting for a person

Read once. **`git rm HANDOFF.md` belongs in your first commit** — this
note is committed so it reaches a fresh container at all, and deleting it
only locally leaves it in HEAD for every later clone. The one before this
sat there for weeks describing #210 as unfinished.

Branch `next`, 25 commits pushed, `beb46d1..236023f`. Every one of them
built, `rake test` green (2369 unit / 306 bintest, KO 0).

## Start the session in THIS checkout

The last one was started in another one, so `.claude/hooks/session-start.sh`
never ran: no rake on PATH, no handoff printed, no submodule check. **If
you do not see a `session-start: rake …, liburing …, submodules …` line
in your context, the hook did not run** and nothing it sets up is set up.
Run it by hand then, or restart in `/home/user/webmachine-mruby`.

Read `.DESIGN.md`'s commandments before writing code. `CLAUDE.md` says
they live there and not in it, and the last session grepped that file
without ever opening the rules.

## What landed

**#33 is done.** `Refusal` and `Setup` no longer exist. Every setup
refusal raises where it is known — the resource/websocket/SSE folds,
config, docroot, media types, asset packs, error pages, listeners,
certificates, log processes, `Ring::init`, `app_load`. `run_guarded` in
application.cpp is the frame a startup raise lands in, and the exception
CLASS is the exit code (`ConfigError` → 2, else 1). snprintf went 121 →
5, and none of the five is a message. The finding that made it a
two-file commit: **`mrb_funcall` only catches while `mrb->jmp` is NULL**
(mruby vm.c), so the same code behaved one way from `main` and another
from inside a Ruby callback.

**Errors go to the error log.** `say_server_error`: the log gets it,
stderr only when no error log is configured. Startup banners stay on
stderr and are not errors.

**The three benches and the fuzzer build again** — all had rotted against
the mruby-io-uring → mruby-slipstreamio rename. `bench/vm.sh`,
`bench/vm/ring_body.sh`, `build_config_libfuzzer.rb` (the fuzzer flag now
belongs to the gem, not the build, so mrbc links plain).

**The fuzzer has a corpus and a runner**: `tools/fuzz-run.sh`,
`tools/fuzz-seeds.py`, `tools/fuzz-merge.sh` rewritten for the one target
that exists. 338 inputs, 28 KB, committed.

## What is waiting for you, and only you can do it

**Two pull requests to litespeedtech/ls-hpack.** Everything is written
and verified in `tools/webmachine-fuzz/ls-hpack/`: `PR1-fixes.md` +
`pr1-000{1,2,3}-*.patch`, `PR2-ubsan.md` + `pr2-0001-*.patch`. Its README
has the order and the dependency.

Three pieces of undefined behaviour on the decode path, **all three
reported by ls-hpack's own test suite** under `-fsanitize=undefined`:
`memcpy` from NULL in `lshpack_arr_push`, a `uint32_t` shifted by 35 and
a signed `15 << 28` in `lshpack_dec_dec_int`. Nobody upstream has
reported or patched any of them (all 8 issues, all 16 PRs checked, and
lighttpd's vendored copy is byte-identical). The second PR turns UBSan on
in their CMake and makes a report fail the build; it depends on the
first.

This session could not fork or open a PR — GitHub access is scoped to
asmod4n repositories, cross-owner attach is refused. The work tree with
the commits is `/home/user/ls-hpack-fork` (branches
`fix/undefined-behaviour` and `ci/undefined-behaviour-sanitizer`), but it
does not survive the container: use the patches.

**After the fork is pinned**, and not before: `H2State`'s pre-allocated
dynamic table (webmachine.hpp, our own workaround for the first defect)
comes out, and `tools/webmachine-fuzz/findings/lshpack-dec-int-shift-35.raw`
moves into the corpus.

## Open from before, unchanged

- The matched h2 before-run: build `f115504`, alternate against
  `420a41a` at `CONNS=16 DURATION=10 PROTO=h2 STREAMS=128
  APP=examples/hello.rb`. Six after-runs exist, no collapse; the before
  side is missing. Forgecore only — this container resolves nothing under
  ~13%.
- `build_config_example.rb` and `build_config_pgo.rb` still carry
  `-march=native`.
- Remote branch deletion still blocked by the proxy:
  `webmachine-mruby/claude/slipstream-seam`, `slipstreamio/backend-split`,
  `slipstreamio/liburing-abi` need the GitHub UI.

## Environment, so it is not rediscovered

- `H2SPEC=/path/to/h2spec tools/conformance.sh h2` — no container runtime
  here (docker CLI without a daemon). Baseline is **145/146**, the one
  failure documented in the script's header.
- The libfuzzer build needs `libclang-rt-18-dev` for liburing's sanitizer
  path. `bench/vm.sh` builds its own google-benchmark; the apt package is
  not used.
- htgen no longer needs `HTGEN=`: the bench scripts look beside the repo
  now, because `$HOME` is `/root` here while the trees are under
  `/home/user`.
