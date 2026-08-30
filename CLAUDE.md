# Rules for this repository

Everything in this repository is written in English: file contents,
comments, documentation, and commit messages. No German, not one word.

## Two branches, no more

There are exactly two branches:

- `next` - all development happens here.
- `master` - only finished features land here.

No topic, bench, or experiment branch beside them. Whoever tries
something out tries it out on `next`. When a feature is done, it moves
to `master` - and not before.

Check before pushing that it stays at those two:

    git ls-remote --heads origin   # master and next only

## No session URLs

A Claude session URL (`https://claude.ai/code/session_...`, whether as
a `Claude-Session:` trailer or bare) belongs nowhere that leaves the
repository or stays in it: commit messages, PR titles and bodies, issue
and review comments, code comments, documentation. That holds even
where a tool default puts one there. `Co-Authored-By:` stays allowed.

    git log --format='%B' <range> | grep -c 'claude.ai/code/session'

must be 0.

## No bang methods

No methods with `!`. Public capability questions are `?` predicates
(pattern: `KTLS::Socket#ktls_available?`).

## The rules are in .DESIGN.md, not here

The commandments are at the top of `.DESIGN.md`, from the founding
commit, and the sections under them carry the reasoning:

- `#cold-paths` - the happy path is the straight line, nothing is
  annotated, and `nm -S` decides whether a hint helped. It already
  names the problem: feed_parse, run_engine and h2_answer are ~14 KB
  of machine code each and one h1 request walks two of them, against a
  32 KiB L1i.
- `#mruby-raises` - mruby here is built with `MRB_USE_CXX_EXCEPTION`,
  always. A raise IS a C++ throw, destructors run, and a failure is
  raised rather than reported through `char* err` and `return false`.
- `#decide-then-do` - compute the round as a value, perform it in one
  place.

Read them before adding a rule. Two sources for one fact is one too
many, which is itself one of them.

## What is only true of the build

One `.cpp` anywhere makes mruby compile the WHOLE tree with the C++
compiler. There is one in this gem, so every `.c` here is C++ too, and
`MRB_USE_CXX_EXCEPTION` follows from that rather than from a choice
made per file.

`mrb_noreturn` resolves to nothing under `-std=c++20` - `common.h` asks
for `__GNUC__ && !__STRICT_ANSI__`, and a strict `-std=` defines
`__STRICT_ANSI__` - so a function ending in `mrb_raise` still needs
`__builtin_unreachable()`.

Only the debug config is built while developing:

    MRUBY_CONFIG=build_config_debug.rb rake compile
    MRUBY_CONFIG=build_config_debug.rb rake test

`portable_smoke` failing at the end of a debug `rake test` is expected -
there is no portable binary. Nothing else may fail.

## Renaming is clang-refactor's job, not a regex's

A rename in C or C++ is an AST question, and a regex cannot answer it.
Use the tool that can, wherever the rename is a symbol:

    /usr/lib/llvm-18/bin/clang-refactor local-rename \
      -p mruby/build/debug -i \
      --old-qualified-name=OLD --new-name=NEW src/FILE.cpp

`compile_commands.json` for `-p` is written by every debug build.
`clang-rename` is the older spelling of the same thing and is also
installed; `clangd` is not, and `apt install clangd-18` gets it if a
full language server is ever wanted.

This is written down because a regex rename cost real time here: a
local `mrb_value r` was shadowing a `Run& r` in the same function, so a
substitution that looked correct handed one function the other's `r`.
The compiler caught it, which was luck rather than method - a rename
that stays type-correct would not have been caught at all.

What clang-refactor does NOT do: `extract` is marked WIP upstream and
cannot turn a capturing lambda into a function that takes its state as
a parameter. That transform stays manual, and its safety net is that a
free function cannot capture, so every missed dependency is a compile
error.
