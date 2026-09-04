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

## Write in Simplified Technical English

Everything written here follows ASD-STE100 - https://asd-ste100.org/ -
and everything means everything: code comments, names, commit messages,
documentation, refusal messages, help text, and the answers in a
session.

The rules that matter most:

- One thought per sentence.
- Short sentences. About 20 words is the limit.
- Active voice. Name who does the thing.
- Simple words. One word keeps one meaning.
- No metaphors, no idioms, no rhetorical questions.

A NAME follows the same rule, and it is the rule that is broken most
often. A function is named for what it does. A file is named for what
is in it. A reader who has never seen this tree must know from the name
alone. `more` was a name that said nothing, and it is now
`spell_next_round`.

This is account-wide knowledge. A session does not always receive it,
so it is written here as well.

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

## Kill a process by its pid, never by a pattern

`pkill -f X` and `pgrep -f X` match every command line that holds X,
and the command that runs them is one of those lines. This cost real
time here, three times: once `pkill -f "rake test"` killed the shell
that ran it, and twice a wait loop spelled `until ! pgrep -f "rake
compile"` waited for itself and never ended.

Find the pid, then kill the pid:

    ps -eo pid,cmd | awk '/[r]ake test/ {print $1}' | xargs -r kill

The bracket in `[r]ake` keeps the awk pattern out of its own output.
The same rule holds for waiting: wait on a job you started, never on a
name that your own command line also carries.

## A symbol question is an AST question

A rename in C or C++ is an AST question, and a regex cannot answer it.
Use a language server. clangd as an MCP server is the best form,
because it answers inside the session; the command line is the fallback
when no such server is attached.

READ THE DIFF EITHER WAY. These tools are beta, and they say so. Here,
`clang-refactor local-rename` of one struct rewrote an unrelated line
of the flow table: `to(Node::kG9)` became `ComputeJobAsk:kG9)`. The
compiler would have caught that one, but a rename that stays
type-correct would go through. So: rename with the tool, then read what
it changed, then build.
Which tool answers what, the invocations, what clang-refactor cannot do,
and what no tool can answer about an mruby method: `.DESIGN.md#tooling`.
