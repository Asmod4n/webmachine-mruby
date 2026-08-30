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

## mruby here has C++ exceptions and nothing else

Every build in this tree defines `MRB_USE_CXX_EXCEPTION`. There is no
`setjmp`/`longjmp` path, and there is no reason to weigh one against the
other or to explain the difference again: an mruby raise IS a C++ throw
here, and it unwinds through C++ frames.

Two consequences that follow from it, so neither has to be re-derived:

- `mrb_raise` from inside the reactor unwinds out of `Webmachine.run`
  and ends the server. That is what `Ring::fatal` is for, and it is
  right only when the reactor cannot go on at all.
- A failure that belongs to ONE connection must therefore not raise
  into the VM. It throws a C++ exception the reactor itself catches.

`mrb_noreturn` resolves to nothing under `-std=c++20` (`common.h` asks
for `__GNUC__ && !__STRICT_ANSI__`, and a strict `-std=` defines
`__STRICT_ANSI__`), so a function that ends in `mrb_raise` still needs
`__builtin_unreachable()` to keep the compiler quiet.

## Nothing fails quietly

A connection that is dropped because something went wrong says what
went wrong. Not a bare `begin_close`: those are for the ordinary ends -
a peer that left, a timeout, a close the App asked for.

The rule exists because it was broken: twenty silent `begin_close`
calls turned a TLS handover that never happened into "the server sent
nothing", and six rounds of guessing went into finding out which of
them it was.

## Prove it, then say it

Nothing is claimed here without something that shows it. A measurement,
a probe under `tools/`, a test that fails before and passes after. "It
should work" is not a result, and neither is a green build.

## Only debug is built while developing

    MRUBY_CONFIG=build_config_debug.rb rake compile
    MRUBY_CONFIG=build_config_debug.rb rake test

`portable_smoke` failing at the end of a debug `rake test` is expected -
there is no portable binary. Nothing else may fail.

## Comments say what a thing is, and where it comes from

Never why, never a restatement of the code below them. An RFC clause, a
kernel ABI, a `.DESIGN.md` section by name. Function names say what they
return or do.

## One C++ file makes the whole build C++

mruby compiles the entire tree with the C++ compiler as soon as a single
`.cpp` exists in it. There is one in this gem, so every `.c` here is
compiled as C++ too, and `MRB_USE_CXX_EXCEPTION` is not a choice
somebody made per file - it follows from that.
