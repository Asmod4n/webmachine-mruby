# Rules for this repository

Everything in this repository is written in English: file contents,
comments, documentation, and commit messages.

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
- No word in capitals for emphasis. `ONE binary` and `READ THE DIFF`
  are shouting. An acronym (RFC, HTTP) and the name of a constant are
  not emphasis.

A name follows the same rule, and it is the rule that is broken most
often. A function is named for what it does. A file is named for what
is in it. A reader who has never seen this tree must know from the name
alone. `more` was a name that said nothing, and it is now
`spell_next_round`.

This is account-wide knowledge. A session does not always receive it,
so it is written here as well.

## No bang methods

No methods with `!`. Public capability questions are `?` predicates
(pattern: `KTLS::Socket#ktls_available?`).

## Three rules of the code

The design file that carried the reasoning is kept outside the
repository. The rules it carried:

- Cold paths: the happy path is the straight line, and `nm -S` on the
  host build decides whether a hint or a split helped. feed_parse,
  run_engine and h2_dispatch are 11 to 15 KB of machine code each, one
  h1 request walks two of them, and the L1i is 32 KiB.
- mruby raises: mruby here is built with `MRB_USE_CXX_EXCEPTION`,
  always. A raise is a C++ throw, destructors run, and a failure is
  raised rather than reported through `char* err` and `return false`.
- Decide, then do: compute the round as a value, perform it in one
  place.

## Use what std:: already has

A thing the standard library answers is not ours to write. We wrote
`Held::Span` to ask whether a pointer lies in a run of bytes, and its
test - `bytes < at || bytes > at + len` - is undefined between pointers
into two different objects, which is the one question it existed to ask.
`std::less` answers it, `std::distance` says how far in the pointer sat,
and `std::next` walks that far into the copy.

Never do pointer arithmetic by hand. Work in views and indices:
`std::string_view` or `std::span` for the run, `std::distance` for the
offset, `std::next` to walk it. An offset added to a pointer by hand is
right only for the case its author had in mind, and the next case is a
pointer into nothing.

The same rule covers the small ones, and they are the ones that pile up:
`std::min` and `std::max` rather than a ternary, `std::from_chars` rather
than a digit loop, `std::clamp` rather than two ternaries.

A C++ value into an `mrb_value` goes through mruby-c-ext-helpers, which
is already in the build: `mrbcpp::value_converter` for the way out,
`mrb_value_to_cpp.hpp` for the way back.

What stays ours is what the standard has no answer for: `tok_eq`, because
no standard function compares without regard to letter case;
`length_is_one_of`, because it is a mask this tree measured; and every
rule an RFC states rather than a library.

## No failure is hidden

A hidden failure is one nobody can fix. `char* err` with `return false`
is the pattern this replaced, and it is worse than it looks: it loses
the exception's class and its backtrace, so every distinct failure
flattens into one string. A lost database and a typo in a block then
read as the same answer.

So a failure is raised, and which kind depends on what is in hand:

- **With a VM** - every fold and every callback - `mrb_raisef` with the
  right error class. The app author gets a Ruby exception with a class,
  a message and a backtrace pointing at their own code.
- **Without one** - startup, before or outside the VM - a C++
  exception.
- **Where a raise cannot unwind** - across a worker thread, across the
  reactor boundary - it comes back as a value, and the value carries
  the class, the message and the backtrace, never one bit and never one
  string. `mrb_protect_error` plus `note_raise` is that path.

The backtrace reaches the client in one build only. `conf.enable_debug`
in a build config defines `MRB_DEBUG`, and `kDebugBuild` is the build's
word for itself rather than a second switch to keep in step. A ship
build puts the class, the message and the fingerprint on the 500 page,
and the fingerprint is what finds the whole record in the error log. A
debug build puts the trace on the page as well, because it is already
telling you about itself.

Where the trace is kept does not depend on the build. An error log that
is configured gets the record, with the backtrace in it; with no error
log there is no record at all, and stderr gets the text instead. So
keeping the trace off a 500 page is not hiding it from the person fixing
it, as long as the log is on.

What the trace names is a third thing, and it is not the build either.
`mrbc -g` writes the line table into the `.mrb`, and it does that
whether mruby itself was built for release or for debug. So every place
this tree compiles an app says `-g`: the Rakefile's smoke app, `rake
install`, the conformance scripts, every bintest. Without `-g` a raise
still has a backtrace, and that backtrace names no file and no line -
application.cpp says so once at boot rather than refusing the app.

Two things follow, and both have been broken here before:

- A guard that returns instead of raising hides our own bug. An index
  that cannot be a connection means the thrower packed its word wrong.
- A test that discards what a failure said is the same sin in Ruby.
  `rescue nil` over a log file, or a subprocess's stderr sent to
  `/dev/null`, leaves a red run with nothing to read.

## What is only true of the build

One `.cpp` anywhere makes mruby compile the whole tree with the C++
compiler. There is one in this gem, so every `.c` here is C++ too, and
`MRB_USE_CXX_EXCEPTION` follows from that rather than from a choice
made per file.

`mrb_noreturn` resolves to nothing under `-std=c++20` - `common.h` asks
for `__GNUC__ && !__STRICT_ANSI__`, and a strict `-std=` defines
`__STRICT_ANSI__` - so a function ending in `mrb_raise` still needs
`WM_UNREACHABLE()`, which is `__builtin_unreachable()` on GCC and Clang
and `__assume(0)` on MSVC.

Only the debug config is built while developing, and one command does it:

    rake test

It builds the debug config itself - the Rakefile's `test` task runs
`rake all test` under `build_config_debug.rb` and reads no
`MRUBY_CONFIG`, because every test in this tree is the debug build's.
A `MRUBY_CONFIG=` in front of it changes nothing, and a `rake compile`
before it builds the same thing twice.

Nothing in that run may fail.

The release build has to work as well, always. `rake test` never
touches it: the suite is the debug build's, and a debug run cannot
answer for a binary it never made. `rake ship_smoke` is what does -
it builds the host config and checks that the binary starts and
answers 200. CI runs it on every push, beside the suite.

## A number about speed comes from bench/

`bench/` owns measuring. Read `bench/how-to-measure.md` before you make
any claim about speed, and then follow it.

What that file settles, and what a session gets wrong without it:

- htgen is the client. `wrk`, `h2load` and `ab` are gone from this
  tree, and the machine that measures does not install them. A script
  that names a tool nobody can run lies about how its numbers were
  made.
- No `taskset`, and that covers the indirect one. A session read
  floor.sh's line about taking "the cpus its caller does not hold",
  pinned its own shell to one cpu so the script would find three free,
  and called that an isolation rather than a pin. It is a pin: it
  narrowed the run to three of four cpus.
  The mechanism stands, its numbers do not. Both numbers this bullet
  used to name came from a tree that is gone: a client mask widened
  from 2 to 15 to 30 cpus, and an asset served at 0.07 of its rate
  under `taskset -c 0`. That second one measured io-wq workers carrying
  splice, and this tree has no splice - `grep -rn splice src/` finds
  the word about header fields and no `IORING_OP_SPLICE`.
  What did not go is io-wq. `ls /proc/<pid>/task` on a serving process
  shows `iou-wrk-<pid>` beside the reactor's own threads, and those
  workers carry the regular-file work the ring cannot do inline: the
  open, the statx and the read of every file the docroot answers. It
  is why a single-ring server reading files holds 112 percent of a cpu
  and not 100. An io-wq worker inherits the affinity of the thread that
  issued its work, so a pinned reactor pins the pool that exists to do
  that work elsewhere. The carrier changed, the mechanism did not.
  The plainer reason came from the author's own machine, where a pin
  showed no advantage at all: a pinned process cannot be moved, so the
  scheduler can no longer put it on a core with less to do. That holds
  whatever the ring carries, and it is why the rule survived the tree
  that made it.
  So a pin is still refused, for two reasons that are current, and no
  number is quoted for it until one is measured here.
  The rule is scoped, and the scope is the whole of what this tree
  measures: loopback. floor.sh drives AF_UNIX or 127.0.0.1, so there is
  no interface, no receive queue and no interrupt to steer. A pin earns
  its keep in the case this bench cannot reach - a card with several
  receive queues, each queue's interrupt on one core, and the thread
  that drains it on that same core. There the packet arrives, is
  softirq'd and is answered without leaving the core. Nothing here
  proves anything about that, in either direction.
- The server and the client each hold more than 85 percent of a cpu, or
  the run measured a wait and not the code. Every row of
  `bench/results/*.log` names both numbers. Read them before the rate.
- Five runs for each arm, A B A B A B, and compare the medians.
- A change smaller than the host can resolve needs
  `bench/instructions.sh`. It counts what the server executed, and the
  count of one binary does not move between runs.
- Both arms of a comparison are built the same way, and the comparison
  lives inside one session. `-march=native` is not one ISA here: this
  tree is built in containers that land on hosts that differ, so native
  gave sapphirerapids with avx512 in one session and something else in
  the next. A host with avx512 is faster for other reasons as well. So
  a rate from one session and a rate from another measure two binaries
  on two machines, whatever the log says.
- To compare across sessions, pin the ISA with `WM_MARCH=`, as
  `bench/instructions.sh` already does. That is why its counts can be
  read beside the counts of a tree from months ago, and a rate cannot.
- `WM_MARCH=x86-64-v3` is the build valgrind can decode, and it is
  slower than what this tree ships: it reads 0.47M where the host build
  reads 0.56M, and it wants a different connection count. Sweep again
  after the build changes.

This rule exists because it was broken. A session measured the reactor
rewrite with `ab`, `h2load` and `taskset -c 0`, read a loss of 20
percent, and spent an hour on a number that measured the benchmark. The
instruction count then read 19 instructions per response less, which is
a small gain.

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

Read the diff either way. These tools are beta, and they say so. Here,
`clang-refactor local-rename` of one struct rewrote an unrelated line
of the flow table: `to(Node::kG9)` became `ComputeJobAsk:kG9)`. The
compiler would have caught that one, but a rename that stays
type-correct would go through. So: rename with the tool, then read what
it changed, then build.
