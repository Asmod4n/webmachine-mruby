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
  h1 request walks two of them, and the L1i is 32 KiB. That last number
  is read and not assumed: `bench/buildline.sh` prints the cache
  hierarchy on every row, so a machine whose L1i is another size shows
  it rather than quietly breaking the reasoning.
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

`bench/` owns measuring. Read the whole directory before you make any
claim about speed: `bench/how-to-measure.md` and every `.sh` in there,
headers included. Then follow what they say.

The whole directory, and not the one document, because the knowledge is
spread and the document does not carry all of it. The header of
`assets.sh` holds what was tried and lost - splice against a sink that
copied twice, `MSG_SPLICE_PAGES` with no effect over 2 GiB, `SEND_ZC`
refused on shape - and the reason a pin is structural rather than
statistical: a server that touches a file gets an io-wq pool, and those
workers inherit the issuing thread's affinity. None of that is in
`how-to-measure.md`. `floor.sh` states which harness knobs are refused
and why each one went. `priority.sh` says what the bench takes from the
machine, and why it does nothing on a machine that is already idle.
`instructions.sh` is the only tool for a change the clock cannot
resolve - a shared host swings 15 percent between two runs of one
binary and an instruction count does not move - and it says which
binary it needs, because valgrind cannot decode AVX-512. `nginx-assets.sh`, `lighttpd-assets.sh` and
`h2o-assets.sh` are the arms that measure another server, so a number
of ours has something beside it.

This rule exists because it was broken from the other side. A session
extended `tools/webmachine-tune.sh` and left its pin advice resting on
the splice measurement, which `assets.sh` had already marked as
historical in its own header. The file that measures was right and the
files that talk about it had drifted. Read the measuring files first.

`docs/` is read the same way and for the same reason: every `.md`
under it, not the page that looks relevant. Twenty five files, and
they do not repeat each other - `reference/` states what a flag and a
callback do, `explanation/` states why the shape is what it is,
`how-to/` states the steps for one task, and `tutorial.md` is the one
path a newcomer walks. A change to what an operator or an app author
can see is a change to some of them, and the page that contradicts the
new behaviour is rarely the page being edited. `explanation/one-thread.md`
opens "one process and one thread"; a flag that makes it several
leaves that sentence false, and nothing in the flag's own patch points
at it.

Read, and do not rewrite on the strength of one session's reading. A
documentation change follows a verified fact, not a fresh measurement
that nobody has reproduced.

What `how-to-measure.md` settles, and what a session gets wrong without
it:

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
- A row says where it ran, and a row from one place is not compared
  with a row from another. Same hardware, WSL2 against bare metal, read
  half the rate. That is larger than every change this tree has
  measured and argued about, so a number that does not name its place
  says nothing. `bench/buildline.sh` writes `on=` for this - `metal`,
  the hypervisor, the container runtime, or both.
  `host=` answers none of it and never did. It is `uname -n`, and on a
  Firecracker fleet every guest is named `vm` whatever hardware it sits
  on, so the field is a constant that looks like a identifier. `on=`
  does not separate them either: every Firecracker guest reports `kvm`.
  The guest's own model name is masked as well - "Intel(R) Xeon(R)
  Processor @ 2.80GHz", no model number - and there is no DMI. So the
  line carries `cpu=family:model:stepping@clock` too. A guest does show
  its caches and its feature set, so `cache=` carries the hierarchy and
  `flags=` a count and a checksum - ninety two names do not belong on
  every row, and a difference in any one of them does. The last
  discriminator is what `-march=native` resolved to, which the harness
  line already prints and which is why `WM_MARCH=` exists.
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

## Code is shown before it is written

A session shows every function that has behaviour or introduces a
name before it writes the function to disk: the declaration and the
body as they will stand in the tree, with the RFC section beside
them. One function per message, 40 lines at most. The owner answers
yes, change, or no. A repeated form is shown once in full; after the
yes, only the list of names follows.

Mechanical changes are not shown one by one: deleting from an agreed
list, copying a parameter name from a definition into its
declaration, `clang-format`. They are summarised before the commit,
with the files and the line counts, and the diff on request.

After the yes, the session writes, runs `tools/syntax-check.sh` and
the tests, and reports only what is red. Green is one line.

## Comments live in tests, and they say why

`src/` carries no comments. Not a note, not a section number, not a
name of a specification. What the code does, the code says. A reader
who needs more than the declaration has found a name that is wrong,
and the answer is the better name.

A test carries one comment, and it answers one question: why this
test exists. An RFC section, an issue, a pull request, a CVE. What
the test does is in the test.

    # RFC 9110 5.6.2: ':' and '(' are not tchar. RFC 2616 called them
    # separators, and that word is gone.

A string that reaches a log, an error page or a client is not a
comment. `"RFC 9110 5.6.4"` inside a ParseError is what the operator
reads at three in the morning. It stays.

## How the code is written

These rules came from `cleanup-plan.md`, which is gone. Where two
rules meet, the stricter one holds.

1. **A declaration says what happens.** The function name says what
   the function does. Each parameter name says what is passed. The
   return type says what comes back. A reader of the header alone
   knows the behaviour.
2. **A name that a specification gives is the name the code uses.**
   A field, a method, a status, a frame, an opcode, a close code, an
   ABNF rule: the word of the RFC, without translation. `tchar`,
   `token`, `OWS`, `quoted-string`, `field-name`, `representation`,
   `origin`. A word that reads better but appears in no specification
   is not chosen over it. The order of a class follows the order of
   the RFC that defines it, section by section. Where C++ names the
   thing instead, C++ wins for the same reason: `what()` stays
   `what()`. Where nothing names it, the name says its purpose, as
   the Google C++ Style Guide states.
3. **No method hides anything.** No function wraps one library call.
   No function changes an argument unless its name says so. No
   function raises unless its name says so. No function does two
   things.
4. **Every argument is const.** A function reads its inputs and
   returns its result. There is no `out_value`, no `&sink` and no
   pointer that is written through. The return type is what the
   function makes. A function that changes an object is a method of
   that object.
5. **Use what a linked library has.** `std::`, mruby, liburing,
   ls-hpack, zlib, miniz, picohttpparser, simdutf and ada are in the
   build. Nothing they answer is written here a second time. Read the
   library first, and read it in its own source: picohttpparser takes
   the whitespace off a field value and this tree does not need to;
   picohttpparser takes BWS after a chunk size, a bare LF and an
   unchecked chunk extension, and every one of those three has a
   vulnerability against its name, so the grammar check in front of
   it stays.
6. **One Resource takes one Request and gives one Response.** There is
   one Request type and one Response type. Every field of either has
   the name the RFC gives it. `Http` holds the semantics of RFC 9110
   and RFC 9111. `Http1`, `Http2` and a later `Http3` turn those
   values into bytes and back, and add nothing. The decision graph
   cannot see which version carried a request.
7. **An RFC that describes a procedure gives one method.** Where an
   RFC states steps, inputs and state for one thing, this tree has one
   function for it. Its arguments are the inputs the RFC names. Its
   state is the state the RFC names, passed in as a value.
8. **Every function could run in a functional language as it is.** A
   function takes values and returns a value. It reads no global. It
   writes no global. It keeps no static. State that changes is a value
   that goes in and a new value that comes out. An effect happens in
   one place, after a pure function decided it. An effect is a
   syscall, a ring submission or a Ruby call. "Decide, then do" is
   this rule.
9. **The code is made as fast, as hard to attack and as plain as
   possible, by repeated testing and adjusting.** No step is done when
   it compiles. A step is done when the suite, the conformance runs,
   the sanitizers, the fuzzer and the instruction count have each run
   and none of them moved the wrong way. The loop ends when a round
   changes nothing.
10. **Every larger change is measured before and after.** The arms
    alternate, A B A B A B, five runs each, and the medians are
    compared, as `bench/how-to-measure.md` says. A change too small
    for the clock is measured with `bench/instructions.sh`. Measure
    the noise floor of the machine first: ten runs of `sysbench cpu`
    say how small a difference the clock can still read there.
11. **A comparison that AVX2 and NEON can help is measured, and the
    code is written so that both compilers vectorize it.** Scalar in
    `std::` terms first. Then count both arms with the same
    `WM_MARCH=`. An intrinsic enters the tree only where the count
    says the compilers cannot reach the speed, and then for both
    architectures at once, with the scalar form as the third branch.
    A loop with a fixed count over a contiguous buffer, with no early
    exit and no branch in the body, is the form both compilers take.
12. **Kernighan and Ritchie.** The layout `.clang-format` already
    states (`BreakBeforeBraces: Linux`). And the discipline: a
    function does one thing and fits on one screen. A name is short
    where its scope is short. The plain construct over the clever one.
    A loop is a loop and not a template.
13. **Asserts live in tests.** No `assert` and no `static_assert` in
    `src/`. A `constexpr` function is tested by `static_assert` in
    `test/`, which mruby compiles into `mrbtest` alone, so the test
    runs at compile time and costs nothing at run time.

## A catch names its type

There are two zones, and they do not share a mechanism.

**Inside a VM, or at its edge.** `MRB_USE_CXX_EXCEPTION` makes mruby
throw an `mrb_jmpbuf *`, a raw pointer with no base class. A
`catch (...)` therefore catches a running raise and destroys it, and
`catch (const std::exception &)` does not catch it at all. So no C++
catch stands at that edge. `mrb_protect_error` does, as
`mruby/throw.h` itself says and as the error rules above already
state. It catches both kinds and gives back a value.

**Outside any VM.** Boot, the configuration, the ring, files, the body
of a thread that runs no Ruby: real C++ exceptions. A catch names the
exact type it can recover from. `std::system_error` where `EAGAIN`
means something other than `ENOSPC`. Nothing else is caught, so our
own faults reach the top and end the process.

Our thrown types hook into the standard hierarchy and add nothing the
standard already carries: `std::system_error` for a syscall, with the
errno in its `error_code`; `std::logic_error` and its children for a
fault of ours; `std::runtime_error` and its children for a condition
of the world, such as a configuration this operator wrote.

Two places catch broadly, because the alternative is a death with no
words: `main`, and the body of a thread we start, where an escaped
exception is `std::terminate` for every thread. Both print or record
the failure and then die or hand it back as a value. Neither
continues.

A client that sends something invalid is not an exception at all. It
is the normal work of a server, it is a value, and it travels in
`std::expected`.
