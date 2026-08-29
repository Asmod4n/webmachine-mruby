# Handoff — #210 error pages

Read this once; the SessionStart hook prints it and deletes it. Branch
`next`, two commits pushed: `459f697` (the wire half) and `6b193ee` (the
error resource).

## What is done and green

`Webmachine::ErrorResource` (mrblib/webmachine.rb) is the one resource
that is always there and never routed. It is instantiated **once** at
startup and rooted with `mrb_gc_register` — the deliberate exception to
#181. It declares `content_types_provided` like any resource, and that
list *is* the negotiation (`http::choose_media_type`, q-values and both
wildcard forms). `text/plain` is the named way out when Accept matches
nothing offered — an error is not a representation of the resource, so
there is nothing to 406 about.

The templates live in that class. C++ knows nothing about mustache: a
Hash goes in, a String comes back.

`handle_exception` lives there and **nowhere else**; the per-resource
hook is gone from the fold. The only thing the server fixes is the shape
of the answer — a String, or an Array joined with CRLF. Whether a
backtrace is in it is the app's call.

Both writers spell it. h1: `store_prefix_` (the status without its
`Content-Length` and terminator) + the page's own Content-Type and
length. h2: a per-request HEADERS block, `END_STREAM` on the DATA frame,
and a 405 keeps its `Allow`. HEAD carries the length and no body.

The reflected XSS is closed: the target and the exception message go
through `{{ }}`.

Suite: **2921 OK, 0 KO**; the 3 crashes are mruby-regexp on this mruby
HEAD (`instance_variable_set` missing without mruby-metaprog) and are
unrelated. Bintest: **219/219**.

## Late additions, and one thing left unproven

- An error answer can be a PICTURE. A browser fetching an <img> sends
  image/* and none of the text forms, so it used to get a page it cannot
  render; it now gets the status's cat, whole, as image/jpeg. The form is
  declared in content_types_provided like the others but has NO method:
  the picture is not rendered, it IS the asset, lent out of the mapping.
  Offered only while there is a cat for that status.
- Accept that names types and none of ours (and only reaches us through
  */*) gets text/plain, not the 1.6 KB page. A subtype range counts as
  naming us - image/*;q=0.8 IS a preference for our jpeg, which is how
  the picture above gets chosen at all.
- content-type is inserted into the peer's HPACK table once per
  connection and referenced after (80de29d): 110 -> 84 bytes per h2
  answer on the real machine, sys 15% -> 11%, 9.59M -> 10.24M rps per
  server core.
- **Unproven, and it matters**: that insert made the head cache hold an
  INDEX, and every later insert shifts it. The dynamic path does insert
  (a /bound answer's HEADERS shrinks 62 -> 30 bytes, which is its date
  being inserted then referenced), so a cached index CAN go stale.
  h2.enc_ins counts inserts and invalidates the cache, and that is the
  fix - but bintest/h2.rb's "an insert between two cache hits" case
  passes with AND without it, because it only compares server-side bytes
  and has no decoder. A test that discriminates needs to decode the
  third answer's block. Until then the fix is reasoned, not demonstrated.
- Route tokens are one path segment: ['/'] is now a named setup refusal
  ("the root is the empty list"), where it used to be silently accepted
  and 404 everything.
- --help is a flag list with the effect per flag; the essays are gone.
- Vocabulary: there are no "packs", only assets. share/error-assets.zip,
  src/error_assets.cpp, WM_ERROR_ASSETS, open_error_assets.

## What is NOT done

1. **`conf.disable_http_cats`.** The user's call: the route serving the
   cats should be there **by default** — no `--assets` needed — and this
   switch turns it off. Today the cats only appear when the operator
   passes `--assets share/error-assets.zip`. Needs deciding: how the
   default pack is found at runtime (path next to the binary? env?), and
   whether it is a second `Assets` mount or a merged lookup.
2. **Asset-tier refusals** (405/406/416 out of `Assets::answer_head`)
   still answer bodyless — they bypass `spell_error`.
3. **No bintest covers the error pages themselves.** Everything above was
   verified by hand and by the four bintests that moved with the
   behaviour. A `bintest/errorpages.rb` should pin: the four Accept
   forms, the escaping, HEAD's length-without-body, the h2 DATA frame,
   and a reopened class adding a format.
4. `README.md` and `share/README.md` are updated; `docs/` was not
   checked for stale references.

## Measurement, and what came out of it

`bench/floor.sh` prints three things it did not before: user against sys
for both ends, and what ELSE ran during the run. That was not cosmetic -
it settled two questions.

- **h1 over a unix socket measures the socket.** 8% user / 91% sys on the
  server; the client 0% user / 90% sys. The server's own work - parse,
  route, flow, spell - is **83 ns per request**. Everything else is the
  kernel copying, and on AF_UNIX the copy is billed to whoever called
  send, which is why a client that "does almost nothing" burns a core.
- **h2 inverts it**: 78% user / 16% sys, because 128 streams amortise one
  syscall over 128 answers. Same server work per request (~89 ns), 52x
  less kernel. So #191 (PGO) and #208 matter on h2; #190 (phr/AVX2) is
  h1-only and stays under 1% of the whole.
- The machine carries 10-18% of a core of background (Plasma, 4K120), and
  run-to-run spread is ~10%. Nothing smaller than that is provable there;
  `other:` now says how much was in the way.

Out of that came `80de29d`: content-type is inserted into the peer's
HPACK table once per connection and referenced afterwards. **83.0 -> 57.0
bytes per h2 answer, -31%**, bad=0 over 4.77M responses. Byte counts, not
timings, so the compositor has no vote.

Two clock reads per reactor round, both vDSO, no syscall
(CLOCK_MONOTONIC_COARSE 5.6 ns, time() 2.7 ns, 15M calls -> 34 syscalls
total). There is nothing to win there; the fine CLOCK_REALTIME at 21 ns
is the one we already avoid.

## Build, on a cold container

The hook installs `liburing-dev`, the submodules and rake. Then:

    rake compile                                      # host — makes mruby/bin/mrbc
    MRUBY_CONFIG=build_config_debug.rb rake compile   # debug — needs that mrbc

Both take several minutes. `rake test` runs the unit suite; the bintests
need the env the hook sets plus `MRBCFILE=mruby/bin/mrbc` (NOT
`build/debug/bin/mrbc`, which does not exist for this target):

    cd mruby && BUILD_DIR=$PWD/build/debug MRBCFILE=$PWD/bin/mrbc \
      EXECUTABLE_EXT= ruby test/bintest.rb ..

## House rules that bit me

- **No session URLs anywhere** — not in commits, not in PR bodies. The
  GitHub tooling stamps one into a PR footer on create *and* on update;
  strip it every time and re-check.
- English everywhere in the repo, commit messages included.
- Two branches only: `master` and `next`. Work on `next`.
- Nothing is claimed without a reproducer.
