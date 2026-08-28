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
