# Keep passwords

This how-to is for an operator who needs a password database, and a
developer who needs to check a login against it. At the end, you have
users in an LMDB file, and a resource that checks a password without
blocking the request loop.

## The tool

    usage: webmachine-passwd COMMAND [OPTIONS]

      create FILE            make the database
      add    FILE DB USER    add a user, refusing one that exists
      set    FILE DB USER    add or replace a user
      del    FILE DB USER    remove a user
      list   FILE DB         the users, when they were made and last changed
      calibrate              what each cost setting takes here

    DB names a sub-database inside FILE - one set of users. The
    server is pointed at the same pair.

    OPTIONS
      --maxdbs N       how many sub-databases FILE may ever hold (16)
      --mapsize MiB    the ceiling FILE may grow to (64)
      --time MS        the time one login may cost; picks the cost (0 = default)
      --workers N      how many hashes run at once, for the rate this prints (8)
      --sort HOW       list order: user, created or changed (user)
      --names          list bare names, for a script to read

`FILE` is one LMDB file that can hold several `DB` sub-databases, each
one set of users. `create` makes the file; a sub-database is made the
first time `add` or `set` names it.

    webmachine-passwd create pw.lmdb
    webmachine-passwd add pw.lmdb users alice
    webmachine-passwd list pw.lmdb users

`add` and `set` ask for the password twice, at a terminal with echo
off, reading from `/dev/tty` and never from an argument or from
standard input: a password is never a process argument another user
can read, and a piped stdin cannot turn the prompt into an unattended
read. `add` refuses a user that already exists; `set` adds or replaces
one. `del` refuses a user that does not exist, with `no such user`.

`set` keeps the day a user was first added; only `add` starts one, so
`list`'s "who is new" answer does not move every time a password
changes.

## The cost

`--time MS` picks the most expensive cost that still answers within
that budget on this machine, measured with `--workers` hashes running
at once, the concurrency a login actually sees. Without `--time`, a
fixed default cost is used. `calibrate` prints what every candidate
cost takes here, without touching any file:

    webmachine-passwd calibrate --time=200 --workers=8

The cost picked for a user is stored with them. Raising it later
re-hashes one user at their next password change and leaves everyone
else verifiable at the cost they were given.

## Checking a password from a resource

Hashing takes tens of milliseconds by design, so it never runs on the
request loop. Declare the callback `compute`, and build the table the
worker reads once per worker through the registry:

```ruby
Webmachine::Workers::Registry[:passwords] = proc do
  { 'ada' => Argon2.hash('secret')[:encoded] }   # built once per worker
end

class Login < Webmachine::Resource
  compute :is_authorized?

  def is_authorized?(header)
    Webmachine::ComputeTask.new(header, max_runtime: 200.ms) do |h|
      user, pass = h.to_s.split(':', 2)
      stored = Webmachine::Workers::Registry[:passwords][user]
      stored ? Argon2.verify(stored, pass.to_s) : false
    end
  end
end
```

A task over its deadline answers 500. A worker that raises answers 503
with `Retry-After`.

The database `webmachine-passwd` writes is LMDB. Its record layout is
the tool's, in `tools/webmachine-passwd/main.cpp`, and this page does
not spell it. Build the table the worker reads from a source you
control, or read the tool's file with the same layout the tool uses.

## Next

- [work-off-the-loop.md](work-off-the-loop.md)
- [../reference/command-line.md](../reference/command-line.md)
- [../reference/configuration.md](../reference/configuration.md)
