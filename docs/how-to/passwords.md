# Keep passwords

This how-to is for an operator who keeps a password database with
`webmachine-passwd`, and a developer who checks a login on a worker
thread. At the end you know what the tool does, what the server does
with its file today, and how a resource checks a password without
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

## What the server does with the database

`Webmachine::Passwd` reads the file `webmachine-passwd` writes.
`Webmachine::Passwd.open(file, db)` opens `file` read-only and its
sub-database `db`, and answers an object with one method:
`valid?(user, password)`. It reads the user's record, recomputes the
argon2id hash with the record's own cost and salt, and compares it to
the stored one. An unknown user, a record this side cannot read, and a
wrong password all answer `false`; the call never tells the three
apart, on the wire or on the clock - a missing user still pays the
cost of one hash, so a login cannot be used to ask "who is in this
database".

Opening the file costs a filesystem call and an LMDB open, so it
happens once, not on every login. `Webmachine::Passwd.open` raises
`Webmachine::Error` when the file cannot be opened or the
sub-database does not exist; the message names the file.

## Checking a password from a resource

Hashing takes tens of milliseconds by design, so it never runs on the
request loop. Declare the callback `compute`, and open the database
once per worker through the registry:

```ruby
Webmachine::Workers::Registry[:passwd] = proc do
  Webmachine::Passwd.open('pw.lmdb', 'users')   # opened once per worker
end

class Login < Webmachine::Resource
  compute :is_authorized?

  def is_authorized?(header)
    Webmachine::ComputeTask.new(header, max_runtime: 200.ms) do |h|
      user, pass = h.to_s.split(':', 2)
      Webmachine::Workers::Registry[:passwd].valid?(user.to_s, pass.to_s)
    end
  end
end
```

`'pw.lmdb'` and `'users'` are the same file and sub-database name
`webmachine-passwd add pw.lmdb users ada` wrote, so an application
names its own database's path here. A task over its deadline answers
500. A worker that raises answers 503 with `Retry-After`.

## Next

- [work-off-the-loop.md](work-off-the-loop.md)
- [../reference/command-line.md](../reference/command-line.md)
- [../reference/configuration.md](../reference/configuration.md)
