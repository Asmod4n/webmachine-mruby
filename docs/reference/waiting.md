# Waiting reference

This page is for a developer who writes a callback that has to wait - 
for a worker thread to finish arithmetic, or for a descriptor to
become ready. At the end, you know the exact signatures of
`compute`, `watch`, `reads_body`, `Webmachine::ComputeTask`, and
`Webmachine::Watcher`, and what the server does at each deadline.

[One thread, and the work off it](../explanation/one-thread.md)
explains why these three exist. This page is the contract.

## `compute`

A class method. Names one or more callbacks whose answer a worker
thread gives instead of the reactor's own thread.

```ruby
compute :is_authorized?
compute :generate_etag, :last_modified
```

`compute` only records the names; the fold checks them once the class
body has finished, against what it now knows each name is:

- A name that is a flow node (`is_authorized?`, `resource_exists?`, and
  so on) must be an instance method (`def`), not `def self.` - a
  compute task is built per request, with `request` in reach, and a
  class method runs once at start and never sees one.
- A name that is not a flow node must be `generate_etag`,
  `last_modified`, or `expires` - the three callbacks whose answer the
  flow only reads and that choose no edge - and, again, an instance
  method.
- A name declared both `compute` and `watch` is refused: it answers
  one way or the other.

The callback itself must answer a `Webmachine::ComputeTask`. Answering
one without declaring `compute` for that name is refused too:

> `%n answered a Webmachine::ComputeTask and never declared one - write
> compute %n`

## `watch`

The same declaration, for a callback that answers a
`Webmachine::Watcher` instead:

```ruby
watch :generate_etag
watch :generate_etag, :last_modified
```

The same three checks apply, with one difference: a watcher's block
runs on the reactor's own thread, inside the request, so nothing about
it has to cross to another VM. The callback may live on the instance
and keep whatever it closed over.

## `reads_body`

A class method. Names the callbacks that read the request body:

```ruby
reads_body :process_post
reads_body :take, save: true
```

Only `process_post`, `create_path`, and a handler named by
`content_types_accepted` can read a body at all; naming any other
callback here is refused, and so is naming
`content_types_accepted` itself - that callback answers the mapping
and never gets a body.

`save: true` promises that the named callback may call
`request.body.save`. The head reads this promise before the first
octet of the body arrives, and puts the body in a file even when it is
small - so the save becomes a filesystem link rather than a second
write of the octets. Without the promise, `request.body.save` from
that callback is refused; see the
[resource reference](resource.md#where-the-body-is-read).

## `Webmachine::ComputeTask`

```ruby
Webmachine::ComputeTask.new(*args, max_runtime:) { |*args| ... }
```

- `*args` - anything, forwarded to the block when a worker runs it.
  Both the block and the arguments have to survive a crossing to
  another VM: mruby has to be able to dump the block, and the
  arguments and the answer have to be things CBOR can carry. An object
  cannot cross; a value can.
- `max_runtime:` - required. A duration in seconds - a plain number of
  seconds, or a `Numeric` built with one of the duration helpers below
  (see them in use as `500.ms` and `2.s`). Missing it, or a number that
  is not greater than zero, raises `ArgumentError` - admission is
  arithmetic over a deadline, and work with no deadline cannot be
  admitted.
- The block - required. It runs on a worker thread, in a VM of its
  own, and it sees only its arguments: no closure, no `request`, no
  `response` field access. `response.userdata` is the one exception - 
  see below.

```ruby
class Slow < Webmachine::Resource
  compute :is_authorized?

  def is_authorized?(header)
    Webmachine::ComputeTask.new(header, max_runtime: 500.ms) { |h| !h.nil? }
  end

  def to_html
    'x'
  end
end
```

### Duration helpers

`500.ms`, `2.s`, `1.min`, and so on are `Numeric` methods (from
`mruby-chrono`) that answer a `Float` number of seconds:
`nanoseconds`/`ns`, `microseconds`/`us`, `milliseconds`/`ms`,
`seconds`/`s`, `minutes`/`min`, `hours`/`h`, `days`, `weeks`. A bare
number is also accepted wherever a duration is asked for - `2.s` and
`2.0` mean the same 2.0 seconds.

### The deadline

A compute task that runs past `max_runtime:` is interrupted. The
request it belongs to answers **500, with no `Retry-After`** - the
author's own number was wrong, and a second attempt would take just as
long.

A worker that raises answers the request with **503 and
`Retry-After: 60`** - a raise is the world telling the caller
something is temporarily wrong, and 60 seconds is a plain number to
come back after.

```ruby
class ComputeRaises < Webmachine::Resource
  compute :is_authorized?

  def is_authorized?(_header)
    Webmachine::ComputeTask.new(max_runtime: 500.ms) { raise 'the handle is gone' }
  end

  def to_html
    'x'
  end
end
```

### What a dumped block may capture

The block is turned into bytecode and reloaded inside the worker's own
VM (`mruby-compiler`'s dump/load of an irep), and only that: a local
the block closes over does not cross with it, because a local is a
value in the caller's VM and the worker's VM is a different one. The
same block, wherever a request reaches it, is dumped once per process
and reused after - a request never pays to dump it twice.

## `Webmachine::Workers::Registry`

What a worker keeps between jobs, since a block carries no environment
of its own - a database handle or a connection has to be built inside
the worker's own VM, once, and kept there.

```ruby
Webmachine::Workers::Registry[:db] = proc { open_connection }
```

The main VM registers a proc, at startup, before the workers start.
Every worker runs it once when it opens and keeps what it answered
under the same key, in its own VM. Setting a key after the workers
have started is refused - they were already built, so the key would
exist in none of them.

Inside a worker's block, `Registry[key]` answers this worker's own
value:

```ruby
class UsesRegistry < Webmachine::Resource
  compute :is_authorized?

  def is_authorized?(_header)
    Webmachine::ComputeTask.new(max_runtime: 500.ms) do
      Webmachine::Workers::Registry[:db]
      true
    end
  end

  def to_html
    'x'
  end
end
```

Calling `Registry[key]` outside a worker - from the reactor's own VM - 
is refused: the values are built inside a worker, and the reactor's VM
has none.

## `Webmachine::Workers.response`

Inside a worker's block, `response` is not the run's response. The
block runs in a worker VM with no environment, and in that VM
`response` is a method on `Object` that answers this worker's own
`Webmachine::Workers::Response`: an object with one member, `userdata`,
and nothing else. `response.body`, `response.code` and the headers do
not exist there.

That one member is what carries `response.userdata` across. The run's
value is encoded as CBOR and sent with the job. The worker decodes it
into its own `response.userdata` before the block starts. The block
reads and writes it with the same spelling as at home. After the
block, the worker sends the value back only when it changed, and the
run's slot takes it. A value CBOR cannot carry raises on either
crossing.

```ruby
class Handoff < Webmachine::Resource
  compute :is_authorized?

  def is_authorized?(_header)
    response.userdata = 'from the run'
    Webmachine::ComputeTask.new(max_runtime: 500.ms) do
      response.userdata = "worker saw #{response.userdata}"
      true
    end
  end

  def to_html
    response.userdata
  end
end
```

## `Webmachine::Watcher`

```ruby
Webmachine::Watcher.new(source, events = :r, timeout:) { |revents, watcher| ... }
```

- `source` - an `IO`-like object, or a bare Integer file descriptor.
  Anything else is asked for `fileno`.
- `events` - `:r`/`:in`, `:w`/`:out`, or `:rw`/`:inout`. Defaults to
  `:r`.
- `timeout:` - required. A duration in seconds, same rule as
  `max_runtime:` above: missing, zero, or negative raises
  `ArgumentError`. A watcher without a deadline would wait for a
  wakeup that can stop coming, and the whole request would wait with
  it.
- The block - required, or `ArgumentError` at construction. It runs on
  the reactor's own thread, inside the request that is waiting, so
  `request` and `response` are already in scope - nothing has to
  cross. It is called with two arguments:
 - the event: a Symbol - `:r`, `:w`, `:rw`, or `:timeout` when the
    deadline passed with nothing to report.
 - the watcher itself.

```ruby
class Patient < Webmachine::Resource
  watch :generate_etag

  def generate_etag
    r, w = IO.pipe
    w.write('e')
    Webmachine::Watcher.new(r, :r, timeout: 2.s) do |_revents, watcher|
      r.read(1)
      watcher.abort
      'watched-value'
    end
  end

  def to_html
    'body'
  end
end
```

### `w.abort`

Calling `abort` inside the block is the one way to say the wait is
over. A block that returns without calling `abort` waits again for the
same events, with the same deadline reset. A block that calls `abort`
ends the wait, and the value it returns is the callback's answer - the
same as if an ordinary instance method had returned it directly. In
the example above, `generate_etag` answers `'watched-value'`.

Other methods on a watcher: `events`, `events=` (changes what is polled
for, without a new watcher), `timeout`, `aborted?`, `source`, `block`.

### `:timeout`

When the deadline passes with nothing to report, the block is called
with `:timeout` as the event and the watcher as the second argument.
This is the world, not a fault of the application - a descriptor that
says nothing is the ordinary end of a wait - so it arrives at the
block exactly like a readable descriptor does, and the block decides
what happens next: call `abort` to give up, or return to wait again.

A round that waits on several watchers at once ends when any one of
them is answered by `abort` - every watcher of the round takes its own
slot, but a single watcher can end the round.

A raise inside a watcher's block is the run's own raise: a 500 that
names it, the same as a raise from an ordinary instance method. It
never unwinds through the reactor, and the reactor answers the next
connection exactly as before.

## Next

- [One thread, and the work off it](../explanation/one-thread.md)
- [Resource callbacks](resource.md)
- [Request and response](request-and-response.md)
- [WebSocket and server-sent events](websocket-and-sse.md)
