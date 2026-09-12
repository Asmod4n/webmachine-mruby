# Work off the request loop

This how-to is for a developer whose callback needs to wait: for a
worker thread to finish, or for a file descriptor to become readable.
At the end, you know `compute` and `watch`, the two ways a callback
answers later without blocking the one thread that answers every
other request.

## compute: hand work to a worker thread

Declare which callback answers with work, then answer it with a
`Webmachine::ComputeTask`:

```ruby
class ComputeRound < Webmachine::Resource
  compute :generate_etag, :last_modified

  def generate_etag
    Webmachine::ComputeTask.new(max_runtime: 500.ms) { 'from-a-worker' }
  end

  def last_modified
    Webmachine::ComputeTask.new(max_runtime: 500.ms) { 1_000_000_000 }
  end

  def to_html
    'body'
  end
end
```

`compute :generate_etag, :last_modified` names the callbacks that are
allowed to answer this way; a callback declared `compute` and left
answering anything else is refused by name. The block runs on a worker
thread, not on the reactor, and its arguments and its return value
cross between the two: whatever the block answers is what the
callback's caller sees, `'from-a-worker'` as the ETag, the Integer as
`Last-Modified`. `max_runtime:` is required and is a deadline for the
block, not a hint.

The block runs fresh on every request: a declared value is not cached
between requests, only computed off the thread that would otherwise
have to wait for it.

`ComputeTask.new` also takes arguments ahead of the block, which the
worker receives as the block's parameters:

```ruby
class ComputeUser < Webmachine::Resource
  compute :is_authorized?

  def is_authorized?(header)
    Webmachine::ComputeTask.new(header, max_runtime: 50.ms) do |h|
      h == 'let-me-in' ? true : 'Basic realm="app"'
    end
  end

  def to_html
    'welcome'
  end
end
```

A callback declared `compute` must be an instance method, `def`, not
`def self.`: a class method runs once at start, before any request
exists, so there is nothing per-request to hand a worker.

## watch: wait for a file descriptor

`watch` names callbacks that may answer with a `Webmachine::Watcher`:
a source, what to wait for on it, and a block that runs when the
reactor sees it ready.

```ruby
class WatchEveryTime < Webmachine::Resource
  watch :generate_etag

  def generate_etag
    r, w = IO.pipe
    w.write('e')
    Webmachine::Watcher.new(r, :r, timeout: 2.s) do |_ev, self_|
      r.read(1)
      self_.abort
      'watched-every-time'
    end
  end

  def to_html
    'body'
  end
end
```

`Watcher.new(source, :r, timeout:) { |revents, watcher| ... }` takes
the descriptor, `:r`, `:w` or `:rw` for which readiness to wait on, and
a required `timeout:`, the same deadline `compute` needs and for the
same reason. The block runs on the reactor itself, not on a worker: it
is for asking whether the wait is over, not for doing work. Only
calling `watcher.abort` inside the block ends the wait; what the block
answers is kept either way, and becomes the callback's answer once
`abort` is called. A block that runs and does not call `abort` waits
again, whatever it returns. A block that raises aborts the watcher
too, and the raise becomes the run's own, the same as any other
callback's.

A watched value is asked fresh on every request, exactly like a
computed one: the file descriptor above is opened once per request,
inside the callback, not kept between requests.

## Which one to reach for

`compute` is for work a worker thread can just run: a slow
calculation, a password check, anything that only needs a thread and a
deadline. `watch` is for a descriptor this process already has open
that will become readable or writable on its own - a pipe, a socket, a
timer - where the work is waiting, not computing.

## When a task makes the answer slower

A crossing has a cost of its own. Per request the server encodes the
arguments as CBOR, hands the job to a worker, the worker wakes, runs
the block, encodes the answer, and the reactor decodes it on its next
turn. A block that finishes in less time than that crossing takes
makes the answer slower, not faster, and it costs a worker as well.

The loop is the fast path for short work. A lookup, a string build, a
small comparison and an ETag from a field in memory belong on the
loop. `compute` pays off when the block runs for longer than the
crossing: a password hash, a render of a large page, a compression.
Measure before you declare: time the callback on the loop, then time
it as a task, and keep the faster one.

## Next

- [passwords.md](passwords.md): a worked `compute` example that checks
  a login.
- [../reference/waiting.md](../reference/waiting.md)
- [../explanation/one-thread.md](../explanation/one-thread.md)
