# webmachine-mruby

**An HTTP server you write in Ruby and ship as one binary.**

It speaks HTTP/1.1, HTTP/2, WebSocket and server-sent events, serves
files and static packs, and terminates TLS through the kernel. One
thread, one core, no runtime to install beside it.

```ruby
class HelloWorld < Webmachine::Resource
  def self.to_html
    '<html><body>Hello, World!</body></html>'
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [:*], HelloWorld
  end
end
```

    rake
    mruby/bin/mrbc -o hello.mrb hello.rb
    mruby/bin/webmachine-server --app=hello.mrb --port=8080

That is a whole server. On one core it answers **a million requests a
second** over a unix socket — and where it has been measured against
openlitespeed on one box, one worker each, it answers **5.5×** what
openlitespeed does.

## Why it is that fast

**The decision is made before the request arrives.**

Webmachine's flow graph — the one from
[webmachine-ruby](https://github.com/webmachine/webmachine-ruby) — is a
constant here. Everything a resource can answer at setup is answered
once, folded into that graph, and baked into the bytes that go on the
wire.

So the resource above never enters the VM again. Its 200, its head, its
ETag, its `Allow`, its h2 header block: all of it exists before the
first accept. A request against it is a table lookup and a write.

**`def self.x` is a constant; `def x` is per request.** That one line is
the whole performance model.

## What that costs, measured

`bench/results/` holds every run with its harness line, its host, its
kernel, its compiler and its CPU split. Two machines answer below, and
their numbers are not mixed.

**A desktop, openSUSE, one core, one thread, over a unix socket**
(`bench/results/forgecore.log`, 2026-09-06)

| | requests per second |
|---|---|
| HTTP/2, 16 connections × 128 streams | **8.2–10.1 M** |
| HTTP/1.1, 192 connections | **1.0 M** |

**A container VM, one core, over TCP** — the openlitespeed comparison
(`bench/results/vm.log`, 2026-09-05)

| | requests per second |
|---|---|
| webmachine-mruby, 192 connections | **232 k** |
| openlitespeed, same box, same minute, same client | 42 k |

That pair is the honest one: both servers pinned to one worker, both
server-bound, openlitespeed with its own best settings and its cache
module off. **4.6× at 64 connections, 5.5× at 192.** The two do not
answer identical bytes — 244 against 155 — and the log says so.

A VM entry costs 95–191 ns. The point of the fold is not that mruby is
fast; it is that a folded resource never pays that at all.

## What it is

- **The whole graph, ported and tested against its source.** 74 cases
  from webmachine-ruby's own `flow_spec` run here. Callback names,
  defaults and terminals are theirs.
- **HTTP/1.1 and HTTP/2**, h2c and prior knowledge, with the h2 header
  blocks prebuilt per route. h2spec reads 145 of 146, and the one it
  refuses is a refusal, not a gap: the same listener also speaks
  HTTP/1.1, so a preface that is already wrong at byte 0 gets HTTP/1.1's
  400 instead of a frame.
- **WebSocket** (RFC 6455, permessage-deflate) and **server-sent
  events**, each a route kind of its own. The Autobahn suite passes
  through both an h1 and an RFC 8441 h2 upgrade.
- **A static tier that never touches the VM.** A ZIP is mapped once;
  gzip is synthesized from the archive's own deflate stream, so a
  compressed file is never compressed twice. Conditional requests,
  ranges and refusals are answered from prebuilt heads.
- **A standalone server.** `--standalone` with a pack or a directory
  and no app at all: the folded graph serves files, and no request
  enters a VM that was never opened.
- **TLS through the kernel.** kTLS: this process does the handshake,
  the kernel does the record layer. From `setsockopt` onwards a plain
  `send` is a TLS record, so iovecs still point straight into asset
  mappings and lent strings - a userspace record layer would have to
  copy every one of those through an encryption buffer.
- **io_uring, or not.** One binary asks the kernel at startup. Where
  io_uring is forbidden or absent, slipstreamIO's engine answers the
  same rings — correctly, and slower — and the server says so on stderr.

## Writing an app

Three route kinds, three tables:

```ruby
app.add_route     ['fizz', :buzz, :*], MyResource   # the flow
app.add_websocket ['ws'],              Echo         # RFC 6455
app.add_sse       ['events'],          Clock        # text/event-stream
```

A String is a literal segment, a Symbol binds one, `:*` is the tail.
`examples/` has a file per kind, and `examples/site/` is a four-page
htmx site served from a pack.

The server runs bytecode, never source: `mrbc` first, always.

## Running it

    webmachine-server [--config=FILE.toml] [--unix=PATH | --port=N]
                      [--app=FILE.mrb] [--assets=FILE.zip] [--docroot=DIR]
                      [--standalone] [--log=FILE] [--error-log=FILE]

`--write-config` writes `webmachine.toml` with every setting the file
form carries and what each one does. `webmachine.toml.example` in this
tree is that file, generated by the server itself so it cannot go stale.

Both logs are opt-in and separate. The access log anonymizes addresses
by default. The error log holds what a callback **raised** — class,
message, backtrace, the request that led there — and every record
carries a 16-hex-digit fingerprint that a 500 page shows as its
reference, so a user can read the number out and `grep` finds the
record. No database in between.

## What it asks of you

Linux, a C/C++ toolchain, zlib and OpenSSL headers. No kernel floor:
where io_uring is missing, the engine answers.

It is one process and one thread by design. Work that must not block
the reactor goes to a compute pool with a deadline; everything else is
a state machine.

## Where the reasoning is

Every file says it in its first line:

```cpp
// Design decisions live in .DESIGN.md, filed under what each comment names.
```

[`.DESIGN.md`](.DESIGN.md) holds every measurement this tree acted on,
with its harness line — including the ones that buried an idea.

## Credit

A port, and it says so. [Webmachine](https://github.com/webmachine/webmachine)
is Justin Sheehy, Andy Gross and Bryan Fink's, written in Erlang at
Basho Technologies; [webmachine-ruby](https://github.com/webmachine/webmachine-ruby)
is Sean Cribbs'. The graph, the callback names and their defaults are
theirs, and the name is used with their permission. `NOTICE` says which
parts are whose.

Apache-2.0.
