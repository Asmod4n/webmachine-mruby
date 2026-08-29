# webmachine-mruby

Webmachine's HTTP state model, executed: the decision graph from
[webmachine-ruby](https://github.com/webmachine/webmachine-ruby) as
data, driven by an io_uring reactor, with mruby as the language a
resource is written in.

What a resource can answer at *setup* is answered once and never again;
only what genuinely depends on a request enters the VM. A `self.`
method is a constant, an instance method is per request.

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

```
rake
mruby/build/host/mrbc/bin/mrbc -o hello.mrb examples/hello.rb
mruby/build/host/bin/webmachine-server --app hello.mrb
```

The server runs bytecode, not source — `mrbc` first, always.

## Routes

Three kinds, three tables. A path is matched in one of them or falls
through to the next; only `add` reaches the decision graph.

```ruby
app.add_route     ['fizz', :buzz, :*], MyResource   # the flow
app.add_websocket ['ws'],              Echo         # RFC 6455
app.add_sse       ['events'],          Clock        # text/event-stream
```

A String is a literal segment, a Symbol binds one, `:*` is the tail.
`examples/` has one file per kind.

## Running it

```
webmachine-server [--config FILE.toml] [--unix PATH | --port N]
                  [--app FILE.mrb] [--assets FILE.zip] [--mime-types FILE]
                  [--log FILE [--log-privacy none|anon|full]]
                  [--error-log FILE] [--log-max-bytes N] [--pidfile PATH]
```

Precedence is CLI > `webmachine.toml` > the app's `conf`. Static files
are served from a ZIP (`--assets`), gzip synthesized from the archive's
own deflate stream.

**One of `--app` and `--assets` is required** - a server with nothing to
serve says so and exits. A pack on its own is a valid server: it answers
what it holds and 404s everything else.

Both logs are opt-in and separate — separate files, separate writers,
no field in common. `--log` is the access log and anonymizes addresses
by default; `--error-log` is what a callback *raised*: class, message
and backtrace, while the peer still sees only a 500. Compile the app
with `mrbc -g` for frames that name a file and a line.
`--log-max-bytes` is a hard ceiling on each file, 500 MB by default —
at the cap the oldest lines go, in place, so a busy server cannot fill
the disk. `0` turns the ceiling off.

## Building

`rake` builds three targets:

| target | what it is |
|---|---|
| `host` | the ship binary — no test gems, no compiler in it |
| `portable` | the same, without liburing: slipstreamIO's select(2). Correct, not fast — for hosts where io_uring is forbidden to the process |
| `debug` | where `rake test` runs, with `MRB_DEBUG` |

Needs Linux ≥ 6.11 with liburing (the `portable` target does not),
plus zlib and OpenSSL headers. `rake test` runs the unit tests, the
bintests and a smoke of both shipped binaries.

## Why it is shaped this way

The source carries one line above each function - which RFC it serves -
and one line at the top of each file saying where the reasoning is:

```cpp
// Design decisions live in .DESIGN.md, filed under what each comment names.
```

[`.DESIGN.md`](.DESIGN.md) is that file. Every measurement this tree
acted on is in it with its harness line, including the ones that buried
an idea.

## Licence

Apache-2.0.
