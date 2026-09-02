# webmachine-mruby

Webmachine's HTTP state model, executed: the decision graph from
[webmachine-ruby](https://github.com/webmachine/webmachine-ruby) as
data, driven by an io_uring reactor, with mruby as the language a
resource is written in.

A port, and it says so. [Webmachine](https://github.com/webmachine/webmachine)
is Justin Sheehy, Andy Gross and Bryan Fink's, written in Erlang at
Basho Technologies; [webmachine-ruby](https://github.com/webmachine/webmachine-ruby)
is Sean Cribbs'. The graph, the callback names and their defaults are
theirs, and 74 cases of webmachine-ruby's own `flow_spec` are what this
port is tested against. The name is used with their permission. `NOTICE`
says which parts are whose.

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
by default; `--error-log` is what a callback *raised*, and it holds all
of what led there: class, message and backtrace, the method and the
target with its query, the header fields the request steered by, and up
to 4 KB of the request body. That last one is whatever the app was sent
— a form login puts a password in it — so give the file the permissions
and the retention that says so. Compile the app with `mrbc -g` for
frames that name a file and a line.

Every record carries a **fingerprint**: that failure hashed, as 16 hex
digits, and a 500 page shows the same 16 digits as its reference. A user
reads it out ("I got `5c4ae529912f1340` after saving"), `grep` finds the
record, and there is no database in between. It is taken over the build,
the method, the target, the steering fields, the class and the trace, so
the same failure in the same place under the same request is one number
— and every `rake` that changes the app changes all of them, because a
reference must never point at a line that has since moved.

A 4xx reaches neither: nothing raised, so there is nothing to explain
and no reference to hand out.

The pages show a cat per status, from a pack the server finds on its own
or is given with `--error-assets FILE.zip`. `app.conf.disable_http_cats =
true` turns that off: the pack is never opened, so no page names a
picture and nothing is mounted at `/error_assets/`. The pages themselves
stay - they live in `Webmachine::ErrorResource`, not in the pack.

What the *peer* sees of that raise is a separate decision, and it is
made in one place — `Webmachine::ErrorResource#handle_exception`, which
by default answers the exception's class and message. Return `nil` there
and a 500 says nothing but "500" and its reference. A `handle_exception`
on an ordinary resource is ignored: how an exception becomes text is one
decision for the server, not a per-route one. An error page never
repeats anything the client sent — no target, no method, no field. What
a request was is in the error log, which is where a request belongs.
`--log-max-bytes` is a hard ceiling on each file, 500 MB by default —
at the cap the oldest lines go, in place, so a busy server cannot fill
the disk. `0` turns the ceiling off.

## Building

`rake` builds ONE binary, and `MRUBY_CONFIG` picks which:

| config | what it is |
|---|---|
| `build_config_host.rb` | the default, and the ship binary — no test gems, no compiler in it |
| `build_config_debug.rb` | where `rake test` runs, with `MRB_DEBUG` |

There is no io_uring-less second target, because there is nothing to
choose at build time any more. mruby-slipstreamio carries liburing and
builds it with the slipstream seam underneath: the one binary asks the
kernel at startup, and either the kernel or slipstreamIO's engine
answers its rings. Where the engine answers, the server says so on
stderr and says why.

Both sides are measured with the same binary — 65536 bytes served
identically with io_uring allowed and under
`kernel.io_uring_disabled=2`, and the engine's banner appearing only in
the second case.

Needs Linux, a C/C++ toolchain, and zlib and OpenSSL headers. No
kernel version floor and no io_uring: where it is missing or forbidden
the engine answers, correctly and more slowly. `rake test` runs the
unit tests and the bintests, in the debug build. `rake ship_smoke` is
separate on purpose: the shipped binary is the HOST build's, and a
debug run cannot answer for a binary it never made.

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
