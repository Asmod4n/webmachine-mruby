# webmachine-mruby

[![test](https://github.com/Asmod4n/webmachine-mruby/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/Asmod4n/webmachine-mruby/actions/workflows/test.yml)

webmachine-mruby runs your Ruby web app as one binary. You write a
class per resource and answer a few questions in it: which media
types, which ETag, which body. The server does the rest of HTTP.

## Why

- **The half of HTTP you did not write.** Every request walks
  webmachine's decision graph. Content negotiation, conditional
  requests, `Allow`, 304, 406 and 412 come from the graph. Your
  resource answers only the questions it cares about.
- **You decide when a method runs.** A method written `def self.x`
  runs once, when the server starts, and its answer is kept as bytes.
  A method written `def x` runs per request. On one core, over a unix
  socket, the server answers about one million HTTP/1.1 requests a
  second and ten million HTTP/2 requests a second. Every run is in
  [`bench/results/`](bench/results/) with the command that made it.
- **One binary, nothing to assemble.** HTTP/1.1, HTTP/2, WebSocket,
  server-sent events, static files and TLS are on board. At run time
  it needs OpenSSL 3 on the machine, and nothing else.

## Quick start

On Debian or Ubuntu, the build needs these packages. Other systems are
in [Building](#building).

    sudo apt-get install build-essential ruby git pkg-config zlib1g-dev libssl-dev

Clone and build. The first `rake` clones mruby and the gems this tree
tracks, then builds everything.

    git clone --recursive https://github.com/Asmod4n/webmachine-mruby
    cd webmachine-mruby
    rake

Write `hello.rb`:

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

Compile it and start the server:

    mruby/bin/mrbc -g -o hello.mrb hello.rb
    mruby/bin/webmachine-server --app=hello.mrb

The server says what it listens on:

    webmachine: up, pid 8538, 1 listener(s)
    webmachine:   [0] tcp port 8080

Ask it:

    $ curl -i http://127.0.0.1:8080/
    HTTP/1.1 200 OK
    Date: Sat, 12 Sep 2026 10:32:20 GMT
    Content-Type: text/html; charset=utf-8
    Content-Length: 39

    <html><body>Hello, World!</body></html>

`self.to_html` is the whole trick. The server calls it once at start
and keeps the answer, with its status line and its head, as bytes. A
request against this resource is a lookup and a write. Write
`def to_html` when the answer changes from request to request.

The [tutorial](docs/tutorial.md) goes on from here: a second media
type, an ETag, and a conditional request that answers 304.

## The model

A resource declares what it knows. The decision graph does the rest.

```ruby
class Article < Webmachine::Resource
  def self.content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  def self.generate_etag
    'article-7'
  end

  def to_html
    "<h1>#{request.path}</h1>"
  end

  def to_json
    %Q({"path":"#{request.path}"})
  end
end
```

This resource answers `Accept`, `If-None-Match` and `OPTIONS`
correctly, and you wrote none of that. The callback names are
[webmachine-ruby](https://github.com/webmachine/webmachine-ruby)'s.

Any callback can be `def self.` when its answer is the same for every
request. A callback that asks about a request is `def`. The server
says so at start if one of them is written the other way. Doing the
work at start is a choice per callback, never a condition: an answer
can be as static or as dynamic as HTTP allows.

## What is on board

| | Read more |
|---|---|
| HTTP/1.1 and HTTP/2 on one listener, cleartext or TLS | [reference](docs/reference/configuration.md) |
| WebSocket, RFC 6455, with permessage-deflate | [how-to](docs/how-to/websocket.md) |
| Server-sent events, as a route kind of its own | [how-to](docs/how-to/server-sent-events.md) |
| Static files from a zip pack or a directory, with ETag and gzip | [how-to](docs/how-to/serve-static-files.md) |
| TLS through the kernel (kTLS) where the kernel has it | [how-to](docs/how-to/tls.md) |
| Work off the request loop: `compute` and `watch` | [how-to](docs/how-to/work-off-the-loop.md) |
| Request bodies and uploads, with a size limit at three levels | [how-to](docs/how-to/accept-uploads.md) |
| Access and error logs, written by their own process | [how-to](docs/how-to/logs.md) |
| A password database, argon2id in LMDB, with its own tool | [how-to](docs/how-to/passwords.md) |

The build makes four programs:

| | |
|---|---|
| `webmachine-server` | runs your app, one process, one thread |
| `mrbc` | compiles your Ruby to bytecode, the form the server runs |
| `webmachine-logd` | writes the access log and the error log, as its own process |
| `webmachine-passwd` | keeps the password database |

## Documentation

The docs are split by what you need from them.

- [Tutorial](docs/tutorial.md): your first server, step by step.
- [How-to guides](docs/README.md#how-to-guides): one job per page.
- [Reference](docs/README.md#reference): every callback, method,
  flag and config key.
- [Explanation](docs/README.md#explanation): the decision graph,
  when a method runs, one thread and the work off the loop.

[`docs/README.md`](docs/README.md) is the map. `examples/` has one
file per kind of resource, and `examples/site/` is a four-page htmx
site served from an asset pack.

## What is checked

- `rake test` on every push: mruby's own tests, this gem's unit tests,
  and the bintests against the debug binary.
- The same suite under the address and thread sanitizers, on every
  push.
- `rake ship_smoke` on every push: the release build starts and
  answers 200.
- [h2spec](https://github.com/summerwind/h2spec) on every push:
  145 of 146 cases. The remaining case asks for a refusal that this
  listener answers as HTTP/1.1; `tools/conformance.sh` says why.
- The [Autobahn](https://github.com/crossbario/autobahn-testsuite)
  WebSocket suite on every release tag.
- Fuzzing of the framers by hand, with `tools/fuzz.sh`.

## Speed

Both figures above are one core, over a unix socket, with both sides
of the measurement busy. [`bench/how-to-measure.md`](bench/how-to-measure.md)
says how to get a number you can trust on your own hardware, and
[`bench/host-variance.md`](bench/host-variance.md) says what the host
adds. A number from someone else's machine is a starting point, not
a result.

It runs on io_uring where the kernel allows it. slipstreamIO carries
the same rings to Linux without io_uring, to macOS, the BSDs, and
Windows.

## Building

`rake` builds everything. `rake deps_update` pulls mruby and every gem
tracked by branch. Only the debug config is built while developing:

    MRUBY_CONFIG=build_config_debug.rb rake compile
    MRUBY_CONFIG=build_config_debug.rb rake test

What a build needs, and what the binary needs where it runs, in
Debian's package names. The `Containerfile` installs the same two
lists.

| | |
|---|---|
| build | `build-essential ruby git pkg-config zlib1g-dev libssl-dev` |
| run | `libz1 libssl3 libstdc++6` |

The same packages elsewhere: `zlib-devel` and `openssl-devel` on RHEL
and Fedora, `zlib-dev` and `openssl-dev` on Alpine, and
`xcode-select --install` plus Homebrew's `openssl@3` on macOS. When a
header is missing, the build stops and names the package for your
distribution. TLS wants a kernel with the tls module loaded. A
listener that serves TLS refuses to start without it and names the
reason. Without kTLS, run plain HTTP with a proxy in front for TLS.

[`docs/container.md`](docs/container.md) builds and runs it in a
container.

## Contributing

[`CLAUDE.md`](CLAUDE.md) holds the rules: two branches, `next` for
development and `master` for finished features; Simplified Technical
English in every file and every commit message; no bang methods; and
the three rules of the code. Nothing in `rake test` may fail.

## License and credit

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

This is a port. [Webmachine](https://github.com/webmachine/webmachine)
is Justin Sheehy, Andy Gross and Bryan Fink's, written at Basho.
[webmachine-ruby](https://github.com/webmachine/webmachine-ruby) is Sean
Cribbs'. The flow, the callback names and their defaults are theirs.
The name is used with their permission. `NOTICE` says which parts are
whose.
