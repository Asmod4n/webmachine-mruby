# webmachine-mruby

webmachine-mruby is a small, fast HTTP server for Ruby. You write
resources, and it runs them from one binary.

- **The HTTP model comes with it.** Conditional requests, content
  negotiation, `Allow`, 304, 406, 412: webmachine's flow answers them
  from what your resource declares. You do not write that logic again
  for every route, as you do on every other server.
- **Everything on board.** HTTP/1.1, HTTP/2, WebSocket, server-sent
  events, static files, TLS.
- **Fast by design.** `def self.x` runs once, when the server starts,
  and its answer is kept as bytes. `def x` runs per request. You choose
  per method.
- **Runs everywhere.** io_uring where the kernel allows it. slipstreamIO
  carries the same rings to Linux without io_uring, to macOS, the BSDs,
  and Windows.

## Hello, World

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

`self.to_html` is the whole trick. The server calls it once at start
and keeps the answer, with its status line, its head, its ETag and its
HTTP/2 header block, as bytes. A request against this resource never
enters the VM. It is a lookup and a write. Write `def to_html` instead,
and the method runs per request.

Any callback can be `def self.`, when its answer is the same for every
request. Four do work and must stay `def`: `process_post`,
`create_path`, `delete_resource` and `finish_request`. The server
refuses a class-level one of those at start, by name, because it would
run once at setup and never again.

On one core, over a unix socket, the server answers about one million
HTTP/1.1 requests a second. Every run is in `bench/results/` with the
command that made it.

The build makes four programs:

| | |
|---|---|
| `webmachine-server` | runs your app, one process, one thread |
| `mrbc` | compiles your Ruby to bytecode, the only form the server runs |
| `webmachine-logd` | writes the access log and the error log, as its own process |
| `webmachine-passwd` | keeps the password database, argon2id in LMDB |

## Writing an app

Three route kinds, three tables:

```ruby
app.add_route     ['fizz', :buzz, :*], MyResource   # the flow
app.add_websocket ['ws'],              Echo         # RFC 6455
app.add_sse       ['events'],          Clock        # text/event-stream
```

A String is a literal segment, a Symbol binds one, and `:*` takes the
rest of the path.

A resource declares what it knows, and the flow does the rest:

```ruby
class Article < Webmachine::Resource
  def content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  def generate_etag
    'article-7'
  end

  def last_modified
    1_756_000_000   # seconds since the epoch
  end
end
```

That resource answers `Accept`, `If-None-Match`, `If-Modified-Since`
and `OPTIONS` correctly, and you wrote none of it. The callback names
are [webmachine-ruby](https://github.com/webmachine/webmachine-ruby)'s,
so its documentation applies here.

`examples/` has one file per kind. `examples/site/` is a four-page
htmx site served from an asset pack.

## Running it

    webmachine-server [--config=FILE.toml] [--unix=PATH | --port=N]
                      [--app=FILE.mrb] [--assets=FILE.zip] [--docroot=DIR]
                      [--standalone] [--log=FILE] [--error-log=FILE]

`--standalone` serves a pack or a directory with no app at all.
`--write-config` writes a `webmachine.toml` with every setting and what
it does. `webmachine.toml.example` is that file.

Both logs are off until you name a file. The access log anonymizes
addresses by default. Every error record carries a fingerprint, and the
500 page shows the same fingerprint, so `grep` finds the record.

## TLS

TLS is kTLS. The server does the TLS 1.3 handshake through OpenSSL and
gives the keys to the kernel. After that, a plain `send` is a TLS
record. Linux and FreeBSD offer this. On a kernel without kTLS the
server speaks plain HTTP, and a proxy in front of it does TLS.

## What you need

- To build: a C/C++ toolchain, zlib headers, OpenSSL 3 headers.
- To run: OpenSSL 3, and for TLS a kernel with the tls module loaded.

## Where the reasoning is

Every source file starts with the same line, and it points at
[`.DESIGN.md`](.DESIGN.md). That file holds every decision this tree
made, with the measurement behind it.

## Credit

This is a port. [Webmachine](https://github.com/webmachine/webmachine)
is Justin Sheehy, Andy Gross and Bryan Fink's, written at Basho.
[webmachine-ruby](https://github.com/webmachine/webmachine-ruby) is Sean
Cribbs'. The flow, the callback names and their defaults are theirs.
The name is used with their permission. `NOTICE` says which parts are
whose.

Apache-2.0.
