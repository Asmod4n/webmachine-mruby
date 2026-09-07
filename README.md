# webmachine-mruby

webmachine-mruby runs your Ruby web app as one binary. You write a class
per resource and answer a few questions in it: which media types, which
ETag, which body. The server does the rest of HTTP for you, the way
webmachine-ruby taught it: content negotiation, conditional requests,
`Allow`, 304, 406, 412. HTTP/1.1, HTTP/2, WebSocket, server-sent events,
static files and TLS are on board. There is nothing to install beside
the binary.

It is fast because you decide, per method, what runs when. A method
written as `def self.x` runs once, when the server starts, and its
answer is kept as bytes. A method written as `def x` runs per request.

It runs on io_uring where the kernel allows it. slipstreamIO carries the
same rings to Linux without io_uring, to macOS, the BSDs, and Windows.

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
    mruby/bin/mrbc -g -o hello.mrb hello.rb
    mruby/bin/webmachine-server --app=hello.mrb --port=8080

`self.to_html` is the whole trick. The server calls it once at start
and keeps the answer, with its status line, its head, its ETag and its
HTTP/2 header block, as bytes. A request against this resource never
enters the VM. It is a lookup and a write. Write `def to_html` only when
the answer changes from request to request. Then the method runs per
request.

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
  def self.content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  def self.generate_etag
    'article-7'
  end

  def self.last_modified
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

## Work that must not block

The server is one thread. Two declarations keep a callback from
stopping it, and they differ in where the work runs, which decides how
you write the callback:

- `compute` sends a block to a worker thread. A worker has its own VM
  and sees nothing of your app, so the block can carry no instance. The
  callback is written `def self.x`: it builds the task, and nothing
  else.
- `watch` waits on a descriptor in the server's own thread. The block
  runs inside the request, with `request` and `response` in reach, so
  the callback is written `def x`, like any other callback that runs
  per request.

**`compute`** sends a block to a worker thread with a deadline. The
flow waits at that node and goes on with the block's answer. Password
hashing is the typical case:

```ruby
Webmachine::Workers::Registry[:passwords] = proc do
  { 'ada' => Argon2.hash('secret')[:encoded] }   # built once per worker
end

class Login < Webmachine::Resource
  compute :is_authorized?

  def self.is_authorized?(header)
    Webmachine::ComputeTask.new(header, max_runtime: 200.ms) do |h|
      user, pass = h.to_s.split(':', 2)
      stored = Webmachine::Workers::Registry[:passwords][user]
      stored ? Argon2.verify(stored, pass.to_s) : false
    end
  end
end
```

A worker has its own VM, so the block sees nothing of your app. What
it needs is built in every worker through the registry. A task over
its deadline answers 500. A worker that raises answers 503 with
`Retry-After`.

**`watch`** waits on a descriptor. The block runs each time the
descriptor is ready, until it says `abort`, and its last value is the
callback's answer. A database query, with the connection reused:

```ruby
DB_IDLE = []   # one thread, so an Array is a pool

class Article < Webmachine::Resource
  watch :generate_etag

  def generate_etag
    conn = DB_IDLE.pop || Pq.new(DB_URL).tap { |c| c.nonblocking = true }
    conn.send_query('select etag from articles where id = 7')
    Webmachine::Watcher.new(conn.socket, :r, timeout: 2.s) do |ready, w|
      next w.abort if ready == :timeout   # mid-query: not returned
      conn.consume_input
      next if conn.busy?                  # not whole yet: wait again
      w.abort
      etag = conn.get_result.to_ary[0][0]
      conn.get_result                     # the nil that ends the set
      DB_IDLE << conn
      etag
    end
  end
end
```

Nothing else on the server waits while this does. Every other
connection is served in between.

## Running it

    webmachine-server [--config=FILE.toml] [--unix=PATH | --port=N]
                      [--app=FILE.mrb] [--assets=FILE.zip] [--docroot=DIR]
                      [--standalone] [--log=FILE] [--error-log=FILE]

A pack is a zip of your site's files, built once with
`rake pack[DIR,OUT.zip]`. The server maps the archive and answers every
file in it from memory, with its ETag and its compressed form ready.
`--assets` names a pack, `--docroot` names a directory of files instead.
`--standalone` serves a pack or a directory with no app at all.
`--write-config` writes a `webmachine.toml` with every setting and what
it does. `webmachine.toml.example` is that file. Without `--config` the
server reads `webmachine.toml` in the start directory, then
`/usr/local/etc/webmachine/webmachine.toml`, then the same under `/etc`.

`rake install[PREFIX]` puts the four programs under `PREFIX/bin`, the
error pages' pictures under `PREFIX/share/webmachine-mruby`, and a
config that names them under `PREFIX/etc/webmachine`. `PREFIX` is
`/usr/local` when not given.

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

## Credit

This is a port. [Webmachine](https://github.com/webmachine/webmachine)
is Justin Sheehy, Andy Gross and Bryan Fink's, written at Basho.
[webmachine-ruby](https://github.com/webmachine/webmachine-ruby) is Sean
Cribbs'. The flow, the callback names and their defaults are theirs.
The name is used with their permission. `NOTICE` says which parts are
whose.

Apache-2.0.
