# webmachine-mruby

webmachine-mruby runs your Ruby web app as one binary. You write a class
per resource and answer a few questions in it: which media types, which
ETag, which body. The server does the rest of HTTP for you, the way
webmachine-ruby taught it: content negotiation, conditional requests,
`Allow`, 304, 406, 412. HTTP/1.1, HTTP/2, WebSocket, server-sent events,
static files and TLS are on board. At run time it needs OpenSSL 3 on
the machine, and nothing else.

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
    mruby/bin/webmachine-server --app=hello.mrb

`self.to_html` is the whole trick. The server calls it once at start
and keeps the answer, with its status line, its head, its ETag and its
HTTP/2 header block, as bytes. A request against this resource is a
lookup and a write. Write `def to_html` when the answer changes from
request to request, and the method runs per request.

Any callback can be `def self.` when its answer is the same for every
request. Four do work per request and stay `def`: `process_post`,
`create_path`, `delete_resource` and `finish_request`. The server
says so at start if one of them is written the other way.

On one core, over a unix socket, the server answers about one million
HTTP/1.1 requests a second and ten million HTTP/2 requests a second.
Every run is in `bench/results/` with the command that made it, and
`bench/how-to-measure.md` says how to get a number you can trust.

The build makes four programs:

| | |
|---|---|
| `webmachine-server` | runs your app, one process, one thread |
| `mrbc` | compiles your Ruby to bytecode, the form the server runs |
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

A websocket resource has two callbacks, and each gets the same
arguments every time: `on_data(data, binary)`, which every websocket
resource defines, and `on_close(code, reason)`, which is optional.

`request.body` is an IO, and `nil` when no body arrived. A resource
reads it with `read`, `gets`, `getc`, `each`, `pos`, `seek`, `rewind`,
`size` and `eof?`, which is what a `File` answers as well:

```ruby
def process_post
  response.body = request.body.read
  true
end
```

`examples/` has one file per kind. `examples/site/` is a four-page
htmx site served from an asset pack.

## Work that must not block

The server is one thread. Two declarations keep a callback from
stopping it, and they differ in where the work runs, which decides how
you write the callback:

- `compute` sends a block to a worker thread. A worker has its own VM
  and sees nothing of your app, so the block carries no instance. The
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

What a worker needs is built in every worker through the registry. A
task over its deadline answers 500. A worker that raises answers 503
with `Retry-After`.

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

## Request bodies

A body may arrive with a `Content-Length`, with
`Transfer-Encoding: chunked`, or over HTTP/2 with no length at all. A
declared length picks where the body lands before the first octet
arrives. A body with no length starts in memory and moves into a file
when it grows past 256 KiB.

A run that waits is declared, and there are three declarations:
`compute` names the callbacks a worker answers, `watch` the ones a
descriptor answers, and `reads_body` the ones that wait for the octets
of a request body:

```ruby
class Upload < Webmachine::Resource
  reads_body :take, save: true

  def self.content_types_accepted
    [['application/octet-stream', :take]]
  end

  def take
    request.body.save('/var/uploads', 'photo.png') { |dir, err| dir }
  end
end
```

The name is the callback a body reaches: `process_post`, `create_path`,
or a handler that `content_types_accepted` points at. The server checks
the declaration when the route is added, so a body only ever reaches a
callback that asked for one, and a missing declaration is a message at
start with the line to write.

`save: true` says the callback may call `request.body.save`. The head
reads it before the first octet and puts the body in a file whatever
its size, so every save is a link and no octet is written twice.

**Uploads.** `request.body.save` puts an upload in the filesystem. The
application names a directory it chose and the name the user gave, and
everything between them is the digest of the octets:

```ruby
def take
  # the block's String is the answer's body: /var/uploads/3f/3fa7c9...d21e
  request.body.save('/var/uploads', 'photo.png') { |dir, err| dir }
end
```

The digest is what makes the rest simple. Two uploads of the same
octets get the same directory, because they are the same file, and
`mkdir` is the atomic claim. A directory that is already there means
the server holds those octets, so nothing is read or written, and the
block is told the directory at once. The same octets under a second
name get a second link in that directory: one inode, two names. Of
what the client sent, only the leaf reaches a path component.

A body that went to a file is linked into place. A link cannot cross a
filesystem, so when `conf.spill_dir` and the directory are on different
ones the kernel copies with `copy_file_range`, and no octet passes
through the server. Name `conf.spill_dir` on the filesystem the uploads
live on, and every save is a link.

The block is told where the content landed or what stopped it, and
whatever it answers is the answer's body, spelled with `to_s`, the same
shape as `to_html`. `nil` and `false` keep the value to the block and
let the resource spell the answer itself. A save that failed is the
server's to report: it answers 500 and the error log names the reason.

**Checking the octets.** A resource that accepts uploads can ask the
server to check the octets against the type the head declared.
`sniff: true` on a `content_types_accepted` row is the whole of it:

```ruby
def self.content_types_accepted
  [['image/png',  :from_png,  { sniff: true }],
   ['text/plain', :from_text, { sniff: true }]]
end
```

A request that declares `text/plain` and sends an mp4 gets 415 at the
first buffer of the body, and the rest of the upload never has to
arrive. The table is the WHATWG MIME Sniffing Standard's, in
`src/sniff.cpp`. It acts only on a certain contradiction: a type the
table knows must match its own octets, a type it cannot confirm is
accepted unless the octets name a concrete format of another family,
and a container never contradicts, because every docx, epub and jar is
a zip. Honest clients pass.

Written on the class, `content_types_accepted` is read once while the
app starts, and that is what lets the check run at the first buffer. On
the instance it is read per request, so the check runs when the flow
reaches it, with the same answer after the body has arrived.

**Size.** Three levels say what a request body may hold, and the
nearest one answers: the resource, then the application, then the
default of 1 MiB, which is nginx's `client_max_body_size` default. A
larger declared `Content-Length` gets 413 before one byte of the body
is read, and HTTP/2 refuses the stream at the frame that crosses the
limit.

An application names its number with `app.conf.max_body`, in octets. A
resource names its own with `def self.max_body`, and raises its limit
while every other route of the application stays where it was:

```ruby
class Uploads < Webmachine::Resource
  def self.max_body
    64 * 1024 * 1024
  end
end
```

## Running it

    webmachine-server --app=FILE.mrb [--config=FILE.toml]
                      [--log=FILE] [--error-log=FILE]
    webmachine-server --standalone [--unix=PATH | --port=N]
                      [--assets=FILE.zip] [--docroot=DIR]

An application names its own listener in its conf: `app.conf.port`,
`app.conf.unix_path`, or `app.conf.url`. One process serves any number
of applications, each on its own. `--unix` and `--port` are for the
standalone server, which has no app to name one.

**Static files.** A pack is a zip of your site's files, built once with
`rake pack[DIR,OUT.zip]`. The server maps the archive and answers every
file in it from memory, with its ETag and its compressed form ready. An
application names its pack with `app.conf.assets`, and a directory of
files with `app.conf.docroot`, which is the directory `response.file`
serves from. `--assets` and `--docroot` give the standalone server a
pack or a directory to serve with no app at all.

**Configuration.** `--write-config` writes a `webmachine.toml` with
every setting and what it does. `webmachine.toml.example` is that file.
Without `--config` the server reads `webmachine.toml` in the start
directory, then `/usr/local/etc/webmachine/webmachine.toml`, then the
same under `/etc`.

**Installing.** `rake install[PREFIX]` puts the four programs under
`PREFIX/bin`, the error pages' pictures under
`PREFIX/share/webmachine-mruby`, and a config that names them under
`PREFIX/etc/webmachine`. `PREFIX` is `/usr/local` when not given.

**Logs.** Both logs are off until you name a file. The access log
anonymizes addresses by default. Every error record carries a
fingerprint, and the 500 page shows the same fingerprint, so `grep`
finds the record.

## TLS

TLS is kTLS. The server does the TLS 1.3 handshake through OpenSSL and
gives the keys to the kernel. After that, a plain `send` is a TLS
record. Linux and FreeBSD offer this. On a kernel without kTLS the
server speaks plain HTTP, and a proxy in front of it does TLS.

## Building

`rake` builds everything. It clones mruby and the gems this tree
tracks on the first run, and it keeps those clones as they are after
that. `rake deps_update` pulls mruby and every gem tracked by branch,
which is the step to take when a build asks for a symbol the clone does
not have yet.

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
