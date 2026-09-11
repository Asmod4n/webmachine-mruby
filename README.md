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
    mruby/bin/webmachine-server --app=hello.mrb

A gem this tree tracks by branch is cloned by mruby once and never
pulled again, so a header added upstream is missing here with no sign
of why. `rake deps_update` pulls them; a gem pinned to a commit is
left where it is.

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

`request.body` is an IO, not a String, and `nil` when no body arrived.
Today it is a `StringIO` over the bytes. It is an IO because a body is
not always going to be in memory: a resource reads it with `read`,
`gets`, `getc`, `each`, `pos`, `seek`, `rewind`, `size` and `eof?`,
which is what a `File` answers as well. It is one object for the whole
run, so a loop that reads it goes forward.

    def process_post
      response.body = request.body.read
      true
    end

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

A websocket resource has two callbacks, and each gets the same arguments
every time: `on_data(data, binary)`, which every websocket resource
defines, and `on_close(code, reason)`, which is optional. A resource that
declares other parameters raises ArgumentError when the callback runs. To
ignore an argument, give it a default value or take `(*)`.

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

    webmachine-server --app=FILE.mrb [--config=FILE.toml]
                      [--log=FILE] [--error-log=FILE]
    webmachine-server --standalone [--unix=PATH | --port=N]
                      [--assets=FILE.zip] [--docroot=DIR]

An application names its own listener, in its conf: `app.conf.port`,
`app.conf.unix_path`, or `app.conf.url`. One process serves any number of
applications, each on its own. `--unix` and `--port` are a standalone
server's, which has no app to name one.

A request body may arrive with a `Content-Length` or with
`Transfer-Encoding: chunked`, and HTTP/2 may send one with no length at
all. A declared length picks the destination at the head. A body with
no length starts in memory and moves into a file when it grows past
256 KiB. Any other transfer coding is 501, and a request that names
both framings is 400.

A run that waits is declared, always. `compute` names the callbacks a
worker answers, `watch` the ones a descriptor answers, and `reads_body`
the ones that wait for the octets of a request body:

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
or a handler `content_types_accepted` points at. The mapping itself
never gets a body - it answers which handler does - so naming it is
refused, with the line to write instead. A callback that gets a body
and was not named is refused when the route is added, or, for a handler
an instance-level `content_types_accepted` names, at the moment the
flow would hand it one.

`save: true` says the callback may call `request.body.save`. The head
reads it before the first octet and puts the body in a file whatever
its size, so every save is a link and never a second write of the
octets. A save from a callback that did not say it is refused by name.

`request.body.save` puts an upload in the filesystem. The application
names a directory it chose and the name the user gave; everything
between them is the digest of the octets:

```ruby
def take
  # the block's String is the answer's body: /var/uploads/3f/3fa7c9...d21e
  request.body.save('/var/uploads', 'photo.png') { |dir, err| dir }
end
```

The digest is what makes the rest safe. Two uploads of the same octets
get the same directory, because they are the same file, and `mkdir` is
the atomic claim - there is no window between asking whether a name is
free and taking it. A directory that is already there means the server
holds exactly those octets: nothing is read, nothing is written, and
the block is told the directory at once. The same octets under a second
name get a second link in that directory - one inode, two names. And
nothing the client sent reaches a path component except the leaf, which
may hold no slash and no `..`.

A body that went to a file is linked into place, so the upload ends
with one link and no second write of the octets. A link cannot cross a
filesystem, so when `conf.spill_dir` and the directory are on different
ones the kernel copies with `copy_file_range`, and no octet passes
through the server. Naming `conf.spill_dir` on the filesystem the
uploads live on is what keeps every save a link.

The block is told where the content landed or what stopped it, and
whatever it answers is the answer's body, spelled with `to_s` - the
same shape as `to_html`, whose value is the body as well. So nothing in
it reaches for the response object; `nil` and `false` keep the value to
the block and let the resource spell the answer itself. It answers no
status and it cannot: a save that failed is the server's fault, so the
server spells the 500 and the error log names the reason. Without a
block the path is answered, and a failure raises just the same.

A resource that accepts uploads can ask the server to check the octets
against the type the head declared. `sniff: true` on a
`content_types_accepted` row is the whole of it - the type is already
on that line, so nothing names a magic number or an offset:

```ruby
def self.content_types_accepted
  [['image/png',  :from_png,  { sniff: true }],
   ['text/plain', :from_text, { sniff: true }]]
end
```

A request that declares `text/plain` and sends an mp4 gets 415 at the
first buffer of the body, and the rest of the upload never arrives.
The table is the WHATWG MIME Sniffing Standard's, in `src/sniff.cpp`.

It refuses only a certain contradiction. A type the table knows must
match its own octets - a JPEG declared as a PNG is refused. A type the
table cannot confirm, like `text/plain` or `application/json`, is
refused only when the octets name a concrete format of another family.
A container never contradicts, because every docx, epub and jar is a
zip. Anything else is accepted: a check that guesses would refuse
honest clients.

Written on the class, `content_types_accepted` is read once while the
app starts, and that is what lets the check run at the first buffer. On
the instance it is read per request, so the check runs when the flow
reaches it - the same answer, after the whole body has arrived.

Three levels say what a request body may hold, and the nearest one
answers: the resource, then the application, then the default of 1 MiB,
which is what nginx's `client_max_body_size` defaults to. A larger
declared `Content-Length` gets 413 before one byte of the body is read,
and HTTP/2 refuses the stream at the frame that crosses the limit.

An application names its number with `app.conf.max_body`, in octets. A
resource names its own with `def self.max_body`, and the fold asks it
once:

```ruby
class Uploads < Webmachine::Resource
  def self.max_body
    64 * 1024 * 1024
  end
end
```

So a route that takes uploads raises its limit and leaves every other
route of the application where it was. `max_body` on the instance is
refused by name: the head decides where the octets land before a
request object exists.

A pack is a zip of your site's files, built once with
`rake pack[DIR,OUT.zip]`. The server maps the archive and answers every
file in it from memory, with its ETag and its compressed form ready.
An application names its pack with `app.conf.assets`, and a directory of
files with `app.conf.docroot`, the only directory `response.file` may
reach. `--assets` and `--docroot` are the standalone server's, which
serves a pack or a directory with no app at all.
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
