# Your first server

This tutorial is for a developer who has never run webmachine-mruby.
It has one path and every step on it. At the end, you have a server
that answers two media types and a conditional request with 304.

## What you need

On Debian or Ubuntu, install these packages first:

    sudo apt-get install build-essential ruby git pkg-config zlib1g-dev libssl-dev

`build-essential` gives you a C++ compiler and `make`. `ruby` runs the
build system, rake. `git` fetches the tree's own submodule and every
mrbgem. `pkg-config` and `zlib1g-dev` let one gem find zlib. `libssl-dev`
gives you libcrypto, for the WebSocket handshake's SHA1. A container
build installs the same list, plus `ca-certificates` for `git` over
`https`.

On other systems: `zlib-devel` and `openssl-devel` on RHEL and Fedora,
`zlib-dev` and `openssl-dev` on Alpine, `xcode-select --install` plus
Homebrew's `openssl@3` on macOS.

## Clone and build

    git clone --recursive https://github.com/Asmod4n/webmachine-mruby
    cd webmachine-mruby
    rake

The first `rake` clones mruby and every gem this tree tracks, then
builds everything. This produces a lock file that pins the build, so
run it once and keep the result.

## Write a resource

A resource is a Ruby class. It answers the questions the server asks
it; the server does the rest of HTTP. Create `hello.rb`:

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

`to_html` is written `def self.`, so it runs once, when the server
starts, and its answer is kept as bytes. Every request against this
resource is a lookup and a write, nothing more. `main` is the one
function an app file must define; the server calls it once, and the
block that registers the app runs when `main` returns.

## Compile and start it

The server never compiles Ruby. It runs bytecode, made by `mrbc`:

    mruby/bin/mrbc -g -o hello.mrb hello.rb
    mruby/bin/webmachine-server --app=hello.mrb

`-g` keeps line numbers, so a raise in this file later names a line.
The server answers:

    webmachine: up, pid 8538, 1 listener(s)
    webmachine:   [0] tcp port 8080

## Ask it

    $ curl -i http://127.0.0.1:8080/
    HTTP/1.1 200 OK
    Date: Sat, 12 Sep 2026 10:32:20 GMT
    Content-Type: text/html; charset=utf-8
    Content-Length: 39

    <html><body>Hello, World!</body></html>

## Add a second media type

A resource declares every media type it can answer with
`content_types_provided`: an Array of pairs, each a media type and
the method that answers it. `Accept` picks between them; the header
that says so, `Vary: Accept`, is written for you.

```ruby
class HelloWorld < Webmachine::Resource
  def self.content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  def self.to_html
    '<html><body>Hello, World!</body></html>'
  end

  def self.to_json
    '{"hello":"world"}'
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [:*], HelloWorld
  end
end
```

Compile and start it the same way, then ask for each type:

    $ curl -i http://127.0.0.1:8080/ -H 'Accept: text/html'
    HTTP/1.1 200 OK
    Date: Sat, 12 Sep 2026 10:38:23 GMT
    Content-Type: text/html; charset=utf-8
    Vary: Accept
    Content-Length: 39

    <html><body>Hello, World!</body></html>

    $ curl -i http://127.0.0.1:8080/ -H 'Accept: application/json'
    HTTP/1.1 200 OK
    Date: Sat, 12 Sep 2026 10:38:23 GMT
    Content-Type: application/json
    Vary: Accept
    Content-Length: 17

    {"hello":"world"}

You wrote no negotiation code. The decision graph read `Accept`,
matched it against your list, and picked the method.

## Add an ETag and answer a conditional request

`generate_etag` names the value the graph puts in the `ETag` header.
When a client sends that same value back in `If-None-Match`, the graph
answers 304 and sends no body.

```ruby
class HelloWorld < Webmachine::Resource
  def self.content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  def self.generate_etag
    'hello-1'
  end

  def self.to_html
    '<html><body>Hello, World!</body></html>'
  end

  def self.to_json
    '{"hello":"world"}'
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [:*], HelloWorld
  end
end
```

Compile and start it, then ask twice: once plain, once with the ETag
you got back.

    $ curl -i http://127.0.0.1:8080/
    HTTP/1.1 200 OK
    Date: Sat, 12 Sep 2026 10:38:34 GMT
    Content-Type: text/html; charset=utf-8
    Vary: Accept
    ETag: "hello-1"
    Content-Length: 39

    <html><body>Hello, World!</body></html>

    $ curl -i http://127.0.0.1:8080/ -H 'If-None-Match: "hello-1"'
    HTTP/1.1 304 Not Modified
    Date: Sat, 12 Sep 2026 10:38:34 GMT
    Vary: Accept
    ETag: "hello-1"

The second answer has no body. `generate_etag` is written `def self.`,
so the graph computes it once, at start, and every request that names
that same ETag is answered from the header alone.

## What you have now

A server that runs one Ruby class, answers two media types over
`Accept`, and answers a conditional request with 304, all without a
line of negotiation code in your resource. The methods you wrote,
`content_types_provided` and `generate_etag`, are the whole of what you
own; the graph did everything else.

## Next

- [how-to/](how-to/): one job per page, for a reader who already runs
  a server.
- [reference/resource.md](reference/resource.md): every callback the
  decision graph calls.
- [reference/configuration.md](reference/configuration.md): every
  `app.conf` key and every `webmachine.toml` key.
- [explanation/decision-graph.md](explanation/decision-graph.md): why
  the server owns half of HTTP, and what a resource owns.
