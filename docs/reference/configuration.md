# Configuration reference

This page is for a developer or operator who configures an application
or a standalone server. At the end, you know every route form, every
`app.conf` key, every `webmachine.toml` key, the search order for the
config file, and `--write-config`.

## Webmachine::Application

`Webmachine::Application.new { |app| ... }` takes a block and yields the
app. When the block returns, the server reads the conf and registers
the app. Without a block, nothing is registered, and a file whose
`main` registers no application is refused: `main registered no
application - Webmachine::Application.new takes a block, and returning
from it is what registers the app`.

| Method | Note |
| --- | --- |
| `app.conf` | The one `Webmachine::Config` object for this app; the same object on every read. |
| `app.configure { \|conf\| ... }` | Yields `app.conf`. Without a block, refuses with `Webmachine::Error`: `app.configure wants a block`. |
| `app.config { \|conf\| ... }` | Same method as `app.configure`, under the other name. |
| `app.routes { \|route\| ... }` | Yields a `Webmachine::Routes` object. Without a block, refuses with `Webmachine::Error`: `app.routes wants a block`. |
| `app.ready { ... }` | Stores a block that runs once, after the bind and before the first accept. Without a block, refuses with `Webmachine::Error`: `app.ready wants a block`. A second call replaces the first block. |
| `app.add_route tokens, klass` | Same function as `route.add` on the Routes object. |
| `app.add_websocket tokens, klass` | Same function as `route.websocket`. |
| `app.add_sse tokens, klass` | Same function as `route.sse`. |
| `app.stop(duration)` | Same function as `Webmachine.stop`. |

`route.assets` is a signpost, not a working method. It raises
`Webmachine::RouteError`: `route.assets is reserved - the asset mount is
#170/#115. Assets are configured with conf.assets and serve unchanged`.

The module functions `Webmachine.run`, `Webmachine.tick(duration)`,
`Webmachine.fd`, `Webmachine.stop(duration)` and `Webmachine.stopped?`
let `main` drive the event loop itself, instead of returning and letting
the tool loop.

Two spellings that both work:

```ruby
def main
  Webmachine::Application.new do |app|
    app.configure do |conf|
      conf.port = 8080
    end
    app.routes do |route|
      route.add ['fizz', :buzz, :*], MyResource
    end
    app.ready do
      puts 'ready'
    end
  end
end
```

```ruby
def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [:*], HelloWorld
  end
end
```

## add_route, in every form

A route is a token list, an Array, and a resource class. A String in
the list is one literal path segment. A Symbol binds one segment under
that name. `:*` takes the rest of the path and must be last in the
list.

| Form | Matches |
| --- | --- |
| `route.add [], YourResource` | The root route. `GET /` matches; `GET /deeper` is 404. |
| `route.add [:*], YourResource` | Every path. |
| `route.add ['fizz', :buzz, :*], YourResource` | `/fizz/one`, `/fizz/one/two/three`, `/fizz/one?v=1`. `/buzz/one` and `/fizz` are 404. `request.path_info[:buzz]` gives the bound segment. |
| `route.add %w[fragment time], YourResource` | Same as `['fragment', 'time']`: two literal segments. |
| `route.websocket tokens, klass` | Same token grammar, registers a WebSocket resource. |
| `route.sse tokens, klass` | Same token grammar, registers a Server-Sent Events resource. Refuses a class that is not a `Webmachine::SseResource`. |

The first matching route wins, in registration order: with
`['a', :*]` registered before `['a', 'b']`, `/a/b` reaches the first. A
router miss is 404 before the flow starts, so a POST on an unknown path
answers 404, not 405.

Refusals, all `Webmachine::RouteError`, prefixed with the caller's name
(`route.add`, `route.websocket` or `route.sse`):

- `<who>: :* is the tail of a route - nothing may follow it`
- ``<who>: ["/"] is a route with one segment named "/", which no request can have - the root is the empty list, add [], YourResource``
- `<who>: a route token is one path segment, and <token> carries a "/" - split it into one token per segment`
- `<who>: an empty token is a segment no request can have - to route the root, pass no tokens at all`
- `<who>: a literal token is too long`
- `<who>: too many bindings in one route (16 is the table's width)`
- `<who>: a token is a String (literal), a Symbol (binding) or :* (tail)`

`route.add` also refuses a non-class with `route.add wants a class
inheriting Webmachine::Resource`, and a class that is not a subclass
with `route.add: <klass> does not inherit Webmachine::Resource`.

## What def main must return

An app file defines a top-level `main`. The server calls it once, with
no arguments, and its return value is not read. A file without `main`
is refused: `<path> defines no `main` - since #116 an app file defines
exactly that, and Webmachine::Application.new inside it registers the
app`.

What matters is that `main` calls `Webmachine::Application.new` with a
block, and that the block registers the app by returning. `main` may
also drive the event loop itself, with `Webmachine.run`, or with
`Webmachine.tick(3.ms) until Webmachine.stopped?`, or by polling
`IO.new(Webmachine.fd)` and then ticking. When `main` returns without
doing that, the server's own loop takes over.

One process can serve any number of applications; each names its own
listener, and registration order is listener order. The ring holds at
most 16 listeners. Two applications on the same listener are refused
with `Webmachine::RouteError`. An application with no listener is
refused at build time: `application <i> has no listener - its configure
block names one (conf.port / conf.unix_path / conf.url)`.

## app.conf: every key

`Webmachine::Config` is a Struct with twelve members, in this order:
`port`, `unix_path`, `url`, `docroot`, `assets`, `certificate`,
`private_key`, `file_map_threshold`, `zero_copy_threshold`,
`disable_http_cats`, `max_body`, `spill_dir`. Every member starts as
nil, meaning the app said nothing about it. A name that is not a member
is a `NoMethodError` at that line.

Refusal texts share a shape. For the four Integer keys: `conf.<name>
wants an Integer` for a non-Integer, and `conf.<name> = <v> is outside
0..<ceiling><unit>` for a value out of range. For the String keys:
`conf.<name> wants a String` for a non-String, and `conf.<name> is
empty` for an empty String. The error class is `Webmachine::ConfigError`.

| Key | Type | Default | Ceiling | What it does |
| --- | --- | --- | --- | --- |
| `port` | Integer | none | 65535 | The TCP port to listen on. `0` is legal: the OS picks a port at bind time, readable back through `app.ready`. Exactly one of `port`, `unix_path` or `url` may be set per application; a second form is refused. An application with none of the three is refused at build. |
| `unix_path` | String, not empty | none | -  | The unix socket path to listen on, instead of a port. |
| `url` | String | none | -  | The listener, and optionally settings, in one string: `scheme://host[:port][?setting=value&...]` or `unix:///path[?setting=value&...]`. See below. |
| `docroot` | String, not empty | none | -  | The directory `response.file` serves from. Process-wide: the first app that names one decides. |
| `assets` | String, not empty | none | -  | The zip pack a standalone or app server answers from. Process-wide: the first app that names one decides. |
| `certificate` | String, not empty | none | -  | Path to the PEM certificate file. Only valid with a `https` listener. |
| `private_key` | String, not empty | none | -  | Path to the PEM private key file. Only valid with a `https` listener; both `certificate` and `private_key` are required together. |
| `file_map_threshold` | Integer | 262144 (256 KiB) | 1073741824 (1 GiB) | From this size up, a `response.file` file is mapped and handed to one send instead of read window by window. `0` means never map. A `--file-map-threshold` flag or `[tune] file_map_threshold` in the config file beats this. |
| `zero_copy_threshold` | Integer | 131072 (128 KiB) | 1073741824 (1 GiB) | From this size up, a body is lent to the kernel instead of copied. `0` means never lend. A `--zero-copy-threshold` flag or `[tune] zero_copy_threshold` in the config file beats this. |
| `disable_http_cats` | any, read for truthiness | false | -  | When true, the error assets zip is never opened, and error pages have no picture. Process-wide: the first app with an opinion decides. |
| `max_body` | Integer | 1048576 (1 MiB) | 1073741824 (1 GiB) | The largest request body this application accepts. A larger declared `Content-Length` gets 413 before one byte of the body is read. Per application, not process-wide. Order of precedence: the resource's `def self.max_body`, then `conf.max_body`, then the default. |
| `spill_dir` | String, not empty | the platform's own (`TMPDIR`, then `/tmp`) | -  | The directory a request body spills into once it outgrows memory. Process-wide: the first app that names one decides. Naming a directory on the disk the uploads live on makes `request.body.save` a link instead of a copy. |

### conf.url

`conf.url` is parsed by ada (WHATWG URL). Scheme `http` gives a plain
listener, default port 80. Scheme `https` gives TLS, default port 443.
Scheme `unix` gives a socket path, percent-decoded. Any other scheme is
refused: `conf.url scheme <scheme> is not http, https or unix`. A
string that does not parse is refused: `conf.url = <u> is not
scheme://host[:port] or unix:///path`. Credentials in the URL are
refused. `unix://` with no path, or with only `/`, is refused with `conf.url
= <u> names no socket path`. `http://` with no host is refused with
`conf.url = <u> has no host`.

The query string may set: `docroot`, `spill_dir`, `assets`,
`certificate`, `private_key`, `file_map_threshold`,
`zero_copy_threshold`, `disable_http_cats`, `max_body`. Any other key is
refused: `conf.url: <key> is not a setting - a URL may name docroot,
assets, certificate, private_key, file_map_threshold,
zero_copy_threshold, disable_http_cats or max_body, and routes stay in
Ruby`. A setting named both by its own writer and in the URL query is
refused: `conf.url: <name> was already named`.

```ruby
app.conf.url = 'http://127.0.0.1:8080?docroot=%2Ftmp&file_map_threshold=65536'
```

## webmachine.toml.example

`webmachine.toml.example` is generated by `rake config_example`, which
runs the server's own `--write-config` and keeps the output verbatim.
Every setting is commented out; a comment shows its default. A flag on
the command line beats the config file; the config file beats the
app's own `conf`.

### [server]

| Key | Default | What it does |
| --- | --- | --- |
| `unix` | none | A unix socket to answer on, for a standalone server. At most one of `unix` and `port`. |
| `port` | none | A TCP port to answer on, for a standalone server. |
| `app` | none | The application to serve, as bytecode. |
| `assets` | none | Standalone: a pack, answered from one mapping. |
| `docroot` | none | Standalone: a directory of files. |
| `mime_types` | the machine's own | The media-type database. Without it: `/etc/mime.types`, then Apache's, then shared-mime-info, then the list compiled in. |
| `pidfile` | none (nowhere) | Where the pid goes; removed on the way out. |
| `error_assets` | the installed archive, or none | The error pages' pictures. Without it: the installed archive under `/usr/local/share/webmachine-mruby`, then under `/usr/share`; without either, the pages render without pictures. |

An application names its own pack and docroot in its own `conf`
(`conf.assets`, `conf.docroot`); `[server] app`, `assets` and `docroot`
are for a standalone server only, and are refused alongside `--app`.

### [log]

| Key | Default | What it does |
| --- | --- | --- |
| `file` | none | The access log. Opt-in; without it, nothing is written. |
| `privacy` | `anon` | What an address looks like in the access log: `none` writes no address, `anon` drops the host part, `full` keeps the address. |
| `error_file` | none | What a callback raised: its class, message, backtrace, the request that led there, and up to 4 KB of its body. That body content is whatever the app was sent, so the file's permissions matter. |
| `max_bytes` | 524288000 (500 MB) | The ceiling on the access log, in bytes. `0` is no ceiling. |

The access log and the error log are separate files, separate writers,
with no field in common.

### [tune]

Every `[tune]` value is a property of the machine, not of the site.

| Key | Default | What it does |
| --- | --- | --- |
| `backlog` | `SOMAXCONN` | `listen(2)`'s backlog. |
| `sq_entries` | 32768 | The io_uring submission queue size this ring asks the kernel for. Halved until the kernel agrees, so this is a wish, not a promise. |
| `zero_copy_threshold` | 131072 (128 KiB) | From this size up, a body is lent to the kernel instead of copied into the send buffer. `0` is "never lend". |
| `file_map_threshold` | 262144 (256 KiB) | From this size up, a file is mapped and handed to one send instead of read window by window. `0` is "never map". |
| `header_timeout` | 60 seconds | How long a client may take to finish sending a request head. Fractions allowed (`0.5`). |
| `send_timeout` | 60 seconds | How long a client may take to receive an answer this side wrote. |
| `idle_timeout` | 75 seconds | How long a client may take to send the next request on a kept connection. |

## Search order for the config file

Without `--config=FILE.toml`, the server looks for the file in this
order: `webmachine.toml` in the start directory, then
`/usr/local/etc/webmachine/webmachine.toml`, then
`/etc/webmachine/webmachine.toml`. It uses the first one it can read.

When the process runs as root, the file in the start directory is
skipped: naming bytecode to run as root from a directory somebody else
can write is a risk the server refuses by default. Root can still use
that file with an explicit `--config=webmachine.toml`.

## --write-config

`--write-config[=PATH]` writes the config file with its defaults
commented in, and stops; nothing is served. Without a path, it writes
to `webmachine.toml` in the start directory. `rake install[PREFIX]`
uses this to create `<PREFIX>/etc/webmachine/webmachine.toml` on a
fresh install, and keeps an existing file rather than overwrite it.

## Next

- [../tutorial.md](../tutorial.md)
- [request-and-response.md](request-and-response.md)
- [command-line.md](command-line.md)
