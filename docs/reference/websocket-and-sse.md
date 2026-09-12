# WebSocket and server-sent events reference

This page is for a developer who writes a `Webmachine::WebsocketResource`
or a `Webmachine::SseResource`. At the end, you know every callback
both classes answer, what each return value means, and where the
connection's limits come from.

Neither class is a `Webmachine::Resource`: a WebSocket or an event
stream has no status to negotiate and no representation to compare, so
neither runs the decision graph the [resource reference](resource.md)
describes. Routing them still goes through the application: `route.websocket`
and `route.sse` (or `app.add_websocket`/`app.add_sse`) name the class
against a set of path tokens, the same way `route.add` does - see the
[configuration reference](configuration.md).

## `Webmachine::WebsocketResource`

```ruby
class Echo < Webmachine::WebsocketResource
  def self.permessage_deflate?
    true
  end

  def initialize
    @seen = 0
  end

  def on_data(data, binary)
    return :close if data.chomp == 'bye'

    @seen += 1
    "#{@seen}: #{data}"
  end

  def on_close(code, reason)
    STDERR.puts "websocket closed: #{code} #{reason}"
    STDERR.flush
  end
end

def main
  Webmachine::Application.new do |app|
    app.add_websocket ['ws'], Echo
  end
end
```

### `initialize`

Runs once per connection, right after the handshake, and is the
connect hook - `request` is in scope here, so a resource can read the
handshake's headers or query before admitting the connection. Unlike
an ordinary `Webmachine::Resource`, a WebSocket resource keeps its own
`initialize`; nothing undefines it.

The return value decides whether the connection is admitted:

| `initialize` returns | Effect |
| --- | --- |
| a String | The connection is admitted, and the String is sent back as the chosen `Sec-WebSocket-Protocol` - it must be a single field-value token. |
| `:forbidden` | Refused, 403. |
| `:not_found` | Refused, 404. |
| `:bad_request` | Refused, 400. |
| any other Symbol | Refused, 403. |
| anything else (including `nil`) | Admitted, with no subprotocol chosen. |
| raises | Refused, 500; the error log carries the exception. |

### `on_data(data, binary)`

Required - a WebSocket resource with no `on_data` is refused when the
route is folded:

> `route.websocket: the resource defines no on_data - that is the one
> method a websocket resource is (on_data(data, binary))`

Called once per complete message. `data` is the message, already
unmasked and, when the peer negotiated it, already inflated. `binary`
is `true` for a binary message and `false` for text; a text message
that is not valid UTF-8 is refused before `on_data` is ever called (RFC
6455 5.6), with a 1007 close.

The return value decides what goes back to the peer:

| `on_data` returns | Effect |
| --- | --- |
| a String | Sent as one message, of the same kind (`binary` or `text`) as the one that arrived. |
| `nil` | Nothing sent. |
| `:close` or `:normal` | Close, code 1000. |
| `:going_away` | Close, code 1001. |
| `:protocol_error` | Close, code 1002. |
| `:unsupported` | Close, code 1003. |
| `:invalid` | Close, code 1007. |
| `:policy` | Close, code 1008. |
| `:too_big` | Close, code 1009. |
| `:internal_error` | Close, code 1011. |
| any other Symbol | Logged as a mistake, then closed with 1011. |
| anything else | Logged as a mistake, then closed with 1011. |
| raises | The connection is closed with 1011, and the exception is written to the error log. |

### `on_close(code, reason)`

Optional. Called at most once, however the connection ended - the
peer's own close frame, this end's own `:close` answer from `on_data`,
or a failure. `code` is the close code as an Integer, `reason` a
String (empty when none was sent).

### `permessage_deflate?`

A class method, asked once while the route is folded. `true` offers
RFC 7692 per-message compression during the handshake; the default is
not to offer it. Whether compression is actually used on a given
connection is what the handshake negotiates, not a further choice this
callback makes.

### `validate_text?`

A class method, asked once while the route is folded. `false` turns
off the UTF-8 validation RFC 6455 5.6 asks for on a text message; the
default is `true`.

### `max_message`

A class method, asked once while the route is folded. The largest
message, in bytes, this resource accepts - after inflation, when
compression is in use. The default is 65536 (64 KiB). Answering
anything but a positive Integer is refused:

> `route.websocket: max_message answers with a positive Integer of
> bytes, or it is not defined at all (the default is 65536) - not %v`

A message that would grow past this limit closes the connection with
1009 before `on_data` sees any of it.

## `Webmachine::SseResource`

```ruby
class Ticker < Webmachine::SseResource
  def self.heartbeat
    15.s
  end

  def initialize
    @n = request.headers['last-event-id'].to_i
  end

  def on_tick
    @n += 1
    { event: 'tick', id: @n.to_s, data: @n.to_s }
  end
end

def main
  Webmachine::Application.new do |app|
    app.add_sse ['events'], Ticker
  end
end
```

### `initialize`

Runs once per connection and is the open hook, with `request` in
scope - the example above reads `Last-Event-ID` so a reconnecting
client picks up where it left off. The return value decides whether
the stream opens:

| `initialize` returns | Effect |
| --- | --- |
| `:not_found` | Refused, 404. |
| `:bad_request` | Refused, 400. |
| any other Symbol | Refused, 403. |
| anything else (including `nil`) | The stream opens. |
| raises | Refused, 500; the error log carries the exception. |

### `on_tick`

Required - an SSE resource with no `on_tick` is refused when the route
is folded:

> `route.sse: the resource defines no on_tick - that is the one method
> an SSE resource is, asked once a second for what it has to say`

Called once a second for the life of the connection. What it returns
becomes the event or events sent that second:

| `on_tick` returns | Effect |
| --- | --- |
| a String | One event whose `data:` is the String. |
| a Hash | One event; see the fields below. |
| an Array of Strings and/or Hashes | Each element becomes its own event, in order. |
| `nil` or `false` | Nothing sent this second (a heartbeat comment may be sent instead - see below). |
| `:close` | The stream ends. |
| any other Symbol, or an Array holding something that is not a String or a Hash | Logged as a mistake; treated as `:close`. |

A Hash may carry:

- `:event` - the event name (the `event:` line).
- `:id` - the event id (the `id:` line), sent back by the client as
  `Last-Event-ID` on reconnect.
- `:retry` - an Integer number of milliseconds (the `retry:` line).
- `:data` - a String, sent as one `data:` line, or an Array of
  Strings, each sent as its own `data:` line - a multi-line event.

A value with an embedded newline is split into one field line per
line, so a multi-line String in `:data` arrives to the client as
several `data:` lines rather than one line with an embedded newline
inside it, which no client would parse as intended.

### `on_close`

Optional. Called at most once, when the stream ends, however it
ended.

### `heartbeat`

A class method, asked once while the route is folded. A duration (see
the [waiting reference](waiting.md#duration-helpers) for `15.s` and
its siblings) from 0 (never) up to one day; the default is 15 seconds.
When a second passes with nothing sent - `on_tick` returned `nil` or
`false` - and at least this many seconds have passed since the last
byte went out, the server sends a comment line (`:` followed by a
blank line) so a proxy in the middle keeps seeing traffic on the
connection. Answering a duration outside that range is refused:

> `route.sse: heartbeat is a duration from 0 (never) to a day - 15.s is
> the default, %v is not in range`

## Next

- [Waiting](waiting.md)
- [Resource callbacks](resource.md)
- [Configuration](configuration.md)
- [One thread, and the work off it](../explanation/one-thread.md)
