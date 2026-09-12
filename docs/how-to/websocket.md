# Add a WebSocket endpoint

This how-to is for a developer who needs a WebSocket endpoint beside
their ordinary resources. At the end, you have one that echoes what it
is sent and closes on a word.

## Write the resource

A WebSocket resource is a `Webmachine::WebsocketResource`, routed with
`add_websocket` instead of `add_route`:

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

class Page < Webmachine::Resource
  def self.to_html
    '<html><body>curl ws://127.0.0.1:8080/ws</body></html>'
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_websocket ['ws'], Echo
    app.add_route [:*], Page
  end
end
```

`initialize` runs once, when the socket opens, for that connection's
own state - `@seen` here is one counter per connection, not one for
the whole server. `on_data(data, binary)` runs for every complete
message the client sends; `binary` says whether it arrived as a
binary message. A String answer is sent back as one message, binary
or text to match what arrived; `nil` says nothing back; a Symbol named
after a close reason (`:close`, `:going_away`, `:protocol_error`, and
the others RFC 6455 7.4.1 names) ends the connection with that code.
`on_close(code, reason)` runs once, when the connection ends, for
cleanup.

`permessage_deflate?` answers whether this resource offers RFC 7692
compression during the handshake; `true` here does.

## Try it

    mrbc -g -o app.mrb app.rb
    webmachine-server --app=app.mrb

Then, from another terminal:

    curl -i http://127.0.0.1:8080/

opens the page, which names the endpoint; a WebSocket client connects
to `ws://127.0.0.1:8080/ws` and gets back `1: <what it sent>`,
`2: <what it sent>`, and so on, until it sends `bye`.

## Next

- [server-sent-events.md](server-sent-events.md)
- [../reference/websocket-and-sse.md](../reference/websocket-and-sse.md)
