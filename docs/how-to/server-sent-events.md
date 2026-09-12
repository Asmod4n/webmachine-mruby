# Send server-sent events

This how-to is for a developer who needs a one-way event stream. At
the end, you have a route that ticks once a second and a page that
reads it.

## Write the resource

A server-sent events resource is a `Webmachine::SseResource`, routed
with `add_sse`:

```ruby
class Clock < Webmachine::SseResource
  def self.heartbeat
    10.s
  end

  def initialize
    @n = 0
    @from = request.headers['last-event-id'].to_i
  end

  def on_tick
    @n += 1
    return :close if @n > 20

    return nil if @n % 3 != 0

    { event: 'tick', id: (@from + @n).to_s, data: "second #{@n}" }
  end

  def on_close
    STDERR.puts "stream closed after #{@n} seconds"
    STDERR.flush
  end
end

class Page < Webmachine::Resource
  def to_html
    '<html><body><script>' \
      "new EventSource('/events').addEventListener('tick', e => " \
      'document.body.append(e.data, document.createElement("br")))' \
      '</script></body></html>'
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_sse ['events'], Clock
    app.add_route [:*], Page
  end
end
```

`on_tick` is required; a class without it is refused at start. It runs
once a second by default, and `heartbeat` sets that instead, as a
duration from 0 (never) up to a day. `initialize` runs once, when the
stream opens; `request.headers['last-event-id']` reads back the id a
reconnecting browser sent, so a stream can pick up where it left off.

`on_tick` answers a Hash (`:event`, `:id`, `:data`), a String (sent as
a bare `data:` line), an Array of either, `nil` (say nothing this
tick), or `:close`. Between ticks with nothing to say, the server
writes a comment line by itself, so a proxy in the middle keeps seeing
traffic; `heartbeat` also names how often that filler line goes out.
`on_close` runs once, when the stream ends.

## Try it

    mrbc -g -o app.mrb app.rb
    webmachine-server --app=app.mrb

Then:

    curl -N http://127.0.0.1:8080/events

streams `event: tick` lines, one every three seconds, until the
twenty-first tick closes the connection. `curl -i http://127.0.0.1:8080/`
gets the page that opens the same stream from a browser.

## Next

- [websocket.md](websocket.md)
- [../reference/websocket-and-sse.md](../reference/websocket-and-sse.md)
