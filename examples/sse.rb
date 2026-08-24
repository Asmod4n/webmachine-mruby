# Server-sent events, and the command that drives it:
#
#   mrbc -o sse.mrb examples/sse.rb
#   webmachine-server --app sse.mrb
#   curl -N http://127.0.0.1:8080/events
#
# curl -N, because without it curl buffers a stream that never ends and
# you see nothing. A browser says `new EventSource('/events')`.
#
# An SSE resource is NOT a Webmachine::Resource: there is nothing for
# the flow to decide - the media type is fixed, there is no
# representation to compare and no length to declare. It is
# instantiated ONCE PER STREAM, like a websocket resource and for the
# same reason (#181): a stream is a session, so `initialize` is the
# open hook and ivars live as long as the connection does.
#
# The difference from every other tier here: this one produces on ITS
# OWN schedule. on_tick is asked once a second - the reactor's own
# second, which it already wakes on for the timeout clocks - and what
# it RETURNS is the whole protocol: nil says nothing this second, a
# String is one event's data, a Hash names the fields, an Array sends
# several, :close ends the stream.
class Clock < Webmachine::SseResource
  # How long this stream may stay silent before the server sends a
  # bare comment, which the spec defines as ignorable. It exists for
  # the proxies in between, which cannot tell a quiet stream from a
  # dead one. A duration, through mruby-chrono like every other one
  # that crosses this boundary; 0 turns it off.
  def self.heartbeat
    10.s
  end

  def initialize
    @n = 0
    # The head that asked is live here: a client reconnecting after a
    # drop sends back the last id it saw, and a real stream would
    # resume from it.
    @from = request.headers['last-event-id'].to_i
  end

  def on_tick
    @n += 1
    return :close if @n > 20

    # Every third second says nothing at all - which is what a stream
    # mostly does, and it costs one method call.
    return nil if @n % 3 != 0

    { event: 'tick', id: (@from + @n).to_s, data: "second #{@n}" }
  end

  def on_close
    STDERR.puts "stream closed after #{@n} seconds"
    STDERR.flush
  end
end

# The same server answers ordinary requests: event-stream routes are
# their own table, matched before the flow or not at all.
class Page < Webmachine::Resource
  def self.to_html
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
