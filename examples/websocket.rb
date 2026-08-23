# A websocket, and the command that drives it:
#
#   mrbc -o websocket.mrb examples/websocket.rb
#   webmachine-server --app websocket.mrb
#   websocat ws://127.0.0.1:8080/ws     # type a line, it comes back
#
# websocat (https://github.com/vi/websocat), not curl: curl's CLI can
# only RECEIVE websocket frames - its src/ carries no send path at all,
# so what you type into `curl ws://...` never leaves the terminal. curl
# is still good for the handshake:
#
#   curl -i --http1.1 -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
#        -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
#        -H 'Sec-WebSocket-Version: 13' http://127.0.0.1:8080/ws
#
# which must answer 101 with Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
#
# A websocket resource is NOT a Webmachine::Resource: no response, no
# status, no flow survives the upgrade. It is instantiated once and
# then fed. What on_data RETURNS is the whole protocol - a String is a
# message back in the same kind that arrived, a Symbol is a close by
# name (:close, :going_away, :protocol_error, :unsupported, :invalid,
# :policy, :too_big, :internal_error), nil says nothing.
class Echo < Webmachine::WebsocketResource
  # permessage-deflate (RFC 7692), which every browser offers and this
  # tree accepts only where a route asks for it. It costs about 296 KiB
  # of zlib per compressing peer, so the default is off and saying yes
  # is one line - here, because a browser talking to this example
  # should get what it asked for. There is nothing else to do: on_data
  # still gets the message whole and decompressed, and a client that
  # does not offer the extension is served exactly as before.
  def self.permessage_deflate?
    true
  end

  def on_data(data, binary)
    # chomp: a line typed into websocat arrives WITH its newline, and a
    # message is bytes - nothing strips anything for you here.
    return :close if data.chomp == 'bye'

    data
  end

  def on_close(code, reason)
    STDERR.puts "websocket closed: #{code} #{reason}"
    STDERR.flush
  end
end

# The same path over plain HTTP is a normal request and answers here:
# websocket routes are their own table.
class Page < Webmachine::Resource
  def self.to_html
    '<html><body>curl ws://127.0.0.1:8080/ws</body></html>'
  end
end

def main
  Webmachine::Application.new do |app|
    app.configure do |conf|
      conf.port = 8080
    end
    app.routes do |route|
      route.websocket ['ws'], Echo
      route.add [:*], Page
    end
  end
end
