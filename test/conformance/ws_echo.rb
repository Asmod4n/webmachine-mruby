# The fixture Autobahn's fuzzingclient talks to (tools/conformance.sh
# ws). NOT examples/websocket.rb: the example is documentation and
# keeps the tree's defaults, while the oracle needs the three konst
# answers its own cases assume - a 16 MiB message ceiling (9.x sends
# messages up to 16 MiB and reads a 1009 close as a failure), text
# validation left ON, which is what 6.x exists to measure, and
# permessage-deflate ON, without which 12.x and 13.x have nothing to
# measure at all. The tree's default for that last one is OFF and
# stays off (wsconn.hpp does the arithmetic: ~296 KiB of zlib per
# compressing peer); a route says yes to it, and here one does.
#
# Everything else is one method: what arrived goes back, in the kind it
# arrived in. That is Autobahn's whole contract with an echo server.
class AutobahnEcho < Webmachine::WebsocketResource
  def self.max_message
    16 * 1024 * 1024
  end

  def self.validate_text?
    true
  end

  def self.permessage_deflate?
    true
  end

  def on_data(data, binary)
    data
  end
end

def main
  Webmachine::Application.new do |app|
    app.routes do |route|
      route.websocket ['echo'], AutobahnEcho
    end
  end
end
