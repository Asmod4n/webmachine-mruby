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
