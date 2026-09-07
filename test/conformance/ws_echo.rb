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
    app.conf.port = 9977
    app.routes do |route|
      route.websocket ['echo'], AutobahnEcho
    end
  end
end
