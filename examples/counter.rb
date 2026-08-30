class Counter < Webmachine::Resource
  HITS = [0]

  def to_html
    HITS[0] += 1
    "<html><body>hit #{HITS[0]}</body></html>"
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [], Counter
  end
end
