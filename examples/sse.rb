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
