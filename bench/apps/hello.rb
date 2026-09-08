# The harness writes BENCH_LISTEN above this line before it compiles the
# file. The server refuses --unix and --port beside --app, because an
# application names its own listener in its conf.
LISTEN = defined?(BENCH_LISTEN) ? BENCH_LISTEN : { port: 8080 }

class HelloWorld < Webmachine::Resource
  def self.to_html
    '<html><body>Hello, World!</body></html>'
  end
end

def main
  Webmachine::Application.new do |app|
    if LISTEN[:unix_path]
      app.conf.unix_path = LISTEN[:unix_path]
    else
      app.conf.port = LISTEN[:port]
    end
    app.add_route [], HelloWorld
  end
end
