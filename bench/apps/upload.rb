# The body path, and nothing else: a resource that reads its request
# body and answers its size. A POST of kBodySpill or more takes the
# spill file, so this is the app that measures the write through the
# ring.
#
# The harness writes BENCH_LISTEN above this line before it compiles
# the file, the same as hello.rb.
LISTEN = defined?(BENCH_LISTEN) ? BENCH_LISTEN : { port: 8080 }

class Upload < Webmachine::Resource
  def self.allowed_methods
    %w[GET POST]
  end

  def process_post
    response.body = request.body.read.bytesize.to_s
    true
  end

  def self.to_html
    'upload'
  end
end

def main
  Webmachine::Application.new do |app|
    if LISTEN[:unix_path]
      app.conf.unix_path = LISTEN[:unix_path]
    else
      app.conf.port = LISTEN[:port]
    end
    app.conf.max_body = 8 * 1024 * 1024
    app.add_route [:*], Upload
  end
end
