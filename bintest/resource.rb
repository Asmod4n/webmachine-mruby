# Resources on the wire: a Ruby class inheriting Webmachine::Resource
# is asked ONCE at setup; the requests that follow never enter the VM.
# What a later tier must honor refuses the start by name, never silently.

require 'socket'
require 'tempfile'

RES_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(RES_BIN)

# Runs a server bound to the given app source; raises if it never comes up.
def resource_server(app_source)
  app = Tempfile.new(['wm-app', '.rb'])
  app.write(app_source)
  app.close
  sock = "/tmp/wm-res-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-res-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, RES_BIN, '--unix', sock, '--app', app.path,
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

# Starts a server that MUST refuse; returns its stderr for the reason.
def resource_refused(app_source)
  app = Tempfile.new(['wm-app', '.rb'])
  app.write(app_source)
  app.close
  err = "/tmp/wm-res-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, RES_BIN, '--unix', "/tmp/wm-res-#{$$}.sock",
              '--app', app.path, out: File::NULL, err: err)
  Process.wait(pid)
  raise 'server came up but must have refused' if $?.exitstatus == 0
  File.read(err)
ensure
  app.unlink
end

def resource_read(s)
  head = +''
  head << s.readpartial(1) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''
  body << s.readpartial(len - body.bytesize) while body.bytesize < len
  [head, body]
end

assert('resource: hello world serves its rendered body, typed, VM silent') do
  resource_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(%r{^Content-Type: text/html\r$}i)
      assert_equal '<html><body>Hello, World!</body></html>', body
      # HEAD: the same head, Content-Length announced, no body bytes -
      # the pipelined GET's response must begin immediately after.
      s.write("HEAD / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
      hh = +''
      hh << s.readpartial(1) until hh.end_with?("\r\n\r\n")
      assert_true hh.match?(/^Content-Length: 39\r$/i)
      nxt = +''
      nxt << s.readpartial(1) until nxt.end_with?("\r\n\r\n")
      assert_true nxt.start_with?('HTTP/1.1 200 OK'), "HEAD leaked body bytes: #{nxt.inspect}"
      len = nxt[/^Content-Length: *(\d+)\r$/i, 1].to_i
      drain = +''
      drain << s.readpartial(len - drain.bytesize) while drain.bytesize < len
      # POST is outside the default allowed_methods: 405 from B10.
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head3, = resource_read(s)
      assert_true head3.start_with?('HTTP/1.1 405')
    end
  end
end

assert('resource: allowed_methods widens and the flow obeys, Allow speaks the list') do
  src = <<~RUBY
    class WideResource < Webmachine::Resource
      def self.allowed_methods
        %w[GET HEAD POST DELETE]
      end
      def self.delete_resource
        true
      end
      def self.delete_completed?
        true
      end
    end
  RUBY
  resource_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head, = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), "POST expected 200, got #{head.lines.first}"
      s.write("DELETE / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = resource_read(s)
      assert_true head2.start_with?('HTTP/1.1 200'), "DELETE expected 200, got #{head2.lines.first}"
      s.write("PUT / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head3, = resource_read(s)
      assert_true head3.start_with?('HTTP/1.1 405')
      assert_true head3.match?(/^Allow: GET, HEAD, POST, DELETE\r$/i)
    end
  end
end

assert('resource: service_available? false turns every request into 503 (B13)') do
  src = <<~RUBY
    class DownResource < Webmachine::Resource
      def self.service_available?
        false
      end
    end
  RUBY
  resource_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 503')
    end
  end
end

assert('resource: a missing resource speaks 404/412 like the graph says') do
  src = <<~RUBY
    class GhostResource < Webmachine::Resource
      def self.resource_exists?
        false
      end
    end
  RUBY
  resource_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 404')  # G7 -> H7 -> I7 -> K7 -> L7
      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-Match: *\r\n\r\n")
      head2, = resource_read(s)
      assert_true head2.start_with?('HTTP/1.1 412')  # H7: If-Match * on missing
    end
  end
end

assert('resource: later-tier callbacks refuse the start by name') do
  src = <<~RUBY
    class EtagResource < Webmachine::Resource
      def self.generate_etag
        'v1'
      end
    end
  RUBY
  assert_true resource_refused(src).include?('generate_etag')
end

assert('resource: an instance body renders per request through the VM') do
  src = File.read(File.expand_path('../examples/counter.rb', __dir__))
  resource_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body1 = resource_read(s)
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body2 = resource_read(s)
      assert_equal '<html><body>hit 1</body></html>', body1
      assert_equal '<html><body>hit 2</body></html>', body2
      # HEAD announces the NEXT render's length and sends no bytes; the
      # pipelined GET must begin right after the head.
      s.write("HEAD / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
      hh = +''
      hh << s.readpartial(1) until hh.end_with?("\r\n\r\n")
      assert_true hh.match?(/^Content-Length: 31\r$/i), hh
      nxt, body4 = resource_read(s)
      assert_true nxt.start_with?('HTTP/1.1 200 OK'), "HEAD leaked body bytes: #{nxt.inspect}"
      assert_equal '<html><body>hit 4</body></html>', body4
    end
  end
end

assert('resource: an instance decision is asked per request (state changes answers)') do
  src = <<~RUBY
    class Flaky < Webmachine::Resource
      def initialize
        @n = 0
      end
      def resource_exists?
        (@n += 1).odd?
      end
    end
  RUBY
  resource_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head1, = resource_read(s)
      assert_true head1.start_with?('HTTP/1.1 200')
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = resource_read(s)
      assert_true head2.start_with?('HTTP/1.1 404')
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head3, = resource_read(s)
      assert_true head3.start_with?('HTTP/1.1 200')
    end
  end
end

assert('resource: a raising runtime callback is 500, the process survives') do
  src = <<~RUBY
    class Boom < Webmachine::Resource
      def to_html
        raise 'boom'
      end
    end
  RUBY
  resource_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 500')
    end
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 500')  # still answering, still alive
    end
  end
end

assert('resource: an app that raises at load refuses the start with the error') do
  assert_true resource_refused("raise 'kaputt'").include?('kaputt')
end

assert('resource: an app without a Webmachine::Resource subclass is refused') do
  assert_true resource_refused('class Quiet; end').include?('Webmachine::Resource')
end
