# The instance-based Application (#116, slice 1): an app file defines
# `main`, `Webmachine::Application.new { |app| ... }` registers one
# application, and its routes decide who answers. The constant scan is
# gone - a resource class reaches the wire only through route.add.
#
# What is proven here: the token forms on the wire (literal, symbol,
# splat), first-registration-wins, the router's 404 BEFORE B13, two
# resources on two routes, and every named refusal this slice owes.

require 'socket'
require 'tempfile'

AP_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(AP_BIN)

def ap_compile(app_source)
  src = Tempfile.new(['wm-apapp', '.rb'])
  src.write(app_source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-apapp', '.mrb'])
  mrb.close
  ok = system(mrbc, '-o', mrb.path, src.path)
  raise "mrbc failed to compile:\n#{app_source}" unless ok
  mrb
ensure
  src&.unlink
end

def ap_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def ap_read(s)
  head = +''
  head << ap_recv(s) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''
  body << ap_recv(s, len - body.bytesize) while body.bytesize < len
  [head, body]
end

# Runs a server on the app source. `args` lets a case decide whether
# --unix overrides the app's own conf or not.
def ap_server(app_source, sock: nil, args: nil)
  app = ap_compile(app_source)
  sock ||= "/tmp/wm-ap-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  args ||= ['--unix', sock]
  out = "/tmp/wm-ap-stdout-#{$$}.log"
  err = "/tmp/wm-ap-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, *args, '--app', app.path, out: out, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock, out, err
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

# Starts a server that MUST refuse; returns its stderr for the reason.
def ap_refused(app_source)
  app = ap_compile(app_source)
  err = "/tmp/wm-ap-refuse-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, '--unix', "/tmp/wm-ap-refuse-#{$$}.sock",
              '--app', app.path, out: File::NULL, err: err)
  Process.wait(pid)
  raise 'server came up but must have refused' if $?.exitstatus == 0
  File.read(err)
ensure
  app.unlink
end

# The user's own sketch, verbatim in shape: a literal, a binding and a
# splat tail on one route.
AP_FIZZ = <<~RUBY unless defined?(AP_FIZZ)
  class MyResource < Webmachine::Resource
    def self.to_html
      '<html><body>fizzbuzz</body></html>'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.configure do |conf|
        conf.port = 8080
      end
      app.routes do |route|
        route.add ['fizz', :buzz, :*], MyResource
      end
      app.ready do
        puts 'ready'
      end
    end
  end
RUBY

assert('application: literal, binding and splat match on the wire; a miss is 404') do
  ap_server(AP_FIZZ) do |sock|
    UNIXSocket.open(sock) do |s|
      # literal + binding, splat empty
      s.write("GET /fizz/one HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = ap_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_equal '<html><body>fizzbuzz</body></html>', body
      # splat carrying a tail of several segments
      s.write("GET /fizz/one/two/three HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = ap_read(s)
      assert_true head2.start_with?('HTTP/1.1 200'), head2.lines.first.to_s
      # the query is not part of the path (RFC 9110 4.2.1)
      s.write("GET /fizz/one?v=1 HTTP/1.1\r\nHost: x\r\n\r\n")
      head3, = ap_read(s)
      assert_true head3.start_with?('HTTP/1.1 200'), head3.lines.first.to_s
      # the literal has to match, and the binding needs a segment
      s.write("GET /buzz/one HTTP/1.1\r\nHost: x\r\n\r\n")
      head4, = ap_read(s)
      assert_true head4.start_with?('HTTP/1.1 404'), head4.lines.first.to_s
      s.write("GET /fizz HTTP/1.1\r\nHost: x\r\n\r\n")
      head5, = ap_read(s)
      assert_true head5.start_with?('HTTP/1.1 404'), head5.lines.first.to_s
    end
  end
end

assert('application: a router miss is 404 BEFORE B13 - POST on an unknown path is not 405') do
  # The whole point of routing before the flow: the method is never
  # tested on a path no resource claims.
  ap_server(AP_FIZZ) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("POST /nowhere HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head, = ap_read(s)
      assert_true head.start_with?('HTTP/1.1 404'), head.lines.first.to_s
      assert_false head.match?(/^Allow:/i), head
      # ... while POST on a path that IS routed still speaks B10's 405.
      s.write("POST /fizz/one HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head2, = ap_read(s)
      assert_true head2.start_with?('HTTP/1.1 405'), head2.lines.first.to_s
      assert_true head2.match?(/^Allow: GET, HEAD\r$/i), head2
    end
  end
end

assert('application: the FIRST matching route wins, in registration order') do
  src = <<~RUBY
    class First < Webmachine::Resource
      def self.to_html
        'first'
      end
    end
    class Second < Webmachine::Resource
      def self.to_html
        'second'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['a', :*], First
          route.add ['a', 'b'], Second
        end
      end
    end
  RUBY
  ap_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /a/b HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body = ap_read(s)
      assert_equal 'first', body
    end
  end
end

assert('application: two resources on two routes keep their own body and Allow') do
  src = <<~RUBY
    class Narrow < Webmachine::Resource
      def self.to_html
        'narrow'
      end
    end
    class Wide < Webmachine::Resource
      def self.allowed_methods
        'GET HEAD POST'
      end
      def self.content_type
        'text/plain'
      end
      def self.to_html
        'wide'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['narrow'], Narrow
          route.add ['wide'], Wide
        end
      end
    end
  RUBY
  ap_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /narrow HTTP/1.1\r\nHost: x\r\n\r\n")
      h1, b1 = ap_read(s)
      assert_equal 'narrow', b1
      assert_true h1.match?(%r{^Content-Type: text/html; charset=utf-8\r$}i), h1
      s.write("GET /wide HTTP/1.1\r\nHost: x\r\n\r\n")
      h2, b2 = ap_read(s)
      assert_equal 'wide', b2
      assert_true h2.match?(%r{^Content-Type: text/plain; charset=utf-8\r$}i), h2
      # Each route's 405 names ITS OWN resource's list.
      s.write("PUT /narrow HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
      h3, = ap_read(s)
      assert_true h3.start_with?('HTTP/1.1 405'), h3.lines.first.to_s
      assert_true h3.match?(/^Allow: GET, HEAD\r$/i), h3
      s.write("PUT /wide HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
      h4, = ap_read(s)
      assert_true h4.start_with?('HTTP/1.1 405'), h4.lines.first.to_s
      assert_true h4.match?(/^Allow: GET, HEAD, POST\r$/i), h4
      # POST is allowed on one and not the other, on the same connection.
      s.write("POST /wide HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
      h5, = ap_read(s)
      assert_true h5.start_with?('HTTP/1.1 200'), h5.lines.first.to_s
    end
  end
end

assert('application: the empty token list is the root route') do
  src = <<~RUBY
    class Root < Webmachine::Resource
      def self.to_html
        'root'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add [], Root
        end
      end
    end
  RUBY
  ap_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = ap_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_equal 'root', body
      s.write("GET /deeper HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = ap_read(s)
      assert_true head2.start_with?('HTTP/1.1 404'), head2.lines.first.to_s
    end
  end
end

assert('application: ready runs exactly once, AFTER the bind, and reads back the real url') do
  sock = "/tmp/wm-ap-ready-#{$$}.sock"
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'ok'
      end
    end

    def main
      seen = nil
      Webmachine::Application.new do |app|
        app.configure do |conf|
          conf.port = 8080
          seen = conf
        end
        app.routes do |route|
          route.add [:*], R
        end
        app.ready do
          # conf.url reads BOTH ways: this runs after the bind, so it
          # spells where the listener really is - which is --unix here,
          # not the port the app asked for.
          puts "ready \#{seen.url}"
        end
      end
    end
  RUBY
  ap_server(src, sock: sock) do |s, out|
    UNIXSocket.open(s) do |c|
      5.times do
        c.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        ap_read(c)
      end
    end
    text = File.read(out)
    assert_equal 1, text.scan(/^ready /).size, text
    assert_true text.include?("ready unix://#{sock}"), text
  end
end

assert('application: config is the same method as configure') do
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'aliased'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.config do |conf|
          conf.port = 8080
        end
        app.routes do |route|
          route.add [:*], R
        end
      end
    end
  RUBY
  ap_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body = ap_read(s)
      assert_equal 'aliased', body
    end
  end
end

assert('application: add_route on the app itself is route.add (webmachine-ruby spelling)') do
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'direct'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.add_route ['direct'], R
      end
    end
  RUBY
  ap_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /direct HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body = ap_read(s)
      assert_equal 'direct', body
    end
  end
end

assert('application: conf.adapter is accepted and ignored - a webmachine-ruby file runs') do
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'adapted'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.configure do |conf|
          conf.port = 8080
          conf.adapter = :Webrick
        end
        app.routes do |route|
          route.add [:*], R
        end
      end
    end
  RUBY
  ap_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body = ap_read(s)
      assert_equal 'adapted', body
    end
  end
end

assert('application: conf.url names the listener when nothing overrides it') do
  # No --unix, no --port: the app's own conf.url is the listener. The
  # port is high and picked here, not by the OS - conf.port = 0 refuses
  # (see below), so a test that binds names its own number.
  port = 20000 + rand(40000)
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'urled'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.configure do |conf|
          conf.url = 'http://127.0.0.1:#{port}'
        end
        app.routes do |route|
          route.add [:*], R
        end
      end
    end
  RUBY
  app = ap_compile(src)
  err = "/tmp/wm-ap-url-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, '--app', app.path, out: File::NULL, err: err)
  begin
    up = false
    50.times do
      begin
        TCPSocket.open('127.0.0.1', port).close
        up = true
        break
      rescue Errno::ECONNREFUSED, Errno::EADDRNOTAVAIL
        break unless Process.wait(pid, Process::WNOHANG).nil?
        sleep 0.05
      end
    end
    raise "no listener on #{port}:\n#{File.read(err) rescue ''}" unless up
    TCPSocket.open('127.0.0.1', port) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body = ap_read(s)
      assert_equal 'urled', body
    end
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    app.unlink
  end
end

# --- the named refusals ------------------------------------------------

def ap_one_route(body)
  <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'x'
      end
    end

    def main
      Webmachine::Application.new do |app|
        #{body}
      end
    end
  RUBY
end

assert('application: :* anywhere but the tail refuses by name') do
  out = ap_refused(ap_one_route("app.add_route [:*, 'tail'], R"))
  assert_true out.include?(':*'), out
  assert_true out.include?('tail of a route'), out
end

assert('application: port and unix_path together refuse by name') do
  out = ap_refused(ap_one_route(<<~BODY))
    app.configure do |conf|
      conf.port = 8080
      conf.unix_path = '/tmp/wm-never.sock'
    end
    app.add_route [:*], R
  BODY
  assert_true out.include?('exactly one of port, unix_path or url'), out
end

assert('application: conf.port = 0 refuses by name and points at slice 2') do
  out = ap_refused(ap_one_route(<<~BODY))
    app.configure do |conf|
      conf.port = 0
    end
    app.add_route [:*], R
  BODY
  assert_true out.include?('getsockname'), out
  assert_true out.include?('slice 2'), out
end

assert('application: the ssl/certificate names refuse by name - no TLS in this tree') do
  %w[ssl ssl_options certificate certificate_key].each do |name|
    out = ap_refused(ap_one_route(<<~BODY))
      app.configure do |conf|
        conf.port = 8080
        conf.#{name} = 'whatever'
      end
      app.add_route [:*], R
    BODY
    assert_true out.include?('no TLS in this tree'), "#{name}: #{out}"
    assert_true out.include?('#110'), "#{name}: #{out}"
  end
end

assert('application: an https url refuses with the same TLS reason') do
  out = ap_refused(ap_one_route(<<~BODY))
    app.configure do |conf|
      conf.url = 'https://example.com'
    end
    app.add_route [:*], R
  BODY
  assert_true out.include?('no TLS in this tree'), out
end

assert('application: websocket, sse and assets are reserved and refuse by name') do
  ws = ap_refused(ap_one_route("app.routes { |route| route.websocket ['ws'], R }"))
  assert_true ws.include?('#175'), ws
  sse = ap_refused(ap_one_route("app.routes { |route| route.sse ['sse'], R }"))
  assert_true sse.include?('#102'), sse
  assets = ap_refused(ap_one_route("app.routes { |route| route.assets '/static' }"))
  assert_true assets.include?('#170'), assets
  assert_true assets.include?('--assets'), assets
end

assert('application: two applications on the same listener refuse by name') do
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'x'
      end
    end

    def main
      2.times do
        Webmachine::Application.new do |app|
          app.configure do |conf|
            conf.port = 8080
          end
          app.add_route [:*], R
        end
      end
    end
  RUBY
  out = ap_refused(src)
  assert_true out.include?('same listener'), out
end

assert('application: two applications at all refuse, pointing at slice 2') do
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'x'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.configure { |conf| conf.port = 8080 }
        app.add_route [:*], R
      end
      Webmachine::Application.new do |app|
        app.configure { |conf| conf.port = 8081 }
        app.add_route [:*], R
      end
    end
  RUBY
  out = ap_refused(src)
  assert_true out.include?('slice 2'), out
end

assert('application: new WITHOUT a block builds nothing anybody serves') do
  # Legal, and inert: registration is what returning from the block
  # means. With no registered app the start refuses by name.
  out = ap_refused("def main\n  Webmachine::Application.new\nend\n")
  assert_true out.include?('registered no application'), out
end

assert('application: route.add refuses a class that is not a Webmachine::Resource') do
  src = <<~RUBY
    class NotAResource; end

    def main
      Webmachine::Application.new do |app|
        app.add_route [:*], NotAResource
      end
    end
  RUBY
  out = ap_refused(src)
  assert_true out.include?('Webmachine::Resource'), out
end

assert('application: route.add refuses a token that is neither String nor Symbol') do
  out = ap_refused(ap_one_route('app.add_route [1], R'))
  assert_true out.include?('String (literal)'), out
end
