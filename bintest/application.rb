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

assert('application: conf.port = 0 refuses by name - no backend answers it') do
  out = ap_refused(ap_one_route(<<~BODY))
    app.configure do |conf|
      conf.port = 0
    end
    app.add_route [:*], R
  BODY
  assert_true out.include?('getsockname'), out
  # SETTLED in slice 2: the bridge exists but not in every backend
  # this tree builds against (#171), so port 0 stays refused.
  assert_true out.include?('#171'), out
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

# SLICE 2 (#116): several applications, one ring. Each app names its
# own listener, the ring binds them all, and the listener a connection
# arrived on is what decides whose routes answer it - which is exactly
# what this proves, on the wire, with two apps whose routes overlap in
# name and differ in body.
assert('application: two applications, two listeners, one ring - each answers its own') do
  a = "/tmp/wm-ap-a-#{$$}.sock"
  b = "/tmp/wm-ap-b-#{$$}.sock"
  [a, b].each { |p| File.unlink(p) if File.exist?(p) }
  src = <<~RUBY
    class A < Webmachine::Resource
      def self.to_html
        'from-a'
      end
    end

    class B < Webmachine::Resource
      def self.to_html
        'from-b'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.configure { |conf| conf.unix_path = '#{a}' }
        app.routes do |route|
          route.add ['only-a'], A
        end
      end
      Webmachine::Application.new do |app|
        app.configure { |conf| conf.unix_path = '#{b}' }
        app.routes do |route|
          route.add ['only-b'], B
        end
      end
    end
  RUBY
  app = ap_compile(src)
  err = "/tmp/wm-ap-two-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, '--app', app.path, out: File::NULL, err: err)
  begin
    100.times { break if File.socket?(a) && File.socket?(b); sleep 0.05 }
    assert_true File.socket?(a) && File.socket?(b), (File.read(err) rescue '')

    # Each app's own route answers on its own socket...
    { a => 'from-a', b => 'from-b' }.each do |sock, body|
      s = UNIXSocket.new(sock)
      path = body == 'from-a' ? '/only-a' : '/only-b'
      s.write("GET #{path} HTTP/1.1\r\nHost: x\r\n\r\n")
      head, got = ap_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head
      assert_equal body, got
      s.close
    end

    # ...and the OTHER app's route is a plain miss there: the tables
    # never blend, the listener index is the whole of "whose app".
    { a => '/only-b', b => '/only-a' }.each do |sock, path|
      s = UNIXSocket.new(sock)
      s.write("GET #{path} HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = ap_read(s)
      assert_true head.start_with?('HTTP/1.1 404'), head
      s.close
    end
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    [a, b].each { |p| File.unlink(p) rescue nil }
    app.unlink
  end
end

assert('application: --unix cannot speak for a file with several apps') do
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
  assert_true out.include?('names one listener'), out
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

# SLICE 3 (#116): the loop is a Ruby surface. `main` may serve itself -
# Webmachine.run blocks like the tool's own loop, Webmachine.tick(3.ms)
# does ONE bounded step for an embedder that owns its loop, and
# Webmachine.fd is what such an embedder waits on in between.
assert('application: main drives the loop itself with Webmachine.tick(3.ms)') do
  sock = "/tmp/wm-ap-tick-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'ticked'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.configure { |conf| conf.unix_path = '#{sock}' }
        app.add_route [:*], R
      end
      # The embedder's own loop: the DURATION crosses the boundary as
      # mruby-chrono spells it, and nothing else in here knows seconds.
      Webmachine.tick(3.ms) until Webmachine.stopped?
    end
  RUBY
  app = ap_compile(src)
  err = "/tmp/wm-ap-tick-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, '--app', app.path, out: File::NULL, err: err)
  begin
    100.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock), (File.read(err) rescue '')
    s = UNIXSocket.new(sock)
    s.write("GET /anything HTTP/1.1\r\nHost: x\r\n\r\n")
    head, body = ap_read(s)
    assert_true head.start_with?('HTTP/1.1 200'), head
    assert_equal 'ticked', body
    s.close
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

assert('application: Webmachine.fd is pollable - idle costs nothing, a request wakes it') do
  sock = "/tmp/wm-ap-fd-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'polled'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.configure { |conf| conf.unix_path = '#{sock}' }
        app.add_route [:*], R
      end
      # The shape the fd exists for: wait on the descriptor, and only
      # then spend a tick. An idle server costs its host nothing.
      io = IO.new(Webmachine.fd)
      until Webmachine.stopped?
        IO.select([io], nil, nil, 0.05)
        Webmachine.tick(3.ms)
      end
    end
  RUBY
  app = ap_compile(src)
  err = "/tmp/wm-ap-fd-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, '--app', app.path, out: File::NULL, err: err)
  begin
    100.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock), (File.read(err) rescue '')
    s = UNIXSocket.new(sock)
    s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    head, body = ap_read(s)
    assert_true head.start_with?('HTTP/1.1 200'), head
    assert_equal 'polled', body
    s.close
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

assert('application: Webmachine.run inside main serves like the tool loop') do
  sock = "/tmp/wm-ap-run-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'ran'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.configure { |conf| conf.unix_path = '#{sock}' }
        app.add_route [:*], R
      end
      Webmachine.run
    end
  RUBY
  app = ap_compile(src)
  err = "/tmp/wm-ap-run-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, '--app', app.path, out: File::NULL, err: err)
  begin
    100.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock), (File.read(err) rescue '')
    s = UNIXSocket.new(sock)
    s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    head, body = ap_read(s)
    assert_true head.start_with?('HTTP/1.1 200'), head
    assert_equal 'ran', body
    s.close
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

# SLICE 4 (#116): the request object. Lazy by construction - the router
# captured the spans while it was walking anyway, and NOTHING becomes a
# Ruby value until a callback asks for it.
assert('application: request names what the route captured, per request') do
  # One field per line, so a value with a space in it (a decoded query
  # parameter) cannot be mistaken for a field boundary.
  src = <<~RUBY
    class Debug < Webmachine::Resource
      def to_html
        r = request
        [r.method, r.uri, r.path, r.disp_path,
         r.path_info.map { |k, v| "\#{k}=\#{v}" }.sort.join(','),
         r.path_tokens.join('|'),
         r.query.map { |k, v| "\#{k}=\#{v}" }.sort.join(','),
         r.query_string].join("\n")
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['fizz', :buzz, :*], Debug
        end
      end
    end
  RUBY
  ap_server(src) do |sock|
    s = UNIXSocket.new(sock)
    s.write("GET /fizz/one/a/b?x=1&y=two%20words&z HTTP/1.1\r\nHost: x\r\n\r\n")
    head, body = ap_read(s)
    assert_true head.start_with?('HTTP/1.1 200'), head
    f = body.split("\n", -1)
    assert_equal 'GET', f[0]
    assert_equal '/fizz/one/a/b?x=1&y=two%20words&z', f[1]
    assert_equal '/fizz/one/a/b', f[2]
    assert_equal 'a/b', f[3]             # the splat tail is what is left
    assert_equal 'buzz=one', f[4]        # the Symbol token, by NAME
    assert_equal 'a|b', f[5]
    assert_equal 'x=1,y=two words,z=', f[6]  # percent-decoded, '+' a space
    assert_equal 'x=1&y=two%20words&z', f[7]

    # A SECOND request through the same warm connection sees its own
    # values - the view is swapped per request, never remembered.
    s.write("GET /fizz/two HTTP/1.1\r\nHost: x\r\n\r\n")
    _, body2 = ap_read(s)
    g = body2.split("\n", -1)
    assert_equal '/fizz/two', g[1]
    assert_equal '', g[3]                # an empty splat tail
    assert_equal 'buzz=two', g[4]
    assert_equal '', g[5]
    assert_equal '', g[7]                # no query at all
    s.close
  end
end

assert('application: request.headers and request.body refuse by name') do
  src = <<~RUBY
    class Asks < Webmachine::Resource
      def to_html
        request.headers
      rescue RuntimeError => e
        e.message
      end
    end

    class AsksBody < Webmachine::Resource
      def to_html
        request.body
      rescue RuntimeError => e
        e.message
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['h'], Asks
          route.add ['b'], AsksBody
        end
      end
    end
  RUBY
  ap_server(src) do |sock|
    s = UNIXSocket.new(sock)
    s.write("GET /h HTTP/1.1\r\nHost: x\r\n\r\n")
    _, body = ap_read(s)
    assert_true body.include?('#165'), body
    s.write("GET /b HTTP/1.1\r\nHost: x\r\n\r\n")
    _, body2 = ap_read(s)
    assert_true body2.include?('request bodies'), body2
    s.close
  end
end

assert('application: request outside a callback refuses instead of reading a dead view') do
  # `main` runs at setup, with no request being answered - asking then
  # is a mistake worth naming.
  out = ap_refused(<<~RUBY)
    class R < Webmachine::Resource
      def self.to_html
        'x'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.add_route [:*], R
      end
      Webmachine::Resource.new.request
    end
  RUBY
  assert_true out.include?('no request being answered'), out
end

# SLICE 5 (#116): the server stops from Ruby - drain, then forget.
assert('application: Webmachine.stop drains, then the process ends by itself') do
  sock = "/tmp/wm-ap-stop-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  src = <<~RUBY
    class Bye < Webmachine::Resource
      def to_html
        # The answer still goes out: the drain closes the LISTENERS,
        # what is already accepted finishes.
        Webmachine.stop(200.ms)
        'bye'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.configure { |conf| conf.unix_path = '#{sock}' }
        app.add_route [:*], Bye
      end
      Webmachine.run
    end
  RUBY
  app = ap_compile(src)
  err = "/tmp/wm-ap-stop-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, '--app', app.path, out: File::NULL, err: err)
  begin
    100.times { break if File.socket?(sock); sleep 0.05 }
    assert_true File.socket?(sock), (File.read(err) rescue '')
    s = UNIXSocket.new(sock)
    s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    head, body = ap_read(s)
    assert_true head.start_with?('HTTP/1.1 200'), head
    assert_equal 'bye', body
    s.close
    # No signal is sent: the grace runs out (or the connection goes)
    # and the loop returns on its own. The unix path goes with it -
    # that is the destructor, the same one a signal's stop reaches.
    ended = false
    100.times do
      break ended = true if Process.waitpid(pid, Process::WNOHANG)
      sleep 0.05
    end
    assert_true ended, 'the server did not end after its drain'
    assert_false File.exist?(sock)
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end
