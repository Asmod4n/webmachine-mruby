
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

# Like ap_refused, but WITHOUT --unix: some refusals are about the
# listener the app named, and an override would answer before them.
def ap_refused_unaided(app_source)
  app = ap_compile(app_source)
  err = "/tmp/wm-ap-unaided-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, '--app', app.path, out: File::NULL, err: err)
  Process.wait(pid)
  raise 'server came up but must have refused' if $?.exitstatus == 0
  File.read(err)
ensure
  app.unlink
end

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
      s.write("GET /fizz/one HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = ap_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_equal '<html><body>fizzbuzz</body></html>', body
      s.write("GET /fizz/one/two/three HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = ap_read(s)
      assert_true head2.start_with?('HTTP/1.1 200'), head2.lines.first.to_s
      s.write("GET /fizz/one?v=1 HTTP/1.1\r\nHost: x\r\n\r\n")
      head3, = ap_read(s)
      assert_true head3.start_with?('HTTP/1.1 200'), head3.lines.first.to_s
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
  ap_server(AP_FIZZ) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("POST /nowhere HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head, = ap_read(s)
      assert_true head.start_with?('HTTP/1.1 404'), head.lines.first.to_s
      assert_false head.match?(/^Allow:/i), head
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
      s.write("PUT /narrow HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
      h3, = ap_read(s)
      assert_true h3.start_with?('HTTP/1.1 405'), h3.lines.first.to_s
      assert_true h3.match?(/^Allow: GET, HEAD\r$/i), h3
      s.write("PUT /wide HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
      h4, = ap_read(s)
      assert_true h4.start_with?('HTTP/1.1 405'), h4.lines.first.to_s
      assert_true h4.match?(/^Allow: GET, HEAD, POST\r$/i), h4
      # RFC 9110 9.3.3 / fsm.rb n11, and #201: Wide allows POST and defines
      # nothing to answer one with. This used to be a 200 - the konst tier
      # walked past n11 without performing it - and the engine has always
      # called it what it is.
      s.write("POST /wide HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
      h5, = ap_read(s)
      assert_true h5.start_with?('HTTP/1.1 500'), h5.lines.first.to_s
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

assert('application: conf.url names the listener when nothing overrides it') do
  # Below ip_local_port_range (32768 up here): a fixed port picked
  # INSIDE that window collides with an ephemeral port the machine
  # already handed out, which is how this suite once died on 44468.
  port = 20000 + rand(11000)
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

assert('application: conf.port = 0 is legal - the OS picks at bind time') do
  sock = "/tmp/wm-ap-eph0-#{$$}.sock"
  src = ap_one_route(<<~BODY)
    app.conf.port = 0
    app.add_route [:*], R
  BODY
  ap_server(src, sock: sock) do |s, _out|
    UNIXSocket.open(s) do |c|
      c.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, _body = ap_read(c)
      assert_include head, '200 OK'
    end
  end
end

assert('application: conf.adapter does not exist - a swallowed setting is a lie') do
  out = ap_refused(ap_one_route(<<~BODY))
    app.conf.port = 8080
    app.conf.adapter = :Webrick
    app.add_route [:*], R
  BODY
  assert_true out.include?('adapter='), out
  assert_true out.include?('NoMethodError'), out
end

assert('application: webmachine-ruby spells TLS three ways this tree does not') do
  %w[ssl ssl_options certificate_key].each do |name|
    out = ap_refused(ap_one_route(<<~BODY))
      app.conf.port = 8080
      app.conf.#{name} = 'whatever'
      app.add_route [:*], R
    BODY
    assert_true out.include?("#{name}="), "#{name}: #{out}"
    assert_true out.include?('NoMethodError'), "#{name}: #{out}"
  end
end

assert('application: https, a certificate and a key are one decision') do
  # A certificate without https: the listener would carry keys it never
  # offers, which is a config that means two things at once.
  out = ap_refused(ap_one_route(<<~BODY))
    app.conf.port = 8080
    app.conf.certificate = '/nonexistent/cert.pem'
    app.conf.private_key = '/nonexistent/key.pem'
    app.add_route [:*], R
  BODY
  assert_true out.include?('not https'), out

  # https without either of them.
  out = ap_refused(ap_one_route(<<~BODY))
    app.configure { |conf| conf.url = 'https://example.com' }
    app.add_route [:*], R
  BODY
  assert_true out.include?('conf.certificate'), out
  assert_true out.include?('conf.private_key'), out

  # https with only one of them, named by which one is missing.
  out = ap_refused(ap_one_route(<<~BODY))
    app.configure do |conf|
      conf.url = 'https://example.com'
      conf.certificate = '/nonexistent/cert.pem'
    end
    app.add_route [:*], R
  BODY
  assert_true out.include?('only the certificate'), out
end

assert('application: an https listener says which file it could not read') do
  out = ap_refused_unaided(ap_one_route(<<~BODY))
    app.configure do |conf|
      conf.url = 'https://example.com:0'
      conf.certificate = '/nonexistent/cert.pem'
      conf.private_key = '/nonexistent/key.pem'
    end
    app.add_route [:*], R
  BODY
  assert_true out.include?('/nonexistent/cert.pem'), out
  assert_true out.include?('No such file'), out
end

assert('application: the kernel has no record layer on a unix socket') do
  # --unix overrides the listener the app named, so this app ends up
  # asking for TLS where setsockopt(IPPROTO_TCP, TCP_ULP) is ENOTSUP.
  out = ap_refused(ap_one_route(<<~BODY))
    app.configure do |conf|
      conf.url = 'https://example.com'
      conf.certificate = '/nonexistent/cert.pem'
      conf.private_key = '/nonexistent/key.pem'
    end
    app.add_route [:*], R
  BODY
  assert_true out.include?('unix socket'), out
  assert_true out.include?('TCP ULP'), out
end

assert('application: route.assets is a signpost, route.sse is a real route kind') do
  assets = ap_refused(ap_one_route("app.routes { |route| route.assets '/static' }"))
  assert_true assets.include?('#170'), assets
  assert_true assets.include?('--assets'), assets
  sse = ap_refused(ap_one_route("app.routes { |route| route.sse ['sse'], R }"))
  assert_true sse.include?('SseResource'), sse
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

    { a => 'from-a', b => 'from-b' }.each do |sock, body|
      s = UNIXSocket.new(sock)
      path = body == 'from-a' ? '/only-a' : '/only-b'
      s.write("GET #{path} HTTP/1.1\r\nHost: x\r\n\r\n")
      head, got = ap_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head
      assert_equal body, got
      s.close
    end

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

assert('application: request names what the route captured, per request') do
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
    assert_equal 'a/b', f[3]
    assert_equal 'buzz=one', f[4]
    assert_equal 'a|b', f[5]
    assert_equal 'x=1,y=two words,z=', f[6]
    assert_equal 'x=1&y=two%20words&z', f[7]

    s.write("GET /fizz/two HTTP/1.1\r\nHost: x\r\n\r\n")
    _, body2 = ap_read(s)
    g = body2.split("\n", -1)
    assert_equal '/fizz/two', g[1]
    assert_equal '', g[3]
    assert_equal 'buzz=two', g[4]
    assert_equal '', g[5]
    assert_equal '', g[7]
    s.close
  end
end

assert('application: request.headers are the head, lowercased; request.body is the entity') do
  src = <<~RUBY
    class Asks < Webmachine::Resource
      def to_html
        h = request.headers
        "\#{h['x-one']}|\#{h['x-two']}|\#{h['host']}"
      end
    end

    class AsksBody < Webmachine::Resource
      def self.allowed_methods
        'GET HEAD POST'
      end

      def to_html
        request.has_body? ? request.body : 'none'
      end

      def process_post
        response.body = request.body
        true
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
    s.write("GET /h HTTP/1.1\r\nHost: x\r\nX-One: a\r\nX-TWO: b\r\nX-One: c\r\n\r\n")
    _, body = ap_read(s)
    assert_equal 'a, c|b|x', body
    s.write("GET /b HTTP/1.1\r\nHost: x\r\n\r\n")
    _, body2 = ap_read(s)
    assert_equal 'none', body2
    s.write("POST /b HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nding")
    _, body3 = ap_read(s)
    assert_equal 'ding', body3
    s.close
  end
end

# #181: there is no way for Ruby to hold a resource instance outside the
# request it belongs to, because there is no way for Ruby to MAKE one - the
# server allocates from the class, per request. Resource.new used to reach
# Object's initialize and hand out an instance whose request view was dead;
# now it refuses by name. The dead-view guard in request.cpp stays as the
# second line of defence, unreachable from Ruby until on_idle (#80) gives
# an escaped self somewhere to run.
assert('application: a resource is the server\'s to build - Resource.new refuses by name') do
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
      Webmachine::Resource.new
    end
  RUBY
  assert_true out.include?('one per request'), out
  assert_false out.include?('undefined method'), out
end

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

assert('application: conf.url port 0 - the kernel picks, ready reads the pick back') do
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'eph'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.url = 'http://0.0.0.0:0'
        app.add_route [:*], R
        app.ready do
          puts "ready \#{app.conf.url}"
        end
      end
    end
  RUBY
  app = ap_compile(src)
  out = "/tmp/wm-ap-eph-out-#{$$}.log"
  err = "/tmp/wm-ap-eph-err-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, '--app', app.path, out: out, err: err)
  port = nil
  refused = false
  100.times do
    text = begin File.read(out) rescue '' end
    if (m = text.match(%r{^ready http://0\.0\.0\.0:(\d+)$}))
      port = m[1].to_i
      break
    end
    etext = begin File.read(err) rescue '' end
    if etext.include?('SOCKET_URING_OP_GETSOCKNAME')
      refused = true
      break
    end
    sleep 0.05
  end
  begin
    if refused
      Process.wait(pid) rescue nil
      assert_include (begin File.read(err) rescue '' end), 'name a port'
    else
      assert_false port.nil?
      assert_true port > 0, "kernel picked #{port}?"
      s = TCPSocket.new('127.0.0.1', port)
      s.write "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
      resp = +''
      loop do
        resp << s.readpartial(4096)
      rescue EOFError
        break
      end
      s.close
      assert_include resp, '200 OK'
      assert_include resp, 'eph'
    end
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    app.unlink
    File.unlink(out) rescue nil
    File.unlink(err) rescue nil
  end
end

assert('application: app.conf is ONE object, not a fresh one per read') do
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'x'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.port = 8080
        app.add_route [:*], R
        app.ready do
          puts "same=\#{app.conf.equal?(app.conf)}"
        end
      end
    end
  RUBY
  ap_server(src) do |_sock, out|
    assert_true File.read(out).include?('same=true'), File.read(out)
  end
end

assert('application: a refusal is catchable BY CLASS, not by luck') do
  src = <<~RUBY
    class R < Webmachine::Resource
      def self.to_html
        'x'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.port = 8080
        begin
          app.conf.port = 99999
        rescue Webmachine::ConfigError => e
          puts "config=\#{e.class}"
        end
        begin
          app.add_route [:*], String
        rescue Webmachine::RouteError => e
          puts "route=\#{e.class}"
        end
        app.add_route [:*], R
      end
    end
  RUBY
  ap_server(src) do |_sock, out|
    text = File.read(out)
    assert_true text.include?('config=Webmachine::ConfigError'), text
    assert_true text.include?('route=Webmachine::RouteError'), text
  end
end

assert('application: a server with nothing to serve refuses to start') do
  # There is no built-in resource any more. What answered before was a
  # Resource that never went through the fold - no media type, no callback
  # behind any answer - and it is exactly the shape #201 was about.
  err = "/tmp/wm-ap-nothing-#{$$}.log"
  sock = "/tmp/wm-ap-nothing-#{$$}.sock"
  pid = spawn({ 'WM_BUNDLE' => '0' }, AP_BIN, '--unix', sock, out: File::NULL, err: err)
  Process.wait(pid)
  assert_false $?.exitstatus == 0, 'server came up with nothing to serve'
  text = File.read(err) rescue ''
  assert_true text.include?('nothing to serve'), text
  assert_false File.exist?(sock), 'a refused server left a listening socket behind'
ensure
  File.unlink(err) rescue nil
  File.unlink(sock) rescue nil
end

# #210 response.error_asset: an app names an entry of the error assets and
# THOSE bytes are the answer. Not response.file - nothing is opened and
# nothing goes through the ring, because the archive is mmap'd for as long
# as the server runs, so what the answer carries is a pointer into that map.
AP_EASSET = <<~RUBY unless defined?(AP_EASSET)
  class Teapot < Webmachine::Resource
    def content_types_provided
      [['image/jpeg', :pic]]
    end

    def pic
      response.error_asset('418.jpg')
      # The same '' convention response.file= already asks for: the answer
      # is already named, so this String is dead on arrival.
      ''
    end
  end

  class Typo < Webmachine::Resource
    def content_types_provided
      [['image/jpeg', :pic]]
    end

    def pic
      response.error_asset('no-such-cat.jpg')
      ''
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes do |route|
        route.add ['teapot'], Teapot
        route.add ['typo'], Typo
      end
    end
  end
RUBY

def ap_shipped_error_assets
  File.expand_path('../share/error-assets.zip', __dir__)
end

# The entry as the archive really holds it, so "these bytes" is a claim
# about bytes and not about a length that happens to agree.
def ap_zip_entry(path, name)
  raw = File.binread(path)
  off = 0
  while off + 30 <= raw.bytesize && raw[off, 4] == "PK\x03\x04".b
    csize, _usize, nlen, elen = raw[off + 18, 12].unpack('VVvv')
    found = raw[off + 30, nlen]
    body = raw[off + 30 + nlen + elen, csize]
    return body if found == name
    off += 30 + nlen + elen + csize
  end
  nil
end

assert('application: response.error_asset answers with the mapped entry, byte for byte') do
  pack = ap_shipped_error_assets
  skip "no #{pack} - run rake error_assets" unless File.exist?(pack)
  want = ap_zip_entry(pack, '418.jpg')
  assert_true want != nil, 'no 418.jpg in the shipped error assets'

  sock = "/tmp/wm-ap-ea-#{$$}.sock"
  ap_server(AP_EASSET, sock: sock,
            args: ['--unix', sock, '--error-assets', pack]) do |s|
    UNIXSocket.open(s) do |c|
      # Twice on ONE connection: a lend that was not handed back, or a
      # pointer the run frame owned, shows up on the second answer.
      2.times do |i|
        c.write("GET /teapot HTTP/1.1\r\nHost: x\r\nAccept: image/jpeg\r\n\r\n")
        head, body = ap_read(c)
        assert_true head.start_with?('HTTP/1.1 200 OK'), "#{i}: #{head}"
        assert_true head.match?(%r{^Content-Type: image/jpeg\r$}i), head
        assert_equal want.bytesize, body.bytesize
        assert_equal want, body.b
      end
      # RFC 9110 9.3.2: HEAD carries the length it would have sent - and
      # sends none of it, so this reads the head ALONE. ap_read would sit
      # here waiting for a body that is never coming.
      c.write("HEAD /teapot HTTP/1.1\r\nHost: x\r\nAccept: image/jpeg\r\n\r\n")
      head = +''
      head << ap_recv(c) until head.end_with?("\r\n\r\n")
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_true head.include?("Content-Length: #{want.bytesize}\r\n"), head
    end
  end
end

assert('application: an error_asset the archive does not carry is refused by name') do
  pack = ap_shipped_error_assets
  skip "no #{pack} - run rake error_assets" unless File.exist?(pack)
  sock = "/tmp/wm-ap-ea2-#{$$}.sock"
  log = "/tmp/wm-ap-ea2-#{$$}.errlog"
  File.unlink(log) if File.exist?(log)
  begin
    ap_server(AP_EASSET, sock: sock,
              args: ['--unix', sock, '--error-assets', pack, '--error-log', log]) do |s|
      UNIXSocket.open(s) do |c|
        c.write("GET /typo HTTP/1.1\r\nHost: x\r\nAccept: image/jpeg\r\n\r\n")
        head, = ap_read(c)
        assert_true head.start_with?('HTTP/1.1 500'), head
      end
    end
    20.times { break if File.exist?(log) && !File.read(log).empty?; sleep 0.1 }
    text = File.read(log)
    # The name the APP wrote, so a typo reads as a typo and not as a
    # request that went astray.
    assert_true text.include?('no-such-cat.jpg'), text
    assert_true text.include?('the error assets hold no'), text
  ensure
    File.unlink(log) rescue nil
  end
end

assert('application: response.error_asset without error assets says so, and how to fix it') do
  sock = "/tmp/wm-ap-ea3-#{$$}.sock"
  log = "/tmp/wm-ap-ea3-#{$$}.errlog"
  File.unlink(log) if File.exist?(log)
  begin
    # /dev/null names a file that is not an archive, so this server ends
    # up with no error assets - which is the state under test. Leaving the
    # flag off no longer reaches it: a server with nothing named now finds
    # the shipped file beside its own binary.
    ap_server(AP_EASSET, sock: sock,
              args: ['--unix', sock, '--error-assets', '/dev/null',
                     '--error-log', log]) do |s|
      UNIXSocket.open(s) do |c|
        c.write("GET /teapot HTTP/1.1\r\nHost: x\r\nAccept: image/jpeg\r\n\r\n")
        head, = ap_read(c)
        assert_true head.start_with?('HTTP/1.1 500'), head
      end
    end
    20.times { break if File.exist?(log) && !File.read(log).empty?; sleep 0.1 }
    text = File.read(log)
    assert_true text.include?('--error-assets'), text
    assert_true text.include?('ConfigError'), text
  ensure
    File.unlink(log) rescue nil
  end
end

# #210: a server started out of its own build tree finds the error assets
# lying in that tree, with no flag and nothing installed. This is the case
# that was silently broken: the lookup knew only the XDG directories, so a
# server run from a checkout answered every error in plain text and never
# said why - which reads exactly like conneg picking the wrong type.
assert('application: error assets are found beside the binary, with no flag at all') do
  pack = ap_shipped_error_assets
  skip "no #{pack} - run rake error_assets" unless File.exist?(pack)
  want = ap_zip_entry(pack, '404.jpg')
  assert_true want != nil, 'no 404.jpg in the shipped error assets'

  sock = "/tmp/wm-ap-find-#{$$}.sock"
  # NO --error-assets. The route below leaves /favicon.ico unrouted, and
  # the Accept is the one a browser sends for a picture: image/* carries
  # q=0.8 over */* at q=0.5, so a picture is what it asked for.
  ap_server(AP_FIZZ, sock: sock, args: ['--unix', sock]) do |s, _out, err|
    UNIXSocket.open(s) do |c|
      c.write("GET /favicon.ico HTTP/1.1\r\nHost: x\r\n" \
              "Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5\r\n\r\n")
      head, body = ap_read(c)
      assert_true head.start_with?('HTTP/1.1 404'), head
      assert_true head.match?(%r{^Content-Type: image/jpeg\r$}i),
                  "no picture: #{head[/^Content-Type:.*$/i]}"
      assert_equal want, body.b
    end
    # And it says which file it took, so an operator can tell a server
    # with pictures from one without at a glance.
    text = File.read(err) rescue ''
    assert_true text.include?('error assets from'), text
  end
end

# RFC 9110 12.5.1: the SAME path answers html or a picture depending on
# what the client asked for, and a browser asks two different things.
# Typing the URL is a navigation: text/html is named with no q, so q=1.0,
# and image/jpeg is named by nothing but */*;q=0.8 - html wins, and must.
# Fetching it as a picture names no text/html at all, and image/*;q=0.8
# beats */*;q=0.5 - the picture wins. Neither is a bug in the other's
# favour, which is why both are written down here.
assert('application: a navigation gets the page, a picture fetch gets the picture') do
  pack = ap_shipped_error_assets
  skip "no #{pack} - run rake error_assets" unless File.exist?(pack)
  nav = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,' \
        'image/png,image/svg+xml,*/*;q=0.8'
  img = 'image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5'

  sock = "/tmp/wm-ap-conneg-#{$$}.sock"
  ap_server(AP_FIZZ, sock: sock,
            args: ['--unix', sock, '--error-assets', pack]) do |s|
    UNIXSocket.open(s) do |c|
      c.write("GET /favicon.ico HTTP/1.1\r\nHost: x\r\nAccept: #{nav}\r\n\r\n")
      head, body = ap_read(c)
      assert_true head.start_with?('HTTP/1.1 404'), head
      assert_true head.match?(%r{^Content-Type: text/html}i),
                  "a navigation got #{head[/^Content-Type:.*$/i]}"
      assert_true body.include?('404'), body[0, 200]

      c.write("GET /favicon.ico HTTP/1.1\r\nHost: x\r\nAccept: #{img}\r\n\r\n")
      head, body = ap_read(c)
      assert_true head.start_with?('HTTP/1.1 404'), head
      assert_true head.match?(%r{^Content-Type: image/jpeg\r$}i),
                  "a picture fetch got #{head[/^Content-Type:.*$/i]}"
      assert_equal "\xFF\xD8".b, body.b[0, 2]
    end
  end
end
