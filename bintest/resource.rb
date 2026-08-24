# Resources on the wire: a Ruby class inheriting Webmachine::Resource
# is asked ONCE at setup; the requests that follow never enter the VM.
# What a later tier must honor refuses the start by name, never silently.

require 'socket'
require 'tempfile'

RES_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(RES_BIN)

# --app takes bytecode (#100): mrbc runs here, the same way an app's
# author runs it before shipping. ENV['MRBCFILE'] is mruby's own
# bintest.rb export - see test/bintest.rb in the mruby checkout - and
# names whichever mrbc this build produced (the bootstrap host/mrbc
# build when the shipped build carries no mruby-compiler, as here).
def wm_compile(app_source)
  src = Tempfile.new(['wm-app', '.rb'])
  src.write(app_source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-app', '.mrb'])
  mrb.close
  ok = system(mrbc, '-o', mrb.path, src.path)
  raise "mrbc failed to compile:\n#{app_source}" unless ok
  mrb
ensure
  src&.unlink
end

# Since #116 a resource class is not an app: the file defines `main`,
# and the Webmachine::Application registered there carries the listener
# and the routes. Every fixture below is ONE resource on the root splat
# route - exactly the semantics the constant scan used to hand out for
# free - and the listener comes from --unix on the command line, which
# overrides whatever conf would have said.
def wm_app(name, src)
  <<~RUBY
    #{src}
    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add [:*], #{name}
        end
      end
    end
  RUBY
end

# Runs a server bound to the given app source; raises if it never comes up.
def resource_server(app_source)
  app = wm_compile(app_source)
  sock = "/tmp/wm-res-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-res-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, RES_BIN, '--unix', sock, '--app', app.path,
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock, pid
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

# Starts a server that MUST refuse; returns its stderr for the reason.
def resource_refused(app_source)
  app = wm_compile(app_source)
  err = "/tmp/wm-res-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, RES_BIN, '--unix', "/tmp/wm-res-#{$$}.sock",
              '--app', app.path, out: File::NULL, err: err)
  Process.wait(pid)
  raise 'server came up but must have refused' if $?.exitstatus == 0
  File.read(err)
ensure
  app.unlink
end

# Starts a server pointed straight at a .rb path - never compiled, the
# case the mrbc line in the refusal message exists to fix.
def resource_refused_rb(app_source)
  src = Tempfile.new(['wm-app', '.rb'])
  src.write(app_source)
  src.close
  err = "/tmp/wm-res-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, RES_BIN, '--unix', "/tmp/wm-res-#{$$}.sock",
              '--app', src.path, out: File::NULL, err: err)
  Process.wait(pid)
  raise 'server came up but must have refused the .rb path' if $?.exitstatus == 0
  [File.read(err), src.path]
ensure
  src.unlink
end

# Every suite read has a deadline: a wedged server must FAIL the test,
# never hang it. Seen live (2026-08-20): the pre-fix accept bug held a
# readpartial forever and the whole run died in the scrollback.
def wm_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def resource_read(s)
  head = +''
  head << wm_recv(s) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''
  body << wm_recv(s, len - body.bytesize) while body.bytesize < len
  [head, body]
end

assert('resource: hello world serves its rendered body, typed, VM silent') do
  resource_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(%r{^Content-Type: text/html; charset=utf-8\r$}i)
      assert_equal '<html><body>Hello, World!</body></html>', body
      # HEAD: the same head, Content-Length announced, no body bytes -
      # the pipelined GET's response must begin immediately after.
      s.write("HEAD / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
      hh = +''
      hh << wm_recv(s) until hh.end_with?("\r\n\r\n")
      assert_true hh.match?(/^Content-Length: 39\r$/i)
      nxt = +''
      nxt << wm_recv(s) until nxt.end_with?("\r\n\r\n")
      assert_true nxt.start_with?('HTTP/1.1 200 OK'), "HEAD leaked body bytes: #{nxt.inspect}"
      len = nxt[/^Content-Length: *(\d+)\r$/i, 1].to_i
      drain = +''
      drain << wm_recv(s, len - drain.bytesize) while drain.bytesize < len
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
        'GET HEAD POST DELETE'
      end
      def self.delete_resource
        true
      end
      def self.delete_completed?
        true
      end
    end
  RUBY
  resource_server(wm_app('WideResource', src)) do |sock|
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
  resource_server(wm_app('DownResource', src)) do |sock|
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
  resource_server(wm_app('GhostResource', src)) do |sock|
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
  assert_true resource_refused(wm_app('EtagResource', src)).include?('generate_etag')
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
      hh << wm_recv(s) until hh.end_with?("\r\n\r\n")
      assert_true hh.match?(/^Content-Length: 31\r$/i), hh
      nxt, body4 = resource_read(s)
      assert_true nxt.start_with?('HTTP/1.1 200 OK'), "HEAD leaked body bytes: #{nxt.inspect}"
      assert_equal '<html><body>hit 4</body></html>', body4
    end
  end
end

assert('resource: an instance decision is asked per request (state changes answers)') do
  # The counter is APP state, so it lives outside the instance (#181):
  # the resource itself is built fresh per request, which is exactly
  # what the next assert proves.
  src = <<~RUBY
    class Flaky < Webmachine::Resource
      def resource_exists?
        $flaky = ($flaky || 0) + 1
        $flaky.odd?
      end
    end
  RUBY
  resource_server(wm_app('Flaky', src)) do |sock|
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

assert('resource: a raising callback answers 500 in the negotiated type, reason as body') do
  src = <<~RUBY
    class Boom < Webmachine::Resource
      def to_html
        raise 'boom'
      end
    end
  RUBY
  resource_server(wm_app('Boom', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 500')
      assert_true head.match?(%r{^Content-Type: text/html; charset=utf-8\r$}i)
      assert_true body.include?('boom'), body
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

assert('resource: an app file without `main` is refused by name (#116)') do
  # The constant scan is gone with #116: nothing goes looking for "the"
  # resource class any more. An app file defines `main`, and a file
  # that does not is refused with that sentence, not with a
  # NoMethodError from a funcall.
  out = resource_refused("class Quiet < Webmachine::Resource; end\n")
  assert_true out.include?('main'), out
end

assert('resource: a main that registers no application is refused by name (#116)') do
  out = resource_refused("def main; end\n")
  assert_true out.include?('registered no application'), out
end

assert('resource: a class NOT on a route never answers - the route is the door') do
  # Two classes in one file, one route: what the scan used to call
  # ambiguous is now simply a fact about routing.
  src = <<~RUBY
    class Served < Webmachine::Resource
      def self.to_html
        '<html><body>served</body></html>'
      end
    end
    class Ignored < Webmachine::Resource
      def self.to_html
        '<html><body>ignored</body></html>'
      end
    end
  RUBY
  resource_server(wm_app('Served', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body = resource_read(s)
      assert_equal '<html><body>served</body></html>', body
    end
  end
end

assert('resource: a .rb path is refused by name, with the mrbc line that fixes it (#100)') do
  out, rb_path = resource_refused_rb("class NotCompiled < Webmachine::Resource; end\n")
  assert_true out.include?(rb_path), out
  mrb_path = "#{rb_path[0..-4]}.mrb"
  assert_true out.include?("mrbc -o #{mrb_path} #{rb_path}"), out
end

assert('chrono: duration units and clocks answer inside the run frame') do
  # mruby-chrono is the ONE gate for durations crossing Ruby<->C.
  # Prove the gem is linked into the server and its whole surface -
  # units, both clocks, the timer - answers inside a per-request frame.
  src = <<~RUBY
    class Clocked < Webmachine::Resource
      def initialize
        @t0 = Chrono::Steady.now
        @timer = Chrono::Timer.new
      end
      def to_html
        raise 'unit broke' unless 500.ms == 0.5 && 2.s == 2.0 && 1.h == 3600.0
        raise 'steady went backwards' if Chrono::Steady.now < @t0
        raise 'timer broke' if @timer.elapsed < 0
        raise 'system clock implausible' if Chrono::System.now < 1.7e9
        '<html><body>chrono ok</body></html>'
      end
    end
  RUBY
  resource_server(wm_app('Clocked', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      2.times do
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        head, body = resource_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
        assert_equal '<html><body>chrono ok</body></html>', body
      end
    end
  end
end

assert('run frame: bodies survive a full GC per request, 200 requests exact') do
  # The memory model on trial: ONE frame roots everything, the arena
  # carries values between callbacks, no ivars, no pins. Two GC.start
  # per render is the harshest weather that claim must hold in - a
  # body swept too early answers with corrupted bytes here.
  src = <<~RUBY
    class Churn < Webmachine::Resource
      HITS = [0]
      def to_html
        GC.start
        junk = Array.new(64) { |i| 'x' * (65 + (i % 31)) }
        GC.start
        HITS[0] += 1
        "<html><body>hit \#{HITS[0]} of \#{junk.size}</body></html>"
      end
    end
  RUBY
  resource_server(wm_app('Churn', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      200.times do |i|
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        _, body = resource_read(s)
        assert_equal "<html><body>hit #{i + 1} of 64</body></html>", body
      end
    end
  end
end

assert('run frame: a raise right after GC still answers 500 with its message') do
  # The pending exception (and its mesg bytes we lend to the writer)
  # must be rooted through the collection that preceded the raise.
  src = <<~RUBY
    class GcBoom < Webmachine::Resource
      def to_html
        GC.start
        raise 'gcboom'
      end
    end
  RUBY
  resource_server(wm_app('GcBoom', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      3.times do
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        head, body = resource_read(s)
        assert_true head.start_with?('HTTP/1.1 500')
        assert_true body.include?('gcboom'), body
      end
    end
  end
end

assert('run frame: RSS stays flat across 8000 runtime requests') do
  # No per-request allocation may outlive its request: not in the VM
  # (arena resets, no ivars), not in C (string capacities are reused).
  # Measured curve (container): the mruby heap reaches steady state by
  # ~4000 requests and then moves ZERO bytes over 16000 more - so warm
  # past the knee and demand near-flat after it. 512KB headroom still
  # convicts any leak of >= 64 bytes per request.
  src = File.read(File.expand_path('../examples/counter.rb', __dir__))
  resource_server(src) do |sock, pid|
    rss = -> { File.read("/proc/#{pid}/status")[/^VmRSS:\s*(\d+)/, 1].to_i }
    UNIXSocket.open(sock) do |s|
      run = lambda do |n|
        n.times do
          s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
          resource_read(s)
        end
      end
      run.call(4000)  # warm past the heap's steady-state knee
      before = rss.call
      run.call(8000)
      grew = rss.call - before
      assert_true grew < 512, "RSS grew #{grew}KB over 8000 requests"
    end
  end
end

assert('resource: the instance is the REQUEST\'s - ivars never cross, always carry') do
  # Two things at once, and they are the whole point of #181:
  #   - an ivar written by one request is GONE for the next (HTTP is
  #     stateless, so its resource is),
  #   - an ivar written by one CALLBACK is there for the next callback
  #     of that SAME request (that is what request scope buys).
  src = <<~RUBY
    class Scope < Webmachine::Resource
      def resource_exists?
        @seen = (@seen || 0) + 1
        true
      end
      def to_html
        # resource_exists? ran first in this same request, so @seen is
        # 1 here - and 1 again on the next request, never 2.
        "seen=\#{@seen}"
      end
    end
  RUBY
  resource_server(wm_app('Scope', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      3.times do
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        _, body = resource_read(s)
        assert_equal 'seen=1', body
      end
    end
  end
end
