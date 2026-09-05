
require 'socket'
require 'tempfile'

RES_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(RES_BIN)

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

def resource_server(app_source)
  app = wm_compile(app_source)
  sock = "/tmp/wm-res-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-res-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, RES_BIN, "--unix=#{sock}", "--app=#{app.path}",
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

def resource_refused(app_source)
  app = wm_compile(app_source)
  err = "/tmp/wm-res-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, RES_BIN, "--unix=/tmp/wm-res-#{$$}.sock",
              "--app=#{app.path}", out: File::NULL, err: err)
  Process.wait(pid)
  raise 'server came up but must have refused' if $?.exitstatus == 0
  File.read(err)
ensure
  app.unlink
end

def resource_refused_rb(app_source)
  src = Tempfile.new(['wm-app', '.rb'])
  src.write(app_source)
  src.close
  err = "/tmp/wm-res-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, RES_BIN, "--unix=/tmp/wm-res-#{$$}.sock",
              "--app=#{src.path}", out: File::NULL, err: err)
  Process.wait(pid)
  raise 'server came up but must have refused the .rb path' if $?.exitstatus == 0
  [File.read(err), src.path]
ensure
  src.unlink
end

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
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head3, = resource_read(s)
      assert_true head3.start_with?('HTTP/1.1 405')
    end
  end
end

# NOTE (#201, fixed): these are the answers of BOTH tiers. They used to be
# the engine's alone - the konst tier answered 200 to a POST with no
# process_post and to a PUT with no content_types_accepted, because n11 and
# o14/p3 are ACTION nodes and a fold performs no action. A resource that
# allows POST or PUT with not one callback defined now runs, so the engine
# gives the only answer either of them has.
assert('resource: allowed_methods widens and the flow obeys, Allow speaks the list') do
  src = <<~RUBY
    class WideResource < Webmachine::Resource
      def self.allowed_methods
        'GET HEAD POST DELETE'
      end
      def delete_resource
        true
      end
      def self.delete_completed?
        true
      end
    end
  RUBY
  resource_server(wm_app('WideResource', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      # RFC 9110 9.3.3 / fsm.rb n11: a POST that is not a create and has no
      # process_post is the app's mistake, and it is named as one.
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head, = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 500'), "POST expected 500, got #{head.lines.first}"
      # RFC 9110 15.3.5 / fsm.rb o20: nothing set a body, so no entity.
      s.write("DELETE / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2 = +''
      head2 << wm_recv(s) until head2.end_with?("\r\n\r\n")
      assert_true head2.start_with?('HTTP/1.1 204'), "DELETE expected 204, got #{head2.lines.first}"
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
      assert_true head.start_with?('HTTP/1.1 404')
      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-Match: *\r\n\r\n")
      head2, = resource_read(s)
      assert_true head2.start_with?('HTTP/1.1 412')
    end
  end
end

assert('resource: i18n callbacks refuse the start by name') do
  src = <<~RUBY
    class LangResource < Webmachine::Resource
      def self.languages_provided
        ['en', 'de']
      end
    end
  RUBY
  assert_true resource_refused(wm_app('LangResource', src)).include?('languages_provided')
end

assert('compute: a name a worker cannot answer is refused at the start (#80)') do
  src = <<~RUBY
    class ComputeNoNode < Webmachine::Resource
      compute :finish_request
      def to_html; 'x'; end
    end
  RUBY
  out = resource_refused(wm_app('ComputeNoNode', src))
  assert_true out.include?('finish_request')
  assert_true out.include?('generate_etag')
end

assert('compute: a callback that is not defined is refused at the start (#80)') do
  src = <<~RUBY
    class ComputeUndefined < Webmachine::Resource
      compute :is_authorized?
      def to_html; 'x'; end
    end
  RUBY
  out = resource_refused(wm_app('ComputeUndefined', src))
  assert_true out.include?('is_authorized')
  assert_true out.include?('def self.')
end

assert('compute: a callback on the instance is refused at the start (#80)') do
  src = <<~RUBY
    class ComputeOnInstance < Webmachine::Resource
      compute :is_authorized?
      def is_authorized?(_h); true; end
      def to_html; 'x'; end
    end
  RUBY
  out = resource_refused(wm_app('ComputeOnInstance', src))
  assert_true out.include?('carries no environment')
end

assert('compute: it wants a symbol, and at least one (#80)') do
  src = <<~RUBY
    class ComputeNoName < Webmachine::Resource
      compute
      def to_html; 'x'; end
    end
  RUBY
  assert_true resource_refused(wm_app('ComputeNoName', src)).include?('got none')

  src2 = <<~RUBY
    class ComputeNotSym < Webmachine::Resource
      compute 'is_authorized?'
      def to_html; 'x'; end
    end
  RUBY
  assert_true resource_refused(wm_app('ComputeNotSym', src2)).include?('wants a symbol')
end

assert('ComputeTask wants a block and a deadline that is a time (#80)') do
  src = <<~RUBY
    class ComputeNoBlock < Webmachine::Resource
      compute :is_authorized?
      def self.is_authorized?(_h)
        Webmachine::ComputeTask.new(max_runtime: 50.ms)
      end
      def to_html; 'x'; end
    end
  RUBY
  resource_server(wm_app('ComputeNoBlock', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, _ = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 500')
    end
  end
end

assert('compute: a worker answers the node, and the graph carries on (#80)') do
  src = <<~RUBY
    class ComputeAuth < Webmachine::Resource
      compute :is_authorized?
      def self.is_authorized?(header)
        Webmachine::ComputeTask.new(header, max_runtime: 500.ms) { |h| !h.nil? }
      end
      def to_html; 'answered by a worker'; end
    end
  RUBY
  resource_server(wm_app('ComputeAuth', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic eA==\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_equal 'answered by a worker', body
    end
  end
end

assert('compute: a task over its max_runtime answers 500 and no Retry-After (#80)') do
  src = <<~RUBY
    class ComputeTooSlow < Webmachine::Resource
      compute :is_authorized?
      def self.is_authorized?(_header)
        Webmachine::ComputeTask.new(max_runtime: 20.ms) { loop { } }
      end
      def to_html; 'x'; end
    end
  RUBY
  resource_server(wm_app('ComputeTooSlow', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, _ = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 500'), head
      # The author's number was wrong. A second attempt costs the same,
      # so nothing tells the client to come back.
      assert_false head.match?(/^Retry-After:/i), head
    end
  end
end

assert('compute: a worker that raises answers 503 and Retry-After: 60 (#80)') do
  src = <<~RUBY
    class ComputeRaises < Webmachine::Resource
      compute :is_authorized?
      def self.is_authorized?(_header)
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { raise 'the handle is gone' }
      end
      def to_html; 'x'; end
    end
  RUBY
  resource_server(wm_app('ComputeRaises', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, _ = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 503'), head
      assert_true head.match?(/^Retry-After: 60\r$/i), head
    end
  end
end

assert('a konst answer carries a real Date, not the placeholder (RFC 9110 6.6.1)') do
  src = <<~RUBY
    class KonstDate < Webmachine::Resource
      def self.to_html; 'x'; end
    end
  RUBY
  resource_server(wm_app('KonstDate', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, _ = resource_read(s)
      date = head[/^Date: (.*)\r$/, 1]
      assert_true !date.nil?, head
      # The prebuilt heads carry a placeholder until the ticker stamps
      # them. One that reaches a client says the server never did.
      assert_false date.include?('1970'), head
    end
  end
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
      assert_true head.start_with?('HTTP/1.1 500')
    end
  end
end

assert('resource: an app that raises at load refuses the start with the error') do
  assert_true resource_refused("raise 'kaputt'").include?('kaputt')
end

assert('resource: an app file without `main` is refused by name (#116)') do
  out = resource_refused("class Quiet < Webmachine::Resource; end\n")
  assert_true out.include?('main'), out
end

assert('resource: a main that registers no application is refused by name (#116)') do
  out = resource_refused("def main; end\n")
  assert_true out.include?('registered no application'), out
end

assert('resource: a class NOT on a route never answers - the route is the door') do
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
      run.call(4000)
      before = rss.call
      run.call(8000)
      grew = rss.call - before
      assert_true grew < 512, "RSS grew #{grew}KB over 8000 requests"
    end
  end
end

assert('resource: the instance is the REQUEST\'s - ivars never cross, always carry') do
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

# RFC 9110 8.3 / 12.5.1: an INSTANCE-level content_types_provided is a value
# the fold cannot know, so the prebuilt head cannot carry its Content-Type
# and the run has to spell its own head. With ONE pair and no Accept there
# is no Vary and no other field line either, so the run's field buffer stays
# empty - which makes this the only case where the negotiated type is the
# whole reason the head goes dynamic. Nothing pinned it before, and dropping
# that half of the writers' condition passed the entire suite.
WM_INSTANCE_CT = <<~RUBY_SRC unless defined?(WM_INSTANCE_CT)
  class OneType < Webmachine::Resource
    def content_types_provided
      [['application/vnd.webmachine.test+json', :to_json]]
    end

    def to_json
      '{"one":true}'
    end
  end
RUBY_SRC

assert('resource: an instance-level content_types_provided types the answer') do
  resource_server(wm_app('OneType', WM_INSTANCE_CT)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      # http::with_charset spells charset only for text/*; a +json type
      # carries no parameter, which is what RFC 9110 8.3 wants here.
      assert_true head.match?(%r{^Content-Type: application/vnd\.webmachine\.test\+json\r$}i), head
      assert_false head.match?(/^Vary:/i), "one provided type must not vary: #{head}"
      assert_equal '{"one":true}', body
    end
  end
end

# RFC 9110 13: examples/conditional.rb is the caching resource - two
# provided types (so Vary), generate_etag, last_modified and expires. It is
# the only example that drives the value engine's FIELD emission, which is
# what makes it the load for that path.
assert('resource: the conditional example spells its caching fields, then answers 304') do
  src = File.read(File.expand_path('../examples/conditional.rb', __dir__))
  resource_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_true head.match?(%r{^Content-Type: text/html; charset=utf-8\r$}i), head
      assert_true head.match?(/^Vary: Accept\r$/i), head
      assert_true head.match?(/^ETag: "article-7"\r$/i), head
      assert_true head.match?(/^Last-Modified: Sun, 24 Aug 2025 01:46:40 GMT\r$/i), head
      assert_true head.match?(/^Expires: Mon, 25 Aug 2025 01:46:40 GMT\r$/i), head
      assert_true body.include?('Conditional'), body

      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"article-7\"\r\n\r\n")
      nm = +''
      nm << wm_recv(s) until nm.end_with?("\r\n\r\n")
      assert_true nm.start_with?('HTTP/1.1 304 Not Modified'), nm
      assert_true nm.match?(/^ETag: "article-7"\r$/i), nm
      assert_false nm.match?(/^Content-Length: [1-9]/i), nm

      s.write("GET / HTTP/1.1\r\nHost: x\r\n" \
              "If-Modified-Since: Sun, 24 Aug 2025 01:46:40 GMT\r\n\r\n")
      ms = +''
      ms << wm_recv(s) until ms.end_with?("\r\n\r\n")
      assert_true ms.start_with?('HTTP/1.1 304 Not Modified'), ms

      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\n\r\n")
      jh, jb = resource_read(s)
      assert_true jh.match?(%r{^Content-Type: application/json\r$}i), jh
      assert_equal '{"title":"Conditional"}', jb
    end
  end
end

# cb.rb: a value callback written as `def self.x` answers on the CLASS. The
# fold resolves it there and the run enters it directly - it used to be the
# one dispatch that searched for its method again on every request. Nothing
# covered that path: allowed_methods and the boolean nodes fold to konst
# instead, so a class-level callback never actually reached the engine in a
# test until this one.
WM_CLASS_CB = <<~RUBY_SRC unless defined?(WM_CLASS_CB)
  class ClassCb < Webmachine::Resource
    def self.generate_etag
      'class-etag-3'
    end

    def self.expires
      1_856_000_000
    end

    def self.variances
      ['Accept-Language']
    end

    def self.is_authorized?(header)
      header != 'no'
    end

    def to_html
      '<html><body>class callbacks</body></html>'
    end
  end
RUBY_SRC

assert('resource: value callbacks on the class answer, and their fields land') do
  resource_server(wm_app('ClassCb', WM_CLASS_CB)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_true head.match?(/^ETag: "class-etag-3"\r$/i), head
      assert_true head.match?(/^Expires: Tue, 24 Oct 2028 11:33:20 GMT\r$/i), head
      assert_true head.match?(/^Vary: Accept-Language\r$/i), head
      assert_equal '<html><body>class callbacks</body></html>', body

      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"class-etag-3\"\r\n\r\n")
      nm = +''
      nm << wm_recv(s) until nm.end_with?("\r\n\r\n")
      assert_true nm.start_with?('HTTP/1.1 304 Not Modified'), nm

      s.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: no\r\n\r\n")
      un = +''
      un << wm_recv(s) until un.end_with?("\r\n\r\n")
      assert_true un.start_with?('HTTP/1.1 401 Unauthorized'), un
    end
  end
end

# RFC 9110 5.1 / 5.5: no app string becomes a field line unchecked. Every
# byte an app can put into an answer's head passes http::field_name_ok /
# field_value_ok, and this asks for that AT THE WIRE - a spliced field
# would show up as a second status line's worth of head, or as a header
# the resource never named.
assert('a resource cannot splice a field into its own answer') do
  src = <<~'APP'
    class Splicer < Webmachine::Resource
      def generate_etag
        "v1\r\nX-Injected: yes"
      end

      def to_html
        '<html><body>hi</body></html>'
      end
    end
  APP
  resource_server(wm_app('Splicer', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      head, = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 500'), "expected a 500, got: #{head[0, 60]}"
      assert_false head.include?('X-Injected'), "the field was spliced in:\n#{head}"
    end
  end
end

assert('response.headers[]= refuses a name that is not a token, and a value with CRLF') do
  src = <<~'APP'
    class Setter < Webmachine::Resource
      def to_html
        case request.headers['x-mode']
        when 'name' then response.headers["X\r\nX-Injected"] = 'yes'
        when 'value' then response.headers['X-Ok'] = "a\r\nX-Injected: yes"
        else response.headers['X-Ok'] = 'plain'
        end
        '<html><body>hi</body></html>'
      end
    end
  APP
  resource_server(wm_app('Setter', src)) do |sock|
    [['name', true], ['value', true], ['plain', false]].each do |mode, must_fail|
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nX-Mode: #{mode}\r\nConnection: close\r\n\r\n")
        head, = resource_read(s)
        assert_false head.include?('X-Injected'), "#{mode} spliced a field in:\n#{head}"
        if must_fail
          assert_true head.start_with?('HTTP/1.1 500'), "#{mode}: expected 500, got #{head[0, 60]}"
        else
          assert_true head.start_with?('HTTP/1.1 200'), "#{mode}: expected 200, got #{head[0, 60]}"
        end
      end
    end
  end
end

assert('resource: an Accept that names no offered type is 406 on both tiers') do
  # RFC 9110 12.5.1 / 15.5.7, and #201: c4 is the CLIENT's question. The
  # konst tier bakes one media type and used to answer 200 to any Accept at
  # all - a resource that offers text/html handed HTML to a client that
  # asked for image/png. Both spellings of the same resource are pinned here
  # because the whole point is that they answer alike.
  konst = <<~RUBY
    class KonstOne < Webmachine::Resource
      def self.to_html
        '<html>K</html>'
      end
    end
  RUBY
  dyn = <<~RUBY
    class DynOne < Webmachine::Resource
      def to_html
        '<html>D</html>'
      end
    end
  RUBY
  [['KonstOne', konst], ['DynOne', dyn]].each do |name, src|
    resource_server(wm_app(name, src)) do |sock|
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: image/png\r\n\r\n")
        head, = resource_read(s)
        assert_true head.start_with?('HTTP/1.1 406'),
                    "#{name} expected 406, got #{head.lines.first}"
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: text/html\r\n\r\n")
        head2, body2 = resource_read(s)
        assert_true head2.start_with?('HTTP/1.1 200'),
                    "#{name} expected 200, got #{head2.lines.first}"
        assert_true body2.include?('html'), "#{name} sent no body: #{body2.inspect}"
        # RFC 9110 12.5.1: the wildcards, because the konst tier weighs a
        # type it keeps for its own head - and that one carries a charset
        # parameter, which no media range ever matches.
        [['*/*', '*/*'], ['text/*', 'text/*'],
         ['a q-list', 'image/png;q=0.9, text/html;q=0.2'],
         ['a browser Accept',
          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8']].each do |what, av|
          s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: #{av}\r\n\r\n")
          h, b = resource_read(s)
          assert_true h.start_with?('HTTP/1.1 200'),
                      "#{name} on #{what}: #{h.lines.first}"
          assert_true b.include?('html'), "#{name} on #{what} sent no body"
        end
      end
    end
  end
end

assert('resource: a class-form resource with two types negotiates like an instance one') do
  # #201: `def self.content_types_provided` defines no callback, so the fold
  # used to leave the resource konst - and the konst tier knows only the
  # FIRST type. A client asking for the second got the first one's bytes
  # under the first one's Content-Type.
  src = <<~RUBY
    class ClassConneg < Webmachine::Resource
      def self.content_types_provided
        [['text/html', :to_html], ['application/json', :to_json]]
      end
      def self.to_html
        '<html>HTML</html>'
      end
      def self.to_json
        '{"form":"class"}'
      end
    end
  RUBY
  resource_server(wm_app('ClassConneg', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_true head.match?(%r{^Content-Type: application/json\r$}i),
                  "wrong type for the second handler: #{head.inspect}"
      assert_equal '{"form":"class"}', body
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: text/html\r\n\r\n")
      head2, body2 = resource_read(s)
      assert_true head2.start_with?('HTTP/1.1 200'), head2.lines.first.to_s
      assert_equal '<html>HTML</html>', body2
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: image/png\r\n\r\n")
      head3, = resource_read(s)
      assert_true head3.start_with?('HTTP/1.1 406'), head3.lines.first.to_s
    end
  end
end

assert('resource: a baked body survives the resource becoming dynamic') do
  # helpers.rb encode_body and #201: the fold renders a `def self.to_html`
  # once and the konst tier serves the bake. One instance callback anywhere
  # binds the resource, and the run then owed the writer a body it never
  # handed over - the page went out as Content-Length: 0.
  src = <<~RUBY
    class BakedBody < Webmachine::Resource
      def self.to_html
        '<html>BAKED</html>'
      end
      def generate_etag
        'e-1'
      end
    end
  RUBY
  resource_server(wm_app('BakedBody', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_true head.match?(/^ETag: "e-1"\r$/i), "no ETag: #{head.inspect}"
      assert_true head.match?(%r{^Content-Type: text/html}i), "no type: #{head.inspect}"
      assert_equal '<html>BAKED</html>', body
    end
  end
end

# #30: the flow says generate_etag, last_modified and expires choose no
# edge. So a run starts every declared one at the same moment, waits
# once, and the answers reach the headers.
assert('compute: a round answers ETag and Last-Modified at one stop (#30)') do
  src = <<~RUBY_SRC
    class ComputeRound < Webmachine::Resource
      compute :generate_etag, :last_modified
      def self.generate_etag
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { 'from-a-worker' }
      end
      def self.last_modified
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { 1_000_000_000 }
      end
      def to_html; 'body'; end
    end
  RUBY_SRC
  resource_server(wm_app('ComputeRound', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_true head.include?('ETag: "from-a-worker"')
      assert_true head.include?('Last-Modified: Sun, 09 Sep 2001 01:46:40 GMT')
      assert_equal 'body', body
    end
  end
end

# The same round, and the conditional request it answers: If-None-Match
# reads the ETag a worker spelled.
assert('compute: a round answers a conditional request (#30)') do
  src = <<~RUBY_SRC
    class ComputeRoundCond < Webmachine::Resource
      compute :generate_etag
      def self.generate_etag
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { 'w-etag' }
      end
      def to_html; 'body'; end
    end
  RUBY_SRC
  resource_server(wm_app('ComputeRoundCond', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"w-etag\"\r\n\r\n")
      head, _ = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 304')
    end
  end
end

# #30: the run's own scratch on the response. The server never looks at
# it - it is storage, and the run is its whole life.
assert('response: what one callback keeps, another one reads (#30)') do
  src = <<~RUBY_SRC
    class Kept < Webmachine::Resource
      def is_authorized?(_h)
        response[:who] = 'from is_authorized?'
        response[:count] = 41
        true
      end
      def to_html
        "\#{response[:who]}/\#{response[:count] + 1}/\#{response.key?(:nothing)}"
      end
    end
  RUBY_SRC
  resource_server(wm_app('Kept', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = resource_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_equal 'from is_authorized?/42/false', body
    end
  end
end

# Two requests on ONE connection: what the first kept is gone.
assert('response: the scratch is one run long (#30)') do
  src = <<~RUBY_SRC
    class KeptTwice < Webmachine::Resource
      def to_html
        was = response[:seen].nil? ? 'nothing' : response[:seen]
        response[:seen] = 'first'
        was
      end
    end
  RUBY_SRC
  resource_server(wm_app('KeptTwice', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, first = resource_read(s)
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, second = resource_read(s)
      assert_equal 'nothing', first
      assert_equal 'nothing', second
    end
  end
end
