
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
