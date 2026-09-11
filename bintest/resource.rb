
require 'socket'
require 'etc'
require 'tempfile'

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

def resource_refused(app_source)
  app = wm_compile(app_source)
  err = "/tmp/wm-res-stderr-#{$$}.log"
  pid = spawn(WM_BIN, "--app=#{app.path}", out: File::NULL, err: err)
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
  pid = spawn(WM_BIN, "--app=#{src.path}", out: File::NULL, err: err)
  Process.wait(pid)
  raise 'server came up but must have refused the .rb path' if $?.exitstatus == 0
  [File.read(err), src.path]
ensure
  src.unlink
end

assert('resource: hello world serves its rendered body, typed, VM silent') do
  wm_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
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
      head3, = wm_read(s)
      assert_true head3.start_with?('HTTP/1.1 405')
    end
  end
end

# Note (#201, fixed): these are the answers of both tiers. They used to be
# the engine's alone - the konst tier answered 200 to a POST with no
# process_post and to a PUT with no content_types_accepted, because n11 and
# o14/p3 are action nodes and a fold performs no action. A resource that
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
  wm_server(wm_app('WideResource', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      # RFC 9110 9.3.3 / fsm.rb n11: a POST that is not a create and has no
      # process_post is the app's mistake, and it is named as one.
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 500'), "POST expected 500, got #{head.lines.first}"
      # RFC 9112 6.6: this resource reads no body, so the answer ended
      # the connection and the rest of this test needs a new one.
      assert_true head.match?(/^Connection: close\r$/i), head
    end
    UNIXSocket.open(sock) do |s|
      # RFC 9110 15.3.5 / fsm.rb o20: nothing set a body, so no entity.
      s.write("DELETE / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2 = +''
      head2 << wm_recv(s) until head2.end_with?("\r\n\r\n")
      assert_true head2.start_with?('HTTP/1.1 204'), "DELETE expected 204, got #{head2.lines.first}"
      s.write("PUT / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head3, = wm_read(s)
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
  wm_server(wm_app('DownResource', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = wm_read(s)
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
  wm_server(wm_app('GhostResource', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 404')
      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-Match: *\r\n\r\n")
      head2, = wm_read(s)
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
  wm_server(wm_app('ComputeNoBlock', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, _ = wm_read(s)
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
  wm_server(wm_app('ComputeAuth', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic eA==\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_equal 'answered by a worker', body
    end
  end
end

# #80: a run that parks reads its request after it resumes: the path, the
# fields and the body. They were in the recv buffer, and that buffer is
# the kernel's again while the run waits. A second request on another
# connection lands in it meanwhile, so a view left pointing there would
# answer the other request's bytes.
assert('compute: a parked run reads its own request after it resumes (#80)') do
  src = <<~RUBY
    class ParkedReads < Webmachine::Resource
      reads_body :process_post
      compute :is_authorized?
      def self.is_authorized?(_header)
        Webmachine::ComputeTask.new(max_runtime: 2.s) do
          t = Time.now
          nil while Time.now - t < 0.3
          true
        end
      end
      def self.allowed_methods
        %w[GET HEAD POST]
      end
      def to_html
        "\#{request.path}|\#{request.headers['x-probe']}|\#{request.query['q']}"
      end
      def process_post
        response.body = "\#{request.path}|\#{request.headers['x-probe']}|\#{request.body.read}"
        true
      end
    end
  RUBY
  wm_server(wm_app('ParkedReads', src)) do |sock|
    a = UNIXSocket.open(sock)
    a.write("GET /alpha?q=1 HTTP/1.1\r\nHost: x\r\nX-Probe: first\r\n\r\n")
    sleep 0.05
    # The second request, while the first waits: its bytes take the
    # buffer the first one was read into.
    UNIXSocket.open(sock) do |b|
      b.write("GET /beta?q=2 HTTP/1.1\r\nHost: x\r\nX-Probe: second\r\n\r\n")
      _, body = wm_read(b)
      assert_equal '/beta|second|2', body
    end
    _, body = wm_read(a)
    assert_equal '/alpha|first|1', body
    a.write("POST /gamma HTTP/1.1\r\nHost: x\r\nX-Probe: third\r\n" \
            "Content-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
    sleep 0.05
    UNIXSocket.open(sock) do |b|
      b.write("GET /delta?q=4 HTTP/1.1\r\nHost: x\r\nX-Probe: fourth\r\n\r\n")
      wm_read(b)
    end
    _, body = wm_read(a)
    assert_equal '/gamma|third|hello', body
    a.close
  end
end

# #80: a peer that leaves while its run is parked leaves nothing behind:
# not the frame, not its roots, not the park bit. Sixteen park slots per
# connection slot, so twenty leaving peers on the same slot would take
# every bit for good if the reset kept them.
assert('compute: a peer that leaves mid-park frees its park slot (#80)') do
  src = <<~RUBY
    class ParkLeave < Webmachine::Resource
      compute :is_authorized?
      def self.is_authorized?(_header)
        Webmachine::ComputeTask.new(max_runtime: 2.s) do
          t = Time.now
          nil while Time.now - t < 0.05
          true
        end
      end
      def to_html; 'still here'; end
    end
  RUBY
  wm_server(wm_app('ParkLeave', src)) do |sock|
    20.times do
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        # Gone before the worker answers.
      end
      sleep 0.01
    end
    sleep 0.3
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head
      assert_equal 'still here', body
    end
  end
end

# #30: response.userdata travels with the parked run and not with the
# resource. Another request on the route meanwhile has its own.
assert('compute: userdata set before a park is the same run\'s after it (#30)') do
  src = <<~RUBY
    class ParkUser < Webmachine::Resource
      compute :is_authorized?
      def service_available?
        response.userdata = request.headers['x-who']
        true
      end
      def self.is_authorized?(_header)
        Webmachine::ComputeTask.new(max_runtime: 2.s) do
          t = Time.now
          nil while Time.now - t < 0.3
          true
        end
      end
      def to_html
        response.userdata.to_s
      end
    end
  RUBY
  wm_server(wm_app('ParkUser', src)) do |sock|
    a = UNIXSocket.open(sock)
    a.write("GET / HTTP/1.1\r\nHost: x\r\nX-Who: alpha\r\n\r\n")
    sleep 0.05
    UNIXSocket.open(sock) do |b|
      b.write("GET / HTTP/1.1\r\nHost: x\r\nX-Who: beta\r\n\r\n")
      _, body = wm_read(b)
      assert_equal 'beta', body
    end
    _, body = wm_read(a)
    assert_equal 'alpha', body
    a.close
  end
end

# A recv completion for a slot that closed still returns its buffer to
# the pool. Many connections that send and leave at once, then a request
# that must still find a buffer.
assert('http1: buffers of a closed slot go back to the pool') do
  src = <<~RUBY
    class Buffers < Webmachine::Resource
      def self.to_html; 'buffers'; end
    end
  RUBY
  wm_server(wm_app('Buffers', src)) do |sock|
    wrote = 0
    refused = 0
    5000.times do
      begin
        UNIXSocket.open(sock) do |s|
          s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
          wrote += 1
        end
      rescue Errno::ENOTCONN, Errno::EPIPE, Errno::ECONNRESET
        # A client that connects and leaves at once, faster than the
        # server reads, can have its socket reset before the write
        # lands: the listen backlog is finite and the kernel refuses
        # the rest. That is this loop's own doing and not the server's,
        # and it is what a sanitizer build on a two core runner meets.
        # What the case measures is the buffer a closed slot gives
        # back, and the request below is what reads it.
        refused += 1
      end
    end
    # Not all of them, but not none either: a server that refused every
    # connection would otherwise pass this case by answering one.
    assert_true wrote > 2500, "only #{wrote} of 5000 connections wrote, #{refused} were refused"
    # The loop leaves the accept queue full, and the server is one
    # thread. The next connection can meet a reset while the server
    # still walks the 5000 that came before it, and a sanitizer build
    # on a two core runner walks them slowly. So the request that
    # measures the pool waits for the server to catch up, rather than
    # counting the queue it filled itself as a failure.
    head = nil
    body = nil
    tries = 0
    while head.nil? && tries < 200
      tries += 1
      begin
        UNIXSocket.open(sock) do |s|
          s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
          head, body = wm_read(s)
        end
      rescue Errno::ENOTCONN, Errno::EPIPE, Errno::ECONNRESET
        head = nil
        sleep 0.05
      end
    end
    assert_false head.nil?, "the server did not answer in #{tries} tries after the loop"
    assert_true head.start_with?('HTTP/1.1 200'), head
    assert_equal 'buffers', body
  end
end

assert('compute: the second request on a server is answered like the first (#80)') do
  src = <<~RUBY
    class ComputeTwice < Webmachine::Resource
      compute :is_authorized?
      def self.is_authorized?(header)
        Webmachine::ComputeTask.new(header, max_runtime: 500.ms) { |h| !h.nil? }
      end
      def to_html; 'again'; end
    end
  RUBY
  wm_server(wm_app('ComputeTwice', src)) do |sock|
    3.times do
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic eA==\r\n\r\n")
        head, body = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), head
        assert_equal 'again', body
      end
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
  wm_server(wm_app('ComputeTooSlow', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, _ = wm_read(s)
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
  wm_server(wm_app('ComputeRaises', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, _ = wm_read(s)
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
  wm_server(wm_app('KonstDate', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, _ = wm_read(s)
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
  wm_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body1 = wm_read(s)
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body2 = wm_read(s)
      assert_equal '<html><body>hit 1</body></html>', body1
      assert_equal '<html><body>hit 2</body></html>', body2
      s.write("HEAD / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
      hh = +''
      hh << wm_recv(s) until hh.end_with?("\r\n\r\n")
      assert_true hh.match?(/^Content-Length: 31\r$/i), hh
      nxt, body4 = wm_read(s)
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
  wm_server(wm_app('Flaky', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head1, = wm_read(s)
      assert_true head1.start_with?('HTTP/1.1 200')
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = wm_read(s)
      assert_true head2.start_with?('HTTP/1.1 404')
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head3, = wm_read(s)
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
  wm_server(wm_app('Boom', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 500')
      assert_true head.match?(%r{^Content-Type: text/html; charset=utf-8\r$}i)
      assert_true body.include?('boom'), body
    end
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = wm_read(s)
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

assert('resource: a class not on a route never answers - the route is the door') do
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
  wm_server(wm_app('Served', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, body = wm_read(s)
      assert_equal '<html><body>served</body></html>', body
    end
  end
end

assert('resource: a .rb path is refused by name, with the mrbc line that fixes it (#100)') do
  out, rb_path = resource_refused_rb("class NotCompiled < Webmachine::Resource; end\n")
  assert_true out.include?(rb_path), out
  mrb_path = "#{rb_path[0..-4]}.mrb"
  assert_true out.include?("mrbc -g -o #{mrb_path} #{rb_path}"), out
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
  wm_server(wm_app('Clocked', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      2.times do
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        head, body = wm_read(s)
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
  wm_server(wm_app('Churn', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      200.times do |i|
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        _, body = wm_read(s)
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
  wm_server(wm_app('GcBoom', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      3.times do
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        head, body = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 500')
        assert_true body.include?('gcboom'), body
      end
    end
  end
end

assert('run frame: RSS stays flat across 8000 runtime requests') do
  skip 'a sanitizer keeps freed blocks, so resident memory grows by design' if WM_SANITIZER_BUILD
  src = File.read(File.expand_path('../examples/counter.rb', __dir__))
  wm_server(src) do |sock, pid|
    rss = -> { File.read("/proc/#{pid}/status")[/^VmRSS:\s*(\d+)/, 1].to_i }
    UNIXSocket.open(sock) do |s|
      run = lambda do |n|
        n.times do
          s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
          wm_read(s)
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

assert('resource: the instance is the request\'s - ivars never cross, always carry') do
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
  wm_server(wm_app('Scope', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      3.times do
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        _, body = wm_read(s)
        assert_equal 'seen=1', body
      end
    end
  end
end

# RFC 9110 8.3 / 12.5.1: an instance-level content_types_provided is a value
# the fold cannot know, so the prebuilt head cannot carry its Content-Type
# and the run has to spell its own head. With one pair and no Accept there
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
  wm_server(wm_app('OneType', WM_INSTANCE_CT)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
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
# provided types (so Vary), generate_etag, last_modified and expires, all
# on the class, so the fold bakes every one of those fields into the head.
assert('resource: the conditional example spells its caching fields, then answers 304') do
  src = File.read(File.expand_path('../examples/conditional.rb', __dir__))
  wm_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
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
      jh, jb = wm_read(s)
      assert_true jh.match?(%r{^Content-Type: application/json\r$}i), jh
      assert_equal '{"title":"Conditional"}', jb
    end
  end
end

# cb.rb: a value callback written as `def self.x` answers on the class. The
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
  wm_server(wm_app('ClassCb', WM_CLASS_CB)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
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
# field_value_ok, and this asks for that at the wire - a spliced field
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
  wm_server(wm_app('Splicer', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
      head, = wm_read(s)
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
  wm_server(wm_app('Setter', src)) do |sock|
    [['name', true], ['value', true], ['plain', false]].each do |mode, must_fail|
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nX-Mode: #{mode}\r\nConnection: close\r\n\r\n")
        head, = wm_read(s)
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
  # RFC 9110 12.5.1 / 15.5.7, and #201: c4 is the client's question. The
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
    wm_server(wm_app(name, src)) do |sock|
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: image/png\r\n\r\n")
        head, = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 406'),
                    "#{name} expected 406, got #{head.lines.first}"
        s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: text/html\r\n\r\n")
        head2, body2 = wm_read(s)
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
          h, b = wm_read(s)
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
  # first type. A client asking for the second got the first one's bytes
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
  wm_server(wm_app('ClassConneg', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_true head.match?(%r{^Content-Type: application/json\r$}i),
                  "wrong type for the second handler: #{head.inspect}"
      assert_equal '{"form":"class"}', body
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: text/html\r\n\r\n")
      head2, body2 = wm_read(s)
      assert_true head2.start_with?('HTTP/1.1 200'), head2.lines.first.to_s
      assert_equal '<html>HTML</html>', body2
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: image/png\r\n\r\n")
      head3, = wm_read(s)
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
  wm_server(wm_app('BakedBody', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
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
  wm_server(wm_app('ComputeRound', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_true head.include?('ETag: "from-a-worker"')
      assert_true head.include?('Last-Modified: Sun, 09 Sep 2001 01:46:40 GMT')
      assert_equal 'body', body
    end
  end
end

# The same round, and the conditional request it answers: If-None-Match
# reads the ETag a worker spelled.
assert('compute: a value round starts on every request, not on the first only (#30)') do
  src = <<~RUBY
    class EtagEveryTime < Webmachine::Resource
      compute :generate_etag
      def self.generate_etag
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { 'every-time' }
      end
      def to_html; 'x'; end
    end
  RUBY
  wm_server(wm_app('EtagEveryTime', src)) do |sock|
    3.times do
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        head, _ = wm_read(s)
        assert_true head.match?(/^ETag: "every-time"\r$/i), head
      end
    end
  end
end

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
  wm_server(wm_app('ComputeRoundCond', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"w-etag\"\r\n\r\n")
      head, _ = wm_read(s)
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
        response.userdata = { who: 'from is_authorized?', count: 41 }
        true
      end
      def to_html
        u = response.userdata
        "\#{u[:who]}/\#{u[:count] + 1}"
      end
    end
  RUBY_SRC
  wm_server(wm_app('Kept', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_equal 'from is_authorized?/42', body
    end
  end
end

# Two requests on one connection: what the first kept is gone.
assert('response: the scratch is one run long (#30)') do
  src = <<~RUBY_SRC
    class KeptTwice < Webmachine::Resource
      def to_html
        was = response.userdata.nil? ? 'nothing' : response.userdata
        response.userdata = 'first'
        was
      end
    end
  RUBY_SRC
  wm_server(wm_app('KeptTwice', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, first = wm_read(s)
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      _, second = wm_read(s)
      assert_equal 'nothing', first
      assert_equal 'nothing', second
    end
  end
end

# #30: response.userdata crosses to the worker and comes back. CBOR
# carries it both ways, and only a slot the worker changed is read.
assert('compute: the worker reads response.userdata and leaves something else (#30)') do
  src = <<~RUBY_SRC
    class ComputeUser < Webmachine::Resource
      compute :is_authorized?
      def service_available?
        response.userdata = 'from the run'
        true
      end
      def self.is_authorized?(_h)
        Webmachine::ComputeTask.new(max_runtime: 500.ms) do
          response.userdata = "worker saw \#{response.userdata}"
          true
        end
      end
      def to_html
        response.userdata
      end
    end
  RUBY_SRC
  wm_server(wm_app('ComputeUser', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200')
      assert_equal 'worker saw from the run', body
    end
  end
end

# #80: a worker runs its jobs one after another. A job queued behind a
# long one starts its clock when it starts, not when it was queued, and
# a deadline that fires names the job it belongs to. Every worker gets
# one long job, and one more waits behind one of them: all answer 200.
assert('compute: a job queued behind a long one keeps its own deadline (#80)') do
  src = <<~RUBY_SRC
    class ComputeQueued < Webmachine::Resource
      compute :is_authorized?
      def self.is_authorized?(_header)
        Webmachine::ComputeTask.new(max_runtime: 250.ms) do
          t0 = Chrono::Steady.now
          nil while Chrono::Steady.now - t0 < 0.15
          true
        end
      end
      def to_html; 'queued'; end
    end
  RUBY_SRC
  cores = Etc.respond_to?(:nprocessors) ? Etc.nprocessors : 2
  workers = cores > 1 ? cores - 1 : 1
  wm_server(wm_app('ComputeQueued', src)) do |sock|
    conns = (workers + 1).times.map { UNIXSocket.open(sock) }
    conns.each { |s| s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n") }
    conns.each do |s|
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_equal 'queued', body
      s.close
    end
  end
end

# RFC 9112 9.3.2: a request that arrives while a run is parked waits,
# and the answers leave in the order the requests came.
assert('compute: a request received behind a parked run is answered after it (#80)') do
  src = <<~RUBY_SRC
    class ComputeThenNext < Webmachine::Resource
      compute :is_authorized?
      def self.is_authorized?(_header)
        Webmachine::ComputeTask.new(max_runtime: 2.s) do
          t0 = Chrono::Steady.now
          nil while Chrono::Steady.now - t0 < 0.2
          true
        end
      end
      def to_html
        request.path.delete_prefix("/")
      end
    end
  RUBY_SRC
  wm_server(wm_app('ComputeThenNext', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /first HTTP/1.1\r\nHost: x\r\n\r\n")
      sleep 0.05
      s.write("GET /second HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_equal 'first', body
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_equal 'second', body
    end
  end
end

# RFC 9110 5.5: a Location with CR or LF would splice a field into the
# head. response.redirect_to refuses it by name, and the run answers 500.
assert('response.redirect_to refuses a location with CRLF; response.code= refuses a number out of range') do
  src = <<~'APP'
    class Refuser < Webmachine::Resource
      def to_html
        case request.headers['x-mode']
        when 'crlf' then response.redirect_to("http://x/\r\nX-Injected: yes")
        when 'high' then response.code = 1000
        when 'low' then response.code = 99
        when 'ok' then response.code = 202   # in range: taken, and the graph still decides
        end
        '<html><body>hi</body></html>'
      end
    end
  APP
  wm_server(wm_app('Refuser', src)) do |sock|
    [['crlf', '500'], ['high', '500'], ['low', '500'], ['ok', '200'], ['none', '200']].each do |mode, want|
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\nX-Mode: #{mode}\r\nConnection: close\r\n\r\n")
        head, body = wm_read(s)
        assert_false head.include?('X-Injected'), "#{mode} spliced a field in:\n#{head}"
        assert_true head.start_with?("HTTP/1.1 #{want}"), "#{mode}: expected #{want}, got #{head[0, 60]}"
        if mode == 'crlf'
          assert_true body.include?('CR, LF or NUL'), body
        elsif want == '500'
          assert_true body.include?('100 through 599'), body
        end
      end
    end
  end
end

# RFC 9110 5.3: a field that came on several lines is one list. Two
# Cookie lines reach request.cookies as one cookie string, two
# If-None-Match lines are one list for the conditional, and the named
# accessor spells the joined list.
assert('request: repeated Cookie and If-None-Match lines are joined') do
  src = <<~'APP'
    class Joined < Webmachine::Resource
      def generate_etag
        'b'
      end
      def to_html
        c = request.cookies
        "#{c['a']}|#{c['b']}|#{request.if_none_match}|#{request.base_uri}"
      end
    end
  APP
  wm_server(wm_app('Joined', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nCookie: a=1\r\nCookie: b=2\r\n" \
              "If-None-Match: \"z\"\r\nIf-None-Match: \"y\"\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_equal '1|2|"z", "y"|http://x/', body
      # The ETag is on the second line: still a match, still 304.
      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: \"z\"\r\nIf-None-Match: \"b\"\r\n\r\n")
      head, _ = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 304'), head.lines.first.to_s
    end
  end
end

# The class app.routes yields is named, so a worker's VM running this
# gem's init leaves the reactor's class alone (#80). A compute route
# still answers after the workers opened.
assert('application: the routes object is a Webmachine::Routes, and compute keeps answering') do
  src = <<~RUBY_SRC
    class RoutesNamed < Webmachine::Resource
      compute :is_authorized?
      def self.is_authorized?(_h)
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { true }
      end
      def to_html
        Webmachine::Routes.name
      end
    end
  RUBY_SRC
  wm_server(wm_app('RoutesNamed', src)) do |sock|
    3.times do
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        head, body = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
        assert_equal 'Webmachine::Routes', body
      end
    end
  end
end

# #80: a node callback named in `compute` and written on the class is
# asked per request, through a worker, and never folded at start.
assert('compute: a class-level node callback is not folded, and answers per request') do
  src = <<~RUBY_SRC
    class ComputeNode < Webmachine::Resource
      compute :service_available?
      def self.service_available?
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { true }
      end
      def to_html; 'up'; end
    end
  RUBY_SRC
  wm_server(wm_app('ComputeNode', src)) do |sock|
    2.times do
      UNIXSocket.open(sock) do |s|
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        head, body = wm_read(s)
        assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
        assert_equal 'up', body
      end
    end
  end
end

# #80: a worker whose VM cannot be built stays at its ring and answers
# every job as a fault, so the request gets its 503 and nothing waits
# for an answer that never comes. The failure itself is on stderr.
assert('compute: a worker that cannot build its registry answers 503, not silence') do
  src = <<~RUBY_SRC
    Webmachine::Workers::Registry[:broken] = proc { raise 'no handle here' }

    class ComputeNoWorker < Webmachine::Resource
      compute :is_authorized?
      def self.is_authorized?(_h)
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { true }
      end
      def to_html; 'x'; end
    end
  RUBY_SRC
  wm_server(wm_app('ComputeNoWorker', src)) do |sock, _pid, errlog|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, _ = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 503'), head.lines.first.to_s
      assert_true head.match?(/^Retry-After: 60\r$/i), head
    end
    err = File.read(errlog) rescue ''
    assert_true err.include?('Registry[broken] could not be built'), err
    assert_true err.include?('no handle here'), err
  end
end

# RFC 9457: a client that asks for JSON gets a problem document, spelled
# by mruby-fast-json. It parses, it carries type, title, status and the
# detail, and a quote or a newline in the message survives the escaping.
assert('error page: the JSON problem document parses, with its fields escaped') do
  require 'json'
  src = <<~'APP'
    class Broken < Webmachine::Resource
      # Before the negotiation, so the Accept below picks the page's
      # type and not the resource's.
      def service_available?
        raise "bad \"quote\"\nsecond line"
      end
      def to_html
        'never'
      end
    end
  APP
  wm_server(wm_app('Broken', src)) do |sock|
    wm_conn(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept: application/json\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 500'), head.lines.first.to_s
      # RFC 6839 3.1: a client that asked for application/json gets it as
      # that; one that asked for problem+json gets problem+json.
      assert_true head.match?(%r{^Content-Type: application/(problem\+)?json}i), head
      doc = JSON.parse(body)
      assert_equal 'about:blank', doc['type']
      assert_equal 500, doc['status']
      assert_equal 'Internal Server Error', doc['title']
      assert_true doc['detail'].include?("bad \"quote\"\nsecond line"), doc.inspect
      assert_true doc.key?('id'), doc.inspect
    end
  end
end

# A callback that carries an argument asks about this request, so it can
# never be konst-folded, however it is defined. Two requests to one
# server, one long path and one short: a folded answer would give both
# the same status.
assert('resource: a class-level uri_too_long? is asked per request') do
  src = <<~RUBY
    class LongPath < Webmachine::Resource
      def self.uri_too_long?(uri)
        uri.length > 20
      end

      def self.to_html
        'short enough'
      end
    end
  RUBY
  wm_server(wm_app('LongPath', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET /short HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK'), head
      assert_equal 'short enough', body
    end
    UNIXSocket.open(sock) do |s|
      s.write("GET /a-path-that-is-longer-than-twenty HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = wm_read(s)
      assert_true head.start_with?('HTTP/1.1 414'), head
    end
  end
end

# #54: every stop this server makes is declared. compute names the
# callbacks a worker answers, watch the ones a descriptor answers, and
# reads_body the ones that wait for octets.
assert('resource: a callback that reads the body must say so') do
  src = <<~RUBY_APP
    class Undeclared < Webmachine::Resource
      def self.allowed_methods
        %w[GET POST]
      end
      def process_post
        true
      end
    end

    class Fine < Webmachine::Resource
      def self.to_html
        'fine'
      end
    end

    def main
      Webmachine::Application.new do |app|
        begin
          app.add_route [:*], Undeclared
        rescue Webmachine::RouteError => e
          puts "refused=\#{e.message}"
        end
        app.add_route [:*], Fine
      end
    end
  RUBY_APP
  wm_server(src, tag: 'wm-declare') do |_sock, _pid, _err, out|
    text = File.read(out)
    assert_true text.include?('refused='), text
    assert_true text.include?('reads_body :process_post'), text
  end
end

assert('resource: reads_body refuses a name that reads no body, and one that is not defined') do
  src = <<~RUBY_APP
    class NotAReader < Webmachine::Resource
      reads_body :is_authorized?
      def self.to_html
        'no'
      end
    end

    class NotDefined < Webmachine::Resource
      reads_body :process_post
      def self.to_html
        'no'
      end
    end

    class Fine < Webmachine::Resource
      def self.to_html
        'fine'
      end
    end

    def main
      Webmachine::Application.new do |app|
        begin
          app.add_route ['a'], NotAReader
        rescue Webmachine::RouteError => e
          puts "one=\#{e.message}"
        end
        begin
          app.add_route ['b'], NotDefined
        rescue Webmachine::RouteError => e
          puts "two=\#{e.message}"
        end
        app.add_route [:*], Fine
      end
    end
  RUBY_APP
  wm_server(src, tag: 'wm-declare-bad') do |_sock, _pid, _err, out|
    text = File.read(out)
    assert_true text.include?('one='), text
    assert_true text.include?('reads no request body'), text
    assert_true text.include?('two='), text
    assert_true text.include?('does not define it'), text
  end
end
