# The mruby bridge, proven on the wire: a Ruby resource class registers
# itself via Webmachine.resource=, decides the flow's konst answers at
# setup, and the requests that follow never enter the VM. Refusals are
# named at startup, never silent.

require 'socket'
require 'tempfile'

BRIDGE_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(BRIDGE_BIN)

# Runs a server bound to the given app source; raises if it never comes up.
def bridge_server(app_source)
  app = Tempfile.new(['wm-app', '.rb'])
  app.write(app_source)
  app.close
  sock = "/tmp/wm-bridge-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-bridge-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, BRIDGE_BIN, '--unix', sock, '--app', app.path,
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
def bridge_refused(app_source)
  app = Tempfile.new(['wm-app', '.rb'])
  app.write(app_source)
  app.close
  err = "/tmp/wm-bridge-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, BRIDGE_BIN, '--unix', "/tmp/wm-bridge-#{$$}.sock",
              '--app', app.path, out: File::NULL, err: err)
  Process.wait(pid)
  raise 'server came up but must have refused' if $?.exitstatus == 0
  File.read(err)
ensure
  app.unlink
end

def bridge_read(s)
  head = +''
  head << s.readpartial(1) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''
  body << s.readpartial(len - body.bytesize) while body.bytesize < len
  [head, body]
end

assert('bridge: a Ruby resource widens allowed_methods and the flow obeys') do
  src = <<~RUBY
    class WideResource
      def allowed_methods
        %w[GET HEAD POST DELETE]
      end
      def delete_resource
        true
      end
      def delete_completed?
        true
      end
    end
    Webmachine.resource = WideResource
  RUBY
  bridge_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      # POST is allowed now: B10 passes, the flow runs to 200 via P11/O20.
      s.write("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head, = bridge_read(s)
      assert_true head.start_with?('HTTP/1.1 200'), "POST expected 200, got #{head.lines.first}"
      # DELETE runs M16 -> M20 (delete_resource true) -> M20b -> O20 -> 200.
      s.write("DELETE / HTTP/1.1\r\nHost: x\r\n\r\n")
      head2, = bridge_read(s)
      assert_true head2.start_with?('HTTP/1.1 200'), "DELETE expected 200, got #{head2.lines.first}"
      # PUT stays outside the list: 405 whose Allow line is Ruby's list.
      s.write("PUT / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
      head3, = bridge_read(s)
      assert_true head3.start_with?('HTTP/1.1 405')
      assert_true head3.match?(/^Allow: GET, HEAD, POST, DELETE\r$/i)
    end
  end
end

assert('bridge: service_available? false turns every request into 503 (B13)') do
  src = <<~RUBY
    class DownResource
      def service_available?
        false
      end
    end
    Webmachine.resource = DownResource
  RUBY
  bridge_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = bridge_read(s)
      assert_true head.start_with?('HTTP/1.1 503')
    end
  end
end

assert('bridge: a missing resource speaks 404/412 like the graph says') do
  src = <<~RUBY
    class GhostResource
      def resource_exists?
        false
      end
    end
    Webmachine.resource = GhostResource
  RUBY
  bridge_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, = bridge_read(s)
      assert_true head.start_with?('HTTP/1.1 404')  # G7 -> H7 -> I7 -> K7 -> L7
      s.write("GET / HTTP/1.1\r\nHost: x\r\nIf-Match: *\r\n\r\n")
      head2, = bridge_read(s)
      assert_true head2.start_with?('HTTP/1.1 412')  # H7: If-Match * on missing
    end
  end
end

assert('bridge: tier-1-only callbacks refuse the start by name') do
  src = <<~RUBY
    class EtagResource
      def generate_etag
        'v1'
      end
    end
    Webmachine.resource = EtagResource
  RUBY
  assert_true bridge_refused(src).include?('generate_etag')
end

assert('bridge: an app that raises at load refuses the start with the error') do
  assert_true bridge_refused("raise 'kaputt'").include?('kaputt')
end

assert('bridge: an app that never registers is refused with the missing call named') do
  assert_true bridge_refused("class Quiet; end").include?('Webmachine.resource')
end
