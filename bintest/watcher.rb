require 'socket'
require 'tempfile'

WA_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(WA_BIN)

def wa_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s"
  s.readpartial(maxlen)
end

def wa_body(app_source)
  src = Tempfile.new(['wm-wa', '.rb'])
  src.write(app_source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-wa', '.mrb'])
  mrb.close
  raise "mrbc failed:\n#{app_source}" unless system(mrbc, '-o', mrb.path, src.path)
  sock = "/tmp/wm-wa-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-wa-err-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, WA_BIN, '--unix', sock, '--app', mrb.path,
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    UNIXSocket.open(sock) do |c|
      c.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head = +''
      head << wa_recv(c) until head.end_with?("\r\n\r\n")
      len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
      body = +''
      body << wa_recv(c, len - body.bytesize) while body.bytesize < len
      body
    end
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    src.unlink
    mrb.unlink
  end
end

# #30: a Watcher is a DESCRIPTION - a source, what to wait for, and what
# to do when that happens. Building one arms nothing, so all of this can
# be asked without a reactor being involved at all.
assert('watcher: it describes, and it says no to what it cannot describe') do
  out = wa_body(<<~RUBY)
    class Probe < Webmachine::Resource
      def self.to_html
        r, w = IO.pipe
        lines = []
        begin
          watcher = Webmachine::Watcher.new(r, :r) { |revents, self_| }
          lines << "source:\#{watcher.source.fileno == r.fileno}"
          # events is what was ORDERED. :r is the default.
          lines << "events:\#{watcher.events}"
          watcher.events = :rw
          lines << "changed:\#{watcher.events}"
          # Running on is the default; stopping is the one word.
          lines << "aborted:\#{watcher.aborted?}"
          watcher.abort
          lines << "then:\#{watcher.aborted?}"
          begin
            watcher.events = :sideways
          rescue ArgumentError => e
            lines << "order:\#{e.message}"
          end
          begin
            Webmachine::Watcher.new('not a socket', :r) { }
          rescue ArgumentError => e
            lines << "source_type:\#{e.message}"
          end
          begin
            Webmachine::Watcher.new(r, :r)
          rescue ArgumentError => e
            lines << "no_block:\#{e.message}"
          end
        ensure
          r.close
          w.close
        end
        lines.join("\\n")
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes { |route| route.add [], Probe }
      end
    end
  RUBY

  assert_true out.include?('source:true'), out
  assert_true out.include?('events:r'), out
  assert_true out.include?('changed:rw'), out
  assert_true out.include?('aborted:false'), out
  assert_true out.include?('then:true'), out
  # The order menu is :r, :w, :rw and nothing else - what ARRIVES is a
  # wider set, which is why the two do not share a name.
  assert_true out.include?('order:a watcher waits for :r, :w or :rw'), out
  # A source is something with a descriptor, refused where the mistake
  # was made rather than somewhere inside the reactor.
  assert_true out.include?('source_type:a watcher watches something with a fileno'), out
  assert_true out.include?('no_block:a watcher without a block'), out
end
