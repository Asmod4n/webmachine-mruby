require 'socket'
require 'tempfile'

SHED_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(SHED_BIN)

# A resource that costs a measurable slice of the reactor's core, so the
# completions of everything else pile up behind it. Nothing else in this
# tree is slow enough on purpose.
SHED_APP = <<~RUBY unless defined?(SHED_APP)
  class SlowFloor < Webmachine::Resource
    def to_html
      i = 0
      i += 1 while i < 200_000
      'OK'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes { |route| route.add [:*], SlowFloor }
    end
  end
RUBY

def shed_app
  return $shed_app if $shed_app
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  rb = "/tmp/wm-shed-app-#{$$}.rb"
  mrb = "/tmp/wm-shed-app-#{$$}.mrb"
  File.write(rb, SHED_APP)
  system(mrbc, '-o', mrb, rb) or raise 'mrbc failed to compile the shed app'
  File.unlink(rb) rescue nil
  $shed_app = mrb
end

# The smallest ring the kernel will give out, so "three quarters of the
# completion queue" is six completions rather than fifty thousand: the
# arithmetic under test is the same one a real ring runs.
assert('shed: a reactor that is behind says so, once a second') do
  cfg = Tempfile.new(['wm-shed', '.toml'])
  cfg.write("[tune]\nsq_entries = 4\n")
  cfg.close
  err = Tempfile.new(['wm-shed-err', '.log'])
  srv = TCPServer.new('127.0.0.1', 0)
  port = srv.addr[1]
  srv.close

  pid = spawn({ 'WM_BUNDLE' => '0' }, SHED_BIN, "--app=#{shed_app}", "--port=#{port}",
              "--config=#{cfg.path}", out: File::NULL, err: err.path)
  begin
    up = false
    100.times do
      begin
        TCPSocket.new('127.0.0.1', port).close
        up = true
        break
      rescue StandardError
        sleep 0.05
      end
    end
    assert_true up, 'the server never came up'
    req = "GET / HTTP/1.1\r\nHost: shed\r\n\r\n" * 16
    threads = 16.times.map do
      Thread.new do
        begin
          s = TCPSocket.new('127.0.0.1', port)
          s.write(req)
          sleep 2
          s.close
        rescue StandardError
          nil
        end
      end
    end
    threads.each(&:join)
    text = File.read(err.path)
    assert_include text, 'overloaded'
    assert_include text, 'of 8 completions waiting'
    # Once a second at most: the notice must not become the load.
    said = text.scan(/overloaded/).size
    assert_true said <= 4, "said it #{said} times in ~2 seconds"
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
    cfg.unlink
    err.unlink
  end
end
