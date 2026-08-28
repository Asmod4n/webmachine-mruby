
require 'socket'
require 'tempfile'

SERVER_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(SERVER_BIN)

def wm_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def floor_server(bundles: false)
  sock = "/tmp/wm-floor-#{$$}-#{bundles ? 'b' : 'r'}.sock"
  File.unlink(sock) if File.exist?(sock)
  args = [SERVER_BIN, '--unix', sock]
  err = "/tmp/wm-floor-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => bundles ? '1' : '0' }, *args, out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  unless File.socket?(sock)
    Process.kill('TERM', pid) rescue nil
    raise "floor never came up\n#{File.read(err) rescue '(no stderr)'}"
  end
  begin
    yield sock
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
  end
end

assert('floor: a receive is answered 200, keep-alive holds') do
  floor_server do |sock|
    UNIXSocket.open(sock) do |s|
      3.times do
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        head = +''
        head << wm_recv(s) until head.end_with?("\r\n\r\n")
        assert_true head.start_with?('HTTP/1.1 200 OK')
        len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
        body = +''
        body << wm_recv(s, len - body.bytesize) while body.bytesize < len
        assert_equal 'OK', body
      end
    end
  end
end

assert('floor: the ring-built TCP listener answers like the unix one') do
  port = 20000 + ($$ % 20000)
  err = "/tmp/wm-floor-tcp-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, SERVER_BIN, '--port', port.to_s,
              out: File::NULL, err: err)
  begin
    s = nil
    100.times do
      begin
        s = TCPSocket.new('127.0.0.1', port)
        break
      rescue Errno::ECONNREFUSED
        sleep 0.05
      end
    end
    raise "tcp floor never came up\n#{File.read(err) rescue ''}" unless s
    s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    head = +''
    head << wm_recv(s) until head.end_with?("\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 200 OK')
    s.close
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
  end
end

assert('floor: TERM removes the unix socket path') do
  sock = "/tmp/wm-floor-#{$$}-term.sock"
  File.unlink(sock) if File.exist?(sock)
  pid = spawn({ 'WM_BUNDLE' => '0' }, SERVER_BIN, '--unix', sock,
              out: File::NULL, err: File::NULL)
  100.times { break if File.socket?(sock); sleep 0.05 }
  assert_true File.socket?(sock)
  Process.kill('TERM', pid)
  Process.wait(pid)
  assert_false File.exist?(sock)
end
