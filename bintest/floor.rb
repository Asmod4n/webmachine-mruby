# The floor, proven at the byte level before any HTTP exists.
#
# Echo mode is the proof: what the reactor read is what it writes back,
# so a reconstruction bug (the bundle class: claimed length spanning
# buffers that were never filled) shows up as a byte mismatch here, not
# as a corrupted request three layers up.
#
# The standard run forces WM_BUNDLE=0: one known kernel (the CI
# container's 6.18.5-fc) violates the bundle dense-fill contract, and a
# suite must be green everywhere. Real kernels honor it - set
# WM_TEST_BUNDLES=1 there (forgecore, the Pi) and the same assertions
# run again with bundles on, which is exactly the density check.

require 'socket'
require 'tempfile'

SERVER_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(SERVER_BIN)
EPOLL_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-floor-epoll') unless defined?(EPOLL_BIN)

def floor_server(echo: false, bundles: false, bin: SERVER_BIN)
  sock = "/tmp/wm-floor-#{$$}-#{echo ? 'e' : 'r'}#{bundles ? 'b' : ''}#{bin.equal?(SERVER_BIN) ? '' : 'p'}.sock"
  File.unlink(sock) if File.exist?(sock)
  args = [bin, '--unix', sock]
  args << '--echo' if echo
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

def floor_echo_assertions(bundles, bin: SERVER_BIN)
  floor_server(echo: true, bundles: bundles, bin: bin) do |sock|
    UNIXSocket.open(sock) do |s|
      # Many small segments, written with pauses so they arrive as
      # separate receives - the exact traffic shape that caught the
      # bundle bug. Random bytes so an offset error cannot pass as luck.
      sent = +''
      60.times do
        seg = Random.bytes(20)
        s.write(seg)
        sent << seg
        sleep 0.002
      end
      got = +''
      got << s.readpartial(65536) while got.bytesize < sent.bytesize
      assert_equal sent.bytesize, got.bytesize
      assert_equal sent, got
    end
    UNIXSocket.open(sock) do |s|
      # One large write: crosses several pool buffers in one receive.
      blob = Random.bytes(3 * 4096 + 123)
      s.write(blob)
      got = +''
      got << s.readpartial(65536) while got.bytesize < blob.bytesize
      assert_equal blob, got
    end
  end
end

assert('floor: echo returns every byte, small segments and large blobs') do
  floor_echo_assertions(false)
end

assert('floor: a receive is answered 200, keep-alive holds') do
  floor_server do |sock|
    UNIXSocket.open(sock) do |s|
      3.times do
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        head = +''
        head << s.readpartial(1) until head.end_with?("\r\n\r\n")
        assert_true head.start_with?('HTTP/1.1 200 OK')
        len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
        body = +''
        body << s.readpartial(len - body.bytesize) while body.bytesize < len
        assert_equal 'OK', body
      end
    end
  end
end

assert('floor: the ring-built TCP listener answers like the unix one') do
  # bind/listen/setsockopt all ran as ring ops; this proves them on the
  # wire. A pid-derived port keeps parallel suites apart.
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
    head << s.readpartial(1) until head.end_with?("\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 200 OK')
    s.close
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
  end
end

assert('epoll floor: echo returns every byte (the measuring stick answers alike)') do
  floor_echo_assertions(false, bin: EPOLL_BIN)
end

assert('epoll floor: a receive is answered 200, keep-alive holds') do
  floor_server(bin: EPOLL_BIN) do |sock|
    UNIXSocket.open(sock) do |s|
      3.times do
        s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        head = +''
        head << s.readpartial(1) until head.end_with?("\r\n\r\n")
        assert_true head.start_with?('HTTP/1.1 200 OK')
        len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
        body = +''
        body << s.readpartial(len - body.bytesize) while body.bytesize < len
        assert_equal 'OK', body
      end
    end
  end
end

assert('floor: TERM removes the unix socket path') do
  # Seen on the Pi: the path outlived the process because nothing ever
  # left the run loop. The signal now interrupts the ring wait and the
  # destructor unlinks - through the ring, like everything else.
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

if ENV['WM_TEST_BUNDLES'] == '1'
  assert('floor: the same bytes survive with recv bundles on (density check)') do
    floor_echo_assertions(true)
  end
end
