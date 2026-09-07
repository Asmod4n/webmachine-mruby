
require 'socket'
require 'tempfile'

ZC_BIG = ('START' + ('abcdefghij' * 19_999) + 'ENDEND').freeze
ZC_SMALL = ('S4K' + ('zyxwvutsrq' * 399) + 'E4K4').freeze

def zc_app
  <<~RUBY
    class ZcBig < Webmachine::Resource
      def to_html
        'START' + ('abcdefghij' * 19_999) + 'ENDEND'
      end
    end
    class ZcSmall < Webmachine::Resource
      def to_html
        'S4K' + ('zyxwvutsrq' * 399) + 'E4K4'
      end
    end
    # A body the app kept: already frozen, so it may be shared, so it is
    # copied however high the threshold says to lend.
    ZC_KEPT = ('START' + ('abcdefghij' * 19_999) + 'ENDEND').freeze
    class ZcFrozen < Webmachine::Resource
      def to_html
        ZC_KEPT
      end
    end
    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['big'], ZcBig
          route.add ['small'], ZcSmall
          route.add ['kept'], ZcFrozen
        end
      end
    end
  RUBY
end

def zc_serve(threshold = nil, &block)
  sock = "/tmp/wm-zc-#{$$}-#{threshold.inspect.gsub(/\W/, '')}.sock"
  args = threshold.nil? ? [] : ["--zero-copy-threshold=#{threshold.to_s}"]
  wm_server(zc_app, *args, sock: sock, tag: 'wm-zc', &block)
end

def zc_get(sock, target)
  wm_conn(sock) do |s|
    wm_request(s, target)
    wm_read(s)
  end
end

assert('zero-copy: a lent body is byte-identical to a copied one') do
  lent = nil
  copied = nil
  zc_serve(1) { |sock| lent = zc_get(sock, '/big') }
  zc_serve(0) { |sock| copied = zc_get(sock, '/big') }
  assert_include lent[0], '200 OK'
  assert_include copied[0], '200 OK'
  assert_equal ZC_BIG.bytesize, lent[1].bytesize
  assert_equal ZC_BIG, lent[1]
  assert_equal copied[1], lent[1]
  assert_include lent[0], "Content-Length: #{ZC_BIG.bytesize}\r\n"
end

assert('zero-copy: the built-in default lends the big body and copies the small') do
  zc_serve do |sock|
    big = zc_get(sock, '/big')
    small = zc_get(sock, '/small')
    assert_equal ZC_BIG, big[1]
    assert_equal ZC_SMALL, small[1]
  end
end

assert('zero-copy: keep-alive releases between rounds') do
  zc_serve(1) do |sock|
    s = UNIXSocket.new(sock)
    8.times do
      s.write "GET /big HTTP/1.1\r\nHost: zc\r\n\r\n"
      head, body = wm_read(s)
      assert_include head, '200 OK'
      assert_equal ZC_BIG, body
    end
    s.close
    true
  end
end

assert('zero-copy: a lent body splits a pipelined round correctly') do
  zc_serve(1) do |sock|
    s = UNIXSocket.new(sock)
    s.write "GET /big HTTP/1.1\r\nHost: zc\r\n\r\n" \
            "GET /small HTTP/1.1\r\nHost: zc\r\n\r\n" \
            "GET /big HTTP/1.1\r\nHost: zc\r\n\r\n"
    h1, b1 = wm_read(s)
    h2, b2 = wm_read(s)
    h3, b3 = wm_read(s)
    s.close
    assert_include h1, '200 OK'
    assert_include h2, '200 OK'
    assert_include h3, '200 OK'
    assert_equal ZC_BIG, b1
    assert_equal ZC_SMALL, b2
    assert_equal ZC_BIG, b3
  end
end

assert('zero-copy: HEAD spells the length and lends nothing') do
  zc_serve(1) do |sock|
    s = UNIXSocket.new(sock)
    s.write "HEAD /big HTTP/1.1\r\nHost: zc\r\nConnection: close\r\n\r\n"
    head = +''.b
    head << wm_recv(s, 1) until head.end_with?("\r\n\r\n")
    rest = begin
      s.read_nonblock(4096)
    rescue StandardError
      ''
    end
    s.close
    assert_include head, '200 OK'
    assert_include head, "Content-Length: #{ZC_BIG.bytesize}\r\n"
    assert_equal '', rest.to_s
  end
end

assert('zero-copy: a String the app froze is copied, not lent') do
  zc_serve(1) do |sock|
    s = UNIXSocket.new(sock)
    2.times do
      s.write "GET /kept HTTP/1.1\r\nHost: zc\r\n\r\n"
      head, body = wm_read(s)
      assert_include head, '200 OK'
      assert_equal ZC_BIG, body
    end
    s.close
    true
  end
end

assert('zero-copy: [tune] zero_copy_threshold is read from the config file') do
  sock = "/tmp/wm-zc-toml-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  app = wm_compile(wm_listen(zc_app, sock), 'wm-zcapp')
  cfg = Tempfile.new(['wm-zc', '.toml'])
  cfg.write("[server]\napp = \"#{app.path}\"\n\n" \
            "[tune]\nzero_copy_threshold = 1024\n")
  cfg.close
  err = "/tmp/wm-zc-toml-stderr-#{$$}.log"
  pid = spawn(WM_BIN, "--config=#{cfg.path}",
              out: File::NULL, err: err)
  begin
    200.times do
      break if File.socket?(sock)
      sleep 0.05
    end
    unless File.socket?(sock)
      raise "server never came up:\n#{begin File.read(err) rescue '' end}"
    end
    head, body = zc_get(sock, '/small')
    assert_include head, '200 OK'
    assert_equal ZC_SMALL, body
  ensure
    Process.kill(:TERM, pid) rescue nil
    Process.waitpid(pid) rescue nil
    app.unlink
    cfg.unlink
    File.unlink(sock) rescue nil
  end
end

assert('zero-copy: a threshold outside the range refuses the start') do
  err = "/tmp/wm-zc-bad-#{$$}.log"
  cfg = Tempfile.new(['wm-zcbad', '.toml'])
  cfg.write("[server]\nunix = \"/tmp/wm-zc-never-#{$$}.sock\"\n\n" \
            "[tune]\nzero_copy_threshold = -1\n")
  cfg.close
  pid = spawn(WM_BIN, "--config=#{cfg.path}",
              out: File::NULL, err: err)
  Process.waitpid(pid)
  ok = $?.exitstatus == 2
  assert_true ok
  assert_include File.read(err), 'zero_copy_threshold'
ensure
  cfg&.unlink
  File.unlink(err) rescue nil
end


def zch2_block(method, path)
  "\x02".b + method.bytesize.chr + method + "\x86".b +
    "\x04".b + path.bytesize.chr + path + "\x41\x0b".b + 'example.com'
end

def zch2_settings(initial_window)
  [4, initial_window].pack('nN')
end

def zch2_handshake(s, initial_window = 1_048_576, conn_credit = 4_194_304)
  h2_handshake(s, zch2_settings(initial_window))
  s.write(h2_frame(8, 0, 0, [conn_credit].pack('N'))) if conn_credit > 0
end

def zch2_collect(s, streams)
  out = {}
  streams.each { |i| out[i] = +''.b }
  done = {}
  until done.size == streams.size
    type, flags, st, payload = h2_next(s)
    raise "GOAWAY mid-body: #{payload.inspect}" if type == 7
    raise "RST_STREAM #{st}: #{payload.inspect}" if type == 3
    next unless type == 0
    out[st] << payload if out.key?(st)
    done[st] = true if out.key?(st) && (flags & 0x01) != 0
  end
  out
end

assert('zero-copy h2: a lent body is byte-identical to a copied one') do
  lent = nil
  copied = nil
  zc_serve(1) do |sock|
    UNIXSocket.open(sock) do |s|
      zch2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, zch2_block('GET', '/big')))
      lent = zch2_collect(s, [1])[1]
    end
  end
  zc_serve(0) do |sock|
    UNIXSocket.open(sock) do |s|
      zch2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, zch2_block('GET', '/big')))
      copied = zch2_collect(s, [1])[1]
    end
  end
  assert_equal ZC_BIG.bytesize, lent.bytesize
  assert_equal ZC_BIG, lent
  assert_equal copied, lent
end

assert('zero-copy h2: a lent body survives flow control across rounds') do
  zc_serve(1) do |sock|
    UNIXSocket.open(sock) do |s|
      zch2_handshake(s, 16_384, 0)
      s.write(h2_frame(1, 0x05, 1, zch2_block('GET', '/big')))
      body = +''.b
      rounds = 0
      until body.bytesize >= ZC_BIG.bytesize
        type, _, st, payload = h2_next(s)
        raise "GOAWAY: #{payload.inspect}" if type == 7
        next unless type == 0 && st == 1
        body << payload
        rounds += 1
        s.write(h2_frame(8, 0, 0, [16_384].pack('N')) +
                h2_frame(8, 0, 1, [16_384].pack('N')))
      end
      assert_true rounds > 1, "expected several DATA frames, got #{rounds}"
      assert_equal ZC_BIG, body
      s.write(h2_frame(1, 0x05, 3, zch2_block('GET', '/small')))
      s.write(h2_frame(8, 0, 3, [1_048_576].pack('N')))
      assert_equal ZC_SMALL, zch2_collect(s, [3])[3]
    end
  end
end

assert('zero-copy h2: two streams lend at once and close in either order') do
  zc_serve(1) do |sock|
    UNIXSocket.open(sock) do |s|
      zch2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, zch2_block('GET', '/big')) +
              h2_frame(1, 0x05, 3, zch2_block('GET', '/big')) +
              h2_frame(1, 0x05, 5, zch2_block('GET', '/small')))
      got = zch2_collect(s, [1, 3, 5])
      assert_equal ZC_BIG, got[1]
      assert_equal ZC_BIG, got[3]
      assert_equal ZC_SMALL, got[5]
      s.write(h2_frame(1, 0x05, 7, zch2_block('GET', '/small')))
      assert_equal ZC_SMALL, zch2_collect(s, [7])[7]
    end
  end
end

assert('zero-copy h2: RST_STREAM mid-body releases the lend') do
  zc_serve(1) do |sock|
    UNIXSocket.open(sock) do |s|
      zch2_handshake(s, 16_384, 0)
      s.write(h2_frame(1, 0x05, 1, zch2_block('GET', '/big')))
      loop do
        type, _, st, = h2_next(s)
        break if type == 0 && st == 1
      end
      s.write(h2_frame(3, 0, 1, [8].pack('N')))
      s.write(h2_frame(1, 0x05, 3, zch2_block('GET', '/big')))
      s.write(h2_frame(8, 0, 0, [4_194_304].pack('N')) +
              h2_frame(8, 0, 3, [4_194_304].pack('N')))
      assert_equal ZC_BIG, zch2_collect(s, [3])[3]
    end
  end
end

assert('zero-copy h2: HEAD lends nothing and sends no DATA') do
  zc_serve(1) do |sock|
    UNIXSocket.open(sock) do |s|
      zch2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, zch2_block('HEAD', '/big')))
      type, flags, st, = h2_next(s)
      assert_equal 1, type
      assert_equal 1, st
      assert_equal 1, flags & 0x01
      s.write(h2_frame(1, 0x05, 3, zch2_block('GET', '/small')))
      assert_equal ZC_SMALL, zch2_collect(s, [3])[3]
    end
  end
end

assert('zero-copy h2: a String the app froze is copied, not lent') do
  zc_serve(1) do |sock|
    UNIXSocket.open(sock) do |s|
      zch2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, zch2_block('GET', '/kept')))
      assert_equal ZC_BIG, zch2_collect(s, [1])[1]
      s.write(h2_frame(1, 0x05, 3, zch2_block('GET', '/kept')))
      assert_equal ZC_BIG, zch2_collect(s, [3])[3]
    end
  end
end
