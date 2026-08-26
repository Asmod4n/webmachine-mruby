
require 'socket'
require 'tempfile'
require 'zlib'

H2_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(H2_BIN)
H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b unless defined?(H2_PREFACE)

def wm_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def wm_compile(app_source)
  src = Tempfile.new(['wm-h2app', '.rb'])
  src.write(app_source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-h2app', '.mrb'])
  mrb.close
  ok = system(mrbc, '-o', mrb.path, src.path)
  raise "mrbc failed to compile:\n#{app_source}" unless ok
  mrb
ensure
  src&.unlink
end

def h2_app(name, src)
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

def h2_server(app_source = nil)
  args = []
  app = nil
  if app_source
    app = wm_compile(app_source)
    args = ['--app', app.path]
  end
  sock = "/tmp/wm-h2-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-h2-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, H2_BIN, '--unix', sock, *args, out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "h2 server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app&.unlink
  end
end

def h2_read_exact(s, n)
  buf = +''.b
  buf << wm_recv(s, n - buf.bytesize) while buf.bytesize < n
  buf
end

def h2_frame(type, flags, stream, payload = ''.b)
  len = payload.bytesize
  [(len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff, type, flags].pack('C5') +
    [stream].pack('N') + payload
end

def h2_next(s)
  h = h2_read_exact(s, 9)
  len = (h.getbyte(0) << 16) | (h.getbyte(1) << 8) | h.getbyte(2)
  payload = len > 0 ? h2_read_exact(s, len) : ''.b
  [h.getbyte(3), h.getbyte(4), h[5, 4].unpack1('N') & 0x7fffffff, payload]
end

def h2_get_block
  "\x82\x86\x84\x41\x0fwww.example.com".b
end

def h2_method_block(method)
  "\x02#{method.bytesize.chr}#{method}\x86\x84\x41\x0bexample.com".b
end

def h2_path_block(path)
  "\x82\x86\x04#{path.bytesize.chr}#{path}\x41\x0bexample.com".b
end

def h2_handshake(s, settings = ''.b)
  s.write(H2_PREFACE + h2_frame(4, 0, 0, settings))
  t, f, st, = h2_next(s)
  raise "expected server SETTINGS, got type #{t}" unless t == 4 && f == 0 && st == 0
  t, f, = h2_next(s)
  raise "expected SETTINGS ACK, got type #{t}/#{f}" unless t == 4 && f == 1
end

assert('h2: the preface upgrades, a GET answers 200 in frames, streams multiplex') do
  h2_server do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      type, flags, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 1, stream
      assert_true (flags & 0x04) != 0, 'END_HEADERS missing'
      assert_equal 0x88, block.getbyte(0)
      type, flags, stream, data = h2_next(s)
      assert_equal 0, type
      assert_equal 1, stream
      assert_true (flags & 0x01) != 0, 'END_STREAM missing on DATA'
      assert_equal 'OK', data
      s.write(h2_frame(1, 0x05, 3, "\x82\x86\x84\xbe".b))
      type, _, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 3, stream
      assert_equal 0x88, block.getbyte(0)
      type, _, stream, data = h2_next(s)
      assert_equal 0, type
      assert_equal 3, stream
      assert_equal 'OK', data
    end
    UNIXSocket.open(sock) do |s|
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head = +''
      head << wm_recv(s) until head.end_with?("\r\n\r\n")
      assert_true head.start_with?('HTTP/1.1 200 OK')
    end
  end
end

assert('h2: PING echoes, unknown frame types are ignored, oversize dies with GOAWAY') do
  h2_server do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(0xdd, 0, 0, 'x' * 8))
      s.write(h2_frame(6, 0, 0, '12345678'))
      type, flags, _, payload = h2_next(s)
      assert_equal 6, type
      assert_equal 1, flags & 1
      assert_equal '12345678', payload
    end
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write([0x00, 0x40, 0x01, 0x00, 0x00].pack('C5') + [1].pack('N'))
      type, _, stream, payload = h2_next(s)
      assert_equal 7, type
      assert_equal 0, stream
      assert_equal 6, payload[4, 4].unpack1('N')
      assert_raise(EOFError) { h2_read_exact(s, 1) }
    end
  end
end

assert('h2: a resource answers typed bodies, HEAD sends no DATA, POST is 405') do
  h2_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      type, _, _, block = h2_next(s)
      assert_equal 1, type
      assert_equal 0x88, block.getbyte(0)
      _, flags, _, data = h2_next(s)
      assert_equal '<html><body>Hello, World!</body></html>', data
      assert_equal 1, flags & 1
      s.write(h2_frame(1, 0x05, 3, h2_method_block('HEAD')))
      type, flags, stream, = h2_next(s)
      assert_equal 1, type
      assert_equal 3, stream
      assert_true (flags & 0x01) != 0, 'HEAD must END_STREAM on HEADERS'
      s.write(h2_frame(1, 0x05, 5, h2_method_block('POST')))
      type, flags, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 5, stream
      assert_true (flags & 0x01) != 0
      assert_not_equal 0x88, block.getbyte(0)
    end
  end
end

assert('h2: the run frame answers per request, exceptions speak 500 with their reason') do
  counter = File.read(File.expand_path('../examples/counter.rb', __dir__))
  h2_server(counter) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      _, _, _, block = h2_next(s)
      assert_equal 0x88, block.getbyte(0)
      _, _, _, data = h2_next(s)
      assert_equal '<html><body>hit 1</body></html>', data
      s.write(h2_frame(1, 0x05, 3, "\x82\x86\x84\xbe".b))
      h2_next(s)
      _, _, _, data = h2_next(s)
      assert_equal '<html><body>hit 2</body></html>', data
    end
  end
  boom = <<~RUBY
    class Boom < Webmachine::Resource
      def to_html
        raise 'boom'
      end
    end
  RUBY
  h2_server(h2_app('Boom', boom)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      type, _, _, block = h2_next(s)
      assert_equal 1, type
      assert_not_equal 0x88, block.getbyte(0)
      _, flags, _, data = h2_next(s)
      assert_true data.include?('boom'), data
      assert_equal 1, flags & 1
      s.write(h2_frame(6, 0, 0, 'still-up!'[0, 8]))
      type, flags, = h2_next(s)
      assert_equal 6, type
      assert_equal 1, flags & 1
    end
  end
end

assert('h2: a request body is counted, credited and discarded; END_STREAM dispatches') do
  src = <<~RUBY
    class WideResource < Webmachine::Resource
      def self.allowed_methods
        'GET HEAD POST'
      end
    end
  RUBY
  h2_server(h2_app('WideResource', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x04, 1, h2_method_block('POST')))
      s.write(h2_frame(0, 0x00, 1, 'a' * 100))
      s.write(h2_frame(0, 0x01, 1, 'b' * 50))
      frames = []
      6.times { frames << h2_next(s) }
      updates = frames.select { |t, _, _, _| t == 8 }
      assert_equal 4, updates.size
      headers = frames.find { |t, _, _, _| t == 1 }
      assert_true headers != nil, 'no HEADERS answer after END_STREAM'
      assert_equal 0x88, headers[3].getbyte(0)
    end
  end
end

assert('h2: an exhausted window parks DATA, WINDOW_UPDATE drains it (9113 6.9)') do
  h2_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write(H2_PREFACE + h2_frame(4, 0, 0, [4, 20].pack('nN')))
      t, f, = h2_next(s)
      raise 'expected server SETTINGS' unless t == 4 && f == 0
      t, f, = h2_next(s)
      raise 'expected SETTINGS ACK' unless t == 4 && f == 1
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      type, flags, = h2_next(s)
      assert_equal 1, type
      assert_equal 0, flags & 1
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 20, data.bytesize
      assert_equal 0, flags & 1
      s.write(h2_frame(8, 0, 1, [64].pack('N')))
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 19, data.bytesize
      assert_equal 1, flags & 1
    end
  end
end

assert('h2: a drained stream is debited for what it already sent (9113 6.9.1)') do
  h2_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write(H2_PREFACE + h2_frame(4, 0, 0, [4, 20].pack('nN')))
      t, f, = h2_next(s)
      raise 'expected server SETTINGS' unless t == 4 && f == 0
      t, f, = h2_next(s)
      raise 'expected SETTINGS ACK' unless t == 4 && f == 1
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      h2_next(s)
      type, _, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 20, data.bytesize
      s.write(h2_frame(8, 0, 1, [10].pack('N')))
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 10, data.bytesize, 'stream window was not debited for the first 20 bytes'
      assert_equal 0, flags & 1, 'nine bytes still owed - END_STREAM must wait'
      s.write(h2_frame(8, 0, 1, [64].pack('N')))
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 9, data.bytesize
      assert_equal 1, flags & 1
    end
  end
end

assert('h2: a merged answer pays the connection window too (9113 6.9.1)') do
  app = <<~RUBY
    class Big < Webmachine::Resource
      def self.to_html
        'x' * 1000
      end
    end
  RUBY
  h2_server(h2_app('Big', app)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      sid = 1
      65.times do
        s.write(h2_frame(1, 0x05, sid, h2_get_block))
        t, = h2_next(s)
        raise "expected HEADERS, got #{t}" unless t == 1
        t, _, _, data = h2_next(s)
        raise "expected DATA, got #{t}" unless t == 0
        raise "short DATA: #{data.bytesize}" unless data.bytesize == 1000
        sid += 2
      end
      s.write(h2_frame(1, 0x05, sid, h2_get_block))
      type, flags, = h2_next(s)
      assert_equal 1, type
      assert_equal 0, flags & 1, 'body is owed - END_STREAM must wait'
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 535, data.bytesize, 'merged answers did not pay the connection window'
      assert_equal 0, flags & 1
      s.write(h2_frame(8, 0, 0, [4096].pack('N')))
      type, flags, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 465, data.bytesize
      assert_equal 1, flags & 1
    end
  end
end

if `curl --version 2>/dev/null`.include?('HTTP2')
  assert('h2: curl --http2-prior-knowledge round-trips against the same listener') do
    h2_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
      body = `curl -sS --max-time 10 --http2-prior-knowledge --unix-socket #{sock} http://localhost/`
      assert_equal '<html><body>Hello, World!</body></html>', body
    end
  end
end

assert('h2: the router is the SAME table - each route keeps its own body, a miss is 404') do
  src = <<~RUBY
    class Alpha < Webmachine::Resource
      def self.to_html
        'alpha'
      end
    end
    class Beta < Webmachine::Resource
      def self.allowed_methods
        'GET HEAD POST'
      end
      def self.to_html
        'beta'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['alpha'], Alpha
          route.add ['beta', :*], Beta
        end
      end
    end
  RUBY
  h2_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_path_block('/alpha')))
      type, _, _, block = h2_next(s)
      assert_equal 1, type
      assert_equal 0x88, block.getbyte(0)
      _, _, _, data = h2_next(s)
      assert_equal 'alpha', data
      s.write(h2_frame(1, 0x05, 3, h2_path_block('/beta/one/two')))
      type, _, _, block = h2_next(s)
      assert_equal 1, type
      assert_equal 0x88, block.getbyte(0)
      _, _, _, data = h2_next(s)
      assert_equal 'beta', data
      s.write(h2_frame(1, 0x05, 5, h2_path_block('/nowhere')))
      type, flags, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 5, stream
      assert_equal 0x8d, block.getbyte(0)
      assert_equal 1, flags & 1, 'a bodyless 404 must end the stream on HEADERS'
      s.write(h2_frame(1, 0x05, 7, "\x02\x03PUT\x86\x04\x06/alpha\x41\x0bexample.com".b))
      type, _, _, block = h2_next(s)
      assert_equal 1, type
      assert_true block.include?('GET, HEAD'), block.inspect
      assert_false block.include?('POST'), block.inspect
      s.write(h2_frame(1, 0x05, 9, "\x02\x03PUT\x86\x04\x05/beta\x41\x0bexample.com".b))
      type, _, _, block = h2_next(s)
      assert_equal 1, type
      assert_true block.include?('GET, HEAD, POST'), block.inspect
    end
  end
end

def h2_method_path_block(method, path)
  "\x02#{method.bytesize.chr}#{method}\x86\x04#{path.bytesize.chr}#{path}\x41\x0bexample.com".b
end

assert('h2: a parked request still names what its route captured') do
  src = <<~RUBY
    class Parked < Webmachine::Resource
      def self.allowed_methods
        'GET HEAD POST'
      end

      # RFC 9110 9.3.3: a POST is answered by process_post - which is
      # where a parked request's captures get read.
      def process_post
        r = request
        response.body = "\#{r.path}|\#{r.path_info[:id]}|\#{r.disp_path}"
        true
      end
    end
  RUBY
  app = <<~RUBY
    #{src}
    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['thing', :id, :*], Parked
        end
      end
    end
  RUBY
  h2_server(app) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x04, 1, h2_method_path_block('POST', '/thing/42/tail')))
      s.write(h2_frame(0, 0x01, 1, 'body'))
      frames = []
      4.times { frames << h2_next(s) }
      data = frames.find { |t, _, _, _| t == 0 }
      assert_true data != nil, 'no DATA answer after END_STREAM'
      assert_equal '/thing/42/tail|42|tail', data[3]
    end
  end
end

assert('h2: a fumbled preface is GOAWAY, a foreign one is h1 400 (9113 3.4)') do
  h2_server do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n".b)
      type, flags, stream, payload = h2_next(s)
      assert_equal 7, type
      assert_equal 0, flags
      assert_equal 0, stream
      assert_equal 8, payload.bytesize
      assert_equal 0, payload[0, 4].unpack1('N')
      assert_equal 1, payload[4, 4].unpack1('N')
      assert_equal '', s.read
    end
    UNIXSocket.open(sock) do |s|
      s.write("PRI * HTTP/2.0\r\n".b)
      assert_nil IO.select([s], nil, nil, 0.5), 'a partial preface was answered too early'
    end
    UNIXSocket.open(sock) do |s|
      s.write("INVALID CONNECTION PREFACE\r\n\r\n".b)
      head = +''
      head << wm_recv(s) until head.include?("\r\n\r\n")
      assert_true head.start_with?('HTTP/1.1 400 Bad Request'), head[0, 40]
      assert_true head.include?('Connection: close')
    end
  end
end

def h2_stored_zip(entries)
  out = +''.b
  cd = +''.b
  dtime = (12 << 11) | (4 << 5) | 3
  ddate = ((2025 - 1980) << 9) | (3 << 5) | 1
  entries.each do |name, data|
    crc = Zlib.crc32(data)
    lho = out.bytesize
    out << [0x04034b50, 20, 0, 0, dtime, ddate, crc, data.bytesize, data.bytesize,
            name.bytesize, 0].pack('VvvvvvVVVvv') << name.b << data.b
    cd << [0x02014b50, 20, 20, 0, 0, dtime, ddate, crc, data.bytesize, data.bytesize,
           name.bytesize, 0, 0, 0, 0, 0, lho].pack('VvvvvvvVVVvvvvvVV') << name.b
  end
  cd_off = out.bytesize
  out << cd
  out << [0x06054b50, 0, 0, entries.size, entries.size, cd.bytesize, cd_off, 0].pack('VvvvvVVv')
  out
end

def h2_asset_server(zip_bytes)
  zf = Tempfile.new(['wm-h2assets', '.zip'])
  zf.binmode
  zf.write(zip_bytes)
  zf.close
  sock = "/tmp/wm-h2a-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-h2a-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, H2_BIN, '--unix', sock, '--assets', zf.path,
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "h2 asset server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    zf.unlink
  end
end

assert('h2: two big assets share the rounds and arrive byte-exact (#168)') do
  a = ((0..250).to_a.pack('C*') * 35_857)[0, 9_000_000].b
  b = ((5..255).to_a.pack('C*') * 35_857)[0, 9_000_000].b
  h2_asset_server(h2_stored_zip([['a.bin', a], ['b.bin', b]])) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s, [4, 16 << 20].pack('nN'))
      s.write(h2_frame(8, 0, 0, [1 << 30].pack('N')))
      s.write(h2_frame(1, 0x5, 1, h2_path_block('/a.bin')))
      s.write(h2_frame(1, 0x5, 3, h2_path_block('/b.bin')))
      got = { 1 => +''.b, 3 => +''.b }
      done = {}
      order = []
      until done[1] && done[3]
        type, flags, stream, payload = h2_next(s)
        next unless type == 0
        got[stream] << payload
        order << stream
        done[stream] = true if (flags & 1) == 1
      end
      assert_equal a, got[1]
      assert_equal b, got[3]
      first_3 = order.index(3)
      last_1 = order.rindex(1)
      assert_true !first_3.nil? && first_3 < last_1,
                  "one stream took every round: #{order.chunk { |x| x }.map(&:first).inspect}"
    end
  end
end

assert('h2: a header block split across CONTINUATION answers, split at any byte') do
  h2_server do |sock|
    [1, 3, 4, 6, 10, 19].each do |cut|
      UNIXSocket.open(sock) do |s|
        h2_handshake(s)
        blk = h2_get_block
        s.write(h2_frame(1, 0x01, 1, blk[0, cut]))
        s.write(h2_frame(9, 0x04, 1, blk[cut..]))
        type, flags, stream, block = h2_next(s)
        assert_equal 1, type, "cut=#{cut}"
        assert_equal 1, stream, "cut=#{cut}"
        assert_true (flags & 0x04) != 0, "END_HEADERS missing, cut=#{cut}"
        assert_equal 0x88, block.getbyte(0), "cut=#{cut}"
        type, _, _, data = h2_next(s)
        assert_equal 0, type, "cut=#{cut}"
        assert_equal 'OK', data, "cut=#{cut}"
      end
    end
  end
end

assert('h2: a block split across TWO CONTINUATION frames answers') do
  h2_server do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      blk = h2_get_block
      s.write(h2_frame(1, 0x01, 1, blk[0, 2]))
      s.write(h2_frame(9, 0x00, 1, blk[2, 5]))
      s.write(h2_frame(9, 0x04, 1, blk[7..]))
      type, flags, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 1, stream
      assert_true (flags & 0x04) != 0, 'END_HEADERS missing'
      assert_equal 0x88, block.getbyte(0)
      type, _, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal 'OK', data
    end
  end
end

assert('h2: CONTINUATION on a stream the HEADERS did not open is a connection error') do
  h2_server do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      blk = h2_get_block
      s.write(h2_frame(1, 0x01, 1, blk[0, 4]))
      s.write(h2_frame(9, 0x04, 3, blk[4..]))
      type, _, _, payload = h2_next(s)
      assert_equal 7, type
      assert_equal 1, payload[4, 4].unpack1('N')
    end
  end
end

assert('h2: CONTINUATION with no HEADERS before it is a connection error') do
  h2_server do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(9, 0x04, 1, h2_get_block))
      type, _, _, payload = h2_next(s)
      assert_equal 7, type
      assert_equal 1, payload[4, 4].unpack1('N')
    end
  end
end

def h2_lit(name, value)
  "\x00".b + name.bytesize.chr + name.b + value.bytesize.chr + value.b
end

# A DATA frame is answered with WINDOW_UPDATE first (RFC 9113 6.9), so a
# parked stream's HEADERS is not the next frame on the wire.
def h2_until(s, type)
  20.times do
    t, f, st, pay = h2_next(s)
    return [t, f, st, pay] if t == type
  end
  raise "no frame of type #{type} arrived"
end

H2_FIELDS_APP = <<~RUBY unless defined?(H2_FIELDS_APP)
  class Fields < Webmachine::Resource
    def self.allowed_methods
      'GET HEAD POST'
    end

    def to_html
      request.headers.keys.sort.join(',')
    end

    def process_post
      response.body = request.headers.keys.sort.join(',') + '|' + request.body.to_s
      true
    end
  end
RUBY

assert('h2: request.headers answers on an immediate request (RFC 9113 8.3)') do
  h2_server(h2_app('Fields', H2_FIELDS_APP)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      blk = "\x82\x86\x84\x41\x0bexample.com".b + h2_lit('x-probe', 'one')
      s.write(h2_frame(1, 0x05, 1, blk))
      t, = h2_next(s)
      assert_equal 1, t
      t, _, _, data = h2_next(s)
      assert_equal 0, t
      assert_true data.include?('x-probe'), "headers missing: #{data.inspect}"
    end
  end
end

assert('h2: a PARKED request keeps its fields - headers and body both answer') do
  h2_server(h2_app('Fields', H2_FIELDS_APP)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      blk = "\x83\x86\x84\x41\x0bexample.com".b + h2_lit('x-probe', 'two')
      s.write(h2_frame(1, 0x04, 1, blk))
      s.write(h2_frame(0, 0x01, 1, 'hello=1'))
      h2_until(s, 1)
      body = +''.b
      20.times do
        ty, fl, _, pay = h2_next(s)
        next unless ty == 0
        body << pay
        break if (fl & 0x01) != 0
      end
      assert_true body.include?('x-probe'), "parked headers missing: #{body.inspect}"
      assert_true body.include?('hello=1'), "parked body missing: #{body.inspect}"
    end
  end
end

assert('h2: a parked request negotiates on the Accept it actually sent') do
  h2_server(h2_app('Fields', H2_FIELDS_APP)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      ok = "\x83\x86\x84\x41\x0bexample.com".b + h2_lit('accept', 'text/html')
      s.write(h2_frame(1, 0x04, 1, ok))
      s.write(h2_frame(0, 0x01, 1, 'a=1'))
      _, _, _, block = h2_until(s, 1)
      assert_equal 0x88, block.getbyte(0), 'a matching Accept must not be refused'
    end
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      no = "\x83\x86\x84\x41\x0bexample.com".b + h2_lit('accept', 'application/json')
      s.write(h2_frame(1, 0x04, 1, no))
      s.write(h2_frame(0, 0x01, 1, 'a=1'))
      _, _, _, block = h2_until(s, 1)
      assert_not_equal 0x88, block.getbyte(0), 'an unservable Accept must still refuse'
    end
  end
end
