
require 'socket'
require 'tempfile'
require 'zlib'

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

# Every server needs something to serve, so an h2 test that does not name a
# resource gets the smallest one: a splat route with a baked body.
H2_FLOOR_APP = <<~RUBY unless defined?(H2_FLOOR_APP)
  class H2Floor < Webmachine::Resource
    def self.to_html
      'OK'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes { |route| route.add [:*], H2Floor }
    end
  end
RUBY

def h2_server(app_source = nil, *extra_args, &block)
  wm_server(app_source || H2_FLOOR_APP, *extra_args, tag: 'wm-h2', &block)
end

def h2_get_block
  "\x82\x86\x84\x41\x0fwww.example.com".b
end

def h2_lit(name, value)
  "\x00".b + name.bytesize.chr + name.b + value.bytesize.chr + value.b
end

def h2_method_block(method)
  "\x02#{method.bytesize.chr}#{method}\x86\x84\x41\x0bexample.com".b
end

def h2_path_block(path)
  "\x82\x86\x04#{path.bytesize.chr}#{path}\x41\x0bexample.com".b
end

def h2_handshake(s, settings = ''.b)
  s.write(WM_H2_PREFACE + h2_frame(4, 0, 0, settings))
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
      # #210: an error carries a page now, so END_STREAM rides the DATA
      # frame and not the HEADERS - the same shape a 200 with a body has.
      s.write(h2_frame(1, 0x05, 5, h2_method_block('POST')))
      type, flags, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 5, stream
      assert_equal 0, flags & 0x01, '405 carries a page - HEADERS must not end it'
      assert_not_equal 0x88, block.getbyte(0)
      type, flags, stream, data = h2_next(s)
      assert_equal 0, type
      assert_equal 5, stream
      assert_equal 1, flags & 1, 'the page ends the stream'
      assert_include data, '405'
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
      s.write(h2_frame(1, 0x04, 1, h2_method_block('POST') + h2_lit('content-length', '150')))
      s.write(h2_frame(0, 0x00, 1, 'a' * 100))
      s.write(h2_frame(0, 0x01, 1, 'b' * 50))
      frames = []
      6.times { frames << h2_next(s) }
      updates = frames.select { |t, _, _, _| t == 8 }
      assert_equal 4, updates.size
      headers = frames.find { |t, _, _, _| t == 1 }
      assert_true headers != nil, 'no HEADERS answer after END_STREAM'
      # RFC 7541 B: 0x8e is the static entry for :status 500. WideResource
      # allows POST and defines nothing to answer one with (#201) - what this
      # test pins is that the body was still counted, credited and read to the
      # end before the flow said so.
      assert_equal 0x8e, headers[3].getbyte(0)
    end
  end
end

assert('h2: an exhausted window parks DATA, WINDOW_UPDATE drains it (9113 6.9)') do
  h2_server(File.read(File.expand_path('../examples/hello.rb', __dir__))) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write(WM_H2_PREFACE + h2_frame(4, 0, 0, [4, 20].pack('nN')))
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
      s.write(WM_H2_PREFACE + h2_frame(4, 0, 0, [4, 20].pack('nN')))
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

assert('h2: the router is the same table - each route keeps its own body, a miss is 404') do
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
      # #210: the 404 carries a page, so the stream ends on the DATA frame.
      assert_equal 0, flags & 1, '404 carries a page - HEADERS must not end it'
      type, flags, stream, data = h2_next(s)
      assert_equal 0, type
      assert_equal 5, stream
      assert_equal 1, flags & 1, 'the page ends the stream'
      assert_include data, 'Not Found'
      # And it says nothing the client sent: the target it asked for is in
      # the error log, not reflected into a document.
      assert_false data.include?('/nowhere')
      # RFC 9110 15.5.6: the 405 keeps its Allow now that it also carries
      # a page - the DATA frame behind the HEADERS is that page.
      s.write(h2_frame(1, 0x05, 7, "\x02\x03PUT\x86\x04\x06/alpha\x41\x0bexample.com".b))
      type, _, _, block = h2_next(s)
      assert_equal 1, type
      assert_true block.include?('GET, HEAD'), block.inspect
      assert_false block.include?('POST'), block.inspect
      type, _, _, = h2_next(s)
      assert_equal 0, type, 'the 405 page follows its HEADERS'
      s.write(h2_frame(1, 0x05, 9, "\x02\x03PUT\x86\x04\x05/beta\x41\x0bexample.com".b))
      type, _, _, block = h2_next(s)
      assert_equal 1, type
      assert_true block.include?('GET, HEAD, POST'), block.inspect
      type, _, _, = h2_next(s)
      assert_equal 0, type, 'the 405 page follows its HEADERS'
    end
  end
end

def h2_method_path_block(method, path)
  "\x02#{method.bytesize.chr}#{method}\x86\x04#{path.bytesize.chr}#{path}\x41\x0bexample.com".b
end

assert('h2: a parked request still names what its route captured') do
  src = <<~RUBY
    class Parked < Webmachine::Resource
      reads_body :process_post
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
      s.write(h2_frame(1, 0x04, 1, h2_method_path_block('POST', '/thing/42/tail') +
                                   h2_lit('content-length', '4')))
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
  wm_server('--standalone', "--assets=#{zf.path}", app: false, tag: 'wm-h2a') do |sock|
    yield sock
  end
ensure
  zf&.unlink
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

assert('h2: a block split across two CONTINUATION frames answers') do
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
    reads_body :process_post
    def self.allowed_methods
      'GET HEAD POST'
    end

    def to_html
      request.headers.keys.sort.join(',')
    end

    def process_post
      response.body = request.headers.keys.sort.join(',') + '|' + request.body.read.to_s +
                      '|type=' + request.content_type.to_s
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

assert('h2: a parked request keeps its fields - headers and body both answer') do
  h2_server(h2_app('Fields', H2_FIELDS_APP)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      blk = "\x83\x86\x84\x41\x0bexample.com".b + h2_lit('x-probe', 'two') +
            h2_lit('content-length', '7')
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

assert('h2: a parked request answers its named fields too (RFC 9113 8.3)') do
  h2_server(h2_app('Fields', H2_FIELDS_APP)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      blk = "\x83\x86\x84\x41\x0bexample.com".b +
            h2_lit('content-type', 'application/x-www-form-urlencoded') +
            h2_lit('content-length', '3')
      s.write(h2_frame(1, 0x04, 1, blk))
      s.write(h2_frame(0, 0x01, 1, 'a=1'))
      h2_until(s, 1)
      body = +''.b
      20.times do
        ty, fl, _, pay = h2_next(s)
        next unless ty == 0
        body << pay
        break if (fl & 0x01) != 0
      end
      assert_true body.include?('type=application/x-www-form-urlencoded'), body.inspect
    end
  end
end

assert('h2: a parked request negotiates on the Accept it actually sent') do
  h2_server(h2_app('Fields', H2_FIELDS_APP)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      ok = "\x83\x86\x84\x41\x0bexample.com".b + h2_lit('accept', 'text/html') +
           h2_lit('content-length', '3')
      s.write(h2_frame(1, 0x04, 1, ok))
      s.write(h2_frame(0, 0x01, 1, 'a=1'))
      _, _, _, block = h2_until(s, 1)
      assert_equal 0x88, block.getbyte(0), 'a matching Accept must not be refused'
    end
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      no = "\x83\x86\x84\x41\x0bexample.com".b + h2_lit('accept', 'application/json') +
           h2_lit('content-length', '3')
      s.write(h2_frame(1, 0x04, 1, no))
      s.write(h2_frame(0, 0x01, 1, 'a=1'))
      _, _, _, block = h2_until(s, 1)
      assert_not_equal 0x88, block.getbyte(0), 'an unservable Accept must still refuse'
    end
  end
end

# RFC 7541 2.3.3: a dynamic-table insert shifts the index of every older
# entry by one. The head cache freezes an index for content-type and
# replays it for the rest of the second, so anything that inserts in
# between moves what that index points at - and the dynamic path inserts
# freely, for its own date and for every field line an app sets.
#
# The order below is the one that breaks it: konst route (cache built,
# content-type indexed), bound route (inserts), konst route again (cache
# hit). Without the fix the third answer's content-type resolves to
# whatever the insert pushed into that slot.
assert('h2: an insert between two cache hits does not move what the head points at') do
  src = <<~RUBY
    class Konst < Webmachine::Resource
      def self.to_html
        '<p>konst</p>'
      end
    end

    class Bound < Webmachine::Resource
      def to_html
        response.headers['X-Run'] = 'yes'
        '<p>bound</p>'
      end
    end
  RUBY
  app = <<~RUBY
    #{src}
    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['bound'], Bound
          route.add [:*], Konst
        end
      end
    end
  RUBY
  h2_server(app) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      seen = []
      [['/k', 1], ['/bound', 3], ['/k', 5], ['/k', 7]].each do |path, id|
        s.write(h2_frame(1, 0x05, id, h2_method_path_block('GET', path)))
        type, _, _, block = h2_next(s)
        assert_equal 1, type, "stream #{id}: expected HEADERS"
        seen << block
        h2_next(s) # the DATA that follows
      end
      # The two later konst answers are cache hits. Whatever the first
      # one said content-type is, they have to say the same - a moved
      # index shows up as a different byte string here, and as a
      # different header at any real client.
      # RFC 7541 6.2.1: 0x5f is "literal with incremental indexing, name
      # index 31" - content-type being inserted. The value beside it is
      # Huffman-coded, so this is checked by shape and not by looking for
      # "text/html" in the bytes.
      assert_true seen[0].bytes.include?(0x5f),
                  "the first konst head must insert content-type: #{seen[0].inspect}"
      assert_false seen[2].bytes.include?(0x5f),
                   "the later ones must reference it, not insert again: #{seen[2].inspect}"
      assert_equal seen[2], seen[3],
                   'two cache hits in the same second must be the same bytes'
      assert_true seen[2].bytesize < seen[0].bytesize,
                  "the reference must be shorter than the insert: " \
                  "#{seen[2].bytesize} vs #{seen[0].bytesize}"
    end
  end
end

# #210 response.error_asset over h2: the entry is parked as Src::kAsset -
# the same source the asset tier parks a mounted file under - so its octets
# are framed out of the mapping by h2_flush_pending, against the window,
# and never copied into an answer buffer.
H2_EASSET_APP = <<~RUBY unless defined?(H2_EASSET_APP)
  class Teapot < Webmachine::Resource
    def content_types_provided
      [['image/jpeg', :pic]]
    end

    def pic
      response.error_asset('418.jpg')
      ''
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes do |route|
        route.add [:*], Teapot
      end
    end
  end
RUBY

def h2_error_assets_server(pack, &block)
  wm_server(H2_EASSET_APP, "--error-assets=#{pack}", tag: 'wm-h2-ea', &block)
end

def h2_zip_entry(path, name)
  raw = File.binread(path)
  off = 0
  while off + 30 <= raw.bytesize && raw[off, 4] == "PK\x03\x04".b
    csize, _usize, nlen, elen = raw[off + 18, 12].unpack('VVvv')
    found = raw[off + 30, nlen]
    body = raw[off + 30 + nlen + elen, csize]
    return body if found == name
    off += 30 + nlen + elen + csize
  end
  nil
end

assert('h2: response.error_asset parks in the mapping and the window drips it out whole') do
  pack = File.expand_path('../share/error-assets.zip', __dir__)
  skip "no #{pack} - run rake error_assets" unless File.exist?(pack)
  want = h2_zip_entry(pack, '418.jpg')
  assert_true want != nil, 'no 418.jpg in the shipped error assets'

  h2_error_assets_server(pack) do |sock|
    UNIXSocket.open(sock) do |s|
      # SETTINGS_INITIAL_WINDOW_SIZE = 1000: the picture cannot leave in one
      # round, so it has to survive parking - which is the whole claim.
      h2_handshake(s, [4, 1000].pack('nN'))
      s.write(h2_frame(1, 0x05, 1, h2_path_block('/teapot') + h2_lit('accept', 'image/jpeg')))
      t, f, = h2_until(s, 1)
      assert_equal 1, t
      assert_equal 0, f & 0x01, 'the HEADERS ended the stream - no picture followed'

      got = +''.b
      frames = 0
      200.times do
        break if got.bytesize >= want.bytesize
        s.write(h2_frame(8, 0, 1, [2000].pack('N')))
        s.write(h2_frame(8, 0, 0, [2000].pack('N')))
        t2, f2, st2, pay = h2_next(s)
        next unless t2 == 0 && st2 == 1
        got << pay
        frames += 1
        break if (f2 & 0x01) != 0
      end
      # More than one DATA frame, or the window never bit and this proves
      # nothing about parking.
      assert_true frames > 1, "the whole picture left in #{frames} frame(s)"
      assert_equal want.bytesize, got.bytesize
      assert_equal want, got
    end
  end
end

# #30: a stream that stops. The resource declares `watch`, so its run
# parks on a descriptor and the stream is framed when the answer comes
# back. Before this the same resource answered 500 on h2 and 200 on h1.
assert('h2: a watcher parks the stream and the answer comes back (#30)') do
  src = <<~RUBY_SRC
    class H2Watch < Webmachine::Resource
      watch :generate_etag
      def generate_etag
        r, w = IO.pipe
        w.write('x')
        Webmachine::Watcher.new(r, :r, timeout: 2.s) do |_ev, self_|
          r.read(1)
          self_.abort
          'from-a-watcher'
        end
      end
      def to_html
        'parked and back'
      end
    end
  RUBY_SRC
  h2_server(h2_app('H2Watch', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      type, flags, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 1, stream
      assert_true (flags & 0x04) != 0, 'END_HEADERS missing'
      assert_equal 0x88, block.getbyte(0), 'the run must answer 200, not 500'
      type, flags, stream, data = h2_next(s)
      assert_equal 0, type
      assert_equal 1, stream
      assert_equal 'parked and back', data
    end
  end
end

# #30: the same for a compute task. It crosses to a worker, and the
# stream waits instead of running the block on the reactor's thread.
assert('h2: a compute task parks the stream (#30)') do
  src = <<~RUBY_SRC
    class H2Compute < Webmachine::Resource
      compute :is_authorized?
      def is_authorized?(_h)
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { true }
      end
      def to_html
        'answered by a worker'
      end
    end
  RUBY_SRC
  h2_server(h2_app('H2Compute', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      type, _flags, stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 1, stream
      assert_equal 0x88, block.getbyte(0)
      type, _flags, stream, data = h2_next(s)
      assert_equal 0, type
      assert_equal 'answered by a worker', data
    end
  end
end

# WHATWG HTML over RFC 9113: an event stream on one h2 stream. The head
# is HEADERS without END_STREAM, and every tick is DATA on that stream.
# On h1 the same resource answers with chunks (bintest/sse.rb).
H2_SSE_APP = <<~RUBY_SRC unless defined?(H2_SSE_APP)
  class H2Clock < Webmachine::SseResource
    def initialize
      @n = 0
    end

    def on_tick
      @n += 1
      { event: 'tick', id: @n.to_s, data: "n=\#{@n}" }
    end
  end

  class H2SsePage < Webmachine::Resource
    def self.to_html
      'not a stream'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.add_sse ['events'], H2Clock
      app.add_route [:*], H2SsePage
    end
  end
RUBY_SRC

assert('h2: an event stream is HEADERS without END_STREAM, then DATA (#30)') do
  h2_server(H2_SSE_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_path_block('/events')))
      type, flags, stream, _block = h2_next(s)
      assert_equal 1, type, 'HEADERS first'
      assert_equal 1, stream
      assert_true (flags & 0x04) != 0, 'END_HEADERS missing'
      assert_true (flags & 0x01) == 0, 'END_STREAM must not be set on a live stream'
      # The ticks arrive as DATA on the same stream, one per second.
      seen = ''.b
      3.times do
        type, flags, stream, data = h2_next(s)
        break unless type == 0
        assert_equal 1, stream
        assert_true (flags & 0x01) == 0, 'a tick must not end the stream'
        seen << data
        break if seen.include?('id: 2')
      end
      assert_true seen.include?("event: tick\n"), seen
      assert_true seen.include?("data: n=1\n"), seen
    end
  end
end

# RFC 8441: a WebSocket on one h2 stream. The client sends an extended
# CONNECT - :method CONNECT with :protocol websocket, and, unlike a plain
# CONNECT, with :scheme and :path - and the answer is 200, not 101.
H2_WS_APP = <<~RUBY_SRC unless defined?(H2_WS_APP)
  class H2Echo < Webmachine::WebsocketResource
    def on_data(data, binary)
      data
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes { |route| route.websocket ['ws'], H2Echo }
    end
  end
RUBY_SRC

def h2_connect_block(path)
  b = ''.b
  b << "\x40\x07:method\x07CONNECT".b
  b << "\x40\x09:protocol\x09websocket".b
  b << "\x87".b
  b << "\x40\x05:path#{path.bytesize.chr}#{path}".b
  b << "\x41\x0bexample.com".b
  b
end

# The next frame that is not flow-control bookkeeping. A server that
# returns its window (RFC 9113 6.9) sends WINDOW_UPDATE whenever it likes.
def h2_next_payload(s)
  loop do
    type, flags, stream, payload = h2_next(s)
    next if type == 8 || type == 4
    return [type, flags, stream, payload]
  end
end

# RFC 6455 5.2: a client frame is masked; this builds one. RSV1 says the
# payload is compressed (RFC 7692 7.2.3.1).
def ws_client_frame_raw(opcode, payload, rsv1: false)
  mask = [1, 2, 3, 4]
  masked = payload.bytes.each_with_index.map { |b, i| b ^ mask[i % 4] }
  first = 0x80 | opcode | (rsv1 ? 0x40 : 0)
  n = payload.bytesize
  head = n < 126 ? [first, 0x80 | n] : [first, 0x80 | 126, (n >> 8) & 0xff, n & 0xff]
  (head + mask + masked).pack('C*')
end

def ws_client_frame(payload, opcode = 0x1)
  ws_client_frame_raw(opcode, payload)
end

assert('h2: the server says it takes the extended CONNECT (RFC 8441)') do
  h2_server(H2_WS_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write(WM_H2_PREFACE + h2_frame(4, 0, 0, ''.b))
      type, _flags, _stream, payload = h2_next(s)
      assert_equal 4, type
      # Every setting is a 6-byte pair; 0x8 is ENABLE_CONNECT_PROTOCOL.
      seen = {}
      payload.bytes.each_slice(6) { |p| seen[(p[0] << 8) | p[1]] = p[2..5].inject(0) { |a, b| (a << 8) | b } }
      assert_equal 1, seen[0x8], seen.inspect
    end
  end
end

assert('h2: a websocket opens with CONNECT and echoes through DATA (RFC 8441)') do
  h2_server(H2_WS_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x04, 1, h2_connect_block('/ws')))
      type, flags, stream, block = h2_next(s)
      assert_equal 1, type, 'HEADERS first'
      assert_equal 1, stream
      assert_true (flags & 0x04) != 0, 'END_HEADERS missing'
      assert_true (flags & 0x01) == 0, 'a websocket stream must stay open'
      assert_equal 0x88, block.getbyte(0), 'RFC 8441 answers 200, not 101'

      s.write(h2_frame(0, 0x00, 1, ws_client_frame('hi')))
      type, flags, stream, data = h2_next_payload(s)
      assert_equal 0, type, 'the answer is DATA'
      assert_equal 1, stream
      assert_true (flags & 0x01) == 0, 'an echo must not end the stream'
      # RFC 6455 5.1: a server frame is not masked.
      assert_equal [0x81, 0x02, 0x68, 0x69], data.bytes
    end
  end
end

# RFC 7692 over RFC 8441: permessage-deflate is the WebSocket's own, so
# it is offered in the CONNECT's fields and answered in the response's.
# Nothing about it is h2's business.
require 'zlib'

H2_WS_DEFLATE_APP = <<~RUBY_SRC unless defined?(H2_WS_DEFLATE_APP)
  class H2DeflateEcho < Webmachine::WebsocketResource
    def self.permessage_deflate?
      true
    end

    def on_data(data, binary)
      data
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes { |route| route.websocket ['ws'], H2DeflateEcho }
    end
  end
RUBY_SRC

# The same CONNECT block, plus one offer. A literal field with no
# indexing (0x00), then the name and the value, both without Huffman.
def h2_connect_deflate_block(path)
  b = h2_connect_block(path)
  name = 'sec-websocket-extensions'
  value = 'permessage-deflate'
  b << "\x00".b << name.bytesize.chr << name << value.bytesize.chr << value
  b
end

def h2_ws_deflate(z, str)
  out = z.deflate(str, Zlib::SYNC_FLUSH)
  out[0, out.bytesize - 4]
end

assert('h2: permessage-deflate is negotiated on the CONNECT (RFC 7692)') do
  h2_server(H2_WS_DEFLATE_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x04, 1, h2_connect_deflate_block('/ws')))
      type, _flags, _stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 0x88, block.getbyte(0), 'RFC 8441 answers 200'
      # The answer names the extension, but the block is HPACK and
      # ls-hpack Huffman-codes the value, so the bytes are not readable
      # here. What proves the negotiation is the exchange below: the
      # server sets RSV1 only on a connection where deflate is on.

      # RFC 7692 7.2.1: a compressed message carries RSV1 and no tail.
      z = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -15)
      zi = Zlib::Inflate.new(-15)
      body = 'the quick brown fox ' * 40
      frame = ws_client_frame_raw(0x1, h2_ws_deflate(z, body), rsv1: true)
      s.write(h2_frame(0, 0x00, 1, frame))
      type, _flags, _stream, data = h2_next_payload(s)
      assert_equal 0, type, 'the answer is DATA'
      assert_true (data.getbyte(0) & 0x40) != 0, 'the answer must carry RSV1'
      len = data.getbyte(1) & 0x7f
      payload = len == 126 ? data[4, data.bytesize - 4] : data[2, data.bytesize - 2]
      assert_equal body, zi.inflate(payload + "\x00\x00\xff\xff".b)
      assert_true payload.bytesize < body.bytesize, "#{payload.bytesize} vs #{body.bytesize}"
    end
  end
end

# RFC 9113 6.9: a websocket that never returns its window stalls as soon
# as the peer has sent 65535 bytes. This pushes past that in messages of
# 8 KiB and expects every one of them back.
assert('h2: a websocket keeps taking bytes past the initial window (#30)') do
  h2_server(H2_WS_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x04, 1, h2_connect_block('/ws')))
      type, _flags, _stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 0x88, block.getbyte(0)

      chunk = 'x' * 8192
      total = 0
      12.times do |i|
        s.write(h2_frame(0, 0x00, 1, ws_client_frame(chunk)))
        type, _flags, _stream, data = h2_next_payload(s)
        assert_equal 0, type, "echo #{i} is DATA"
        # RFC 9113 6.9: and the client returns its own credit, or the
        # server stops sending after 65535 bytes - as it should.
        inc = [data.bytesize].pack('N')
        s.write(h2_frame(8, 0, 0, inc))
        s.write(h2_frame(8, 0, 1, inc))
        # 8192 needs the 16-bit length form: 0x81, 126, then two bytes.
        assert_equal 0x81, data.getbyte(0)
        assert_equal 126, data.getbyte(1) & 0x7f
        total += (data.getbyte(2) << 8) | data.getbyte(3)
      end
      assert_equal 12 * 8192, total, 'every message must come back whole'
    end
  end
end

# RFC 8441 5: what a websocket needs from the handshake, h2 carries in
# the CONNECT's fields. The subprotocol is one of those. The answer
# names it in HPACK, and ls-hpack Huffman-codes the value, so what this
# pins is the half that is h2's own: the client's offer reaches
# initialize. bintest/websocket.rb pins the answer field over h1, and
# the code that writes it is the same code.
H2_WS_SUBPROTOCOL_APP = <<~RUBY_SRC unless defined?(H2_WS_SUBPROTOCOL_APP)
  class H2Picky < Webmachine::WebsocketResource
    def initialize
      @offered = request.headers['sec-websocket-protocol'].to_s
      'chat.v1' if @offered.split(',').map { |s| s.strip }.include?('chat.v1')
    end

    def on_data(data, binary)
      @offered
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes { |route| route.websocket ['ws'], H2Picky }
    end
  end
RUBY_SRC

def h2_connect_subprotocol_block(path, offer)
  b = h2_connect_block(path)
  name = 'sec-websocket-protocol'
  b << "\x00".b << name.bytesize.chr << name << offer.bytesize.chr << offer
  b
end

assert('h2: the CONNECT carries the websocket subprotocol offer (RFC 8441)') do
  h2_server(H2_WS_SUBPROTOCOL_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      offer = 'chat.v0, chat.v1'
      s.write(h2_frame(1, 0x04, 1, h2_connect_subprotocol_block('/ws', offer)))
      type, _flags, _stream, block = h2_next(s)
      assert_equal 1, type
      assert_equal 0x88, block.getbyte(0), 'RFC 8441 answers 200'

      s.write(h2_frame(0, 0x00, 1, ws_client_frame('what did I offer?')))
      type, _flags, _stream, data = h2_next_payload(s)
      assert_equal 0, type, 'the answer is DATA'
      len = data.getbyte(1) & 0x7f
      assert_equal offer, data[2, len]
    end
  end
end

# RFC 9113 6.9: a DATA frame the server refuses still counts against the
# connection window, so its credit comes back like any other. The
# credits on stream 0 add up to every DATA byte sent, refused ones
# included, and a second upload on the same connection completes.
assert('h2: a refused DATA frame is credited on the connection (RFC 9113 6.9)') do
  src = <<~RUBY_SRC
    class TakesPosts < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        'GET HEAD POST'
      end
      def process_post
        response.body = 'taken'
        true
      end
    end
  RUBY_SRC
  h2_server(h2_app('TakesPosts', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      frames = []
      reader = Thread.new do
        loop do
          f = h2_next(s)
          frames << f
          # HEADERS on stream 3 is the second upload's answer.
          break if f[0] == 1 && f[2] == 3
        end
      rescue StandardError
        nil
      end
      # One frame past conf.max_body (1 MiB by default): the last one is refused.
      chunk = 16_384
      sent = 0
      declared = chunk * (1 + (1 << 20) / chunk)
      s.write(h2_frame(1, 0x04, 1,
                       h2_method_block('POST') + h2_lit('content-length', declared.to_s)))
      (1 + (1 << 20) / chunk).times do
        s.write(h2_frame(0, 0x00, 1, 'a' * chunk))
        sent += chunk
        # Stay inside the connection window: wait until stream 0 gave
        # back what the peer still owes past 65535.
        waited = 0
        until sent - frames.select { |t, _, st, _| t == 8 && st == 0 }.sum { |_, _, _, p| p.unpack1('N') } < 65_535
          sleep 0.005
          waited += 1
          raise 'the server credited nothing for 5 seconds' if waited > 1000
        end
      end
      s.write(h2_frame(1, 0x04, 3, h2_method_block('POST') + h2_lit('content-length', '100')))
      s.write(h2_frame(0, 0x01, 3, 'b' * 100))
      sent += 100
      reader.join(10) or raise "no answer for the second upload; frames: #{frames.map { |f| f[0..2] }.inspect}"
      rst = frames.find { |t, _, st, _| t == 3 && st == 1 }
      assert_true rst != nil, 'the oversize upload must be RST_STREAM'
      credited = frames.select { |t, _, st, _| t == 8 && st == 0 }.sum { |_, _, _, p| p.unpack1('N') }
      assert_equal sent, credited
      answer = frames.find { |t, _, st, _| t == 1 && st == 3 }
      assert_true answer != nil, 'the second upload must be answered'
    end
  end
end

# RFC 7541 4.4: a dynamic table entry the encoder adds moves every index
# the peer holds. An asset answer adds none, so a cached konst head
# still points where it did. The blocks are walked by shape here: a
# literal with incremental indexing (01xxxxxx) is an insert, an indexed
# field (1xxxxxxx) names an entry, and the entry named for content-type
# must be the one the first konst head inserted.
def h2_hpack_int(bytes, at, prefix)
  mask = (1 << prefix) - 1
  v = bytes[at] & mask
  at += 1
  return [v, at] if v < mask
  m = 0
  loop do
    b = bytes[at]
    at += 1
    v += (b & 0x7f) << m
    m += 7
    break if (b & 0x80) == 0
  end
  [v, at]
end

def h2_hpack_shape(block)
  bytes = block.bytes
  at = 0
  out = []
  while at < bytes.size
    b = bytes[at]
    if (b & 0x80) != 0
      idx, at = h2_hpack_int(bytes, at, 7)
      out << [:indexed, idx]
    elsif (b & 0xc0) == 0x40
      name, at = h2_hpack_int(bytes, at, 6)
      if name == 0
        len, at = h2_hpack_int(bytes, at, 7)
        at += len
      end
      len, at = h2_hpack_int(bytes, at, 7)
      at += len
      out << [:insert, name]
    elsif (b & 0xe0) == 0x20
      _size, at = h2_hpack_int(bytes, at, 5)
      out << [:resize]
    else
      name, at = h2_hpack_int(bytes, at, 4)
      if name == 0
        len, at = h2_hpack_int(bytes, at, 7)
        at += len
      end
      len, at = h2_hpack_int(bytes, at, 7)
      at += len
      out << [:literal, name]
    end
  end
  out
end

assert('h2: an asset answer between two konst heads leaves their index in place') do
  src = <<~RUBY_SRC
    class KonstBeside < Webmachine::Resource
      def self.to_html
        '<p>konst</p>'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.assets = ASSETS_PATH
        app.routes { |route| route.add [:*], KonstBeside }
      end
    end
  RUBY_SRC
  zip = h2_stored_zip([['a.txt', 'asset']])
  zf = Tempfile.new(['wm-h2ka', '.zip'])
  zf.binmode
  zf.write(zip)
  zf.close
  begin
    h2_server(src.sub('ASSETS_PATH', zf.path.inspect)) do |sock|
      UNIXSocket.open(sock) do |s|
        h2_handshake(s)
        blocks = []
        [['/k', 1], ['/a.txt', 3], ['/k', 5]].each do |path, id|
          s.write(h2_frame(1, 0x05, id, h2_method_path_block('GET', path)))
          type, _, _, block = h2_next(s)
          assert_equal 1, type, "stream #{id}: expected HEADERS"
          blocks << block
          h2_next(s)
        end
        # Every insert seen, in order, from the first block on. The
        # content-type insert is the first konst head's, with static
        # name index 31.
        inserts = 0
        content_type_at = nil
        shapes = blocks.map { |b| h2_hpack_shape(b) }
        shapes[0].each do |kind, name|
          next unless kind == :insert
          inserts += 1
          content_type_at = inserts if name == 31
        end
        assert_true content_type_at != nil, "the first konst head inserts content-type: #{shapes[0].inspect}"
        shapes[1].each { |kind, _| inserts += 1 if kind == :insert }
        # RFC 7541 2.3.3: the newest entry is index 62; an entry made
        # n inserts ago is 62 + n.
        want = 62 + (inserts - content_type_at)
        named = shapes[2].select { |kind, idx| kind == :indexed && idx >= 62 }.map(&:last)
        assert_true named.include?(want),
                    "the third head must name content-type at #{want}, names #{named.inspect}; " \
                    "shapes: #{shapes.inspect}"
      end
    end
  ensure
    zf.unlink
  end
end

# WHATWG HTML: an event stream that ends at once. The stream still has
# to end on the wire, so the peer sees END_STREAM and not a silence.
assert('h2: an event stream that closes with nothing to say ends the stream (#30)') do
  src = <<~RUBY_SRC
    class ClosesAtOnce < Webmachine::SseResource
      def on_tick
        :close
      end
    end

    class ClosePage < Webmachine::Resource
      def self.to_html
        'not a stream'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.add_sse ['events'], ClosesAtOnce
        app.add_route [:*], ClosePage
      end
    end
  RUBY_SRC
  h2_server(src) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_path_block('/events')))
      type, flags, stream, _block = h2_next(s)
      assert_equal 1, type, 'HEADERS first'
      assert_equal 1, stream
      assert_true (flags & 0x01) == 0, 'the head does not end the stream'
      type, flags, stream, data = h2_next(s)
      assert_equal 0, type, 'a DATA frame ends it'
      assert_equal 1, stream
      assert_true (flags & 0x01) != 0, 'END_STREAM must be set'
      assert_equal '', data
    end
  end
end

# RFC 9113 5.1: a stream the peer resets while a run is parked on it is
# closed. When the run answers, nothing goes out on that id.
assert('h2: RST_STREAM on a parked stream ends it, and its answer stays silent') do
  src = <<~RUBY_SRC
    class H2ParkThenReset < Webmachine::Resource
      compute :is_authorized?
      def is_authorized?(_h)
        Webmachine::ComputeTask.new(max_runtime: 2.s) do
          t0 = Chrono::Steady.now
          nil while Chrono::Steady.now - t0 < 0.3
          true
        end
      end
      def to_html
        'answered by a worker'
      end
    end
  RUBY_SRC
  h2_server(h2_app('H2ParkThenReset', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x05, 1, h2_get_block))
      sleep 0.05
      s.write(h2_frame(3, 0x00, 1, [0x8].pack('N')))   # RST_STREAM CANCEL
      s.write(h2_frame(1, 0x05, 3, h2_get_block))
      frames = []
      loop do
        f = h2_next(s)
        frames << f
        break if f[0] == 0 && f[2] == 3
      end
      # Stream 3 answered. Stream 1's run answers about now, and says
      # nothing. What comes after is read for a while, and must not
      # name stream 1 either.
      sleep 0.5
      while IO.select([s], nil, nil, 0.2)
        frames << h2_next(s)
      end
      on_reset = frames.select { |_, _, st, _| st == 1 }
      assert_true on_reset.empty?, "frames on the reset stream: #{on_reset.map { |f| f[0..2] }.inspect}"
      assert_true frames.any? { |t, _, st, _| t == 1 && st == 3 }, 'stream 3 must be answered'
    end
  end
end

# The access line of a parked request is written when its run answers,
# with that answer's status and bytes, not the previous answer's.
assert('h2: a parked request logs its own status and bytes') do
  src = <<~RUBY_SRC
    class H2LoggedPark < Webmachine::Resource
      compute :is_authorized?
      def is_authorized?(_h)
        Webmachine::ComputeTask.new(max_runtime: 2.s) { true }
      end
      def to_html
        'answered by a worker'
      end
    end

    class H2LoggedPlain < Webmachine::Resource
      def self.to_html
        'plain'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['park'], H2LoggedPark
          route.add [:*], H2LoggedPlain
        end
      end
    end
  RUBY_SRC
  logf = "/tmp/wm-h2log-#{$$}.log"
  File.unlink(logf) if File.exist?(logf)
  begin
    h2_server(src, "--log=#{logf}") do |sock|
      UNIXSocket.open(sock) do |s|
        h2_handshake(s)
        s.write(h2_frame(1, 0x05, 1, h2_method_path_block('GET', '/plain')))
        2.times { h2_next(s) }
        s.write(h2_frame(1, 0x05, 3, h2_method_path_block('GET', '/park')))
        2.times { h2_next(s) }
      end
    end
    20.times { break if File.exist?(logf) && File.readlines(logf).size >= 2; sleep 0.1 }
    lines = File.readlines(logf)
    assert_equal 2, lines.size, lines.inspect
    assert_true lines[0].match?(%r{"GET /plain [^"]*" 200 5 }), lines[0]
    assert_true lines[1].match?(%r{"GET /park [^"]*" 200 20 }), lines[1]
  ensure
    File.unlink(logf) rescue nil
  end
end

# RFC 9113 8.2.3: an h2 client may split Cookie into several fields.
# They reach request.cookies as one cookie string.
assert('h2: split cookie fields reach request.cookies as one (RFC 9113 8.2.3)') do
  src = <<~'APP'
    class H2Cookies < Webmachine::Resource
      def to_html
        c = request.cookies
        "#{c['a']}|#{c['b']}"
      end
    end
  APP
  h2_server(h2_app('H2Cookies', src)) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      block = h2_get_block + h2_lit('cookie', 'a=1') + h2_lit('cookie', 'b=2')
      s.write(h2_frame(1, 0x05, 1, block))
      type, _, _, _ = h2_next(s)
      assert_equal 1, type
      type, _, _, data = h2_next(s)
      assert_equal 0, type
      assert_equal '1|2', data
    end
  end
end

# RFC 9110 6.4: an h2 request body of 256 KiB or more leaves memory and
# goes to a file, the same as h1's. h2 decides on what has arrived, and
# moves what arrived before it into the file.
def h2_post_block(len)
  block = "\x02\x04POST\x86\x84\x41\x0bexample.com".b
  block + h2_lit('content-length', len.to_s)
end

# Writes DATA in frames the peer's SETTINGS allow, and reads what the
# server sends back between them - the server credits both windows per
# frame, and a full socket buffer would stop the write half way. Every
# frame read is kept in `seen`, because an answer to an earlier stream
# arrives while a later one is still sending.
def h2_write_body(s, id, body, seen)
  off = 0
  while off < body.bytesize
    chunk = body.byteslice(off, 16_384)
    off += chunk.bytesize
    last = off >= body.bytesize
    s.write(h2_frame(0, last ? 0x01 : 0x00, id, chunk))
    seen << h2_next(s) while IO.select([s], nil, nil, 0)
  end
end

# Reads until every stream in `ids` has ended, then answers the DATA
# octets of each. `seen` holds what the write half already read.
def h2_bodies(s, ids, seen)
  ended = seen.select { |t, f, st, _| (t == 0 || t == 1) && (f & 0x01) != 0 }
              .map { |_, _, st, _| st }
  while (ids - ended).any?
    frame = h2_next(s)
    seen << frame
    t, f, st, = frame
    ended << st if (t == 0 || t == 1) && (f & 0x01) != 0
  end
  ids.map do |id|
    seen.select { |t, _, st, _| t == 0 && st == id }.map { |_, _, _, p| p }.join
  end
end

assert('h2: a large request body is a File, a small one is a StringIO') do
  src = <<~RUBY
    class H2Upload < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        'GET HEAD POST'
      end

      def process_post
        b = request.body
        bytes = b.read
        response.body = [
          b.class.to_s, b.size.to_s, bytes.bytesize.to_s,
          bytes[0, 4], bytes[-4, 4],
        ].join('|')
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 4 * 1024 * 1024
        app.add_route [:*], H2Upload
      end
    end
  RUBY
  h2_server(src) do |sock|
    small = 'ab' + ('s' * ((256 * 1024) - 5)) + 'yz'
    big = 'AB' + ('L' * ((1024 * 1024) - 4)) + 'YZ'
    [[small, 'StringIO'], [big, 'File']].each_with_index do |(payload, want), i|
      UNIXSocket.open(sock) do |s|
        h2_handshake(s)
        id = 1
        seen = []
        s.write(h2_frame(1, 0x04, id, h2_post_block(payload.bytesize)))
        h2_write_body(s, id, payload, seen)
        got = h2_bodies(s, [id], seen)[0].split('|')
        assert_equal want, got[0], "round #{i}"
        assert_equal payload.bytesize.to_s, got[1]
        assert_equal payload.bytesize.to_s, got[2]
        assert_equal payload[0, 4], got[3]
        assert_equal payload[-4, 4], got[4]
      end
    end

    # Two large uploads at once on one connection. Each stream owns its
    # file, so neither reads the other's octets.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      a = 'AA' + ('x' * ((512 * 1024) - 4)) + 'ZZ'
      b = 'BB' + ('y' * ((512 * 1024) - 4)) + 'WW'
      seen = []
      s.write(h2_frame(1, 0x04, 1, h2_post_block(a.bytesize)))
      s.write(h2_frame(1, 0x04, 3, h2_post_block(b.bytesize)))
      h2_write_body(s, 1, a, seen)
      h2_write_body(s, 3, b, seen)
      answers = h2_bodies(s, [1, 3], seen)
      {1 => a, 3 => b}.each_with_index do |(id, payload), i|
        got = answers[i].split('|')
        assert_equal 'File', got[0], "stream #{id}"
        assert_equal payload.bytesize.to_s, got[1], "stream #{id}"
        assert_equal payload[0, 4], got[3], "stream #{id} read the wrong body"
        assert_equal payload[-4, 4], got[4], "stream #{id} read the wrong body"
      end
    end
  end
end

assert('h2: a body with no declared length is read, and it grows into a file') do
  src = <<~RUBY_SRC
    class NoLength < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        'GET HEAD POST'
      end
      def process_post
        b = request.body
        bytes = b.read
        response.body = [b.class.to_s, bytes.bytesize.to_s, bytes[0, 2], bytes[-2, 2]].join('|')
        true
      end
    end
  RUBY_SRC
  h2_server(h2_app('NoLength', src)) do |sock|
    # RFC 9110 8.6: nothing is declared, so the count is the only thing
    # that knows. A small body stays in memory.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      seen = []
      s.write(h2_frame(1, 0x04, 1, h2_method_block('POST')))
      s.write(h2_frame(0, 0x01, 1, 'ab' + ('s' * 12) + 'yz'))
      got = h2_bodies(s, [1], seen)[0].split('|')
      assert_equal 'StringIO', got[0]
      assert_equal '16', got[1]
      assert_equal 'ab', got[2]
      assert_equal 'yz', got[3]
    end

    # The same request, past the spill mark: the octets already in
    # memory move to the file, and the body reads back whole and in
    # order.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      seen = []
      payload = 'ab' + ('L' * ((512 * 1024) - 4)) + 'yz'
      s.write(h2_frame(1, 0x04, 1, h2_method_block('POST')))
      h2_write_body(s, 1, payload, seen)
      got = h2_bodies(s, [1], seen)[0].split('|')
      assert_equal 'File', got[0], 'a body that outgrows memory moves to a file'
      assert_equal payload.bytesize.to_s, got[1]
      assert_equal 'ab', got[2], 'the octets written before the move must be first'
      assert_equal 'yz', got[3]
    end

    # A body with no length is still held to conf.max_body, by the count
    # alone. The default is 1 MiB and h2_app names nothing else.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      seen = []
      s.write(h2_frame(1, 0x04, 1, h2_method_block('POST')))
      rst = nil
      chunk = 'x' * 16_384
      sent = 0
      while sent < (2 << 20) && rst.nil?
        s.write(h2_frame(0, 0x00, 1, chunk))
        sent += chunk.bytesize
        while IO.select([s], nil, nil, 0)
          f = h2_next(s)
          rst = f if f[0] == 3 && f[2] == 1
          break if rst
        end
      end
      deadline = Time.now + 5
      while Time.now < deadline && rst.nil?
        f = h2_next(s)
        rst = f if f[0] == 3 && f[2] == 1
      end
      assert_true rst != nil, 'a body past conf.max_body must be refused by its count'
    end
  end
end

# RFC 9110 15.5.14: the same three levels as HTTP/1, and the stream
# carries the answer the head worked out.
assert('h2: max_body - the resource answers before the application does') do
  src = <<~RUBY_APP
    class H2Uploads < Webmachine::Resource
      reads_body :process_post
      def self.max_body
        4096
      end
      def self.allowed_methods
        %w[GET POST]
      end
      def process_post
        response.body = request.body.read.bytesize.to_s
        true
      end
    end

    class H2Small < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        %w[GET POST]
      end
      def process_post
        response.body = request.body.read.bytesize.to_s
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 64
        app.routes do |route|
          route.add ['uploads'], H2Uploads
          route.add [:*], H2Small
        end
      end
    end
  RUBY_APP
  h2_server(src) do |sock|
    # The resource says 4096, so 1024 octets pass where the
    # application's 64 would have refused them.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      seen = []
      block = "\x02\x04POST\x86\x04\x08/uploads\x41\x0bexample.com".b +
              h2_lit('content-length', '1024')
      s.write(h2_frame(1, 0x04, 1, block))
      h2_write_body(s, 1, 'u' * 1024, seen)
      assert_equal '1024', h2_bodies(s, [1], seen)[0]
    end
    # The same size on a route that named nothing: the application's 64
    # refuses the stream.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      block = "\x02\x04POST\x86\x04\x06/small\x41\x0bexample.com".b +
              h2_lit('content-length', '1024')
      s.write(h2_frame(1, 0x04, 3, block))
      s.write(h2_frame(0, 0x01, 3, 'u' * 1024))
      rst = nil
      deadline = Time.now + 5
      while Time.now < deadline
        f = h2_next(s)
        break rst = f if f[0] == 3 && f[2] == 3
      end
      assert_true rst != nil, 'the oversize upload must be RST_STREAM'
    end
  end
end

# RFC 9113 8.1.2.6: a request that sends more or less than its own
# Content-Length loses its stream, at the frame that breaks the word. A
# connection that keeps doing it ends with ENHANCE_YOUR_CALM.
assert('h2: a body that breaks its declared length ends the stream, and a run of them ends the connection') do
  src = <<~RUBY_APP
    class H2Liar < Webmachine::Resource
      reads_body :process_post
      def self.allowed_methods
        %w[GET POST]
      end
      def process_post
        response.body = request.body.read.bytesize.to_s
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.max_body = 1024 * 1024
        app.add_route [:*], H2Liar
      end
    end
  RUBY_APP
  h2_server(src) do |sock|
    # One stream, one lie: 10 declared, 40 sent. The stream dies and the
    # connection stays, so the next request is answered.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x04, 1, h2_post_block(10)))
      s.write(h2_frame(0, 0x01, 1, 'a' * 40))
      rst = nil
      deadline = Time.now + 5
      while Time.now < deadline && rst.nil?
        f = h2_next(s)
        rst = f if f[0] == 3 && f[2] == 1
      end
      assert_true rst != nil, 'the oversize body must be RST_STREAM'
      assert_equal 1, rst[3].unpack1('N'), 'the code must be PROTOCOL_ERROR'
    end
    # A body that stops short of what it declared is the same rule.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      s.write(h2_frame(1, 0x04, 1, h2_post_block(40)))
      s.write(h2_frame(0, 0x01, 1, 'a' * 10))
      rst = nil
      deadline = Time.now + 5
      while Time.now < deadline && rst.nil?
        f = h2_next(s)
        rst = f if f[0] == 3 && f[2] == 1
      end
      assert_true rst != nil, 'the short body must be RST_STREAM'
      assert_equal 1, rst[3].unpack1('N')
    end
    # Four lies on one connection: the fourth ends it.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      id = 1
      4.times do
        s.write(h2_frame(1, 0x04, id, h2_post_block(10)))
        s.write(h2_frame(0, 0x01, id, 'a' * 40))
        id += 2
      end
      goaway = nil
      deadline = Time.now + 5
      while Time.now < deadline && goaway.nil?
        begin
          f = h2_next(s)
        rescue EOFError
          break
        end
        goaway = f if f[0] == 7
      end
      assert_true goaway != nil, 'the fourth lie must end the connection'
      assert_equal 11, goaway[3][4, 4].unpack1('N'), 'the code must be ENHANCE_YOUR_CALM'
    end
  end
end

# #54: a run that stops keeps its request. The dispatch's decode buffer
# is reused by the next stream, so a parked run reads a copy it holds
# itself - and before this it was given no view and no values at all.
assert('h2: a parked run still has its headers, its bindings and its body') do
  src = <<~RUBY_SRC
    class H2Parked < Webmachine::Resource
      reads_body :process_post
      compute :is_authorized?
      def is_authorized?(_h)
        Webmachine::ComputeTask.new(max_runtime: 500.ms) { true }
      end
      def self.allowed_methods
        %w[GET POST]
      end
      def to_html
        [request.headers['x-mark'].to_s,
         request.path_info[:name].to_s,
         request.query['q'].to_s].join('|')
      end
      def process_post
        response.body = [request.headers['x-mark'].to_s, request.body.read].join('|')
        true
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.routes do |route|
          route.add ['files', :name], H2Parked
          route.add [:*], H2Parked
        end
      end
    end
  RUBY_SRC
  h2_server(src) do |sock|
    # A parked GET reads a field, a path binding and the query.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      block = "\x82\x86".b + h2_lit(':path', '/files/report.txt?q=deep') +
              h2_lit(':authority', 'example.com') + h2_lit('x-mark', 'kept')
      s.write(h2_frame(1, 0x05, 1, block))
      _, _, _, hblock = h2_until(s, 1)
      assert_equal 0x88, hblock.getbyte(0)
      _, _, _, data = h2_until(s, 0)
      assert_equal 'kept|report.txt|deep', data
    end
    # Two streams in one dispatch: the second overwrites the decode
    # buffer while the first is parked, which is the case this holds
    # the head for.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      first = "\x82\x86".b + h2_lit(':path', '/files/one.txt') +
              h2_lit(':authority', 'example.com') + h2_lit('x-mark', 'first')
      second = "\x82\x86".b + h2_lit(':path', '/files/two.txt') +
               h2_lit(':authority', 'example.com') + h2_lit('x-mark', 'second')
      s.write(h2_frame(1, 0x05, 1, first) + h2_frame(1, 0x05, 3, second))
      seen = {}
      deadline = Time.now + 10
      while seen.size < 2 && Time.now < deadline
        t, _, st, payload = h2_next(s)
        seen[st] = payload if t == 0 && !payload.empty?
      end
      assert_equal 'first|one.txt|', seen[1]
      assert_equal 'second|two.txt|', seen[3]
    end
    # A parked run reads its own body.
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      body = 'the body a stopped run still owns'
      block = "\x02\x04POST\x86".b + h2_lit(':path', '/files/upload.bin') +
              h2_lit(':authority', 'example.com') + h2_lit('x-mark', 'body') +
              h2_lit('content-length', body.bytesize.to_s)
      s.write(h2_frame(1, 0x04, 1, block))
      s.write(h2_frame(0, 0x01, 1, body))
      _, _, _, data = h2_until(s, 0)
      assert_equal "body|#{body}", data
    end
  end
end
