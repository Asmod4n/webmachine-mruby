
require 'socket'
require 'stringio'
require 'tempfile'
require 'zlib'

GZ_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(GZ_BIN)

def gz_recv(s, maxlen = 65536, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def gz_app(name, src)
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

def gz_compile(app_source)
  src = Tempfile.new(['wm-gzapp', '.rb'])
  src.write(app_source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wm-gzapp', '.mrb'])
  mrb.close
  ok = system(mrbc, '-o', mrb.path, src.path)
  raise "mrbc failed to compile:\n#{app_source}" unless ok
  mrb
ensure
  src&.unlink
end

def gz_read(s)
  head = +''.b
  head << gz_recv(s, 1) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''.b
  body << gz_recv(s, len - body.bytesize) while body.bytesize < len
  [head, body]
end

def gz_unix_server(app_source)
  app = gz_compile(app_source)
  sock = "/tmp/wm-gz-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-gz-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, GZ_BIN, "--unix=#{sock}", "--app=#{app.path}",
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    UNIXSocket.open(sock) { |s| yield s }
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

def gz_tcp_server(app_source)
  app = gz_compile(app_source)
  err = "/tmp/wm-gz-tcp-stderr-#{$$}.log"
  port = nil
  pid = nil
  10.times do
    # Below ip_local_port_range (32768 up here): a fixed port picked
    # INSIDE that window collides with an ephemeral port the machine
    # already handed out, which is how this suite once died on 44468.
    port = 20000 + rand(11000)
    pid = spawn({ 'WM_BUNDLE' => '0' }, GZ_BIN, "--port=#{port.to_s}", "--app=#{app.path}",
                out: File::NULL, err: err)
    up = false
    50.times do
      begin
        TCPSocket.open('127.0.0.1', port).close
        up = true
        break
      rescue Errno::ECONNREFUSED, Errno::EADDRNOTAVAIL
        break unless Process.wait(pid, Process::WNOHANG).nil?
        sleep 0.05
      end
    end
    break if up
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    pid = nil
  end
  raise "tcp server never came up:\n#{File.read(err) rescue ''}" if pid.nil?
  begin
    yield port
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    app.unlink
  end
end

def gz_tcp_connect(port)
  TCPSocket.open('127.0.0.1', port)
end

GZ_ENC_RESOURCE = gz_app('GzEncResource', <<~RUBY) unless defined?(GZ_ENC_RESOURCE)
  class GzEncResource < Webmachine::Resource
    def self.encodings_provided
      {"identity" => :encode_identity, "gzip" => :encode_gzip}
    end
    def to_html
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 200
    end
  end
RUBY

GZ_NOENC_RESOURCE = gz_app('GzNoEncResource', <<~RUBY) unless defined?(GZ_NOENC_RESOURCE)
  class GzNoEncResource < Webmachine::Resource
    def to_html
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 200
    end
  end
RUBY

GZ_SMALL_RESOURCE = gz_app('GzSmallResource', <<~RUBY) unless defined?(GZ_SMALL_RESOURCE)
  class GzSmallResource < Webmachine::Resource
    def self.encodings_provided
      {"identity" => :encode_identity, "gzip" => :encode_gzip}
    end
    def to_html
      "hi"
    end
  end
RUBY

GZ_BODY = ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 200).b unless defined?(GZ_BODY)

def gz_sized_resource(n)
  body = GZ_BODY[0, n]
  raise "GZ_BODY too short for #{n} bytes" if body.bytesize != n
  gz_app('GzBoundaryResource', <<~RUBY)
    class GzBoundaryResource < Webmachine::Resource
      def self.encodings_provided
        {"identity" => :encode_identity, "gzip" => :encode_gzip}
      end
      def to_html
        #{body.inspect}
      end
    end
  RUBY
end

assert('gzip: encodings_provided + Accept-Encoding: gzip + a body over the floor compresses, byte-identical') do
  gz_tcp_server(GZ_ENC_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_true head.match?(/^Content-Encoding: gzip\r$/i), head
      assert_true head.match?(/^Vary: Accept-Encoding\r$/i), head
      decompressed = Zlib::GzipReader.new(StringIO.new(body)).read
      assert_equal GZ_BODY, decompressed
      assert_true body.bytesize < GZ_BODY.bytesize, 'gzip should shrink repetitive text'
    ensure
      s.close
    end
  end
end

assert('gzip: the same resource over a unix socket never compresses') do
  gz_unix_server(GZ_ENC_RESOURCE) do |s|
    s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
    head, body = gz_read(s)
    assert_true head.start_with?('HTTP/1.1 200 OK')
    assert_false head.match?(/^Content-Encoding:/i), head
    assert_true head.match?(/^Vary: Accept-Encoding\r$/i), head
    assert_equal GZ_BODY, body
  end
end

assert('gzip: a response under the compress floor stays identity') do
  gz_tcp_server(GZ_SMALL_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_false head.match?(/^Content-Encoding:/i), head
      assert_true head.match?(/^Vary: Accept-Encoding\r$/i), head
      assert_equal 'hi', body
    ensure
      s.close
    end
  end
end

assert('gzip: a resource without encodings_provided is always identity') do
  gz_tcp_server(GZ_NOENC_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_false head.match?(/^Content-Encoding:/i), head
      assert_false head.match?(/^Vary:/i), head
      assert_equal GZ_BODY, body
    ensure
      s.close
    end
  end
end

assert('gzip: Accept-Encoding: gzip;q=0 refuses the coding, identity answers') do
  gz_tcp_server(GZ_ENC_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip;q=0\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.start_with?('HTTP/1.1 200 OK')
      assert_false head.match?(/^Content-Encoding:/i), head
      assert_equal GZ_BODY, body
    ensure
      s.close
    end
  end
end

assert('gzip: a missing Accept-Encoding still compresses past the size gate') do
  gz_tcp_server(GZ_ENC_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.match?(/^Content-Encoding: gzip\r$/i), head
      assert_equal GZ_BODY, Zlib::GzipReader.new(StringIO.new(body)).read
    ensure
      s.close
    end
  end
end

assert('gzip: HEAD reports the gzipped Content-Length and no body') do
  gz_tcp_server(GZ_ENC_RESOURCE) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("HEAD / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n")
      data = +''.b
      begin
        loop { data << gz_recv(s) }
      rescue EOFError
      end
      idx = data.index("\r\n\r\n")
      head = data[0, idx + 4]
      assert_true head.match?(/^Content-Encoding: gzip\r$/i), head
      gz_len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
      assert_true gz_len > 0 && gz_len < GZ_BODY.bytesize
      assert_equal idx + 4, data.bytesize, 'HEAD must not leak body bytes'
    ensure
      s.close
    end
  end
end

assert('gzip: exactly at the compress floor (1280B) compresses; 1279B does not') do
  cal_n = 2000
  head_bytesize = nil
  gz_tcp_server(gz_sized_resource(cal_n)) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip;q=0\r\n\r\n")
      head, body = gz_read(s)
      assert_false head.match?(/^Content-Encoding:/i), head
      assert_equal cal_n, body.bytesize
      head_bytesize = head.bytesize
    ensure
      s.close
    end
  end

  n_compress = 1280 - head_bytesize
  n_identity = 1279 - head_bytesize
  assert_equal cal_n.to_s.size, n_compress.to_s.size, 'digit count drifted - recheck cal_n'
  assert_equal cal_n.to_s.size, n_identity.to_s.size, 'digit count drifted - recheck cal_n'

  gz_tcp_server(gz_sized_resource(n_compress)) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
      head, body = gz_read(s)
      assert_true head.match?(/^Content-Encoding: gzip\r$/i), head
      assert_equal GZ_BODY[0, n_compress], Zlib::GzipReader.new(StringIO.new(body)).read
    ensure
      s.close
    end
  end

  gz_tcp_server(gz_sized_resource(n_identity)) do |port|
    s = gz_tcp_connect(port)
    begin
      s.write("GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip\r\n\r\n")
      head, body = gz_read(s)
      assert_false head.match?(/^Content-Encoding:/i), head
      assert_equal GZ_BODY[0, n_identity], body
    ensure
      s.close
    end
  end
  true
end
