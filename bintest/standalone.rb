# STANDALONE: --docroot and/or --assets, and no app at all. Nobody wrote a
# resource, so the folded graph answers on its own - the pack from its
# mapping, the docroot from disk, everything else a 404.
require 'socket'
require 'tempfile'
require 'fileutils'

S_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(S_BIN)

def s_recv(sock, maxlen = 1, deadline = 10)
  IO.select([sock], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s"
  sock.readpartial(maxlen)
end

def s_read(sock)
  head = +''.b
  head << s_recv(sock) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''.b
  body << s_recv(sock, len - body.bytesize) while body.bytesize < len
  [head, body]
end

def s_ask(sock_path, request)
  UNIXSocket.open(sock_path) do |s|
    s.write(request)
    s_read(s)
  end
end

# One directory, the files this suite serves out of it, and a server with
# NO --app. The window is 256 KiB, so big.bin is mapped and small.bin is read.
S_SMALL = "small\n" * 4 unless defined?(S_SMALL)
S_BIG = ('x' * 1024) * 300 unless defined?(S_BIG)

def s_server(extra = [])
  root = "/tmp/wm-standalone-#{$$}"
  FileUtils.mkdir_p(File.join(root, 'sub'))
  File.binwrite(File.join(root, 'index.html'), "<h1>root</h1>\n")
  File.binwrite(File.join(root, 'sub', 'index.html'), "<h1>sub</h1>\n")
  File.binwrite(File.join(root, 'small.bin'), S_SMALL)
  File.binwrite(File.join(root, 'big.bin'), S_BIG)
  File.binwrite(File.join(root, 'a.css'), "body { margin: 0; }\n")
  sock = "/tmp/wm-standalone-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-standalone-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, S_BIN, "--unix=#{sock}", "--docroot=#{root}", *extra,
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "standalone server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock, root
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    FileUtils.rm_rf(root)
  end
end

assert('standalone: a docroot alone is a server, and / takes its index.html') do
  s_server do |sock|
    head, body = s_ask(sock, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 200 OK'), head
    assert_true head.match?(%r{^Content-Type: text/html; charset=utf-8\r$}i), head
    assert_equal "<h1>root</h1>\n", body
  end
end

assert('standalone: a directory takes its own index.html') do
  s_server do |sock|
    head, body = s_ask(sock, "GET /sub/ HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 200 OK'), head
    assert_equal "<h1>sub</h1>\n", body
  end
end

assert('standalone: the media type comes off the machine, by extension') do
  s_server do |sock|
    head, = s_ask(sock, "GET /a.css HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.match?(%r{^Content-Type: text/css; charset=utf-8\r$}i), head
  end
end

assert('standalone: read below the window, mapped above it, same bytes either way') do
  s_server do |sock|
    _, small = s_ask(sock, "GET /small.bin HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_equal S_SMALL, small
    _, big = s_ask(sock, "GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_equal S_BIG.bytesize, big.bytesize
    assert_equal S_BIG, big
  end
end

assert('standalone: a name that is not there is 404, and one that climbs out is too') do
  s_server do |sock|
    head, = s_ask(sock, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 404'), head
    out, = s_ask(sock, "GET /../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true out.start_with?('HTTP/1.1 404'), out
  end
end

assert('standalone: only GET and HEAD answer; a POST is 405') do
  s_server do |sock|
    head, = s_ask(sock, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 405'), head
  end
end

assert('standalone: If-Modified-Since answers 304 without a body') do
  s_server do |sock|
    head, = s_ask(sock, "GET /a.css HTTP/1.1\r\nHost: x\r\n\r\n")
    when_ = head[/^Last-Modified: *(.+)\r$/i, 1]
    assert_true !when_.nil?, head
    out = +''.b
    UNIXSocket.open(sock) do |s|
      s.write("GET /a.css HTTP/1.1\r\nHost: x\r\nIf-Modified-Since: #{when_}\r\n\r\n")
      out << s_recv(s) until out.end_with?("\r\n\r\n")
    end
    assert_true out.start_with?('HTTP/1.1 304'), out
  end
end
