# Standalone: --docroot and/or --assets, and no app at all. Nobody wrote a
# resource, so the folded graph answers on its own - the pack from its
# mapping, the docroot from disk, everything else a 404.
require 'socket'
require 'tempfile'
require 'fileutils'

def s_ask(sock_path, request)
  wm_conn(sock_path) do |s|
    s.write(request)
    wm_read(s)
  end
end

# One directory, the files this suite serves out of it, and a server with
# no --app. The window is 256 KiB, so big.bin is mapped and small.bin is read.
S_SMALL = "small\n" * 4 unless defined?(S_SMALL)
S_BIG = ('x' * 1024) * 300 unless defined?(S_BIG)

def s_server(extra = [])
  root = "/tmp/wm-standalone-#{$$}"
  FileUtils.mkdir_p(File.join(root, 'sub'))
  File.binwrite(File.join(root, 'a b.txt'), "spaced\n")
  File.binwrite(File.join(root, 'a#b.txt'), "hashed\n")
  File.binwrite(File.join(root, 'index.html'), "<h1>root</h1>\n")
  File.binwrite(File.join(root, 'sub', 'index.html'), "<h1>sub</h1>\n")
  File.binwrite(File.join(root, 'small.bin'), S_SMALL)
  File.binwrite(File.join(root, 'big.bin'), S_BIG)
  File.binwrite(File.join(root, 'a.css'), "body { margin: 0; }\n")
  wm_server("--docroot=#{root}", *extra, app: false,
            tag: 'wm-standalone') do |sock|
    yield sock, root
  end
ensure
  FileUtils.rm_rf(root)
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
      out << wm_recv(s) until out.end_with?("\r\n\r\n")
    end
    assert_true out.start_with?('HTTP/1.1 304'), out
  end
end

# RFC 3986 2.1: the target spells a byte a name cannot carry as a percent
# triplet. These pin that the tier resolves one, and that resolving one
# opens no way out of the docroot.
assert('standalone: a name that needs percent-encoding is reachable') do
  s_server do |sock|
    head, body = s_ask(sock, "GET /a%20b.txt HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 200 OK'), head
    assert_equal "spaced\n", body
    head, body = s_ask(sock, "GET /a%23b.txt HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 200 OK'), head
    assert_equal "hashed\n", body
  end
end

assert('standalone: an encoded dot-dot climbs out no further than a plain one') do
  outside = "/tmp/wm-standalone-outside-#{$$}"
  File.binwrite(outside, "SECRET\n")
  begin
    s_server do |sock|
      ["/%2e%2e#{outside}",
       "/sub/%2e%2e/%2e%2e#{outside}",
       "/..%2f..#{outside}",
       "/sub%2f..%2f..#{outside}"].each do |target|
        head, = s_ask(sock, "GET #{target} HTTP/1.1\r\nHost: x\r\n\r\n")
        assert_true head.start_with?('HTTP/1.1 404'), "#{target}: #{head}"
      end
    end
  ensure
    File.unlink(outside) if File.exist?(outside)
  end
end

assert('standalone: a target that does not decode names nothing') do
  s_server do |sock|
    # A lone '%', a short escape, a non-hex escape, and a decoded NUL. Each
    # is refused rather than read as written: one file with two spellings
    # is what a cache and a filter disagree about.
    ['/%zz.txt', '/%2.txt', '/plain%', '/%00plain.txt'].each do |target|
      head, = s_ask(sock, "GET #{target} HTTP/1.1\r\nHost: x\r\n\r\n")
      assert_true head.start_with?('HTTP/1.1 404'), "#{target}: #{head}"
    end
  end
end

assert('standalone: a plus in a target is a plus, not a space') do
  # RFC 3986: '+' is a space in form encoding only. In a path it is the
  # literal byte, so it names a file called "a+b.txt" and nothing else.
  root = "/tmp/wm-plus-#{$$}"
  FileUtils.mkdir_p(root)
  File.binwrite(File.join(root, 'a+b.txt'), "plus\n")
  File.binwrite(File.join(root, 'a b.txt'), "space\n")
  begin
    wm_server("--docroot=#{root}", app: false, tag: 'wm-plus') do |sock|
      _, body = s_ask(sock, "GET /a+b.txt HTTP/1.1\r\nHost: x\r\n\r\n")
      assert_equal "plus\n", body
      _, body = s_ask(sock, "GET /a%20b.txt HTTP/1.1\r\nHost: x\r\n\r\n")
      assert_equal "space\n", body
    end
  ensure
    FileUtils.rm_rf(root)
  end
end
