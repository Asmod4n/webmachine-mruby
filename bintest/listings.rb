# --listings: a directory with no index.html answers a list of what is in
# it. The list is an ordinary application - mrblib/listing.rb, one route,
# one resource - so these tests also prove that the graph answers for it:
# the media type is negotiated, and a client that already holds the list
# gets 304.
require 'socket'
require 'fileutils'

def l_ask(sock_path, request)
  wm_conn(sock_path) do |s|
    s.write(request)
    wm_read(s)
  end
end

# A directory with no index.html, one with an index.html, a file, and a
# name nobody may see.
def l_server(extra = [])
  root = "/tmp/wm-listings-#{$$}"
  FileUtils.mkdir_p(File.join(root, 'open', 'deeper'))
  FileUtils.mkdir_p(File.join(root, 'closed'))
  File.binwrite(File.join(root, 'open', 'note.txt'), "a note\n")
  File.binwrite(File.join(root, 'closed', 'index.html'), "<h1>closed</h1>\n")
  File.binwrite(File.join(root, '.secret'), "not for the list\n")
  File.binwrite(File.join(root, 'plain.txt'), "plain\n")
  wm_server("--docroot=#{root}", '--listings=on', *extra, app: false,
            tag: 'wm-listings') do |sock|
    yield sock, root
  end
ensure
  FileUtils.rm_rf(root)
end

assert('listings: a directory with no index.html lists what is in it') do
  l_server do |sock|
    head, body = l_ask(sock, "GET /open/ HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 200 OK'), head
    assert_true head.match?(%r{^Content-Type: text/html; charset=utf-8\r$}i), head
    assert_true body.include?('>note.txt<'), body
    assert_true body.include?('>deeper/<'), body
    assert_true body.include?('href="deeper/"'), body
    assert_true body.include?('href="../"'), body
  end
end

assert('listings: the docroot itself lists, and has no parent to climb to') do
  l_server do |sock|
    _, body = l_ask(sock, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true body.include?('>plain.txt<'), body
    assert_false body.include?('href="../"'), body
  end
end

assert('listings: a name that begins with a dot is in no list') do
  l_server do |sock|
    _, body = l_ask(sock, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_false body.include?('.secret'), body
  end
end

assert('listings: a directory that has an index.html answers that document') do
  l_server do |sock|
    head, body = l_ask(sock, "GET /closed/ HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 200 OK'), head
    assert_equal "<h1>closed</h1>\n", body
  end
end

assert('listings: a directory named without its slash is 301 to the one with it') do
  l_server do |sock|
    head, = l_ask(sock, "GET /open HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 301 Moved Permanently'), head
    assert_true head.match?(%r{^Location: /open/\r$}), head
    # RFC 9112 6.3: a kept-alive connection needs the framing said.
    assert_true head.match?(%r{^Content-Length: 0\r$}i), head
  end
end

assert('listings: a plain file still comes off the file tier, unchanged') do
  l_server do |sock|
    head, body = l_ask(sock, "GET /plain.txt HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 200 OK'), head
    assert_true head.match?(%r{^Content-Type: text/plain}i), head
    assert_equal "plain\n", body
  end
end

assert('listings: a name that is not there is still 404') do
  l_server do |sock|
    head, = l_ask(sock, "GET /nowhere/ HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 404'), head
  end
end

assert('listings: a client that asks for JSON gets the list as JSON') do
  l_server do |sock|
    head, body = l_ask(sock, "GET /open/ HTTP/1.1\r\nHost: x\r\n" \
                             "Accept: application/json\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 200 OK'), head
    assert_true head.match?(%r{^Content-Type: application/json}i), head
    assert_true body.include?('note.txt'), body
    assert_true body.include?('/open/note.txt'), body
    assert_true body.include?('deeper'), body
  end
end

assert('listings: If-Modified-Since on an unchanged directory is 304') do
  l_server do |sock|
    head, = l_ask(sock, "GET /open/ HTTP/1.1\r\nHost: x\r\n\r\n")
    when_said = head[%r{^Last-Modified: (.+)\r$}, 1]
    assert_true !when_said.nil?, head
    again, body = l_ask(sock, "GET /open/ HTTP/1.1\r\nHost: x\r\n" \
                              "If-Modified-Since: #{when_said}\r\n\r\n")
    assert_true again.start_with?('HTTP/1.1 304'), again
    assert_equal '', body
  end
end

assert('listings: only GET and HEAD; a POST is 405') do
  l_server do |sock|
    head, = l_ask(sock, "POST /open/ HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
    assert_true head.start_with?('HTTP/1.1 405'), head
    assert_true head.match?(%r{^Allow: }i), head
  end
end

assert('listings: off, a directory with no index.html is 404') do
  root = "/tmp/wm-listings-off-#{$$}"
  FileUtils.mkdir_p(File.join(root, 'open'))
  File.binwrite(File.join(root, 'open', 'note.txt'), "a note\n")
  begin
    wm_server("--docroot=#{root}", app: false, tag: 'wm-listings-off') do |sock|
      head, = l_ask(sock, "GET /open/ HTTP/1.1\r\nHost: x\r\n\r\n")
      assert_true head.start_with?('HTTP/1.1 404'), head
    end
  ensure
    FileUtils.rm_rf(root)
  end
end

assert('listings: --listings without --docroot refuses the start, by name') do
  err = "/tmp/wm-listings-nodoc-#{$$}.log"
  pid = spawn(WM_BIN, "--unix=/tmp/wm-listings-nodoc-#{$$}.sock", '--listings=on',
              out: File::NULL, err: err)
  Process.wait(pid)
  assert_false $?.exitstatus == 0
  said = File.read(err)
  assert_true said.include?('--listings'), said
  assert_true said.include?('--docroot'), said
ensure
  File.unlink(err) if File.exist?(err)
end

assert('listings: a word that is neither on nor off is refused, by name') do
  err = "/tmp/wm-listings-word-#{$$}.log"
  pid = spawn(WM_BIN, "--unix=/tmp/wm-listings-word-#{$$}.sock",
              '--docroot=/tmp', '--listings=perhaps', out: File::NULL, err: err)
  Process.wait(pid)
  assert_false $?.exitstatus == 0
  said = File.read(err)
  assert_true said.include?('perhaps'), said
ensure
  File.unlink(err) if File.exist?(err)
end

assert('listings: off, on, true, 1 and yes all switch it on; off words switch it off') do
  root = "/tmp/wm-listings-words-#{$$}"
  FileUtils.mkdir_p(File.join(root, 'open'))
  File.binwrite(File.join(root, 'open', 'note.txt'), "a note\n")
  begin
    %w[on true yes enabled 1 ON].each do |word|
      wm_server("--docroot=#{root}", "--listings=#{word}", app: false,
                tag: "wm-listings-#{word}") do |sock|
        head, = l_ask(sock, "GET /open/ HTTP/1.1\r\nHost: x\r\n\r\n")
        assert_true head.start_with?('HTTP/1.1 200 OK'), "--listings=#{word}: #{head}"
      end
    end
    %w[off false no disabled 0].each do |word|
      wm_server("--docroot=#{root}", "--listings=#{word}", app: false,
                tag: "wm-listings-#{word}") do |sock|
        head, = l_ask(sock, "GET /open/ HTTP/1.1\r\nHost: x\r\n\r\n")
        assert_true head.start_with?('HTTP/1.1 404'), "--listings=#{word}: #{head}"
      end
    end
  ensure
    FileUtils.rm_rf(root)
  end
end

assert('--standalone is gone, and a command line that carries it hears why') do
  err = "/tmp/wm-standalone-gone-#{$$}.log"
  pid = spawn(WM_BIN, "--unix=/tmp/wm-standalone-gone-#{$$}.sock",
              '--standalone', '--docroot=/tmp', out: File::NULL, err: err)
  Process.wait(pid)
  assert_false $?.exitstatus == 0
  said = File.read(err)
  assert_true said.include?('--standalone is gone'), said
ensure
  File.unlink(err) if File.exist?(err)
end
