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

assert('listings: every link the page writes is one the file tier answers') do
  # The list encodes its hrefs with URI.encode; the file tier decodes the
  # target. This is the round trip - if either side stopped, a name that
  # needs encoding would be listed and then 404.
  root = "/tmp/wm-listings-enc-#{$$}"
  FileUtils.mkdir_p(File.join(root, 'open'))
  ['a b.txt', 'a#b.txt', 'a+b.txt', 'plain.txt'].each do |name|
    File.binwrite(File.join(root, 'open', name), "#{name}\n")
  end
  begin
    wm_server("--docroot=#{root}", '--listings=on', app: false, tag: 'wm-list-enc') do |sock|
      _, page = l_ask(sock, "GET /open/ HTTP/1.1\r\nHost: x\r\n\r\n")
      hrefs = page.scan(/href="([^"]+)"/).flatten - ['../']
      assert_equal 4, hrefs.length, hrefs.inspect
      hrefs.each do |href|
        head, body = l_ask(sock, "GET /open/#{href} HTTP/1.1\r\nHost: x\r\n\r\n")
        assert_true head.start_with?('HTTP/1.1 200 OK'), "#{href}: #{head}"
        assert_true body.end_with?("\n"), "#{href}: #{body.inspect}"
      end
    end
  ensure
    FileUtils.rm_rf(root)
  end
end

assert('listings: a size names the unit it is actually in') do
  # The first division is what makes KiB. Counting it as a step named
  # every size one unit too large - 307200 octets read "300.0 MiB" - so
  # each row here is a byte count whose unit is not in doubt.
  root = "/tmp/wm-listings-size-#{$$}"
  FileUtils.mkdir_p(File.join(root, 'open'))
  sizes = { 'one.bin' => 1, 'k1.bin' => 1024, 'k1half.bin' => 1536,
            'k300.bin' => 307_200, 'carry.bin' => 1_048_575, 'm1.bin' => 1_048_576 }
  sizes.each { |name, n| File.binwrite(File.join(root, 'open', name), 'x' * n) }
  want = { 'one.bin' => '1 B', 'k1.bin' => '1.0 KiB', 'k1half.bin' => '1.5 KiB',
           'k300.bin' => '300.0 KiB',
           # 1023.999 KiB rounds to 1024.0, which is a unit that reads wrong.
           'carry.bin' => '1.0 MiB', 'm1.bin' => '1.0 MiB' }
  begin
    wm_server("--docroot=#{root}", '--listings=on', app: false, tag: 'wm-list-size') do |sock|
      _, page = l_ask(sock, "GET /open/ HTTP/1.1\r\nHost: x\r\n\r\n")
      want.each do |name, size|
        row = page[/<a href="#{Regexp.escape(name)}">[^<]*<\/a><\/td><td class=size>([^<]*)</, 1]
        assert_equal size, row, "#{name} (#{sizes[name]} octets)"
      end
    end
  ensure
    FileUtils.rm_rf(root)
  end
end

assert('listings: a target that ends in a slash says no-cache; a file does not') do
  # RFC 9111 4.2.2: a response with Last-Modified and no freshness
  # directive lets a cache guess a lifetime from the age of the
  # representation. A generated list, and an index document, keep their
  # name while their content changes, so the guess serves an old page for
  # as long as it lasts and no update ever lands. RFC 9111 5.2.2.4:
  # no-cache keeps the copy and revalidates it, so the 304 this server
  # already answers still saves the body.
  #
  # One connection for all of it. Six targets over six connections is the
  # shape that trips #110 - a recycled connection slot that wedges - and
  # what is under test here is a field line, not the reactor.
  l_server do |sock|
    wm_conn(sock) do |s|
      wm_request(s, '/open/')
      generated, = wm_read(s)
      assert_true generated.match?(/^Cache-Control: no-cache\r$/i), generated

      # /closed/ holds an index.html, which the listing serves through
      # response.file. The head is the file tier's; the rule still applies.
      wm_request(s, '/closed/')
      index_doc, = wm_read(s)
      assert_true index_doc.match?(/^Cache-Control: no-cache\r$/i), index_doc

      # A file is named by itself. Its name changes when its content does,
      # or its Last-Modified is the truth about it. Nothing is said.
      #
      # #111: a docroot file answered here used to be replayed for every
      # request after it on the same connection. Asked in the middle on
      # purpose, so the requests that follow prove it is not.
      wm_request(s, '/plain.txt')
      named, = wm_read(s)
      assert_false named.match?(/^Cache-Control:/i), named

      # The root of the docroot is a directory like any other.
      wm_request(s, '/')
      root_list, = wm_read(s)
      assert_true root_list.match?(/^Cache-Control: no-cache\r$/i), root_list

      # RFC 3986 3.4: the query is not part of the path.
      wm_request(s, '/open/?sort=name')
      with_query, = wm_read(s)
      assert_true with_query.match?(/^Cache-Control: no-cache\r$/i), with_query

      # RFC 9111: the copy is kept, so the conditional request still saves
      # the body. no-cache is not no-store.
      stamp = generated[/^Last-Modified: *(.+)\r$/i, 1]
      assert_true !stamp.nil?, generated
      wm_request(s, '/open/', { 'If-Modified-Since' => stamp })
      again, = wm_read(s)
      assert_true again.start_with?('HTTP/1.1 304'), again

    end
  end
end
