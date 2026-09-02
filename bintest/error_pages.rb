# #210: an error page says nothing the client sent. What a request asked
# for is in the error log, which is where a request belongs; the page
# carries the status, what the exception said, and the fingerprint of the
# failure - and that fingerprint is the whole bridge between the two.
#
# A user reads the reference off the page, an operator greps it in the
# log and has the target, the method, the fields it steered by, the body
# and the trace. These check both ends of that bridge, and that nothing
# of the request leaks into the page on the way.
require 'socket'
require 'tempfile'

EPG_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server')
EPG_APP = File.expand_path('../examples/every_path.rb', __dir__)

# What a client can put in a target: the five characters mustache escapes
# for HTML, and a tag that must not come back as one.
EPG_NASTY = %q{a=<script>alert(1)</script>&b="q"&c='z'}.freeze

def epg_server
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  app = Tempfile.new(['wm-epg', '.mrb'])
  app.close
  raise "mrbc failed on #{EPG_APP}" unless system(mrbc, '-o', app.path, EPG_APP)

  sock = "/tmp/wm-epg-#{$$}.sock"
  log = "/tmp/wm-epg-#{$$}.log"
  err = "/tmp/wm-epg-stderr-#{$$}.log"
  [sock, log].each { |f| File.unlink(f) rescue nil }
  pid = spawn(EPG_BIN, "--unix=#{sock}", "--app=#{app.path}", "--error-log=#{log}",
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock, log
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    [sock, log, err].each { |f| File.unlink(f) rescue nil }
    app.unlink
  end
end

def epg_ask(sock, path, fields = {})
  UNIXSocket.open(sock) do |s|
    head = +"GET #{path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
    fields.each { |k, v| head << "#{k}: #{v}\r\n" }
    head << "\r\n"
    s.write(head)
    out = +''.b
    loop do
      IO.select([s], nil, nil, 10) or raise "read deadline on #{path}"
      out << s.readpartial(65_536)
    rescue EOFError
      break
    end
    out
  end
end

# The 16 hex digits the page names itself by.
def epg_reference(page)
  page[/Reference ([0-9a-f]{16})/, 1]
end

assert('error pages: nothing the client sent comes back in the page') do
  epg_server do |sock, _log|
    answer = epg_ask(sock, "/no-such-route?#{EPG_NASTY}")
    assert_equal 404, answer[%r{\AHTTP/1\.1 (\d+)}, 1].to_i
    body = answer.split("\r\n\r\n", 2)[1].to_s
    # Not escaped, not encoded, not there: neither the tag the client
    # wrote nor the path it asked for.
    assert_false body.include?('script')
    assert_false body.include?('&lt;')
    assert_false body.include?('no-such-route')
  end
  true
end

assert('error pages: a 500 names the failure, a 404 has none to name') do
  epg_server do |sock, _log|
    boom = epg_ask(sock, '/boom')
    assert_equal 500, boom[%r{\AHTTP/1\.1 (\d+)}, 1].to_i
    assert_true !epg_reference(boom).nil?, 'a 500 carries a reference'
    # A 4xx is an answer, not a failure - nothing raised, so there is
    # nothing to look up and no reference to hand out.
    missing = epg_ask(sock, '/no-such-route')
    assert_equal 404, missing[%r{\AHTTP/1\.1 (\d+)}, 1].to_i
    assert_true epg_reference(missing).nil?, 'a 404 carries none'
  end
  true
end

assert('error pages: the same failure hashes the same, a different one does not') do
  epg_server do |sock, _log|
    once = epg_reference(epg_ask(sock, '/boom'))
    twice = epg_reference(epg_ask(sock, '/boom'))
    assert_equal once, twice
    # The target is what led there, so a different one is a different
    # failure even at the same line.
    elsewhere = epg_reference(epg_ask(sock, '/boom?after=save'))
    assert_true !elsewhere.nil?
    assert_true once != elsewhere, 'a different target is a different reference'
  end
  true
end

assert('error pages: the reference on the page is the one in the log') do
  epg_server do |sock, log|
    said = epg_reference(epg_ask(sock, '/boom?after=save'))
    assert_true !said.nil?
    # The daemon writes the decoded record; the hash leads the line, so
    # this is the grep a person would type.
    20.times do
      break if File.exist?(log) && File.read(log).include?(said)
      sleep 0.05
    end
    text = File.read(log)
    assert_include text, said
    line = text.lines.find { |l| l.include?(said) }
    # And beside it, what the page refused to say: the request.
    assert_include line, '/boom?after=save'
    assert_include line, 'GET'
  end
  true
end

# conf.disable_http_cats: the pictures are a default, not a requirement.
# The pack is never opened, so no page names one and nothing is mounted at
# /error_assets/ - and the page itself still renders, because the
# templates were never in the pack to begin with.
EPG_NO_CATS = <<~APP
  class Ok < Webmachine::Resource
    def to_html
      '<html><body>ok</body></html>'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.conf.disable_http_cats = true
      app.add_route [], Ok
    end
  end
APP

assert('error pages: conf.disable_http_cats leaves the pages and drops the pictures') do
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  src = Tempfile.new(['wm-nocats', '.rb'])
  src.write(EPG_NO_CATS)
  src.close
  app = Tempfile.new(['wm-nocats', '.mrb'])
  app.close
  raise 'mrbc failed' unless system(mrbc, '-o', app.path, src.path)

  pack = File.expand_path('../share/error-assets.zip', __dir__)
  sock = "/tmp/wm-nocats-#{$$}.sock"
  err = "/tmp/wm-nocats-stderr-#{$$}.log"
  File.unlink(sock) rescue nil
  pid = spawn(EPG_BIN, "--unix=#{sock}", "--app=#{app.path}", "--error-assets=#{pack}",
              out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    answer = epg_ask(sock, '/no-such-route')
    assert_equal 404, answer[%r{\AHTTP/1\.1 (\d+)}, 1].to_i
    # The page is there - it never lived in the pack.
    assert_include answer, 'Not Found'
    # The picture is not, and neither is the route it would have come from.
    assert_false answer.include?('img src')
    assert_false answer.include?('/error_assets/')
    picture = epg_ask(sock, '/error_assets/404.jpg')
    assert_equal 404, picture[%r{\AHTTP/1\.1 (\d+)}, 1].to_i
    # And the operator was told, once, that this was asked for.
    assert_include File.read(err), 'conf.disable_http_cats'
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    [sock, err].each { |f| File.unlink(f) rescue nil }
    app.unlink
    src.unlink
  end
  true
end

# The pack carries the whole <img> (assets.rb checks what is written),
# and the page emits it as it stands. Unescaped is the point - through
# {{ }} the tag would arrive as &lt;img and mean nothing - and the alt
# has to name the status the page's own <h1> names, which is the thing
# a second table would eventually get wrong.
assert('error pages: the page names the size of the picture it shows') do
  epg_server do |sock, _log|
    body = epg_ask(sock, '/no-such-route').split("\r\n\r\n", 2)[1].to_s
    skip 'this build ships no error assets' unless body.include?('<img src=')
    m = body.match(/<img src="[^"]+" width="(\d+)" height="(\d+)" alt="([^"]*)">/)
    assert_true !m.nil?, 'the page carries no finished img'
    assert_true m[1].to_i > 0 && m[2].to_i > 0, "the img is #{m[1]}x#{m[2]}"
    assert_false body.include?('&lt;img'), 'the tag came through escaped'
    # What the picture is said to be, and what the page says it is.
    assert_include m[3], body[%r{<h1>([^<]+)</h1>}, 1]
  end
  true
end
