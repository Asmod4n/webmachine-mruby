# examples/every_path.rb has one route per way through the flow graph.
# This asks for every one of them and checks the terminal it exists to
# produce - so a route that stops producing it is a failing test, not a
# surprise in somebody's profile.
#
# The graph has 24 terminals (grep halt( in webmachine.hpp); the table
# below covers all of them, plus the two routes that read the whole
# request API and write the whole response API without moving the status.
require 'socket'
require 'tempfile'

EP_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server')
EP_APP = File.expand_path('../examples/every_path.rb', __dir__)

FORM = 'application/x-www-form-urlencoded'.freeze

# method, path, request fields, the status the route exists to produce.
EP_CASES = [
  ['GET',    '/ok',                  {},                                    200],
  ['GET',    '/unavailable',         {},                                    503],
  ['DELETE', '/known-only',          {},                                    501],
  ['GET',    '/uri-too-long',        {},                                    414],
  ['POST',   '/get-only',            {},                                    405],
  ['GET',    '/malformed',           {},                                    400],
  ['GET',    '/unauthorized',        {},                                    401],
  ['GET',    '/forbidden',           {},                                    403],
  ['GET',    '/bad-content-headers', {},                                    501],
  ['GET',    '/bad-type',            {},                                    415],
  ['GET',    '/too-large',           {},                                    413],
  ['GET',    '/negotiate',           { 'Accept' => 'image/tiff' },          406],
  ['GET',    '/negotiate',           { 'Accept' => 'application/json' },    200],
  ['GET',    '/conditional',         { 'If-None-Match' => '"every-path-1"' }, 304],
  ['GET',    '/conditional',         { 'If-Match' => '"nope"' },            412],
  ['GET',    '/missing',             {},                                    404],
  ['GET',    '/gone',                {},                                    410],
  ['GET',    '/moved-permanently',   {},                                    301],
  ['GET',    '/moved-temporarily',   {},                                    307],
  ['GET',    '/choices',             {},                                    300],
  ['DELETE', '/delete-accepted',     {},                                    202],
  ['DELETE', '/delete-done',         {},                                    204],
  ['POST',   '/created',             { 'Content-Type' => FORM },            201],
  ['POST',   '/see-other',           { 'Content-Type' => FORM },            303],
  ['PUT',    '/conflict',            { 'Content-Type' => FORM },            409],
  ['GET',    '/boom',                {},                                    500],
  ['GET',    '/reads-request',       { 'Cookie' => 'a=b' },                 200],
  ['GET',    '/writes-response',     {},                                    200]
].freeze

def ep_server
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  app = Tempfile.new(['wm-ep', '.mrb'])
  app.close
  raise "mrbc failed on #{EP_APP}" unless system(mrbc, '-o', app.path, EP_APP)

  sock = "/tmp/wm-ep-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-ep-stderr-#{$$}.log"
  pid = spawn(EP_BIN, '--unix', sock, '--app', app.path, out: File::NULL, err: err)
  100.times { break if File.socket?(sock); sleep 0.05 }
  raise "server never came up:\n#{File.read(err) rescue ''}" unless File.socket?(sock)
  begin
    yield sock
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    File.unlink(sock) rescue nil
    app.unlink
  end
end

# One request, one connection: Connection: close makes the socket itself
# the framing, so nothing here has to agree with the writer about lengths.
def ep_ask(sock, method, path, fields)
  body = %w[POST PUT].include?(method) ? 'a=b' : ''
  UNIXSocket.open(sock) do |s|
    head = +"#{method} #{path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n"
    fields.each { |k, v| head << "#{k}: #{v}\r\n" }
    head << "Content-Length: #{body.bytesize}\r\n" unless body.empty?
    head << "\r\n"
    s.write(head + body)
    out = +''.b
    loop do
      IO.select([s], nil, nil, 10) or raise "read deadline on #{method} #{path}"
      out << s.readpartial(65_536)
    rescue EOFError
      break
    end
    out
  end
end

assert('every_path: each route answers the terminal it exists for') do
  ep_server do |sock|
    EP_CASES.each do |method, path, fields, want|
      answer = ep_ask(sock, method, path, fields)
      got = answer[/\AHTTP\/1\.1 (\d+)/, 1].to_i
      assert_equal want, got, "#{method} #{path} #{fields.keys.join(',')}"
    end
  end
  true
end

assert('every_path: 303 carries the Location process_post set') do
  ep_server do |sock|
    answer = ep_ask(sock, 'POST', '/see-other', { 'Content-Type' => FORM })
    assert_include answer, "\r\nLocation: /ok\r\n"
  end
  true
end

assert('every_path: the response API reaches the wire') do
  ep_server do |sock|
    answer = ep_ask(sock, 'GET', '/writes-response', {})
    assert_include answer, "\r\nX-Every-Path: yes\r\n"
    assert_include answer, "\r\nX-Finished: yes\r\n"
    assert_include answer, 'Set-Cookie: every=path'
  end
  true
end
