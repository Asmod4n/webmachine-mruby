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

# One request, one connection, the whole answer as one string.
def ep_ask(sock, method, path, fields)
  body = %w[POST PUT].include?(method) ? 'a=b' : nil
  wm_conn(sock) do |s|
    wm_request(s, path, fields, method: method, body: body)
    wm_read(s).join
  end
end

assert('every_path: each route answers the terminal it exists for') do
  wm_server(File.read(EP_APP), tag: 'wm-ep') do |sock|
    EP_CASES.each do |method, path, fields, want|
      answer = ep_ask(sock, method, path, fields)
      got = answer[/\AHTTP\/1\.1 (\d+)/, 1].to_i
      assert_equal want, got, "#{method} #{path} #{fields.keys.join(',')}"
    end
  end
  true
end

assert('every_path: 303 carries the Location process_post set') do
  wm_server(File.read(EP_APP), tag: 'wm-ep') do |sock|
    answer = ep_ask(sock, 'POST', '/see-other', { 'Content-Type' => FORM })
    assert_include answer, "\r\nLocation: /ok\r\n"
  end
  true
end

assert('every_path: the response API reaches the wire') do
  wm_server(File.read(EP_APP), tag: 'wm-ep') do |sock|
    answer = ep_ask(sock, 'GET', '/writes-response', {})
    assert_include answer, "\r\nX-Every-Path: yes\r\n"
    assert_include answer, "\r\nX-Finished: yes\r\n"
    assert_include answer, 'Set-Cookie: every=path'
  end
  true
end
