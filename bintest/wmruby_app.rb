
require 'socket'
require 'tempfile'

WMR_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-server') unless defined?(WMR_BIN)

def wmr_compile(app_source)
  src = Tempfile.new(['wmr-app', '.rb'])
  src.write(app_source)
  src.close
  mrbc = ENV['MRBCFILE'] or raise 'MRBCFILE not set - bintest must run under rake bintest'
  mrb = Tempfile.new(['wmr-app', '.mrb'])
  mrb.close
  ok = system(mrbc, '-o', mrb.path, src.path)
  raise "mrbc failed to compile:\n#{app_source}" unless ok
  mrb
ensure
  src&.unlink
end

def wmr_server(app_source)
  app = wmr_compile(app_source)
  sock = "/tmp/wm-oracle-#{$$}.sock"
  File.unlink(sock) if File.exist?(sock)
  err = "/tmp/wm-oracle-stderr-#{$$}.log"
  pid = spawn({ 'WM_BUNDLE' => '0' }, WMR_BIN, "--unix=#{sock}", "--app=#{app.path}",
              out: File::NULL, err: err)
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

def wmr_recv(s, maxlen = 1, deadline = 10)
  IO.select([s], nil, nil, deadline) or raise "read deadline: no bytes in #{deadline}s (server wedged?)"
  s.readpartial(maxlen)
end

def wmr_read(s)
  head = +''
  head << wmr_recv(s) until head.end_with?("\r\n\r\n")
  len = head[/^Content-Length: *(\d+)\r$/i, 1].to_i
  body = +''
  body << wmr_recv(s, len - body.bytesize) while body.bytesize < len
  [head, body]
end

WMR_AUTH = 'Basic c3BlYzpzcGVj' unless defined?(WMR_AUTH)

def wmr_request(s, method, path = '/', fields = {}, body = nil)
  head = +"#{method} #{path} HTTP/1.1\r\nHost: oracle\r\n"
  fields.each { |k, v| head << "#{k}: #{v}\r\n" }
  head << "Content-Length: #{body.bytesize}\r\n" if body
  head << "\r\n"
  head << body if body
  s.write(head)
  wmr_read(s)
end

WMR_APP = <<~'RUBY' unless defined?(WMR_APP)
  class OracleDoc < Webmachine::Resource
    ETAG = 'v1-oracle'
    STAMP = 1000000000  # Sun, 09 Sep 2001 01:46:40 GMT

    def allowed_methods
      %w[GET HEAD POST PUT DELETE]
    end

    def content_types_provided
      [['text/html', :to_html]]
    end

    def content_types_accepted
      [['text/plain', :accept_text]]
    end

    def is_authorized?(authorization)
      return true if authorization == 'Basic c3BlYzpzcGVj'
      'Basic realm=Webmachine'
    end

    def generate_etag
      ETAG
    end

    def last_modified
      Time.at(STAMP)
    end

    def post_is_create?
      true
    end

    def create_path
      '/created/1'
    end

    def accept_text
      true
    end

    def delete_resource
      true
    end

    def delete_completed?
      true
    end

    def to_html
      '<html><body>oracle</body></html>'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.routes do |route|
        route.add [:*], OracleDoc
      end
    end
  end
RUBY

assert('wm-ruby app: GET carries the representation, its ETag and its Last-Modified') do
  wmr_server(WMR_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      head, body = wmr_request(s, 'GET', '/', 'Authorization' => WMR_AUTH)
      assert_true head.start_with?('HTTP/1.1 200'), head.lines.first.to_s
      assert_equal '<html><body>oracle</body></html>', body
      assert_true head.match?(%r{^Content-Type: text/html; charset=utf-8\r$}i), head
      assert_true head.match?(/^ETag: "v1-oracle"\r$/i), head
      assert_true head.match?(/^Last-Modified: Sun, 09 Sep 2001 01:46:40 GMT\r$/i), head
    end
  end
end

assert('wm-ruby app: If-None-Match of the served ETag answers 304') do
  wmr_server(WMR_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      head, = wmr_request(s, 'GET', '/', 'Authorization' => WMR_AUTH)
      etag = head[/^ETag: *(\S+)\r$/i, 1]
      assert_equal '"v1-oracle"', etag
      head2, = wmr_request(s, 'GET', '/', 'Authorization' => WMR_AUTH, 'If-None-Match' => etag)
      assert_true head2.start_with?('HTTP/1.1 304'), head2.lines.first.to_s
    end
  end
end

assert('wm-ruby app: no Authorization answers 401 with the challenge (b8)') do
  wmr_server(WMR_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      head, = wmr_request(s, 'GET', '/')
      assert_true head.start_with?('HTTP/1.1 401'), head.lines.first.to_s
      assert_true head.match?(/^WWW-Authenticate: Basic realm=Webmachine\r$/i), head
      head2, = wmr_request(s, 'GET', '/', 'Authorization' => 'Basic bogus')
      assert_true head2.start_with?('HTTP/1.1 401'), head2.lines.first.to_s
    end
  end
end

assert('wm-ruby app: POST creates and answers 201 with Location (n11 -> p11)') do
  wmr_server(WMR_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      head, = wmr_request(s, 'POST', '/',
                          { 'Authorization' => WMR_AUTH, 'Content-Type' => 'text/plain' },
                          'a new thing')
      assert_true head.start_with?('HTTP/1.1 201'), head.lines.first.to_s
      loc = head[/^Location: *(\S+)\r$/i, 1]
      assert_true !loc.nil? && loc.end_with?('/created/1'), head
    end
  end
end

assert('wm-ruby app: a PUT the resource does not accept answers 415 (o14)') do
  wmr_server(WMR_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      head, = wmr_request(s, 'PUT', '/',
                          { 'Authorization' => WMR_AUTH, 'Content-Type' => 'application/xml' },
                          '<doc/>')
      assert_true head.start_with?('HTTP/1.1 415'), head.lines.first.to_s
      head2, = wmr_request(s, 'PUT', '/',
                           { 'Authorization' => WMR_AUTH, 'Content-Type' => 'text/plain' },
                           'replacement')
      assert_true head2.start_with?('HTTP/1.1 204'), head2.lines.first.to_s
    end
  end
end

assert('wm-ruby app: DELETE completes and answers 204 (m20 -> m20b -> o20)') do
  wmr_server(WMR_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      head, = wmr_request(s, 'DELETE', '/', 'Authorization' => WMR_AUTH)
      assert_true head.start_with?('HTTP/1.1 204'), head.lines.first.to_s
      assert_true !head.match?(/^Content-Length: *[1-9]/i), head
    end
  end
end

assert('wm-ruby app: a known method outside allowed_methods answers 405, Allow names the list') do
  wmr_server(WMR_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      head, = wmr_request(s, 'OPTIONS', '/', 'Authorization' => WMR_AUTH)
      assert_true head.start_with?('HTTP/1.1 405'), head.lines.first.to_s
      assert_true head.match?(/^Allow: GET, HEAD, POST, PUT, DELETE\r$/i), head
    end
  end
end

assert('wm-ruby app: an unknown method answers 501 (b12)') do
  wmr_server(WMR_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      head, = wmr_request(s, 'PATCH', '/',
                          { 'Authorization' => WMR_AUTH, 'Content-Type' => 'text/plain' },
                          'patchbody')
      assert_true head.start_with?('HTTP/1.1 501'), head.lines.first.to_s
    end
  end
end

assert('wm-ruby app: HEAD answers the GET head and no body bytes') do
  wmr_server(WMR_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      s.write("HEAD / HTTP/1.1\r\nHost: oracle\r\nAuthorization: #{WMR_AUTH}\r\n\r\n" \
              "GET / HTTP/1.1\r\nHost: oracle\r\nAuthorization: #{WMR_AUTH}\r\n\r\n")
      hh = +''
      hh << wmr_recv(s) until hh.end_with?("\r\n\r\n")
      assert_true hh.start_with?('HTTP/1.1 200'), hh.lines.first.to_s
      assert_true hh.match?(/^Content-Length: 32\r$/i), hh
      nxt, body = wmr_read(s)
      assert_true nxt.start_with?('HTTP/1.1 200 OK'), "HEAD leaked body bytes: #{nxt.inspect}"
      assert_equal '<html><body>oracle</body></html>', body
    end
  end
end
