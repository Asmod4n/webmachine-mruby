require 'socket'
require 'tempfile'

# RFC 6066 3: one listener, several certificates. conf.certificate and
# conf.private_key are the default pair; conf.certificates names a pair
# per host, and the ClientHello's server_name picks between them.
#
# The proof needs a real handshake, so it needs the tls ULP. A machine
# without it skips: the server refuses a TLS listener there, and says so.

# One self-signed P-256, valid for a century, written to two temporary
# files. Worth nothing outside this test.
def tls_sni_pair(common_name)
  cert = Tempfile.new(['wm-sni-cert', '.pem'])
  key = Tempfile.new(['wm-sni-key', '.pem'])
  cert.close
  key.close
  ok = system('openssl', 'req', '-x509', '-newkey', 'ec',
              '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '36500',
              '-subj', "/CN=#{common_name}", '-keyout', key.path, '-out', cert.path,
              out: File::NULL, err: File::NULL)
  raise "openssl could not make a certificate for #{common_name}" unless ok

  [cert, key]
end

# A port nobody is on, asked of the kernel and given back at once.
def tls_sni_free_port
  server = TCPServer.new('127.0.0.1', 0)
  port = server.addr[1]
  server.close
  port
end

# The server with its own conf, compiled as written: wm_server would add
# a second listener form to a source that already names conf.url, and two
# forms are refused.
def tls_sni_server(src, port)
  mrb = wm_compile(src, 'wm-sni-app')
  err = "/tmp/wm-sni-stderr-#{$$}.log"
  $tls_sni_server_log = ''
  pid = spawn(WM_BIN, "--app=#{mrb.path}", out: File::NULL, err: err)
  begin
    up = false
    60.times do
      begin
        TCPSocket.new('127.0.0.1', port).close
        up = true
        break
      rescue SystemCallError
        break if Process.waitpid(pid, Process::WNOHANG)

        sleep 0.1
      end
    end
    unless up
      reason = File.read(err) rescue ''
      return [false, reason]
    end
    yield
    [true, '']
  ensure
    Process.kill('TERM', pid) rescue nil
    Process.wait(pid) rescue nil
    # Read before the unlink: a failing case reports what the server said,
    # which is the only account of a connection that died after its
    # handshake.
    $tls_sni_server_log = (File.read(err) rescue '')
    File.unlink(err) rescue nil
    mrb.unlink
  end
end

# One request, and the three answers it carries: the subject of the
# certificate the server chose, the HTTP version the connection settled
# on, and the status. curl sends the name from the URL as the TLS
# server_name and --resolve points that name at this listener, which is
# exactly what a browser does.
#
# All three come from one connection on purpose. SNI sits below HTTP: the
# name picks the certificate, and ALPN then picks h2 or http/1.1 on that
# same connection. A named certificate whose TLS context never heard the
# ALPN list would answer with the right certificate and no ALPN at all,
# and the version here would be 1.1 instead of 2. Asking for all three is
# what notices that.
#
# --noproxy matters: a machine with HTTPS_PROXY set would otherwise send
# this request to the proxy instead of to the listener. -k because the
# certificates are self-signed and worth nothing.
def tls_sni_ask(port, servername)
  trace = "/tmp/wm-sni-curl-#{$$}.log"
  out = IO.popen(['curl', '-sk', '-v', '--noproxy', '*', '--http2',
                  '--resolve', "#{servername}:#{port}:127.0.0.1",
                  '-o', File::NULL,
                  '-w', "%{http_version} %{response_code}\n%{certs}",
                  "https://#{servername}:#{port}/", err: trace], 'r+') do |io|
    io.close_write
    io.read
  end
  said = (File.read(trace) rescue '')
  File.unlink(trace) rescue nil
  version, code = out.lines.first.to_s.split
  { subject: out[/^Subject:(.*)$/, 1].to_s.strip, version: version, code: code,
    trace: said.lines.grep(/^\* (ALPN|TLS|SSL|error|Recv|Connection|h2|using)/i).join }
end

assert('tls: one listener answers several names, and an unknown name gets the default (6066 3)') do
  # curl is what names the host in the handshake; nothing in this tree can
  # do that yet, because KTLS::Keys.client has no servername setter.
  skip 'no curl on PATH - nothing here can name a host in a handshake' unless
    system('curl', '--version', out: File::NULL, err: File::NULL)

  default_cert, default_key = tls_sni_pair('default.example')
  other_cert, other_key = tls_sni_pair('other.example')
  wild_cert, wild_key = tls_sni_pair('wild.example')
  port = tls_sni_free_port
  src = <<~RUBY
    class Sni < Webmachine::Resource
      def self.to_html
        'ok'
      end
    end

    def main
      Webmachine::Application.new do |app|
        app.conf.url = 'https://127.0.0.1:#{port}'
        app.conf.certificate = #{default_cert.path.inspect}
        app.conf.private_key = #{default_key.path.inspect}
        app.conf.certificates = {
          'other.example' => [#{other_cert.path.inspect}, #{other_key.path.inspect}],
          '*.api.example' => [#{wild_cert.path.inspect}, #{wild_key.path.inspect}]
        }
        app.add_route [:*], Sni
      end
    end
  RUBY

  answers = {}
  started, reason = tls_sni_server(src, port) do
    %w[other.example v1.api.example nothing.example default.example].each do |name|
      answers[name] = tls_sni_ask(port, name)
    end
  end
  if !started && reason.include?('tls ULP')
    skip 'this kernel has no tls ULP - a TLS listener cannot start here'
  end
  assert_true started, "the server did not come up: #{reason}"

  # The name conf.certificates holds gets that pair.
  assert_include answers['other.example'][:subject], 'CN = other.example'
  # One leading "*." matches exactly one label.
  assert_include answers['v1.api.example'][:subject], 'CN = wild.example'
  # A name nobody named keeps the default pair, rather than a refused
  # handshake that would say which names exist here.
  assert_include answers['nothing.example'][:subject], 'CN = default.example'
  # And so does the name the default pair itself carries.
  assert_include answers['default.example'][:subject], 'CN = default.example'

  # RFC 7301: and every one of those connections is HTTP/2 that answered.
  # The certificate a name picks comes with its own TLS context, and a
  # context that never heard the ALPN list would leave the connection at
  # HTTP/1.1 under every name but the default.
  answers.each do |name, answer|
    why = "under #{name}\ncurl said:\n#{answer[:trace]}server said:\n#{$tls_sni_server_log}"
    assert_equal '2', answer[:version], "not h2 #{why}"
    assert_equal '200', answer[:code], "no answer #{why}"
  end
ensure
  [default_cert, default_key, other_cert, other_key, wild_cert, wild_key].each do |file|
    file&.unlink
  end
end

# Compiles one app, runs the server, and answers what it said. Every case
# below is a refusal at build, so the process is expected to end on its
# own.
def tls_sni_refusal(src)
  mrb = wm_compile(src, 'wm-sni-refuse')
  err = "/tmp/wm-sni-refuse-#{$$}.log"
  pid = spawn(WM_BIN, "--app=#{mrb.path}", out: File::NULL, err: err)
  Process.wait(pid)
  said = File.read(err)
  File.unlink(err) rescue nil
  mrb.unlink
  said
end

# One app that names a listener and whatever conf.certificates is given.
def tls_sni_app(certificates, listener = "app.conf.unix_path = '/tmp/wm-sni-never.sock'")
  <<~RUBY
    class Sni2 < Webmachine::Resource
      def self.to_html
        'ok'
      end
    end

    def main
      Webmachine::Application.new do |app|
        #{listener}
        app.conf.certificates = #{certificates}
        app.add_route [:*], Sni2
      end
    end
  RUBY
end

assert('tls: conf.certificates is refused by shape, and without an https listener') do
  cert, key = tls_sni_pair('shape.example')
  pair = "[#{cert.path.inspect}, #{key.path.inspect}]"

  # mrblib's writer refuses a value of the wrong shape on the line that
  # wrote it, the way every other conf writer does. The refusal reaches
  # the operator as the reason the server did not start.
  assert_include tls_sni_refusal(tls_sni_app(cert.path.inspect)), 'wants a Hash'
  assert_include tls_sni_refusal(tls_sni_app("{ 'shop.example' => #{cert.path.inspect} }")),
                 'wants [certificate, private_key]'
  assert_include tls_sni_refusal(tls_sni_app("{ 'shop.example' => [#{cert.path.inspect}] }")),
                 'wants [certificate, private_key]'
  assert_include tls_sni_refusal(tls_sni_app("{ '' => #{pair} }")), 'certificates host name'

  # A pair named without https is the same mistake conf.certificate makes
  # there, and it gets the same refusal at build.
  assert_include tls_sni_refusal(tls_sni_app("{ 'shop.example' => #{pair} }")),
                 'its listener is not https'

  # A path that names no file is read where every other PEM is read, and
  # the message names the file.
  missing = "{ 'shop.example' => ['/nowhere/shop.crt', '/nowhere/shop.key'] }"
  said = tls_sni_refusal(tls_sni_app(missing, "app.conf.url = 'https://127.0.0.1:#{tls_sni_free_port}'\n" \
                                              "        app.conf.certificate = #{cert.path.inspect}\n" \
                                              "        app.conf.private_key = #{key.path.inspect}"))
  assert_include said, '/nowhere/shop.crt'
ensure
  cert&.unlink
  key&.unlink
end
