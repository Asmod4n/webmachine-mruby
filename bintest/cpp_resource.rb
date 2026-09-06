# #207 acceptance 1: a C++ resource and a Ruby resource that declare the
# same things answer the same bytes, over both protocols, on every
# method the resource allows.
#
# The pairs come from examples/cpp_resource.rb: /cppk against /rbk is
# the static tier (`def self.to_html`, baked at fold), /cpp against /rb
# is the dynamic one (`def to_html`, run per request). CppKonst and
# CppRun are defined in C++ - tools/webmachine-example/main.cpp - which
# is why this test drives that binary and not webmachine-server.
require 'socket'
require 'tempfile'

CPPR_BIN = File.join(ENV['BUILD_DIR'] || 'build/host', 'bin', 'webmachine-example')
CPPR_APP = File.expand_path('../examples/cpp_resource.rb', __dir__)

def cppr_server(&block)
  raise "no #{CPPR_BIN} - the example binary needs WM_EXAMPLES (build_config_debug.rb)" \
    unless File.executable?(CPPR_BIN)

  wm_server(File.read(CPPR_APP), bin: CPPR_BIN, tag: 'wm-cppr', &block)
end

# One request, one connection, the whole answer as one string.
def cppr_ask(sock, method, path, fields = {})
  wm_conn(sock) do |s|
    wm_request(s, path, fields, method: method)
    wm_read(s, body: method != 'HEAD').join
  end
end

# RFC 9110 6.6.1: Date is generated per answer, so it is the one field
# two resources may legitimately differ on. Everything else must match.
def cppr_undate(answer)
  answer.sub(/^Date: [^\r\n]*\r\n/, '')
end

# #210: an error page names the request target, so two answers about two
# different paths differ in that one string - and in the Content-Length
# it moves. Both are normalized the way Date is: replaced, not dropped,
# so everything else still has to match byte for byte.
def cppr_untarget(answer, path)
  answer.sub(/^Content-Length: \d+\r\n/, "Content-Length: N\r\n").gsub(path, '/TARGET')
end

# One h2 request as the first on its connection: the HPACK encoder is in
# its initial state both times, so two answers that mean the same are
# also spelled the same - which is what makes a byte comparison possible
# at all on a stateful encoding.
def cppr_h2_ask(sock, method, path)
  wm_conn(sock) do |s|
    h2_handshake(s)
    block = "\x02#{method.bytesize.chr}#{method}\x86\x04#{path.bytesize.chr}#{path}" \
            "\x41\x0bexample.com".b
    h2_stream(s, 1, block)
    h2_collect(s, 1).map { |type, _flags, _stream, payload| [type, payload] }
  end
end

assert('#207 h1: the C++ resource and the Ruby one answer the same bytes') do
  cppr_server do |sock|
    %w[/cppk /cpp].each_with_index do |cpp, i|
      rb = %w[/rbk /rb][i]
      %w[GET HEAD].each do |m|
        a = cppr_undate(cppr_ask(sock, m, cpp))
        b = cppr_undate(cppr_ask(sock, m, rb))
        assert_equal b, a, "#{m} #{cpp} differs from #{m} #{rb}"
        assert_true a.start_with?('HTTP/1.1 200 OK'), "#{m} #{cpp}: #{a[0, 40]}"
      end
      # The methods the resource does not allow - OPTIONS on the static
      # pair, which declares no allowed_methods, and POST on both. The
      # refusal has to match too, Allow header included; what it must
      # not do is differ between C++ and Ruby.
      %w[OPTIONS POST].each do |m|
        a = cppr_untarget(cppr_undate(cppr_ask(sock, m, cpp)), cpp)
        b = cppr_untarget(cppr_undate(cppr_ask(sock, m, rb)), rb)
        assert_equal b, a, "#{m} #{cpp} differs from #{m} #{rb}"
      end
    end
  end
end

assert('#207 h1: the dynamic pair agrees on ETag and on the 304 it earns') do
  cppr_server do |sock|
    a = cppr_ask(sock, 'GET', '/cpp')
    assert_true a.include?("ETag: \"v1\"\r\n"), "no ETag from the C++ resource: #{a[0, 120]}"
    a = cppr_undate(cppr_ask(sock, 'GET', '/cpp', 'If-None-Match' => '"v1"'))
    b = cppr_undate(cppr_ask(sock, 'GET', '/rb', 'If-None-Match' => '"v1"'))
    assert_true a.start_with?('HTTP/1.1 304 Not Modified'), a[0, 40]
    assert_equal b, a
  end
end

assert('#207 h2: the same pairs, frame for frame') do
  cppr_server do |sock|
    [%w[/cppk /rbk], %w[/cpp /rb]].each do |cpp, rb|
      %w[GET HEAD].each do |m|
        # The Date field rides inside the HPACK block, so a second
        # boundary between the two connections is a false negative, not
        # a difference in the resources. Retried, never slackened.
        ok = false
        3.times do
          ok = cppr_h2_ask(sock, m, cpp) == cppr_h2_ask(sock, m, rb)
          break if ok
        end
        assert_true ok, "h2 #{m} #{cpp} differs from h2 #{m} #{rb}"
      end
    end
  end
end
