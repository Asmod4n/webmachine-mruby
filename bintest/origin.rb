require 'socket'

# #4: request.same_origin? - the origin check, which is the half of CSRF
# defence a server makes with no state at all. Three answers: nil when the
# request carries no Origin, true when the Origin is the request's own, and
# false for any other origin.
ORIGIN_APP = <<~RUBY unless defined?(ORIGIN_APP)
  class Origins < Webmachine::Resource
    def to_html
      answer = request.same_origin?
      text = answer.nil? ? 'none' : answer.to_s
      response.headers['X-Same-Origin'] = text
      text
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.add_route [:*], Origins
    end
  end
RUBY

# One request with a Host of its own and, where the case names one, an
# Origin. Returns what the resource read.
def origin_case(sock, host, origin = nil)
  UNIXSocket.open(sock) do |s|
    request = +"GET / HTTP/1.1\r\nHost: #{host}\r\nConnection: close\r\n"
    request << "Origin: #{origin}\r\n" if origin
    request << "\r\n"
    s.write(request)
    head, = wm_read(s)
    head[/^X-Same-Origin: (.*)\r$/, 1]
  end
end

assert('origin: same_origin? answers nil, true or false (RFC 6454 6.1)') do
  wm_server(ORIGIN_APP, tag: 'wm-origin') do |sock|
    # A client that is not a browser sends no Origin. Absent is not
    # cross-site, so the answer is nil and the resource decides what that
    # means.
    assert_equal 'none', origin_case(sock, 'x')
    # The listener here is a unix socket and carries no TLS, so the
    # request's own origin is http:// and its Host.
    assert_equal 'true', origin_case(sock, 'x', 'http://x')
    # Another host is another origin.
    assert_equal 'false', origin_case(sock, 'x', 'http://y')
    # Another scheme is another origin, whatever the host says.
    assert_equal 'false', origin_case(sock, 'x', 'https://x')
    # The opaque origin. It carries no scheme, so it is not this one.
    assert_equal 'false', origin_case(sock, 'x', 'null')
    # RFC 9110 4.2.3: the scheme and the host compare without regard to
    # letter case.
    assert_equal 'true', origin_case(sock, 'X', 'HTTP://x')
    assert_equal 'true', origin_case(sock, 'x', 'http://X')
    # A browser leaves the default port out of an Origin, so a Host that
    # names it is still the same origin.
    assert_equal 'true', origin_case(sock, 'x:80', 'http://x')
    assert_equal 'true', origin_case(sock, 'x', 'http://x:80')
    assert_equal 'true', origin_case(sock, 'x:80', 'http://x:80')
    # Another port is another origin.
    assert_equal 'false', origin_case(sock, 'x:8080', 'http://x')
    assert_equal 'false', origin_case(sock, 'x', 'http://x:8080')
    # :443 is not the default port of http, so it is not dropped here.
    assert_equal 'false', origin_case(sock, 'x', 'http://x:443')
    # An Origin with a path is not an origin at all.
    assert_equal 'false', origin_case(sock, 'x', 'http://x/')
    # And an empty Origin is present but names nothing.
    assert_equal 'false', origin_case(sock, 'x', '')
  end
end

# RFC 9113 8.3.1: an h2 request names its host in :authority, and that
# pseudo-header does not reach the Host value request.host reads. So the
# comparison has nothing of its own to compare against and answers nil
# rather than a false that would read as "another origin". A client that
# sends a host field beside the authority gets the full answer.
assert('origin: an h2 request with no host field answers nil, one with a host field answers') do
  h2_server(ORIGIN_APP) do |sock|
    UNIXSocket.open(sock) do |s|
      h2_handshake(s)
      # :authority alone, and an Origin beside it.
      block = "\x82\x86\x84\x01\x0bexample.com".b + h2_lit('origin', 'http://example.com')
      s.write(h2_frame(1, 0x05, 1, block))
      _, _, _, answer = h2_until(s, 0, 1)
      assert_equal 'none', answer
      # And with a host field, which is what the comparison reads.
      block = "\x82\x86\x84\x01\x0bexample.com".b + h2_lit('host', 'example.com') +
              h2_lit('origin', 'http://example.com')
      s.write(h2_frame(1, 0x05, 3, block))
      _, _, _, answer = h2_until(s, 0, 3)
      assert_equal 'true', answer
      block = "\x82\x86\x84\x01\x0bexample.com".b + h2_lit('host', 'example.com') +
              h2_lit('origin', 'http://elsewhere.example')
      s.write(h2_frame(1, 0x05, 5, block))
      _, _, _, answer = h2_until(s, 0, 5)
      assert_equal 'false', answer
    end
  end
end
