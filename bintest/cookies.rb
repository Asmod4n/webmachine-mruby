require 'socket'

# RFC 6265bis 4.1.2.7 and 4.1.3: SameSite, and the two name prefixes a
# browser enforces. A cookie that breaks one of those rules is dropped by
# the browser and nothing says why, so set_cookie refuses it at the call.
#
# Each case arrives as X-Case on one request. The resource rescues the
# refusal and puts the message in X-Refused, so the test reads the rule
# the server applied instead of a 500.
COOKIE_APP = <<~RUBY unless defined?(COOKIE_APP)
  class Cookies < Webmachine::Resource
    def to_html
      case request.headers['x-case'].to_s
      when 'plain'
        response.set_cookie('a', '1', path: '/')
      when 'same-site-lax'
        response.set_cookie('a', '1', same_site: 'Lax')
      when 'same-site-strict-symbol'
        response.set_cookie('a', '1', same_site: :strict)
      when 'same-site-upper'
        response.set_cookie('a', '1', same_site: 'LAX')
      when 'same-site-none-secure'
        response.set_cookie('a', '1', same_site: 'None', secure: true)
      when 'same-site-none-bare'
        response.set_cookie('a', '1', same_site: 'None')
      when 'same-site-unknown'
        response.set_cookie('a', '1', same_site: 'Sometimes')
      when 'host-ok'
        response.set_cookie('__Host-a', '1', secure: true, path: '/')
      when 'host-no-secure'
        response.set_cookie('__Host-a', '1', path: '/')
      when 'host-with-domain'
        response.set_cookie('__Host-a', '1', secure: true, path: '/',
                                             domain: 'example.com')
      when 'host-wrong-path'
        response.set_cookie('__Host-a', '1', secure: true, path: '/app')
      when 'host-no-path'
        response.set_cookie('__Host-a', '1', secure: true)
      when 'host-no-attributes'
        response.set_cookie('__Host-a', '1')
      when 'host-lowercase'
        response.set_cookie('__host-a', '1', path: '/')
      when 'secure-ok'
        response.set_cookie('__Secure-a', '1', secure: true)
      when 'secure-bare'
        response.set_cookie('__Secure-a', '1')
      when 'secure-lowercase'
        response.set_cookie('__secure-a', '1')
      end
      'ok'
    rescue Webmachine::Error => refusal
      response.headers['X-Refused'] = refusal.message
      'refused'
    end
  end

  def main
    Webmachine::Application.new do |app|
      app.add_route [:*], Cookies
    end
  end
RUBY

# Asks one case and returns [body, the Set-Cookie line or nil, X-Refused
# or nil].
def cookie_case(sock, name)
  UNIXSocket.open(sock) do |s|
    wm_request(s, '/', { 'X-Case' => name }, close: true)
    head, body = wm_read(s)
    cookie = head[/^Set-Cookie: (.*)\r$/, 1]
    refused = head[/^X-Refused: (.*)\r$/, 1]
    [body, cookie, refused]
  end
end

assert('cookies: SameSite is written, and None without Secure is refused (6265bis 4.1.2.7)') do
  wm_server(COOKIE_APP, tag: 'wm-cookie-same-site') do |sock|
    # The attribute this work adds. It goes out after Secure and HttpOnly.
    body, cookie, = cookie_case(sock, 'same-site-lax')
    assert_equal 'ok', body
    assert_equal 'a=1; SameSite=Lax', cookie
    # A Symbol names it as well, because the call turns the value into a
    # String the same way every other attribute does.
    _, cookie, = cookie_case(sock, 'same-site-strict-symbol')
    assert_equal 'a=1; SameSite=Strict', cookie
    # The value is read without regard to letter case, and the line
    # carries the spelling the RFC writes.
    _, cookie, = cookie_case(sock, 'same-site-upper')
    assert_equal 'a=1; SameSite=Lax', cookie
    # None with Secure beside it is the one legal way to write None.
    _, cookie, = cookie_case(sock, 'same-site-none-secure')
    assert_equal 'a=1; Secure; SameSite=None', cookie
    # And without Secure the browser drops it, so the call raises.
    body, cookie, refused = cookie_case(sock, 'same-site-none-bare')
    assert_equal 'refused', body
    assert_nil cookie
    assert_include refused.to_s, 'Secure beside SameSite=None'
    # A fourth spelling is not a SameSite value at all.
    body, cookie, refused = cookie_case(sock, 'same-site-unknown')
    assert_equal 'refused', body
    assert_nil cookie
    assert_include refused.to_s, 'Strict, Lax or None'
    # A cookie that names no SameSite is written as it always was.
    _, cookie, = cookie_case(sock, 'plain')
    assert_equal 'a=1; Path=/', cookie
  end
end

assert('cookies: the __Host- and __Secure- name prefixes keep their promise (6265bis 4.1.3)') do
  wm_server(COOKIE_APP, tag: 'wm-cookie-prefix') do |sock|
    # __Host- needs Secure, no Domain and Path=/. All three together pass.
    body, cookie, = cookie_case(sock, 'host-ok')
    assert_equal 'ok', body
    assert_equal '__Host-a=1; Path=/; Secure', cookie
    # And each broken rule is its own refusal.
    %w[host-no-secure host-with-domain host-wrong-path host-no-path
       host-no-attributes].each do |name|
      body, cookie, refused = cookie_case(sock, name)
      assert_equal 'refused', body, name
      assert_nil cookie, name
      assert_include refused.to_s, 'for a __Host- name'
    end
    # A browser reads the prefix without regard to letter case, so this
    # server reads it the same way.
    body, _, refused = cookie_case(sock, 'host-lowercase')
    assert_equal 'refused', body
    assert_include refused.to_s, 'for a __Host- name'
    # __Secure- needs Secure, and nothing else.
    body, cookie, = cookie_case(sock, 'secure-ok')
    assert_equal 'ok', body
    assert_equal '__Secure-a=1; Secure', cookie
    body, cookie, refused = cookie_case(sock, 'secure-bare')
    assert_equal 'refused', body
    assert_nil cookie
    assert_include refused.to_s, 'for a __Secure- name'
    body, _, refused = cookie_case(sock, 'secure-lowercase')
    assert_equal 'refused', body
    assert_include refused.to_s, 'for a __Secure- name'
  end
end
