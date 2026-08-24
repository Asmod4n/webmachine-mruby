# The objects webmachine-ruby's specs CONSTRUCT around the FSM. Plain
# Ruby, because none of them touches the flow - only the FSM does, and
# that one is C (test/wm_ruby.cpp).
#
# The names are deliberately not Webmachine::Request / ::Response: those
# two are the PRODUCT's, defined in C (src/request.cpp, src/response.cpp)
# as handles the run frame binds, and an app never builds one. What the
# oracle needs is a plain value object to hand the shim on the way in and
# to read back on the way out, so it gets its own name.
module Webmachine
  # RFC 9110 5.1: a field name is case-insensitive. The specs spell them
  # in mixed case ('Content-MD5', 'If-None-Match'); the smallest thing
  # that is true is to store and read them downcased.
  class Headers < Hash
    def self.[](pairs = nil)
      h = new
      pairs.each { |k, v| h[k] = v } if pairs
      h
    end

    def [](k)
      super(k.to_s.downcase)
    end

    def []=(k, v)
      super(k.to_s.downcase, v)
    end

    def delete(k)
      super(k.to_s.downcase)
    end

    def key?(k)
      super(k.to_s.downcase)
    end
  end

  # What the spec's Webmachine::Request.new(method, uri, headers, body)
  # carries, minus the URI object mruby has no class for - the authority
  # rides in the Host field and the path is a String, which is what the
  # ReqView the shim builds wants anyway.
  class SpecRequest
    attr_accessor :method, :path, :headers, :body

    def initialize(method = 'GET', path = '/', headers = nil, body = nil)
      @method = method
      @path = path
      @headers = headers || Headers.new
      @body = body
    end
  end

  # What the spec reads after subject.run: the status, the field lines
  # and the representation.
  class SpecResponse
    attr_accessor :code, :body
    attr_reader :headers

    def initialize
      @code = 0
      @headers = Headers.new
      @body = nil
    end
  end
end

assert('wm-ruby oracle: the shim drives the real flow') do
  klass = Class.new(Webmachine::Resource) do
    def to_html
      'test resource'
    end
  end
  req = Webmachine::SpecRequest.new('GET', '/', Webmachine::Headers['Host' => 'localhost'])
  res = Webmachine::SpecResponse.new
  Webmachine::Decision::FSM.new(klass, req, res).run
  assert_equal 200, res.code
  assert_equal 'test resource', res.body
end

assert('wm-ruby oracle: the digest helpers the Content-MD5 cases need') do
  # RFC 1321 / RFC 4648 test vectors, so a wrong helper cannot quietly
  # make a b9a case pass.
  assert_equal 'd41d8cd98f00b204e9800998ecf8427e', Webmachine::TestDigest.md5_hex('')
  assert_equal '900150983cd24fb0d6963f7d28e17f72', Webmachine::TestDigest.md5_hex('abc')
  assert_equal 'Zg==', Webmachine::TestDigest.b64('f')
  assert_equal 'Zm9vYmFy', Webmachine::TestDigest.b64('foobar')
end

# The oracle's cases, run. They are REGISTERED by test/wm_flow.rb and
# test/wm_helpers.rb rather than asserted there, because mruby loads a
# gem's test/**/*.rb in sorted order - wm_flow, wm_helpers, wm_ruby -
# and `assert` runs its block the moment it is called. The classes above
# do not exist yet at that point. One queue, drained here, keeps every
# case where the port put it and still gives each its own assert.
$wm_cases.each { |name, blk| assert(name) { blk.call } } if $wm_cases
