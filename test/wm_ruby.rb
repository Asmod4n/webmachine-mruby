module Webmachine
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

  class SpecRequest
    attr_accessor :method, :path, :headers, :body

    def initialize(method = 'GET', path = '/', headers = nil, body = nil)
      @method = method
      @path = path
      @headers = headers || Headers.new
      @body = body
    end
  end

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
  assert_equal 'd41d8cd98f00b204e9800998ecf8427e', Webmachine::TestDigest.md5_hex('')
  assert_equal '900150983cd24fb0d6963f7d28e17f72', Webmachine::TestDigest.md5_hex('abc')
  assert_equal 'Zg==', Webmachine::TestDigest.b64('f')
  assert_equal 'Zm9vYmFy', Webmachine::TestDigest.b64('foobar')
end

$wm_cases.each { |name, blk| assert(name) { blk.call } } if $wm_cases
