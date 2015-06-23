module Webmachine
  # Request represents a single HTTP request sent from a client. It
  # should be instantiated by {Adapters} when a request is received
  class Request
    extend Forwardable

    attr_reader :method, :uri, :headers, :body, :routing_tokens, :base_uri
    attr_accessor :disp_path, :path_info, :path_tokens

    # @param [String] method the HTTP request method
    # @param [URI] uri the requested URI, including host, scheme and
    #   port
    # @param [Headers] headers the HTTP request headers
    # @param [String,#to_s,#each,nil] body the entity included in the
    #   request, if present
    def initialize(method, uri, headers, body, routing_tokens=nil, base_uri=nil)
      @method = method
      @uri = uri
      @headers = headers
      @routing_tokens = routing_tokens
      @base_uri = base_uri
    end

    def_delegators :headers, :[]

    # The cookies sent in the request.
    #
    # @return [Hash]
    #   {} if no Cookies header set
    def cookies
      unless @cookies
        @cookies = Webmachine::Cookie.parse(headers['Cookie'])
      end
      @cookies
    end

    # Is this an HTTPS request?
    #
    # @return [Boolean]
    #   true if this request was made via HTTPS
    def https?
      uri.scheme == "https"
    end

    # Is this a GET request?
    #
    # @return [Boolean]
    #   true if this request was made with the GET method
    def get?
      method == GET_METHOD
    end

    # Is this a HEAD request?
    #
    # @return [Boolean]
    #   true if this request was made with the HEAD method
    def head?
      method == HEAD_METHOD
    end

    # Is this a POST request?
    #
    # @return [Boolean]
    #   true if this request was made with the GET method
    def post?
      method == POST_METHOD
    end

    # Is this a PUT request?
    #
    # @return [Boolean]
    #   true if this request was made with the PUT method
    def put?
      method == PUT_METHOD
    end

    # Is this a DELETE request?
    #
    # @return [Boolean]
    #   true if this request was made with the DELETE method
    def delete?
      method == DELETE_METHOD
    end

    # Is this a TRACE request?
    #
    # @return [Boolean]
    #   true if this request was made with the TRACE method
    def trace?
      method == TRACE_METHOD
    end

    # Is this a CONNECT request?
    #
    # @return [Boolean]
    #   true if this request was made with the CONNECT method
    def connect?
      method == CONNECT_METHOD
    end

    # Is this an OPTIONS request?
    #
    # @return [Boolean]
    #   true if this request was made with the OPTIONS method
    def options?
      method == OPTIONS_METHOD
    end
  end # class Request
end # module Webmachine
