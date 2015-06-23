module Webmachine
  module Decision
    # Implements the finite-state machine described by the Webmachine
    # sequence diagram.
    class FSM
      include Flow

      attr_reader :resource, :request, :response, :metadata

      def initialize(resource, request, response)
        @resource, @request, @response = resource, request, response
        @metadata = {}
        super
      end

      # Processes the request, iteratively invoking the decision methods in {Flow}.
      def run
        state = Flow::START
        trace_request(request)
        loop do
          result = handle_exceptions { send(state) }
          case result
          when Fixnum # Response code
            respond(result)
            break
          when Symbol # Next state
            state = result
          else # You bwoke it
            raise InvalidResource, "FSM Broke"
          end
        end
      rescue => e
        Webmachine.render_error(500, request, response, :message => e.message)
      end

      private

      def handle_exceptions
        yield
      rescue MalformedRequest => e
        Webmachine.render_error(400, request, response, :message => e.message)
        400
      rescue => e
        resource.handle_exception(e)
        500
      end

      def respond(code, headers={})
        response.code = code
        response.headers.merge!(headers)
        case code
        when 404
          Webmachine.render_error(code, request, response)
        when 304
          response.headers.delete(CONTENT_TYPE)
          add_caching_headers
        end

        response.code = handle_exceptions do
          resource.finish_request
          response.code
        end

        ensure_content_length(response)
        ensure_date_header(response)
      end
    end # class FSM
  end # module Decision
end # module Webmachine
