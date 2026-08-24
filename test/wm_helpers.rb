# webmachine-ruby's spec/webmachine/decision/helpers_spec.rb, ported -
# the part of it that is about the MACHINE rather than about the Ruby
# object graph around it.
#
# PORTED 3 (the "accepting request bodies" block). OMITTED the rest,
# in two groups:
#
#   "setting the Content-Length header when responding" - drives
#   `subject.send :respond, code` and reads response.headers, i.e. an
#   FSM method and a Hash this tree does not have. Content-Length is the
#   WRITER's field here, computed from the bytes it is about to send;
#   bintest/ proves it on the wire, where it exists.
#
#   "#encode_body" - asserts which Webmachine::Streaming encoder wraps
#   the body (EnumerableEncoder, CallableEncoder, FiberEncoder,
#   IOEncoder) and the Transfer-Encoding that follows. There is no
#   streaming encoder tier in this tree, so there is nothing to assert.
#
# The three that remain test accept_helper: which content_types_accepted
# entry a request body is handed to, and the 415 when none matches.
# Upstream calls subject.accept_helper directly; here the same decision
# is reached the only way it can be - a PUT that lands on o14.

def wm_res_accept_none
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[GET HEAD PUT]
    end

    def content_types_accepted
      []
    end
  end
end

def wm_res_accept_json
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[GET HEAD PUT]
    end

    def content_types_accepted
      [['application/json', :accept_doc]]
    end

    def accept_doc
      response.body = 'accept_doc'
      true
    end
  end
end

def wm_res_accept_params
  Class.new(WmSpecResource) do
    def allowed_methods
      %w[GET HEAD PUT]
    end

    # Upstream: ['application/json;v=3', ['application/json', :other]].
    # The first entry carries a parameter the request does not match, so
    # the SECOND is the first acceptable one.
    def content_types_accepted
      [['application/json;v=3', :accept_doc], ['application/json', :other]]
    end

    def accept_doc
      response.body = 'accept_doc'
      true
    end

    def other
      response.body = 'other'
      true
    end
  end
end

wm_case('helpers accept_helper: a resource that accepts no type answers 415') do
  assert_equal 415, wm_run(wm_res_accept_none, 'PUT', wm_h('Content-Type' => 'text/xml'), 'x').code
end

wm_case('helpers accept_helper: a Content-Type outside the accepted set answers 415') do
  assert_equal 415, wm_run(wm_res_accept_json, 'PUT', wm_h('Content-Type' => 'text/xml'), 'x').code
end

wm_case('helpers accept_helper: the first acceptable type wins, parameters counted') do
  h = wm_h('Content-Type' => 'application/json;v=2')
  res = wm_run(wm_res_accept_params, 'PUT', h, 'x')
  assert_true res.code != 415
  assert_equal 'other', res.body
end
