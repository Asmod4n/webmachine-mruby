
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
