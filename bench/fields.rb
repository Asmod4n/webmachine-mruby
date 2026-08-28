class Fields < Webmachine::Resource
  def content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  def generate_etag
    'w-fields-1'
  end

  def last_modified
    1_756_000_000
  end

  def expires
    1_856_000_000
  end

  def variances
    ['Accept-Language']
  end

  def to_html
    '<html><body>fields</body></html>'
  end

  def to_json
    '{"fields":true}'
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [:*], Fields
  end
end
