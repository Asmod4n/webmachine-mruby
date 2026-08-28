class Article < Webmachine::Resource
  HTML = '<html><body><h1>Conditional</h1></body></html>'
  JSON = '{"title":"Conditional"}'
  UPDATED = 1_756_000_000

  def content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  def generate_etag
    'article-7'
  end

  def last_modified
    UPDATED
  end

  def expires
    UPDATED + 86_400
  end

  def to_html
    HTML
  end

  def to_json
    JSON
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [:*], Article
  end
end
