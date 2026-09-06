class Article < Webmachine::Resource
  HTML = '<html><body><h1>Conditional</h1></body></html>'
  JSON = '{"title":"Conditional"}'
  UPDATED = 1_756_000_000

  def self.content_types_provided
    [['text/html', :to_html], ['application/json', :to_json]]
  end

  def self.generate_etag
    'article-7'
  end

  def self.last_modified
    UPDATED
  end

  def self.expires
    UPDATED + 86_400
  end

  def self.to_html
    HTML
  end

  def self.to_json
    JSON
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [:*], Article
  end
end
