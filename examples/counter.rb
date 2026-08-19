# The runtime tier: an INSTANCE method answers per request through the
# VM - here the body changes on every hit. Class methods would be
# constants; this one is deliberately not.
#
#   webmachine-server --port 8080 --app examples/counter.rb
class Counter < Webmachine::Resource
  def initialize
    @n = 0
  end

  def to_html
    "<html><body>hit #{@n += 1}</body></html>"
  end
end
