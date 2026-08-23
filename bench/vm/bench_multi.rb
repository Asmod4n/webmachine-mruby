# Four dynamic callbacks in one run frame - what the frame costs when
# the flow actually asks it something on the way. Since #181 the
# frame also builds the request's own resource; the four callbacks
# share THAT object, which is what @n proves here (it reads 1 every
# request - request scope, not a counter).
class BenchMulti < Webmachine::Resource
  def initialize
    @n = 0
  end

  def service_available?
    true
  end

  def resource_exists?
    true
  end

  def multiple_choices?
    false
  end

  def to_html
    "<html><body>hit #{@n += 1}</body></html>"
  end
end
