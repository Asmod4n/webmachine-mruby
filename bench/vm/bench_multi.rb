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
