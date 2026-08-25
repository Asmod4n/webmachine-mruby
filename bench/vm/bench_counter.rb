class BenchCounter < Webmachine::Resource
  def initialize
    @n = 0
  end

  def to_html
    "<html><body>hit #{@n += 1}</body></html>"
  end
end
