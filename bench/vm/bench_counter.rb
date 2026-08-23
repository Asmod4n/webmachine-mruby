# One dynamic callback: the whole runtime tier in its smallest shape.
# Since #181 that shape includes the per-request instance itself - the
# allocation and this initialize are part of what the number measures,
# because they are part of what every dynamic request now does.
class BenchCounter < Webmachine::Resource
  def initialize
    @n = 0
  end

  def to_html
    "<html><body>hit #{@n += 1}</body></html>"
  end
end
