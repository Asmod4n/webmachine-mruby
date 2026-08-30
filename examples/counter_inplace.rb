# The same counter as examples/counter.rb, with the number kept as
# digits inside one long-lived body string. setbyte carries '9' -> '0'
# in place, so a request allocates nothing and converts nothing - the
# interpolation, Integer#to_s and both literal copies of counter.rb
# fall away. Safe because the reactor copies the body to the wire
# before the next request can touch it. Wraps at 99999999.
class Counter < Webmachine::Resource
  PREFIX = "<html><body>hit "
  BODY = PREFIX + "00000000" + "</body></html>"
  FIRST = PREFIX.size
  LAST = FIRST + 7

  def to_html
    i = LAST
    while i >= FIRST
      b = BODY.getbyte(i)
      if b < 57
        BODY.setbyte(i, b + 1)
        return BODY
      end
      BODY.setbyte(i, 48)
      i -= 1
    end
    BODY
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [], Counter
  end
end
