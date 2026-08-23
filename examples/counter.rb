# The runtime tier: an INSTANCE method answers per request through the
# VM - here the body changes on every hit. Class methods would be
# constants; this one is deliberately not.
#
# WHERE STATE LIVES (#181). The resource instance belongs to ONE
# REQUEST: it is built when the request arrives and dropped when the
# answer is written, so ivars are request scope - useful for carrying
# something between the callbacks of one request, useless for counting
# across requests. HTTP is stateless and so is its resource.
#
# Application state therefore lives outside the instance. It cannot be
# a class ivar or a class variable either: add_route FREEZES the
# resource class, so nothing may be written into the class object
# afterwards. What works is a mutable object a constant NAMES (the
# constant is frozen, the object it points at is not) - or a global.
#
# --app takes bytecode, not source (#100): compile first, then run.
#
#   mrbc -o counter.mrb examples/counter.rb
#   webmachine-server --app counter.mrb
class Counter < Webmachine::Resource
  # The box is the state; the class only knows its name.
  HITS = [0]

  def to_html
    HITS[0] += 1
    "<html><body>hit #{HITS[0]}</body></html>"
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [:*], Counter
  end
end
