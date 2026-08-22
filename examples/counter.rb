# The runtime tier: an INSTANCE method answers per request through the
# VM - here the body changes on every hit. Class methods would be
# constants; this one is deliberately not.
#
# --app takes bytecode, not source (#100): compile first, then run.
#
#   mrbc -o counter.mrb examples/counter.rb
#   webmachine-server --app counter.mrb
class Counter < Webmachine::Resource
  def initialize
    @n = 0
  end

  def to_html
    "<html><body>hit #{@n += 1}</body></html>"
  end
end

def main
  Webmachine::Application.new do |app|
    app.configure do |conf|
      conf.port = 8080
    end
    app.routes do |route|
      route.add [:*], Counter
    end
  end
end
