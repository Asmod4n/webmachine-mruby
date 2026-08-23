# Hello, World - the whole app. A CLASS method declares its answer
# konst: it belongs to the class, not to a request, so route.add
# renders it once and the request path never enters the VM. An instance
# method here would be per-request semantics - the runtime tier, which
# examples/counter.rb shows.
#
# --app takes bytecode, not source (#100): compile first, then run.
#
#   mrbc -o hello.mrb examples/hello.rb
#   webmachine-server --app hello.mrb
#
# An app of several files is still ONE artifact - mrbc concatenates,
# in argument order, the way it builds mruby's own mrblib:
#
#   mrbc -o app.mrb a.rb b.rb c.rb
class HelloWorld < Webmachine::Resource
  def self.to_html
    '<html><body>Hello, World!</body></html>'
  end
end

# The app file defines `main` and nothing else (#116). The tool loads
# the bytecode, calls this, and the Application the block registers
# says where to listen and what answers there; --port/--unix on the
# command line override conf.
def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    # :* is the tail: every path lands on this one resource, which is
    # what a one-resource app has always meant here.
    app.add_route [:*], HelloWorld
  end
end
