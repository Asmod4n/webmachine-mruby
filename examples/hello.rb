# Hello, World - the whole app. A CLASS method declares its answer
# konst: it belongs to the class, not to a request, so setup renders it
# once and the request path never enters the VM. An instance method
# here would be per-request semantics - a tier that does not exist yet.
#
# --app takes bytecode, not source (#100): compile first, then run.
#
#   mrbc -o hello.mrb examples/hello.rb
#   webmachine-server --port 8080 --app hello.mrb
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
