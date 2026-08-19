# Hello, World - the whole app. A CLASS method declares its answer
# konst: it belongs to the class, not to a request, so setup renders it
# once and the request path never enters the VM. An instance method
# here would be per-request semantics - a tier that does not exist yet.
#
#   webmachine-server --port 8080 --app examples/hello.rb
class HelloWorld < Webmachine::Resource
  def self.to_html
    '<html><body>Hello, World!</body></html>'
  end
end
