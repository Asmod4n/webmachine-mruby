# The program README opens with, and the one the Containerfile builds
# into its image.
#
# self.to_html is the whole trick. The server calls it once at start and
# keeps the answer, with its status line, its head, its ETag and its
# HTTP/2 header block, as bytes. A request against this resource never
# enters the VM.
#
#     rake
#     mruby/bin/mrbc -g -o hello.mrb examples/hello.rb
#     mruby/bin/webmachine-server --app=hello.mrb
class HelloWorld < Webmachine::Resource
  def self.to_html
    '<html><body>Hello, World!</body></html>'
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route [:*], HelloWorld
  end
end
