# The app half of the C++ resource example (#207).
#
# CppKonst and CppRun are NOT defined here - they come from C++, out of
# tools/webmachine-example/main.cpp, and are ordinary mruby classes by
# the time this file runs. RbKonst and RbRun are their twins, written
# the usual way, declaring exactly the same things.
#
# Four routes, so both halves can be asked the same question:
#
#   /cppk  /rbk   the static tier - `def self.to_html`, run once at
#                 setup, its String baked into the konst answer
#   /cpp   /rb    the dynamic tier - `def to_html`, run per request
#
# The bytes must match across each pair. bintest/cpp_resource.rb asks
# for exactly that, over HTTP/1.1 and HTTP/2.

BODY = '<html><body>Hello from a C++ resource</body></html>'

class RbKonst < Webmachine::Resource
  def self.to_html
    BODY
  end
end

class RbRun < Webmachine::Resource
  def to_html
    BODY
  end

  def allowed_methods
    %w[GET HEAD OPTIONS]
  end

  def generate_etag
    'v1'
  end
end

def main
  Webmachine::Application.new do |app|
    app.conf.port = 8080
    app.add_route ['cppk'], CppKonst
    app.add_route ['rbk'], RbKonst
    app.add_route ['cpp'], CppRun
    app.add_route ['rb'], RbRun
  end
end
