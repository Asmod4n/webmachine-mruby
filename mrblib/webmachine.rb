# The gem's own Ruby. It holds what is Ruby's to hold: a reader is a
# reader, and writing one in C would be a two-line function whose only
# content is a name (the standing rule against those is why this file
# exists at all).
#
# This is the GEM's code, compiled into the binary at build time - it
# has nothing to do with #100, which is about the APPLICATION being
# bytecode.
module Webmachine
  class Application
    # Built once in Application.new and rooted by this object; the same
    # object every time, so `app.conf.equal?(app.conf)` holds.
    attr_reader :conf
  end
end
