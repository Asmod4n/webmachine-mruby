MRuby::Gem::Specification.new('webmachine-mruby') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Webmachine: the HTTP state model, executed'

  # webmachine-floor-epoll is the measuring stick: the same floor
  # protocol on the classic epoll reactor, so the ring's number has a
  # denominator on every machine.
  spec.bins = ['webmachine-server', 'webmachine-floor-epoll']

  # liburing arrives through mruby-io-uring and only through it - one
  # place builds and pins it for every consumer in the process.
  spec.add_dependency 'mruby-io-uring'
  # picohttpparser arrives through mruby-phr the same way liburing does
  # through mruby-io-uring: one place builds and pins it.
  spec.add_dependency 'mruby-phr'
end
