MRuby::Gem::Specification.new('webmachine-mruby') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Webmachine: the HTTP state model, executed'

  spec.bins = ['webmachine-server']

  # liburing arrives through mruby-io-uring and only through it - one
  # place builds and pins it for every consumer in the process.
  spec.add_dependency 'mruby-io-uring'
end
