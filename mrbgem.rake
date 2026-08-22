MRuby::Gem::Specification.new('webmachine-mruby') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Webmachine: the HTTP state model, executed'

  # webmachine-floor-epoll is the measuring stick: the same floor
  # protocol on the classic epoll reactor, so the ring's number has a
  # denominator on every machine.
  spec.bins = ['webmachine-server', 'webmachine-floor-epoll']

  # liburing arrives through mruby-io-uring and only through it - one
  # place builds and pins it for every consumer in the process. And it
  # may not arrive at all: that gem runs liburing's own build on the
  # host and degrades when it fails (URING_AVAILABLE = false). This
  # tree degrades WITH it rather than aborting the whole build, because
  # mruby-slipstreamio takes the name <liburing.h> over on such a host
  # and implements it over select(2). Nothing in src/ knows which one
  # answered.
  spec.add_dependency 'mruby-io-uring'
  spec.add_dependency 'mruby-slipstreamio'
  # picohttpparser arrives through mruby-phr the same way liburing does
  # through mruby-io-uring: one place builds and pins it.
  spec.add_dependency 'mruby-phr'
  # Every DURATION that crosses the Ruby<->C boundary - timeouts,
  # work budgets, intervals - goes through mruby-chrono: Float seconds
  # on the Ruby side, std::chrono/timespec on the C side, converted at
  # the edge and nowhere else. Wall-clock/date stays plain C.
  spec.add_dependency 'mruby-chrono'

  # ls-hpack: the HPACK codec for HTTP/2, and ONLY the codec - frames
  # and streams are this gem's own. The codec is reused rather than
  # written because HPACK is its own CVE class (decompression bombs,
  # dynamic-table confusion, Huffman decode overflows); this one runs
  # at fleet scale in the LiteSpeed ecosystem and is fuzzed there.
  # Pinned v2.3.5 (submodule), proven against RFC 7541's own vectors
  # in test/hpack.rb before any frame exists.
  #
  # It is also the fastest of the three that can be vendored at all,
  # measured once against the two real alternatives on the exact calls
  # src/http2.cpp makes - a request decode and one date field:
  #
  #               decode    encode
  #   ls-hpack     90.9ns    31.6ns
  #   cashpack      118ns    39.9ns   (+30% / +26%)
  #   nghttp2_hd    145ns    47.0ns   (+59% / +49%)
  #
  # (container, one thread, google-benchmark; nghttp2 v1.66.0,
  # cashpack 0.5 from git.sr.ht/~dridi/cashpack). h2o, proxygen,
  # Envoy and QUICHE never got that far: none is extractable as a bare
  # codec - h2o's hpack.c wants h2o's memory pools and token table,
  # proxygen needs Folly, Envoy has no HPACK of its own (it uses
  # nghttp2). The harness that produced this is deliberately NOT in
  # the tree: it fetched and built two foreign libraries to answer a
  # question that is now answered, and the answer is worth keeping
  # where the choice is made - the machinery is not.
  lshp = "#{dir}/deps/ls-hpack"
  spec.cc.include_paths  << lshp << "#{lshp}/deps/xxhash"
  spec.cxx.include_paths << lshp << "#{lshp}/deps/xxhash"
  # lshpack.c does `#include XXH_HEADER_NAME`. The quotes have to
  # survive the shell, hence the escapes; only the C compiler ever
  # sees the file.
  spec.cc.defines << 'XXH_HEADER_NAME=\"xxhash.h\"'
  spec.objs += %W(#{lshp}/lshpack.c #{lshp}/deps/xxhash/xxhash.c).map { |f|
    f.relative_path_from(dir).pathmap("#{build_dir}/%X#{spec.exts.object}")
  }
  # test/flow_vectors.cpp drives src/flow_walk.hpp from outside the
  # product, the way a caller does. src/ is on the path for the gem's
  # own sources by convention, not for test/ - so say it.
  spec.cxx.include_paths << "#{dir}/src"
  # mrbtest runs each gem in an isolated state of gem + dependencies;
  # test/hpack.rb builds its byte strings with string-ext methods. Test
  # only - the product never depends on it.
  spec.add_test_dependency 'mruby-string-ext'
end
