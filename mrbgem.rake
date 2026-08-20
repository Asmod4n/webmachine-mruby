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
  # mrbtest runs each gem in an isolated state of gem + dependencies;
  # test/hpack.rb builds its byte strings with string-ext methods. Test
  # only - the product never depends on it.
  spec.add_test_dependency 'mruby-string-ext'
end
