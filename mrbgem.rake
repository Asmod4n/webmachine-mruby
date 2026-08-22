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

  # ON LINUX IT IS io_uring OR NOTHING (user decision). The whole point
  # of this server is the ring; a Linux build that quietly fell back to
  # select would still be called webmachine and would no longer be the
  # thing the numbers describe. So refuse to produce it - at BUILD
  # time, by name, next to the reason - rather than shipping a binary
  # that is slow in a way nobody can see. (The same rule at runtime is
  # in tools/webmachine-server: URING_AVAILABLE false does not start.)
  #
  # Asked through the compiler's own include path rather than the host
  # Ruby's platform string, so a cross build answers for its TARGET:
  # sys/epoll.h exists on Linux and nowhere else.
  #
  # mruby-slipstreamio stays neutral in this - it installs its
  # liburing.h wherever there is none, and another project may well
  # want that on Linux. The policy is ours, so the check is ours.
  if spec.cc.search_header('sys/epoll.h') && !spec.cc.search_header('liburing.h')
    abort <<~MSG
      webmachine-mruby: this is a Linux build with no liburing.

      liburing could not be built here (see mruby-io-uring's output above;
      it needs kernel headers and a working C compiler). On Linux this
      tree is io_uring or nothing: the alternative implementations exist
      for platforms that have no io_uring at all, not to make a Linux
      server quietly slow.

      Fix the liburing build, or build for a platform where slipstreamIO
      is the intended implementation.
    MSG
  end
  # picohttpparser arrives through mruby-phr the same way liburing does
  # through mruby-io-uring: one place builds and pins it.
  spec.add_dependency 'mruby-phr'
  # Every DURATION that crosses the Ruby<->C boundary - timeouts,
  # work budgets, intervals - goes through mruby-chrono: Float seconds
  # on the Ruby side, std::chrono/timespec on the C side, converted at
  # the edge and nowhere else. Wall-clock/date stays plain C.
  spec.add_dependency 'mruby-chrono'
  # simdutf, through the user's own gem: a websocket text message MUST
  # be valid UTF-8 (RFC 6455 8.1), and validating a whole buffer with
  # SIMD is a solved problem this tree is not going to solve worse.
  # The gem installs simdutf.h into its include/, so this side calls
  # simdutf::validate_utf8 on the frame's own bytes - no mruby String
  # is built to ask the question.
  spec.add_dependency 'mruby-string-is-utf8', github: 'Asmod4n/mruby-string-is-utf8'

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
  # zlib-ng: gzip for dynamic bodies (#147) - encodings_provided,
  # server-side, gzip level 1 only (the fast end of the scale; a build
  # step is where zstd -19 / brotli q11 belong, never a response).
  # Chosen over mruby-libdeflate (already vendored, used for #170's
  # zip reader) for one reason that outranks speed: #172/#175's
  # permessage-deflate will need Z_SYNC_FLUSH streaming with a
  # persistent context across messages, which libdeflate's one-shot
  # whole-buffer API cannot do at all. One library for both customers,
  # decided honestly on day one rather than adding a second dependency
  # later - libdeflate stays a candidate for THIS path specifically if
  # a measurement ever justifies it (Gebot 10), not a default.
  #
  # Pinned 2.3.3 (submodule) - no system zlib anywhere, on the same
  # reasoning as ls-hpack above: an unpinned version is an unpinned CVE
  # surface in a library that decompresses attacker-adjacent bytes
  # nowhere here yet, but will (RFC 7692 receives untrusted DEFLATE).
  #
  # Built the SAME way ls-hpack is, three lines up - portable sources
  # through spec.objs, not a shelled-out cmake/configure. zlib-ng's own
  # build asks autotools/cmake to fill in three templated headers, and
  # every substitution turns out to be something this Rake file can do
  # itself without either tool: the symbol prefix is empty (native zng_
  # API, see below - nothing to substitute), unistd.h is a probe
  # spec.cc can run directly, and the name-mangling header has an
  # upstream .empty for exactly the no-prefix case. spec.objs also
  # means every target this gem ever cross-compiles for (a real
  # concern the day #171's build_config grows one) gets these objects
  # built with ITS toolchain automatically, the way ls-hpack's already
  # do - a nested cmake would have to be taught the cross toolchain and
  # sysroot separately to get the same result.
  #
  # zng_ API, not --zlib-compat: this process links nothing else that
  # touches zlib today (checked: no gem under this build pulls libz),
  # but the compat build's whole point is binary-compatible `deflate`/
  # `z_stream` symbol names for a caller expecting system zlib - names
  # that a TLS library linked in later could bring right back. The
  # zng_ prefix cannot collide with anything, ever, by construction;
  # paying for that safety costs nothing since nothing here calls the
  # classic API today.
  #
  # Only the GENERIC C implementations are compiled (arch/generic/*.c),
  # no arch/x86 or arch/arm SIMD sources: those want per-file flags
  # (-mavx512f and friends) that spec.objs applies uniformly or not at
  # all, and a dynamic HTTP body compressed once per response is a
  # different cost shape than the hot per-packet path those exist for.
  # WITH_ALL_FALLBACKS wires functable.c's dispatch straight to the
  # generic implementations instead of a runtime CPU-feature switch
  # (see functable.c's own #ifndef WITH_ALL_FALLBACKS) - correct on
  # every host, not merely the one this was built on. Revisiting this
  # is a measurement away (Gebot 10), not a rewrite: bench/results/ is
  # exactly where that measurement would have to live, never guessed
  # from a container number.
  zng_src = "#{dir}/deps/zlib-ng"
  zng_gen = "#{spec.build_dir}/zlib-ng"
  FileUtils.mkdir_p(zng_gen)
  File.write("#{zng_gen}/zlib-ng.h",
             File.read("#{zng_src}/zlib-ng.h.in").gsub('@ZLIB_SYMBOL_PREFIX@', ''))
  have_unistd = spec.cc.respond_to?(:search_header_path) && spec.cc.search_header_path('unistd.h')
  File.write("#{zng_gen}/zconf-ng.h",
             File.read("#{zng_src}/zconf-ng.h.in")
                 .sub('#ifdef HAVE_UNISTD_H', have_unistd ? '#if 1' : '#if 0'))
  FileUtils.cp "#{zng_src}/zlib_name_mangling.h.empty", "#{zng_gen}/zlib_name_mangling-ng.h"

  spec.cc.include_paths  << zng_src << zng_gen
  spec.cxx.include_paths << zng_src << zng_gen

  zng_defines = %w(ZLIBNG_NATIVE_API WITH_ALL_FALLBACKS)
  unless spec.cc.command.to_s =~ /\bcl(\.exe)?$/
    zng_defines += %w(HAVE_ATTRIBUTE_ALIGNED HAVE_BUILTIN_ASSUME_ALIGNED
                      HAVE_BUILTIN_CTZ HAVE_BUILTIN_CTZLL
                      HAVE_VISIBILITY_HIDDEN HAVE_VISIBILITY_INTERNAL)
  end
  if spec.cc.respond_to?(:search_header_path)
    zng_defines << 'HAVE_SYS_AUXV_H' if spec.cc.search_header_path('sys/auxv.h')
    zng_defines << 'HAVE_LINUX_AUXVEC_H' if spec.cc.search_header_path('linux/auxvec.h')
  end
  spec.cc.defines += zng_defines
  spec.cxx.defines += zng_defines

  zng_sources = %w(
    adler32.c compress.c cpu_features.c crc32.c crc32_braid_comb.c
    deflate.c deflate_fast.c deflate_huff.c deflate_medium.c
    deflate_quick.c deflate_rle.c deflate_slow.c deflate_stored.c
    functable.c infback.c inflate.c inftrees.c insert_string.c
    insert_string_roll.c trees.c uncompr.c zutil.c
    arch/generic/adler32_c.c arch/generic/adler32_fold_c.c
    arch/generic/chunkset_c.c arch/generic/compare256_c.c
    arch/generic/crc32_braid_c.c arch/generic/crc32_chorba_c.c
    arch/generic/crc32_fold_c.c arch/generic/slide_hash_c.c
  ).map { |f| "#{zng_src}/#{f}" }
  spec.objs += zng_sources.map { |f|
    f.relative_path_from(dir).pathmap("#{build_dir}/%X#{spec.exts.object}")
  }

  # test/flow_vectors.cpp drives src/flow_walk.hpp from outside the
  # product, the way a caller does. src/ is on the path for the gem's
  # own sources by convention, not for test/ - so say it.
  spec.cxx.include_paths << "#{dir}/src"

  # src/embed.hpp is the flow machine WITHOUT the reactor (#173): bytes
  # in, bytes out, no IO. That is a claim about an include closure, so
  # it is checked where a claim can still stop something - here, at
  # build time, on every build. test/embed_vectors.cpp carries the same
  # cut as a #error on ring.hpp's guard; this walks the hops that guard
  # cannot see, and names <liburing.h> too, which only the reactor has
  # ever included.
  #
  # A missing embed.hpp is not silence: the facade is part of the gem,
  # so its absence is a broken tree, not an opt-out.
  facade = "#{dir}/src/embed.hpp"
  abort 'webmachine-mruby: src/embed.hpp is missing - the embedder facade is not optional (#173)' unless File.exist?(facade)
  seen = {}
  todo = [facade]
  until todo.empty?
    f = todo.shift
    next if seen[f]
    seen[f] = true
    # binread: these headers cite RFC sections with a UTF-8 section
    # sign, and the check is about ASCII include lines either way.
    File.binread(f).scan(/^\s*#\s*include\s+[<"]([^>"]+)[>"]/).flatten.each do |inc|
      if ['ring.hpp', 'liburing.h'].include?(File.basename(inc))
        abort "webmachine-mruby: src/embed.hpp reaches #{inc} through " \
              "#{f.sub("#{dir}/", '')} - the embedder facade must carry no IO (#173)"
      end
      hop = File.join(File.dirname(f), inc)
      todo << hop if File.exist?(hop)
    end
  end
  # mrbtest runs each gem in an isolated state of gem + dependencies;
  # test/hpack.rb builds its byte strings with string-ext methods. Test
  # only - the product never depends on it.
  spec.add_test_dependency 'mruby-string-ext'
end
