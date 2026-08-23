require 'fileutils'

MRuby::Gem::Specification.new('webmachine-mruby') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Webmachine: the HTTP state model, executed'

  # webmachine-floor-epoll is the measuring stick: the same floor
  # protocol on the classic epoll reactor, so the ring's number has a
  # denominator on every machine.
  spec.bins = ['webmachine-server', 'webmachine-floor-epoll', 'webmachine-logd']

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
  # WHICH liburing counts: the one mruby-io-uring BUILDS out of its own
  # submodule is the one this tree links (a static .a, its headers on
  # the include path), so a machine without liburing-dev is perfectly
  # fine - and a container image should not have to install a package
  # it never links. Asking only the system header was wrong and only
  # ever worked by accident on a host that happened to carry it: an
  # image built from a clean base refused with liburing sitting right
  # there, freshly compiled.
  uring_built = File.exist?("#{build.build_dir}/mrbgems/mruby-io-uring/build/lib/liburing.a")
  if spec.cc.search_header('sys/epoll.h') && !spec.cc.search_header('liburing.h') &&
     !uring_built
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
  # The config file's parser (#166): TOML through the VM the process
  # already carries. Config is read ONCE at startup, never on a
  # request path, so the Ruby-side surface (TOML.load -> Document,
  # tables as plain Hashes) is exactly enough - no vendored C parser,
  # no second TOML implementation in the binary.
  spec.add_dependency 'mruby-toml', github: 'Asmod4n/mruby-toml', branch: 'main'

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
  # zlib, THE SYSTEM ONE: gzip for dynamic bodies (#147) and, next
  # round, permessage-deflate (#175). Chosen over mruby-libdeflate
  # (vendored for #170's zip reader) for a reason that outranks speed:
  # permessage-deflate needs Z_SYNC_FLUSH streaming with a persistent
  # context across messages, which libdeflate's one-shot whole-buffer
  # API cannot do at all. One library for both customers.
  #
  # SYSTEM, not vendored - STEHENDE NUTZER-REGEL (2026-08-22): what has
  # a stable ABI and is de facto present on every distribution, we USE;
  # we do not carry our own copy of it. zlib is the textbook case:
  # libz.so.1 has been the soname since the 1990s, z_stream has not
  # moved, and nothing on a server is without it (systemd, rpm/dpkg,
  # git, curl all pull it in). Where a distribution has swapped in
  # zlib-ng under that soname (Fedora, recent Ubuntu), we get its
  # speed for free and without knowing.
  #
  # This tree DID vendor zlib-ng at a pinned tag, and the measurement
  # that ends that is embarrassing enough to write down: the vendored
  # build compiled arch/generic/*.c ONLY - no SIMD at all, because
  # those sources want per-file flags (-mavx512f and friends) that
  # spec.objs applies uniformly or not at all. So the copy we carried
  # was the SLOW path, next to a distribution library that ships the
  # full runtime-dispatched one. Pinning also bought less than it
  # promised: a pinned tag is a CVE we patch ourselves, on a library
  # that will decompress attacker-supplied DEFLATE (RFC 7692) - the
  # distribution's security team does that job better and sooner.
  #
  # Refused BY NAME at build time when the headers are missing: the
  # runtime library is everywhere, the -dev package is not, and a
  # missing header should say which package instead of erroring 40
  # lines deep in a compile.
  unless spec.cc.search_header('zlib.h')
    abort <<~MSG
      webmachine-mruby: zlib headers not found.

      This tree links the SYSTEM zlib (gzip for dynamic bodies, #147,
      and permessage-deflate next). The library itself is on every
      server distribution; only its headers are a separate package:

        Debian/Ubuntu   apt install zlib1g-dev
        RHEL/Fedora     dnf install zlib-devel
        Alpine          apk add zlib-dev
        macOS           xcode-select --install
    MSG
  end
  spec.linker.libraries << 'z'

  # miniz: the ZIP container reader for the asset tier (#177). The
  # format stays ZIP (#170 wants Explorer to open, read and change the
  # pack); this tree stopped parsing it - 137 instrumented edges of
  # Central Directory walking, which is the shape every ZIP CVE has.
  #
  # libzip would have been the packaged choice and links our libz and
  # libcrypto, but it hands over BYTES and never a POSITION. Copying
  # every served byte into an arena would turn file-backed pages into
  # anonymous RSS and give up #155/#168's iovec-into-the-mapping.
  # miniz's m_local_header_ofs is the offset that keeps it.
  #
  # The price, named: MINIZ_NO_INFLATE_APIS cannot be set - miniz.h:162
  # turns it into MINIZ_NO_ARCHIVE_APIS, because mz_zip_archive embeds a
  # tinfl_decompressor. So ~15 KB of a second DEFLATE rides along
  # uncalled; the codec on the serving path is and stays the system
  # zlib. Pinned at 3.1.2; deps-upstream.yml watches for newer tags.
  mnz = "#{dir}/deps/miniz"
  abort 'webmachine-mruby: deps/miniz is empty - run: git submodule update --init' unless File.exist?("#{mnz}/miniz_zip.h")
  # miniz_export.h is CMake's and decorates symbols for a SHARED build.
  # This one is static in the same binary, so it is empty.
  mnz_gen = "#{build_dir}/miniz"
  FileUtils.mkdir_p(mnz_gen)
  File.write("#{mnz_gen}/miniz_export.h", "#pragma once\n#define MINIZ_EXPORT\n")
  spec.cc.include_paths  << mnz << mnz_gen
  spec.cxx.include_paths << mnz << mnz_gen
  # No stdio: the archive is OUR mmap (mz_zip_reader_init_mem), so miniz
  # must not know what a file is. No deflate: nothing here compresses,
  # and it implies MINIZ_NO_ARCHIVE_WRITING_APIS.
  %w[MINIZ_NO_STDIO MINIZ_NO_DEFLATE_APIS].each do |d|
    spec.cc.defines  << d
    spec.cxx.defines << d
  end
  spec.objs += %W(#{mnz}/miniz.c #{mnz}/miniz_tinfl.c #{mnz}/miniz_zip.c).map { |f|
    f.relative_path_from(dir).pathmap("#{build_dir}/%X#{spec.exts.object}")
  }

  # libcrypto, for ONE function: SHA1(), the fixed transform RFC 6455
  # 4.2.2 puts in the websocket handshake (#175). Same standing rule as
  # zlib above - a stable ABI that every server distribution already
  # carries is used, not reimplemented - and the same measured reason
  # the base64 next to it comes from simdutf: this tree had a
  # hand-rolled SHA-1 once and it was a bottleneck.
  #
  # It is not TLS creeping back in. Nothing here opens a context, and
  # aws-lc - the crypto library this stack brings when TLS returns
  # through mruby-ktls/s2n - answers the same OpenSSL API, so that day
  # is a link-line change and nothing else.
  unless spec.cc.search_header('openssl/sha.h')
    abort <<~MSG
      webmachine-mruby: OpenSSL headers not found.

      The websocket handshake (#175) needs SHA1() out of libcrypto -
      one function, no TLS. The library is on every server
      distribution; only its headers are a separate package:

        Debian/Ubuntu   apt install libssl-dev
        RHEL/Fedora     dnf install openssl-devel
        Alpine          apk add openssl-dev
    MSG
  end
  spec.linker.libraries << 'crypto'

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
