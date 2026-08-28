require 'fileutils'

MRuby::Gem::Specification.new('webmachine-mruby') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Webmachine: the HTTP state model, executed'

  # The fuzz binary is the SAME sources with libFuzzer's entry instead of
  # the CLI's, and it exists ONLY in the build that asked for it - the
  # shipped server never carries it (#206).
  # ONE binary in that build, and it is the fuzz one: -fsanitize=fuzzer
  # goes to every link in a build, so libFuzzer's main would collide with
  # the server's and the server has no LLVMFuzzerTestOneInput to offer.
  fuzzing = build.cc.defines.include?('WM_FUZZ_BUILD')
  spec.bins = fuzzing ? ['webmachine-fuzz'] : ['webmachine-server', 'webmachine-logd']

  # The C++ resource example (#207) is a BINARY, because that is what a
  # C++ resource is: an embedder's own main, linking this library and
  # defining resource classes before the app file routes them. It is
  # built where it can be exercised - build_config_debug.rb, so bintest
  # reaches it, and build_config_example.rb, which carries the host
  # flags so its number may be compared with the host build's. The
  # shipped binaries never carry it.
  spec.bins += ['webmachine-example'] if build.cc.defines.include?('WM_EXAMPLES')


  # SLIPSTREAM_IO_ONLY is the `portable` target's whole declaration
  # (build_config.rb): no liburing in this binary, on any host. mruby
  # resolves the gem list per BUILD TARGET, never per spec.bins entry,
  # so a target is the only place that decision can live - all three
  # binaries of one build link the same libmruby.a.
  portable = build.cc.defines.include?('SLIPSTREAM_IO_ONLY')

  spec.add_dependency 'mruby-io-uring' unless portable
  spec.add_dependency 'mruby-slipstreamio'

  uring_built = File.exist?("#{build.build_dir}/mrbgems/mruby-io-uring/build/lib/liburing.a")
  if !portable && spec.cc.search_header('sys/epoll.h') &&
     !spec.cc.search_header('liburing.h') && !uring_built
    abort <<~MSG
      webmachine-mruby: this is a Linux build with no liburing.

      liburing could not be built here (see mruby-io-uring's output above;
      it needs kernel headers and a working C compiler).

      A target that WANTS to go without it says so - see the `portable`
      build in build_config.rb.
    MSG
  end

  spec.add_dependency 'mruby-phr'

  spec.add_dependency 'mruby-chrono'

  spec.add_dependency 'mruby-string-is-utf8'

  spec.add_dependency 'mruby-toml'

  lshp = "#{dir}/deps/ls-hpack"
  spec.cc.include_paths  << lshp << "#{lshp}/deps/xxhash"
  spec.cxx.include_paths << lshp << "#{lshp}/deps/xxhash"

  spec.cc.defines << 'XXH_HEADER_NAME=\"xxhash.h\"'
  spec.objs += %W(#{lshp}/lshpack.c #{lshp}/deps/xxhash/xxhash.c).map { |f|
    f.relative_path_from(dir).pathmap("#{build_dir}/%X#{spec.exts.object}")
  }

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
  mnz = "#{dir}/deps/miniz"
  abort 'webmachine-mruby: deps/miniz is empty - run: git submodule update --init' unless File.exist?("#{mnz}/miniz_zip.h")
  mnz_gen = "#{build_dir}/miniz"
  FileUtils.mkdir_p(mnz_gen)
  mnz_export = "#{mnz_gen}/miniz_export.h"
  mnz_export_content = "#pragma once\n#define MINIZ_EXPORT\n"
  # An unconditional write here reset this file's mtime on every `rake
  # compile`, whether its content changed or not - and since miniz.c/
  # miniz_tinfl.c/miniz_zip.c include it, that alone forced all three to
  # recompile every single run. Written only when the content actually
  # differs, the mtime - and the rebuild it drives - now tracks reality.
  unless File.exist?(mnz_export) && File.read(mnz_export) == mnz_export_content
    File.write(mnz_export, mnz_export_content)
  end
  spec.cc.include_paths  << mnz << mnz_gen
  spec.cxx.include_paths << mnz << mnz_gen
  # MINIZ_NO_ZLIB_COMPATIBLE_NAMES: miniz otherwise claims zlib's own
  # names (voidpc, alloc_func, inflateInit_ ...), and since src/ speaks
  # through ONE header both libraries now meet in every translation
  # unit. Nothing here uses the compat layer - the ZIP reader is called
  # by its mz_ names, and zlib itself serves gzip and permessage-deflate.
  %w[MINIZ_NO_STDIO MINIZ_NO_DEFLATE_APIS MINIZ_NO_ZLIB_COMPATIBLE_NAMES].each do |d|
    spec.cc.defines  << d
    spec.cxx.defines << d
  end
  spec.objs += %W(#{mnz}/miniz.c #{mnz}/miniz_tinfl.c #{mnz}/miniz_zip.c).map { |f|
    f.relative_path_from(dir).pathmap("#{build_dir}/%X#{spec.exts.object}")
  }

  # The media-type list compiled in (src/mime.cpp), generated from
  # share/mime.types - Apache httpd's own, public domain by its
  # authors' own words (share/README.md). It is the LAST source the
  # server tries; the machine's own database wins whenever it has one.
  # A server that is one binary cannot depend on a data file being
  # installed beside it, so the bytes ride along.
  #
  # Only lines that carry an extension survive: the upstream file
  # lists hundreds of registered types with none, to guide
  # configuration, and a type without an extension cannot answer a
  # lookup. Whitespace collapses to one space - same grammar, fewer
  # bytes, and the runtime parser is the SAME one that reads
  # /etc/mime.types, so there is no second format to keep in step.
  mime_src = "#{dir}/share/mime.types"
  abort "webmachine-mruby: #{mime_src} is missing" unless File.exist?(mime_src)
  mime_gen = "#{build_dir}/mime"
  FileUtils.mkdir_p(mime_gen)
  rows = File.readlines(mime_src).filter_map { |l|
    f = l.sub(/#.*/, '').split
    f.size >= 2 ? f.join(' ') : nil
  }
  File.write("#{mime_gen}/mime_builtin.h", <<~GEN)
    // GENERATED by mrbgem.rake from share/mime.types - do not edit.
    // #{rows.size} types that name an extension.
    #pragma once
    static const char kBuiltinMimeTypes[] =
    #{rows.map { |r| "    \"#{r}\\n\"" }.join("\n")};
  GEN
  spec.cxx.include_paths << mime_gen

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

  spec.add_test_dependency 'mruby-string-ext'
end
