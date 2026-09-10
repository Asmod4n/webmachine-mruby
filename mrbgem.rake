require 'fileutils'

MRuby::Gem::Specification.new('webmachine-mruby') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Webmachine: the HTTP state model, executed'

  # The fuzz binary is the same sources with libFuzzer's entry instead of
  # the CLI's, and it exists only in the build that asked for it - the
  # shipped server never carries it (#206).
  # One binary in that build, and it is the fuzz one: the server has no
  # LLVMFuzzerTestOneInput to offer, and libFuzzer's main would collide
  # with the server's.
  fuzzing = build.cc.defines.include?('WM_FUZZ_BUILD')
  spec.bins = fuzzing ? ['webmachine-fuzz']
                     : ['webmachine-server', 'webmachine-logd', 'webmachine-passwd']

  # -fsanitize=fuzzer belongs to this gem and not to the build: a flag in
  # a build's linker reaches every binary the build produces, and mrbc -
  # mruby-bin-mrbc's tool, built in the same tree - has a main of its own
  # for libFuzzer's to collide with. The build carries the sanitizers
  # (conf.enable_sanitizer) and this carries the fuzzer.
  if fuzzing
    fuzz_flags = %w[-fsanitize=fuzzer]
    spec.cc.flags << fuzz_flags
    spec.cxx.flags << fuzz_flags
    spec.linker.flags << fuzz_flags
  end

  # The C++ resource example (#207) is a binary, because that is what a
  # C++ resource is: an embedder's own main, linking this library and
  # defining resource classes before the app file routes them. It is
  # built where it can be exercised - build_config_debug.rb, so bintest
  # reaches it, and build_config_example.rb, which carries the host
  # flags so its number may be compared with the host build's. The
  # shipped binaries never carry it.
  spec.bins += ['webmachine-example'] if build.cc.defines.include?('WM_EXAMPLES')


  # One binary, every host: mruby-slipstreamio carries liburing and
  # builds it with the seam, so whether the kernel or slipstream's
  # engine answers is decided at runtime, per process, by asking the
  # kernel. There is no build-time fallback to reach for, because the one
  # binary is the fallback. That gem builds its liburing when its own
  # mrbgem.rake runs, and a build that fails stops there with the
  # compiler's own words; nothing here asks for liburing before that.
  spec.add_dependency 'mruby-slipstreamio', github: 'Asmod4n/slipstreamIO', branch: 'main'

  # mruby: the VM as a guest - every gem this build carries is named
  # here, core ones included, and no build config names a gembox.
  %w[
    mruby-object-ext
    mruby-kernel-ext
    mruby-class-ext
    mruby-proc-ext
    mruby-symbol-ext
    mruby-string-ext
    mruby-numeric-ext
    mruby-array-ext
    mruby-hash-ext
    mruby-range-ext
    mruby-compar-ext
    mruby-enum-ext
    mruby-toplevel-ext
    mruby-sprintf
    mruby-time
    mruby-struct
    mruby-data
    mruby-io
    mruby-dir
    mruby-errno
  ].each { |g| spec.add_dependency g }

  spec.add_dependency 'mruby-phr'

  spec.add_dependency 'mruby-chrono'

  spec.add_dependency 'mruby-string-is-utf8'

  spec.add_dependency 'mruby-toml'

  # ada-url, vendored by this gem as an amalgamation. What is wanted here
  # is percent decoding and the query parser, not the URL parser: a
  # request target arrives already split by picohttpparser.
  spec.add_dependency 'mruby-uri-parser'

  # Authentication: the password database is LMDB, the hash is argon2id.
  # Both gems carry their C library, so naming them is enough.
  #
  # A record is PasswdRec (src/webmachine.hpp) followed by its salt and
  # its hash, written by webmachine-passwd and read by the server. The
  # cost is in the record, so raising it later re-hashes one user at
  # their next password change and leaves the others verifiable.
  spec.add_dependency 'mruby-argon2'
  spec.add_dependency 'mruby-lmdb'

  # The command line is TypedArgs' grammar (--key=value), parsed in Ruby
  # by the gem rather than by a switch over argv here. One parser, one
  # set of refusals.
  spec.add_dependency 'typedargs'

  # The error pages are mustache templates (#210). Every status is
  # rendered once at boot and lent from there. A page that carries a
  # message, a backtrace or a fingerprint, the 500s, is rendered when it
  # is sent.
  spec.add_dependency 'mruby-mustache', github: 'Asmod4n/mruby-mustache', branch: 'main'
  # RFC 9457: the problem document an error resource answers with is a
  # Hash, and this gem spells it - the escaping (RFC 8259 7) is its job.
  spec.add_dependency 'mruby-fast-json'

  # RFC 9110 6.4: request.body is an IO, not a String - a resource reads
  # it, seeks in it, and asks it how long it is, the same way whether the
  # bytes are in memory or in a file. This is the in-memory half.
  spec.add_dependency 'mruby-stringio', github: 'ksss/mruby-stringio'

  # TLS: the handshake is this process's, the record layer is the
  # kernel's. The gem brings ktls.h and links the
  # machine's OpenSSL 3, which also gives SHA1() to the WebSocket
  # handshake.
  spec.add_dependency 'mruby-ktls', github: 'Asmod4n/mruby-ktls', branch: 'master'

  # #80: the compute pool, and what crosses into it.
  #
  # A compute task's block is dumped as an irep once per process, the
  # first time the reactor sees it, and each worker loads it once. The
  # arguments and the answer cross as CBOR, per request. Nothing else
  # crosses: an mrb_value belongs to one mrb_state.
  spec.add_dependency 'mruby-proc-irep-ext'
  spec.add_dependency 'mruby-cbor'

  # RFC 7541: HPACK is nghttp2's. It is the implementation curl, Apache
  # httpd and Node.js use, it is fuzzed by OSS-Fuzz with libFuzzer, AFL
  # and honggfuzz under the address and undefined sanitizers, and it
  # comes from the distribution, so its security updates are the
  # distribution's. Only nghttp2_hd_* is used here - no session, no
  # framing, no callbacks.
  unless spec.cc.search_header('nghttp2/nghttp2.h')
    abort <<~MSG
      webmachine-mruby: nghttp2 headers not found.

      This tree links the SYSTEM nghttp2 for HPACK (RFC 7541). The
      library is on every server distribution; only its headers are a
      separate package:

        Debian/Ubuntu   apt install libnghttp2-dev
        RHEL/Fedora     dnf install libnghttp2-devel
        Alpine          apk add nghttp2-dev
        macOS           brew install nghttp2
    MSG
  end
  spec.linker.libraries << 'nghttp2'

  unless spec.cc.search_header('zlib.h')
    abort <<~MSG
      webmachine-mruby: zlib headers not found.

      This tree links the SYSTEM zlib (gzip for dynamic bodies and
      permessage-deflate). The library itself is on every
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
  # through one header both libraries now meet in every translation
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
  # authors' own words (share/README.md). It is the last source the
  # server tries; the machine's own database wins whenever it has one.
  # A server that is one binary cannot depend on a data file being
  # installed beside it, so the bytes ride along.
  #
  # Only lines that carry an extension survive: the upstream file
  # lists hundreds of registered types with none, to guide
  # configuration, and a type without an extension cannot answer a
  # lookup. Whitespace collapses to one space - same grammar, fewer
  # bytes, and the runtime parser is the same one that reads
  # /etc/mime.types, so there is no second format to keep in step.
  mime_src = "#{dir}/share/mime.types"
  abort "webmachine-mruby: #{mime_src} is missing" unless File.exist?(mime_src)
  mime_gen = "#{build_dir}/mime"
  FileUtils.mkdir_p(mime_gen)
  rows = File.readlines(mime_src).filter_map { |l|
    f = l.sub(/#.*/, '').split
    f.size >= 2 ? f.join(' ') : nil
  }
  # Written only when the content actually differs - the same rule
  # miniz_export.h above already follows, and for the same measured
  # reason: an unconditional write resets this file's mtime on every
  # `rake compile`, and src/mime.cpp includes it, so mime.o and
  # everything the one header drags with it recompiled every single
  # run. Measured: five objects and sixteen seconds, on a tree where
  # nothing had changed.
  mime_builtin = "#{mime_gen}/mime_builtin.h"
  mime_builtin_content = <<~GEN
    // GENERATED by mrbgem.rake from share/mime.types - do not edit.
    // #{rows.size} types that name an extension.
    #pragma once
    static const char kBuiltinMimeTypes[] =
    #{rows.map { |r| "    \"#{r}\\n\"" }.join("\n")};
  GEN
  unless File.exist?(mime_builtin) && File.read(mime_builtin) == mime_builtin_content
    File.write(mime_builtin, mime_builtin_content)
  end
  spec.cxx.include_paths << mime_gen
end
