require 'fileutils'

MRuby::Gem::Specification.new('webmachine-mruby') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Webmachine: the HTTP state model, executed'

  # The fuzz binary is the SAME sources with libFuzzer's entry instead of
  # the CLI's, and it exists ONLY in the build that asked for it - the
  # shipped server never carries it (#206).
  # ONE binary in that build, and it is the fuzz one: the server has no
  # LLVMFuzzerTestOneInput to offer, and libFuzzer's main would collide
  # with the server's.
  fuzzing = build.cc.defines.include?('WM_FUZZ_BUILD')
  spec.bins = fuzzing ? ['webmachine-fuzz']
                     : ['webmachine-server', 'webmachine-logd', 'webmachine-passwd']

  # -fsanitize=fuzzer belongs to THIS GEM and not to the build: a flag in
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

  # The C++ resource example (#207) is a BINARY, because that is what a
  # C++ resource is: an embedder's own main, linking this library and
  # defining resource classes before the app file routes them. It is
  # built where it can be exercised - build_config_debug.rb, so bintest
  # reaches it, and build_config_example.rb, which carries the host
  # flags so its number may be compared with the host build's. The
  # shipped binaries never carry it.
  spec.bins += ['webmachine-example'] if build.cc.defines.include?('WM_EXAMPLES')


  # ONE binary, every host: mruby-slipstreamio carries liburing and
  # builds it WITH the seam, so whether the kernel or slipstream's
  # engine answers is decided at RUNTIME, per process, by asking the
  # kernel. There is no build-time fallback to reach for, because the one
  # binary IS the fallback.
  spec.add_dependency 'mruby-slipstreamio', github: 'Asmod4n/slipstreamIO', branch: 'main'

  uring_built = File.exist?("#{build.build_dir}/mrbgems/mruby-slipstreamio/build/lib/liburing.a")
  if spec.cc.search_header('sys/epoll.h') &&
     !spec.cc.search_header('liburing.h') && !uring_built
    abort <<~MSG
      webmachine-mruby: liburing could not be built here (see
      mruby-slipstreamio's output above; it needs a working C compiler).

      There is no separate fallback build to point at any more: the one
      binary IS the fallback - liburing built with the slipstream seam
      answers from slipstream's engine wherever the kernel refuses
      io_uring. A failing liburing BUILD is a broken build host, and it
      is reported instead of served around.
    MSG
  end

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

  # ada-url, vendored by this gem as its 3.4.4 amalgamation, and put on
  # this one's compiler path the way mruby does for a dependency's
  # include/. What is wanted here is the decoding, not the URL parser:
  # a request target arrives already split by picohttpparser, and an
  # origin-form target is a path and a query. Affordable only because
  # the host build drops the sections nothing reaches - whole, the
  # amalgamation is 103 KB of .text.
  spec.add_dependency 'mruby-uri-parser', github: 'Asmod4n/mruby-uri-parser', branch: 'master'

  # Authentication: the password database is LMDB, the hash is argon2,
  # and both gems carry their C library, so naming them is enough - each
  # exports its vendored header's directory, and argon2.h and lmdb.h
  # land on this gem's compiler path with nothing to wire up here.
  #
  # What is stored is argon2's OWN encoded form,
  # $argon2id$v=19$m=...,t=...,p=...$salt$hash. Salt and parameters
  # travel inside it, so there is no record format belonging to this
  # tree that webmachine-passwd, which writes, and the server, which
  # verifies, would have to keep in step. Raising the cost later is a
  # per-record decision, because every record says what it cost.
  spec.add_dependency 'mruby-argon2'
  spec.add_dependency 'mruby-lmdb'

  # The command line is TypedArgs' grammar (--key=value), parsed in Ruby
  # by the gem rather than by a switch over argv here. One parser, one
  # set of refusals, and the structured forms are there the day a flag
  # needs a list or a record instead of a scalar.
  spec.add_dependency 'typedargs', github: 'Asmod4n/typedargs', branch: 'main'

  # The error pages are mustache templates (#210). They are rendered per
  # response, not once at boot: a 404 names what was not found, so the set
  # of bodies is as large as the set of request targets.
  spec.add_dependency 'mruby-mustache', github: 'Asmod4n/mruby-mustache', branch: 'main'

  # TLS: the handshake is this process's, the record layer is the
  # kernel's (.DESIGN.md "TLS"). The gem brings include/ktls.h - mruby
  # puts a dependency's include/ on this one's compiler path - and the
  # vendored OpenSSL >= 3.0 it links, which is also where SHA1() for the
  # websocket handshake comes from once this is in the build.
  spec.add_dependency 'mruby-ktls', github: 'Asmod4n/mruby-ktls', branch: 'claude/c-api'

  # #80: the compute pool, and what crosses into it.
  #
  # A worker VM must be preemptible. A promise carries a deadline. A Ruby
  # job that runs past the deadline is stopped, not waited for. mruby-task
  # does that.
  #
  # The HAL comes from this tree. mruby-task/ports/posix drives its tick
  # from SIGALRM. It also protects the scheduler with sigprocmask(), which
  # is undefined in a threaded process. The build system finds our HAL by
  # name: a gem called hal-<short>-<conf> replaces the ports of the gem
  # whose name ends in <short>.
  #
  # The main VM does not want the scheduler. It has no tasks, and the
  # per-opcode check costs it 30% on dynamic Ruby. run_guarded disables it
  # with mrb_disable_task_scheduler (mruby/mruby#7491), which is why the
  # mruby checkout is on task-scheduler-disable. Until that PR is merged,
  # patches/mruby-task-scheduler-disable.patch carries the three commits
  # for a plain checkout.
  spec.add_dependency 'hal-task-webmachine', gemdir: "#{dir}/hal-task-webmachine"

  # A promised callback crosses as a dumped irep, once per worker. Its
  # arguments and its answer cross as CBOR, once per request. Nothing else
  # crosses. An mrb_value belongs to one mrb_state, so a handle, an object
  # or a closure cannot travel (.DESIGN.md #promise).
  spec.add_dependency 'mruby-proc-irep-ext', github: 'Asmod4n/mruby-proc-irep-ext',
                                             branch: 'master'
  spec.add_dependency 'mruby-cbor', github: 'Asmod4n/mruby-cbor', branch: 'main'

  # A worker runs every promised block as a Task, so a deadline can end
  # one. That API lives in mruby-task's own header, and the gem does not
  # export its include path - so it is named here rather than declared a
  # second time in our source. One fact, one source.
  spec.cc.include_paths  << "#{build.root}/mrbgems/mruby-task/include"
  spec.cxx.include_paths << "#{build.root}/mrbgems/mruby-task/include"

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

  # SHA1() for the websocket handshake (#175) comes out of the SAME
  # libcrypto the key exchange uses - mruby-ktls vendors it and exports
  # its headers, and this gem no longer names the machine's. The
  # distribution's may be LibreSSL, or an OpenSSL without kTLS; two
  # libcryptos in one address space is a bug waiting for a link order.
end
