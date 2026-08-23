require 'fileutils'

MRuby::Gem::Specification.new('webmachine-mruby') do |spec|
  spec.license = 'Apache-2'
  spec.author  = 'Hendrik Beskow'
  spec.summary = 'Webmachine: the HTTP state model, executed'

  spec.bins = ['webmachine-server', 'webmachine-floor-epoll', 'webmachine-logd']


  spec.add_dependency 'mruby-io-uring'
  spec.add_dependency 'mruby-slipstreamio'

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
  File.write("#{mnz_gen}/miniz_export.h", "#pragma once\n#define MINIZ_EXPORT\n")
  spec.cc.include_paths  << mnz << mnz_gen
  spec.cxx.include_paths << mnz << mnz_gen
  %w[MINIZ_NO_STDIO MINIZ_NO_DEFLATE_APIS].each do |d|
    spec.cc.defines  << d
    spec.cxx.defines << d
  end
  spec.objs += %W(#{mnz}/miniz.c #{mnz}/miniz_tinfl.c #{mnz}/miniz_zip.c).map { |f|
    f.relative_path_from(dir).pathmap("#{build_dir}/%X#{spec.exts.object}")
  }

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

  spec.cxx.include_paths << "#{dir}/src"

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
  spec.add_test_dependency 'mruby-string-ext'
end
