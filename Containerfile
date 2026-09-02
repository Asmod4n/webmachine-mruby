# webmachine-mruby in a container, in two stages: one that has a
# toolchain, one that has four shared libraries and the binary.
#
# TESTED, not guessed: built and run with podman on Debian trixie; the
# numbers and package names in docs/container.md come out of this file
# actually running. `docker build` reads it the same way (name it
# Dockerfile or pass -f).

# ---------------------------------------------------------------- build
FROM debian:trixie AS build

# What a build needs, and why each one is here:
#   build-essential  gcc/g++ (C++20) and make - liburing builds with make
#   ruby             mruby's build system IS rake
#   git              the tree's submodule (ls-hpack) and every mrbgem
#   pkg-config       mruby-io-uring asks it for liburing's cflags
#   zlib1g-dev       the system zlib this tree links (#147 gzip)
#   libssl-dev       libcrypto, for the websocket handshake's SHA1()
#   ca-certificates  git over https
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ruby git pkg-config zlib1g-dev libssl-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# NOT -march=native: this binary leaves the machine that built it. See
# build_config.rb - x86-64-v3 is AVX2 and later, the usual fleet floor.
# Override at build time for a different baseline.
ARG WM_MARCH=x86-64-v3
ENV WM_MARCH=${WM_MARCH}
# The context carries no .git (see .containerignore), so the submodule
# has to be checked out BEFORE the build. Said by name here rather than
# discovered forty lines into a compile.
RUN test -f deps/ls-hpack/lshpack.c || { \
      echo 'deps/ls-hpack is empty - run: git submodule update --init --recursive' >&2; \
      exit 1; \
    }
RUN rake compile

# The app is BYTECODE (#100): the server never compiles Ruby. mrbc
# comes out of the same build, so an image can carry it and compile the
# app right here.
RUN mruby/build/host/mrbc/bin/mrbc -o /src/app.mrb examples/hello.rb

# -------------------------------------------------------------- runtime
FROM debian:trixie-slim AS runtime

# The whole runtime dependency list, and it is this short because
# liburing is linked statically and everything else is the tree's own:
#   libz1        zlib      (#147)
#   libssl3      libcrypto (the handshake's SHA1)
#   libstdc++6   pulls libgcc-s1 and libc6 with it
RUN apt-get update && apt-get install -y --no-install-recommends \
      libz1 libssl3 libstdc++6 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/mruby/build/host/bin/webmachine-server /usr/local/bin/
COPY --from=build /src/app.mrb /app/app.mrb

# Nothing here needs root: the ring, the listener and the buffer pool
# are all unprivileged. A port below 1024 is the one exception, and the
# answer is a published port, not a privileged process.
RUN useradd --system --uid 10001 --no-create-home webmachine
USER 10001
EXPOSE 8080
ENTRYPOINT ["webmachine-server", "--app=/app/app.mrb", "--port=8080"]
