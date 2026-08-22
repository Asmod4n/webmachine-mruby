# Running webmachine-mruby in a container

Everything below was BUILT AND RUN, not guessed: `Containerfile` in the
repository root is the recipe, `podman build` and `podman run` are what
produced the numbers and the failure modes. `docker build -f
Containerfile` reads the same file.

    git submodule update --init --recursive     # the context carries no .git
    podman build -f Containerfile -t webmachine .
    podman run --rm -p 8080:8080 \
      --security-opt seccomp=./webmachine-seccomp.json \
      webmachine

That seccomp file is the one thing without which nothing works. It is
the next section, and it is not optional.

## io_uring and seccomp: the one thing that will bite you

**Measured**: podman's default profile
(`/usr/share/containers/seccomp.json`) does not allow `io_uring_setup`,
`io_uring_enter` or `io_uring_register`. Docker's default profile
dropped them too (moby removed them in 2023, after the io_uring CVEs).
A container started with the default profile gets this, on stderr, at
startup:

    webmachine: io_uring is not usable here (URING_AVAILABLE is false:
    the kernel is too old, or a seccomp profile or sysctl blocks it).
    This binary was built against liburing and carries no other
    implementation.

That is the server refusing by name rather than falling back to
something slow and pretending. Do not paper over it with
`--security-opt seccomp=unconfined` (it works - measured - but it
switches off the whole profile). Add the three calls to your runtime's
OWN default instead, so the profile stays whatever your runtime ships
today:

    jq '.syscalls += [{"names":["io_uring_setup","io_uring_enter","io_uring_register"],
                       "action":"SCMP_ACT_ALLOW","args":[]}]' \
       /usr/share/containers/seccomp.json > webmachine-seccomp.json

For Docker the same recipe reads moby's default profile
(`profiles/seccomp/default.json` in the moby tree - Docker does not
install it as a file). For Kubernetes, put the result under the
kubelet's seccomp directory and name it:

    securityContext:
      seccompProfile:
        type: Localhost
        localhostProfile: webmachine-seccomp.json

Two more places can switch io_uring off, and neither is namespaced -
they are the HOST's, and no container flag reaches them:

- `/proc/sys/kernel/io_uring_disabled` (kernel 6.6+): `0` on, `1` only
  for processes in `kernel.io_uring_group`, `2` off entirely.
- The kernel itself: this tree needs **6.11 or newer** (it binds and
  listens through the ring - `IORING_OP_BIND`/`IORING_OP_LISTEN`).

## What goes into the build image

    build-essential   gcc/g++ (C++20) and make - liburing builds with make
    ruby              mruby's build system IS rake
    git               the tree's submodule and every mrbgem
    pkg-config        mruby-io-uring asks it for liburing's cflags
    zlib1g-dev        the system zlib this tree links (gzip, #147)
    libssl-dev        libcrypto, for the websocket handshake's SHA1()
    ca-certificates   git over https

**liburing-dev is NOT in that list, on purpose.** mruby-io-uring builds
liburing out of its own pinned submodule and this tree links that
static archive. (The build guard used to ask the SYSTEM for
`liburing.h` and refuse without it - which only ever worked by accident
on a developer machine that happened to carry the package. An image
built from a clean base refused with liburing sitting right there,
freshly compiled. Fixed; the guard now accepts the archive the gem
built.)

## What goes into the runtime image

Three packages, because liburing is linked statically and the rest is
the tree's own code:

    libz1        zlib
    libssl3      libcrypto
    libstdc++6   pulls libgcc-s1 and libc6 with it

## -march: do not ship `native`

`build_config.rb` compiles `-march=native` by default, which bakes the
BUILDER's CPU into the binary - correct for a machine that measures
itself, fatal for an image that moves. The Containerfile passes
`WM_MARCH=x86-64-v3` (AVX2, ~2015 and later) instead:

    podman build --build-arg WM_MARCH=x86-64-v2 -f Containerfile -t webmachine .

What that baseline costs against a native build is a measurement, and
it belongs in `bench/results/` like every other.

## Sizes, measured

    runtime image                99.6 MB
      of which debian:trixie-slim  81.1 MB
      of which the server binary   15.5 MB

If the base is what bothers you: a distroless or `-minimal` base works,
with one rule that is easy to get wrong and was measured getting
wrong - **the builder and the runtime must be the same distribution
release**. glibc and libstdc++ are forward-compatible only, so a
trixie-built binary on `distroless/cc-debian12` (Debian 12, glibc 2.36)
dies with `GLIBC_2.38 not found`. Pair bookworm with
`distroless/cc-debian12`, trixie with `debian:trixie-slim`, ubi9 with
`ubi9/ubi-minimal`. And if you copy libraries in by hand rather than
installing packages, copy the whole closure: on trixie, `libcrypto.so.3`
itself needs `libzstd.so.1`.

## The app is bytecode

The server never compiles Ruby (#100). `mrbc` comes out of the same
build, so the image compiles the app in the build stage:

    mruby/build/host/mrbc/bin/mrbc -o app.mrb examples/hello.rb

Handing `--app` a `.rb` file is refused by name, with the mrbc line to
run.

## File descriptors, and why the limit is not cosmetic

The server raises its soft `RLIMIT_NOFILE` to the hard one at startup
and DERIVES its connection capacity from what stands (#169) - there is
no guessed maximum anywhere. That means the container's limit decides
both how many connections it accepts and how much memory it reserves
for their state at startup. Name it:

    podman run --ulimit nofile=65536:65536 ...

An unbounded hard limit (systemd's `LimitNOFILE=infinity`, some CI
runners) makes the server reserve for a million connections it will
never see. `tools/webmachine-tune.sh` prints the same arithmetic
without starting anything.

## Ports and users

The image runs as uid 10001 and needs no capabilities: the ring, the
listener and the buffer pool are all unprivileged. A port below 1024 is
the one exception - publish a port instead of granting
`CAP_NET_BIND_SERVICE`:

    podman run -p 80:8080 ...

## One kernel with a broken recv-bundle contract

`WM_BUNDLE=0` narrows the server to one buffer per completion. It
exists for one measured kernel build (a 6.18.5-fc container kernel that
violated the dense-fill contract). Set it only if you see truncated or
interleaved request bytes:

    podman run -e WM_BUNDLE=0 ...
