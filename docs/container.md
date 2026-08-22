# Container

## Build and run

    git submodule update --init --recursive
    podman build -f Containerfile -t webmachine .

    jq '.syscalls += [{"names":["io_uring_setup","io_uring_enter","io_uring_register"],
                       "action":"SCMP_ACT_ALLOW","args":[]}]' \
       /usr/share/containers/seccomp.json > webmachine-seccomp.json

    podman run --rm -p 8080:8080 --ulimit nofile=65536:65536 \
      --security-opt seccomp=./webmachine-seccomp.json webmachine

Docker: same `Containerfile`, and derive the profile from moby's
`profiles/seccomp/default.json`. Kubernetes: `seccompProfile: {type:
Localhost, localhostProfile: webmachine-seccomp.json}`.

Without those three syscalls the server prints `URING_AVAILABLE is
false` and exits.

## Host requirements

- Linux 6.11+
- `/proc/sys/kernel/io_uring_disabled` = 0

## Packages

Build: `build-essential ruby git pkg-config zlib1g-dev libssl-dev
ca-certificates` (no liburing-dev - the gem builds it).

Runtime: `libz1 libssl3 libstdc++6`.

## Knobs

    --build-arg WM_MARCH=x86-64-v2   CPU baseline (default x86-64-v3)
    -e WM_BUNDLE=0                   one buffer per completion
    --ulimit nofile=N                sets capacity and startup memory

## App

`--app` takes bytecode, not `.rb`:

    mruby/build/host/mrbc/bin/mrbc -o app.mrb examples/hello.rb

## Smaller base

Builder and runtime must be the same distribution release. Pair
bookworm with `distroless/cc-debian12`, trixie with
`debian:trixie-slim`, ubi9 with `ubi9/ubi-minimal`.
