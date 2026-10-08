# The real-world benchmark environment (docs/adr/0018): one image holding
# everything a benchmark run reads apart from the corpus and aurora-lint,
# which are mounted at run time (python -m bench container-run).
#
#   podman build --platform linux/amd64 -f container/benchmark.Dockerfile \
#     -t aurora-bench .
#
# The build context is the repository root, cut down by .containerignore to
# bench/ and the dependency-set declarations.
#
# Pinned here: the base image by its linux/amd64 digest; every Debian package
# by the snapshot.debian.org timestamp the dependency sets also use; Rust,
# Infer and clang-tidy by exact version (and sha256 where the upstream
# publishes one). The image is amd64 on every host, an arm64 Mac included
# (emulated), because the tools' exact builds are part of the pin.
#
# What a run records is not this image's digest (two builds of this file do
# not share one) but the hash of /etc/aurora-bench/environment.json, written
# by the last step (bench/environment.py).

# Stages. 'system' is the snapshot system plus the corpus build tools, with
# no -dev package beyond libc's. 'tools' is that plus its own manifest:
# python -m bench container-build-db starts a throwaway container from it
# per corpus, installs exactly that corpus's build packages into it, and
# builds the corpus there to capture its compile database, so no other
# corpus's packages can shadow its headers or change its configure results.
# 'framac' builds Frama-C on 'system' by itself. 'bench' adds the analysis
# tools, aurora-lint's own build dependencies and the dependency-set trees,
# and is what scans run in.
#
#   podman build --platform linux/amd64 --target tools \
#     -f container/benchmark.Dockerfile -t aurora-bench-tools .

ARG BASE=docker.io/library/debian@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867
FROM ${BASE} AS system
ARG BASE
ARG SNAPSHOT=20260915T000000Z

ENV DEBIAN_FRONTEND=noninteractive \
    AURORA_BENCH_BASE=${BASE} \
    AURORA_BENCH_SNAPSHOT=${SNAPSHOT} \
    SQC_BENCH_ROOT=/bench

# Debian, frozen at the snapshot: the same packages on every build. Only
# the bookworm main suite, the one index the dependency sets are resolved
# against (bench/deps.py resolve), so the image and every set see one
# package universe: a set's pinned version is always installable here
# without a downgrade (bookworm-security carries a newer linux-libc-dev, for
# one). Security updates buy a frozen analysis environment nothing.
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' \
    "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${SNAPSHOT} bookworm main" \
    > /etc/apt/sources.list \
 && apt-get update \
 && apt-get -y upgrade \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils gnupg git python3 \
      build-essential cmake ninja-build autoconf automake libtool pkg-config bear \
 && rm -rf /var/lib/apt/lists/*

# The 'tools' stage: the system above plus its own manifest. Compile
# databases are built here, so the bench image records the manifest's pin
# and container-build-db checks it. Only the two files the manifest needs
# are copied, so an edit elsewhere in bench/ rebuilds nothing.
FROM system AS tools
COPY bench/__init__.py bench/environment.py /opt/aurora-bench/bench/
RUN cd /opt/aurora-bench && python3 -m bench.environment write-tools /etc/aurora-bench/tools.json

# Frama-C (with the Eva plugin), built by opam into /opt/opam: a stage of
# its own, so changing it rebuilds nothing else. opam-repository is pinned
# to one commit, and opam checks every source tarball against the checksum
# that commit records.
FROM system AS framac
ARG OPAM_REPOSITORY_COMMIT=e4cd7ede2d55a46570977c0ffaa7e96845190817
ARG OCAML_VERSION=4.14.2
ARG FRAMA_C_VERSION=33.0
ENV OPAMROOT=/opt/opam OPAMYES=1 OPAMCONFIRMLEVEL=unsafe-yes
RUN apt-get update \
 && apt-get install -y --no-install-recommends opam m4 unzip libgmp-dev zlib1g-dev graphviz \
 && rm -rf /var/lib/apt/lists/*
RUN opam init --bare --disable-sandboxing --no-setup default \
      "git+https://github.com/ocaml/opam-repository.git#${OPAM_REPOSITORY_COMMIT}" \
 && opam switch create default "ocaml-base-compiler.${OCAML_VERSION}" \
 && opam install --switch=default "frama-c.${FRAMA_C_VERSION}" \
 && opam clean --all-switches --download-cache --logs --repo-cache

FROM tools AS bench
ARG RUST_VERSION=1.95.0
ARG RUST_SHA256=2e0338f18ecbaa4a0f631b9e80e8b8e26bb6fe77dd5454fba8a70cf96c1e84a1
ARG INFER_VERSION=1.2.0
ARG INFER_SHA256=21504063fb3a1dbc7919f34dc6e50ca0d35f50b996d91deb7b8bea8243d52d82
ENV CARGO_HOME=/opt/cargo \
    PATH=/opt/rust/bin:/opt/infer/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Open-source cppcheck removed its CERT addon (addons/cert.py) in 2022, so
# cppcheck runs here without it.
# cppcheck and Flawfinder from the snapshot; libgmp10, zlib1g and graphviz
# are what Frama-C (copied from its stage below) needs at run time. gcc's
# -fanalyzer is the snapshot's gcc 12, already in the tools stage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cppcheck flawfinder libtinfo5 \
      libgmp10 zlib1g graphviz \
 && rm -rf /var/lib/apt/lists/*

# clang-tidy and the Clang Static Analyzer (scan-build, analyze-build), one
# LLVM build: the one the tool comparison is measured against. apt.llvm.org
# is not snapshotted and prunes old builds, so the packages are named here
# by file and sha256, fetched from LLVM_POOL (apt.llvm.org's pool by
# default; the maintainers' sha256-keyed artifact cache keeps a copy) and
# installed as local files, their dependencies from the snapshot. No
# repository or signing key is trusted: each file is checked by its hash.
ARG LLVM_POOL=https://apt.llvm.org/bookworm/pool/main/l/llvm-toolchain-21
RUN mkdir /tmp/llvm && cd /tmp/llvm \
 && printf '%s\n' \
    "43167d4912316e591f4dc122bd8e9cd0c2db95c31edcc47cde97e89a496c2024  clang-21_21.1.8~++20251221032947+2078da43e25a-1~exp1~20251221153113.67_amd64.deb" \
    "c3d950ac10216becc29c4b545bd7a8905c005ff344f9b60c167728d7c9886708  clang-tidy-21_21.1.8~++20251221032947+2078da43e25a-1~exp1~20251221153113.67_amd64.deb" \
    "a08c8d1c53f7ef2c1fa559ac63b3b2e35ae7525ef633225615ab5f47ed6c1ffb  clang-tools-21_21.1.8~++20251221032947+2078da43e25a-1~exp1~20251221153113.67_amd64.deb" \
    "8b5d26e30f336b0f5727f506b9d3e31890d225efc1a5eb1f73ab4e253ced9da6  libclang-common-21-dev_21.1.8~++20251221032947+2078da43e25a-1~exp1~20251221153113.67_amd64.deb" \
    "2e04f5de6f6f877f505a7abee85e1210d71b3b07d380ec5ebfaec45efe5a7fea  libclang-cpp21_21.1.8~++20251221032947+2078da43e25a-1~exp1~20251221153113.67_amd64.deb" \
    "9ba73f312d5e76875363f493287ad6a5ee6754c22bbca3a07061ae07c1129659  libclang1-21_21.1.8~++20251221032947+2078da43e25a-1~exp1~20251221153113.67_amd64.deb" \
    "06646d519de58f391ca049b8a47bbd678c929540f4cb8a73caac29818c5cf720  libllvm21_21.1.8~++20251221032947+2078da43e25a-1~exp1~20251221153113.67_amd64.deb" \
    "d7a8b99bf09cfd75f9b2dc9bc016fd2da5bada6b55722485f632615cc972c4c0  llvm-21-linker-tools_21.1.8~++20251221032947+2078da43e25a-1~exp1~20251221153113.67_amd64.deb" \
    > SHA256SUMS \
 && for f in $(awk '{print $2}' SHA256SUMS); do curl -fsSLo "$f" "$LLVM_POOL/$f"; done \
 && sha256sum -c SHA256SUMS \
 && apt-get update \
 && apt-get install -y --no-install-recommends ./*.deb \
 && ln -s /usr/bin/clang-tidy-21 /usr/local/bin/clang-tidy \
 && ln -s /usr/bin/clang-21 /usr/local/bin/clang \
 && ln -s /usr/bin/scan-build-21 /usr/local/bin/scan-build \
 && ln -s /usr/bin/analyze-build-21 /usr/local/bin/analyze-build \
 && cd / && rm -rf /tmp/llvm /var/lib/apt/lists/*

# Rust, the version rust-toolchain.toml names, from its sha256-checked
# standalone installer. aurora-lint is built with it at run time.
RUN curl -fsSLo /tmp/rust.tar.xz \
      https://static.rust-lang.org/dist/rust-${RUST_VERSION}-x86_64-unknown-linux-gnu.tar.xz \
 && echo "${RUST_SHA256}  /tmp/rust.tar.xz" | sha256sum -c - \
 && mkdir /tmp/rust && tar -xJf /tmp/rust.tar.xz -C /tmp/rust --strip-components=1 \
 && /tmp/rust/install.sh --prefix=/opt/rust --components=rustc,cargo,rust-std-x86_64-unknown-linux-gnu \
 && rm -rf /tmp/rust /tmp/rust.tar.xz

# Infer, the prebuilt release, sha256-checked.
RUN curl -fsSLo /tmp/infer.tar.xz \
      https://github.com/facebook/infer/releases/download/v${INFER_VERSION}/infer-linux-x86_64-v${INFER_VERSION}.tar.xz \
 && echo "${INFER_SHA256}  /tmp/infer.tar.xz" | sha256sum -c - \
 && mkdir /opt/infer && tar -xJf /tmp/infer.tar.xz -C /opt/infer --strip-components=1 \
 && rm /tmp/infer.tar.xz

# Frama-C: the opam root, built in its own stage above.
COPY --from=framac /opt/opam /opt/opam
ENV OPAMROOT=/opt/opam \
    PATH=/opt/opam/default/bin:${PATH}

# aurora-lint's own build dependencies (git2 links libgit2, which needs
# OpenSSL and zlib headers). They land in the image's /usr/include, which a
# scan never searches: a benchmark scan reads its dependency set's tree.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# Every benchmark's dependency set, each its own tree under /bench/deps
# (never installed into the image's system directories).
COPY bench /opt/aurora-bench/bench
COPY data/benchmark_deps /opt/aurora-bench/data/benchmark_deps
COPY data/benchmark_repos.json /opt/aurora-bench/data/benchmark_repos.json
RUN cd /opt/aurora-bench \
 && for f in data/benchmark_deps/*.json; do \
      python3 -m bench.deps fetch "$(basename "$f" .json)" || exit 1; \
    done \
 && rm -rf /bench/deps/.cache

# The environment manifest: its hash is the pin a run records.
RUN cd /opt/aurora-bench && python3 -m bench.environment write /etc/aurora-bench/environment.json

WORKDIR /work
