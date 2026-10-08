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

# Two stages. 'tools' is the snapshot system plus the corpus build tools and
# no -dev package beyond libc's: python -m bench container-build-db starts a
# throwaway container from it per corpus, installs exactly that corpus's
# dependency set into it, and builds the corpus there to capture its compile
# database, so no other corpus's packages can shadow its headers or change
# its configure results. 'bench' adds the analysis tools, aurora-lint's own
# build dependencies and the dependency-set trees, and is what scans run in.
#
#   podman build --platform linux/amd64 --target tools \
#     -f container/benchmark.Dockerfile -t aurora-bench-tools .

ARG BASE=docker.io/library/debian@sha256:5ae3c39ebd15e229dcedd5cee596b2497182493d41ff162e824ba13fc1b2b867
FROM ${BASE} AS tools
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

# Frama-C (with the Eva plugin), built by opam into /opt/opam: a stage of
# its own, so changing it rebuilds nothing else. opam-repository is pinned
# to one commit, and opam checks every source tarball against the checksum
# that commit records.
FROM tools AS framac
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
ARG CLANG_TIDY_VERSION=1:21.1.8~++20251221032947+2078da43e25a-1~exp1~20251221153113.67
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
# LLVM build, pinned to the one the tool comparison is measured against.
# apt.llvm.org is not snapshotted, so the exact version is named here and
# recorded in the manifest; the packages are also kept in the maintainers' sha256-keyed artifact cache.
RUN curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] https://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-21 main" \
    > /etc/apt/sources.list.d/llvm.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends "clang-tidy-21=${CLANG_TIDY_VERSION}" \
      "clang-21=${CLANG_TIDY_VERSION}" "clang-tools-21=${CLANG_TIDY_VERSION}" \
 && ln -s /usr/bin/clang-tidy-21 /usr/local/bin/clang-tidy \
 && ln -s /usr/bin/clang-21 /usr/local/bin/clang \
 && ln -s /usr/bin/scan-build-21 /usr/local/bin/scan-build \
 && ln -s /usr/bin/analyze-build-21 /usr/local/bin/analyze-build \
 && rm -rf /var/lib/apt/lists/*

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
