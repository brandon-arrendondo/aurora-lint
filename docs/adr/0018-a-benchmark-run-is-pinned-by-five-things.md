# 0018. A real-world benchmark run is pinned by five things, and the environment it ran in is one of them

## Status

Proposed

## Context

A real-world benchmark figure is reproducible only if everything that moves
it is pinned. Four inputs already are:

- the **corpus commit**: each codebase's pin in `data/benchmark_repos.json`,
  which `corpus-check` verifies;
- the **aurora-lint commit**;
- the **oracle**: the `benchmark_adjudication` commit whose labels the run is
  scored against (ADR-0014);
- the **settings hash**: the SHA-256 the binary computes over the declared
  settings a run resolved to (ADR-0015), carried in the run id.

The environment the scan ran in was unpinned. Above all, that means the
system headers it resolved `#include <...>` against, and which of a
corpus's build flags it knew. Those move findings in both directions:

- A declaration the scan cannot see becomes an undeclared identifier.
- A macro it cannot see leaves an arm unevaluated.
- A header found on one host and missing on another changes which arms the
  file itself proves dead (ADR-0010).

Which `-dev` packages a host has installed changes findings, not only their
versions. The same aurora-lint change measured on a macOS host and on the
Linux benchmark machine moved the suite's findings in opposite directions, and
nothing in either run recorded why.

A host can also shadow a corpus's own headers. A host's `libsqlite3-dev`
supplies an older `sqlite3.h` than the one sqlite's tree generates, and a
host's `libmbedtls-dev` supplies `everest/` headers in place of mbed TLS's
bundled ones.

The hosts aurora-lint is developed on differ: Linux distributions,
macOS, Windows, FreeBSD. No host-wide header set installs the same way on all
of them, and a corpus's build run on a host configures against that host.

## Decision

1. **The benchmark environment is one container image**
   (`container/benchmark.Dockerfile`). It holds:
   - a Debian 12 (bookworm) base pinned by digest, its `main` suite frozen at
     one snapshot.debian.org timestamp (the same suite the dependency sets
     are resolved against, so every pinned version installs as is);
   - the corpus build tools, in a stage of their own;
   - the comparison tools at exact versions: cppcheck, clang-tidy and the
     Clang Static Analyzer (one LLVM build), Flawfinder, gcc's `-fanalyzer`,
     Infer and Frama-C;
   - the Rust toolchain aurora-lint is built with;
   - every benchmark's dependency set.

   The corpus checkout and aurora-lint are mounted at run time, and
   aurora-lint is built inside the image (`python -m bench container-run`).
   The image is linux/amd64 on every host, an arm64 Mac included, because the
   tools' exact builds are part of the environment.
2. **Each benchmark declares its dependency set** in
   `data/benchmark_deps/<benchmark>.json`.
   - **Coverage.** A set is the union of the system headers that every
     in-scope source file needs, in any configuration Debian can supply.
     Only the files a declaration names as written for another platform
     (Windows, a BSD, Android, the web) are left out. Backend and option
     files are in scope and scored, and every compilable configuration counts
     (ADR-0010).
   - **Exclusions.** A package is excluded only for one of these reasons:
     - it is a multilib variant (`-m32`, x32);
     - it ships a copy of the corpus's own headers, or of a library the corpus
       bundles and builds itself;
     - it reuses another platform's header name;
     - it serves only an out-of-scope directory.

     Each exclusion and each package carries its reason.
   - **Pinning.** Packages are pinned by version and by the sha256 of the
     `.deb`, resolved against the same snapshot as the image.
   - **Layout.** Each set is installed as its own tree, never into the image's
     system directories, so one corpus's packages cannot shadow another's.
   - **Target platform.** A set describes the corpus's target platform (its
     `primary_build_config`), not the host.
3. **Each benchmark declares its build recipe; its compile database is the
   declared default build.** The recipe is the configure or CMake line, with
   every autodetected option it depends on set explicitly, and the part of
   the set its build installs.
   - `python -m bench container-build-db` runs the recipe in a throwaway
     container from the image's build stage. Only that corpus's build
     packages are installed there.
   - It caches the result per (environment, corpus commit): the database as
     a template plus the headers the build generated.
   - A scan reads the database for project directories and `-D` flags, and
     the set's directories as its system directories. The search order is
     the corpus's own directories, then the build's generated headers, then
     the set: no system copy can shadow a corpus header.
   - Nothing derived from a corpus is committed.
4. **The fifth pin is the environment manifest's hash.** The image's last
   build step writes `/etc/aurora-bench/environment.json`. It lists:
   - the base and the snapshot;
   - every installed package's version;
   - each tool's version;
   - each dependency set's manifest hash.

   The manifest's SHA-256 is the pin. An image digest is not: two builds of
   one Dockerfile do not share a digest, but they do share the manifest, which
   was measured by rebuilding without cache. A set's manifest hash is
   computed from the package contents as they are unpacked, so it is the same
   on every host.
5. **A benchmark run, real-world or Juliet, happens in the image, and records
   its pins.** Juliet's set is the C library, compiler and kernel headers;
   its test cases for Windows are another platform's.
   - The commit declares the environment it expects
     (`data/benchmark_environment.json`). A run in any other image gets its
     own run id (`-env<hash>`), so two environments at one commit never
     share one.
   - The run's sidecar records the environment pin, the set's pin and the
     compile database's hashes, alongside the corpus commit.
   - A run refuses a missing or mismatched set, and a missing or stale build
     cache.
   - Any other scan of a benchmark corpus runs under its own run id and is
     never cited. That covers the host's tools outside the image
     (`-hostenv`), another header tree (`-hdr-<id>`, `-hdr-host`), and the
     checkout's own host-built database.
6. **The shadow suite is deliberate variance.** Shadow corpora (randomized
   A/B) run on a contributor's own host:
   - no compile database;
   - system headers not required;
   - warnings and partial scans accepted.

   Their extra noise is welcome. Outside the benchmark suite, headers stay
   optional for every scan: a scan reports what it could not resolve and does
   not refuse.
7. **Windows.** Linux corpora do not cover Windows, so their sets never
   include Windows SDK headers. Windows-only files in them read no Windows
   headers, as ADR-0010's platform handling expects.
   - The Win32 corpus's set is the pinned Windows SDK and CRT tree, fetched
     by xwin. Fetching it accepts Microsoft's licence, and that tree is never
     copied between machines. So the shared image is built without it, and
     each machine that runs the Win32 corpus adds it locally
     (`container/licence.Dockerfile`), accepting the licence for itself.
     Adding it to the shared image yields exactly the full environment's
     pin, so one declared pin covers every machine.
   - Its compile database comes from its Visual Studio project's declared
     configuration, as `clang-cl` entries targeting MSVC, with that tree as
     its system directories.
   - Native-MSVC checks need a Windows host.

## Transition

Until a corpus declares its set and recipe, its runs continue as before,
under the same run id, and are not covered by the five-pin claim. Each corpus
moves when its set is declared and its trend break is measured.

## Consequences

- **Official numbers still come only from the benchmark machine** (ADR-0004).
  Any machine holding the five pins is expected to reproduce them key for key.
  A difference between such a machine and the benchmark machine is a defect to explain, not
  environment noise.
- **Moving the suite into the image is a one-time trend break.** It is
  recorded and re-baselined, and new keys are delta-adjudicated before any
  precision claim. A later change to the image, a set or a recipe is a
  reviewed change with its own A/B, never a silent refresh.
- **The Dockerfile, the set declarations and the manifest generator are the
  published recipe**, and there is no parallel one. A stranger builds the
  image and checks the manifest hash against the one a release records. Each
  release's reproducibility record carries its `environment.json`.
- **Pins rot.** Snapshot timestamps and sha256-pinned downloads keep their
  meaning, but their sources can disappear: a dated base-image tag, a
  release tarball, a non-snapshotted package repository. Every such artifact
  is kept by the maintainers in a sha256-keyed artifact cache, refreshed whenever the Dockerfile changes. The shared image is distributed privately from that
  private registry by digest (`data/benchmark_environment.json` names it).
  It is never published, because it contains other projects' headers.
  Strangers build it from the Dockerfile instead. Microsoft's SDK is in
  neither: each machine fetches its own.
- **This repository stays Postgres-blind** (ADR-0004). Recording the pins
  alongside results in the shared database belongs to `benchmarking_db`.
- **aurora-lint itself is unchanged.** Its behaviour with and without include
  paths or a compile database is what it was. Only the benchmark harness
  demands an environment.
