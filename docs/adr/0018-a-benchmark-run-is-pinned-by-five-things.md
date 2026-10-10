# 0018. A benchmark run is pinned by five things, and the environment it ran in is one of them

## Status

Accepted (Brandon, 2026-10-09).

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

The hosts aurora-lint is developed on differ: Linux distributions, macOS,
Windows, FreeBSD. No host-wide header set installs the same way on all of
them, and a corpus's build run on a host configures against that host.

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
  A difference between such a machine and the benchmark machine is a defect
  to explain, not environment noise.
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
  is kept by the maintainers in a sha256-keyed artifact cache, refreshed
  whenever the Dockerfile changes, and the shared image is distributed
  privately by digest (`data/benchmark_environment.json` names it). The
  image is never published, because it contains other projects' headers.
  Strangers build it from the Dockerfile instead. Microsoft's SDK is in
  neither: each machine fetches its own.
- **This repository stays Postgres-blind** (ADR-0004). Recording the pins
  alongside results in the shared database belongs to `benchmarking_db`.
- **aurora-lint itself is unchanged.** Its behaviour with and without include
  paths or a compile database is what it was. Only the benchmark harness
  demands an environment.

## Amendment (2026-10-09, Brandon): a benchmark declares its target facts

**Status:** ruled (Brandon, 2026-10-08 and 2026-10-09); not yet
implemented. The real-world manifests declare only their data model today,
and Juliet only its data model and that it is a closed program.

### Context

ADR-0015's 2026-10-08 amendment separates a preset's reading from its
environment stance. `--strict` assumes a hosted ISO C library, and POSIX and
the language editions are facts that hold only when declared (its Decisions
1 and 4). A benchmark scored under `--strict` would therefore apply no POSIX
exemption on a corpus built for Linux unless the benchmark declares POSIX.
That amendment's Decision 5 says each benchmark declares its facts, and
that this ADR needs an amendment to say so.

### Decision

1. **Each benchmark declares `posix_version` and `c_standard`, and its
   target facts** (ADR-0015 Decision 4's 2026-10-03 amendment: the data
   model, type widths and the like). Each value describes the corpus's
   configuration of record (its `primary_build_config`; ADR-0010 Decision 6),
   not the host. Each carries a comment stating its basis, as the declared
   data models already do. A corpus whose configuration of record is not
   POSIX declares no `posix_version`.
2. **Its library stays the ISO C and POSIX model** (`libc = "iso-posix"`),
   even where the configuration of record names glibc as its toolchain. No
   library's extensions enter published figures (ADR-0015 Decision 5;
   Brandon, 2026-10-09). The library is declared explicitly, so that it is
   the same under all three presets: `--pedantic` trusts only a declared
   library.
3. **Where the facts live.** They are aurora-lint settings, so they live
   where each benchmark's settings already do. Brandon's ruling put them in
   "the benchmark environment manifest", which he reads as each
   benchmark's own settings, not the image's `environment.json` (Brandon,
   2026-10-09):
   - a real-world corpus: the `[environment]` section of its rules
     manifest, `conf/realworld/<corpus>-rules.toml`, which already declares
     its `data_model`;
   - Juliet: the settings every Juliet scan passes
     (`JULIET_SETTING_OVERRIDES` in `bench/config.py`), which already
     declare `data_model` and `closed_program`.

   They do not go in `data/benchmark_environment.json`, which pins the
   image for every benchmark at once. Nor do they go in
   `data/benchmark_deps/<corpus>.json` or `data/benchmark_repos.json`,
   which describe the header set, the build recipe and the corpus. A
   `--profile` keeps a manifest's declared facts, so every preset a
   benchmark runs under scans with them.
4. **How they are pinned.** A declared fact enters the settings hash, the
   fourth pin, which the run id carries. It does not enter the environment
   pin, which is unchanged. The facts a corpus's compile database states
   per translation unit (`-std`, `-D_POSIX_C_SOURCE`, `-m32`) are
   declarations too (ADR-0015, 2026-10-08 amendment, Decision 3). The run
   already pins that database by its hashes in the sidecar (Decision 5),
   and the decoupling code records each fact's source in the settings as
   ADR-0015 requires. Nothing is read from the host.

### Interaction with the decoupling code

The code that implements ADR-0015's 2026-10-08 amendment is what reads
these facts. Until it lands, the binary accepts `c_standard` and
`posix_version` and hashes them, but no rule reads them. Declaring them
earlier would change every benchmark's settings hash, and so its run id,
with no change in findings, and then the code would change them again.
They are therefore declared in the same change as that code (Brandon,
2026-10-09), so a benchmark's hash changes once, with its trend break measured by that
change's A/B under `default` and `strict`. That change also decides how
`iso-posix` relates to `posix_version` once the POSIX contracts move behind
the fact. If it splits the model, a benchmark declares the ISO C model plus
`posix_version`, which is the same contracts under a new name.

### Consequences

- "aurora-lint itself is unchanged" (Consequences, above) no longer holds
  for compile databases. Once the decoupling code lands, a compile database
  supplies facts as well as include paths and `-D` macros. A benchmark's
  declarations are made in its manifest, so a conflict between a manifest
  fact and the database is reported by the scan, and the manifest wins.
- A `--strict` benchmark figure no longer depends on what the strict preset
  assumes about POSIX, only on what the benchmark declares.

## Amendment (2026-10-09, Brandon): the sixth pin is the text of each rule

**Status:** ruled (Brandon, 2026-10-09); not yet implemented. The title's
"five things" is left as written; with this amendment a run is pinned by
six.

### Context

The oracle records whether the code violates a CERT C rule "as written"
(ADR-0014 Decision 1), and `--strict` is that reading (ADR-0015). The
written rule moves. CERT's pages are maintained in the
`cmu-sei/secure-coding-standards` repository, and they change: examples are
fixed, lists gain or lose functions, exceptions are reworded, and this
project contributes some of those changes. A label judged against one
version of a page can be wrong against the next, and nothing in a run
records which version a label meant. Brandon: "the 6th element of our
reproducibility vector - what version of the rules are we using? ... that
greatly affects the oracle", and "i'm also OK with per rule determination
of pin of the rule".

The project's rulings move too. A ruling can change what `--strict` reads
in an unchanged page (how a list is read, which reading of an ambiguous
sentence is taken), so a label also depends on the rulings it was judged
under.

### Decision

1. **The sixth pin is the rule-text pin: a per-rule map.** Each rule id maps
   to the merged commit of `cmu-sei/secure-coding-standards` its text is
   pinned at, the path of its page's source in that commit, and the SHA-256
   of that file's content (the rule's `rule_text_version`). The pin a run
   records is the SHA-256 of the map's canonical serialisation, next to the
   other five.
2. **The map lives with the oracle.** It is one file in the oracle
   repository, `benchmark_adjudication`, versioned with the labels it
   governs. Each entry also records the date it was set and the reason it
   moved (an upstream fix, a new rule, a correction of the pin). The oracle
   commit (the third pin) therefore contains the map; recording the map's
   digest as its own pin lets a release show that a rule's text moved
   without diffing the oracle.
3. **There is one oracle, not one per pin.** Each label carries the
   `rule_text_version` it was judged against, so ADR-0014's key becomes
   `(project, commit, file, line, rule, rule_text_version)`. "The oracle at
   pin P" is a query: for each rule, the labels whose `rule_text_version`
   equals the map's entry.
4. **Each label also records the rulings version it was judged under:** a
   `benchmark_adjudication` commit, since the project's record of rulings
   lives with the labels, or the identifier of the ruling it applied. It is
   a field of the label, not part of its key: a later ruling adds a newer
   label for the same key and leaves the earlier one as history. It is not
   a seventh pin: because the rulings live in the oracle repository, the
   oracle commit pins them with the labels (Rulings, below).
5. **Advancing one rule's pin relabels only that rule.** A pin moves on
   Brandon's ruling, when CERT merges a change to the rule's page or when a
   review finds the pin stale. Only that rule's map entry changes. Unless
   the move carries labels forward by a recorded review (Rulings, below),
   its labels are re-judged against the new text under E5 of the 2026-10-07
   cross-cutting rulings in `docs/design/rule-disposition.md` (relabel and
   re-run before re-scoring), and attributed as a relabel caused by the
   text. The old labels stay, under their old `rule_text_version`, as the
   living record. Every other rule's pin and labels carry forward unchanged.
6. **Scoring selects by the map.** For each rule, a score uses the labels
   whose `rule_text_version` equals the map's entry for that rule, and among
   those the label judged under the latest rulings version. A rule with no
   labels at its pinned version is unscored at that pin, and the report says
   so; it is not scored against labels for an older text.
7. **A pin is always a merged commit.** Labels are never judged against
   wording that has been proposed but not merged upstream, this project's
   own proposals included. A ruling may anticipate a proposed change, but
   the labels follow the merged text.
8. **A release reports a moved pin.** A release's reproducibility record
   carries the map's digest and lists every rule whose pin moved since the
   previous release, with both commits. Where a measured rule's pin moved
   inside the period a release reports on, that rule's figures are given
   under both pins.

### Implementation

Named here; their code is specified where it is written.

- **The oracle's label schema, export, ingest and scoring**, in
  `benchmark_adjudication` and in `benchmarking_db`, which holds the shared
  copy (ADR-0004): the `rule_text_version` key component, the rulings
  version field, the map file, and selection by the map.
- **aurora-lint's rule metadata** records, beside each rule's page link,
  the page version its implementation was last reviewed against (commit
  and content hash), so a rule reviewed against a different text than the
  oracle's pin is visible.
- **Run provenance**: the run's sidecar records the map's digest with the
  other five pins.

### Rulings (2026-10-09)

- **The rulings version is a label field, not a seventh element** (Brandon:
  "so long as it appears in the [benchmark_adjudication] repo so it does
  have a SHA - it then becomes an extension of the oracle SHA"). The
  project's record of rulings therefore lives with the labels in
  `benchmark_adjudication`, and the oracle commit pins both. Moving the
  record there is its own change.
- **A page change that does not touch the rule's reading** (tool rows,
  bibliography, formatting) carries the rule's labels forward by a recorded
  review: the map entry records that the pin moved with no change to the
  reading, and why. The labels take the new `rule_text_version` without
  being re-judged.
- **The first map** pins every rule at one merged commit: the one the
  rules were last read against. Existing labels take that version as
  carried forward and are marked so.

### Consequences

- A label's churn now has three named causes, kept apart: the tool changed
  (a run), the text changed (a pin), or the reading changed (a ruling).
- A figure is comparable across releases rule by rule: where a rule's pin
  did not move, its labels carry forward; where it did, both are reported.
- Contributing a fix upstream changes the oracle only once the fix is
  merged and the rule's pin is moved on a ruling, never by the proposal
  itself.
