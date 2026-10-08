# 0018. A real-world benchmark run is pinned by five things, and the system headers it reads are one of them

## Status

Proposed

## Context

A real-world benchmark figure is reproducible only if everything that moves
it is pinned. Four inputs already are:

- the **corpus pins**: each codebase's commit in `data/benchmark_repos.json`,
  which `corpus-check` verifies;
- the **aurora-lint commit**;
- the **oracle**: the `benchmark_adjudication` commit whose labels the run is
  scored against (ADR-0014);
- the **settings hash**: the SHA-256 the binary computes over the declared
  settings a run resolved to (ADR-0015), carried in the run id.

The system headers a scan resolves `#include <...>` against are a fifth input,
and until now nothing pinned them. They move findings in both directions:

- A declaration the scan cannot see becomes an undeclared identifier.
- A macro it cannot see leaves an arm unevaluated.
- A header found on one host and missing on another changes which preprocessor
  arms the file itself proves dead (ADR-0010).

Which `-dev` packages a host has installed changes findings, not only their
versions. The same aurora-lint change measured on a macOS host and on the Linux
benchmark machine moved the suite's findings in opposite directions, and nothing
in either run recorded why.

The hosts aurora-lint is developed on differ: Linux distributions,
macOS, Windows, FreeBSD. A fixed host-wide header set cannot be installed the
same way on all of them. Pinning the benchmark machine's own environment makes
every other machine's run non-reproducible by definition.

## Decision

1. **Each real-world benchmark declares its dependency set**, in
   `data/benchmark_deps/<benchmark>.json`. That is one set per benchmark and
   build configuration.
   - The set lists the packages that supply the system headers its
     declared build configuration includes.
   - Each entry is pinned by the content hash of what is fetched.
   - Each package carries one line saying which `#include` needs it. A
     package without one is refused, because review is what keeps a set
     minimal.
   - The tooling fetches Debian packages today. The Win32 corpus's SDK and
     CRT tree is already pinned the same way by a different fetcher, its
     existing header tree. Bringing it, or any other non-Debian source,
     into this declaration is future work, and it stays as it is meanwhile.
   - The set describes the corpus's **target platform**, its
     `primary_build_config`, not the host that scans it. A macOS host
     scanning a Linux corpus installs the same Linux headers a Linux host
     does.
2. **The set is installed into a per-benchmark tree**, never into the system.
   - One Ansible playbook installs the sets named with `-e benchmarks=`, or
     every declared set. It calls the same standard-library Python fetcher
     a host without Ansible can run directly.
   - The tree's directory is named by a hash of the declaration's platform,
     package base, sources, installed roots and pruned paths. So a re-pin is
     a new tree, and an existing one never changes.
   - Downloads are shared between sets through a content-addressed cache.
3. **The fifth pin is the set's manifest hash.** It is the SHA-256 of the
   sorted `F <path> <sha256 of bytes>` and `L <path> <link target>` lines, one
   for each file and link the set installs.
   - It is computed from the package contents as they are unpacked, not from
     the filesystem afterwards, so two hosts with the same declaration compute
     the same pin.
   - Modes, owners, timestamps and directory entries are not hashed.
   - A set that cannot be laid out faithfully on a host is refused there, with
     the paths that do not fit. An example is two paths differing only in case
     on a case-insensitive filesystem. Such a set is never silently merged.
4. **A real-world benchmark run requires its set.**
   - The runner verifies the tree's manifest hash before scanning, and refuses
     a missing or mismatched tree.
   - It records `{id, decl_sha256, manifest_sha256}` in the scan's sidecar,
     alongside the corpus commit.
   - The aurora-lint commit already pins the declaration, so the default run
     id needs no suffix for it.
   - A scan against the host's own headers is not a benchmark run. It is a
     local A/B or exploratory scan under its own run identity, and is never
     cited.
5. **Outside real-world benchmark runs, headers stay optional.** Shadow
   benchmarks, local scans and users' own scans run against whatever include
   paths they are given. A scan reports what it could not resolve; it does not
   refuse.

## Transition

Until a corpus declares its set, its runs continue exactly as before, under
the same run id. They are not covered by the five-pin claim. Each corpus
moves when its set is declared and its trend break is measured.

## Consequences

- **Official numbers still come only from the benchmark machine** (ADR-0004).
  What changes is that any machine holding the five pins reproduces them key for
  key. A difference between such a machine and the benchmark machine is a defect to explain, not
  environment noise to tolerate.
- **Moving every benchmark onto its declared set is a one-time trend break.**
  It is recorded as such and re-baselined, with the new keys
  delta-adjudicated before any precision claim. A later change to a set, such
  as a security update, a new distribution base, or a package added for a
  missed `#include`, is a reviewed change with its own A/B, never a silent
  refresh.
- **The declaration and fetcher live in this repository** because a stranger
  needs them to reproduce a benchmark. Recording the pin alongside results in
  the shared database belongs to `benchmarking_db`, and this repository stays
  Postgres-blind (ADR-0004).
- **The headers belong to other projects.** Each machine fetches its own copy from
  the upstream archive. The trees are never committed to a repository or
  copied between machines, which is why the pin is a package list plus a hash
  rather than the files.
- **This does not make headers mandatory for aurora-lint itself.** The binary's
  behaviour with and without include paths is unchanged. Only the benchmark
  harness demands them.
