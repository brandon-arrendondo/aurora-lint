# 0010. Every compilable configuration counts — a preprocessor arm is live unless the file itself proves it dead

## Status

Accepted (Brandon, 2026-09-21). Records a policy the code and the oracle
have applied since mid-2026 without a single written statement of it; like
the other ADRs it implies rework downstream (scope declarations, a small
legacy relabel, two tasks named under Consequences) rather than describing
a finished state.

## Context

aurora-lint has no preprocessor. tree-sitter parses the file as written, so
every `#if`/`#ifdef`/`#else` arm is visible to every rule at once, and the
project had to decide what a finding inside a conditional arm *means*. The
decision was made piecemeal, in code comments and adjudication batches, and
each piece points the same way:

- **Suppression only for arms the file itself proves dead.**
  `src/analyze/suppression.rs` silences a finding only inside `#if 0`, a
  `__cplusplus`-gated region when building as C, or a `#if defined(MACRO)`
  arm whose definedness is provable from an unconditional `#define`/`#undef`
  in the same file. Those arms cannot be compiled
  by *any* configuration of a C build; nothing else is suppressed.
- **The platform profile resolves names, it does not filter findings.**
  `src/analyze/dead_regions.rs` seeds a POSIX assumption table so that a
  collector building one `name -> fact` table (typedefs, function-like
  macros) picks the POSIX definition of `u16` instead of the `_MSC_VER` one.
  Its module doc says in so many words that finding suppression deliberately
  stays *unseeded*: "silencing every finding inside an `#ifdef _WIN32` block
  corpus-wide is a separate policy decision from which of several typedefs a
  name resolves to." This ADR is that decision, and the answer is no.
- **Mutually exclusive arms are alternatives, not one flow.** MEM31-C,
  MEM30-C and ARR36-C were all misfires from *conflating* arms —
  a free in the OpenSSL-3 arm and a free in the `#else` arm read as two frees
  on one path. The fix in every case was to analyze each arm as its own
  flow, not to drop an arm. MSC13-C's preprocessor-alternative groups (`bad232a5` and
  the fixes before it) are the same idea for declarations.
- **The oracle labels config-disabled arms as violations.** hostap's full
  audit labeled ~195 DCL13-C rows TP in `#else` stubs of `CONFIG_SAE`,
  `CONFIG_GAS`, `CONFIG_PR` and similar — code a default hostap build with
  those features enabled never compiles. The project's API00-C labeling standard holds
  that an `assert()` is not a parameter guard *because*
  `NDEBUG` strips it: the release configuration exists, so the unguarded
  path exists.
- **Platform-specific files are a scope boundary, not a label basis.**
  `docs/design/realworld-corpus-scope.md` puts curl's Windows/Apple-only
  files outside the Linux oracle's denominator and says explicitly this is
  "a configuration boundary, not a 'don't ship it' boundary". A similar
  benchmarking_db finding (INT02-C TPs in code the oracle host never compiles) reached the same
  place: the verdicts stand as statements about the source; what needs
  deciding is the denominator.

- **The oracle measures one configuration per corpus, implicitly.** The
  benchmark host is Linux; `dead_regions.rs` assumes POSIX; curl's oracle
  excludes 14 Windows/Apple-only files; sel4's compile database is the
  `pc99`/x86 build and its arm/riscv trees are scanned but never compiled
  there (macro-expansion.md §11). No corpus entry in
  `data/benchmark_repos.json` *states* which configuration its precision
  figure describes. Scanning every configuration a project can build
  (cppcheck's `-D`/`--max-configs` enumeration) is a different capability:
  it is not in the backlog as a task today, and doing it in a
  time-expedient way needs design work first.

What prompted writing it down: a human-review packet (hostap EXP34-C,
2026-09-21) asked whether a NULL return that only exists under
`CONFIG_TESTING_OPTIONS` "counts". Brandon's ruling: any compilable CFLAG
path that produces a violation is a violation, full stop; it is not our
place to decide which flags an end consumer builds with or which are
"rarely used"; the project suppresses if it wants to (ADR-0001). A survey
of the public oracle the same day found the applied policy already agrees
(hundreds of TP rows inside config-gated arms) with a residue of roughly two
dozen legacy FP rows whose stated basis is "compiled out in release" or
"only under the standard build config" — the pattern this ADR rules out.

## Decision

1. **A finding in an arm that some C configuration can compile is reported,
   and labeled, as written.** Which flags a build defines, which are
   default, which are "testing-only", "debug-only" or "rarely used" — none
   of it is a detection input and none of it is an FP basis. The reason
   field states what the construct is and why it violates the rule at that
   line; "not compiled in a normal build" is not a reason.
2. **"Dead" means provable from the file itself.** `#if 0`, `__cplusplus`
   when built as C, and locally-constant `#define`/`#undef` evidence are
   the whole list. Extending it needs the same kind of proof: no
   configuration of a C build can include the arm. A compiler-predefined
   platform macro (`_WIN32`, `_MSC_VER`, `__vxworks`) does not qualify — a
   different host compiles it.
3. **Platform is resolved, not suppressed.** The one-profile assumption
   table picks among conditional *definitions* of a name so width- and
   type-sensitive rules can work. It never decides whether a finding is
   emitted. A future `--platform` or compile-database-derived table changes
   name resolution and nothing else.
4. **Arms are alternatives.** A rule that tracks state across statements
   models each mutually exclusive arm as its own path. A finding that only
   exists by combining two arms that never compile together is a misfire
   (ADR-0005) and a bug to fix — that is how "every configuration counts"
   avoids inventing configurations that don't exist.
5. **Asserts depend on the policy setting (ADR-0015).** In the `NDEBUG`
   configuration a standard `assert()` is gone, and in the debug
   configuration it is compiled and evaluated.
   - **Default policy:** a dominating assert whose condition establishes the
     property is a guard, strippable or not. This is the assumption the Clang
     Static Analyzer, Polyspace and Coverity's models make, and CERT's own
     EXP34-C compliant solution relies on it.
   - **Strict policy:** a strippable assert guards nothing, because the release
     build removes it (C11 7.2p1; CERT MSC11-C: assertions are not for
     run-time error checking and are generally turned off before
     deployment). This is the reading MISRA-style and certified code needs.
   - **Both policies:** a violation inside an assert's argument is a
     violation, because an active assert evaluates it. An assert macro with
     no build-flag arm, such as valkey's `serverAssert`, is compiled in every
     configuration, and one that dominates the flagged use is a guard under
     both policies, provided its failure path provably does not return.
   - **The oracle** records the strict verdict and tags the rows whose only
     safety basis is a strippable assert, so both policies are scored from
     it (amended 2026-09-25, Brandon).
6. **Each oracle describes one stated primary build configuration.** A
   corpus's precision/recall figure is a statement about the code the
   primary configuration compiles; that configuration dominates what the
   scan sees and what TP/FP mean *within that scope*, and it must be
   written down per corpus (`data/benchmark_repos.json` alongside
   `scope_include`, and its section of `realworld-corpus-scope.md`). Today
   it is POSIX/Linux on the benchmark host for every corpus, by
   construction rather than declaration.
7. **Other configurations are other benchmarks, not label reasons.** A
   finding in an arm outside the primary configuration is still a finding
   and, when adjudicated, is still labeled as written (Decision 1) — it
   simply lies outside that oracle's denominator until the configuration
   is onboarded as its own benchmark. sel4 built for x86, arm and riscv is
   effectively three codebases in one repository and is measured as three
   oracles, the way ventoy was onboarded as the Win32 oracle rather than
   Windows code being scored under the Linux one. Whether the host compiles
   a file or an arm is therefore a corpus-*scope* question, never a row's verdict.
8. **The primary configuration guides the benchmark; it never proves
   anything.** It decides what an oracle scores (Decisions 6-7), and it
   picks among platform-specific definitions so a rule can understand the
   construct in front of it: a typedef, an enum, a macro defined
   differently per platform (Decision 3). A fact that follows only from
   that choice is not proof of safety: a width, a signedness, or a
   library's behavior beyond ISO C. That is ADR-0011 basis 4. Questions of
   reach look at every compilable configuration, not only the primary one:
   "can this be called from outside the scanned source" and "are all paths
   to it checked". The project doesn't scan every configuration, for the
   reasons above, but that doesn't exclude the others from those questions
   (Brandon, 2026-09-25).

## Consequences

- An adjudicator who finds "this only compiles under X" is looking at scope
  (Decisions 6–7), not at an FP. If X is a platform or architecture, the
  question is whether the file or arm belongs to this oracle's primary
  configuration; if it does not, the row is still labeled on the construct
  and the *scope* declaration is what needs fixing. If X is a feature or
  debug flag inside the primary configuration's build, the row is labeled
  on the construct alone.
- Two tasks follow from Decisions 6–7: state the primary build
  configuration per corpus (benchmarking_db, extending the existing scope declarations), and a
  research task for multi-configuration scanning in aurora-lint
  (cppcheck-style enumeration or a `--platform` profile per scan — name
  resolution only, per Decision 3). Onboarding a second configuration of
  an existing corpus (sel4 arm, raylib's platform backends) is the
  measurement-side path and needs no new scanner capability.
- **Why the default answer is a new corpus, not a second scan of an
  existing one** (Brandon, 2026-09-22): systematically scanning every
  compilable configuration of every pinned corpus — not just finding a
  stray off-config violation, but running, adjudicating and maintaining a
  second oracle for it — multiplies the regular benchmark run by roughly
  the number of alternate configurations that exist, which for
  platform-specific code is real and recurring cost, not a one-time setup.
  Bluntly, illustratively (not a measured split — nobody has counted
  curl's actual shared/POSIX/Windows lines): if a corpus is on the rough
  order of 80% shared code, 10% POSIX-specific and 5% Windows-specific,
  scanning the whole codebase a second time under a Windows configuration
  re-does that 80% for the sake
  of the ~5% that's actually config-specific — a lot of rework for little
  added value, and the project would rather half-support nothing than
  half-support several configurations across every existing corpus. ventoy
  is the concrete instance of the alternative: rather than double-scanning
  curl or hostap for their Windows arms, the project
  onboarded a codebase *whose primary configuration already is* the
  platform it wanted coverage for (`docs/design/realworld-corpus-scope.md`'s
  ventoy section). A new corpus chosen for the rule/platform coverage it
  adds is cheaper than a second oracle bolted onto an existing one, and is
  the default move going forward. This does not change Decision 7's answer
  for a finding that shows up incidentally outside the primary
  configuration (still labeled as written, still outside that corpus's
  denominator) — it is guidance for when a *systematic* second-configuration
  scan is worth building at all.
- The ~two dozen legacy FP rows whose basis is release-build or
  default-config reachability (sqlite `sqlite_fts5_index`, `precision_audit_*`,
  `curl_full_audit_0.4.35`, `hostap_full_audit_0.4.169`, lua
  `precision_audit_0.4.59`, mostly "inside an assert, compiled out under
  NDEBUG") go to the human-review queue or a reviewed
  consistency batch; the `validate.py` vocabulary check can flag
  that phrasing as needing a code-level basis.
- This does **not** license a rule to report across arms (Decision 4), and
  it does **not** make a preprocessor misread acceptable (ADR-0008): a rule
  that reads `#ifdef SQLITE_DEBUG` as an expression is still wrong.
- It does **not** decide whether a literal inside a `#if`
  condition is a finding — that is about what the construct *is*, not about which arm
  is live.
- Tool behaviour does not change: `suppression.rs` and `dead_regions.rs`
  already implement Decisions 2 and 3. Any proposal to add a
  `--assume-defined`/`--platform` *suppression* switch is a proposal to
  revisit this ADR, not a feature request.
