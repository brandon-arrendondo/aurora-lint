# Scoping: Project-Relevance Gating (task 216)

**Status:** v1 IMPLEMENTED (2026-07-08, v0.4.86). `src/analyze/relevance.rs`
+ the `--detect-relevance`/`--write-manifest` CLI flags ship exactly the v1
scope below: CON*/WIN* auto-gating only. **Check `todo-sqlite-cli show 216`
for the latest status, not this header** — v1/v2 split and the design
narrative below predate implementation and are not kept in sync with it.
C11/Annex-K auto-gating (detection-only today, not auto-disabled) is the
open v2 scope. User-facing docs: `docs/cli-usage.rst` ("Project-Relevance
Detection").
**Driver:** Task 151 established that per-project rule applicability is
currently curated *by hand* in `conf/realworld/<project>-rules.toml` — each
file hand-disables categorically-inapplicable rule classes and documents why
in `[metadata].description` prose. That works for 7 benchmark codebases we
read closely, but doesn't scale to an arbitrary user codebase running `sqc`
for the first time with no tailored manifest.

---

## 1. Problem statement

`rules_templates/rules-all.toml` enables all 285 rules unconditionally. Several
whole rule *classes* only apply under conditions knowable from the source
itself:

- **WIN\* (6 rules)**: only meaningful if the code touches the Win32 API.
  A POSIX-only codebase (libcrc, sqlite core) gets zero true positives and
  either zero findings (harmless) or, if a rule's heuristic is loose, noise
  (`conf/realworld/*-rules.toml` doesn't currently disable WIN* anywhere,
  which is correct evidence they're currently zero-signal-zero-noise, not
  proof the class is safe to leave "on" as a default UX choice for a
  brand-new embedded/POSIX project).
- **CON0x/CON3x (23 rules)**: threading/concurrency rules. A single-threaded
  program (no `pthread.h`, `threads.h`, `_Atomic`, `mtx_*`/`atomic_*` calls)
  cannot have most of these defects. Per memory `fn-focus-vs-perproject-disable`
  this is explicitly *not* what the realworld configs do today — they leave
  CON* enabled everywhere including single-threaded libcrc — so this would be
  a genuinely new capability, not a reproduction of an existing manual step.
- **C11/Annex-K-specific rules**: rules keyed on `<stdatomic.h>`, `<threads.h>`,
  `_Generic`, or the `*_s` bounds-checked family only fire on constructs a
  strict-C99 codebase never contains. Grep today
  (`grep -rl 'stdatomic\|threads.h\|_Generic\|_s(' src/rules/cert_c`) shows
  this logic living inside CON02/03/07/31/32/33-C, ENV31-C, API04/07-C,
  PRE04/30/31-C, EXP44-C, FIO11-C — i.e. it's entangled with rules that also
  fire on plain C99 patterns, so this dimension is a **finer-grained internal
  gate on rule sub-behavior**, not a whole-rule disable like WIN*/CON*.

This is about **relevance**, not FP-suppression: the class is inapplicable to
what the codebase *is*, independent of how well-tuned the analyzer is. Every
rule that isn't categorically gated keeps measuring its true precision in the
`ground_truth` oracle — this must not become a backdoor to hide real FPs
(memory `fn-focus-vs-perproject-disable` is the hard boundary here).

---

## 2. Where this plugs into the existing pipeline

`sqc` already does one pre-pass over the whole tree before rule evaluation
starts: `prescan::prescan_directories` (`src/analyze/prescan.rs:141`), which
walks every `.c`/`.h` file once, populating `ProjectContext`
(`src/analyze/context.rs`) — function summaries, macro tables, global state,
etc. Rule gating is a separate, later stage: `RuleManifest::load` in
`src/main.rs:215` reads a TOML file and `enabled_rules()` filters the rule set
before any file is scanned (`src/manifest/mod.rs:113`).

Project-relevance detection is naturally a **second lightweight prescan
signal**, not a new phase: cheap, single-pass, headers-and-includes-only
(no AST-heavy work), producing a small `ProjectProfile` that answers yes/no
per dimension. It sits between "user picked a manifest" and "rules actually
run": `effective_manifest = gate(loaded_manifest, project_profile)`.

---

## 3. Detection dimensions and signals

| Dimension | Signal (cheap, prescan-compatible) | Rules gated | Confidence bar |
|---|---|---|---|
| Threading/concurrency | Any `#include <pthread.h>\|<threads.h>`, or identifier match `pthread_*\|mtx_*\|cnd_*\|thrd_*\|atomic_*\|_Atomic` anywhere in the corpus (including headers pulled in via `-I`) | CON0x, CON3x (23 rules) | High — POSIX threads and C11 threads are the only two APIs CERT-C's CON rules target; absence of both across the *whole* scanned corpus is a strong negative signal |
| Windows platform | Any `#include <windows.h>` (and common variants `winsock2.h`, `windef.h`), or identifiers `Win32`, `HANDLE`, `LPCSTR` at file scope | WIN00–04-C, WIN30-C (6 rules) | High — same logic, narrower API surface |
| C11/Annex-K availability | `lang_parsing_substrate::detect_min_c_standard` (added v0.3.0, task 22 upstream) aggregated as a project-wide max across every scanned file's AST — see §3.1 — **plus** the existing include/identifier scan for signals the substrate deliberately doesn't cover (`<threads.h>`/`<stdatomic.h>` includes with no C11 *syntax* yet used, and Annex-K `*_s(` calls, which the substrate excludes because `_Bool`/`_Complex`/`typeof`/`_BitInt` aren't distinctly tokenized and Annex-K functions aren't a syntax construct at all) | *Sub-behavior* inside CON02/03/07/31/32/33-C, ENV31-C, API04/07-C, PRE04/30/31-C, EXP44-C, FIO11-C — **not a whole-rule disable** | Now High for the syntax-marker half (upstream, tested, syntax-only — no more hand-rolled `_Generic(` text matching); still Medium overall because the include/Annex-K half stays a bespoke scan and because gating is finer-grained than a whole-rule toggle (see open question in §5) |

### 3.1 Using `detect_min_c_standard`

`lang_parsing_substrate` v0.3.0 ships `detect_min_c_standard(tree, source) ->
Option<CStandard>` (`CStandard::{C99, C11, C23}`), a **lower bound**: `None`
means "consistent with C89", i.e. no C99+ marker was seen. It already
recognizes the exact AST shapes this design's C11 dimension needs —
`_Generic`, `_Atomic`/`_Noreturn` qualifiers, `_Alignas`/`_Alignof`,
`_Static_assert` — with the false-positive traps (GNU pre-standard spellings,
macro-guarded-but-still-counted markers) already handled and tested upstream,
so sqc no longer needs to hand-roll that text/node matching itself. Project-
level aggregation is a straightforward fold: run `detect_min_c_standard` once
per file during the existing prescan tree-walk (the tree is already parsed
there for other prescan passes, so this is a marginal per-file call, not a
second parse) and keep the max `CStandard` seen across the whole corpus. If
the corpus-wide max stays `<= C99` (i.e. never reaches `C11`), that is strong,
upstream-vetted evidence the C11-only branches inside the rules listed above
are unreachable — a much stronger basis than the bespoke `_Generic(` grep
this doc originally proposed. Note the caveat inherited from upstream: this is
syntax-only, not preprocessor-aware, so a marker inside a `#if
__STDC_VERSION__` branch that's never actually compiled at that standard still
counts (documented upstream as a known limitation, not a bug — same
conservative-bias direction this design already requires in §5, so it composes
cleanly rather than needing a workaround).

This narrows, but does not close, the remaining gap: `<threads.h>`/
`<stdatomic.h>` *header inclusion* without any C11 syntax actually appearing
yet, and Annex-K `*_s(` bounds-checked function calls, are not syntax markers
at all (the substrate's own doc explicitly excludes `_Bool`/`_Complex`/
`typeof`/`_BitInt`/Annex-K from its scope for the same "no distinct grammar
node" reason). Those two signals still need the include/identifier scan
originally proposed in this section, run alongside `detect_min_c_standard`
rather than instead of it.

All three dimensions reduce to: **header includes present in the scanned
corpus** ∪ **identifier/call-name matches against a fixed allowlist**, no
build-flag or `compile_commands.json` parsing needed for v1. That keeps this
in the same cost class as the existing macro-constant prescan pass (one file
read + one grep-equivalent identifier walk per file, no extra parses).

The corpus considered is deliberately the **union of everything the prescan
already visits**: input path + `-d` directories + anything discoverable via
`-I` resolution (`resolve_includes`, `prescan.rs:3148`), because a codebase
that `#include`s a vendored `pthread.h`-touching header from a dependency
directory is still a threaded codebase even if the primary target files don't
call `pthread_create` directly.

---

## 4. Output: generated manifest override, not an in-process mask

Two options were named in the task:

1. **Generated `rules-<project>.toml` override** — auditable, diffable,
   matches the existing manual workflow (`conf/realworld/*-rules.toml`) byte
   for byte; a user can inspect exactly what got turned off and why, and hand
   -edit the result afterward.
2. **In-process relevance mask** applied silently at scan time — zero-config,
   but findings become harder to reproduce (`sqc . --manifest X` on the same
   manifest could report a different effective rule set from one repo to the
   next with no artifact showing why).

**Recommendation: option 1.** It composes with the manifest system that
already exists rather than adding a second, invisible gating mechanism next to
it, and it matches how `conf/realworld/*-rules.toml` documents rationale in
`[metadata].description` — the generated file should populate that same field
with the detected signal per disabled rule (e.g. `enabled = false  # auto:
no pthread/threads.h/atomic usage detected in corpus`), so a human reviewing
the generated manifest sees the *evidence*, not just the verdict. This also
gives a natural CLI shape:

```
sqc --detect-relevance /path/to/project --base-manifest rules_templates/rules-all.toml \
    --write-manifest generated-rules.toml
# then:
sqc /path/to/project --manifest generated-rules.toml
```

i.e. a separate, explicit generation step (not an implicit flag on every scan)
— this matches CLAUDE.md's benchmark discipline of "the manifest a run used is
a durable, inspectable artifact" and avoids surprising a CI pipeline with a
rule set that silently changes as the codebase evolves.

---

## 5. Guardrails and open questions

- **Conservative bias is mandatory**: a false "irrelevant" verdict is a
  silent false negative with no measurement — unlike a rule's ordinary FP,
  which shows up in the `ground_truth` oracle, a wrongly-gated-off rule
  produces *no finding at all* to audit. Each dimension's signal must be an
  "any evidence found ⇒ stay enabled" check, never a heuristic score. When in
  doubt (e.g., a `-I` path couldn't be resolved, or scan was file-scoped
  rather than whole-project), the tool should refuse to gate that dimension
  rather than guess — surfaced as `# unresolved: <reason>` in the generated
  manifest, rule left enabled.
- **C11/Annex-K is not whole-rule-shaped.** Unlike WIN*/CON*, the rules it
  touches (CON02/03/07/31/32/33-C, ENV31-C, API04/07-C, PRE04/30/31-C,
  EXP44-C, FIO11-C) mix C11-specific and plain-C99 logic in the same rule
  file. `detect_min_c_standard` (§3.1) makes the *detection* half solid, but
  it doesn't remove the need for a per-rule audit of which *code path* inside
  each rule is actually C11-gated, before deciding whether a manifest-level
  toggle (`parameters` map on `RuleConfig`, which already exists and is
  currently unused by any shipped rule) is the right knob, versus leaving
  this dimension as "detect and report, don't auto-gate yet." **Recommend
  still scoping the auto-*gating* of C11/Annex-K out of v1** and shipping
  WIN*/CON* first (clean whole-rule disables, no per-rule surgery), but
  pulling the *detection* itself (project-wide `detect_min_c_standard`
  aggregation, surfaced in the generated manifest's rationale comments as
  `# detected: corpus max standard = C99` even on rules left enabled) into
  v1 as a reporting-only signal — it's now cheap enough (one upstream call
  per already-parsed file) that there's no reason to wait for the per-rule
  audit to at least show the evidence.
- **Ties to task 194 (C99 corpus validation)**: the "strict C99 target"
  signal doubles as the applicability check that task 194's synthetic
  conformance corpus would need anyway. `detect_min_c_standard` now defines
  "C11 construct present" precisely (and upstream-tested) for the syntax
  half, so task 194 and this task can share that definition directly instead
  of each inventing its own marker list — only the include/Annex-K half
  still needs a bespoke decision.
- **Interaction with existing per-project manifests**: `conf/realworld/*.toml`
  should NOT be regenerated/overwritten by this tool once it exists — those
  are hand-adjudicated and carry oracle-labelled history. This is a
  bootstrapping tool for *new* codebases without a tailored manifest yet
  (matching the README's existing fallback: "a codebase with no entry here
  falls back to the shared benchmark base").

---

## 6. Proposed v1 scope

1. New module `src/analyze/relevance.rs`: `ProjectProfile { has_threading:
   bool, has_windows: bool, max_c_standard: Option<lang_parsing_substrate::CStandard> }`
   (C11/Annex-K auto-*gating* deferred per §5, but `max_c_standard` detection
   ships in v1 as a reporting-only field — folded via
   `lang_parsing_substrate::detect_min_c_standard` over each already-parsed
   file's tree during the same walk) plus one `detect(files: &[PathBuf]) ->
   ProjectProfile` walk reusing the existing file-discovery/include-resolution
   code from `prescan.rs` rather than a second directory walk. Requires
   bumping the `lang-parsing-substrate` dependency in `Cargo.toml` from
   `0.1.11` to `0.3.0`.
2. New CLI subcommand/flag pair (`--detect-relevance` + `--write-manifest`,
   see §4) in `src/main.rs`, gated so it's a distinct, explicit action from a
   normal scan — never runs implicitly.
3. Generator: take a base `RuleManifest`, clone it, for each WIN*/CON* rule ID
   whose class the profile says is absent, set `enabled = false` and write a
   `# auto: ...` rationale into that rule's `description` (or a new
   `RuleConfig.auto_rationale: Option<String>` field, TBD during
   implementation — reusing `description` risks colliding with a rule's own
   doc-string default).
4. Tests: fixture corpora (a POSIX-threaded stub, a single-threaded stub, a
   Win32 stub) asserting the right rule IDs get disabled/kept, mirroring the
   test style already used for prescan (`.c` fixtures, not embedded strings,
   per `CLAUDE.md`'s "no inline test C code in rule files" — this module
   isn't a rule file so embedded fixtures here are fine, matching
   `prescan.rs`'s existing test style).
5. Explicitly out of scope for v1: C11/Annex-K sub-rule gating (§5),
   `compile_commands.json`/build-flag signals, any change to the existing
   `conf/realworld/*-rules.toml` files.

Once this lands, task 216 stays open for a v2 that revisits C11/Annex-K after
task 194 defines the C99-conformance detection list precisely.
