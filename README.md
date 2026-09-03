# SqC - Software Code Quality

A static analysis tool for C code compliance with [SEI CERT C Coding Standards](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard). SqC checks 307 rules across 17 categories, with a CI/CD-ready command-line interface and an optional interactive terminal UI.

## Key Features

- **307 CERT C rules** enabled by default (311 implemented) across 17 categories (API, ARR, CON, DCL, ENV, ERR, EXP, FIO, FLP, INT, MEM, MSC, POS, PRE, SIG, STR, WIN)
- **Optional interactive terminal UI** for browsing and managing violations (build with `--features tui`)
- **Multiple export formats**: CSV, XLSX, JSON, SARIF 2.1.0
- **CI/CD ready**: exit codes, severity thresholds, diff-only mode, SARIF output
- **Cross-file analysis**: pre-scans directories for function definitions to reduce false positives
- **Fast**: tree-sitter based parsing with control-flow graphs and inter-procedural reasoning

## Benchmark Highlights

<!-- BENCH:HIGHLIGHTS:START -->
| Metric | Value |
|--------|-------|
| **Juliet TP Rate** | 87.1% (v0.4.321) |
| **Juliet CWEs Scanned** | 79 (fast mode, CWE-matched rules) |
| **100% Precision CWEs** | 43 (zero false positives, with real detections) |
| **Per-File Detection** | 38.0% (19,073 / 50,256 files) |
| **Real-World Precision / Recall** | 24.2% / 93.9% (v0.4.325, run #226, 89.8% label coverage) |
| **Real-World Projects** | curl, hostap, libcrc, lua, mosquitto, pure-ftpd, raylib, seL4, sqlite |
| **Basis** | `distinct/scored-projects/in_scope` (definitions `1`) |
<!-- BENCH:HIGHLIGHTS:END -->

Regenerate this table with `python -m bench render-docs --realworld-run RUN`
(see `bench/render_docs.py`) after a version bump or a fresh delta-adjudication.

Benchmarked against the [NIST Juliet Test Suite v1.3](https://samate.nist.gov/SARD/test-suites/112) and 9 open-source C codebases — see the Benchmark Highlights table above and [`docs/juliet-history.rst`](docs/juliet-history.rst) for the full round-by-round Juliet history; the complete record for both is `sqc_bench` Postgres (see `benchmarking_db`).

> **Note**: the real-world precision/recall figure is pinned to the last
> validly-adjudicated run, and its unlabeled remainder is mostly
> `pure-ftpd`/`seL4`'s deliberately-unsampled 90%. Rule-logic commits landed
> since that run aren't reflected; a current figure requires
> delta-adjudicating the newer unlabeled findings first (see CLAUDE.md's
> delta-adjudication protocol) before it can be safely republished.
>
> **Recall is measured against *known* true positives**, not against all
> defects present. There is no exhaustive false-negative hunt behind the
> recall figure — past audits scoped their FN searches to specific bug
> categories. True recall is unknown and lower.
>
> This note deliberately restates no number from the table above. It used to
> carry the run's version, its unlabeled percentage and the recall figure, and
> when the table was refreshed onto the canonical basis those three did not
> move with it: the table said 93.9% recall and 89.8% coverage while this
> paragraph still said 93.7% and 11.8% unlabeled, eight lines apart, for the
> same run. A caveat's job is to say what the number does not cover, which it
> can do without repeating the number.

### Juliet TP rate is not the ceiling signal — the flaw-hit rate is

**Juliet TP Rate** above is the share of sqc's Juliet findings that are true
positives. It says how clean the output is, not how much of the suite's
planted defect set sqc actually locates. That second question is the
**flaw-hit rate** — the fraction of Juliet's known flaw lines sqc lands a
finding on — and it moves independently: as of v0.4.321 it was 12.9%
(17,100 of 132,406 flaw lines), essentially flat for weeks while the TP
rate above was moving. Quoting only the TP rate overstates the tool; this
paragraph is not auto-refreshed with the table above (deliberately, per the
lesson in the note above this section — see `python -m bench compare` or
`sqc_bench` Postgres for the current figure), so treat the number here as
illustrative of the *gap*, not as a current measurement.

Per-file detection rate (in the table above) sits between the two: sqc
flags something in over a third of flawed files, but lands on the specific
planted flaw line in roughly an eighth of cases. When judging headroom, the
flaw-hit rate is the honest signal to watch for movement, not the TP rate.

Juliet also exercises only part of the rule suite — 127 rules have any
Juliet true positive, out of 311 implemented. See "Rule-suite coverage"
below for what that leaves unmeasured, and
[`docs/juliet-history.rst`](docs/juliet-history.rst) for the full
round-by-round version history behind the table above.

### Rule-suite coverage

Precision and recall above are aggregates over the rules that actually fire
on the benchmark corpora. They say nothing about the rest of the suite, and
the rest of the suite is substantial (measured 2026-09-02, run #226):

| | Rules |
|---|---:|
| Implemented | **311** (307 enabled by default) |
| Have true-positive evidence somewhere | **186** — 127 from Juliet, 144 from real-world TP/FN labels |
| **No true-positive evidence anywhere** | **125 (40%)** |
| &nbsp;&nbsp;· fire on the corpus, but have only ever produced FPs | 65 |
| &nbsp;&nbsp;· never fire on the nine projects at all | 60 |

A rule in that last group has never been shown to detect anything real —
but that is usually a statement about the corpora, not about the rule. The
nine real-world projects are mature, warning-clean C, which is the opposite
population from sqc's nominal use case (newer, in-progress, possibly
non-compiling code wired into CI/CD early — sqc needs no build system, which
is the whole point). A rule whose defect cannot survive review in released
software is structurally incapable of scoring a true positive there. The 60
never-firing rules include `WIN02-C` and `WIN30-C` — Windows rules against
Linux-only corpora, categorically inapplicable rather than broken (rule
applicability is the user's lever, by design: manifest scoping and
suppression exist so the user decides which rules apply to their code,
rather than detection logic silently deciding for them).

**Worked example of why a per-rule 0.0% is sometimes a corpus artifact, not
a rule defect** (task 692): `DCL31-C` shows 364 findings, 324 labeled, 0
TP — 0.0% precision. That figure measures sqc's header reachability, not
the rule's quality. `mosquitto` alone goes from 1,365 `DCL31-C` findings
with no `-I` to 0 with `-I /usr/include`. The rule guards a genuine defect —
under C89 an implicit declaration makes the compiler assume `int f()`, so
the return type is misread, no argument checking happens, and a returned
pointer is truncated on LP64; C99 removed implicit declarations and C23
makes them an error — on code this corpus does not contain. Quoting that
number as a rule-quality measure is a category error.

The material to close this gap already exists in the repo: **1,959
must-detect** fixtures (`src/rules/cert_c/*/*/tests/fail/*.c`, across 306
rules) and **1,568 must-not-detect** fixtures
(`src/rules/cert_c/*/*/tests/pass/*.c`, across 308 rules), labeled by
construction — 309 distinct rules carry at least one. 121 of the 125
unvalidated rules already have a must-detect fixture — only `ENV04-C`,
`FLP01-C`, `MSC18-C` and `MSC25-C` have none.
Today those fixtures run only as pass/fail unit tests and feed no measured
metric, so a rule can be fully exercised by tests and still read as having
no detection evidence. Scoring them as a third benchmark tier is tracked as
tasks 693–696.

### Cross-tool comparison

sqc implements 311 CERT C rules against cppcheck's and clang-tidy's ~20
checks each; the comparison below is about coverage shape, not a
precision/recall claim (see Benchmark Highlights above for that). Counts
are illustrative, from before the Postgres migration — not an official,
currently-cited figure; query `sqc_bench` for current numbers.

| Bug Class | sqc Rule | clang-tidy Check | cppcheck Check | Notes |
|-----------|----------|------------------|----------------|-------|
| Unchecked return value | ERR33-C | `cert-err33-c` | — | sqc 5x count (broader function list) |
| Unsafe numeric conversion | ERR34-C | `cert-err34-c` | — | sqc finds MORE (126 vs 33 on mosquitto) |
| Null pointer dereference | EXP34-C | `NullDereference` | `nullPointer` | sqc 4,300:1 ratio (see below) |
| Uninitialized variable | EXP33-C | — | `uninitvar` | Different sub-patterns of CWE-457 |
| String/buffer safety | STR rules | `DeprecatedOrUnsafe...` | — | Different scope |

**EXP34-C, a known high-FP-rate case on real code:**

| Project | sqc EXP34-C | cppcheck nullPointer (error) | cppcheck nullPointerRedundantCheck |
|---------|------------:|-----------------------------:|-----------------------------------:|
| mosquitto | 8,657 | 2 | 0 |
| curl | 22,350 | 0 | 177 |

sqc uses CFG-based null state dataflow with inter-procedural call-site
propagation; cppcheck uses data-flow analysis and only fires when it can
prove a null-dereference path. The gap is narrowing but sqc still flags
more conservatively.

**What sqc uniquely covers**, with no cppcheck/clang-tidy equivalent:
`POS49-C` (POSIX misuse), `INT32-C`/`INT30-C` (signed/unsigned overflow,
which competitors skip), `MEM30-C`/`MEM31-C` (use-after-free, memory
management), `API00-C`/`API02-C`, and 270+ additional rules across integer,
floating-point, environment, concurrency and POSIX categories.

## Installation

```bash
git clone https://github.com/brandon-arrendondo/tools_sqc
cd tools_sqc
cargo build --release
```

The binary is at `target/release/sqc`. Requires Rust 2021 edition (stable toolchain).

## Getting Started

### Analyze a project

```bash
# Analyze a directory (prints violations to stdout)
sqc /path/to/project

# With cross-file context (reduces false positives)
sqc /path/to/project -d /path/to/project
```

### Interactive mode

The terminal UI is disabled by default (CLI + CI/CD is the primary use case). Build with the `tui` feature to enable it:

```bash
cargo build --release --features tui
sqc /path/to/project --interactive
```

### Export results

```bash
sqc /path/to/project --export results.json
sqc /path/to/project --export results.sarif
sqc /path/to/project --export results.csv
```

### Filter by severity

```bash
# Only report Medium and above
sqc /path/to/project --min-severity Medium

# Fail if any High+ violations found (for CI)
sqc /path/to/project --fail-on-severity High
```

### Diff mode (only changed files)

```bash
sqc /path/to/repo --diff
```

### Exclude files from a scan

```bash
# Drop vendored code, test harnesses, or generated/amalgamated files
sqc /path/to/repo --exclude "tests/**" --exclude "vendor/**" --exclude "**/onelua.c"
```

`--exclude` is the only flag that removes files from the scan — `-d` only adds
directories for cross-file context and never restricts what gets analyzed.

### Use a custom rules manifest

```bash
sqc /path/to/project --manifest my-rules.toml
```

The default manifest (`rules_templates/rules-all.toml`) enables 307 of the 311 implemented rules. See the [Developer Guide](docs/index.rst) for the manifest format.

## Quick CI Example

```bash
# CI pipeline: diff-only, Medium+ reporting, fail on High, SARIF export
sqc . --diff --min-severity Medium --fail-on-severity High --export results.sarif
```

Exit codes: `0` = success, `1` = violations found (with `--fail-on-*`), `2` = error.

Ready-to-use workflow examples for [GitHub Actions and Azure DevOps](docs/cicd-integration.rst) are in the Developer Guide.

## Documentation

For advanced usage, CI/CD integration details, interactive UI reference, testing methodology, and contributing:

**[Developer Guide](docs/index.rst)** - comprehensive reference for all features and project internals.

| File | Contents |
|------|----------|
| [Developer Guide](docs/index.rst) | Advanced usage, CI/CD, UI reference, testing, architecture, contributing |
| [`docs/juliet-history.rst`](docs/juliet-history.rst) | Juliet benchmark data: TP/FP history, per-CWE results |

## AI Assistance

This project was developed with assistance from [Claude](https://claude.ai) (Anthropic). Claude was used throughout the development process for code generation, rule implementation, analysis, and documentation.

## License

See [LICENSE](LICENSE).
