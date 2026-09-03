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
<!-- BENCH:HIGHLIGHTS:END -->

Regenerate this table with `python -m bench render-docs --realworld-run RUN`
(see `bench/render_docs.py`) after a version bump or a fresh delta-adjudication.

Benchmarked against the [NIST Juliet Test Suite v1.3](https://samate.nist.gov/SARD/test-suites/112) and 9 open-source C codebases. See [JULIET_RESULTS.md](JULIET_RESULTS.md) and [REALWORLD_RESULTS.md](REALWORLD_RESULTS.md) for details.

> **Note**: the real-world precision/recall figure is pinned to the last
> validly-adjudicated run (v0.4.325, run #226 — 11.8% of its findings are
> still unlabeled, mostly `pure-ftpd`/`seL4`'s deliberately-unsampled 90%;
> see REALWORLD_RESULTS.md). Rule-logic commits landed since v0.4.325 aren't
> reflected here; a current figure requires delta-adjudicating the newer
> unlabeled findings first (see CLAUDE.md's delta-adjudication protocol)
> before it can be safely republished.
>
> **Recall is measured against *known* true positives**, not against all
> defects present. There is no exhaustive false-negative hunt behind the
> 93.7% — past audits scoped their FN searches to specific bug categories.
> True recall is unknown and lower.

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
Linux-only corpora, categorically inapplicable rather than broken. See
[REALWORLD_RESULTS.md](REALWORLD_RESULTS.md#what-this-corpus-can-and-cannot-measure)
for the `DCL31-C` worked example of why a per-rule 0.0% here is a category
error.

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
| [JULIET_RESULTS.md](JULIET_RESULTS.md) | Juliet benchmark data: TP/FP history, per-CWE results |
| [REALWORLD_RESULTS.md](REALWORLD_RESULTS.md) | Real-world results: sqc vs cppcheck vs clang-tidy |

## AI Assistance

This project was developed with assistance from [Claude](https://claude.ai) (Anthropic). Claude was used throughout the development process for code generation, rule implementation, analysis, and documentation.

## License

See [LICENSE](LICENSE).
