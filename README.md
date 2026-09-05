# SqC - Software Code Quality

A static analysis tool for C code compliance with [SEI CERT C Coding Standards](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard). SqC tracks 311 CERT C rules across 17 categories (307 implemented and enabled by default), with a CI/CD-ready command-line interface and an optional interactive terminal UI.

## Why CERT C

SqC targets the [SEI CERT C Coding
Standard](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard)
rather than MISRA C, and that is a deliberate fit-to-domain choice rather than
a fallback.

**CERT C is open.** The standard is public and freely implementable, so the
rules a tool enforces can be read, argued with, and checked against the
analyzer's behaviour by anyone. Every rule SqC implements cites its CERT C
entry, and the false-positive work in this repo is legible for the same
reason — you can look up what the rule actually says.

**The overlap with MISRA is strong.** The two standards address the same
defect classes for the most part; CERT C reaches further into security
(untrusted input, integer conversion, resource lifetime) while MISRA reaches
further into language-subsetting discipline.

**The remaining difference is process, not coverage.** MISRA's extra apparatus
— mandatory/required/advisory categories, language subsetting, a
certification-oriented deviation process — exists to satisfy a certification
body. SqC does not implement that apparatus, which is a statement about what
SqC is, not about who should use it: **nothing here is domain-restricted.**
If you write C for automotive, medical or aerospace, these rules apply to your
code exactly as they do to anyone else's, and SqC is usable alongside whatever
MISRA tooling your certification process requires.

Two rules from NASA JPL's Power of Ten are also implemented alongside CERT C
(`BRULE-060` no dynamic allocation after initialisation, `BRULE-065` no
excessive pointer indirection). See
[`docs/future-rulesets.rst`](docs/future-rulesets.rst) for other open
standards that could be added and why they were not needed first.

## What Makes It Different

**No build system. No compilation. No `compile_commands.json` required.** Point
SqC at a directory of C source and it analyses it. It parses with tree-sitter
rather than driving a compiler, so it needs neither your toolchain, your
headers, your defines, nor a working build — which means it runs on code you
*cannot* build: a partial checkout, a vendored tree, a CI job with no
cross-compiler installed, or a file an AI just generated. It will happily use
`compile_commands.json` and `-I`/`-D` flags when given them, for better
cross-file context; it just does not depend on them.

That is the trade it makes. Without a preprocessor, SqC reasons about source
as written, which is why it has its own macro-expansion engine and why the
false-positive work in this repo is as substantial as the rule work.

**Imperfect on purpose, and measured about it.** SqC reports every rule
violation as written rather than guessing which ones you meant, so it produces
false positives — the precision and recall above are measured against a
hand-adjudicated oracle, not asserted. What makes that workable is that the
noise judgement is yours: per-project rule manifests
([configuration](docs/configuration.rst)), inline and file-scoped
[suppression](docs/suppression.rst), and severity thresholds, so you tune it
to your codebase instead of accepting one global verdict. That same property
is what makes it cheap to drop into a CI gate or an AI-assisted development
loop as a repeated check.

**Scope: C.** SqC analyses `.c` and `.h` against CERT C. It is not a C++
checker — it recognises C++ constructs only well enough to avoid reporting
nonsense on a C++ header it encounters.

## Key Features

- **307 CERT C rules** implemented and enabled by default (311 tracked; see [Configuration](docs/configuration.rst) for the 4 tracked but not yet implemented) across 17 categories (API, ARR, CON, DCL, ENV, ERR, EXP, FIO, FLP, INT, MEM, MSC, POS, PRE, SIG, STR, WIN)
- **Optional interactive terminal UI** for browsing and managing violations (build with `--features tui`)
- **Multiple export formats**: CSV, XLSX, JSON, SARIF 2.1.0
- **CI/CD ready**: exit codes, severity thresholds, diff-only mode, SARIF output
- **Cross-file analysis**: pre-scans directories for function definitions to reduce false positives
- **Fast**: tree-sitter based parsing with control-flow graphs and inter-procedural reasoning

## How Well Does It Work?

Measured, not asserted. Two benchmarks, both with published methodology.

<!-- BENCH:HIGHLIGHTS:START -->
| Metric | Value |
|--------|-------|
| **Juliet Precision** | 87.1% (v0.4.321) |
| **Juliet CWEs Scanned** | 75 (fast mode, CWE-matched rules) |
| **100% Precision CWEs** | 43 (zero false positives, with real detections) |
| **Per-File Detection** | 38.0% (19,073 / 50,256 files) |
| **Real-World Precision / Recall** | 24.2% / 93.9% (v0.4.325, run #226, 89.8% label coverage) |
| **Real-World Projects** | curl, hostap, libcrc, lua, mosquitto, pure-ftpd, raylib, seL4, sqlite |
| **Basis** | `distinct/scored-projects/in_scope` (definitions `1`) |
<!-- BENCH:HIGHLIGHTS:END -->

Regenerate this table with `python -m bench render-docs --realworld-run RUN`
after a version bump or a fresh delta-adjudication.

**[NIST Juliet](https://samate.nist.gov/SARD/test-suites/112) is the headline
number**, because its defects are planted and labelled by the suite itself —
so a true/false positive is a fact, not a judgement. 75 CWEs, 87.1% of SqC's
findings are true positives, and 43 CWEs come back with zero false positives
and real detections.

**The 9 real-world codebases are a reference point**, and a harder one: curl,
hostap, libcrc, lua, mosquitto, pure-ftpd, raylib, seL4 and sqlite, scanned at
pinned commits with findings hand-adjudicated into a ground-truth oracle. Real
code is messier than a test suite and the precision figure reflects that.

> **Recall is measured against *known* true positives**, not against all
> defects present. No exhaustive false-negative hunt sits behind it — past
> audits scoped their searches to specific bug categories — so true recall is
> unknown and lower than the figure above.

How both numbers are produced, what they exclude, and why the Juliet
true-positive rate is not the whole story:
[`docs/testing-methodology.rst`](docs/testing-methodology.rst) and
[`docs/juliet-history.rst`](docs/juliet-history.rst).

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

The default manifest (`rules_templates/rules-all.toml`) enables 307 of the 311 tracked rules; the other 4 are tracked but not yet implemented (2 parked on incomplete upstream CERT content) — see [Configuration](docs/configuration.rst). See the [Developer Guide](docs/index.rst) for the manifest format.

## Quick CI Example

```bash
# CI pipeline: diff-only, Medium+ reporting, fail on High, SARIF export
sqc . --diff --min-severity Medium --fail-on-severity High --export results.sarif
```

Exit codes: `0` = success, `1` = violations found (with `--fail-on-*`), `2` = error.

Ready-to-use workflow examples for [GitHub Actions and Azure DevOps](docs/cicd-integration.rst) are in the Developer Guide.

## Alternatives

Honest version: on the narrow set of defect classes clang-tidy checks, **clang-tidy
is more precise than SqC** — 99.2% to 81.7% on the 15 Juliet CWEs it covers, and it
finds more true positives there too. It gets that by compiling your code.

SqC's case is breadth and reach, not beating clang-tidy at its fifteen:

| | CERT C coverage | Juliet CWEs | Needs a build? |
|---|---|---:|---|
| **SqC** | **311 rules implemented**, 17 categories | **75** | **No** |
| clang-tidy | ~20 `cert-*` checks | 15 | Yes |
| cppcheck | ~20 (addon) | 15 | No |
| [Infer](https://fbinfer.com/) | bug-type indexed | 10 | Yes |
| [Frama-C](https://frama-c.com/) | not rule-indexed | 6 | Yes |

cppcheck is the useful control, since it also runs without a build: on the same
15 CWEs it scores 36.7% against SqC's 81.7%, and takes roughly ten times as long
on real code.

Per-CWE precision for all five tools, the speed measurements, and what the
build-vs-no-build trade actually costs:
**[`docs/tool-comparison.rst`](docs/tool-comparison.rst)**.

## Documentation

For advanced usage, CI/CD integration details, interactive UI reference, testing methodology, and contributing:

**[Developer Guide](docs/index.rst)** - comprehensive reference for all features and project internals.

| File | Contents |
|------|----------|
| [Developer Guide](docs/index.rst) | Advanced usage, CI/CD, UI reference, testing, architecture, contributing |
| [`docs/juliet-history.rst`](docs/juliet-history.rst) | Juliet benchmark data: TP/FP history, per-CWE results |
| [`docs/future-rulesets.rst`](docs/future-rulesets.rst) | Why CERT C is the base standard, and which open standards could be added |
| [`docs/tool-comparison.rst`](docs/tool-comparison.rst) | SqC vs cppcheck, clang-tidy, Frama-C, Infer — per-CWE precision, speed, build requirements |
| [`docs/testing-methodology.rst`](docs/testing-methodology.rst) | How the benchmark numbers are produced, and what they exclude |
| [CONTRIBUTORS.md](CONTRIBUTORS.md) | Who built this |

## AI Assistance

This project was developed with assistance from [Claude](https://claude.ai) (Anthropic). Claude was used throughout the development process for code generation, rule implementation, analysis, and documentation.

Claude is deliberately not listed as a commit co-author — the acknowledgement
belongs once, here, rather than repeated across several thousand commit
messages. See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the people involved.

## License

Apache-2.0. [LICENSE](LICENSE) is the unmodified Apache-2.0 text; copyright and
attribution live in [NOTICE](NOTICE), per Apache-2.0 section 4(d).
