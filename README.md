# aurora-lint

[![CI](https://github.com/brandon-arrendondo/aurora-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/brandon-arrendondo/aurora-lint/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/brandon-arrendondo/aurora-lint)](https://github.com/brandon-arrendondo/aurora-lint/releases/latest)
[![License](https://img.shields.io/github/license/brandon-arrendondo/aurora-lint)](LICENSE)

A static analysis tool for C code compliance with [SEI CERT C Coding Standards](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard). aurora-lint tracks 311 CERT C rules across 17 categories (307 implemented and enabled by default), with a CI/CD-ready command-line interface and an optional interactive terminal UI.

## Does It Find Real Bugs?

Yes, in shipping software. Audits of SQLite, hostap (hostapd +
wpa_supplicant), and raylib have produced 30 disclosed defects, reported to
each project's maintainers — **30 of 30 confirmed and fixed upstream**: the
SQLite team fixed all nine, most the same day they were filed; hostap's
Jouni Malinen fixed all eighteen — eight from the first disclosure within
two weeks, ten more from a follow-up disclosure the very next day; raylib's
three were merged the same day they were opened.
Defect-by-defect detail, including drafts and disclosures still in flight,
is tracked privately until every referenced item has landed upstream, rather
than kept as an in-repo record.

All 30 came out of the same file-at-a-time adjudication audit behind the
real-world precision figure below, but they are not all evidence for the
same thing. Fourteen are **tool-found**: aurora-lint emitted the finding and
adjudication confirmed it. Twelve are **audit-found**: the adjudicator,
reading the whole of a file the tool's findings had led it to, spotted a
defect no rule flagged. The remaining four (raylib's three and one SQLite
item) are not attributed by origin in the working record. The fourteen
are evidence for the rule set; the rest are evidence for the audit process
built around it — read "30 of 30" as the second claim, not the first.
Methodology: [`docs/testing-methodology.rst`](docs/testing-methodology.rst).

## Why CERT C

aurora-lint targets the [SEI CERT C Coding
Standard](https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard)
rather than MISRA C, and that is a deliberate fit-to-domain choice rather than
a fallback.

**CERT C is open.** The standard is public and freely implementable, so the
rules a tool enforces can be read, argued with, and checked against the
analyzer's behavior by anyone. Every rule aurora-lint implements cites its CERT C
entry, and the false-positive work in this repo is legible for the same
reason — you can look up what the rule actually says.

**The overlap with MISRA is strong.** The two standards address the same
defect classes for the most part; CERT C reaches further into security
(untrusted input, integer conversion, resource lifetime) while MISRA reaches
further into language-subsetting discipline.

**The remaining difference is process, not coverage.** MISRA's extra apparatus
— mandatory/required/advisory categories, language subsetting, a
certification-oriented deviation process — exists to satisfy a certification
body. aurora-lint does not implement that apparatus, which is a statement about what
aurora-lint is, not about who should use it: **nothing here is domain-restricted.**
If you write C for automotive, medical or aerospace, these rules apply to your
code exactly as they do to anyone else's, and aurora-lint is usable alongside whatever
MISRA tooling your certification process requires.

Two rules from NASA JPL's Power of Ten are also implemented alongside CERT C
(`BRULE-060` no dynamic allocation after initialization, `BRULE-065` no
excessive pointer indirection). See
[`docs/future-rulesets.rst`](docs/future-rulesets.rst) for other open
standards that could be added and why they were not needed first.

## What Makes It Different

**No build system. No compilation. No `compile_commands.json` required.** Point
aurora-lint at a directory of C source and it analyzes it. It parses with tree-sitter
rather than driving a compiler, so it needs neither your toolchain, your
headers, your defines, nor a working build — which means it runs on code you
*cannot* build: a partial checkout, a vendored tree, a CI job with no
cross-compiler installed, or a file an AI just generated. It will happily use
`compile_commands.json` and `-I`/`-D` flags when given them, for better
cross-file context; it just does not depend on them.

That is the trade it makes. Without a preprocessor, aurora-lint reasons about source
as written, which is why it has its own macro-expansion engine and why the
false-positive work in this repo is as substantial as the rule work.

**Imperfect on purpose, and measured about it.** aurora-lint reports every rule
violation as written rather than guessing which ones you meant, so it produces
false positives — the precision and recall above are measured against an
adjudicated ground-truth oracle, not asserted (most of its labels were
written by a language model reading the whole file, the rest by hand; the
paper documents the protocol). What makes that workable is that the
noise judgment is yours: per-project rule manifests
([configuration](docs/configuration.rst)), inline and file-scoped
[suppression](docs/suppression.rst), and severity thresholds, so you tune it
to your codebase instead of accepting one global verdict. That same property
is what makes it cheap to drop into a CI gate or an AI-assisted development
loop as a repeated check.

**Scope: C.** aurora-lint analyzes `.c` and `.h` against CERT C. It is not a C++
checker — it recognizes C++ constructs only well enough to avoid reporting
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
| **Juliet Precision** | 87.2% (v0.5.2) |
| **Juliet CWEs Scanned** | 79 (fast mode, CWE-matched rules) |
| **100% Precision CWEs** | 41 (zero false positives, with real detections) |
| **Per-File Detection** | 39.5% (19,838 / 50,256 files) |
| **Real-World Precision / Recall (vs. known TPs)** | 52.8% / 96.9% (v0.5.2, run #269, 78.3% label coverage) |
| **Real-World Projects** | curl, hostap, libcrc, lua, mbedtls, mosquitto, pure-ftpd, raylib, seL4, sqlite, valkey, Ventoy |
| **Basis** | `distinct/scored-projects/in_scope` (definitions `1`) |
<!-- BENCH:HIGHLIGHTS:END -->

Regenerate this table with `python -m bench render-docs --realworld-run RUN`
after a version bump or a fresh delta-adjudication.

**[NIST Juliet](https://samate.nist.gov/SARD/test-suites/112) is the
easier number**: its defects are planted and labeled by the suite itself, so
no adjudication stands between a finding and its verdict. That makes it a
clean regression check and a poor predictor of real-world behavior — a rule
can score perfectly on its Juliet CWE and still be mostly noise on shipping
code, and the paper documents rules that do exactly that. The table gives
the current per-CWE figures; treat them as a floor on how a rule reads the
standard, not as a forecast of what it will do on your tree.

**The real-world codebases are the reference point**, and the harder one:
the projects listed in the table, scanned at pinned commits with findings
adjudicated into a ground-truth oracle — by an LLM for most labels, by hand
for the rest. Real code is messier than a test suite and the precision
figure reflects that.

> **The real-world figures are on a new basis from v0.5.0** and are not
> comparable to anything published before it. Commit `10745a46` re-enabled
> a block of rules that earlier manifests had held out of the benchmark as
> noise, which grew the oracle several-fold and moved the headline
> precision by a large step in one release. That step is a denominator
> effect, not a detection improvement: on a like-for-like basis (that block
> excluded) precision was flat across the change. Do not read the series
> across that break as a trend; the paper treats v0.5.0 as a fresh baseline
> and reports the like-for-like series beside it.

> **Recall is measured against *known* true positives**, not against all
> defects present — the known-TP set is built mostly from the tool's own
> adjudicated findings plus scoped audit hunts, so the figure is labeled-TP
> retention (a regression guard), not recall. No exhaustive false-negative
> hunt sits behind it, so true recall is unknown and lower than the figure
> above. The one detection figure the tool had no hand in assembling is
> Juliet's flaw-hit rate — the share of planted flaw lines it flags — which
> is far lower; the two measure different things and belong side by side.

How both numbers are produced, what they exclude, and why the Juliet
true-positive rate is not the whole story:
[`docs/testing-methodology.rst`](docs/testing-methodology.rst) and
[`docs/juliet-history.rst`](docs/juliet-history.rst).
To regenerate a published figure yourself from the analyzer tag, the public
label set and the corpus pins — no database, no credential — see
[`docs/reproducing-published-numbers.rst`](docs/reproducing-published-numbers.rst).

**The third check is the fixture corpus**, and it reproduces from a clone
with one command each. Every implemented rule ships C fixtures under its own
`tests/{fail,pass,expected_fail}/` — must-detect, must-not-detect, and
known-limitation — auto-generated into Rust tests at build time:

```bash
cargo test --package aurora-lint                                # every fixture, zero failures
python3 scripts/fixture_provenance.py --containment             # how many, from where, how faithful
```

The second command prints the corpus split by provenance — fixtures derived
from the CERT wiki's own compliant/noncompliant examples (third-party
evidence: SEI wrote them without knowledge of this tool) versus ones written
here to pin a regression — and the containment audit
([`scripts/audit_wiki_fixture_staleness.py`](scripts/audit_wiki_fixture_staleness.py)):
what fraction of each wiki example's lines still appear in the fixture that
claims to derive from it, so a fixture quietly rewritten to match the
checker would show up as low containment. Its rule count sits between the
implemented and tracked totals above because it counts rules *by fixture*:
two of the four tracked-but-unimplemented rules keep fixtures, which the
build generates and `#[ignore]`s.

## Installation

The crate, the binary and the man page are all named **`aurora-lint`** — that
is the canonical name to package under.

```bash
cargo install aurora-lint
```

Or build from source:

```bash
git clone https://github.com/brandon-arrendondo/aurora-lint
cd aurora-lint
cargo build --release
```

The binary is at `target/release/aurora-lint`. Requires Rust 2021 edition (stable toolchain).

> **Formerly `sqc`.** This tool was published on crates.io as `sqc` up to
> 0.4.123. That crate is abandoned and will not be updated — crates.io names
> are permanent, so it stays claimed and pointing here, but every release from
> the rename onward is `aurora-lint`. Existing `SQC-SUPPRESS` comments and
> `.sqc-suppress.toml` files keep working; see
> [`docs/suppression.rst`](docs/suppression.rst).

## Getting Started

### Analyze a project

```bash
# Analyze a directory (prints violations to stdout). The target is
# pre-scanned for its own definitions, so cross-file context within it
# is already there.
aurora-lint /path/to/project

# Add context from outside the target (reduces false positives). Once -d
# is given, name every directory you want context from, the target included.
aurora-lint /path/to/project -d /path/to/project -d /path/to/shared/headers
```

### Interactive mode

The terminal UI is disabled by default (CLI + CI/CD is the primary use case). Build with the `tui` feature to enable it:

```bash
cargo build --release --features tui
aurora-lint /path/to/project --interactive
```

### Export results

```bash
aurora-lint /path/to/project --export results.json
aurora-lint /path/to/project --export results.sarif
aurora-lint /path/to/project --export results.csv
```

### Filter by severity

```bash
# Only report Medium and above
aurora-lint /path/to/project --min-severity Medium

# Fail if any High+ violations found (for CI)
aurora-lint /path/to/project --fail-on-severity High
```

### Diff mode (only changed files)

```bash
aurora-lint /path/to/repo --diff
```

### Exclude files from a scan

```bash
# Drop vendored code, test harnesses, or generated/amalgamated files
aurora-lint /path/to/repo --exclude "tests/**" --exclude "vendor/**" --exclude "**/onelua.c"
```

`--exclude` is the only flag that removes files from the scan — `-d` only adds
directories for cross-file context and never restricts what gets analyzed.

### Use a custom rules manifest

```bash
aurora-lint /path/to/project --manifest my-rules.toml
```

The default manifest (`rules_templates/rules-all.toml`) enables 307 of the 311 tracked rules; the other 4 are tracked but not yet implemented (2 parked on incomplete upstream CERT content) — see [Configuration](docs/configuration.rst). See the [Developer Guide](docs/index.rst) for the manifest format.

First run against an existing codebase surfacing more findings than your team can triage at once? `--min-severity`/`--fail-on-severity` and `--exclude` are the fastest levers; [Configuration's "Strict vs. Relaxed Onboarding"](docs/configuration.rst) has the full discipline for building your own scoped-down manifest, and why this project doesn't ship a one-size-fits-all "relaxed" one.

## Quick CI Example

```bash
# CI pipeline: diff-only, Medium+ reporting, fail on High, SARIF export
aurora-lint . --diff --min-severity Medium --fail-on-severity High --export results.sarif
```

Exit codes: `0` = success, `1` = violations found (with `--fail-on-*`), `2` = error.

Ready-to-use workflow examples for [GitHub Actions and Azure DevOps](docs/cicd-integration.rst) are in the Developer Guide.

## Alternatives

Honest version: on the narrow set of defect classes clang-tidy checks, **clang-tidy
is more precise than aurora-lint** — 99.2% to 81.7% on the 15 Juliet CWEs it covers, and it
finds more true positives there too. It gets that by compiling your code.

aurora-lint's case is breadth and reach, not beating clang-tidy at its fifteen:

| | CERT C coverage | Juliet CWEs | Needs a build? |
|---|---|---:|---|
| **aurora-lint** | **307 rules implemented** (311 tracked), 17 categories | **75** | **No** |
| clang-tidy | ~20 `cert-*` checks | 15 | Yes |
| cppcheck | ~20 (addon) | 15 | No |
| [Infer](https://fbinfer.com/) | bug-type indexed | 10 | Yes |
| [Frama-C](https://frama-c.com/) | not rule-indexed | 6 | Yes |

cppcheck is the useful control, since it also runs without a build: on the same
15 CWEs it scores 36.7% against aurora-lint's 81.7%, and takes roughly ten times as long
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
| [`docs/tool-comparison.rst`](docs/tool-comparison.rst) | aurora-lint vs cppcheck, clang-tidy, Frama-C, Infer — per-CWE precision, speed, build requirements |
| [`docs/testing-methodology.rst`](docs/testing-methodology.rst) | How the benchmark numbers are produced, and what they exclude |
| [`docs/reproducing-published-numbers.rst`](docs/reproducing-published-numbers.rst) | Reproduce a published figure from three SHAs: the aurora-lint tag, the `benchmark_adjudication` label commit, and the corpus pins |
| [CONTRIBUTORS.md](CONTRIBUTORS.md) | Who built this |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to submit a PR, DCO sign-off, licensing |

## AI Assistance

This project was developed with assistance from [Claude](https://claude.ai) (Anthropic). Claude was used throughout the development process for code generation, rule implementation, analysis, and documentation.

Claude is deliberately not listed as a commit co-author — the acknowledgment
belongs once, here, rather than repeated across several thousand commit
messages. See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the people involved.

## License

Apache-2.0. Copyright 2025-2026 BISSELL Homecare, Inc.

[LICENSE](LICENSE) is the unmodified Apache-2.0 text; copyright and
attribution live in [NOTICE](NOTICE), per Apache-2.0 section 4(d).

aurora-lint also carries third-party material from the SEI CERT C Coding Standard,
which keeps its own upstream terms: rule titles and descriptions under
CC BY 4.0, and CERT code examples under MIT. CMU's own notice is mirrored
verbatim in [thirdparty/cert/LICENSE](thirdparty/cert/LICENSE), and
[docs/licensing.rst](docs/licensing.rst) has the full breakdown and what a
distribution packager needs.

Carnegie Mellon and CERT are registered trademarks of Carnegie Mellon
University. aurora-lint is not affiliated with, endorsed by, or certified by CMU or
its Software Engineering Institute.
