# SqC - Software Code Quality

A static analysis tool for C code compliance with [SEI CERT C Coding Standards](https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard). SqC checks 285 rules across 17 categories, with a CI/CD-ready command-line interface and an optional interactive terminal UI.

## Key Features

- **285 CERT C rules** across 17 categories (API, ARR, CON, DCL, ENV, ERR, EXP, FIO, FLP, INT, MEM, MSC, POS, PRE, SIG, STR, WIN)
- **Optional interactive terminal UI** for browsing and managing violations (build with `--features tui`)
- **Multiple export formats**: CSV, XLSX, JSON, SARIF 2.1.0
- **CI/CD ready**: exit codes, severity thresholds, diff-only mode, SARIF output
- **Cross-file analysis**: pre-scans directories for function definitions to reduce false positives
- **Fast**: tree-sitter based parsing with control-flow graphs and inter-procedural reasoning

## Benchmark Highlights

| Metric | Value |
|--------|-------|
| **Juliet TP Rate** | 83.8% (v0.4.116) |
| **Juliet CWEs Scanned** | 74 (fast mode, CWE-matched rules) |
| **100% Precision CWEs** | 48 (zero false positives) |
| **Per-File Detection** | 38.2% (19,117 / 50,038 files) |
| **Real-World Precision / Recall** | 6.2% / 91.7% (v0.4.120, adjudicated oracle) |
| **Real-World Projects** | libcrc, sqlite, mosquitto, curl, hostap, lua, raylib |

Benchmarked against the [NIST Juliet Test Suite v1.3](https://samate.nist.gov/SARD/test-suites/112) and 5 open-source C codebases. See [JULIET_RESULTS.md](JULIET_RESULTS.md) and [REALWORLD_RESULTS.md](REALWORLD_RESULTS.md) for details.

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

### Use a custom rules manifest

```bash
sqc /path/to/project --manifest my-rules.toml
```

The default manifest (`rules_templates/rules-all.toml`) enables all 285 rules. See the [Developer Guide](docs/index.rst) for the manifest format.

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
