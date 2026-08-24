Project Structure
=================

::

    src/
    +-- main.rs              # CLI entry point and argument parsing
    +-- prelude.rs           # Common imports and type definitions
    +-- analyze/             # Core analysis engine
    |   +-- mod.rs           # Project analysis orchestration
    |   +-- cfg.rs           # Control-flow graph construction
    |   +-- context.rs       # Cross-file project context
    |   +-- dataflow.rs      # Reaching definitions analysis
    |   +-- function_summary.rs  # Inter-procedural function summaries
    |   +-- null_state.rs    # CFG-based null state dataflow
    |   +-- prescan.rs       # Directory pre-scanning for cross-file context
    |   +-- suppression.rs   # Violation suppression system
    +-- export/              # Export functionality
    |   +-- mod.rs           # CSV, XLSX, JSON, and SARIF export
    +-- files/               # File and repository handling
    |   +-- mod.rs           # Git integration and file discovery
    +-- manifest/            # Rule configuration system
    |   +-- mod.rs           # TOML manifest parsing and validation
    +-- parser/              # C code parsing
    |   +-- mod.rs           # Tree-sitter C parser integration
    +-- progress.rs          # CLI progress reporting
    +-- rules/               # CERT C rule implementations
    |   +-- mod.rs           # Rule trait and registry
    |   +-- cert_c/          # Individual CERT C rule modules (17 categories)
    |       +-- API/         # API rules (9 rules)
    |       +-- ARR/         # Array rules (9 rules)
    |       +-- CON/         # Concurrency rules (23 rules)
    |       +-- DCL/         # Declaration rules (31 rules)
    |       +-- ENV/         # Environment rules (8 rules)
    |       +-- ERR/         # Error handling rules (11 rules)
    |       +-- EXP/         # Expression rules (31 rules)
    |       +-- FIO/         # I/O rules (35 rules)
    |       +-- FLP/         # Floating point rules (13 rules)
    |       +-- INT/         # Integer rules (23 rules)
    |       +-- MEM/         # Memory rules (17 rules)
    |       +-- MSC/         # Miscellaneous rules (10 rules)
    |       +-- POS/         # POSIX rules (20 rules)
    |       +-- PRE/         # Preprocessor rules (16 rules)
    |       +-- SIG/         # Signal rules (7 rules)
    |       +-- STR/         # String rules (16 rules)
    |       +-- WIN/         # Windows rules (6 rules)
    +-- ui/                  # Terminal user interface (optional `tui` feature, disabled by default)
    |   +-- mod.rs           # Ratatui-based interactive UI
    +-- utility/             # Helper functions
        +-- mod.rs           # Common utilities and helpers

    bench/                   # Benchmark infrastructure
    +-- runner.py            # Juliet benchmark runner
    +-- analyzer.py          # Result analysis and scoring
    +-- __main__.py          # Benchmark CLI (python -m bench)

    rules_templates/         # Rule manifests
    +-- rules-all.toml       # 305 of 311 rules enabled
    +-- cwe/                 # Per-CWE manifests for Juliet benchmarking

    docs/                    # Documentation and CI examples
    +-- index.rst            # Master document (Sphinx toctree)
    +-- conf.py              # Sphinx configuration
    +-- azure-pipelines.yml  # Azure DevOps example pipeline

    .github/workflows/       # GitHub Actions
    +-- ci.yml               # CI: fmt, clippy, test, coverage, docs
    +-- release.yml          # Release automation
