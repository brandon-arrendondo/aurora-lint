"""Centralized paths, constants, and defaults for the benchmark infrastructure."""

import os
from pathlib import Path

# ── Project layout ────────────────────────────────────────────────────────────
PROJECT_DIR = Path(__file__).resolve().parent.parent
SQC_BIN = PROJECT_DIR / "target" / "release" / "sqc"
MANIFEST_ALL = PROJECT_DIR / "rules_templates" / "rules-benchmark.toml"
MANIFEST_CWE_DIR = PROJECT_DIR / "rules_templates" / "cwe"
RULE_CWE_MAP = PROJECT_DIR / "data" / "rule_cwe_map.json"
GENERATE_MAP_SCRIPT = PROJECT_DIR / "scripts" / "generate_rule_cwe_map.py"

# ── Juliet test suite ─────────────────────────────────────────────────────────
JULIET_BASE = Path.home() / "toolchain" / "benchmarks" / "juliet-test-suite-c" / "testcases"

# ── Database ──────────────────────────────────────────────────────────────────
# BENCH_DB overrides the default path (handy for tests/alternate corpora).
DB_PATH = Path(os.environ["BENCH_DB"]) if os.environ.get("BENCH_DB") \
    else PROJECT_DIR / "data" / "benchmarks.db"

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_JOBS = 12
KNOWN_TOTAL_CWES = 118
