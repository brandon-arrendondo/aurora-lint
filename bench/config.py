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


def _load_dotenv(path: Path) -> None:
    """Populate os.environ from a plain KEY=VALUE .env file (a machine-local,
    gitignored override of the benchmark host layout). Never clobbers a
    variable already set in the environment."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip().strip('"').strip("'")


_load_dotenv(PROJECT_DIR / ".env")

# ── Benchmark host layout ────────────────────────────────────────────────────
# SQC_BENCH_ROOT (env var, or set in a repo-root .env -- see .env.example) is
# the base directory holding the Juliet suite and every real-world codebase
# checkout. Defaults to ~/toolchain. Provisioned by
# playbooks/setup-benchmark-repos.yml; see docs/benchmark-setup.rst.
BENCH_ROOT = Path(os.environ.get("SQC_BENCH_ROOT", str(Path.home() / "toolchain"))).expanduser()

# ── Juliet test suite ─────────────────────────────────────────────────────────
JULIET_BASE = BENCH_ROOT / "benchmarks" / "juliet-test-suite-c" / "testcases"

# ── Database ──────────────────────────────────────────────────────────────────
# BENCH_DB overrides the default path (handy for tests/alternate corpora).
DB_PATH = Path(os.environ["BENCH_DB"]) if os.environ.get("BENCH_DB") \
    else PROJECT_DIR / "data" / "benchmarks.db"

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_JOBS = 12
KNOWN_TOTAL_CWES = 118
