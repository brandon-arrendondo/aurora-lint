"""Centralized paths, constants, and defaults for the benchmark infrastructure."""

import os
from pathlib import Path

# ── Project layout ────────────────────────────────────────────────────────────
PROJECT_DIR = Path(__file__).resolve().parent.parent
# The binary was renamed sqc -> aurora-lint. The *recorded* tool identifier
# stays "sqc" throughout bench/ -- it is the value in `realworld_results.tool`,
# the `runs.sqc_version` column and the `sqc-{version}-{sha}` run_id prefix, all
# of which are keyed the same way in the shared Postgres instance and in
# `ground_truth`'s (project, commit, file, line, rule) tuples. Renaming the
# identifier would fork the namespace and drop every historical row out of
# comparison; only the path on disk changed.
SQC_BIN = PROJECT_DIR / "target" / "release" / "aurora-lint"
# The FULL-MODE JULIET manifest, and nothing else. It is deliberately its own
# constant rather than an alias of RULES_ALL_TOML below, even though both name
# the same file today: these are two different masters (a `-m` argument to a Juliet
# scan vs. the implemented-rule inventory), and the whole point of retiring the
# old separate rules-benchmark.toml was that one shared, hand-curatable
# manifest let a real-world noise judgement silently move a Juliet number.
# Real-world scans do NOT come through here -- every codebase names its own
# conf/realworld/<cb>-rules.toml (bench/realworld_runner.py requires one).
MANIFEST_JULIET_FULL = PROJECT_DIR / "rules_templates" / "rules-all.toml"
RULES_ALL_TOML = PROJECT_DIR / "rules_templates" / "rules-all.toml"
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
        value = value.strip()
        # Only strip a quote pair that wraps the WHOLE value -- a value like
        # a Postgres DSN can legitimately contain a single-quoted substring
        # (password='has a space') that doesn't wrap the whole line;
        # unconditionally stripping one trailing quote character truncated
        # that password by one char and broke psycopg's conninfo parser.
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(PROJECT_DIR / ".env")

# ── Benchmark host layout ────────────────────────────────────────────────────
# SQC_BENCH_ROOT (env var, or set in a repo-root .env -- see .env.example) is
# the base directory holding the Juliet suite and every real-world codebase
# checkout. Defaults to ~/toolchain. Provisioned by
# playbooks/setup-benchmark-repos.yml; see docs/benchmark-setup.rst.
BENCH_ROOT = Path(os.environ.get("SQC_BENCH_ROOT", str(Path.home() / "toolchain"))).expanduser()

# ── Juliet test suite ─────────────────────────────────────────────────────────
JULIET_BASE = BENCH_ROOT / "benchmarks" / "juliet-test-suite-c" / "testcases"

# ── Compile databases (sqc --compile-commands, task 187/622) ─────────────────
# Optional. sqc runs fine without one; a compile_commands.json only adds the
# build's include search paths and -D macro state to the cross-file context.
#
# Written by playbooks/setup-compile-commands.yml (one per real-world checkout
# root) and scripts/generate_juliet_compile_commands.py (one for Juliet, a
# sibling of testcases/). NOT committed: a compile DB embeds absolute paths, so
# it is per-host and must be regenerated wherever BENCH_ROOT differs.
COMPILE_DB_NAME = "compile_commands.json"
JULIET_COMPILE_DB = JULIET_BASE.parent / COMPILE_DB_NAME

# Appended to a run_id when a benchmark runs with --compile-commands, so a
# with/without pair on the *same* sqc build stays two distinct runs. Without
# this the second run would collide: Juliet's resume logic skips a run_id whose
# status is already "completed", and the real-world runner reuses the id for
# its results directory.
COMPILE_DB_RUN_SUFFIX = "cdb"


def load_rule_ids() -> set[str]:
    """Every CERT-C rule id sqc can emit, from rules-all.toml's section keys.

    This is the full IMPLEMENTED set, not the currently-enabled subset: a rule
    disabled in the default manifest is still one a run can be configured to
    emit, so a label naming it is legitimate. An id absent from here is not --
    sqc cannot produce that finding, so no adjudicator can have seen it.
    """
    import tomllib
    with RULES_ALL_TOML.open("rb") as f:
        return set(tomllib.load(f)["rules"]["cert_c"])


def opam_wrap(argv: list[str]) -> list[str]:
    """Wrap a command so the user's opam switch is on PATH.

    Frama-C is installed by playbooks/install-static-analyzers.yml into
    ~/.opam, which only reaches PATH via `eval $(opam env)` in a login shell --
    and no benchmark runner is one. Calling `frama-c` directly from
    subprocess.run raises FileNotFoundError, and both runners used to catch
    that alongside real analysis errors and return "no alarms", so a Frama-C
    benchmark scored a clean zero on every file instead of failing (task 775).

    `opam env` failing is tolerated rather than required: a Frama-C installed
    some other way is already on PATH.
    """
    return ["bash", "-c", 'eval "$(opam env 2>/dev/null)" 2>/dev/null; exec "$@"',
            "_", *argv]


def compile_db_for(path) -> Path | None:
    """Return `<path>/compile_commands.json` if it exists, else None.

    `path` is a real-world codebase checkout root — the location the Ansible
    playbook copies each generated database into.
    """
    candidate = Path(path) / COMPILE_DB_NAME
    return candidate if candidate.is_file() else None


def apply_run_suffix(run_id: str, compile_commands: bool) -> str:
    """Tag a run_id as a compile-database run so it cannot collide with the
    plain run of the same sqc build."""
    return f"{run_id}-{COMPILE_DB_RUN_SUFFIX}" if compile_commands else run_id

# ── Database ──────────────────────────────────────────────────────────────────
# BENCH_DB overrides the default path (handy for tests/alternate corpora).
DB_PATH = Path(os.environ["BENCH_DB"]) if os.environ.get("BENCH_DB") \
    else PROJECT_DIR / "data" / "benchmarks.db"

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_JOBS = 12
KNOWN_TOTAL_CWES = 118
