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

# AURORA_LINT_SRC_ROOT (env var or .env) is the parent directory of the SOURCE
# clones -- this repo is $AURORA_LINT_SRC_ROOT/aurora-lint, and a maintainer
# node keeps benchmarking_db and sqc_paper beside it. Nothing under bench/
# needs it to find THIS checkout (PROJECT_DIR is resolved from these files),
# so a clone anywhere works with it unset; it exists so the docs' commands and
# playbooks/setup-dev-environment.yml have one name for where the clones are.
# Defaults to this checkout's own parent.
SRC_ROOT = Path(os.environ.get("AURORA_LINT_SRC_ROOT", str(PROJECT_DIR.parent))).expanduser()

# ── Juliet test suite ─────────────────────────────────────────────────────────
JULIET_BASE = BENCH_ROOT / "benchmarks" / "juliet-test-suite-c" / "testcases"

# ── Compile databases (sqc --compile-commands) ─────────────────
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

# Appended to a Juliet run_id for a full-mode run, for the same collision
# reason. Fast mode keeps the bare id: it is the published default, so every
# historical fast run keeps its id and the trend history is unbroken.
FULL_MODE_RUN_SUFFIX = "full"

# Appended to a Juliet run_id when the run is restricted to some CWEs
# (`bench juliet --cwe`), followed by the CWE numbers ("-cwe78_476"). A subset
# run is a smoke test, not a benchmark: without its own id it would mark the
# build's real run_id "completed" after one CWE, and resume would then refuse
# to scan the rest.
CWE_SUBSET_RUN_SUFFIX = "cwe"


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
    benchmark scored a clean zero on every file instead of failing.

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


def juliet_run_id(version: str, sha: str, *, fast: bool,
                  compile_commands: bool, cwes: tuple[str, ...] = ()) -> str:
    """The run_id for a Juliet run, distinct per (mode, compile-db, CWE
    subset) so every configuration of one sqc build is its own run.

    benchmarking_db's queue_worker.py builds the same name to find the run it
    ingests; change the two together. `cwes` defaults to empty, which leaves
    every id the queue builds unchanged.
    """
    run_id = f"sqc-{version}-{sha}"
    if not fast:
        run_id += f"-{FULL_MODE_RUN_SUFFIX}"
    if compile_commands:
        run_id += f"-{COMPILE_DB_RUN_SUFFIX}"
    if cwes:
        numbers = sorted({c.removeprefix("CWE-") for c in cwes}, key=int)
        run_id += f"-{CWE_SUBSET_RUN_SUFFIX}{'_'.join(numbers)}"
    return run_id

# ── Database ──────────────────────────────────────────────────────────────────
# BENCH_DB overrides the default path (handy for tests/alternate corpora).
DB_PATH = Path(os.environ["BENCH_DB"]) if os.environ.get("BENCH_DB") \
    else PROJECT_DIR / "data" / "benchmarks.db"

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_JOBS = 12
KNOWN_TOTAL_CWES = 118
