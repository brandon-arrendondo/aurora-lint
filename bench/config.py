"""Centralized paths, constants, and defaults for the benchmark infrastructure."""

import json
import os
import subprocess
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

# ── The aurora-lint commit a run records ─────────────────────────────────────
# A run id names aurora-lint's commit (`sqc-{version}-{sha}`). Inside the
# benchmark container git often cannot answer: a worktree checkout's .git
# points at a directory on the host that is not mounted, and a tree owned by
# another uid is "dubious ownership". So `bench container-run` resolves the
# commit on the host and passes it in; these names carry it.
COMMIT_ENV = "AURORA_BENCH_COMMIT"              # the full SHA
COMMIT_SHORT_ENV = "AURORA_BENCH_COMMIT_SHORT"  # `git rev-parse --short` on the host
UNKNOWN_COMMIT = "unknown"


def host_commit(project_dir: Path = PROJECT_DIR) -> tuple[str, str] | None:
    """(full, short) SHA of the checkout at `project_dir`, as git there
    resolves it, or None when git cannot."""
    try:
        out = [subprocess.run(["git", "rev-parse", *args, "HEAD"], capture_output=True,
                              text=True, cwd=project_dir, timeout=5)
               for args in ([], ["--short"])]
    except (OSError, subprocess.SubprocessError):
        return None
    if any(r.returncode != 0 or not r.stdout.strip() for r in out):
        return None
    return out[0].stdout.strip(), out[1].stdout.strip()


def aurora_lint_commit(project_dir: Path = PROJECT_DIR) -> str:
    """The short SHA a run records. Git's answer in `project_dir` whenever
    git can give one; a passed-in AURORA_BENCH_COMMIT that disagrees with it
    is refused, so a stale value (a leftover export, a .env line) can never
    relabel a run. Only when git cannot resolve HEAD (inside the benchmark
    container, a worktree checkout or another uid's tree) is the commit
    `bench container-run` passed in used, and failing that UNKNOWN_COMMIT.
    A passed-in short SHA that is not a prefix of the full one is refused."""
    short, full = os.environ.get(COMMIT_SHORT_ENV, ""), os.environ.get(COMMIT_ENV, "")
    if short and not full.startswith(short):
        raise ValueError(f"{COMMIT_SHORT_ENV}={short} is not a prefix of "
                         f"{COMMIT_ENV}={full or '(unset)'}")
    resolved = host_commit(project_dir)
    if resolved is not None:
        if full and full != resolved[0]:
            raise ValueError(f"{COMMIT_ENV}={full} disagrees with git, which resolves "
                             f"{project_dir} to {resolved[0]}; unset it (it is set only "
                             f"inside a `bench container-run`)")
        # Agreeing, the host's abbreviation is the one to record: its length
        # is git's choice per repository.
        return short or resolved[1]
    return short or UNKNOWN_COMMIT


def require_known_commit(sha: str, what: str) -> None:
    """Refuse to run or ingest a benchmark whose aurora-lint commit is
    unknown: every such run would share one run id, so two refs would
    overwrite each other's results."""
    if not sha or sha == UNKNOWN_COMMIT:
        raise ValueError(
            f"{what}: aurora-lint's commit is unknown (git cannot resolve HEAD in "
            f"{PROJECT_DIR}), and a run recorded as '{UNKNOWN_COMMIT}' would share its "
            f"run id with every other such run. Run from a git checkout, or inside "
            f"the benchmark image through `bench container-run`, which passes the "
            f"host's commit in ({COMMIT_ENV}, {COMMIT_SHORT_ENV}).")


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
    """Every rule id sqc can emit, from rules-all.toml's section keys: the
    CERT C rules and the CWE ruleset's.

    This is the full IMPLEMENTED set, not the currently-enabled subset: a rule
    disabled in the default manifest is still one a run can be configured to
    emit, so a label naming it is legitimate. An id absent from here is not --
    sqc cannot produce that finding, so no adjudicator can have seen it.
    """
    import tomllib
    with RULES_ALL_TOML.open("rb") as f:
        rules = tomllib.load(f)["rules"]
    return set(rules["cert_c"]) | set(rules.get("cwe", {}))


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


# ── Policy/environment settings (ADR-0015) ────────────────────────────────────
# The preset every run scans under unless told otherwise; also the binary's
# own default. Runs recorded before settings existed keep their bare
# `sqc-{version}-{sha}` ids and a NULL `settings` column ("pre-settings"):
# they ran under neither preset exactly, and nothing renames or back-fills
# them.
DEFAULT_PROFILE = "default"
PROFILES = ("default", "strict")

# What a Juliet testcase set is, declared on every Juliet scan: a closed
# program, which nothing outside links against or loads (the binary's
# `closed_program` option; ADR-0011), built for Linux x86_64 with GCC, whose
# data model is LP64 (`data_model`; ADR-0011 credits integer widths only
# where they are declared). Real-world scans declare their data model in
# their own manifests (conf/realworld/*-rules.toml).
JULIET_SETTING_OVERRIDES = ("closed_program=true", "data_model=lp64")
# How a run_id names that declaration after its preset (ADR-0015 Decision 8).
JULIET_RUN_LABEL_SUFFIX = "+closed"

# aurora-lint options that change the resolved settings, each taking one
# value. `resolve_settings` forwards these from a scan's extra arguments so
# the settings it records are the ones the scan ran under.
SETTINGS_FLAGS = ("--compile-commands", "--include-names", "--policy",
                  "--environment", "--libc", "--data-model", "--set")


def settings_args(extra_args: list[str]) -> list[str]:
    """The settings-changing options in `extra_args`, with their values, in
    order (`--flag value` and `--flag=value` both)."""
    out, i = [], 0
    while i < len(extra_args):
        arg = extra_args[i]
        if arg in SETTINGS_FLAGS and i + 1 < len(extra_args):
            out += [arg, extra_args[i + 1]]
            i += 2
            continue
        if arg.startswith(tuple(f"{f}=" for f in SETTINGS_FLAGS)):
            out.append(arg)
        i += 1
    return out


def resolve_settings(profile: str, overrides: tuple[str, ...] = (), *,
                     compile_db: str | None = None,
                     extra_args: list[str] = (),
                     manifest: Path | None = None) -> dict:
    """The settings `profile` (plus each `--set NAME=VALUE` in `overrides`)
    resolves to, exactly as the binary reports them (`aurora-lint
    --list-options json`): the resolved values, the preset they equal (None
    for neither) and their SHA-256 `hash`, which the binary computes over
    their canonical JSON so SARIF and this harness never disagree about it.

    Pass the scan's `compile_db` and its `extra_args` when it has them: a
    database can change the settings (one written for cl matches `#include`
    names ignoring case), and so can a settings option among the extra
    arguments, so without them the recorded settings could differ from the
    scan's. The options go in the order the scan command gives them.

    `manifest` is the rules manifest the scan itself is given. `--profile`
    discards its settings except the project's declared facts: its allocators
    and deallocators and its `data_model`, which a scan under that manifest
    uses, so they must be in the settings a run records and in its hash. A scan with a manifest
    resolves its settings with the same one."""
    if profile not in PROFILES:
        raise ValueError(f"unknown profile '{profile}'; one of: {', '.join(PROFILES)}")
    cmd = [str(SQC_BIN), "--list-options", "json", "--profile", profile]
    if manifest is not None:
        cmd += ["--manifest", str(manifest)]
    if compile_db:
        cmd += ["--compile-commands", compile_db]
    for o in overrides:
        cmd.extend(["--set", o])
    cmd += settings_args(list(extra_args))
    out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(out.stdout)["current"]


def juliet_settings(profile: str = DEFAULT_PROFILE,
                    compile_db: str | None = None) -> dict:
    """The settings every Juliet scan under `profile` runs with: the preset
    plus JULIET_SETTING_OVERRIDES, as the binary resolves them, carrying the
    `run_label` its run_id is named by (`default+closed`, `strict+closed`).
    The one place that answers what a Juliet run's settings and name are:
    the runner and benchmarking_db's ingest probe both call it, so the two
    cannot build different run_ids for one run."""
    settings = resolve_settings(profile, JULIET_SETTING_OVERRIDES,
                                compile_db=compile_db)
    settings["run_label"] = f"{profile}{JULIET_RUN_LABEL_SUFFIX}"
    return settings


def settings_run_suffix(settings: dict) -> str:
    """The run_id suffix naming a run's settings, and the one place its
    spelling lives: `-default-{hash12}` or `-strict-{hash12}` when the
    settings are exactly that preset, `-{run_label}-{hash12}` when they are
    a preset plus a declared fact (`-default+closed-...`, from
    `juliet_settings`), `-preset-{hash12}` for anything else. The hash tells
    two runs apart even when they share a label -- a preset whose options
    changed between builds hashes differently."""
    label = settings.get("run_label") or settings.get("preset") or "preset"
    return f"-{label}-{settings['hash'][:12]}"


def settings_column(settings: dict) -> str:
    """`settings` as stored in a run's `settings` column: sorted-key JSON,
    hash included."""
    return json.dumps(settings, sort_keys=True)


def juliet_run_id(version: str, sha: str, *, fast: bool,
                  compile_commands: bool, cwes: tuple[str, ...] = (),
                  settings: dict | None = None) -> str:
    """The run_id for a Juliet run, distinct per (mode, compile-db, settings,
    CWE subset) so every configuration of one sqc build is its own run:
    `sqc-{version}-{sha}[-full][-cdb]-{preset}-{hash12}[-cwe...]`.

    Every new run passes `settings` (`resolve_settings`); None yields the bare
    pre-settings form, which only historical runs carry.

    benchmarking_db's queue_worker.py builds the same name to find the run it
    ingests, and a results directory named the same way for real-world runs.
    It must produce the settings suffix too (by calling `resolve_settings` and
    `settings_run_suffix` rather than re-spelling them), and land together
    with any change here: a worker still building the bare name finds nothing
    to ingest.
    """
    run_id = f"sqc-{version}-{sha}"
    if not fast:
        run_id += f"-{FULL_MODE_RUN_SUFFIX}"
    if compile_commands:
        run_id += f"-{COMPILE_DB_RUN_SUFFIX}"
    if settings is not None:
        run_id += settings_run_suffix(settings)
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
