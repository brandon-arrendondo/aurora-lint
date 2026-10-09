"""Run a real-world benchmark inside the benchmark container image
(container/benchmark.Dockerfile; docs/adr/0018).

The image is the environment: the Debian snapshot, every benchmark's
dependency set, the build and comparison tools, the Rust toolchain. What it
does not hold is mounted at run time: this checkout at /work (read-write,
since results and the local database are written there) and each corpus
checkout at /bench/<name>, read-only. aurora-lint is built inside the
container with the image's rustc, into a target directory kept in a podman
volume named after the image's environment pin, so a binary built by one
environment is never reused by another.

  python -m bench container-run [--image IMAGE] [--runtime podman] \
      -- [realworld-run | juliet] [its arguments]

e.g.
  python -m bench container-run -- realworld-run --tool sqc --codebase mosquitto
  python -m bench container-run -- juliet --run-id-out /tmp/juliet.run-id

(no subcommand means realworld-run). The Juliet tree is mounted read-only
too, when this machine has it.

Every scan run this way records the environment manifest's pin in its
sidecar (bench/environment.py), next to the dependency set's.
"""

import os
import shlex
import shutil
import subprocess
from pathlib import Path

from bench.config import (BENCH_ROOT, COMMIT_ENV, COMMIT_SHORT_ENV, PROJECT_DIR,
                          host_commit)

DEFAULT_IMAGE = os.environ.get("AURORA_BENCH_IMAGE", "localhost/aurora-bench:dev")
# The image's 'tools' stage (podman build --target tools), where each
# corpus's compile database is built (bench/dbbuild.py).
DEFAULT_TOOLS_IMAGE = os.environ.get("AURORA_BENCH_TOOLS_IMAGE",
                                     "localhost/aurora-bench-tools:dev")
WORK = "/work"
IN_BENCH_ROOT = "/bench"
# Arguments of realworld-run that name a file on the host; their directory
# is mounted at the same path so the run can write there.
_HOST_PATH_ARGS = ("--dirs-out", "--run-id-out")
# The bench subcommands container-run runs; a run whose first argument is
# none of these is a realworld-run.
SUBCOMMANDS = ("realworld-run", "juliet")


def image_pin(image: str, runtime: str = "podman") -> str:
    """The environment pin of `image` (the hash of its manifest)."""
    out = subprocess.run(
        [runtime, "run", "--rm", "-w", "/opt/aurora-bench", image,
         "python3", "-m", "bench.environment", "hash",
         "/etc/aurora-bench/environment.json"],
        capture_output=True, text=True, check=True, cwd="/",
        env={**os.environ})
    return out.stdout.strip().splitlines()[-1]


def _read_in_image(image: str, code: str, runtime: str = "podman") -> str:
    """The stripped output of a line of Python run in `image` with its
    bench/ importable, or '' if it fails."""
    out = subprocess.run([runtime, "run", "--rm", "-w", "/opt/aurora-bench", image,
                          "python3", "-c", code], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else ""


def _host_dirs(args: list[str]) -> list[Path]:
    dirs = []
    for i, a in enumerate(args):
        for flag in _HOST_PATH_ARGS:
            if a == flag and i + 1 < len(args):
                dirs.append(Path(args[i + 1]).resolve().parent)
            elif a.startswith(flag + "="):
                dirs.append(Path(a.split("=", 1)[1]).resolve().parent)
    if os.environ.get("BENCH_DB"):
        dirs.append(Path(os.environ["BENCH_DB"]).resolve().parent)
    return dirs


def command(run_args: list[str], image: str, pin: str, runtime: str = "podman",
            bench_root=None, project_dir=None, commit=None) -> list[str]:
    """The `podman run` line for one container-run. `commit` is the
    checkout's (full, short) SHA as the host resolves it: only the checkout
    is mounted, so git inside cannot always answer (a worktree's .git names
    a host directory; another uid's tree is "dubious ownership")."""
    from bench.realworld_runner import CODEBASES
    bench_root = Path(bench_root) if bench_root else BENCH_ROOT
    project_dir = Path(project_dir) if project_dir else PROJECT_DIR
    cmd = [runtime, "run", "--rm", "--platform", "linux/amd64",
           "-v", f"{project_dir}:{WORK}",
           "-v", f"aurora-bench-target-{pin[:12]}:{WORK}/target",
           "-v", "aurora-bench-cargo-registry:/opt/cargo/registry",
           "-e", f"SQC_BENCH_ROOT={IN_BENCH_ROOT}",
           "-w", WORK]
    if commit:
        cmd += ["-e", f"{COMMIT_ENV}={commit[0]}", "-e", f"{COMMIT_SHORT_ENV}={commit[1]}"]
    for name in sorted(CODEBASES):
        # Mounted under the project's own name: scoring keys strip a path up
        # to its first /<project>/ (BenchDB.project_relpath), so the
        # container path and the host path normalize to the same key.
        host = bench_root / Path(CODEBASES[name]["path"]).name
        if host.is_dir():
            cmd += ["-v", f"{host}:{IN_BENCH_ROOT}/{name}:ro"]
    trees = bench_root / "header-trees"
    if trees.is_dir():
        cmd += ["-v", f"{trees}:{IN_BENCH_ROOT}/header-trees:ro"]
    cache = bench_root / ".build-cache"
    if cache.is_dir():
        cmd += ["-v", f"{cache}:{IN_BENCH_ROOT}/.build-cache:ro"]
    for d in sorted(set(_host_dirs(run_args))):
        cmd += ["-v", f"{d}:{d}"]
    if os.environ.get("BENCH_DB"):
        cmd += ["-e", f"BENCH_DB={Path(os.environ['BENCH_DB']).resolve()}"]
    juliet = bench_root / "benchmarks" / "juliet-test-suite-c"
    if juliet.is_dir():
        cmd += ["-v", f"{juliet}:{IN_BENCH_ROOT}/benchmarks/juliet-test-suite-c:ro"]
    sub, rest = (run_args[0], run_args[1:]) if run_args[:1] and run_args[0] in SUBCOMMANDS \
        else ("realworld-run", run_args)
    inner = (f"cargo build --release --locked --quiet && python3 -m bench {sub} "
             + " ".join(shlex.quote(a) for a in rest))
    cmd += [image, "sh", "-c", inner]
    return cmd


def run(run_args: list[str], image: str = DEFAULT_IMAGE, runtime: str = "podman") -> int:
    if shutil.which(runtime) is None:
        print(f"container-run: '{runtime}' is not installed (see docs/benchmark-setup.rst)")
        return 2
    commit = host_commit(PROJECT_DIR)
    if commit is None:
        print(f"container-run: git cannot resolve HEAD in {PROJECT_DIR}, so the run "
              "could not record which aurora-lint commit it measured")
        return 2
    pin = image_pin(image, runtime)
    print(f"environment {pin} ({image}); aurora-lint {commit[1]}")
    return subprocess.run(command(run_args, image, pin, runtime, commit=commit)).returncode


def build_db_command(project: str, tools_image: str, pin: str, corpus_commit: str,
                     runtime: str = "podman", bench_root=None, project_dir=None,
                     out_name: str | None = None) -> list[str]:
    """The `podman run` line that builds `project`'s compile database in a
    throwaway container from the tools stage (bench/dbbuild.py). The
    checkout and this repository are mounted read-only; only the cache
    root is writable. The build writes `out_name` there (default: the cache
    directory's own name); build_db passes a fresh temporary name and swaps
    it in."""
    from bench import deps
    from bench.realworld_runner import CODEBASES
    bench_root = Path(bench_root) if bench_root else BENCH_ROOT
    project_dir = Path(project_dir) if project_dir else PROJECT_DIR
    decl = deps.declared_for(project)
    host = bench_root / Path(CODEBASES[project]["path"]).name
    cache = deps.build_cache_dir(decl, corpus_commit, pin, bench_root)
    cache.parent.mkdir(parents=True, exist_ok=True)
    return [runtime, "run", "--rm", "--platform", "linux/amd64",
            "-v", f"{project_dir}:{WORK}:ro",
            "-v", f"{host}:{IN_BENCH_ROOT}/{project}:ro",
            "-v", f"{cache.parent}:/cache-root",
            "-w", WORK, tools_image,
            "python3", "-m", "bench.dbbuild", project, f"{IN_BENCH_ROOT}/{project}",
            f"/cache-root/{out_name or cache.name}", pin]


def build_db(project: str, image: str = DEFAULT_IMAGE,
             tools_image: str = DEFAULT_TOOLS_IMAGE, runtime: str = "podman",
             rebuild: bool = False, bench_root=None) -> int:
    """Build and cache `project`'s compile database for the environment of
    `image` (the bench stage: its pin keys the cache), unless the cache is
    already there and intact: built from this recipe, for this corpus commit
    and environment, every file matching the hash cache.json records. Then
    it is reused ("cache hit") and no container starts.

    Otherwise the build writes a temporary directory beside the cache, which
    is checked the same way and then renamed into place ("rebuilt"); a live
    cache is never deleted while it is being read. All of it runs under the
    cache's exclusive lock (deps.cache_lock), which a scan's materialize
    shares, so concurrent builders build once and a scan never reads a
    cache mid-swap; a scan that starts while a rebuild holds the lock waits
    for it. BENCH_ROOT/.build-cache must be on a local filesystem: flock
    does not hold across machines sharing it over NFS. `rebuild` builds even
    over an intact cache."""
    from bench import deps
    from bench.realworld_runner import CODEBASES, _get_codebase_sha
    if shutil.which(runtime) is None:
        print(f"container-build-db: '{runtime}' is not installed")
        return 2
    pin = image_pin(image, runtime)
    expected = _read_in_image(image, "import json;print(json.load(open('/etc/aurora-bench/environment.json')).get('tools_stage',''))", runtime)
    actual = _read_in_image(tools_image, "from bench import environment as e;print(e.pin(e.load(e.TOOLS_MANIFEST_PATH)))", runtime)
    if not expected or expected != actual:
        print(f"container-build-db: {tools_image} is not the tools stage of {image} "
              f"(its manifest {actual[:12] or 'missing'}, {image} records "
              f"{expected[:12] or 'none'}); rebuild both from one Dockerfile")
        return 2
    from bench import environment
    try:
        declared = environment.declared()["tools_stage"]
    except (OSError, ValueError) as e:
        print(f"container-build-db: {e}")
        return 2
    if actual != declared:
        # Not an error: a rebuilt image is a different environment, and its
        # runs already carry -env<hash>. But a pulled tools image should be
        # the declared one (tools_image), and this says when it is not.
        print(f"container-build-db: note: {tools_image} is tools stage {actual[:12]}, not "
              f"the declared {declared[:12]} (data/benchmark_environment.json tools_image)")
    commit = _get_codebase_sha(CODEBASES[project]["path"])
    if not commit:
        print(f"container-build-db: {CODEBASES[project]['path']} is not a git checkout")
        return 2
    print(f"environment {pin} ({image}); {project} @ {commit[:12]}")
    decl = deps.declared_for(project)
    cache = deps.build_cache_dir(decl, commit, pin, bench_root)
    with deps.cache_lock(cache, exclusive=True):
        # A builder killed mid-build or mid-swap leaves these; under the
        # exclusive lock no other builder is using one.
        for stale in [*cache.parent.glob(f"{cache.name}.tmp-*"),
                      *cache.parent.glob(f"{cache.name}.old-*")]:
            shutil.rmtree(stale, ignore_errors=True)
        if rebuild:
            reason = "--rebuild"
        else:
            try:
                record, _, _ = deps.check_cache(decl, cache, commit, pin)
            except (FileNotFoundError, ValueError) as e:
                reason = str(e)
            else:
                print(f"cache hit: {cache} ({record['entries']} entries, "
                      f"{len(record.get('generated', {}))} generated)")
                return 0
        tmp = cache.with_name(f"{cache.name}.tmp-{os.getpid()}")
        shutil.rmtree(tmp, ignore_errors=True)
        rc = subprocess.run(build_db_command(project, tools_image, pin, commit, runtime,
                                             bench_root=bench_root,
                                             out_name=tmp.name)).returncode
        try:
            if rc == 0:
                deps.check_cache(decl, tmp, commit, pin)
        except (FileNotFoundError, ValueError) as e:
            print(f"container-build-db: the build's output does not check out: {e}")
            rc = 1
        if rc != 0:
            shutil.rmtree(tmp, ignore_errors=True)
            return rc
        old = None
        if cache.exists():
            old = cache.with_name(f"{cache.name}.old-{os.getpid()}")
            cache.rename(old)
        tmp.rename(cache)
        if old is not None:
            # No reader holds the shared lock while this one is exclusive.
            shutil.rmtree(old, ignore_errors=True)
        print(f"rebuilt: {cache} ({reason})")
        return 0
