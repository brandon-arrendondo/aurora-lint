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
      -- [realworld-run arguments]

e.g.
  python -m bench container-run -- --tool sqc --codebase mosquitto

Every scan run this way records the environment manifest's pin in its
sidecar (bench/environment.py), next to the dependency set's.
"""

import os
import shlex
import shutil
import subprocess
from pathlib import Path

from bench.config import BENCH_ROOT, PROJECT_DIR

DEFAULT_IMAGE = os.environ.get("AURORA_BENCH_IMAGE", "localhost/aurora-bench:dev")
# The image's 'tools' stage (podman build --target tools), where each
# corpus's compile database is built (bench/dbbuild.py).
DEFAULT_TOOLS_IMAGE = os.environ.get("AURORA_BENCH_TOOLS_IMAGE",
                                     "localhost/aurora-bench-tools:dev")
WORK = "/work"
IN_BENCH_ROOT = "/bench"
# Arguments of realworld-run that name a file on the host; their directory
# is mounted at the same path so the run can write there.
_HOST_PATH_ARGS = ("--dirs-out",)


def image_pin(image: str, runtime: str = "podman") -> str:
    """The environment pin of `image` (the hash of its manifest)."""
    out = subprocess.run(
        [runtime, "run", "--rm", "-w", "/opt/aurora-bench", image,
         "python3", "-m", "bench.environment", "hash",
         "/etc/aurora-bench/environment.json"],
        capture_output=True, text=True, check=True, cwd="/",
        env={**os.environ})
    return out.stdout.strip().splitlines()[-1]


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
            bench_root=None, project_dir=None) -> list[str]:
    """The `podman run` line for one container-run."""
    from bench.realworld_runner import CODEBASES
    bench_root = Path(bench_root) if bench_root else BENCH_ROOT
    project_dir = Path(project_dir) if project_dir else PROJECT_DIR
    cmd = [runtime, "run", "--rm", "--platform", "linux/amd64",
           "-v", f"{project_dir}:{WORK}",
           "-v", f"aurora-bench-target-{pin[:12]}:{WORK}/target",
           "-v", "aurora-bench-cargo-registry:/opt/cargo/registry",
           "-e", f"SQC_BENCH_ROOT={IN_BENCH_ROOT}",
           "-w", WORK]
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
    inner = ("cargo build --release --locked --quiet && python3 -m bench realworld-run "
             + " ".join(shlex.quote(a) for a in run_args))
    cmd += [image, "sh", "-c", inner]
    return cmd


def run(run_args: list[str], image: str = DEFAULT_IMAGE, runtime: str = "podman") -> int:
    if shutil.which(runtime) is None:
        print(f"container-run: '{runtime}' is not installed (see docs/benchmark-setup.rst)")
        return 2
    pin = image_pin(image, runtime)
    print(f"environment {pin} ({image})")
    return subprocess.run(command(run_args, image, pin, runtime)).returncode


def build_db_command(project: str, tools_image: str, pin: str, corpus_commit: str,
                     runtime: str = "podman", bench_root=None, project_dir=None) -> list[str]:
    """The `podman run` line that builds `project`'s compile database in a
    throwaway container from the tools stage (bench/dbbuild.py). The
    checkout and this repository are mounted read-only; only the cache
    directory is writable."""
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
            f"/cache-root/{cache.name}", pin]


def build_db(project: str, image: str = DEFAULT_IMAGE,
             tools_image: str = DEFAULT_TOOLS_IMAGE, runtime: str = "podman") -> int:
    """Build and cache `project`'s compile database for the environment of
    `image` (the bench stage: its pin keys the cache)."""
    from bench.realworld_runner import CODEBASES, _get_codebase_sha
    if shutil.which(runtime) is None:
        print(f"container-build-db: '{runtime}' is not installed")
        return 2
    pin = image_pin(image, runtime)
    commit = _get_codebase_sha(CODEBASES[project]["path"])
    if not commit:
        print(f"container-build-db: {CODEBASES[project]['path']} is not a git checkout")
        return 2
    print(f"environment {pin} ({image}); {project} @ {commit[:12]}")
    return subprocess.run(build_db_command(project, tools_image, pin, commit, runtime)).returncode
