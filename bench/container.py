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
WORK = "/work"
IN_BENCH_ROOT = "/bench"
# Arguments of realworld-run that name a file on the host; their directory
# is mounted at the same path so the run can write there.
_HOST_PATH_ARGS = ("--dirs-out",)


def image_pin(image: str, runtime: str = "podman") -> str:
    """The environment pin of `image` (the hash of its manifest)."""
    out = subprocess.run(
        [runtime, "run", "--rm", image, "python3", "-m", "bench.environment", "hash",
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
        host = bench_root / Path(CODEBASES[name]["path"]).name
        if host.is_dir():
            cmd += ["-v", f"{host}:{IN_BENCH_ROOT}/{host.name}:ro"]
    trees = bench_root / "header-trees"
    if trees.is_dir():
        cmd += ["-v", f"{trees}:{IN_BENCH_ROOT}/header-trees:ro"]
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
