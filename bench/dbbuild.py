"""Build one corpus's compile database inside a throwaway container from the
benchmark image's 'tools' stage (container/benchmark.Dockerfile), and write
it to the build cache as a template (bench/deps.py, "the build
configuration").

Run by `python -m bench container-build-db`, never on a host: it installs
packages system-wide, which is the point of a throwaway container.

  python3 -m bench.dbbuild PROJECT CORPUS_DIR CACHE_DIR ENV_PIN

1. Install exactly the corpus's dependency set, each package at its pinned
   version, from the snapshot the container's apt already points at, plus
   the recipe's own build tools. apt brings the matching runtime libraries
   from the same snapshot. Nothing else is installed, so no other corpus's
   packages can shadow this one's headers or change what its configure
   finds.
2. Copy the checkout to $SRC and run the recipe's steps with $SRC and
   $BUILD set.
3. Collect the headers the build generated: everything under $BUILD, and
   whatever the build wrote into $SRC that git does not track.
4. Write the database as a template plus those headers, and cache.json.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from bench import deps

SRC_ROOT = Path("/src")
BUILD_ROOT = Path("/build")
HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".inc", ".def")


def _run(cmd, **kw):
    print("+", cmd if isinstance(cmd, str) else " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, **kw)


# Always installed for a build: the C library, compiler and kernel headers.
BASE_PACKAGES = ("libc6-dev", "libgcc-12-dev", "linux-libc-dev")


def install(decl: dict) -> None:
    """The set's packages the declared default build uses ('packages', plus
    BASE_PACKAGES), at their pinned versions. Not the whole set: a set is
    the union over every configuration of the in-scope files, and an
    optional library present at build time would switch on an autodetected
    feature the default build does not have."""
    wanted = set(decl["build"].get("packages", [])) | set(BASE_PACKAGES)
    debs = [d for src in decl["sources"] for d in src["debs"]]
    in_set = {d["package"] for d in debs}
    # A package the set does not carry is one the build needs for something
    # other than headers (a link-only library such as libnl-genl-3-dev, a
    # tool): installed by name, at the version the image's snapshot holds.
    pins = [f"{d['package']}={d['version']}" for d in debs if d["package"] in wanted]
    pins += sorted(wanted - in_set - set(BASE_PACKAGES))
    _run(["apt-get", "update", "-q"])
    _run(["apt-get", "install", "-y", "-q", "--no-install-recommends",
          *pins, *decl["build"].get("apt", [])])


def generated_files(src: Path, build: Path) -> dict[str, Path]:
    """{'build/<rel>' or 'src/<rel>': path} for each header the build made."""
    out = {}
    for p in sorted(build.rglob("*")):
        if p.is_file() and p.suffix in HEADER_SUFFIXES:
            out[f"build/{p.relative_to(build).as_posix()}"] = p
    untracked = subprocess.run(
        ["git", "-C", str(src), "ls-files", "--others", "-z"],
        capture_output=True, check=True).stdout.decode().split("\0")
    for rel in sorted(r for r in untracked if r):
        p = src / rel
        if p.is_file() and p.suffix in HEADER_SUFFIXES:
            out[f"src/{rel}"] = p
    return out


def build(project: str, corpus_dir: Path, cache_dir: Path, env_pin: str) -> dict:
    decl = deps.declared_for(project)
    if decl is None or not decl.get("build"):
        raise SystemExit(f"{project}: no dependency set with a build recipe")
    install(decl)
    src, bld = SRC_ROOT / project, BUILD_ROOT / project
    shutil.rmtree(src, ignore_errors=True)
    shutil.rmtree(bld, ignore_errors=True)
    shutil.copytree(corpus_dir, src, symlinks=True)
    bld.mkdir(parents=True)
    # A recipe step may run this repository's own tools (bench.vcxproj_db),
    # so bench stays importable from the build's working directory.
    env = {**os.environ, "SRC": str(src), "BUILD": str(bld),
           "PYTHONPATH": os.pathsep.join(p for p in (os.getcwd(), os.environ.get("PYTHONPATH")) if p)}
    _run(["git", "-C", str(src), "config", "--global", "--add", "safe.directory", "*"])
    commit = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    for step in decl["build"]["steps"]:
        _run(["bash", "-e", "-c", step], cwd=src, env=env)
    db_path = Path(decl["build"]["db"].replace("$SRC", str(src)).replace("$BUILD", str(bld)))
    dropped: set = set()
    template = deps.normalize_db(json.loads(db_path.read_text()), str(src), str(bld), dropped)
    gen = generated_files(src, bld)
    overlay = {k[len("src/"):] for k in gen if k.startswith("src/")}
    template = deps.overlay_source_dirs(template, overlay)

    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    (cache_dir / "generated").mkdir(parents=True)
    body = json.dumps(template, indent=1, sort_keys=True).encode()
    (cache_dir / "compile_commands.json").write_bytes(body)
    hashes = {}
    for rel, p in gen.items():
        out = cache_dir / "generated" / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        data = p.read_bytes()
        out.write_bytes(data)
        hashes[rel] = hashlib.sha256(data).hexdigest()
    record = {"corpus": project, "corpus_commit": commit, "environment": env_pin,
              "recipe_sha256": deps.recipe_sha256(decl),
              "db_sha256": hashlib.sha256(body).hexdigest(),
              "entries": len(template), "generated": hashes,
              "dropped_include_dirs": sorted(dropped)}
    (cache_dir / "cache.json").write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
    return record


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 4:
        print(__doc__)
        return 2
    record = build(args[0], Path(args[1]), Path(args[2]), args[3])
    print(json.dumps({k: v for k, v in record.items() if k != "generated"}, indent=1))
    print(f"{len(record['generated'])} generated header(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
