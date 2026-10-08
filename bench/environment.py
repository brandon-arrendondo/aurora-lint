"""The benchmark environment manifest: what the benchmark container image
holds, written into the image when it is built, and hashed into the pin a
real-world benchmark run records (docs/adr/0018).

An image digest is not a usable pin across machines: two builds of one
Dockerfile do not produce the same digest (timestamps, layer ordering), so
the digest identifies one copy of an image, not an environment. The manifest
lists what decides findings and is the same wherever the same environment is
built:

  base       the base image reference and the Debian snapshot its packages
             come from
  packages   every installed Debian package, name -> version
  tools      the exact version line of each tool a run uses: rustc and
             cargo (aurora-lint is built in the container), cppcheck,
             clang-tidy, infer, python
  sets       every dependency set the image holds, id -> manifest_sha256,
             each verified against its tree when the manifest is written
  tools_stage  the pin of the 'tools' stage's own manifest (base and
             packages): the stage compile databases are built in

Its pin is the SHA-256 of its canonical JSON (sorted keys, no whitespace).
Nothing time- or host-dependent goes in: no build date, no hostname, no
image digest.

  python3 -m bench.environment write PATH   collect and write the manifest
                                            (run inside the image build)
  python3 -m bench.environment write-tools PATH
                                            the 'tools' stage's manifest
  python3 -m bench.environment hash PATH    print the pin of a manifest
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

# Where the image keeps its manifest; the runner reads it from here.
MANIFEST_PATH = Path("/etc/aurora-bench/environment.json")
# The 'tools' stage's own manifest (its base and packages), written when
# that stage is built: compile databases are built in that stage, so the
# bench image's manifest records this one's pin, and container-build-db
# refuses a tools image whose manifest differs.
TOOLS_MANIFEST_PATH = Path("/etc/aurora-bench/tools.json")

TOOLS = {
    "rustc": ["rustc", "--version"],
    "cargo": ["cargo", "--version"],
    "cppcheck": ["cppcheck", "--version"],
    "clang-tidy": ["clang-tidy", "--version"],
    # The Clang Static Analyzer (scan-build, analyze-build) is this clang.
    "clang": ["clang", "--version"],
    "gcc": ["gcc", "--version"],
    "flawfinder": ["flawfinder", "--version"],
    "frama-c": ["frama-c", "-version"],
    "infer": ["infer", "--version"],
    "python": [sys.executable, "--version"],
}


def canonical(manifest: dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def pin(manifest: dict) -> str:
    return hashlib.sha256(canonical(manifest)).hexdigest()


def _first_line(cmd) -> str | None:
    """The first non-empty output line of `cmd`, or None if it is not
    installed. The version line of every tool here is its first line."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    for line in (out.stdout + out.stderr).splitlines():
        if line.strip():
            return line.strip()
    return None


def packages() -> dict:
    out = subprocess.run(["dpkg-query", "-W", "-f", "${Package}:${Architecture}=${Version}\n"],
                         capture_output=True, text=True, check=True).stdout
    return dict(sorted(line.split("=", 1) for line in out.splitlines() if "=" in line))


def sets(bench_root=None) -> dict:
    """Every declared dependency set, verified present in this image."""
    from bench import deps
    out = {}
    for f in sorted(deps.DEPS_DIR.glob("*.json")):
        decl = deps.load(f.stem)
        res = deps.check(decl, bench_root)
        if res["status"] == deps.MISSING and deps.licence_gated(decl) \
                and os.environ.get(deps.LICENCE_ENV) != "1":
            # An image built without accepting Microsoft's licence lacks the
            # Win32 corpus's set: a different environment, so say so.
            out[res["id"]] = "unprovisioned: Microsoft licence not accepted"
            continue
        if res["status"] != deps.OK:
            raise RuntimeError(f"dependency set {f.stem}: {res['status']} at {res['path']}")
        out[res["id"]] = decl["manifest_sha256"]
    return out


def _base() -> dict:
    return {"image": os.environ.get("AURORA_BENCH_BASE", ""),
            "snapshot": os.environ.get("AURORA_BENCH_SNAPSHOT", "")}


def collect_tools() -> dict:
    """The 'tools' stage's manifest: what a compile database is built with."""
    return {"base": _base(), "packages": packages()}


def collect(bench_root=None) -> dict:
    manifest = {
        "base": _base(),
        "packages": packages(),
        "tools": {name: _first_line(cmd) for name, cmd in sorted(TOOLS.items())},
        "sets": sets(bench_root),
    }
    tools_stage = load(TOOLS_MANIFEST_PATH)
    if tools_stage is not None:
        manifest["tools_stage"] = pin(tools_stage)
    return manifest


def load(path=MANIFEST_PATH) -> dict | None:
    """The manifest of the image this process runs in, or None outside one."""
    p = Path(path)
    return json.loads(p.read_text()) if p.is_file() else None


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] not in ("write", "write-tools", "hash"):
        print(__doc__)
        return 2
    if args[0] in ("write", "write-tools"):
        manifest = collect() if args[0] == "write" else collect_tools()
        Path(args[1]).parent.mkdir(parents=True, exist_ok=True)
        Path(args[1]).write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        print(pin(manifest))
        return 0
    print(pin(json.loads(Path(args[1]).read_text())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
