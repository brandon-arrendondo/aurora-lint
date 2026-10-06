"""Pinned system-header trees: a real-world corpus's platform headers, pinned
and verified the way its source checkout is.

Why this exists: ventoy is the suite's Win32 corpus, and a Linux node has no
<windows.h>. Scanned without one, aurora-lint still parses Ventoy2Disk, but
every Win32 API call is an undeclared identifier, which DCL31-C reports by the
hundred and which shifts what API00-C and INT30-C see. Those findings describe
the benchmark node's missing headers, not the corpus. Scanning against the
real headers fixes that, but only if every node scans against the SAME
headers: a different SDK servicing build can declare different functions, and
the findings would differ between nodes with nothing recording why.

So a corpus that needs one declares a header tree in
data/benchmark_repos.json under 'header_tree', alongside its commit pin:

  id               directory name under BENCH_ROOT/header-trees/; it names
                   every pinned version, so a re-pin is a new directory
  fetch            the exact xwin invocation that produces the tree (tool
                   version, VS manifest version and channel, arch, variant,
                   SDK and CRT versions, whether case symlinks are made),
                   consumed by playbooks/setup-benchmark-repos*.yml
  hashed_dirs      the subtrees the manifest hash covers
  manifest_sha256  the hash itself (`manifest_sha256` below)
  include_dirs     the -I list, relative to the tree, in search order

The headers themselves are Microsoft's, fetched by xwin from Microsoft's own
servers under Microsoft's license terms. Each machine fetches its own copy;
they are never committed to this repo or copied between machines, which is
why the pin is a version list plus a hash rather than the files.

The manifest hash is the check that two machines hold the same tree. It is a
SHA-256 over one line per entry under each hashed directory, sorted:

  F <path> <sha256 of the file's bytes>
  L <path> <symlink target, as written>

with <path> relative to the tree root. Symlinks are hashed by their target
and not followed. The tree is splatted WITHOUT xwin's lower-case alias
symlinks (windows.h -> Windows.h; 'case_symlinks': false): aurora-lint's
include resolver already matches an #include name ignoring case, the way cl
does, so the aliases add nothing to a scan, and they cannot be created on a
case-insensitive filesystem (macOS, a Windows drive), where the alias and its
target are the same name. Without them the tree is byte-identical on every
node. Directory entries carry nothing on their own, and the library
directories (crt/lib, sdk/lib) are not hashed: a scan reads headers only, and
provisioning prunes the libraries.
"""

import hashlib
import json
import os
from pathlib import Path

from bench.config import BENCH_ROOT, PROJECT_DIR

REPOS_JSON = PROJECT_DIR / "data" / "benchmark_repos.json"

# Statuses, worst first.
MISSING = "MISSING"          # no tree at the declared path
MISMATCH = "MISMATCH"        # a tree is there, but its manifest hash differs
OK = "OK"


def trees_root(bench_root=None) -> Path:
    return (Path(bench_root) if bench_root else BENCH_ROOT) / "header-trees"


def spec_for(project: str):
    """The 'header_tree' declaration of `project`, or None if it scans
    against the host's own headers (every corpus but ventoy)."""
    for entry in json.loads(REPOS_JSON.read_text())["repos"]:
        if entry["name"] == project:
            return entry.get("header_tree")
    return None


def tree_path(spec: dict, bench_root=None) -> Path:
    return trees_root(bench_root) / spec["id"]


def manifest_lines(root, hashed_dirs) -> list[str]:
    """The sorted per-entry lines the manifest hash covers (see module doc)."""
    root = Path(root)
    lines = []
    for sub in hashed_dirs:
        for dirpath, dirnames, filenames in os.walk(root / sub):
            # os.walk does not descend into a symlinked directory, but lists it
            # in dirnames; it is an entry like any other link.
            for name in filenames + dirnames:
                p = Path(dirpath) / name
                rel = p.relative_to(root).as_posix()
                if p.is_symlink():
                    lines.append(f"L {rel} {os.readlink(p)}")
                elif p.is_file():
                    lines.append(f"F {rel} {hashlib.sha256(p.read_bytes()).hexdigest()}")
    lines.sort()
    return lines


def manifest_sha256(root, hashed_dirs) -> str:
    """The manifest hash of the tree at `root`. A missing hashed directory
    contributes nothing, so an empty or partial tree gets a hash that simply
    fails to match rather than an exception."""
    body = "".join(line + "\n" for line in manifest_lines(root, hashed_dirs))
    return hashlib.sha256(body.encode()).hexdigest()


def check(spec: dict, bench_root=None) -> dict:
    """Inspect the tree `spec` declares. Returns a result dict whose 'status'
    is MISSING, MISMATCH or OK."""
    path = tree_path(spec, bench_root)
    res = {"id": spec["id"], "path": str(path),
           "expected": spec["manifest_sha256"], "actual": None, "status": None}
    if not path.is_dir():
        res["status"] = MISSING
        return res
    res["actual"] = manifest_sha256(path, spec["hashed_dirs"])
    res["status"] = OK if res["actual"] == spec["manifest_sha256"] else MISMATCH
    return res


def include_args(spec: dict, bench_root=None) -> list[str]:
    path = tree_path(spec, bench_root)
    args = []
    for d in spec["include_dirs"]:
        args.extend(["-I", str(path / d)])
    return args


def provenance(spec: dict) -> dict:
    """What a scan records about the tree it ran against: the declaration
    minus the -I plumbing. The hash is the one the scan verified."""
    return {"id": spec["id"], "fetch": spec["fetch"],
            "hashed_dirs": spec["hashed_dirs"],
            "manifest_sha256": spec["manifest_sha256"]}


def fix_hint(project: str) -> str:
    return (f"provision it with: ansible-playbook playbooks/setup-benchmark-repos.yml "
            f"-i 'localhost,' -c local -e accept_microsoft_license=true "
            f"--tags header-trees   (corpus '{project}'; see docs/benchmark-setup.rst)")


def main(argv=None) -> int:
    """`python -m bench.header_tree verify PROJECT` exits 0 if PROJECT's
    declared tree is present with the declared hash (1 otherwise);
    `python -m bench.header_tree hash PROJECT DIR` prints the manifest hash
    of the tree at DIR over PROJECT's declared hashed_dirs -- the value to
    declare when re-pinning."""
    import sys
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 2 or args[0] not in ("verify", "hash"):
        print(main.__doc__)
        return 2
    spec = spec_for(args[1])
    if spec is None:
        print(f"{args[1]}: no header_tree declared in {REPOS_JSON}")
        return 2
    if args[0] == "hash":
        if len(args) != 3:
            print(main.__doc__)
            return 2
        print(manifest_sha256(args[2], spec["hashed_dirs"]))
        return 0
    res = check(spec)
    print(f"{args[1]}: {res['status']} {res['path']}"
          + (f" (manifest {res['actual']}, expected {res['expected']})"
             if res["status"] == MISMATCH else ""))
    return 0 if res["status"] == OK else 1


if __name__ == "__main__":
    raise SystemExit(main())
