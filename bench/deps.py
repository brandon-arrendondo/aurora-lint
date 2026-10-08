"""Per-benchmark dependency sets: the system headers a real-world benchmark
is scanned against, declared per benchmark, installed into a tree of their
own and pinned by a manifest hash (docs/adr/0018).

A real-world benchmark run is pinned by five things: the corpus commit, the
aurora-lint commit, the oracle commit, the settings hash, and this set's
manifest hash. The headers are the fifth because they move findings (a
declaration the scan cannot see is an undeclared identifier; a macro it
cannot see leaves an arm unevaluated), and the hosts that scan benchmarks do
not share a platform, let alone a set of installed -dev packages.

Each benchmark declares its set in data/benchmark_deps/<name>.json, and a
corpus names it with 'deps' in data/benchmark_repos.json:

  corpus           the benchmark the set belongs to
  platform         its primary_build_config id: the TARGET the headers are
                   for, not the host that scans it. A macOS host scanning a
                   Linux corpus installs the same Linux headers.
  base             where the packages come from: {"archive", "suite",
                   "arch", "snapshot", "release_sha256"}: a
                   snapshot.debian.org timestamp, so resolving a header to a
                   package is repeatable, and the sha256 of that snapshot's
                   Release file, which every index resolve reads is checked
                   against (`release`)
  sources          what to fetch. Kind "debs": Debian binary packages, each
                   {"package", "version", "file", "url", "sha256"} with the
                   sha256 of the .deb itself
  roots            the directories the set installs and the hash covers
  prune            paths under `roots` the set leaves out: never unpacked,
                   never hashed. For subtrees no #include of the corpus
                   reaches, chiefly the linux-libc-dev netfilter headers
                   whose names differ only in case, so the set can be laid
                   out on a case-insensitive filesystem
  include_dirs     the -I list, relative to the tree, in the search order a
                   compiler uses for its system directories
  exclude          {package: why it is not part of this configuration},
                   which resolve never picks (the -m32 multilib packages
                   an x86_64 glibc header names in an arm for another ABI)
  manifest_sha256  the fifth pin (below)
  why              {package: the #include that needs it}, for review only

The tree lives at BENCH_ROOT/deps/<id>/, where the id is
<corpus>-<platform>-<8 hex of the sources' hash>: a re-pin is a new
directory, and an existing tree never changes. Downloads are shared between
sets in BENCH_ROOT/deps/.cache/, named by their sha256.

The manifest hash is bench/header_tree.py's (the 'F <path> <sha256>' and
'L <path> <target>' lines, sorted, SHA-256), over every file and link under
`roots`. fetch computes it from the package members as it unpacks them, not
from the filesystem afterwards, so two hosts that unpack the same packages
compute the same pin. A host that cannot lay the set out faithfully (two
paths that differ only in case, on a case-insensitive filesystem) is refused
with the list of paths, never given a merged tree.

The runner verifies the tree before a real-world scan, refuses a missing or
different one, and records `provenance` in the scan's .meta.json sidecar.
"""

import gzip
import hashlib
import json
import lzma
import os
import posixpath
import re
import shutil
from pathlib import Path

from bench.config import BENCH_ROOT, PROJECT_DIR
from bench.header_tree import (REPOS_JSON, _download, _sha256_file,
                               ar_members, extract_headers, manifest_sha256)

DEPS_DIR = PROJECT_DIR / "data" / "benchmark_deps"
SNAPSHOT = "https://snapshot.debian.org"

# Statuses, worst first.
MISSING = "MISSING"          # no tree at the declared path
UNPINNED = "UNPINNED"        # the declaration carries no manifest hash yet
MISMATCH = "MISMATCH"        # a tree is there, but its manifest hash differs
OK = "OK"


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def _tree_relative(path: str, what: str) -> str:
    """`path` as a normalized path inside the tree. A trailing slash would
    make a prefix match nothing, and an absolute or escaping path names
    something outside the tree, so both are refused rather than ignored."""
    norm = posixpath.normpath(path)
    if posixpath.isabs(norm) or norm == ".." or norm.startswith("../") or norm == ".":
        raise ValueError(f"{what} '{path}' is not a path inside the tree")
    return norm


def validate(decl: dict) -> dict:
    """`decl` with its tree paths normalized, or ValueError. Every pinned
    package must say why it is in the set (review is how a set stays
    minimal), and only 'debs' sources are fetched: an SDK tree such as
    ventoy's (fetched by xwin, bench/header_tree.py) is not a source kind
    here yet."""
    for key in ("roots", "prune", "include_dirs"):
        decl[key] = [_tree_relative(p, key) for p in decl.get(key, [])]
    why = decl.get("why", {})
    for src in decl.get("sources", []):
        if src.get("kind") != "debs":
            raise ValueError(f"{decl.get('corpus')}: source kind '{src.get('kind')}' "
                             "is not supported (only 'debs')")
        unexplained = [d["package"] for d in src.get("debs", []) if d["package"] not in why]
        if unexplained:
            raise ValueError(f"{decl.get('corpus')}: no 'why' entry for "
                             f"{', '.join(unexplained)}")
    return decl


def load(name: str) -> dict:
    """The declaration data/benchmark_deps/`name`.json, or the file `name`
    itself when it ends in .json (a declaration being drafted), validated."""
    path = Path(name) if name.endswith(".json") else DEPS_DIR / f"{name}.json"
    if not path.is_file():
        raise KeyError(f"no dependency set '{name}' ({path} does not exist)")
    return validate(json.loads(path.read_text()))


def deps_name(project: str):
    """The name of the dependency set `project` declares ('deps' in
    data/benchmark_repos.json), or None if it declares none."""
    for entry in json.loads(REPOS_JSON.read_text())["repos"]:
        if entry["name"] == project:
            return entry.get("deps") or None
    return None


def declared_for(project: str):
    """The dependency set `project` declares, or None if it declares none."""
    name = deps_name(project)
    return load(name) if name else None


def decl_sha256(decl: dict) -> str:
    """The hash of what was asked for: the whole declaration except its
    result (the manifest hash) and its review notes ('why')."""
    body = {k: v for k, v in decl.items() if k not in ("manifest_sha256", "why")}
    return hashlib.sha256(_canonical(body)).hexdigest()


def set_id(decl: dict) -> str:
    """The tree's directory name. Only what changes the tree's contents
    goes into it, so editing include_dirs or 'why' keeps the tree."""
    key = {k: decl.get(k) for k in ("platform", "base", "sources", "roots")}
    key["prune"] = decl.get("prune") or []
    return f"{decl['corpus']}-{decl['platform']}-{hashlib.sha256(_canonical(key)).hexdigest()[:8]}"


def deps_root(bench_root=None) -> Path:
    return (Path(bench_root) if bench_root else BENCH_ROOT) / "deps"


def tree_path(decl: dict, bench_root=None) -> Path:
    return deps_root(bench_root) / set_id(decl)


def check(decl: dict, bench_root=None) -> dict:
    """Inspect the tree `decl` declares. 'status' is MISSING, UNPINNED,
    MISMATCH or OK."""
    path = tree_path(decl, bench_root)
    res = {"id": set_id(decl), "path": str(path),
           "expected": decl.get("manifest_sha256"), "actual": None, "status": None}
    if not path.is_dir():
        res["status"] = MISSING
        return res
    res["actual"] = manifest_sha256(path, decl["roots"])
    if not res["expected"]:
        res["status"] = UNPINNED
    else:
        res["status"] = OK if res["actual"] == res["expected"] else MISMATCH
    return res


def include_args(decl: dict, bench_root=None) -> list[str]:
    root = tree_path(decl, bench_root)
    args = []
    for d in decl["include_dirs"]:
        args.extend(["-I", str(root / d)])
    return args


def provenance(decl: dict) -> dict:
    """What a scan records about the set it ran against. The manifest hash
    is the one the scan verified."""
    return {"id": set_id(decl), "platform": decl["platform"],
            "decl_sha256": decl_sha256(decl),
            "manifest_sha256": decl["manifest_sha256"]}


# -- unpacking ---------------------------------------------------------------

def _data_members(deb_bytes: bytes):
    """The data tarball of a .deb, opened."""
    import io
    import tarfile
    for name, body in ar_members(deb_bytes):
        if name.startswith("data.tar"):
            return tarfile.open(fileobj=io.BytesIO(body), mode="r:*")
    raise ValueError("no data.tar member in .deb")


def _under(rel: str, dirs) -> bool:
    return any(rel == d or rel.startswith(d + "/") for d in dirs)


def member_paths(deb_bytes: bytes, roots, prune=()) -> list[str]:
    """The normalized paths of a .deb's files and links under `roots` and
    not under `prune`."""
    out = []
    with _data_members(deb_bytes) as tar:
        for m in tar.getmembers():
            if m.isdir():
                continue
            raw = m.name[2:] if m.name.startswith("./") else m.name
            rel = posixpath.normpath(raw)
            if _under(rel, roots) and not _under(rel, prune):
                out.append(rel)
    return out


def case_collisions(paths) -> list[list[str]]:
    """Groups of distinct paths that are one path on a case-insensitive
    filesystem. The directories along each path count too, so a file a/B
    and a directory a/b (from a/b/c) are a group."""
    groups: dict[str, set[str]] = {}
    for p in paths:
        parts = p.split("/")
        for i in range(1, len(parts) + 1):
            sub = "/".join(parts[:i])
            groups.setdefault(sub.casefold(), set()).add(sub)
    return sorted(sorted(g) for g in groups.values() if len(g) > 1)


def is_case_insensitive(directory: Path) -> bool:
    directory.mkdir(parents=True, exist_ok=True)
    probe = directory / ".CaseProbe"
    probe.write_text("")
    try:
        return (directory / ".caseprobe").exists()
    finally:
        probe.unlink()


def _cached_deb(deb: dict, cache: Path, log) -> Path:
    f = cache / deb["sha256"]
    if not (f.is_file() and _sha256_file(f) == deb["sha256"]):
        log(f"  fetch {deb['file']}")
        _download(deb["url"], f)
    got = _sha256_file(f)
    if got != deb["sha256"]:
        f.unlink(missing_ok=True)
        raise ValueError(f"{deb['file']}: sha256 {got}, pinned {deb['sha256']}")
    return f


def _debs(decl: dict) -> list[dict]:
    out = []
    for src in decl["sources"]:
        if src.get("kind") != "debs":
            raise ValueError(f"{decl['corpus']}: source kind '{src.get('kind')}' "
                             "is not fetched here")
        out.extend(src["debs"])
    return out


def fetch(decl: dict, bench_root=None, log=print) -> dict:
    """Provision the set's tree: download every pinned .deb (reusing a
    cached copy whose sha256 matches), unpack `roots` into a staging
    directory while computing the manifest from the members, refuse a
    layout this filesystem cannot hold, compare the manifest with the pin
    and move the tree into place. A declaration without a pin yet is
    unpacked and reported UNPINNED with the hash to declare."""
    root = deps_root(bench_root)
    dest = tree_path(decl, bench_root)
    stage = root / f".{set_id(decl)}.partial"
    cache = root / ".cache"
    cache.mkdir(parents=True, exist_ok=True)
    debs = [(d, _cached_deb(d, cache, log).read_bytes()) for d in _debs(decl)]

    prune = decl.get("prune", [])
    clashes = case_collisions(p for _, body in debs
                              for p in member_paths(body, decl["roots"], prune))
    if clashes and is_case_insensitive(root):
        raise ValueError(
            f"{set_id(decl)}: {len(clashes)} path group(s) differ only in case, "
            f"which this filesystem cannot hold apart (prune them if no "
            f"#include reaches them): "
            + "; ".join(" / ".join(g) for g in clashes))

    if stage.exists():
        shutil.rmtree(stage)
    manifest: dict[str, str] = {}
    try:
        for _, body in debs:
            extract_headers(body, stage, decl["roots"], manifest, prune)
        lines = sorted(manifest.values())
        actual = hashlib.sha256("".join(l + "\n" for l in lines).encode()).hexdigest()
        on_disk = manifest_sha256(stage, decl["roots"])
        if on_disk != actual:
            # The filesystem did not keep what was unpacked: a link it could
            # not make, a name it changed. A scan would read the disk.
            raise ValueError(f"{set_id(decl)}: the unpacked tree hashes to "
                             f"{on_disk} on disk but {actual} from the packages")
        expected = decl.get("manifest_sha256")
        if expected and actual != expected:
            raise ValueError(f"{set_id(decl)}: unpacked set has manifest hash "
                             f"{actual}, pinned {expected}")
        if dest.exists():
            shutil.rmtree(dest)
        stage.rename(dest)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    res = check(decl, bench_root)
    res["archive_manifest"] = actual
    return res


# -- resolving #include spellings to packages ---------------------------------
#
# `resolve` turns a benchmark's unresolved #include spellings (its
# --report-headers inventory) into pinned 'debs' entries at the declared
# snapshot: it looks each spelling up in the snapshot's Contents index under
# the set's include_dirs, fetches the package, reads the #include lines of
# the header it found and resolves those in turn, until nothing new is
# reached. Every arm of every #if is followed, so the set is a superset of
# what one configuration reaches; a spelling no package provides is
# reported, not guessed.

_INCLUDE = re.compile(rb'^[ \t]*#[ \t]*include[ \t]*([<"])([^>"]+)[>"]', re.M)


def _dists_url(base: dict) -> str:
    return f"{SNAPSHOT}/archive/{base['archive']}/{base['snapshot']}/dists/{base['suite']}"


# Where Debian's archive signing keys live when the debian-archive-keyring
# package is installed. Without it (or without gpgv) the Release file's
# signature is not checked, and its pinned sha256 is the trust anchor.
ARCHIVE_KEYRING = Path("/usr/share/keyrings/debian-archive-keyring.gpg")


def _cached(base: dict, rel: str, cache: Path, log) -> bytes:
    name = f"{base['archive']}-{base['snapshot']}-{base['suite']}-{rel.replace('/', '_')}"
    f = cache / name
    if not f.is_file():
        log(f"  fetch {rel} @ {base['snapshot']}")
        _download(f"{_dists_url(base)}/{rel}", f)
    return f.read_bytes()


def release(base: dict, cache: Path, log=print) -> dict:
    """The snapshot's Release file: {"sha256", "hashes": {path: sha256},
    "signature"}. A declared base['release_sha256'] must match; the hashes
    it lists are what every index is checked against, and each .deb is
    pinned by the sha256 its Packages entry gives, so one pinned hash
    anchors the whole chain. The signature is verified with gpgv when the
    Debian archive keyring is installed ("verified"), and otherwise left
    unchecked ("unchecked"); a bad signature raises."""
    import subprocess
    import tempfile
    body = _cached(base, "Release", cache, log)
    sha = hashlib.sha256(body).hexdigest()
    pinned = base.get("release_sha256")
    if pinned and sha != pinned:
        raise ValueError(f"Release @ {base['snapshot']}: sha256 {sha}, pinned {pinned}")
    hashes, in_sha256 = {}, False
    for line in body.decode(errors="replace").splitlines():
        if not line.startswith(" "):
            in_sha256 = line.startswith("SHA256:")
            continue
        if in_sha256:
            digest, _size, path = line.split()
            hashes[path] = digest
    signature = "unchecked"
    if shutil.which("gpgv") and ARCHIVE_KEYRING.is_file():
        sig = _cached(base, "Release.gpg", cache, log)
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "Release").write_bytes(body)
            (Path(td) / "Release.gpg").write_bytes(sig)
            proc = subprocess.run(["gpgv", "--keyring", str(ARCHIVE_KEYRING),
                                   str(Path(td) / "Release.gpg"), str(Path(td) / "Release")],
                                  capture_output=True, text=True)
        if proc.returncode != 0:
            raise ValueError(f"Release @ {base['snapshot']}: bad signature\n{proc.stderr}")
        signature = "verified"
    return {"sha256": sha, "hashes": hashes, "signature": signature}


def _index(base: dict, rel: str, cache: Path, log, rel_info: dict | None = None) -> bytes:
    """One index file, checked against the hash the Release file lists."""
    rel_info = rel_info or release(base, cache, log)
    data = _cached(base, rel, cache, log)
    want = rel_info["hashes"].get(rel)
    got = hashlib.sha256(data).hexdigest()
    if want != got:
        raise ValueError(f"{rel} @ {base['snapshot']}: sha256 {got}, Release lists {want}")
    return lzma.decompress(data) if rel.endswith(".xz") else gzip.decompress(data)


def packages_index(base: dict, cache: Path, log=print, rel_info=None) -> dict:
    """{package: {"version", "filename", "sha256"}} from the snapshot's
    main Packages index for base['arch']."""
    text = _index(base, f"main/binary-{base['arch']}/Packages.xz", cache, log,
                  rel_info).decode()
    out = {}
    for stanza in text.split("\n\n"):
        fields = dict(re.findall(r"^([A-Za-z0-9-]+): (.*)$", stanza, re.M))
        if "Package" in fields:
            out[fields["Package"]] = {"version": fields["Version"],
                                      "filename": fields["Filename"],
                                      "sha256": fields["SHA256"]}
    return out


def contents_index(base: dict, roots, cache: Path, log=print, rel_info=None) -> dict:
    """{path: [package, ...]} for every path under `roots`, from the
    snapshot's Contents index for base['arch']."""
    out: dict[str, list[str]] = {}
    text = _index(base, f"main/Contents-{base['arch']}.gz", cache, log,
                  rel_info).decode(errors="replace")
    for line in text.splitlines():
        path, _, owners = line.rpartition(" ")
        path = path.strip()
        if not _under(path, roots):
            continue
        out[path] = sorted(o.rsplit("/", 1)[-1] for o in owners.split(","))
    return out


def deb_entry(base: dict, package: str, info: dict) -> dict:
    return {"package": package, "version": info["version"],
            "file": info["filename"].rsplit("/", 1)[-1],
            "url": f"{SNAPSHOT}/archive/{base['archive']}/{base['snapshot']}/{info['filename']}",
            "sha256": info["sha256"]}


def resolve(decl: dict, spellings, bench_root=None, log=print) -> dict:
    """Resolve `spellings` (angle-bracket #include names) to packages, with
    the closure over the headers they include. Returns {"debs": [...],
    "why": {package: spelling}, "unresolved": [spelling, ...],
    "missed_in_closure": {spelling: includer}, "ambiguous": {path:
    [package, ...]}}. Packages already in the
    declaration's sources are kept and preferred."""
    base = decl["base"]
    cache = deps_root(bench_root) / ".cache"
    cache.mkdir(parents=True, exist_ok=True)
    rel_info = release(base, cache, log)
    pkgs = packages_index(base, cache, log, rel_info)
    contents = contents_index(base, decl["roots"], cache, log, rel_info)
    excluded = set(decl.get("exclude", {}))
    chosen: dict[str, dict] = {}
    why: dict[str, str] = {}
    for src in decl.get("sources", []):
        for d in src.get("debs", []):
            chosen[d["package"]] = d
    files: dict[str, bytes] = {}

    def load_pkg(p):
        entry = chosen.get(p) or deb_entry(base, p, pkgs[p])
        chosen[p] = entry
        body = _cached_deb(entry, cache, log).read_bytes()
        with _data_members(body) as tar:
            for m in tar.getmembers():
                if m.isfile():
                    rel = posixpath.normpath(m.name[2:] if m.name.startswith("./") else m.name)
                    if _under(rel, decl["roots"]) and not _under(rel, decl.get("prune", [])):
                        files[rel] = tar.extractfile(m).read()

    for p in list(chosen):
        load_pkg(p)
    unresolved, missed, ambiguous, seen = [], {}, {}, set()
    pruned_reached: dict[str, str] = {}
    queue = [(s, None, None) for s in spellings]
    while queue:
        spelling, includer_dir, includer = queue.pop(0)
        key = (spelling, includer_dir)
        if key in seen:
            continue
        seen.add(key)
        dirs = ([includer_dir] if includer_dir else []) + list(decl["include_dirs"])
        hit = next((f"{d}/{spelling}" for d in dirs
                    if posixpath.normpath(f"{d}/{spelling}") in files), None)
        if hit is None:
            cands = [(d, posixpath.normpath(f"{d}/{spelling}")) for d in dirs]
            found = next(((path, contents[path]) for _, path in cands if path in contents), None)
            owners = [o for o in found[1] if o in pkgs and o not in excluded] if found else []
            if not owners:
                if includer is None:
                    unresolved.append(spelling)
                else:
                    missed.setdefault(spelling, includer)
                continue
            path = found[0]
            if _under(path, decl.get("prune", [])):
                pruned_reached.setdefault(path, includer or "(inventory)")
                continue
            if len(owners) > 1:
                ambiguous[path] = owners
            pkg = next((o for o in owners if o in chosen), owners[0])
            if pkg not in chosen:
                why[pkg] = spelling
                load_pkg(pkg)
            hit = path
        rel = posixpath.normpath(hit)
        for kind, inc in _INCLUDE.findall(files.get(rel, b"")):
            inc = inc.decode(errors="replace").strip()
            queue.append((inc, posixpath.dirname(rel) if kind == b'"' else None, rel))
    return {"release_sha256": rel_info["sha256"],
            "release_signature": rel_info["signature"],
            "debs": sorted(chosen.values(), key=lambda d: d["package"]),
            "why": dict(sorted(why.items())),
            "unresolved": sorted(set(unresolved)),
            # Named only by a header in the set, usually in an arm for
            # another platform or compiler; listed for review, not failed.
            "missed_in_closure": dict(sorted(missed.items())),
            # A pruned path some #include does reach: the prune is wrong.
            "pruned_but_reached": dict(sorted(pruned_reached.items())),
            "ambiguous": dict(sorted(ambiguous.items()))}


def fix_hint(name: str) -> str:
    """How to provision the set `name` (its data/benchmark_deps/ file name)."""
    return (f"provision it with: python3 -m bench.deps fetch {name}   or "
            f"ansible-playbook playbooks/setup-benchmark-deps.yml -i localhost, "
            f"-c local -e benchmarks={name}")


def main(argv=None) -> int:
    """`python -m bench.deps verify NAME`   exit 0 if NAME's tree is present
                                          with the pinned manifest hash;
    `python -m bench.deps fetch NAME`    provision it (download, sha256
                                          check, unpack, verify); a
                                          declaration without a pin prints
                                          the hash to declare;
    `python -m bench.deps id NAME`       print the tree id and decl hash;
    `python -m bench.deps resolve NAME SPELLING...`
                                          print the pinned 'debs' that
                                          provide those #include names, with
                                          the closure, as JSON."""
    import sys
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 2 or args[0] not in ("verify", "fetch", "id", "resolve"):
        print(main.__doc__)
        return 2
    try:
        decl = load(args[1])
    except KeyError as e:
        print(e.args[0])
        return 2
    if args[0] == "id":
        print(f"{set_id(decl)} decl_sha256={decl_sha256(decl)}")
        return 0
    if args[0] == "resolve":
        out = resolve(decl, args[2:], log=lambda m: print(m, file=sys.stderr))
        print(json.dumps(out, indent=2))
        return 0 if not (out["unresolved"] or out["pruned_but_reached"]) else 1
    if args[0] == "fetch":
        res = check(decl)
        if res["status"] != OK:
            res = fetch(decl)
    else:
        res = check(decl)
    line = f"{args[1]}: {res['status']} {res['path']}"
    if res["status"] == MISMATCH:
        line += f" (manifest {res['actual']}, expected {res['expected']})"
    if res["status"] == UNPINNED:
        line += f" (declare manifest_sha256: {res['actual']})"
    print(line)
    return 0 if res["status"] == OK else 1


if __name__ == "__main__":
    raise SystemExit(main())
