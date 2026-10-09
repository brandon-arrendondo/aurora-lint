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
  other_platform   globs of the in-scope files written for another platform
                   (Windows, a BSD, Android, the web), whose includes the
                   set does not resolve
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

import contextlib
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


# A set whose source is the Windows SDK and MSVC CRT (kind 'xwin') is fetched
# from Microsoft's servers under Microsoft's licence terms: fetch refuses it
# unless this variable is "1" (the image's ACCEPT_MICROSOFT_LICENSE build
# argument sets it).
LICENCE_ENV = "AURORA_ACCEPT_MICROSOFT_LICENSE"
_XWIN_FIELDS = ("tool_version", "manifest_version", "channel", "arch", "variant",
                "sdk_version", "crt_version")


class LicenceNotAccepted(PermissionError):
    """A licence-gated set was asked for without the licence accepted."""


def licence_gated(decl: dict) -> bool:
    return any(src.get("kind") == "xwin" for src in decl.get("sources", []))


def validate(decl: dict) -> dict:
    """`decl` with its tree paths normalized, or ValueError. Every pinned
    package must say why it is in the set (review is how a set stays
    minimal). A source is 'debs' (Debian packages) or 'xwin' (the Windows SDK
    and MSVC CRT at pinned versions, fetched by xwin; alone in its set)."""
    if not isinstance(decl.get("other_platform", []), list):
        raise ValueError(f"{decl.get('corpus')}: other_platform must be a list of globs")
    for key in ("roots", "prune", "include_dirs"):
        decl[key] = [_tree_relative(p, key) for p in decl.get(key, [])]
    build = decl.get("build")
    if build is not None:
        if not build.get("steps") or not build.get("db"):
            raise ValueError(f"{decl.get('corpus')}: build needs 'steps' and 'db'")
        if not build["db"].startswith(("$SRC/", "$BUILD/")):
            raise ValueError(f"{decl.get('corpus')}: build.db must start with $SRC/ or $BUILD/")
    why = decl.get("why", {})
    for src in decl.get("sources", []):
        if src.get("kind") == "xwin":
            missing = [f for f in _XWIN_FIELDS if not src.get(f)]
            if missing or len(decl["sources"]) != 1:
                raise ValueError(f"{decl.get('corpus')}: an xwin source needs "
                                 f"{', '.join(_XWIN_FIELDS)} and must be the set's only source")
            continue
        if src.get("kind") != "debs":
            raise ValueError(f"{decl.get('corpus')}: source kind '{src.get('kind')}' "
                             "is not supported ('debs' or 'xwin')")
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


def spellings(project: str, checkout=None, other_platform=None,
              dropped: dict | None = None) -> list[str]:
    """The #include spellings a dependency set must resolve for `project`:
    every <...> and "..." include in the corpus's in-scope source files
    (scope_include/scope_exclude: bench/corpus.py), except those of files
    for another platform, that the corpus does not provide itself. A set
    covers every configuration of those files Debian can supply, not only
    the default build (docs/adr/0018; ADR-0010), so every arm's includes
    count, and so do the files for an alternative Linux backend.

    `other_platform` are globs naming the in-scope files written for another
    platform (Windows, a BSD, Android, the web): their includes are not
    Debian's to supply. Default: the declaration's 'other_platform'.

    A spelling is the corpus's own when it names an in-scope file (as a
    path suffix), a file under one of the corpus's own -I directories
    (bench/realworld_runner.py CODEBASES), or a file relative to the
    including file. A copy somewhere else in the checkout (a vendored
    compatibility header, an example's bundled library) does not count:
    `dropped`, when given, records each spelling the narrower rule kept
    that a match against the whole checkout would have dropped."""
    import subprocess
    from bench import corpus
    from bench.realworld_runner import CODEBASES
    root = Path(checkout) if checkout else BENCH_ROOT / project
    if other_platform is None:
        name = deps_name(project)
        other_platform = load(name).get("other_platform", []) if name else []
    files = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True,
                           check=True).stdout.decode().split("\0")
    files = [f for f in files if f]
    shipped = set(files)
    in_scope = [f for f in files if corpus.in_scope(project, f)]

    def suffixes(paths):
        out = set()
        for f in paths:
            parts = f.split("/")
            out.update("/".join(parts[i:]) for i in range(len(parts)))
        return out

    own = suffixes(in_scope)
    anywhere = suffixes(files)
    inc_dirs = [""]
    cfg = CODEBASES.get(project, {}).get("sqc", {})
    incs = cfg.get("includes", [])
    for flag, val in zip(incs, incs[1:]):
        if flag == "-I" and (val == "{path}" or val.startswith("{path}/")):
            inc_dirs.append(val[len("{path}"):].lstrip("/"))
    found = set()
    for f in in_scope:
        if not f.endswith((".c", ".h")):
            continue
        if any(corpus._match(f, pat) for pat in other_platform):
            continue
        try:
            text = (root / f).read_bytes()
        except OSError:
            continue
        for _, inc in _INCLUDE.findall(text):
            name = posixpath.normpath(inc.decode(errors="replace").strip())
            if (name in own
                    or posixpath.normpath(posixpath.join(posixpath.dirname(f), name)) in shipped
                    or any(posixpath.normpath(posixpath.join(d, name)) in shipped for d in inc_dirs)):
                continue
            if dropped is not None and name in anywhere:
                dropped.setdefault(name, f)
            found.add(name)
    return sorted(found)


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
    return [d for src in decl["sources"] if src.get("kind") == "debs" for d in src["debs"]]


def _xwin_splat(src: dict, stage: Path, log) -> None:
    """Fetch the Windows SDK and MSVC CRT headers into `stage` with xwin at
    the pinned versions (the licence accepted by the caller), without
    xwin's lower-case alias links (aurora-lint matches an #include name
    ignoring case for a cl build, and the aliases cannot exist on a
    case-insensitive filesystem), and drop the libraries: a scan reads
    headers only."""
    import subprocess
    got = subprocess.run(["xwin", "--version"], capture_output=True, text=True)
    if got.returncode != 0 or got.stdout.strip() != f"xwin {src['tool_version']}":
        raise ValueError(f"xwin {src['tool_version']} is required, found "
                         f"{got.stdout.strip() or 'none'}")
    log(f"  xwin splat sdk {src['sdk_version']} crt {src['crt_version']} {src['arch']}")
    subprocess.run(
        ["xwin", "--accept-license", "--cache-dir", str(stage / ".cache"),
         "--manifest-version", src["manifest_version"], "--channel", src["channel"],
         "--arch", src["arch"], "--variant", src["variant"],
         "--sdk-version", src["sdk_version"], "--crt-version", src["crt_version"],
         "--http-retry", "3", "splat", "--disable-symlinks", "--output", str(stage / ".splat")],
        check=True)
    for sub in ("crt/lib", "sdk/lib"):
        shutil.rmtree(stage / ".splat" / sub, ignore_errors=True)
    for entry in (stage / ".splat").iterdir():
        entry.rename(stage / entry.name)
    shutil.rmtree(stage / ".splat")
    shutil.rmtree(stage / ".cache", ignore_errors=True)


def _fetch_xwin(decl: dict, bench_root, log) -> dict:
    if os.environ.get(LICENCE_ENV) != "1":
        raise LicenceNotAccepted(
            f"{set_id(decl)}: fetching the Windows SDK and MSVC CRT accepts Microsoft's "
            f"licence terms; set {LICENCE_ENV}=1 to accept them for this machine")
    root = deps_root(bench_root)
    dest = tree_path(decl, bench_root)
    stage = root / f".{set_id(decl)}.partial"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    try:
        _xwin_splat(decl["sources"][0], stage, log)
        actual = manifest_sha256(stage, decl["roots"])
        expected = decl.get("manifest_sha256")
        if expected and actual != expected:
            raise ValueError(f"{set_id(decl)}: fetched tree has manifest hash {actual}, "
                             f"pinned {expected}")
        if dest.exists():
            shutil.rmtree(dest)
        stage.rename(dest)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    res = check(decl, bench_root)
    res["archive_manifest"] = actual
    return res


def fetch(decl: dict, bench_root=None, log=print) -> dict:
    """Provision the set's tree: download every pinned .deb (reusing a
    cached copy whose sha256 matches), unpack `roots` into a staging
    directory while computing the manifest from the members, refuse a
    layout this filesystem cannot hold, compare the manifest with the pin
    and move the tree into place. A declaration without a pin yet is
    unpacked and reported UNPINNED with the hash to declare. An 'xwin' set
    is fetched with xwin instead, and only with Microsoft's licence
    accepted (LICENCE_ENV)."""
    if licence_gated(decl):
        return _fetch_xwin(decl, bench_root, log)
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
    # Created up front: a set with no packages (a freestanding corpus) is
    # an empty tree, pinned like any other.
    stage.mkdir(parents=True)
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
    snapshot's Contents indices for base['arch'] AND for 'all': an
    architecture-independent package (x11proto-dev's X11/*.h, for one) is
    listed only in Contents-all, though the Packages index carries it."""
    out: dict[str, set] = {}
    for arch in (base["arch"], "all"):
        text = _index(base, f"main/Contents-{arch}.gz", cache, log,
                      rel_info).decode(errors="replace")
        for line in text.splitlines():
            path, _, owners = line.rpartition(" ")
            path = path.strip()
            if not _under(path, roots):
                continue
            out.setdefault(path, set()).update(o.rsplit("/", 1)[-1] for o in owners.split(","))
    return {p: sorted(o) for p, o in out.items()}


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


# -- the build configuration: compile database and generated headers ---------
#
# The set supplies the system directories a compiler searches on its own. A
# corpus's build supplies the rest: its project include directories, its -D
# flags, and the headers its build generates (a configure-written config.h,
# a make-generated parse.h). A declaration's optional 'build' section is the
# RECIPE for that build, never its output:
#
#   apt     build tools the recipe needs beyond the image's 'tools' stage
#           (tclsh, xsltproc), installed from the same snapshot
#   steps   shell commands run with $SRC (a copy of the checkout) and
#           $BUILD (an empty directory) set, in $SRC, under bash -e
#   db      where the steps leave compile_commands.json ($SRC/... or
#           $BUILD/...)
#   packages  the set's packages the default build uses (the set itself is
#           the union over every configuration, so installing all of it
#           would switch on autodetected features the default build lacks)
#   why     what the recipe chooses and why (the declared configuration)
#
# python -m bench container-build-db runs the recipe in a throwaway
# container from the image's 'tools' stage, with exactly this corpus's set
# installed (bench/dbbuild.py), and caches what it produced under
# BENCH_ROOT/.build-cache/<corpus>-<corpus sha>-<environment pin>/:
#
#   compile_commands.json  a TEMPLATE: checkout paths written ${CORPUS},
#                          build-tree paths ${GEN}/build, system include
#                          directories removed (the set supplies them),
#                          entries sorted
#   generated/             headers the build produced: build/<path> from
#                          the build tree, src/<path> for files an in-tree
#                          build wrote into its copy of the checkout (each
#                          -I ${CORPUS}/X is followed by -I ${GEN}/src/X)
#   cache.json             the template's and every header's sha256, the
#                          recipe's hash, the corpus commit and environment
#
# A scan materializes the cache for its machine (materialize). Nothing
# derived from a corpus is committed to this repository.

_DIR_FLAGS = ("-I", "-isystem", "-iquote", "-idirafter")


def recipe_sha256(decl: dict) -> str:
    return hashlib.sha256(_canonical(decl["build"])).hexdigest()


# The layout of a build cache (bench/dbbuild.py). A cache written in any
# other layout is rebuilt, never read. 2: the build's generated translation
# units are kept too, under UNITS_DIR and in cache.json's generated_units.
BUILD_CACHE_FORMAT = 2
UNITS_DIR = "units"


def build_cache_dir(decl: dict, corpus_commit: str, env_pin: str, bench_root=None) -> Path:
    root = (Path(bench_root) if bench_root else BENCH_ROOT) / ".build-cache"
    return root / f"{decl['corpus']}-{corpus_commit[:12]}-{env_pin[:12]}"


@contextlib.contextmanager
def cache_lock(cache_dir, exclusive: bool):
    """Hold the build cache's lock (`<cache>.lock` beside it): exclusive to
    build or replace it, shared to read it. A builder swaps a rebuilt cache
    in under the exclusive lock, so a reader holding the shared one never
    sees half of one cache and half of another; a scan that starts during a
    rebuild waits for the whole rebuild. A reader whose lock file does not
    exist (no builder has run here yet; the cache directory may be mounted
    read-only) reads unlocked. flock holds only between processes on one
    host, so BENCH_ROOT/.build-cache must be on a local filesystem, not NFS
    shared between machines."""
    import fcntl
    path = Path(cache_dir).with_name(Path(cache_dir).name + ".lock")
    if exclusive:
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(path, "a")
    elif path.is_file():
        fh = open(path, "r")
    else:
        yield
        return
    with fh:
        fcntl.flock(fh, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def check_cache(decl: dict, cache_dir, corpus_commit: str | None = None,
                env_pin: str | None = None) -> tuple[dict, dict, bytes, dict]:
    """The build cache's record, its generated headers' bytes, its
    compile_commands.json bytes and its generated units' bytes, exactly the
    bytes hashed, after
    checking that it is in this layout (BUILD_CACHE_FORMAT) and was built
    from this recipe, for this corpus commit and environment, and that
    every file, generated units included, hashes to what cache.json records.
    Raises FileNotFoundError when there is no cache, ValueError when it is
    not this one or is damaged."""
    cache_dir = Path(cache_dir)
    record_path = cache_dir / "cache.json"
    if not record_path.is_file():
        raise FileNotFoundError(f"no build cache at {cache_dir}")
    record = json.loads(record_path.read_text())
    if record.get("format") != BUILD_CACHE_FORMAT:
        raise ValueError(f"{cache_dir}: cache format {record.get('format', 1)}, not "
                         f"{BUILD_CACHE_FORMAT}; rebuild it")
    if record.get("recipe_sha256") != recipe_sha256(decl):
        raise ValueError(f"{cache_dir}: built from another recipe; rebuild it")
    for key, want in (("corpus_commit", corpus_commit), ("environment", env_pin)):
        if want and record.get(key) != want:
            raise ValueError(f"{cache_dir}: built for {key} {record.get(key)}, not {want}")
    db = cache_dir / "compile_commands.json"
    body = db.read_bytes() if db.is_file() else b""
    got = hashlib.sha256(body).hexdigest() if db.is_file() else "missing"
    if got != record.get("db_sha256"):
        raise ValueError(f"{db}: sha256 {got}, recorded {record.get('db_sha256')}")
    gen_files = {}
    for rel, sha in sorted(record.get("generated", {}).items()):
        f = cache_dir / "generated" / rel
        data = f.read_bytes() if f.is_file() else None
        if data is None or hashlib.sha256(data).hexdigest() != sha:
            raise ValueError(f"{f}: missing or not the recorded generated header")
        gen_files[rel] = data
    unit_files = {}
    for rel, sha in sorted(record.get("generated_units", {}).items()):
        f = cache_dir / UNITS_DIR / rel
        data = f.read_bytes() if f.is_file() else None
        if data is None or hashlib.sha256(data).hexdigest() != sha:
            raise ValueError(f"{f}: missing or not the recorded generated unit")
        unit_files[rel] = data
    return record, gen_files, body, unit_files


def _norm_path(value: str, corpus: str, build: str):
    """`value` with the checkout written ${CORPUS} and the build tree
    ${GEN}/build, or None when it lies outside both (a system directory)."""
    v = posixpath.normpath(value)
    for prefix, token in ((build, "${GEN}/build"), (corpus, "${CORPUS}")):
        if v == prefix or v.startswith(prefix + "/"):
            return token + v[len(prefix):]
    return None


def normalize_db(entries: list[dict], corpus: str, build: str,
                 dropped: set | None = None) -> list[dict]:
    """A compile database (as written on the machine that ran the build) as
    a template: paths tokenized, include directories outside the checkout
    and the build tree dropped, the driver spelled cc, entries sorted.
    A relative include directory is resolved against its entry's directory
    first. An argument that names some other absolute path outside both
    trees is refused, since the template would carry it to every machine.
    `dropped`, when given, collects the include directories left out, for
    a reviewer to check that each is a system directory the set supplies."""
    import shlex
    corpus, build = posixpath.normpath(corpus), posixpath.normpath(build)
    out = []
    for e in entries:
        args = list(e["arguments"]) if "arguments" in e else shlex.split(e["command"])
        directory = posixpath.normpath(e["directory"])
        dir_tok = _norm_path(directory, corpus, build)
        if dir_tok is None:
            raise ValueError(f"entry directory {directory} is outside the checkout and build tree")
        # The driver keeps its name only when it is cl's: aurora-lint reads
        # such an entry with cl's syntax and matches #include names ignoring
        # case, as cl does. Any other driver is spelled cc.
        driver = posixpath.basename(args[0]).lower().removesuffix(".exe")
        norm = [driver if driver in ("cl", "clang-cl") else "cc"]
        i = 1
        while i < len(args):
            a = args[i]
            flag, val, step = None, None, 1
            # None of the four flags is a prefix of another (and -include
            # does not start with -I), so a prefix match is exact.
            for f in _DIR_FLAGS:
                if a == f and i + 1 < len(args):
                    flag, val, step = f, args[i + 1], 2
                    break
                if a.startswith(f) and len(a) > len(f):
                    flag, val, step = f, a[len(f):].lstrip("="), 1
                    break
            if flag:
                path = val if posixpath.isabs(val) else posixpath.join(directory, val)
                tok = _norm_path(path, corpus, build)
                if tok is not None:
                    norm.extend([flag, tok])
                elif dropped is not None:
                    dropped.add(posixpath.normpath(path))
                i += step
                continue
            if posixpath.isabs(a):
                tok = _norm_path(a, corpus, build)
                if tok is None:
                    raise ValueError(f"argument {a!r} names a path outside the "
                                     "checkout and build tree")
                a = tok
            norm.append(a)
            i += 1
        file_path = e["file"] if posixpath.isabs(e["file"]) else posixpath.join(directory, e["file"])
        file_tok = _norm_path(file_path, corpus, build)
        if file_tok is None:
            raise ValueError(f"entry file {file_path} is outside the checkout and build tree")
        out.append({"directory": dir_tok, "file": file_tok, "arguments": norm})
    return sorted(out, key=lambda x: (x["file"], x["arguments"]))


def overlay_source_dirs(template: list[dict], overlay: set[str]) -> list[dict]:
    """After each -I ${CORPUS}/X, add -I ${GEN}/src/X when the build wrote a
    header under X of its copy of the checkout (`overlay`: paths relative
    to the checkout). A scan reads the pristine checkout, so that is where
    the header has to be found instead."""
    dirs = {posixpath.dirname(p) for p in overlay}
    out = []
    for e in template:
        args, norm, i = e["arguments"], [], 0
        while i < len(args):
            norm.append(args[i])
            if args[i] in _DIR_FLAGS and i + 1 < len(args):
                val = args[i + 1]
                norm.append(val)
                if val == "${CORPUS}" or val.startswith("${CORPUS}/"):
                    sub = val[len("${CORPUS}"):].lstrip("/")
                    if sub in dirs:
                        norm.extend([args[i], "${GEN}/src" + (f"/{sub}" if sub else "")])
                i += 2
                continue
            i += 1
        out.append(dict(e, arguments=norm))
    return out


# A directive in a generated unit that names a file: a line marker
# (`#line N "path"`, or GNU's `# N "path"`), or an include, which is how a
# CMake unity unit joins its sources (`#include "/abs/path.c"`).
_LINE_MARKER = re.compile(
    r'^([ \t]*#[ \t]*(?:(?:line[ \t]+)?\d+|include)[ \t]+")([^"\n]*)(")', re.M)


# A directive split over lines with a backslash continuation is not matched,
# and keeps the path it was written with; build systems do not write them.


def directive_paths(text: str) -> list[str]:
    """Every path a unit's line markers and quoted includes name, in order."""
    return [m.group(2) for m in _LINE_MARKER.finditer(text)]


def resolve_unit_path(token: str, corpus: str, root: Path, units: set[str]) -> str:
    """A tokenized path as this machine's file: a kept generated unit
    (`units`: its 'build/<rel>' or 'src/<rel>' keys) at root/units/...,
    any other build-tree file at root/generated/build/..., a header the
    build generated into its checkout copy at root/generated/src/..., and
    the checkout's own files under `corpus`. Anything else as written."""
    for prefix, key in (("${GEN}/build/", "build/"), ("${GEN}/src/", "src/"),
                        ("${CORPUS}/", "src/")):
        if token.startswith(prefix):
            rel = token[len(prefix):]
            if key + rel in units:
                return str(root / UNITS_DIR / key / rel)
            if prefix == "${CORPUS}/":
                return f"{corpus}/{rel}"
            return str(root / "generated" / key / rel)
    return token


def tokenize_line_markers(text: str, corpus: str, build: str,
                          generated_src: set[str] = frozenset()) -> str:
    """A generated unit's line markers and quoted includes with the paths of
    the machine that built it written as tokens, as normalize_db writes the
    database's: a
    file in the build tree ${GEN}/build/..., a file the build generated into
    its copy of the checkout (`generated_src`, relative paths) ${GEN}/src/...,
    and any other file of the checkout ${CORPUS}/.... A path outside both
    trees (a system header) or a relative one is left as written."""
    corpus, build = posixpath.normpath(corpus), posixpath.normpath(build)

    def one(m):
        path = m.group(2)
        if not path.startswith("/"):
            return m.group(0)
        v = posixpath.normpath(path)
        if v.startswith(corpus + "/") and v[len(corpus) + 1:] in generated_src:
            token = "${GEN}/src/" + v[len(corpus) + 1:]
        else:
            token = _norm_path(v, corpus, build)
        return m.group(1) + (token if token else path) + m.group(3)
    return _LINE_MARKER.sub(one, text)


def db_include_dirs(db_path) -> list[str]:
    """The include directories a materialized compile database searches,
    in its own order, each once. aurora-lint appends a database's paths
    AFTER every -I on its command line (src/main.rs), so a benchmark run
    passes these as -I itself, ahead of the dependency set's system
    directories: the corpus's own and generated headers must win over any
    system copy of the same name."""
    out = []
    for e in json.loads(Path(db_path).read_text()):
        args = e["arguments"]
        for flag, val in zip(args, args[1:]):
            if flag in _DIR_FLAGS and val not in out:
                out.append(val)
    return out


def build_id(decl: dict, cache: dict) -> str:
    return f"{decl['corpus']}-{decl['platform']}-{cache['db_sha256'][:8]}"


def materialize(decl: dict, corpus_path, cache_dir, bench_root=None,
                corpus_commit: str | None = None,
                env_pin: str | None = None) -> tuple[Path, dict]:
    """Write the corpus's compile database for this machine from its build
    cache: the template with ${CORPUS} and ${GEN} replaced, and the
    generated headers copied into BENCH_ROOT/build/<id>/generated/, and the
    generated units into BENCH_ROOT/build/<id>/units/ with their line
    markers' tokens replaced the same way. Refuses
    a cache built from another recipe, commit or environment, and any file
    missing or whose sha256 differs from the cache's record.
    Returns the database's path and the cache record."""
    cache_dir = Path(cache_dir)
    # The bytes check_cache hashed, not a second read: without a lock file
    # (an older cache) a second read could come from a cache swapped in since.
    with cache_lock(cache_dir, exclusive=False):
        record, gen_files, body, unit_files = check_cache(decl, cache_dir, corpus_commit,
                                                          env_pin)
    entries = json.loads(body)
    # Every build-tree directory the template searches, whether or not the
    # build generated a header into it: a CMake build adds its binary
    # directories to the search path as a matter of course. The cache holds
    # exactly what the build that wrote the template produced, every file
    # checked by its sha256 above, so an empty one is not a stale one.
    searched = {val[len("${GEN}"):].lstrip("/")
                for e in entries for flag, val in zip(e["arguments"], e["arguments"][1:])
                if flag in _DIR_FLAGS and val.startswith("${GEN}")}
    root = (Path(bench_root) if bench_root else BENCH_ROOT) / "build" / build_id(decl, record)
    gen = root / "generated"
    if root.exists():
        shutil.rmtree(root)
    for rel, data in gen_files.items():
        out = gen / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
    gen.mkdir(parents=True, exist_ok=True)
    for d in searched:
        (gen / d).mkdir(parents=True, exist_ok=True)
    corpus_s, gen_s = str(Path(corpus_path)), str(gen)

    def sub(v: str) -> str:
        return v.replace("${CORPUS}", corpus_s).replace("${GEN}", gen_s)

    units = set(unit_files)

    def resolve(token: str) -> str:
        return resolve_unit_path(token, corpus_s, root, units)

    # An entry compiling a kept generated unit names it where it is written
    # below, so every entry's file exists here.
    db = [{"directory": sub(e["directory"]), "file": resolve(e["file"]),
           "arguments": [sub(a) for a in e["arguments"]]} for e in entries]
    # Generated units, the paths their directives name resolved to this
    # machine's files; nothing else in their text is touched. Not under any
    # directory the database searches: scans do not read them.
    for rel, data in unit_files.items():
        out = root / UNITS_DIR / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        text = _LINE_MARKER.sub(lambda m: m.group(1) + resolve(m.group(2)) + m.group(3),
                                data.decode("utf-8", "surrogateescape"))
        out.write_text(text, encoding="utf-8", errors="surrogateescape")
    path = root / "compile_commands.json"
    path.write_text(json.dumps(db, indent=1))
    return path, record


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
                                          the hash to declare; exit 3 for a
                                          licence-gated set not accepted;
    `python -m bench.deps id NAME`       print the tree id and decl hash;
    `python -m bench.deps spellings PROJECT`
                                          the #include names the corpus's
                                          in-scope files need from a set;
    `python -m bench.deps resolve NAME SPELLING...`
                                          print the pinned 'debs' that
                                          provide those #include names, with
                                          the closure, as JSON."""
    import sys
    args = sys.argv[1:] if argv is None else argv
    if len(args) >= 2 and args[0] == "spellings":
        print("\n".join(spellings(args[1])))
        return 0
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
            try:
                res = fetch(decl)
            except LicenceNotAccepted as e:
                print(e)
                return 3
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
