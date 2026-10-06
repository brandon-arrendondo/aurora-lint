"""Pinned system-header trees: a real-world corpus's platform headers, pinned
and verified the way its source checkout is.

There are two kinds, sharing the hash, the verification and the provenance
below. ventoy's Windows SDK/CRT tree (this docstring's first half) supplies
headers a Linux node does not have at all. The Debian tree (the 'debs'
section further down) stands in for the host's own /usr/include on the
corpora whose runner config passes -I /usr/include (curl, hostap,
mosquitto, sqlite, valkey): which -dev packages a host happens to have
installed, not only their versions, moves those corpora's findings, so a
run that must not depend on the host can read one pinned set instead. A
tree that 'replaces' a prefix rewrites the corpus's own -I flags into the tree
(substitute_includes); a tree without one appends its include_dirs.

Trees can be declared inline on a corpus (ventoy) or once in the top-level
'header_trees' map. ventoy's tree is required: no host has the Windows
headers, so the runner refuses to scan it without the tree. The Debian
trees are OPT-IN. A corpus whose runner config reads the host's headers
names that prefix under 'host_headers', and by default it is scanned
against the host's own /usr/include, as official runs are (the benchmark
node's headers are its environment of record; docs/adr/0004).
`realworld-run --header-tree ID` scans those corpora against a named tree
that replaces the same prefix instead, to reproduce another node's
environment or to take the host out of an A/B; such a run gets its own
run id (-hdr-ID), so it never overwrites the default run.

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


# Names a tree in the top-level 'header_trees' map to scan the host-header
# corpora against instead of the host's own headers (`realworld-run
# --header-tree`). Only a tree that replaces the corpus's 'host_headers'
# prefix may stand in.
HOST_TREE_ENV = "SQC_BENCH_HEADER_TREE"

# The tree id of the default: this host's own headers. Accepted as a
# --header-tree value too, meaning the same as passing none.
HOST = "host"


def _repos() -> dict:
    return json.loads(REPOS_JSON.read_text())


def tree_spec(tree_id: str, data=None) -> dict:
    """The entry `tree_id` of the top-level 'header_trees' map."""
    trees = (data or _repos()).get("header_trees", {})
    if tree_id not in trees:
        raise KeyError(f"no header tree '{tree_id}' in {REPOS_JSON} "
                       f"(declared: {', '.join(sorted(trees)) or 'none'})")
    return trees[tree_id]


def host_spec(prefix: str) -> dict:
    """The spec of a scan against this host's own headers under `prefix`."""
    return {"id": HOST, "host": True, "replaces": prefix, "hashed_dirs": [],
            "manifest_sha256": None, "include_dirs": [],
            "fetch": {"kind": "host"}}


def resolve(decl, data=None):
    """A corpus's 'header_tree' declaration as a spec dict, or None.

    A dict is the spec itself (ventoy's Windows tree). A string names an
    entry of the top-level 'header_trees' map."""
    if decl is None or isinstance(decl, dict):
        return decl
    return tree_spec(decl, data)


def spec_for(project: str, override=None):
    """The header tree `project` scans against, or None if it reads no
    system headers the runner knows of.

    A declared 'header_tree' is always used. A corpus that reads the host's
    headers ('host_headers') gets the host spec, or the named tree
    `override` (default $SQC_BENCH_HEADER_TREE), which must replace the same
    prefix."""
    if override is None:
        override = os.environ.get(HOST_TREE_ENV) or None
    data = _repos()
    for entry in data["repos"]:
        if entry["name"] != project:
            continue
        if entry.get("header_tree"):
            return resolve(entry["header_tree"], data)
        prefix = entry.get("host_headers")
        if not prefix:
            return None
        if not override or override == HOST:
            return host_spec(prefix)
        alt = tree_spec(override, data)
        if alt.get("replaces") != prefix:
            raise ValueError(f"header tree '{override}' replaces "
                             f"{alt.get('replaces')}, not {project}'s {prefix}")
        return alt
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
    if spec.get("host"):
        return {"id": HOST, "path": spec.get("replaces"), "expected": None,
                "actual": None, "status": OK}
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


def substitute_includes(spec: dict, includes: list[str], bench_root=None) -> list[str]:
    """Rewrite a corpus's -I list for a tree that 'replaces' a host prefix.

    Every `-I <prefix>[/sub]` becomes `-I <tree>/<prefix>[/sub]`, so the scan
    reads the pinned copy of exactly the directories it used to read on the
    host. The tree's own 'include_dirs' (the multiarch directory, which a
    compiler searches before /usr/include) go in just before the first
    rewritten path. A list with nothing under the prefix comes back as is."""
    if spec.get("host"):
        return list(includes)
    prefix = spec["replaces"].rstrip("/")
    root = tree_path(spec, bench_root)
    out, extra_done = [], False
    i = 0
    while i < len(includes):
        flag = includes[i]
        val = includes[i + 1] if flag == "-I" and i + 1 < len(includes) else None
        if val is not None and (val == prefix or val.startswith(prefix + "/")):
            if not extra_done:
                for d in spec.get("include_dirs", []):
                    out.extend(["-I", str(root / d)])
                extra_done = True
            out.extend(["-I", str(root / val.lstrip("/"))])
            i += 2
            continue
        out.append(flag)
        i += 1
    return out


def provenance(spec: dict) -> dict:
    """What a scan records about the tree it ran against: the declaration
    minus the -I plumbing. The hash is the one the scan verified."""
    if spec.get("host"):
        return {"id": HOST, "host": True, "replaces": spec.get("replaces")}
    out = {"id": spec["id"], "fetch": spec["fetch"],
           "hashed_dirs": spec["hashed_dirs"],
           "manifest_sha256": spec["manifest_sha256"]}
    if "replaces" in spec:
        out["replaces"] = spec["replaces"]
    return out


# -- 'debs' trees: Debian packages, fetched and unpacked without dpkg --------
#
# A tree whose fetch kind is "debs" is the usr/include/ of a fixed list of
# Debian binary packages, each named by package, version and architecture
# and pinned by the sha256 of its .deb. The URLs are snapshot.debian.org
# file URLs, which do not expire the way a mirror's pool does when a
# security update supersedes a version. Fetching needs only the standard
# library (an ar reader and tarfile), so a macOS, Fedora or FreeBSD node
# provisions the same tree a Debian one does.

SNAPSHOT = "https://snapshot.debian.org"


def _sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ar_members(data: bytes):
    """(name, bytes) for each member of a Unix ar archive (a .deb)."""
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    pos = 8
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[:16].decode("ascii").strip().rstrip("/")
        size = int(hdr[48:58].decode("ascii").strip())
        pos += 60
        yield name, data[pos:pos + size]
        pos += size + (size % 2)


def _within(rel: str) -> bool:
    norm = os.path.normpath(rel)
    return not (norm == ".." or norm.startswith("../") or os.path.isabs(norm))


def _inside(dest_real: Path, path: Path) -> bool:
    """Whether `path` lands inside `dest_real` once every symlink that
    already exists along it is followed. A path that does not exist yet is
    judged by its nearest existing ancestor, the part a later mkdir or
    write would follow."""
    probe = path
    while not (probe.exists() or probe.is_symlink()):
        if probe.parent == probe:
            return False
        probe = probe.parent
    real = probe.resolve()
    return real == dest_real or dest_real in real.parents


def _prepare_parent(dest_real: Path, out: Path) -> None:
    """Create `out`'s parent directories, refusing if any step of the way
    resolves outside the tree (a link chain such as a -> ../.. then
    b -> a/.. reads as inside but lands outside)."""
    if not _inside(dest_real, out.parent):
        raise ValueError(f"path leaves the tree through a symlink: {out}")
    out.parent.mkdir(parents=True, exist_ok=True)
    if not _inside(dest_real, out.parent):
        raise ValueError(f"path leaves the tree through a symlink: {out}")


def extract_headers(deb_bytes: bytes, dest, prefix: str = "usr/include") -> int:
    """Unpack the members of a .deb's data tarball that lie under `prefix`
    into `dest`. Returns the number of files and links written.

    Every member name is normalized before it is tested against `prefix`,
    so `usr/include/../../x` is judged as `x`. Refused: a member that would
    land outside `dest` by name or by following a symlink already in the
    tree, an absolute or escaping symlink target, and a file another
    package already wrote with different bytes (dpkg would refuse that
    overlap too). Devices, FIFOs and other special members are skipped, and
    no mode bits are applied."""
    import io
    import tarfile
    payload = None
    for name, body in ar_members(deb_bytes):
        if name.startswith("data.tar"):
            if name.endswith(".zst"):
                raise ValueError("zstd-compressed .deb: not readable with the "
                                 "standard library; pin an xz-compressed build")
            payload = body
            break
    if payload is None:
        raise ValueError("no data.tar member in .deb")
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_real = dest.resolve()
    written = 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tar:
        for m in tar.getmembers():
            raw = m.name[2:] if m.name.startswith("./") else m.name
            if os.path.isabs(raw) or not _within(raw):
                raise ValueError(f"member escapes the tree: {m.name}")
            rel = os.path.normpath(raw)
            if not (rel == prefix or rel.startswith(prefix + "/")):
                continue
            out = dest / rel
            if m.isdir():
                _prepare_parent(dest_real, out)
                if out.is_symlink() and not _inside(dest_real, out):
                    raise ValueError(f"path leaves the tree through a symlink: {out}")
                out.mkdir(exist_ok=True)
            elif m.issym():
                target = os.path.join(os.path.dirname(rel), m.linkname)
                if os.path.isabs(m.linkname) or not _within(target):
                    raise ValueError(f"symlink leaves the tree: {m.name} -> {m.linkname}")
                _prepare_parent(dest_real, out)
                if out.is_symlink() or out.exists():
                    if out.is_symlink() and os.readlink(out) == m.linkname:
                        continue
                    raise ValueError(f"two packages provide {rel} differently")
                os.symlink(m.linkname, out)
                written += 1
            elif m.isfile() or m.islnk():
                if m.islnk():
                    src_name = m.linkname[2:] if m.linkname.startswith("./") else m.linkname
                    if os.path.isabs(src_name) or not _within(src_name):
                        raise ValueError(f"hardlink leaves the tree: {m.name} -> {m.linkname}")
                    src = tar.extractfile(tar.getmember(m.linkname))
                else:
                    src = tar.extractfile(m)
                body = src.read()
                _prepare_parent(dest_real, out)
                if out.is_symlink():
                    raise ValueError(f"two packages provide {rel} differently")
                if out.exists():
                    if out.is_file() and out.read_bytes() == body:
                        continue
                    raise ValueError(f"two packages provide {rel} differently")
                out.write_bytes(body)
                written += 1
    return written


def _download(url: str, dest: Path) -> None:
    import urllib.request
    tmp = dest.with_name(dest.name + ".part")
    try:
        with urllib.request.urlopen(url, timeout=120) as resp, open(tmp, "wb") as fh:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                fh.write(chunk)
        tmp.replace(dest)
    finally:
        tmp.unlink(missing_ok=True)


def fetch(spec: dict, bench_root=None, log=print) -> dict:
    """Provision a 'debs' tree: download every pinned .deb (reusing a cached
    copy whose sha256 matches), check each hash, unpack usr/include into a
    staging directory, verify the manifest hash and move the tree into
    place. Raises on any hash mismatch and leaves no partial tree behind."""
    import shutil
    if spec["fetch"].get("kind") != "debs":
        raise ValueError(f"{spec['id']}: only 'debs' trees are fetched here")
    root = trees_root(bench_root)
    dest = tree_path(spec, bench_root)
    stage = root / f".{spec['id']}.partial"
    cache = root / ".deb-cache"
    cache.mkdir(parents=True, exist_ok=True)
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    try:
        for deb in spec["fetch"]["debs"]:
            f = cache / deb["file"]
            if not (f.is_file() and _sha256_file(f) == deb["sha256"]):
                log(f"  fetch {deb['file']}")
                _download(deb["url"], f)
            got = _sha256_file(f)
            if got != deb["sha256"]:
                raise ValueError(f"{deb['file']}: sha256 {got}, pinned {deb['sha256']}")
            extract_headers(f.read_bytes(), stage)
        actual = manifest_sha256(stage, spec["hashed_dirs"])
        if actual != spec["manifest_sha256"]:
            raise ValueError(f"{spec['id']}: unpacked tree has manifest hash "
                             f"{actual}, pinned {spec['manifest_sha256']}")
        if dest.exists():
            shutil.rmtree(dest)
        stage.rename(dest)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return check(spec, bench_root)


def pin_debs(specs: list[str], arch: str = "amd64", log=print) -> list[dict]:
    """Resolve PACKAGE=VERSION strings against snapshot.debian.org into the
    'debs' entries a tree declares: the .deb's file name, its stable
    snapshot URL and its sha256 (computed from the download, since the
    archive itself publishes sha1). For writing a new pin, not for scans."""
    import tempfile
    import urllib.request
    out = []
    for s in specs:
        pkg, ver = s.split("=", 1)
        with urllib.request.urlopen(
                f"{SNAPSHOT}/mr/binary/{pkg}/{ver}/binfiles?fileinfo=1", timeout=60) as r:
            info = json.load(r)["fileinfo"]
        hit = None
        for sha1, entries in sorted(info.items()):
            for e in entries:
                if e["archive_name"] in ("debian", "debian-security") and (
                        e["name"].endswith(f"_{arch}.deb") or e["name"].endswith("_all.deb")):
                    hit = (sha1, e["name"])
                    break
            if hit:
                break
        if hit is None:
            raise LookupError(f"{s}: no {arch} or all .deb on {SNAPSHOT}")
        url = f"{SNAPSHOT}/file/{hit[0]}"
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / hit[1]
            _download(url, f)
            sha = _sha256_file(f)
        log(f"  {hit[1]} {sha}")
        out.append({"package": pkg, "version": ver, "file": hit[1],
                    "url": url, "sha256": sha})
    return out


def fix_hint(project: str) -> str:
    spec = spec_for(project)
    if spec and spec["fetch"].get("kind") == "debs":
        return (f"provision it with: python -m bench.header_tree fetch {spec['id']}   "
                f"(see docs/benchmark-setup.rst), or drop --header-tree to scan "
                f"against this host's own headers")
    return (f"provision it with: ansible-playbook playbooks/setup-benchmark-repos.yml "
            f"-i 'localhost,' -c local -e accept_microsoft_license=true "
            f"--tags header-trees   (corpus '{project}'; see docs/benchmark-setup.rst)")


def _spec_arg(name: str):
    """A CLI argument naming either a tree in 'header_trees' or a corpus that
    declares one."""
    data = _repos()
    if name in data.get("header_trees", {}):
        return tree_spec(name, data)
    spec = spec_for(name, override="")
    return None if spec is None or spec.get("host") else spec


def main(argv=None) -> int:
    """`python -m bench.header_tree verify NAME` exits 0 if the tree NAME
    names (a tree id, or a corpus that declares a tree) is present with the
    declared hash, 1 otherwise;
    `python -m bench.header_tree hash NAME DIR` prints the manifest hash of
    the tree at DIR over NAME's hashed_dirs -- the value to declare when
    re-pinning;
    `python -m bench.header_tree fetch NAME` provisions a 'debs' tree
    (download, sha256 check, unpack, verify);
    `python -m bench.header_tree pin PKG=VER ...` prints the 'debs' entries
    for a new pin, resolved against snapshot.debian.org (amd64)."""
    import sys
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 2 or args[0] not in ("verify", "hash", "fetch", "pin"):
        print(main.__doc__)
        return 2
    if args[0] == "pin":
        print(json.dumps(pin_debs(args[1:], log=lambda m: print(m, file=sys.stderr)),
                         indent=2))
        return 0
    spec = _spec_arg(args[1])
    if spec is None:
        trees = ", ".join(sorted(_repos().get("header_trees", {}))) or "none"
        print(f"{args[1]}: no header tree declared in {REPOS_JSON} (a corpus "
              f"that reads host headers declares none: name a tree, one of "
              f"{trees})")
        return 2
    if args[0] == "hash":
        if len(args) != 3:
            print(main.__doc__)
            return 2
        print(manifest_sha256(args[2], spec["hashed_dirs"]))
        return 0
    if args[0] == "fetch":
        res = check(spec)
        if res["status"] != OK:
            res = fetch(spec)
    else:
        res = check(spec)
    print(f"{args[1]}: {res['status']} {res['path']}"
          + (f" (manifest {res['actual']}, expected {res['expected']})"
             if res["status"] == MISMATCH else ""))
    return 0 if res["status"] == OK else 1


if __name__ == "__main__":
    raise SystemExit(main())
