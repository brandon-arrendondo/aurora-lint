"""Verify every real-world benchmark checkout is still sitting on its pinned commit.

Why this exists: the pinned SHAs were recorded only in
`playbooks/setup-benchmark-repos.yml`, which runs once at provisioning time.
Nothing ever re-checked them, and `bench/realworld_runner.py` records
whatever SHA it finds at scan time rather than asserting the expected one. So a
checkout that drifted -- or was cloned by hand onto a tracking branch and later
pulled -- silently produces findings at (file, line) pairs the `ground_truth`
oracle was never adjudicated against. The oracle is keyed on
project+commit+file+line+rule, so those findings fall outside the
precision/recall denominator in either direction and nothing complains.

This was not hypothetical: on one machine curl, hostap and sqlite had all
drifted, and libcrc and lua sat on tracking branches matching their pins only
by coincidence. A gate run against the drifted trees reported hostap 452 /
sqlite 516 findings where the pinned snapshots give 447 / 506.

Statuses, worst first:
  MISSING     checkout directory absent
  NOT_GIT     directory exists but is not a git checkout
  PIN_ABSENT  pinned commit not present locally (needs a fetch)
  DRIFTED     HEAD is not the pinned commit
  UNPINNED    HEAD equals the pin but sits on a branch, so the next pull
              silently drifts it -- provisioning leaves a detached HEAD
  OK          detached at the pinned commit

Independently of status, three contamination flags are reported:
  dirty       tracked files modified, so the scanned source is not the pin
  untracked   untracked *.c/*.h files, which sqc WILL scan and attribute to
              the pinned commit. Untracked files sqc ignores (e.g. the
              ~800 *.uncrustify formatter leftovers once found in hostap) are
              counted separately and are harmless.
  ignored     *.c/*.h files present on disk but matched by a .gitignore.
              These are invisible to `git status`, yet sqc scans by file
              extension and does not consult git at all -- so they contaminate
              a scan exactly as much as untracked ones. The motivating case is
              a build run inside a checkout: sqlite's build generates a
              gitignored sqlite3.c amalgamation, which would silently add
              ~250k lines to every sqlite scan.

A corpus that declares a pinned system-header tree (ventoy's Windows SDK/CRT;
see bench/header_tree.py) has it checked too: present under
BENCH_ROOT/header-trees/, with the declared manifest hash. A missing or
different tree fails the check like a drifted commit, since the runner
refuses to scan the corpus without it.

Git submodules are checked the same way. The pinned superproject commit
records each submodule's commit as a gitlink, so a pin implies its
submodules -- but only if they are checked out. A clone that skipped
`git submodule update --init` is on the right superproject commit with the
submodule directory empty, and nothing above notices. mbedtls's `framework`
is the one case: outside the scanned tree, but its build scripts generate
part of library/, so a compile-database build fails without it. Every
gitlink in the pinned tree has to be declared under 'submodules' in
data/benchmark_repos.json (provisioning initialises exactly those), checked
out, at the recorded commit, and unmodified:
  UNINITIALIZED  declared, but the directory holds no checkout
  DRIFTED        checked out at a commit other than the gitlink
  MODIFIED       at the gitlink, with local changes or untracked files
  UNDECLARED     a gitlink in the pin that 'submodules' does not name, so
                 provisioning never initialises it
  NOT_IN_PIN     declared, but the pin has no gitlink at that path
A submodule's own submodules are not checked; none of the corpora has any.

Where the dependency sets have to be depends on how this machine runs
benchmarks, which corpus-check cannot tell from the checkouts, so it is told:
--mode, defaulting to AURORA_BENCH_MODE (set it in the machine's .env), else
'host'.
  host       `bench realworld-run` on this machine reads each set from
             BENCH_ROOT/deps/, so a missing or different set fails.
  container  every run goes through `bench container-run`, whose image
             carries every set. The host sets are not needed and are reported
             as such; instead the image must be present and its environment
             pin must be the manifest_sha256 data/benchmark_environment.json
             declares, or the check fails. A machine that has a matching image
             but scans on the host still needs host mode: the image is not
             what such a scan reads. A pinned header tree that is not a
             dependency set is mounted into the container from the host, so
             it is checked in both modes.

Both untracked and gitignored counts are run through the SAME --exclude-all
globs `bench/realworld_runner.py`'s CODEBASES[...]["sqc"]["extra_args"] passes
to the real scan: a stray .c/.h sitting under a tree the scan leaves out of
everything never reaches the scanner or its cross-file facts, so it is split
into its own harmless bucket instead of being counted as contamination it
cannot actually cause. Only --exclude-all counts: a tree
under --report-exclude (or the deprecated --exclude, which means it) gets no
findings but is still read for cross-file facts, so a generated file there
contaminates the scan as surely as one in plain view.
This is a different mechanism from
in_scope()/scope_include above -- that filters *findings* after the fact;
this filters the *fileset the scan itself walks*, which is what "will this
untracked file get scanned" actually depends on.
"""

import json
import os
import re
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

from bench.config import BENCH_ROOT, PROJECT_DIR

REPOS_JSON = PROJECT_DIR / "data" / "benchmark_repos.json"

# Extensions sqc actually analyzes; an untracked file with one of these is a
# real contamination risk, anything else is inert clutter.
SCANNED_SUFFIXES = (".c", ".h")

_ORDER = ["MISSING", "NOT_GIT", "PIN_ABSENT", "DRIFTED", "UNPINNED", "OK"]


def load_repos():
    """The pinned name/repo/version triples, shared with the ansible playbook."""
    return json.loads(REPOS_JSON.read_text())["repos"]


def project_scope(project):
    """This project's (scope_include, scope_exclude) glob lists, or (None, None)
    if it declares no scope (whole-repo audits: libcrc, raylib)."""
    for e in load_repos():
        if e["name"] == project:
            return e.get("scope_include"), e.get("scope_exclude")
    return None, None


def in_scope(project, relpath):
    """An earlier fix: is `relpath` (project-relative, as returned by
    BenchDB.project_relpath) inside this project's oracle scope?

    The machine-readable mirror of the project's '## Scope' section in
    docs/design/realworld-corpus-scope.md -- see data/benchmark_repos.json's
    own comment.
    A project with no scope_include declared is unrestricted.

    Path-aware globbing: `*`, `?` and `[...]` stop at `/`, and `**` is the only
    way to cross one. Plain `fnmatch` was used here originally and has no
    concept of a path, so `*.c` also matched `testes/libs/lib1.c` -- harmless
    for precision/recall (scope filters findings, and an unscanned file
    produces none) but wrong for any file-count denominator derived from these
    globs. `_translate` below is lifted verbatim from `bench_db/corpus.py`,
    which owns the shared oracle's copy of this predicate: the two MUST agree,
    or a local clone and the shared instance disagree about what is in scope.
    """
    include, exclude = project_scope(project)
    if not include:
        return True
    if not any(_match(relpath, pat) for pat in include):
        return False
    if exclude and any(_match(relpath, pat) for pat in exclude):
        return False
    return True


def _translate(pat: str) -> "re.Pattern":
    """Compile one glob to a full-match regex under the semantics above.

    Hand-written rather than delegating to fnmatch.translate, whose output
    bakes in the `*`-crosses-`/` behaviour this module exists to avoid. The
    `**` cases follow the usual shell/gitignore reading:

      `a/**`     everything beneath a/          -> `a/` + anything
      `a/**/b`   b at any depth beneath a/, b included at depth 1
      `**/b`     b anywhere, including at the root
    """
    i, n, out = 0, len(pat), []
    while i < n:
        ch = pat[i]
        i += 1
        if ch == "*":
            if i < n and pat[i] == "*":          # '**' -- crosses separators
                i += 1
                if i < n and pat[i] == "/":
                    i += 1
                    out.append("(?:.*/)?")       # '**/' may match nothing
                else:
                    out.append(".*")
            else:
                out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        elif ch == "[":
            j = i
            if j < n and pat[j] in "!^":
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            while j < n and pat[j] != "]":
                j += 1
            if j >= n:                            # unterminated: a literal '['
                out.append(r"\[")
            else:
                inner = pat[i:j].replace("\\", r"\\")
                i = j + 1
                if inner[:1] in ("!", "^"):
                    inner = "^" + inner[1:]
                out.append("[" + inner + "]")
        else:
            out.append(re.escape(ch))
    return re.compile("(?s:" + "".join(out) + r")\Z")


@lru_cache(maxsize=512)


@lru_cache(maxsize=512)
def _matcher(pat: str) -> "re.Pattern":
    """_translate, memoised. count_inscope_files runs every glob against every
    file in a checkout -- sqlite is ~5k paths against 14 patterns."""
    return _translate(pat)


def _match(relpath: str, pat: str) -> bool:
    return _matcher(pat).match(relpath) is not None


def _scan_excludes(project):
    """This project's compiled sqc --exclude-all patterns (not
    --report-exclude or the deprecated --exclude, whose files the prescan
    still reads) from bench/realworld_runner.py's
    CODEBASES registry, or [] if the project isn't registered there
    (data/benchmark_repos.json and CODEBASES are expected to agree on names,
    but don't assume it)."""
    from bench.realworld_runner import CODEBASES, _sqc_untouched_patterns
    cfg = CODEBASES.get(project)
    return _sqc_untouched_patterns(cfg) if cfg else []


def _excluded(relpath, patterns):
    return any(p.search(relpath) for p in patterns)


def _git(path, *args):
    """Run a git command in `path`; return stripped stdout, or None on failure."""
    try:
        out = subprocess.run(
            ["git", "-C", str(path), *args],
            capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return out.stdout.strip()


def check_repo(entry, bench_root=None):
    """Inspect one checkout against its pin. Returns a result dict."""
    root = Path(bench_root) if bench_root else BENCH_ROOT
    name, pin = entry["name"], entry["version"]
    path = root / name
    res = {
        "name": name, "path": str(path), "expected": pin,
        "head": None, "branch": None, "status": None,
        "dirty": 0, "untracked_scanned": 0, "untracked_ignored": 0,
        "gitignored_scanned": 0, "untracked_scanned_but_excluded": 0,
        "gitignored_scanned_but_excluded": 0,
        "header_tree": None, "submodules": [],
    }
    if entry.get("deps"):
        # A dependency set (bench/deps.py, docs/adr/0018) is the corpus's
        # system headers for a benchmark run, required like the commit pin.
        # It is reported under the same key as a pinned header tree.
        from bench import deps
        res["header_tree"] = dict(deps.check(deps.load(entry["deps"]), bench_root),
                                  deps=entry["deps"])
    elif entry.get("header_tree"):
        from bench.header_tree import check, resolve
        # Only a declared tree is required. The opt-in trees a host-header
        # corpus can scan against (realworld-run --header-tree) are not.
        res["header_tree"] = check(resolve(entry["header_tree"]), bench_root)

    if not path.is_dir():
        res["status"] = "MISSING"
        return res
    head = _git(path, "rev-parse", "HEAD")
    if head is None:
        res["status"] = "NOT_GIT"
        return res

    res["head"] = head
    # "HEAD" here means a detached HEAD, which is what provisioning leaves.
    branch = _git(path, "rev-parse", "--abbrev-ref", "HEAD")
    res["branch"] = branch

    if head != pin:
        # Distinguish "wrong commit" from "pin was never fetched", which need
        # different fixes (checkout vs. fetch-then-checkout).
        have_pin = _git(path, "cat-file", "-e", f"{pin}^{{commit}}") is not None
        res["status"] = "DRIFTED" if have_pin else "PIN_ABSENT"
    elif branch != "HEAD":
        res["status"] = "UNPINNED"
    else:
        res["status"] = "OK"

    if res["status"] != "PIN_ABSENT":
        res["submodules"] = check_submodules(path, pin, entry.get("submodules", []))

    excludes = _scan_excludes(name)

    sub_paths = {s["path"] for s in res["submodules"]}
    porcelain = _git(path, "status", "--porcelain") or ""
    for line in porcelain.splitlines():
        code, _, rel = line.partition(" ")
        rel = (rel or line[3:]).strip()
        if rel in sub_paths:
            continue  # reported per submodule, not as a modified file
        if line.startswith("??"):
            if not rel.endswith(SCANNED_SUFFIXES):
                res["untracked_ignored"] += 1
            elif _excluded(rel, excludes):
                res["untracked_scanned_but_excluded"] += 1
            else:
                res["untracked_scanned"] += 1
        else:
            res["dirty"] += 1

    # Ignored files never appear in `git status`, but sqc dispatches on file
    # extension and never consults git -- so a gitignored .c/.h is scanned.
    ignored = _git(path, "ls-files", "--others", "--ignored",
                   "--exclude-standard") or ""
    for line in ignored.splitlines():
        rel = line.strip()
        if not rel.endswith(SCANNED_SUFFIXES):
            continue
        if _excluded(rel, excludes):
            res["gitignored_scanned_but_excluded"] += 1
        else:
            res["gitignored_scanned"] += 1
    return res


def _gitlinks(path, commit):
    """{path: commit} for every submodule recorded in `commit`'s tree."""
    out = _git(path, "ls-tree", "-r", "-z", commit) or ""
    links = {}
    for rec in out.split("\0"):
        meta, _, rel = rec.partition("\t")
        mode, _, rest = meta.partition(" ")
        if mode == "160000":
            links[rel] = rest.split()[-1]
    return links


def check_submodules(path, pin, declared):
    """One result per submodule, declared or recorded in `pin`'s tree."""
    links = _gitlinks(path, pin)
    out = []
    for rel in sorted(set(links) | set(declared)):
        sub = Path(path) / rel
        r = {"path": rel, "expected": links.get(rel), "head": None, "status": None}
        out.append(r)
        if rel not in links:
            r["status"] = "NOT_IN_PIN"
            continue
        # An uninitialised submodule is an empty directory, and `git -C` there
        # would answer for the superproject, so look for its own .git first.
        if (sub / ".git").exists():
            r["head"] = _git(sub, "rev-parse", "HEAD")
        if rel not in declared:
            r["status"] = "UNDECLARED"
        elif r["head"] is None:
            r["status"] = "UNINITIALIZED"
        elif r["head"] != links[rel]:
            r["status"] = "DRIFTED"
        elif _git(sub, "status", "--porcelain"):
            r["status"] = "MODIFIED"
        else:
            r["status"] = "OK"
    return out


def submodules_bad(r):
    """The submodules of `r` that are not checked out clean at their gitlink."""
    return [s for s in r["submodules"] if s["status"] != "OK"]


def _submodule_fix_hint(repo_path, s):
    init = f"git -C {repo_path} submodule update --init -- {s['path']}"
    if s["status"] in ("UNINITIALIZED", "DRIFTED"):
        return init
    if s["status"] == "MODIFIED":
        sub = f"{repo_path}/{s['path']}"
        return (f"inspect with git -C {sub} status, then "
                f"git -C {sub} checkout -- . && git -C {sub} clean -fd")
    if s["status"] == "UNDECLARED":
        return ("declare it under 'submodules' in data/benchmark_repos.json, "
                f"then {init}")
    return "remove it from 'submodules' in data/benchmark_repos.json"


def header_tree_bad(r):
    """True if `r` declares a header tree that is needed and not present
    and matching."""
    t = r["header_tree"]
    return bool(t) and t.get("needed", True) and t["status"] != "OK"


MODES = ("host", "container")
MODE_ENV = "AURORA_BENCH_MODE"


def default_mode():
    """AURORA_BENCH_MODE, or 'host'. A value that is neither mode is refused
    rather than read as 'host', which would fail every set on a container
    machine for a typo."""
    mode = os.environ.get(MODE_ENV, "host")
    if mode not in MODES:
        raise ValueError(f"{MODE_ENV}={mode!r}: expected one of {', '.join(MODES)}")
    return mode


def check_image(image, runtime="podman"):
    """Is `image` present, and is its environment pin the declared one?
    'status' is NO_RUNTIME, ABSENT, UNREADABLE, NO_LICENCE_LAYER (the shared
    image alone, without the Win32 corpus's set the licence layer adds),
    MISMATCH or OK."""
    from bench import container, environment
    declared = environment.declared()
    res = {"image": image, "runtime": runtime,
           "expected": declared["manifest_sha256"],
           "actual": None, "status": None}
    if shutil.which(runtime) is None:
        res["status"] = "NO_RUNTIME"
        return res
    exists = subprocess.run([runtime, "image", "exists", image], capture_output=True)
    if exists.returncode != 0:
        res["status"] = "ABSENT"
        return res
    try:
        res["actual"] = container.image_pin(image, runtime)
    except (subprocess.CalledProcessError, IndexError):
        res["status"] = "UNREADABLE"
        return res
    if res["actual"] == res["expected"]:
        res["status"] = "OK"
    elif res["actual"] == declared["shared_manifest_sha256"]:
        res["status"] = "NO_LICENCE_LAYER"
    else:
        res["status"] = "MISMATCH"
    return res


def _image_fix_hint(img):
    if img["status"] == "NO_RUNTIME":
        return f"install {img['runtime']} (see docs/benchmark-setup.rst)"
    if img["status"] == "NO_LICENCE_LAYER":
        return ("build container/licence.Dockerfile on top of it (it accepts "
                "Microsoft's licence terms for this machine; "
                "docs/benchmark-setup.rst), or pass --image")
    if img["status"] == "MISMATCH":
        return ("runs there get their own -env<hash> run id; pull or build the "
                "declared image (docs/benchmark-setup.rst, \"When the image "
                "changes\"), or pass --image")
    return ("pull or build the declared image (docs/benchmark-setup.rst), "
            "or pass --image")


def check_all(bench_root=None):
    """Inspect every pinned checkout, worst status first."""
    results = [check_repo(e, bench_root) for e in load_repos()]
    results.sort(key=lambda r: (_ORDER.index(r["status"]), r["name"]))
    return results


def _fix_hint(r):
    if r["status"] == "MISSING":
        return "run playbooks/setup-benchmark-repos.yml"
    if r["status"] == "NOT_GIT":
        return "remove and re-provision"
    if r["status"] == "PIN_ABSENT":
        return f"git -C {r['path']} fetch --all && git checkout --detach {r['expected'][:12]}"
    if r["status"] in ("DRIFTED", "UNPINNED"):
        return f"git -C {r['path']} checkout --detach {r['expected'][:12]}"
    return ""


def report(bench_root=None, as_json=False, mode=None, image=None,
           runtime="podman"):
    """Print a corpus report. Returns an exit code: 0 clean, 1 problems found.
    `mode` is 'host' or 'container' (default_mode() when None); `image` is
    the benchmark image container mode checks (bench container-run's
    default when None)."""
    root = Path(bench_root) if bench_root else BENCH_ROOT
    mode = mode or default_mode()
    results = check_all(bench_root)
    img = None
    if mode == "container":
        from bench.container import DEFAULT_IMAGE
        img = check_image(image or DEFAULT_IMAGE, runtime)
        for r in results:
            if r["header_tree"] and r["header_tree"].get("deps"):
                r["header_tree"]["needed"] = False
    bad = [r for r in results if r["status"] != "OK"]
    bad_trees = [r for r in results if header_tree_bad(r)]
    contaminated = [r for r in results
                    if r["dirty"] or r["untracked_scanned"]
                    or r["gitignored_scanned"]]
    bad_subs = [r for r in results if submodules_bad(r)]
    bad_image = bool(img) and img["status"] != "OK"
    clean = (not bad and not bad_trees and not contaminated and not bad_subs
             and not bad_image)

    if as_json:
        print(json.dumps({
            "bench_root": str(root),
            "bench_root_exists": root.is_dir(),
            "mode": mode,
            "image": img,
            "clean": clean,
            "repos": results,
        }, indent=2))
        return 0 if clean else 1

    print(f"BENCH_ROOT: {root}"
          f"{'' if root.is_dir() else '   *** DOES NOT EXIST ***'}")
    print(f"mode: {mode}"
          + (f"   image {img['image']}: {img['status']}" if img else ""))
    if not root.is_dir():
        print("  Set SQC_BENCH_ROOT (see .env.example) to the directory "
              f"holding the {len(results)} checkouts, or provision it with\n"
              "  playbooks/setup-benchmark-repos.yml.")
    print()
    print(f"{'project':<11} {'status':<11} {'head':<13} {'expected':<13} notes")
    for r in results:
        notes = []
        if r["branch"] and r["branch"] != "HEAD":
            notes.append(f"on branch {r['branch']}")
        if r["dirty"]:
            notes.append(f"{r['dirty']} tracked file(s) modified")
        if r["untracked_scanned"]:
            notes.append(f"{r['untracked_scanned']} untracked .c/.h WILL be scanned")
        if r["gitignored_scanned"]:
            notes.append(f"{r['gitignored_scanned']} gitignored .c/.h WILL be scanned")
        if r["untracked_ignored"]:
            notes.append(f"{r['untracked_ignored']} untracked (not scanned)")
        if r["untracked_scanned_but_excluded"]:
            notes.append(f"{r['untracked_scanned_but_excluded']} untracked "
                         "under a scan --exclude-all (harmless)")
        if r["header_tree"] and not r["header_tree"].get("needed", True):
            notes.append("dependency set not needed (container runs use the "
                         "image's sets)")
        elif r["header_tree"]:
            notes.append(f"header tree {r['header_tree']['status']}")
        for sm in r["submodules"]:
            notes.append(f"submodule {sm['path']} {sm['status']}")
        if r["gitignored_scanned_but_excluded"]:
            notes.append(f"{r['gitignored_scanned_but_excluded']} gitignored "
                         "under a scan --exclude-all (harmless)")
        print(f"{r['name']:<11} {r['status']:<11} "
              f"{(r['head'] or '-')[:12]:<13} {r['expected'][:12]:<13} "
              f"{'; '.join(notes)}")

    if bad:
        print(f"\n{len(bad)} checkout(s) not pinned:")
        for r in bad:
            print(f"  {r['name']:<11} {r['status']:<11} {_fix_hint(r)}")
    if bad_trees:
        from bench import deps
        from bench.header_tree import fix_hint
        print(f"\n{len(bad_trees)} pinned header tree(s) missing or different:")
        for r in bad_trees:
            t = r["header_tree"]
            got = (f"manifest {t['actual'][:12]}, expected {(t['expected'] or 'none')[:12]}"
                   if t["actual"] else "not present")
            hint = deps.fix_hint(t["deps"]) if t.get("deps") else fix_hint(r["name"])
            print(f"  {r['name']:<11} {t['status']:<11} {t['path']} ({got})\n"
                  f"  {'':<11} {hint}")
        if mode == "host" and any(r["header_tree"].get("deps") for r in bad_trees):
            print("  A machine that runs benchmarks only through `bench "
                  "container-run` uses the\n  image's sets instead: pass --mode "
                  f"container, or set {MODE_ENV}=container in its .env.")
    if bad_image:
        print(f"\nBenchmark image {img['image']} {img['status']}"
              + (f": environment {img['actual'][:12]}, declared "
                 f"{img['expected'][:12]}" if img["actual"] else "")
              + f"\n  {_image_fix_hint(img)}")
    if bad_subs:
        print(f"\n{len(bad_subs)} checkout(s) with a submodule missing or "
              "not at the commit the pin records:")
        for r in bad_subs:
            for sm in submodules_bad(r):
                print(f"  {r['name']:<11} {sm['status']:<13} {sm['path']} "
                      f"(head {(sm['head'] or '-')[:12]}, gitlink "
                      f"{(sm['expected'] or '-')[:12]})\n"
                      f"  {'':<11} {_submodule_fix_hint(r['path'], sm)}")
    if contaminated:
        print(f"\n{len(contaminated)} checkout(s) with modified or scannable "
              f"untracked files -- scanned source differs from the pin:")
        for r in contaminated:
            print(f"  {r['name']:<11} dirty={r['dirty']} "
                  f"untracked_scanned={r['untracked_scanned']} "
                  f"gitignored_scanned={r['gitignored_scanned']}")
    if clean:
        print(f"\nAll {len(results)} checkouts detached at their pinned "
              "commits, submodules checked out, working trees clean.")
    else:
        print("\nFindings taken off a non-OK checkout are NOT comparable to "
              "ground_truth,\nwhich is keyed on project+commit+file+line+rule.")
    return 0 if clean else 1
