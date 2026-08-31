"""Verify every real-world benchmark checkout is still sitting on its pinned commit.

Why this exists (task 619): the pinned SHAs were recorded only in
`playbooks/setup-benchmark-repos.yml`, which runs once at provisioning time.
Nothing ever re-checked them, and `bench/realworld_runner.py` records
whatever SHA it finds at scan time rather than asserting the expected one. So a
checkout that drifted -- or was cloned by hand onto a tracking branch and later
pulled -- silently produces findings at (file, line) pairs the `ground_truth`
oracle was never adjudicated against. The oracle is keyed on
project+commit+file+line+rule, so those findings fall outside the
precision/recall denominator in either direction and nothing complains.

This was not hypothetical: on the work node curl, hostap and sqlite had all
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
"""

import fnmatch
import json
import subprocess
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
    """Task 636: is `relpath` (project-relative, as returned by
    BenchDB.project_relpath) inside this project's oracle scope?

    The machine-readable mirror of precision_audit/<project>/README.md's
    '## Scope' section -- see data/benchmark_repos.json's own comment.
    A project with no scope_include declared is unrestricted.
    """
    include, exclude = project_scope(project)
    if not include:
        return True
    if not any(fnmatch.fnmatch(relpath, pat) for pat in include):
        return False
    if exclude and any(fnmatch.fnmatch(relpath, pat) for pat in exclude):
        return False
    return True


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
        "gitignored_scanned": 0,
    }

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

    porcelain = _git(path, "status", "--porcelain") or ""
    for line in porcelain.splitlines():
        code, _, rel = line.partition(" ")
        rel = (rel or line[3:]).strip()
        if line.startswith("??"):
            key = ("untracked_scanned" if rel.endswith(SCANNED_SUFFIXES)
                   else "untracked_ignored")
            res[key] += 1
        else:
            res["dirty"] += 1

    # Ignored files never appear in `git status`, but sqc dispatches on file
    # extension and never consults git -- so a gitignored .c/.h is scanned.
    ignored = _git(path, "ls-files", "--others", "--ignored",
                   "--exclude-standard") or ""
    res["gitignored_scanned"] = sum(
        1 for line in ignored.splitlines()
        if line.strip().endswith(SCANNED_SUFFIXES)
    )
    return res


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


def report(bench_root=None, as_json=False):
    """Print a corpus report. Returns an exit code: 0 clean, 1 problems found."""
    root = Path(bench_root) if bench_root else BENCH_ROOT
    results = check_all(bench_root)
    bad = [r for r in results if r["status"] != "OK"]
    contaminated = [r for r in results
                    if r["dirty"] or r["untracked_scanned"]
                    or r["gitignored_scanned"]]

    if as_json:
        print(json.dumps({
            "bench_root": str(root),
            "bench_root_exists": root.is_dir(),
            "clean": not bad and not contaminated,
            "repos": results,
        }, indent=2))
        return 0 if not bad and not contaminated else 1

    print(f"BENCH_ROOT: {root}"
          f"{'' if root.is_dir() else '   *** DOES NOT EXIST ***'}")
    if not root.is_dir():
        print("  Set SQC_BENCH_ROOT (see .env.example) to the directory "
              "holding the 9 checkouts, or provision it with\n"
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
        print(f"{r['name']:<11} {r['status']:<11} "
              f"{(r['head'] or '-')[:12]:<13} {r['expected'][:12]:<13} "
              f"{'; '.join(notes)}")

    if bad:
        print(f"\n{len(bad)} checkout(s) not pinned:")
        for r in bad:
            print(f"  {r['name']:<11} {r['status']:<11} {_fix_hint(r)}")
    if contaminated:
        print(f"\n{len(contaminated)} checkout(s) with modified or scannable "
              f"untracked files -- scanned source differs from the pin:")
        for r in contaminated:
            print(f"  {r['name']:<11} dirty={r['dirty']} "
                  f"untracked_scanned={r['untracked_scanned']} "
                  f"gitignored_scanned={r['gitignored_scanned']}")
    if not bad and not contaminated:
        print("\nAll 9 checkouts detached at their pinned commits, working "
              "trees clean.")
    else:
        print("\nFindings taken off a non-OK checkout are NOT comparable to "
              "ground_truth,\nwhich is keyed on project+commit+file+line+rule.")
    return 0 if not bad and not contaminated else 1
