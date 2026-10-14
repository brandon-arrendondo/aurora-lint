"""Held-out reference corpus: fetch pinned codebases and A/B two binaries over them.

The oracle corpora (data/benchmark_repos.json) are what rules get tuned and
adjudicated against, so a change can look clean there while it moves findings
on code nobody has looked at. This corpus is the check for that. It carries no
labels and no per-codebase tuning, and it answers only one question: which
findings did the change add or remove, per rule and per codebase, and in rules
it was not meant to touch? See docs/design/reference-corpus-ab.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from bench.config import BENCH_ROOT, DEFAULT_PROFILE, PROJECT_DIR, SQC_BIN

CORPUS_FILE = PROJECT_DIR / "data" / "reference_corpus.json"
MANIFEST = PROJECT_DIR / "rules_templates" / "rules-all.toml"
OUT_DIR = PROJECT_DIR / "data" / "reference_ab"
TIERS = ("quick", "standard", "large")
# What a shadow scan may read besides the checkout's own sources: its own
# headers and the host's system headers, and no other dependency (Brandon,
# 2026-10-13). Part of the cache key, so changing it never reuses a scan.
INCLUDES = "own+system"


# The large tier's scans peak near 12 GB resident at 8 threads, so a node
# with less RAM than this scans it with fewer threads unless told otherwise.
LARGE_TIER_RAM_GIB = 16


def total_ram_gib() -> float | None:
    try:
        return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / 2**30
    except (AttributeError, ValueError, OSError):
        return None


def jobs_for(repos: list[dict], requested: int | None) -> int:
    """Scan threads for an A/B: the requested count, or min(CPUs, 8), halved
    when the selection includes the large tier on a node with under
    LARGE_TIER_RAM_GIB of RAM. Either way, a small node is warned."""
    default = min(os.cpu_count() or 4, 8)
    ram = total_ram_gib()
    if not any(r["tier"] == "large" for r in repos) or ram is None \
            or ram >= LARGE_TIER_RAM_GIB:
        return requested or default
    jobs = requested or max(1, default // 2)
    print(f"warning: the large tier's scans can peak near 12 GB resident and "
          f"this node has {ram:.0f} GiB of RAM; scanning with --jobs {jobs}"
          + ("" if requested else " (pass --jobs to override)"),
          file=sys.stderr)
    return jobs


def default_root() -> Path:
    return BENCH_ROOT / "shadow_corpus"


def shadow_names() -> set[str]:
    return {r["name"] for r in json.loads(CORPUS_FILE.read_text())["repos"]}


def load(tier: str = "quick", names: list[str] | None = None) -> list[dict]:
    """Repos for a tier selection; each tier includes the ones before it."""
    repos = json.loads(CORPUS_FILE.read_text())["repos"]
    if names:
        known = {r["name"] for r in repos}
        unknown = sorted(set(names) - known)
        if unknown:
            raise SystemExit(f"unknown reference codebase(s): {', '.join(unknown)}")
        return [r for r in repos if r["name"] in names]
    if tier == "all":
        return repos
    allowed = TIERS[:TIERS.index(tier) + 1]
    return [r for r in repos if r["tier"] in allowed]


def _git(path: Path, *args: str, check: bool = True) -> str:
    proc = subprocess.run(["git", "-C", str(path), *args],
                          capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} in {path}: {proc.stderr.strip()}")
    return proc.stdout.strip()


def _at_pin(path: Path, commit: str) -> bool:
    if not (path / ".git").exists():
        return False
    return (_git(path, "rev-parse", "HEAD", check=False) == commit
            and _git(path, "status", "--porcelain", "--untracked-files=all", check=False) == "")


def fetch(repo: dict, root: Path) -> str:
    """Shallow-fetch exactly the pinned commit and detach on it."""
    path = root / repo["name"]
    if _at_pin(path, repo["commit"]):
        return "ok"
    path.mkdir(parents=True, exist_ok=True)
    if not (path / ".git").exists():
        _git(path, "init", "-q")
        _git(path, "remote", "add", "origin", repo["repo"])
    _git(path, "fetch", "-q", "--depth", "1", "origin", repo["commit"])
    _git(path, "checkout", "-q", "--force", "--detach", repo["commit"])
    _git(path, "clean", "-qfdx")
    if not _at_pin(path, repo["commit"]):
        raise RuntimeError(f"{repo['name']}: not at {repo['commit']} after fetch")
    return "fetched"


def binary_id(binary: Path) -> str:
    h = hashlib.sha256()
    with open(binary, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:12]


def settings_id() -> str:
    """What a scan read besides the binary and the checkout: the manifest's
    content, the profile and the include configuration. A cached scan made under other settings is not
    the same measurement, even from the same binary at the same pin."""
    h = hashlib.sha256(MANIFEST.read_bytes())
    h.update(DEFAULT_PROFILE.encode())
    h.update(INCLUDES.encode())
    return h.hexdigest()[:12]


def scan(binary: Path, bid: str, repo: dict, root: Path, jobs: int,
         timeout: int) -> dict:
    """Run one binary over one checkout, cached by (binary hash, settings, pin)."""
    path = root / repo["name"]
    out = (OUT_DIR / "scans" / bid / settings_id()
           / f"{repo['name']}-{repo['commit'][:12]}.json")
    if out.exists():
        return json.loads(out.read_text())
    out.parent.mkdir(parents=True, exist_ok=True)
    export = out.with_suffix(".raw.json")
    headers = out.with_suffix(".headers.json")
    cmd = [str(binary), str(path), "--manifest", str(MANIFEST),
           "--export", str(export), "--jobs", str(jobs),
           "--profile", DEFAULT_PROFILE, "-d", str(path),
           "--system-includes"]
    for d in own_include_dirs(path):
        cmd += ["-I", str(d)]
    if _reports_headers(binary):
        cmd += ["--report-headers", str(headers)]
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        status = "ok" if export.exists() else f"exit {proc.returncode}: {proc.stderr.strip()[-300:]}"
    except subprocess.TimeoutExpired:
        status = f"timeout after {timeout}s"
    result = {"status": status, "seconds": round(time.monotonic() - start, 1),
              "headers": _headers(headers), "findings": []}
    headers.unlink(missing_ok=True)
    if status == "ok":
        result["findings"] = [_normalize(v, path) for v in json.loads(export.read_text())]
        export.unlink()
    # A failed scan is not cached: it may be the environment, not the binary.
    if status == "ok":
        out.write_text(json.dumps(result))
    return result


def own_include_dirs(path: Path) -> list[Path]:
    """Every directory of the checkout that holds a header, shallowest first.

    A shadow codebase gets no build recipe or compile database, so nothing
    says which of its directories are include roots. Searching all of them
    gives every codebase the same configuration: its own headers, found
    wherever they are, and nothing from outside it but the host's system
    headers (--system-includes). Where two directories hold a header of the
    same name, the shallower one wins, which is what a top-level -I usually
    means. A miss is reported, never fixed for.
    """
    dirs = set()
    for root, subdirs, files in os.walk(path):
        subdirs[:] = [d for d in subdirs if d != ".git"]
        if any(f.endswith((".h", ".H", ".hh", ".hpp")) for f in files):
            dirs.add(Path(root))
    return sorted(dirs, key=lambda d: (len(d.relative_to(path).parts), str(d)))


def _reports_headers(binary: Path) -> bool:
    """Whether this binary has --report-headers. A base built at an older
    release may not, and passing it an unknown flag would fail the scan."""
    proc = subprocess.run([str(binary), "--help"], capture_output=True, text=True)
    return "--report-headers" in proc.stdout


def _headers(report: Path) -> dict:
    """How much of a scan's #include resolution happened. Shadow scans run
    with whatever headers the host has and are never fixed for a missing one
    (ADR-0018), so the report has to say what was missing. A report with no
    search path and no forced include is read as resolution not attempted,
    which is what such a scan meant for older binaries, so an empty list is
    never taken to mean every header was found."""
    if not report.exists():
        return {}
    data = json.loads(report.read_text())
    attempted = bool(data.get("search_paths") or data.get("forced_includes"))
    if not attempted:
        return {"attempted": False, "unresolved": None}
    # Distinct headers a project file names, as the scan's own "Headers:"
    # line counts them; one named only inside a system header is the host's.
    sites = Counter(u["spelling"] for u in data.get("unresolved", [])
                    if not u.get("includer_outside_project"))
    return {"attempted": True, "unresolved": len(sites),
            "top": [name for name, _ in sites.most_common(5)]}


def _normalize(v: dict, root: Path) -> dict:
    f = v.get("file", "")
    try:
        f = str(Path(f).resolve().relative_to(root.resolve()))
    except ValueError:
        pass
    return {"rule": v.get("rule_id", "unknown"), "file": f,
            "line": v.get("line", 0), "column": v.get("column", 0),
            "message": v.get("message", "")}


def _key(f: dict) -> tuple:
    return (f["rule"], f["file"], f["line"], f["column"])


def diff(base: list[dict], target: list[dict]) -> dict:
    """Multiset diff on (rule, file, line, column); same key, new text is 'changed'."""
    bk, tk = Counter(map(_key, base)), Counter(map(_key, target))
    removed_keys, added_keys = bk - tk, tk - bk
    by_key_b = defaultdict(list)
    for f in base:
        by_key_b[_key(f)].append(f)
    by_key_t = defaultdict(list)
    for f in target:
        by_key_t[_key(f)].append(f)
    removed = [f for k, n in removed_keys.items() for f in by_key_b[k][:n]]
    added = [f for k, n in added_keys.items() for f in by_key_t[k][:n]]
    changed = []
    for k in bk.keys() & tk.keys():
        bm = sorted(f["message"] for f in by_key_b[k])
        tm = sorted(f["message"] for f in by_key_t[k])
        if bm != tm:
            changed.append({"key": list(k), "base": bm, "target": tm})
    return {"added": added, "removed": removed, "changed": changed}


def run_ab(base_bin: Path, target_bin: Path, repos: list[dict], root: Path,
           intended: set[str], jobs: int, timeout: int) -> Path:
    for b in (base_bin, target_bin):
        if not b.is_file():
            raise SystemExit(f"binary not found: {b}")
    bid, tid = binary_id(base_bin), binary_id(target_bin)
    if bid == tid:
        print("warning: base and target are byte-identical binaries", file=sys.stderr)
    per_codebase = {}
    for i, repo in enumerate(repos, 1):
        name = repo["name"]
        print(f"[{i}/{len(repos)}] {name}", file=sys.stderr, flush=True)
        try:
            fetch(repo, root)
        except RuntimeError as e:
            per_codebase[name] = {"error": f"fetch: {e}"}
            continue
        b = scan(base_bin, bid, repo, root, jobs, timeout)
        t = scan(target_bin, tid, repo, root, jobs, timeout)
        entry = {"commit": repo["commit"], "domain": repo["domain"],
                 "base_status": b["status"], "target_status": t["status"],
                 "headers": t.get("headers") or b.get("headers"),
                 "base_total": len(b["findings"]), "target_total": len(t["findings"])}
        if b["status"] == "ok" and t["status"] == "ok":
            entry.update(diff(b["findings"], t["findings"]))
        per_codebase[name] = entry
    report = {"base": {"path": str(base_bin), "sha256_12": bid},
              "target": {"path": str(target_bin), "sha256_12": tid},
              "manifest": str(MANIFEST.relative_to(PROJECT_DIR)),
              "settings_id": settings_id(),
              "intended_rules": sorted(intended),
              "codebases": per_codebase}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"ab-{bid}-{tid}.json"
    out.write_text(json.dumps(report, indent=1))
    print_summary(report)
    return out


def print_summary(report: dict) -> None:
    intended = set(report["intended_rules"])
    rules: dict[str, dict] = defaultdict(lambda: {"added": 0, "removed": 0, "codebases": set()})
    failures, changed = [], 0
    for name, e in report["codebases"].items():
        if "error" in e or e["base_status"] != "ok" or e["target_status"] != "ok":
            failures.append((name, e.get("error") or f"base: {e['base_status']} / target: {e['target_status']}"))
            continue
        changed += len(e["changed"])
        for side in ("added", "removed"):
            for f in e[side]:
                r = rules[f["rule"]]
                r[side] += 1
                r["codebases"].add(name)
    ok = len(report["codebases"]) - len(failures)
    print(f"\nreference A/B  base {report['base']['sha256_12']}  ->  "
          f"target {report['target']['sha256_12']}   ({ok} codebases compared)")
    if not rules:
        print("no findings added or removed")
    else:
        print(f"\n{'rule':<14}{'added':>8}{'removed':>9}{'codebases':>11}")
        for rule, r in sorted(rules.items(), key=lambda kv: -(kv[1]["added"] + kv[1]["removed"])):
            flag = "" if not intended or rule in intended else "   <- not an intended rule"
            print(f"{rule:<14}{r['added']:>8}{r['removed']:>9}{len(r['codebases']):>11}{flag}")
    if changed:
        print(f"\n{changed} finding(s) kept their location but changed message text")
    _print_headers(report)
    for name, why in failures:
        print(f"FAILED {name}: {why}")


def _print_headers(report: dict) -> None:
    """Missing headers, said where nobody can scroll past them."""
    skipped, missing = [], []
    for name, e in report["codebases"].items():
        h = e.get("headers") or {}
        if not h:
            continue
        if not h.get("attempted"):
            skipped.append(name)
        elif h.get("unresolved"):
            missing.append((name, h["unresolved"]))
    if not (skipped or missing):
        return
    print("\nHEADERS: these scans did not see every header their code includes; "
          "findings that depend on them can differ on another host")
    if skipped:
        print(f"  no search path, include resolution not counted: "
              f"{len(skipped)} codebase(s)")
    for name, n in sorted(missing, key=lambda m: -m[1]):
        top = ", ".join((report["codebases"][name].get("headers") or {}).get("top", []))
        print(f"  {name}: {n} header(s) not found" + (f" ({top}, ...)" if n > 5 else f" ({top})" if top else ""))
