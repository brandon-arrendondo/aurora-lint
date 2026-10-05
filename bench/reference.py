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


def scan(binary: Path, bid: str, repo: dict, root: Path, jobs: int,
         timeout: int) -> dict:
    """Run one binary over one checkout, cached by (binary hash, pin)."""
    path = root / repo["name"]
    out = OUT_DIR / "scans" / bid / f"{repo['name']}-{repo['commit'][:12]}.json"
    if out.exists():
        return json.loads(out.read_text())
    out.parent.mkdir(parents=True, exist_ok=True)
    export = out.with_suffix(".raw.json")
    cmd = [str(binary), str(path), "--manifest", str(MANIFEST),
           "--export", str(export), "--jobs", str(jobs),
           "--profile", DEFAULT_PROFILE, "-d", str(path)]
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        status = "ok" if export.exists() else f"exit {proc.returncode}: {proc.stderr.strip()[-300:]}"
    except subprocess.TimeoutExpired:
        status = f"timeout after {timeout}s"
    result = {"status": status, "seconds": round(time.monotonic() - start, 1),
              "findings": []}
    if status == "ok":
        result["findings"] = [_normalize(v, path) for v in json.loads(export.read_text())]
        export.unlink()
    # A failed scan is not cached: it may be the environment, not the binary.
    if status == "ok":
        out.write_text(json.dumps(result))
    return result


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
                 "base_total": len(b["findings"]), "target_total": len(t["findings"])}
        if b["status"] == "ok" and t["status"] == "ok":
            entry.update(diff(b["findings"], t["findings"]))
        per_codebase[name] = entry
    report = {"base": {"path": str(base_bin), "sha256_12": bid},
              "target": {"path": str(target_bin), "sha256_12": tid},
              "manifest": str(MANIFEST.relative_to(PROJECT_DIR)),
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
    for name, why in failures:
        print(f"FAILED {name}: {why}")
