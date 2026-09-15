"""Parallel CWE benchmark runner with SQLite output.

Replaces scripts/run_juliet_parallel.sh with structured error handling,
direct DB writes, and resume support.
"""

import os
import re
import subprocess
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from datetime import datetime, timezone
from pathlib import Path

from bench.analyzer import analyze_shard, merge_shards
from bench.config import (
    DEFAULT_JOBS, GENERATE_MAP_SCRIPT, JULIET_BASE, MANIFEST_JULIET_FULL,
    MANIFEST_CWE_DIR, RULE_CWE_MAP, SQC_BIN,
    JULIET_COMPILE_DB, apply_run_suffix,
)
from bench.db import BenchDB
from bench.machine import get_machine_metadata

# Below this file count, a CWE stays monolithic: the per-shard overhead
# (a full `-d <cwe_dir>` prescan repeated per shard, ~20s measured on
# CWE-121) isn't worth it, and it keeps the vast majority of CWEs on the
# simple single-subprocess path. Set comfortably below the smallest of the
# 3 long-pole CWEs this was scoped for (CWE-190 at 5040 files) while still
# covering the next tier down (task 388; docs/design/juliet-cwe-sharding.md).
SHARD_MIN_FILES = 1500


def _get_sqc_version() -> str:
    """Read sqc version from Cargo.toml."""
    cargo = Path(__file__).resolve().parent.parent / "Cargo.toml"
    try:
        for line in cargo.read_text().splitlines():
            m = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "unknown"


def _get_git_sha() -> str:
    """Get short git commit SHA."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True,
            cwd=Path(__file__).resolve().parent.parent,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _ensure_rule_cwe_map() -> None:
    """Regenerate rule-CWE map and per-CWE manifests if the script exists."""
    if GENERATE_MAP_SCRIPT.exists():
        try:
            subprocess.run(
                ["python3", str(GENERATE_MAP_SCRIPT)],
                capture_output=True, text=True, timeout=30,
            )
        except Exception:
            pass


def _resolve_manifest(cwe_dir_name: str, fast_mode: bool) -> str | None:
    """Resolve the rules manifest for a CWE directory.

    Returns manifest path, or None to skip this CWE (fast mode, no manifest).
    """
    if fast_mode:
        m = re.match(r'CWE(\d+)', cwe_dir_name)
        if m:
            manifest = MANIFEST_CWE_DIR / f"CWE-{m.group(1)}.toml"
            if manifest.exists():
                return str(manifest)
        return None  # Skip in fast mode if no per-CWE manifest
    return str(MANIFEST_JULIET_FULL)


def _enumerate_cwes() -> list[str]:
    """List all CWE directory names under the Juliet testcases dir."""
    if not JULIET_BASE.is_dir():
        return []
    return sorted(
        entry.name for entry in JULIET_BASE.iterdir()
        if entry.is_dir() and entry.name.startswith("CWE")
    )


def _count_c_files(cwe_dir: Path) -> int:
    """Count .c files in a CWE directory (including subdirectories)."""
    return sum(1 for _ in cwe_dir.rglob("*.c"))


def _extract_cwe_id(dirname: str) -> str:
    """Extract normalized CWE-NNN from directory name."""
    m = re.match(r'CWE(\d+)', dirname)
    if m:
        return f"CWE-{m.group(1)}"
    return dirname


def _cwe_shard_dirs(cwe_dir: Path) -> list[Path] | None:
    """Return this CWE's `sNN` sub-shard dirs, or None if it should stay
    monolithic (no split, or only one subdir -- sharding into one shard
    buys nothing)."""
    subdirs = sorted(p for p in cwe_dir.glob('s*') if p.is_dir())
    return subdirs if len(subdirs) >= 2 else None

# ── Shard worker ──────────────────────────────────────────────────────────────
# One shard is either a single `sNN` subdirectory (a large CWE, split) or an
# entire CWE dir (the common case, unsplit) -- callers treat both uniformly,
# submitting shard_count(cwe) futures per CWE and merging them once all land
# (task 388). No DB writes happen here: multiple shards of the same CWE
# would race on the same `cwe_scans` row (UNIQUE(run_id, cwe_dir_name)), so
# writing is deferred to the coordinator after `merge_shards`.

def _prescan_args(cwe_dir_str: str, compile_db: str | None) -> list[str]:
    """The cross-file context arguments every scan of a CWE shares: the whole
    CWE dir plus Juliet's support library, and the compile database if the
    run has one."""
    args = [
        "-d", cwe_dir_str,
        "-d", str(JULIET_BASE.parent / "testcasesupport"),
    ]
    if compile_db:
        args.extend(["--compile-commands", compile_db])
    return args


def _warm_prescan(cwe_dir_name: str, cwe_dir_str: str, manifest: str,
                  cache_path: str, compile_db: str | None = None) -> dict:
    """Build a sharded CWE's cross-file context once and save it for its
    shards to load (`--save-prescan`).

    Runs in a worker process. The scan target is an empty directory, so the
    process does nothing but the prescan and the save. The manifest is the
    shards' own: whether any enabled rule needs VRA changes what the prescan
    computes, so a cache built under a different manifest would not be the
    context a shard's live prescan builds.
    """
    start_time = time.monotonic()
    empty_dir = tempfile.mkdtemp(prefix=f"{cwe_dir_name}_warm_")
    try:
        cmd = [
            str(SQC_BIN), empty_dir,
            "-m", manifest,
            *_prescan_args(cwe_dir_str, compile_db),
            "--save-prescan", cache_path,
            "-e", os.devnull,
            "-j", "1",
        ]
        proc = subprocess.run(cmd, capture_output=True, timeout=3600)
        duration_s = round(time.monotonic() - start_time, 1)
        if proc.returncode != 0 or not os.path.isfile(cache_path):
            return {
                "cwe_dir_name": cwe_dir_name, "status": "failed",
                "duration_s": duration_s,
                "error": proc.stderr.decode(errors="replace")[:500]
                or "prescan cache was not written",
            }
        return {"cwe_dir_name": cwe_dir_name, "status": "completed",
                "duration_s": duration_s}
    except subprocess.TimeoutExpired:
        return {"cwe_dir_name": cwe_dir_name, "status": "failed",
                "duration_s": round(time.monotonic() - start_time, 1),
                "error": "timeout (3600s)"}
    except Exception as e:
        return {"cwe_dir_name": cwe_dir_name, "status": "failed",
                "duration_s": round(time.monotonic() - start_time, 1),
                "error": str(e)[:500]}
    finally:
        try:
            os.rmdir(empty_dir)
        except OSError:
            pass


def _scan_one_shard(cwe_dir_name: str, cwe_id: str, cwe_dir_str: str,
                    shard_dir_str: str, manifest: str, scan_id: int,
                    keep_csv: bool = False, compile_db: str | None = None,
                    prescan_cache: str | None = None) -> dict:
    """Scan one shard: run sqc, parse its own CSV into a raw ShardPartial.

    Runs in a worker process. A shard of a split CWE loads the context its
    CWE's `_warm_prescan` saved (`--load-prescan`), so cross-file resolution
    matches the monolithic path exactly while the whole-CWE prescan runs
    once per CWE rather than once per shard. Task 388 measured that prescan
    at ~0.8% of a big CWE's time and repeated it per shard to skip this
    warm step; once the per-file scan got an order of magnitude cheaper
    (the Juliet wall-clock regression task and its follow-ups), the repeated
    prescan was most of a shard's time -- 11s of a 12s CWE-78 shard.
    An unsplit CWE (no cache) still prescans its own directory (`-d`).
    """
    cwe_dir = Path(cwe_dir_str)
    shard_dir = Path(shard_dir_str)
    csv_fd, csv_path = tempfile.mkstemp(suffix=".csv", prefix=f"{cwe_dir_name}_{shard_dir.name}_")
    os.close(csv_fd)

    start_time = time.monotonic()
    try:
        cmd = [
            str(SQC_BIN), str(shard_dir),
            "-m", manifest,
        ]
        if prescan_cache:
            cmd.extend(["--load-prescan", prescan_cache])
        else:
            cmd.extend(_prescan_args(str(cwe_dir), compile_db))
        cmd.extend(["-e", csv_path, "-j", "1"])
        proc = subprocess.run(cmd, capture_output=True, timeout=3600)
        duration_s = round(time.monotonic() - start_time, 1)

        if proc.returncode != 0:
            return {
                "cwe_dir_name": cwe_dir_name, "shard_name": shard_dir.name,
                "status": "failed", "duration_s": duration_s,
                "error": proc.stderr.decode(errors="replace")[:500],
            }

        violation_count = 0
        try:
            with open(csv_path) as f:
                violation_count = max(0, sum(1 for _ in f) - 1)
        except Exception:
            pass

        partial = analyze_shard(csv_path, shard_dir, cwe_id, cwe_dir_name, scan_id)

        return {
            "cwe_dir_name": cwe_dir_name, "shard_name": shard_dir.name,
            "status": "completed", "duration_s": duration_s,
            "violation_count": violation_count, "partial": partial,
        }
    except subprocess.TimeoutExpired:
        return {
            "cwe_dir_name": cwe_dir_name, "shard_name": shard_dir.name,
            "status": "failed", "duration_s": round(time.monotonic() - start_time, 1),
            "error": "timeout (3600s)",
        }
    except Exception as e:
        return {
            "cwe_dir_name": cwe_dir_name, "shard_name": shard_dir.name,
            "status": "failed", "duration_s": round(time.monotonic() - start_time, 1),
            "error": str(e)[:500],
        }
    finally:
        if not keep_csv:
            try:
                os.unlink(csv_path)
            except OSError:
                pass


def _finish_cwe(db: BenchDB, scan_map: dict, cwe_dir_name: str,
                shard_results: list[dict], warm_duration_s: float) -> str:
    """Merge a CWE's landed shards and write its rows once. Returns the
    DONE line's payload."""
    scan_id = scan_map[cwe_dir_name]
    cwe_id = _extract_cwe_id(cwe_dir_name)
    analysis = merge_shards(
        cwe_id, cwe_dir_name, [r["partial"] for r in shard_results])

    db.insert_violations(analysis.violations)
    db.insert_cwe_metrics({
        "cwe_scan_id": scan_id,
        "tp_count": analysis.tp_count,
        "fp_count": analysis.fp_count,
        "tp_rate_pct": analysis.tp_rate_pct,
        "flaw_lines_total": analysis.flaw_lines_total,
        "flaw_lines_detected": analysis.flaw_lines_detected,
        "flaw_detection_rate_pct": analysis.flaw_detection_rate_pct,
        "cwe_matched_tp": analysis.cwe_matched_tp,
        "cwe_matched_fp": analysis.cwe_matched_fp,
        "noise_count": analysis.noise_count,
        "noise_ratio": analysis.noise_ratio,
        "per_file_detected": analysis.per_file_detected,
        "per_file_total": analysis.per_file_total,
        "per_file_rate": analysis.per_file_rate,
        "flaw_hit_detected": analysis.flaw_hit_detected,
        "flaw_hit_total": analysis.flaw_hit_total,
        "flaw_hit_rate": analysis.flaw_hit_rate,
    })
    rule_rows = [
        {
            "cwe_scan_id": scan_id, "rule_id": rule_id,
            "tp_count": counts["tp"], "fp_count": counts["fp"],
            "flaw_line_count": counts["flaw"],
            "is_cwe_matched": counts["is_cwe_matched"],
        }
        for rule_id, counts in analysis.rule_breakdown.items()
    ]
    db.insert_rule_breakdown(rule_rows)

    # Sum, not max: this CWE's stored duration_s becomes summed subprocess
    # time across its shards plus the warm prescan step, same as how the
    # run-level analysis_s already exceeds wall_s under CWE-level
    # parallelism (bench/db.py sums this same field across CWEs). A sharded
    # CWE's *wall*-clock benefit shows up in the run's total wall_s, not in
    # its own duration_s -- don't read a flat/higher duration_s here as
    # "sharding didn't help" (task 388). With the shared cache the
    # whole-CWE prescan is counted once per CWE rather than once per shard,
    # which is a real drop in the work done, not an accounting change.
    total_duration_s = round(
        warm_duration_s + sum(r["duration_s"] for r in shard_results), 1)
    total_violations = sum(r["violation_count"] for r in shard_results)
    db.update_cwe_scan(scan_id, status="completed",
                       violation_count=total_violations,
                       duration_s=total_duration_s,
                       file_count=analysis.files_analyzed)

    shard_note = f" ({len(shard_results)} shards)" if len(shard_results) > 1 else ""
    return (f"{cwe_dir_name}{shard_note} | {total_duration_s}s | "
            f"{total_violations} violations | {analysis.files_analyzed} files")


def _build_submissions(work_items: list[tuple]) -> tuple[list[dict], dict]:
    """Expand the work list into pool submissions, largest first.

    Returns the submissions and, per CWE, how many of them it has."""
    # Expand each CWE into 1+ shard submissions (task 388): a large CWE
    # (>= SHARD_MIN_FILES, with sNN subdirs) becomes one submission per sNN
    # dir; everything else stays a single submission for the whole CWE dir.
    # Sharded or not, every submission is scheduled the same way — LPT by
    # its own file count — so a big CWE's shards compete fairly for pool
    # slots against smaller CWEs instead of being bound to one slot each.
    submissions = []
    shard_counts = {}  # cwe_dir_name -> total shard submissions expected

    for cwe_dir_name, cwe_id, manifest, file_count in work_items:
        cwe_dir = JULIET_BASE / cwe_dir_name
        shard_dirs = _cwe_shard_dirs(cwe_dir) if file_count >= SHARD_MIN_FILES else None
        if shard_dirs:
            shard_counts[cwe_dir_name] = len(shard_dirs)
            for shard_dir in shard_dirs:
                shard_file_count = sum(1 for _ in shard_dir.glob("*.c"))
                submissions.append({
                    "cwe_dir_name": cwe_dir_name, "cwe_id": cwe_id,
                    "cwe_dir": cwe_dir, "shard_dir": shard_dir,
                    "manifest": manifest, "sort_key": shard_file_count,
                })
        else:
            shard_counts[cwe_dir_name] = 1
            submissions.append({
                "cwe_dir_name": cwe_dir_name, "cwe_id": cwe_id,
                "cwe_dir": cwe_dir, "shard_dir": cwe_dir,
                "manifest": manifest, "sort_key": file_count,
            })

    submissions.sort(key=lambda s: s["sort_key"], reverse=True)
    return submissions, shard_counts



def _run_submissions(db: BenchDB, run_id: str, scan_map: dict, work_items: list[tuple],
                     submissions: list[dict], shard_counts: dict, jobs: int,
                     keep_csv: bool, compile_db: str | None,
                     already_done: int, total_cwes: int) -> tuple[int, int]:
    """Drive the worker pool until every submission has landed and every
    CWE's rows are written. Returns (completed, failed) CWE counts."""
    # A split CWE's shards load one shared prescan cache, built by a warm
    # submission that must land before its shards are submitted. Warm steps
    # go into the pool first (largest CWE first, like everything else) and
    # the unsplit CWEs fill the remaining slots meanwhile; each CWE's shards
    # are submitted the moment its warm step returns.
    cache_dir = tempfile.mkdtemp(prefix=f"{run_id}_prescan_")
    warm_items = []  # (cwe_dir_name, cwe_dir, manifest), largest first
    for cwe_dir_name, cwe_id, manifest, file_count in work_items:
        if shard_counts[cwe_dir_name] > 1:
            warm_items.append((cwe_dir_name, JULIET_BASE / cwe_dir_name, manifest))
    prescan_caches = {
        name: os.path.join(cache_dir, f"{name}.prescan")
        for name, _, _ in warm_items
    }

    def _discard_cache(cwe_dir_name: str) -> None:
        cache = prescan_caches.get(cwe_dir_name)
        if cache:
            try:
                os.unlink(cache)
            except OSError:
                pass

    # Run in parallel
    completed = 0
    failed = 0
    pending = {}  # cwe_dir_name -> [shard result dict, ...], until all land
    warm_duration = {}  # cwe_dir_name -> the warm step's subprocess seconds
    shard_failed = set()  # cwe_dir_name already marked failed; drop late siblings

    def _fail_cwe(cwe_dir_name: str, detail: str) -> None:
        nonlocal failed
        shard_failed.add(cwe_dir_name)
        pending.pop(cwe_dir_name, None)
        _discard_cache(cwe_dir_name)
        failed += 1
        db.update_cwe_scan(scan_map[cwe_dir_name], status="failed")
        print(f"FAIL: {cwe_dir_name} | {detail}")

    with ProcessPoolExecutor(max_workers=jobs) as executor:
        futures = {}  # future -> ("warm" | "shard", cwe_dir_name)

        def _submit_shard(sub: dict) -> None:
            scan_id = scan_map[sub["cwe_dir_name"]]
            future = executor.submit(
                _scan_one_shard, sub["cwe_dir_name"], sub["cwe_id"],
                str(sub["cwe_dir"]), str(sub["shard_dir"]), sub["manifest"],
                scan_id, keep_csv, compile_db,
                prescan_caches.get(sub["cwe_dir_name"]),
            )
            futures[future] = ("shard", sub["cwe_dir_name"])

        for cwe_dir_name, cwe_dir, manifest in warm_items:
            future = executor.submit(
                _warm_prescan, cwe_dir_name, str(cwe_dir), manifest,
                prescan_caches[cwe_dir_name], compile_db,
            )
            futures[future] = ("warm", cwe_dir_name)
        for sub in submissions:
            if sub["cwe_dir_name"] not in prescan_caches:
                _submit_shard(sub)

        while futures:
            done, _ = wait(list(futures), return_when=FIRST_COMPLETED)
            for future in done:
                kind, cwe_dir_name = futures.pop(future)
                if cwe_dir_name in shard_failed:
                    continue  # sibling of an already-failed CWE; drop it

                try:
                    result = future.result()
                except Exception as e:
                    _fail_cwe(cwe_dir_name, str(e))
                    continue

                if kind == "warm":
                    if result["status"] != "completed":
                        _fail_cwe(cwe_dir_name,
                                  f"prescan | {result.get('error', 'unknown')}")
                        continue
                    warm_duration[cwe_dir_name] = result["duration_s"]
                    for sub in submissions:
                        if sub["cwe_dir_name"] == cwe_dir_name:
                            _submit_shard(sub)
                    continue

                if result["status"] != "completed":
                    _fail_cwe(cwe_dir_name,
                              f"({result['shard_name']}) {result.get('error', 'unknown')}")
                    continue

                pending.setdefault(cwe_dir_name, []).append(result)
                if len(pending[cwe_dir_name]) < shard_counts[cwe_dir_name]:
                    continue  # more shards still in flight for this CWE

                # All shards for this CWE have landed — merge and write once.
                shard_results = pending.pop(cwe_dir_name)
                _discard_cache(cwe_dir_name)
                note = _finish_cwe(db, scan_map, cwe_dir_name, shard_results,
                                   warm_duration.get(cwe_dir_name, 0.0))
                completed += 1
                print(f"DONE [{completed + already_done}/{total_cwes}]: {note}")

    try:
        os.rmdir(cache_dir)
    except OSError:
        pass

    return completed, failed


# ── Main runner ───────────────────────────────────────────────────────────────

def run_benchmark(fast: bool = True, jobs: int = DEFAULT_JOBS,
                  keep_csv: bool = False, compile_commands: bool = False) -> str:
    """Run a full Juliet benchmark.

    Args:
        fast: Use per-CWE manifests (default True).
        jobs: Number of parallel workers.
        keep_csv: Retain temp CSV files after analysis.
        compile_commands: Pass ``--compile-commands`` to sqc, using the
            synthesized Juliet compile database. Off by default, so a plain
            run is unchanged. When on, the run_id is suffixed so a with/without
            pair on the same sqc build stays two distinct, comparable runs.

    Returns:
        The run_id for the completed benchmark.
    """
    if not SQC_BIN.exists():
        raise FileNotFoundError(f"aurora-lint binary not found at {SQC_BIN}. Run 'cargo build --release' first.")
    if not JULIET_BASE.is_dir():
        raise FileNotFoundError(f"Juliet test suite not found at {JULIET_BASE}.")

    # Fail loudly rather than silently running without the database — a run
    # that quietly ignored the flag would be indistinguishable from a real
    # "compile DB made no difference" result.
    compile_db = None
    if compile_commands:
        if not JULIET_COMPILE_DB.is_file():
            raise FileNotFoundError(
                f"--compile-commands requested but no compile database at {JULIET_COMPILE_DB}. "
                f"Generate it with: python3 scripts/generate_juliet_compile_commands.py"
            )
        compile_db = str(JULIET_COMPILE_DB)

    _ensure_rule_cwe_map()

    version = _get_sqc_version()
    sha = _get_git_sha()
    run_id = apply_run_suffix(f"sqc-{version}-{sha}", compile_commands)
    mode = "fast" if fast else "full"
    if compile_commands:
        mode += " +compile-db"
    started_at = datetime.now(timezone.utc).isoformat()
    machine = get_machine_metadata()

    db = BenchDB()

    # Check for existing run — support resume
    existing = db.get_run(run_id)
    if existing and existing["status"] == "completed":
        print(f"Run {run_id} already completed. Use a new version/commit for a fresh run.")
        return run_id

    all_cwes = _enumerate_cwes()
    if not all_cwes:
        raise RuntimeError(f"No CWE directories found under {JULIET_BASE}")

    # Build work list: resolve manifests, skip already-completed
    completed_cwes = db.get_completed_cwes(run_id) if existing else set()
    work_items = []

    for cwe_dir_name in all_cwes:
        if cwe_dir_name in completed_cwes:
            continue
        manifest = _resolve_manifest(cwe_dir_name, fast)
        if manifest is None:
            continue  # Skip in fast mode
        file_count = _count_c_files(JULIET_BASE / cwe_dir_name)
        cwe_id = _extract_cwe_id(cwe_dir_name)
        work_items.append((cwe_dir_name, cwe_id, manifest, file_count))

    # Longest-processing-time-first: submit the biggest CWEs first so they
    # start at t=0 instead of whenever their name comes up alphabetically.
    # The largest CWEs dominate wall-clock (task 388) — starting them last
    # means workers idle waiting on a straggler that could have started
    # 30+ minutes earlier. file_count is an imperfect proxy for scan time
    # but a far better signal than sorted-CWE-name order.
    work_items.sort(key=lambda item: item[3], reverse=True)

    total_cwes = len(work_items) + len(completed_cwes)

    # Create or update run record
    if not existing:
        db.create_run(run_id, version, sha, mode, started_at,
                      os.getpid(), jobs, total_cwes, machine)
    else:
        db.update_run_status(run_id, "running")

    # Create cwe_scan records for new work items
    scan_map = {}  # cwe_dir_name -> scan_id
    for cwe_dir_name, cwe_id, manifest, file_count in work_items:
        scan_id = db.create_cwe_scan(run_id, cwe_id, cwe_dir_name, file_count)
        scan_map[cwe_dir_name] = scan_id
        db.update_cwe_scan(scan_id, status="running")

    print(f"{'='*70}")
    print(f"BENCHMARK: {run_id} ({mode} mode)")
    print(f"CWEs: {len(work_items)} to scan, {len(completed_cwes)} already done | Jobs: {jobs}")
    print(f"{'='*70}")

    submissions, shard_counts = _build_submissions(work_items)
    completed, failed = _run_submissions(
        db, run_id, scan_map, work_items, submissions, shard_counts,
        jobs, keep_csv, compile_db, len(completed_cwes), total_cwes,
    )

    # Finalize
    finished_at = datetime.now(timezone.utc).isoformat()
    final_status = "completed" if failed == 0 else "completed"  # still mark complete even with some failures
    db.finish_run(run_id, final_status, finished_at)

    print(f"\n{'='*70}")
    print(f"BENCHMARK COMPLETE: {run_id}")
    print(f"Completed: {completed + len(completed_cwes)} | Failed: {failed} | Total: {total_cwes}")
    print(f"{'='*70}")

    return run_id
