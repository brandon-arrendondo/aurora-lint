"""Parallel CWE benchmark runner with SQLite output.

Replaces scripts/run_juliet_parallel.sh with structured error handling,
direct DB writes, and resume support.
"""

import os
import re
import subprocess
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from bench.analyzer import analyze_cwe
from bench.config import (
    DEFAULT_JOBS, GENERATE_MAP_SCRIPT, JULIET_BASE, MANIFEST_ALL,
    MANIFEST_CWE_DIR, RULE_CWE_MAP, SQC_BIN, DB_PATH,
    JULIET_COMPILE_DB, apply_run_suffix,
)
from bench.db import BenchDB
from bench.machine import get_machine_metadata


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
    return str(MANIFEST_ALL)


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


# ── Single CWE worker ─────────────────────────────────────────────────────────

def _scan_single_cwe(db_path: str, run_id: str, scan_id: int,
                     cwe_dir_name: str, manifest: str,
                     keep_csv: bool, compile_db: str | None = None) -> dict:
    """Scan a single CWE: run sqc, analyze, write results to DB.

    This runs in a worker process. Opens its own DB connection (WAL safe).
    Returns a summary dict for logging.
    """
    db = BenchDB(db_path)
    cwe_dir = JULIET_BASE / cwe_dir_name

    db.update_cwe_scan(scan_id, status="running")

    # Create a temp CSV for sqc output
    csv_fd, csv_path = tempfile.mkstemp(suffix=".csv", prefix=f"{cwe_dir_name}_")
    os.close(csv_fd)

    start_time = time.monotonic()
    try:
        # Run sqc
        cmd = [
            str(SQC_BIN), str(cwe_dir),
            "-m", manifest,
            "-d", str(cwe_dir),
            "-d", str(JULIET_BASE.parent / "testcasesupport"),
            "-e", csv_path,
            "-j", "1",  # single-threaded: runner parallelizes at CWE level
        ]
        if compile_db:
            cmd.extend(["--compile-commands", compile_db])
        proc = subprocess.run(
            cmd, capture_output=True, timeout=3600,
        )
        duration_s = round(time.monotonic() - start_time, 1)

        if proc.returncode != 0:
            db.update_cwe_scan(scan_id, status="failed", duration_s=duration_s)
            return {
                "cwe": cwe_dir_name, "status": "failed",
                "error": proc.stderr.decode(errors="replace")[:500],
                "duration_s": duration_s,
            }

        # Count violations from CSV
        violation_count = 0
        try:
            with open(csv_path) as f:
                violation_count = max(0, sum(1 for _ in f) - 1)  # -1 for header
        except Exception:
            pass

        # Analyze
        analysis = analyze_cwe(csv_path, cwe_dir, cwe_scan_id=scan_id)

        # Write violations to DB
        db.insert_violations(analysis.violations)

        # Write CWE metrics
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

        # Write per-rule breakdown
        rule_rows = []
        for rule_id, counts in analysis.rule_breakdown.items():
            rule_rows.append({
                "cwe_scan_id": scan_id,
                "rule_id": rule_id,
                "tp_count": counts["tp"],
                "fp_count": counts["fp"],
                "flaw_line_count": counts["flaw"],
                "is_cwe_matched": counts["is_cwe_matched"],
            })
        db.insert_rule_breakdown(rule_rows)

        # Update scan record
        db.update_cwe_scan(scan_id,
                           status="completed",
                           violation_count=violation_count,
                           duration_s=duration_s,
                           file_count=analysis.files_analyzed)

        return {
            "cwe": cwe_dir_name,
            "status": "completed",
            "duration_s": duration_s,
            "violations": violation_count,
            "files": analysis.files_analyzed,
            "tp": analysis.tp_count,
            "fp": analysis.fp_count,
        }

    except subprocess.TimeoutExpired:
        duration_s = round(time.monotonic() - start_time, 1)
        db.update_cwe_scan(scan_id, status="failed", duration_s=duration_s)
        return {"cwe": cwe_dir_name, "status": "failed",
                "error": "timeout (3600s)", "duration_s": duration_s}
    except Exception as e:
        duration_s = round(time.monotonic() - start_time, 1)
        db.update_cwe_scan(scan_id, status="failed", duration_s=duration_s)
        return {"cwe": cwe_dir_name, "status": "failed",
                "error": str(e)[:500], "duration_s": duration_s}
    finally:
        if not keep_csv:
            try:
                os.unlink(csv_path)
            except OSError:
                pass


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
        raise FileNotFoundError(f"sqc binary not found at {SQC_BIN}. Run 'cargo build --release' first.")
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

    print(f"{'='*70}")
    print(f"BENCHMARK: {run_id} ({mode} mode)")
    print(f"CWEs: {len(work_items)} to scan, {len(completed_cwes)} already done | Jobs: {jobs}")
    print(f"{'='*70}")

    # Run in parallel
    completed = 0
    failed = 0
    db_path_str = str(DB_PATH)

    with ProcessPoolExecutor(max_workers=jobs) as executor:
        futures = {}
        for cwe_dir_name, cwe_id, manifest, file_count in work_items:
            scan_id = scan_map[cwe_dir_name]
            future = executor.submit(
                _scan_single_cwe, db_path_str, run_id, scan_id,
                cwe_dir_name, manifest, keep_csv, compile_db,
            )
            futures[future] = cwe_dir_name

        for future in as_completed(futures):
            cwe_name = futures[future]
            try:
                result = future.result()
                if result["status"] == "completed":
                    completed += 1
                    print(f"DONE [{completed + len(completed_cwes)}/{total_cwes}]: "
                          f"{cwe_name} | {result['duration_s']}s | "
                          f"{result['violations']} violations | {result['files']} files")
                else:
                    failed += 1
                    print(f"FAIL: {cwe_name} | {result.get('error', 'unknown')}")
            except Exception as e:
                failed += 1
                print(f"FAIL: {cwe_name} | {e}")

    # Finalize
    finished_at = datetime.now(timezone.utc).isoformat()
    final_status = "completed" if failed == 0 else "completed"  # still mark complete even with some failures
    db.finish_run(run_id, final_status, finished_at)

    print(f"\n{'='*70}")
    print(f"BENCHMARK COMPLETE: {run_id}")
    print(f"Completed: {completed + len(completed_cwes)} | Failed: {failed} | Total: {total_cwes}")
    print(f"{'='*70}")

    return run_id
