#!/usr/bin/env python3
"""
MCP server for running and monitoring the Juliet CERT C benchmark against sqc.

Tools:
  run_benchmark          - Start a fresh benchmark run (SQLite-backed)
  cancel_benchmark       - Cancel a running benchmark
  clear_results          - Remove old benchmark result directories
  get_status             - Progress %, ETA, recently completed CWEs
  get_results(sort_by)   - Aggregated TP/FP stats + per-rule breakdown
  get_cwe_detail(cwe_id) - Detailed stats for one CWE
  list_runs              - List all benchmark runs
  get_run_timings        - Runtime (wall/analysis time) of the last N runs
  compare_runs           - Compare two runs
  compare_cwe            - Compare one CWE across two runs
  reanalyze_run          - Re-run analysis on existing CSVs
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent
PROJECT_DIR = _HERE.parent
SCRIPT = PROJECT_DIR / "scripts" / "run_juliet_parallel.sh"
ANALYZE_SCRIPT = PROJECT_DIR / "scripts" / "analyze_juliet_results.py"
GENERATE_MAP_SCRIPT = PROJECT_DIR / "scripts" / "generate_rule_cwe_map.py"
RULE_CWE_MAP = PROJECT_DIR / "data" / "rule_cwe_map.json"
RESULTS_BASE = Path("/tmp/juliet_results")
STATE_FILE = Path("/tmp/juliet_bench.pid")  # stores JSON state (name kept for compat)

# The benchmark script knows its total CWE list; we use 118 as the known count.
KNOWN_TOTAL_CWES = 118

# ── SQLite backend (new) ─────────────────────────────────────────────────────
# Add project root to path so bench package is importable
sys.path.insert(0, str(PROJECT_DIR))
from bench.db import BenchDB
from bench.config import DB_PATH, JULIET_BASE, apply_run_suffix

def _get_db() -> BenchDB:
    """Get a BenchDB instance."""
    return BenchDB()

def _db_has_run(run_id: str) -> bool:
    """Check if a run exists in the SQLite DB."""
    try:
        db = _get_db()
        return db.get_run(run_id) is not None
    except Exception:
        return False

# ── MCP server ────────────────────────────────────────────────────────────────
mcp = FastMCP(
    "juliet-benchmark",
    instructions="Run and monitor the Juliet C benchmark suite against sqc",
)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _fmt_duration(seconds: int) -> str:
    """Format a duration in seconds as 'Xh Ym Zs' (omitting leading zero units)."""
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f"{h}h")
    if m or h:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def _get_sqc_version() -> str:
    """Read sqc version from Cargo.toml."""
    try:
        for line in (PROJECT_DIR / "Cargo.toml").read_text().splitlines():
            m = re.match(r'^version\s*=\s*"([^"]+)"', line)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "unknown"


def _get_git_sha() -> str:
    """Get short git commit SHA for the current HEAD."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=PROJECT_DIR, timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _read_state() -> dict | None:
    """Read persisted benchmark state from disk."""
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return None


def _write_state(state: dict) -> None:
    """Write benchmark state to disk."""
    STATE_FILE.write_text(json.dumps(state))


def _update_state(**kwargs) -> dict | None:
    """Read state, merge kwargs, write back. Returns updated state or None."""
    state = _read_state()
    if state is None:
        return None
    state.update(kwargs)
    _write_state(state)
    return state


def _process_alive(pid: int) -> bool:
    """Check if process is alive (not a zombie)."""
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    # Check for zombie on Linux
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        for line in status.splitlines():
            if line.startswith("State:") and "zombie" in line.lower():
                return False
    except Exception:
        pass
    return True


def _active_results_dir(state: dict | None = None) -> Path:
    """Return the results directory for the current/latest run."""
    if state is None:
        state = _read_state()
    if state and "results_dir" in state:
        return Path(state["results_dir"])
    # Legacy fallback: flat /tmp/juliet_results/
    return RESULTS_BASE


def _get_log_file(state: dict | None = None) -> Path:
    """Return the log file path for the current/latest run."""
    if state is None:
        state = _read_state()
    if state and "results_dir" in state:
        return Path(state["results_dir"]) / "benchmark.log"
    # Legacy fallback
    return Path("/tmp/juliet_bench.log")


def _kill_process_group(pid: int) -> None:
    """Kill an entire process group: SIGTERM, wait, then SIGKILL stragglers."""
    # SIGTERM the group
    try:
        os.killpg(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return  # already dead

    # Give processes time to handle SIGTERM gracefully
    time.sleep(1.0)

    # SIGKILL anything still alive
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass

    # Reap zombie if we're the parent
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass


def _find_child_pids(parent_pid: int) -> list[int]:
    """Find all descendant PIDs of a process (Linux /proc)."""
    children = []
    try:
        result = subprocess.run(
            ["ps", "--ppid", str(parent_pid), "-o", "pid=", "--no-headers"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines():
            pid_str = line.strip()
            if pid_str.isdigit():
                children.append(int(pid_str))
                # Recurse for grandchildren
                children.extend(_find_child_pids(int(pid_str)))
    except Exception:
        pass
    return children


def _parse_log(log_file: Path) -> dict:
    """
    Parse benchmark log and return:
      done    - list of completed CWEs with timing/violation data
      started - set of CWE names that have been started
      errors  - error lines
    """
    if not log_file.exists():
        return {"done": [], "started": set(), "errors": []}

    done: list[dict] = []
    started: set[str] = set()
    started_files: dict[str, int] = {}  # CWE name → file count from START line
    errors: list[str] = []
    done_names: set[str] = set()  # dedup (script may log twice on retry)

    for line in log_file.read_text().splitlines():
        if line.startswith("DONE"):
            # DONE: CWE78_OS_Command_Injection | 1276s | 125780 violations | 5600 files
            # Also handles: DONE [N/M]: ...
            m = re.search(
                r"(?:DONE[^:]*:\s*)(\S+)\s*\|\s*(\d+(?:\.\d+)?)s\s*\|\s*(\d+)\s*violations\s*\|\s*(\d+)\s*files",
                line
            )
            if m and m.group(1) not in done_names:
                done_names.add(m.group(1))
                done.append(
                    {
                        "cwe": m.group(1),
                        "duration_s": int(float(m.group(2))),
                        "violations": int(m.group(3)),
                        "files": int(m.group(4)),
                    }
                )
        elif line.startswith("START"):
            # START: CWE78_OS_Command_Injection (5600 files)
            m = re.match(r"START[^:]*:\s*(\S+)\s*(?:\((\d+) files\))?", line)
            if m:
                started.add(m.group(1))
                if m.group(2):
                    started_files[m.group(1)] = int(m.group(2))
        elif "FAIL:" in line or "ERROR:" in line:
            errors.append(line)

    return {"done": done, "started": started, "started_files": started_files, "errors": errors}


def _parse_analysis(content: str) -> dict:
    """Extract TP/FP counts and per-rule breakdown from an analysis .txt file."""
    tp_m = re.search(r"Violations in OMITBAD \(TP\): (\d+)", content)
    fp_m = re.search(r"Violations in OMITGOOD \(FP\): (\d+)", content)
    flaw_m = re.search(r"FLAW lines detected: (\d+) / (\d+)", content)
    files_m = re.search(r"Files analyzed: (\d+)", content)

    tp = int(tp_m.group(1)) if tp_m else 0
    fp = int(fp_m.group(1)) if fp_m else 0

    top_tp: list[dict] = []
    top_fp: list[dict] = []
    flaw_rules: list[dict] = []
    cwe_matched_tp_rules: list[dict] = []
    cwe_matched_fp_rules: list[dict] = []

    # Section state machine
    section = None

    for line in content.splitlines():
        if "Rules in OMITBAD (True Positives)" in line:
            section = "tp"
        elif "Rules in OMITGOOD (False Positives)" in line:
            section = "fp"
        elif "Rules on FLAW Lines" in line:
            section = "flaw"
        elif "CWE-Matched Rules in OMITBAD" in line:
            section = "cwe_tp"
        elif "CWE-Matched Rules in OMITGOOD" in line:
            section = "cwe_fp"
        elif line.startswith("---") or line.startswith("==="):
            section = None
        else:
            m = re.match(r"\s+(\w[\w-]+):\s+(\d+)", line)
            if m:
                entry = {"rule": m.group(1), "count": int(m.group(2))}
                if section == "tp":
                    top_tp.append(entry)
                elif section == "fp":
                    top_fp.append(entry)
                elif section == "flaw":
                    flaw_rules.append(entry)
                elif section == "cwe_tp":
                    cwe_matched_tp_rules.append(entry)
                elif section == "cwe_fp":
                    cwe_matched_fp_rules.append(entry)

    result: dict = {
        "tp": tp,
        "fp": fp,
        "files": int(files_m.group(1)) if files_m else 0,
        "flaw_detected": int(flaw_m.group(1)) if flaw_m else 0,
        "flaw_total": int(flaw_m.group(2)) if flaw_m else 0,
        "top_tp_rules": top_tp,
        "top_fp_rules": top_fp,
        "flaw_line_rules": flaw_rules,
    }

    # ── CWE-Aware fields (None when not present = backward compat) ────────
    cwe_tp_m = re.search(r"CWE-matched TP: (\d+)", content)
    cwe_fp_m = re.search(r"CWE-matched FP: (\d+)", content)
    cwe_tp_rate_m = re.search(r"CWE-matched TP Rate: ([\d.]+)%", content)
    noise_m = re.search(r"Noise findings \(non-CWE-matched\): (\d+)", content)
    noise_ratio_m = re.search(r"Noise ratio: ([\d.]+)%", content)
    per_file_m = re.search(r"Per-file detection rate: ([\d.]+)% \((\d+)/(\d+)\)", content)
    flaw_hit_m = re.search(r"FLAW-line hit rate \(CWE-matched\): ([\d.]+)% \((\d+)/(\d+)\)", content)
    cwe_rules_m = re.search(r"CWE-matched rules: (.+)", content)

    if cwe_tp_m:
        result["cwe_matched_tp"] = int(cwe_tp_m.group(1))
        result["cwe_matched_fp"] = int(cwe_fp_m.group(1)) if cwe_fp_m else 0
        result["cwe_matched_tp_rate"] = float(cwe_tp_rate_m.group(1)) if cwe_tp_rate_m else None
        result["noise_count"] = int(noise_m.group(1)) if noise_m else None
        result["noise_ratio"] = float(noise_ratio_m.group(1)) if noise_ratio_m else None
        if per_file_m:
            result["per_file_rate"] = float(per_file_m.group(1))
            result["per_file_detected"] = int(per_file_m.group(2))
            result["per_file_total"] = int(per_file_m.group(3))
        else:
            result["per_file_rate"] = None
            result["per_file_detected"] = None
            result["per_file_total"] = None
        if flaw_hit_m:
            result["flaw_hit_rate"] = float(flaw_hit_m.group(1))
            result["flaw_hit_detected"] = int(flaw_hit_m.group(2))
            result["flaw_hit_total"] = int(flaw_hit_m.group(3))
        else:
            result["flaw_hit_rate"] = None
            result["flaw_hit_detected"] = None
            result["flaw_hit_total"] = None
        result["cwe_matched_rules"] = (
            [r.strip() for r in cwe_rules_m.group(1).split(",")]
            if cwe_rules_m else []
        )
        result["cwe_matched_tp_rules"] = cwe_matched_tp_rules
        result["cwe_matched_fp_rules"] = cwe_matched_fp_rules

    return result


def _dir_size_human(path: Path) -> str:
    """Return human-readable size of a directory."""
    total = 0
    try:
        for f in path.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
    except Exception:
        pass
    for unit in ("B", "KB", "MB", "GB"):
        if total < 1024:
            return f"{total:.1f} {unit}"
        total /= 1024
    return f"{total:.1f} TB"


def _extract_cwe_id(cwe_dir_name: str) -> str | None:
    """Extract normalized CWE ID from a Juliet directory name.

    E.g. 'CWE190_Integer_Overflow' → 'CWE-190'
         'CWE121_Stack_Based_Buffer_Overflow' → 'CWE-121'
    """
    m = re.match(r'(CWE)(\d+)', cwe_dir_name)
    if m:
        return f"CWE-{m.group(2)}"
    return None


def _ensure_rule_cwe_map() -> bool:
    """Ensure data/rule_cwe_map.json exists, generating it if needed."""
    if RULE_CWE_MAP.exists():
        return True
    if not GENERATE_MAP_SCRIPT.exists():
        return False
    try:
        subprocess.run(
            ["python3", str(GENERATE_MAP_SCRIPT)],
            capture_output=True, text=True, timeout=30,
        )
        return RULE_CWE_MAP.exists()
    except Exception:
        return False


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def run_benchmark(mode: str = "fast", compile_commands: bool = False) -> str:
    """
    Start a fresh Juliet benchmark run against sqc.

    Uses the new Python-based runner (bench.runner) which writes results
    directly to SQLite. Returns immediately — use get_status() to monitor.

    Args:
        mode: "fast" (default, per-CWE manifests) or "full" (all rules)
        compile_commands: Pass --compile-commands to sqc using the synthesized
            Juliet compile database (scripts/generate_juliet_compile_commands.py).
            Off by default. The run_id and log directory are suffixed "-cdb" so
            a with/without pair on the same sqc build stays two distinct,
            comparable runs. The runner errors if the database is absent rather
            than quietly running without it.
    """
    state = _read_state()
    if state and _process_alive(state.get("pid", 0)):
        elapsed = int(time.time() - state["start_time"])
        return json.dumps(
            {
                "status": "already_running",
                "pid": state["pid"],
                "results_dir": state.get("results_dir", str(RESULTS_BASE)),
                "elapsed_seconds": elapsed,
                "message": "Benchmark already running. Use get_status() to monitor.",
            }
        )

    # Determine version and commit for the unique directory name
    version = _get_sqc_version()
    sha = _get_git_sha()
    run_name = apply_run_suffix(f"sqc-{version}-{sha}", compile_commands)

    # Create a log directory for stdout capture
    results_dir = RESULTS_BASE / run_name
    results_dir.mkdir(parents=True, exist_ok=True)
    log_path = results_dir / "benchmark.log"
    log_fh = log_path.open("w")

    # Build command for the new Python runner
    cmd = [sys.executable, "-m", "bench", "juliet"]
    if mode == "full":
        cmd.append("--full")
    if compile_commands:
        cmd.append("--compile-commands")

    # Launch benchmark detached from the MCP server process so it survives
    # even if the MCP server is restarted.
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_DIR) + ((":" + env["PYTHONPATH"]) if "PYTHONPATH" in env else "")

    proc = subprocess.Popen(
        cmd,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        start_new_session=True,  # detach — PID becomes PGID
        cwd=str(PROJECT_DIR),
        env=env,
    )
    log_fh.close()  # MCP server doesn't need to hold the handle

    start_time = time.time()
    new_state = {
        "pid": proc.pid,
        "start_time": start_time,
        "results_dir": str(results_dir),
        "version": version,
        "commit_sha": sha,
        "run_name": run_name,
        "status": "running",
        "backend": "sqlite",
    }
    _write_state(new_state)

    return json.dumps(
        {
            "status": "started",
            "pid": proc.pid,
            "results_dir": str(results_dir),
            "run_name": run_name,
            "version": version,
            "commit_sha": sha,
            "message": (
                f"Benchmark started (PID {proc.pid}). "
                f"Run: {run_name} ({mode} mode). "
                "Results written to SQLite. Use get_status() to monitor progress."
            ),
        }
    )


@mcp.tool()
def cancel_benchmark() -> str:
    """
    Cancel a running Juliet benchmark.

    Kills the benchmark process group (the main script, workers, and all
    child sqc processes). Partial results already written are preserved and can
    still be queried with get_results() and get_cwe_detail().
    """
    state = _read_state()
    if state is None:
        return json.dumps(
            {
                "status": "no_benchmark",
                "message": "No benchmark has been run. Nothing to cancel.",
            }
        )

    pid = state["pid"]
    if not _process_alive(pid):
        # Check if it was already cancelled
        if state.get("status") == "cancelled":
            return json.dumps(
                {
                    "status": "already_cancelled",
                    "pid": pid,
                    "message": "Benchmark was already cancelled.",
                }
            )
        elapsed = int(time.time() - state["start_time"])
        return json.dumps(
            {
                "status": "not_running",
                "pid": pid,
                "elapsed_seconds": elapsed,
                "message": (
                    "Benchmark process is not running (already finished or crashed). "
                    "Use get_status() to check results."
                ),
            }
        )

    # Collect child PIDs before killing (for verification)
    child_pids = _find_child_pids(pid)

    # Kill the entire process group
    _kill_process_group(pid)

    # Belt-and-suspenders: kill any children that escaped the process group
    time.sleep(0.3)
    for cpid in child_pids:
        try:
            os.kill(cpid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    # Update state to reflect cancellation
    elapsed = int(time.time() - state["start_time"])
    _update_state(status="cancelled")

    # Update DB status if this was a SQLite-backed run
    run_name = state.get("run_name")
    if run_name and state.get("backend") == "sqlite":
        try:
            db = _get_db()
            from datetime import datetime, timezone
            db.finish_run(run_name, "cancelled", datetime.now(timezone.utc).isoformat())
        except Exception:
            pass

    # Get completion count from DB or log
    done_count = 0
    if state.get("backend") == "sqlite" and run_name:
        try:
            db = _get_db()
            progress = db.get_progress(run_name)
            done_count = progress["done_cwes"]
        except Exception:
            pass
    if done_count == 0:
        log_file = _get_log_file(state)
        log_data = _parse_log(log_file)
        done_count = len(log_data["done"])

    return json.dumps(
        {
            "status": "cancelled",
            "pid": pid,
            "elapsed_seconds": elapsed,
            "elapsed_human": _fmt_duration(elapsed),
            "cwes_completed_before_cancel": done_count,
            "processes_killed": 1 + len(child_pids),
            "results_dir": state.get("results_dir", str(RESULTS_BASE)),
            "message": (
                f"Benchmark cancelled (PID {pid}) after {_fmt_duration(elapsed)}. "
                f"{done_count} CWEs completed before cancellation. "
                f"Killed {1 + len(child_pids)} processes (main + children). "
                "Partial results are preserved — use get_results() to view them."
            ),
        }
    )


@mcp.tool()
def clear_results() -> str:
    """
    Remove old benchmark result directories.

    Removes all result directories under /tmp/juliet_results/ that are not
    from a currently running benchmark. Also cleans up legacy flat result files.
    """
    if not RESULTS_BASE.exists():
        return json.dumps(
            {
                "status": "nothing_to_clear",
                "message": f"{RESULTS_BASE} does not exist. Nothing to clear.",
            }
        )

    state = _read_state()
    active_dir = None
    if state and _process_alive(state.get("pid", 0)):
        active_dir = state.get("results_dir")

    removed: list[dict] = []
    skipped: list[str] = []
    errors: list[str] = []

    # Remove run subdirectories (sqc-version-sha/)
    for entry in sorted(RESULTS_BASE.iterdir()):
        if entry.is_dir() and entry.name.startswith("sqc-"):
            if active_dir and str(entry) == active_dir:
                skipped.append(entry.name)
                continue
            try:
                size = _dir_size_human(entry)
                n_files = sum(1 for _ in entry.rglob("*") if _.is_file())
                shutil.rmtree(entry)
                removed.append({"name": entry.name, "size": size, "files": n_files})
            except Exception as e:
                errors.append(f"Failed to remove {entry.name}: {e}")

    # Clean up legacy flat files (*.csv, *.txt directly in RESULTS_BASE)
    legacy_count = 0
    for pattern in ("*.csv", "*.txt"):
        for f in RESULTS_BASE.glob(pattern):
            if f.is_file():
                try:
                    f.unlink()
                    legacy_count += 1
                except Exception as e:
                    errors.append(f"Failed to remove {f.name}: {e}")

    # Clean up legacy log file
    legacy_log = Path("/tmp/juliet_bench.log")
    if legacy_log.exists():
        try:
            legacy_log.unlink()
            legacy_count += 1
        except Exception:
            pass

    total_removed = len(removed)
    msg_parts = []
    if total_removed:
        msg_parts.append(f"Removed {total_removed} run directories")
    if legacy_count:
        msg_parts.append(f"cleaned up {legacy_count} legacy files")
    if skipped:
        msg_parts.append(f"skipped {len(skipped)} active run(s)")
    if not msg_parts:
        msg_parts.append("Nothing to clear")

    return json.dumps(
        {
            "status": "cleared" if (total_removed or legacy_count) else "nothing_to_clear",
            "removed_dirs": removed,
            "skipped_active": skipped,
            "legacy_files_removed": legacy_count,
            "errors": errors,
            "message": ". ".join(msg_parts) + ".",
        }
    )


@mcp.tool()
def reanalyze_run(run: str = "all") -> str:
    """
    Re-run the analysis script on existing benchmark CSVs.

    Regenerates _analysis.txt files from raw CSV data using the current
    version of analyze_juliet_results.py. Does NOT re-run sqc — only
    reclassifies existing violations as TP/FP.

    Args:
        run: Run identifier (run name, SHA, or "latest"), or "all" to
             reanalyze every run directory.
    """
    if not JULIET_BASE.exists():
        return json.dumps({"error": f"Juliet test suite not found at {JULIET_BASE}"})
    if not ANALYZE_SCRIPT.exists():
        return json.dumps({"error": f"Analysis script not found at {ANALYZE_SCRIPT}"})

    # Ensure rule-CWE map exists for CWE-aware metrics
    has_map = _ensure_rule_cwe_map()

    # Determine which run directories to process
    if run == "all":
        targets = [
            RESULTS_BASE / entry.name
            for entry in sorted(RESULTS_BASE.iterdir())
            if entry.is_dir() and entry.name.startswith("sqc-")
        ]
    else:
        resolved = _resolve_run(run)
        if resolved is None:
            avail = [r["run_name"] for r in _list_run_dirs()]
            return json.dumps({"error": f"Cannot resolve '{run}'.", "available": avail})
        targets = [resolved]

    results = []
    for results_dir in targets:
        csv_files = sorted(results_dir.glob("CWE*.csv"))
        if not csv_files:
            results.append({"run": results_dir.name, "status": "skipped", "reason": "no CSVs"})
            continue

        reanalyzed = 0
        errors = []
        for csv_file in csv_files:
            cwe_name = csv_file.stem  # e.g. CWE134_Uncontrolled_Format_String
            cwe_dir = JULIET_BASE / cwe_name
            analysis_file = results_dir / f"{cwe_name}_analysis.txt"

            if not cwe_dir.is_dir():
                continue

            # Build command with CWE-aware args when map is available
            cmd = [
                "python3", str(ANALYZE_SCRIPT),
                "--csv", str(csv_file),
                "--dir", str(cwe_dir),
            ]
            if has_map:
                cwe_id = _extract_cwe_id(cwe_name)
                if cwe_id:
                    cmd.extend(["--cwe", cwe_id])
                cmd.extend(["--rule-cwe-map", str(RULE_CWE_MAP)])

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True, text=True, timeout=60,
                )
                if result.returncode == 0:
                    analysis_file.write_text(result.stdout)
                    reanalyzed += 1
                else:
                    errors.append(f"{cwe_name}: {result.stderr[:200]}")
            except subprocess.TimeoutExpired:
                errors.append(f"{cwe_name}: timeout")
            except Exception as e:
                errors.append(f"{cwe_name}: {e}")

        results.append({
            "run": results_dir.name,
            "cwes_reanalyzed": reanalyzed,
            "errors": errors[:5] if errors else [],
        })

    return json.dumps({
        "results": results,
        "cwe_aware": has_map,
        "message": (
            f"Reanalyzed {len(targets)} run(s). "
            + ("Analysis files now include CWE-aware metrics." if has_map
               else "CWE-aware metrics skipped (no rule-CWE map).")
        ),
    })


@mcp.tool()
def get_status(verbose: bool = False) -> str:
    """
    Get the current status of the Juliet benchmark run.

    Returns progress percentage, estimated time remaining, and number of CWEs
    completed vs total. This is meant to be polled during a ~15-min run, so by
    default it omits the per-CWE `recently_completed` detail (which repeats and
    compounds across polls).

    Args:
        verbose: Include `recently_completed` (last 5 CWEs with timing/counts)
                 and the `errors` list. Default False (compact poll shape).
    """
    state = _read_state()
    if state is None:
        return json.dumps(
            {
                "state": "not_started",
                "message": "No benchmark has been run yet. Use run_benchmark() to start.",
            }
        )

    pid = state.get("pid", 0)
    is_running = _process_alive(pid)
    was_cancelled = state.get("status") == "cancelled"
    run_name = state.get("run_name")
    elapsed_s = int(time.time() - state["start_time"])

    # Try SQLite first for status
    if state.get("backend") == "sqlite" and run_name:
        try:
            db = _get_db()
            progress = db.get_progress(run_name)
            run = progress.get("run", {})
            done_count = progress["done_cwes"]
            total_cwes = progress["total_cwes"] or KNOWN_TOTAL_CWES
            progress_pct = progress["progress_pct"]

            eta_s = None
            if is_running and done_count > 0 and elapsed_s > 0:
                rate = done_count / elapsed_s
                remaining = total_cwes - done_count
                eta_s = int(remaining / rate) if rate > 0 else None

            # Determine state string
            db_status = run.get("status", "unknown")
            if not is_running and db_status == "running":
                state_str = "crashed"
            elif was_cancelled:
                state_str = "cancelled"
            elif db_status == "completed":
                state_str = "completed"
            elif is_running:
                state_str = "running"
            else:
                state_str = db_status

            result: dict = {
                "state": state_str,
                "progress_pct": progress_pct,
                "done_cwes": done_count,
                "total_cwes": total_cwes,
                "elapsed_seconds": elapsed_s,
                "elapsed_human": _fmt_duration(elapsed_s),
                "eta_seconds": eta_s,
                "eta_human": _fmt_duration(eta_s) if eta_s else None,
                "results_dir": state.get("results_dir", str(RESULTS_BASE)),
                "run_name": run_name,
                "version": state.get("version"),
                "commit_sha": state.get("commit_sha"),
                "backend": "sqlite",
                "cache_state": run.get("cache_state", "cold"),
            }

            if verbose:
                # Convert recent completions to legacy format
                recently = []
                for c in progress.get("recently_completed", []):
                    recently.append({
                        "cwe": c["cwe_dir_name"],
                        "duration_s": int(c["duration_s"] or 0),
                        "violations": c["violation_count"],
                        "files": c["file_count"],
                    })
                result["recently_completed"] = recently
                result["errors"] = []

            if state_str == "completed":
                finished = run.get("finished_at")
                if finished and run.get("started_at"):
                    from datetime import datetime
                    try:
                        t0 = datetime.fromisoformat(run["started_at"])
                        t1 = datetime.fromisoformat(finished)
                        total_s = int((t1 - t0).total_seconds())
                    except Exception:
                        total_s = elapsed_s
                else:
                    total_s = elapsed_s
                result["total_duration_seconds"] = total_s
                result["total_duration_human"] = _fmt_duration(total_s)
                result["message"] = (
                    f"Benchmark complete in {_fmt_duration(total_s)}. "
                    f"{done_count}/{total_cwes} CWEs analyzed. "
                    "Use get_results() for aggregated stats or get_cwe_detail(cwe_id) for specifics."
                )
            elif was_cancelled:
                result["message"] = (
                    f"Benchmark was cancelled after {_fmt_duration(elapsed_s)}. "
                    f"{done_count}/{total_cwes} CWEs completed before cancellation. "
                    "Partial results available via get_results()."
                )
            elif is_running:
                eta_str = _fmt_duration(eta_s) if eta_s else "unknown"
                result["message"] = (
                    f"{done_count}/{total_cwes} CWEs done ({progress_pct}%). "
                    f"Elapsed: {_fmt_duration(elapsed_s)}. ETA: {eta_str}."
                )
            else:
                result["message"] = (
                    f"Benchmark process (PID {pid}) is no longer running. "
                    f"{done_count}/{total_cwes} CWEs completed. "
                    "It may have crashed — check errors field."
                )

            return json.dumps(result)
        except Exception:
            pass  # Fall through to legacy log-based status

    # Legacy: log-based status (for old runs or if DB not available)
    results_dir = _active_results_dir(state)
    log_file = _get_log_file(state)
    log_data = _parse_log(log_file)
    done = log_data["done"]
    done_count = len(done)
    started_files = log_data.get("started_files", {})

    summary_file = results_dir / "multi_cwe_summary.txt"
    is_complete = summary_file.exists() and not is_running

    # Use the known total; fall back to observed started count if higher.
    total_cwes = max(KNOWN_TOTAL_CWES, len(log_data["started"]), done_count)

    progress_pct = 0.0
    eta_s = None
    if done_count > 0:
        progress_pct = round(done_count / total_cwes * 100, 1)
        if is_running and elapsed_s > 0:
            rate = done_count / elapsed_s  # CWEs per second
            remaining = total_cwes - done_count
            eta_s = int(remaining / rate) if rate > 0 else None

    # Determine state string
    if is_complete:
        state_str = "completed"
    elif was_cancelled:
        state_str = "cancelled"
    elif is_running:
        state_str = "running"
    else:
        state_str = "crashed"

    # File-level progress from START/DONE lines
    done_names = {d["cwe"] for d in done}
    files_processed = sum(d["files"] for d in done)
    files_total = sum(started_files.values()) if started_files else None
    files_in_progress = sum(
        started_files[cwe] for cwe in started_files
        if cwe not in done_names
    ) if started_files else 0

    result: dict = {
        "state": state_str,
        "progress_pct": progress_pct,
        "done_cwes": done_count,
        "total_cwes": total_cwes,
        "files_processed": files_processed,
        "files_total": files_total,
        "files_in_progress": files_in_progress,
        "elapsed_seconds": elapsed_s,
        "elapsed_human": _fmt_duration(elapsed_s),
        "eta_seconds": eta_s,
        "eta_human": _fmt_duration(eta_s) if eta_s else None,
        "results_dir": str(results_dir),
        "run_name": state.get("run_name"),
        "version": state.get("version"),
        "commit_sha": state.get("commit_sha"),
    }
    if verbose:
        result["recently_completed"] = done[-5:]
        result["errors"] = log_data["errors"]

    files_str = f" ({files_processed:,} / {files_total:,} files)" if files_total else ""

    if is_complete:
        total_s = int(summary_file.stat().st_mtime - state["start_time"])
        result["total_duration_seconds"] = total_s
        result["total_duration_human"] = _fmt_duration(total_s)
        result["message"] = (
            f"Benchmark complete in {_fmt_duration(total_s)}. "
            f"{done_count}/{total_cwes} CWEs analyzed{files_str}. "
            "Use get_results() for aggregated stats or get_cwe_detail(cwe_id) for specifics."
        )
    elif was_cancelled:
        result["message"] = (
            f"Benchmark was cancelled after {_fmt_duration(elapsed_s)}. "
            f"{done_count}/{total_cwes} CWEs completed before cancellation{files_str}. "
            "Partial results available via get_results()."
        )
    elif is_running:
        eta_str = _fmt_duration(eta_s) if eta_s else "unknown"
        result["message"] = (
            f"{done_count}/{total_cwes} CWEs done ({progress_pct}%){files_str}. "
            f"Elapsed: {_fmt_duration(elapsed_s)}. ETA: {eta_str}."
        )
    else:
        result["message"] = (
            f"Benchmark process (PID {pid}) is no longer running. "
            f"{done_count}/{total_cwes} CWEs completed. "
            "It may have crashed — check errors field."
        )

    return json.dumps(result)


@mcp.tool()
def get_results(sort_by: str = "fp_count", run: str = "latest") -> str:
    """
    Get aggregated TP/FP results across all completed CWEs.

    Args:
        sort_by: How to sort the per-rule breakdown.
                 One of: "fp_count" (default), "fp_rate", "tp_count"
        run: Run identifier — "latest" (default), run name, or commit SHA.

    Returns a summary (total TP, FP, TP rate), the top 20 rules by the chosen
    sort key, and a per-CWE table sorted by FP count.
    """
    # Try SQLite first
    try:
        db = _get_db()
        run_id = db.resolve_run(run)
        if run_id:
            result = db.get_run_summary(run_id)
            if result["summary"]["cwes_analyzed"] > 0:
                # Sort top_rules by requested key
                sort_keys = {
                    "fp_count": lambda x: -x["fp"],
                    "fp_rate": lambda x: -x.get("fp_pct", 0),
                    "tp_count": lambda x: -x["tp"],
                }
                result["top_rules"].sort(
                    key=sort_keys.get(sort_by, sort_keys["fp_count"]))
                result["summary"]["sort_by"] = sort_by
                return json.dumps(result)
    except Exception:
        pass

    # Legacy fallback: read from text analysis files
    state = _read_state()
    results_dir = _active_results_dir(state)

    if not results_dir.exists() or not list(results_dir.glob("*_analysis.txt")):
        return json.dumps(
            {
                "error": (
                    "No analysis files found. "
                    "Run run_benchmark() and wait for it to complete."
                )
            }
        )

    total_tp = 0
    total_fp = 0
    rule_tp: dict[str, int] = {}
    rule_fp: dict[str, int] = {}
    per_cwe: list[dict] = []

    # CWE-aware aggregates
    total_cwe_matched_tp = 0
    total_cwe_matched_fp = 0
    total_noise = 0
    total_per_file_detected = 0
    total_per_file_total = 0
    total_flaw_hit_detected = 0
    total_flaw_hit_total = 0
    cwes_with_cwe_aware = 0

    # Build timing lookup from log (cwe_name → duration_s).
    log_file = _get_log_file(state)
    log_data = _parse_log(log_file)
    cwe_timing: dict[str, int] = {e["cwe"]: e["duration_s"] for e in log_data["done"]}

    for f in sorted(results_dir.glob("*_analysis.txt")):
        cwe_name = f.stem.replace("_analysis", "")
        parsed = _parse_analysis(f.read_text())
        tp, fp = parsed["tp"], parsed["fp"]
        cwe_total = tp + fp

        total_tp += tp
        total_fp += fp

        entry: dict = {
            "cwe": cwe_name,
            "tp": tp,
            "fp": fp,
            "total": cwe_total,
            "tp_pct": round(tp / cwe_total * 100, 1) if cwe_total else 0,
            "fp_pct": round(fp / cwe_total * 100, 1) if cwe_total else 0,
        }
        if cwe_name in cwe_timing:
            entry["duration_seconds"] = cwe_timing[cwe_name]
            entry["duration_human"] = _fmt_duration(cwe_timing[cwe_name])

        # Accumulate CWE-aware totals if present
        if "cwe_matched_tp" in parsed:
            cwes_with_cwe_aware += 1
            total_cwe_matched_tp += parsed["cwe_matched_tp"]
            total_cwe_matched_fp += parsed["cwe_matched_fp"]
            if parsed.get("noise_count") is not None:
                total_noise += parsed["noise_count"]
            if parsed.get("per_file_detected") is not None:
                total_per_file_detected += parsed["per_file_detected"]
                total_per_file_total += parsed["per_file_total"]
            if parsed.get("flaw_hit_detected") is not None:
                total_flaw_hit_detected += parsed["flaw_hit_detected"]
                total_flaw_hit_total += parsed["flaw_hit_total"]
            entry["cwe_matched_tp"] = parsed["cwe_matched_tp"]
            entry["cwe_matched_fp"] = parsed["cwe_matched_fp"]
            entry["cwe_matched_tp_rate"] = parsed.get("cwe_matched_tp_rate")
            entry["per_file_rate"] = parsed.get("per_file_rate")
            entry["flaw_hit_rate"] = parsed.get("flaw_hit_rate")

        per_cwe.append(entry)

        for e in parsed["top_tp_rules"]:
            rule_tp[e["rule"]] = rule_tp.get(e["rule"], 0) + e["count"]
        for e in parsed["top_fp_rules"]:
            rule_fp[e["rule"]] = rule_fp.get(e["rule"], 0) + e["count"]

    # Build per-rule table
    all_rules = set(rule_tp) | set(rule_fp)
    rules_data: list[dict] = []
    for rule in all_rules:
        tp = rule_tp.get(rule, 0)
        fp = rule_fp.get(rule, 0)
        total = tp + fp
        rules_data.append(
            {
                "rule": rule,
                "fp": fp,
                "tp": tp,
                "total": total,
                "fp_pct": round(fp / total * 100, 1) if total else 0,
            }
        )

    sort_keys = {
        "fp_count": lambda x: -x["fp"],
        "fp_rate": lambda x: -x["fp_pct"],
        "tp_count": lambda x: -x["tp"],
    }
    rules_data.sort(key=sort_keys.get(sort_by, sort_keys["fp_count"]))

    grand_total = total_tp + total_fp

    summary: dict = {
        "total_violations": grand_total,
        "total_tp": total_tp,
        "total_fp": total_fp,
        "tp_rate_pct": round(total_tp / grand_total * 100, 1) if grand_total else 0,
        "fp_rate_pct": round(total_fp / grand_total * 100, 1) if grand_total else 0,
        "cwes_analyzed": len(per_cwe),
        "sort_by": sort_by,
        "results_dir": str(results_dir),
        "run_name": state.get("run_name") if state else None,
        "version": state.get("version") if state else None,
        "commit_sha": state.get("commit_sha") if state else None,
    }

    # Include total run duration if we have a start time and the summary file exists.
    summary_file = results_dir / "multi_cwe_summary.txt"
    if state and summary_file.exists():
        total_s = int(summary_file.stat().st_mtime - state["start_time"])
        summary["total_duration_seconds"] = total_s
        summary["total_duration_human"] = _fmt_duration(total_s)

    # CWE-aware summary block (only when data is present)
    cwe_aware_summary = None
    if cwes_with_cwe_aware > 0:
        cwe_matched_total = total_cwe_matched_tp + total_cwe_matched_fp
        all_findings = cwe_matched_total + total_noise
        cwe_aware_summary = {
            "cwes_with_data": cwes_with_cwe_aware,
            "cwe_matched_tp": total_cwe_matched_tp,
            "cwe_matched_fp": total_cwe_matched_fp,
            "cwe_matched_total": cwe_matched_total,
            "cwe_matched_tp_rate_pct": (
                round(total_cwe_matched_tp / cwe_matched_total * 100, 1)
                if cwe_matched_total else 0
            ),
            "noise_total": total_noise,
            "noise_ratio_pct": (
                round(total_noise / all_findings * 100, 1)
                if all_findings else 0
            ),
            "per_file_detected": total_per_file_detected,
            "per_file_total": total_per_file_total,
            "per_file_rate_pct": (
                round(total_per_file_detected / total_per_file_total * 100, 1)
                if total_per_file_total else 0
            ),
            "flaw_hit_detected": total_flaw_hit_detected,
            "flaw_hit_total": total_flaw_hit_total,
            "flaw_hit_rate_pct": (
                round(total_flaw_hit_detected / total_flaw_hit_total * 100, 1)
                if total_flaw_hit_total else 0
            ),
        }

    result_dict: dict = {
        "summary": summary,
        "top_rules": rules_data[:20],
        "per_cwe": sorted(per_cwe, key=lambda x: -x["fp"]),
    }
    if cwe_aware_summary:
        result_dict["cwe_aware"] = cwe_aware_summary

    return json.dumps(result_dict)


@mcp.tool()
def get_cwe_detail(cwe_id: str, run: str = "latest") -> str:
    """
    Get detailed TP/FP breakdown for a specific CWE.

    Args:
        cwe_id: CWE identifier. Accepts any of:
                "CWE78", "78", "CWE78_OS_Command_Injection"
        run: Run identifier — "latest" (default), run name, or commit SHA.

    Returns file count, TP/FP rates, top contributing rules for TPs and FPs,
    and FLAW-line detection statistics.
    """
    # Try SQLite first
    try:
        db = _get_db()
        run_id = db.resolve_run(run)
        if run_id:
            detail = db.get_cwe_detail(run_id, cwe_id)
            if detail:
                return json.dumps(detail)
    except Exception:
        pass

    # Legacy fallback: read from text analysis files
    state = _read_state()
    results_dir = _active_results_dir(state)

    if not results_dir.exists():
        return json.dumps(
            {"error": "No results found. Run run_benchmark() first."}
        )

    # Normalise: ensure it starts with "CWE" (case-insensitive match)
    needle = cwe_id.upper()
    if not needle.startswith("CWE"):
        needle = "CWE" + needle

    # Match CWE78 → CWE78_... but NOT CWE780_... by requiring _ or end after the ID.
    matches = [
        f
        for f in results_dir.glob("*_analysis.txt")
        if re.match(rf"^{re.escape(needle)}(_|$)", f.name.upper())
    ]

    if not matches:
        available = sorted(
            f.stem.replace("_analysis", "")
            for f in results_dir.glob("*_analysis.txt")
        )
        return json.dumps(
            {
                "error": f"No results found for '{cwe_id}'.",
                "tip": "Use get_status() to see which CWEs are done.",
                "available_cwes": available,
            }
        )

    f = matches[0]
    cwe_name = f.stem.replace("_analysis", "")
    parsed = _parse_analysis(f.read_text())

    tp, fp = parsed["tp"], parsed["fp"]
    total = tp + fp

    log_file = _get_log_file(state)
    log_data = _parse_log(log_file)
    cwe_timing: dict[str, int] = {e["cwe"]: e["duration_s"] for e in log_data["done"]}

    detail: dict = {
        "cwe": cwe_name,
        "files_analyzed": parsed["files"],
        "results_dir": str(results_dir),
        "run_name": state.get("run_name") if state else None,
        "summary": {
            "total_violations": total,
            "tp": tp,
            "fp": fp,
            "tp_rate_pct": round(tp / total * 100, 1) if total else 0,
            "fp_rate_pct": round(fp / total * 100, 1) if total else 0,
            "flaw_lines_detected": parsed["flaw_detected"],
            "flaw_lines_total": parsed["flaw_total"],
            "flaw_detection_rate_pct": (
                round(parsed["flaw_detected"] / parsed["flaw_total"] * 100, 1)
                if parsed["flaw_total"]
                else 0
            ),
        },
        "top_tp_rules": parsed["top_tp_rules"],
        "top_fp_rules": parsed["top_fp_rules"],
        "flaw_line_rules": parsed["flaw_line_rules"],
    }
    if cwe_name in cwe_timing:
        detail["duration_seconds"] = cwe_timing[cwe_name]
        detail["duration_human"] = _fmt_duration(cwe_timing[cwe_name])

    # CWE-aware metrics (when present in parsed data)
    if "cwe_matched_tp" in parsed:
        cwe_matched_total = parsed["cwe_matched_tp"] + parsed["cwe_matched_fp"]
        detail["cwe_aware"] = {
            "cwe_matched_rules": parsed.get("cwe_matched_rules", []),
            "cwe_matched_tp": parsed["cwe_matched_tp"],
            "cwe_matched_fp": parsed["cwe_matched_fp"],
            "cwe_matched_total": cwe_matched_total,
            "cwe_matched_tp_rate_pct": parsed.get("cwe_matched_tp_rate"),
            "noise_count": parsed.get("noise_count"),
            "noise_ratio_pct": parsed.get("noise_ratio"),
            "per_file_detected": parsed.get("per_file_detected"),
            "per_file_total": parsed.get("per_file_total"),
            "per_file_rate_pct": parsed.get("per_file_rate"),
            "flaw_hit_detected": parsed.get("flaw_hit_detected"),
            "flaw_hit_total": parsed.get("flaw_hit_total"),
            "flaw_hit_rate_pct": parsed.get("flaw_hit_rate"),
            "cwe_matched_tp_rules": parsed.get("cwe_matched_tp_rules", []),
            "cwe_matched_fp_rules": parsed.get("cwe_matched_fp_rules", []),
        }

    return json.dumps(detail)


# ── Comparison helpers ────────────────────────────────────────────────────────

def _list_run_dirs() -> list[dict]:
    """List all run directories under RESULTS_BASE with metadata."""
    runs = []
    if not RESULTS_BASE.exists():
        return runs

    for entry in sorted(RESULTS_BASE.iterdir()):
        if not entry.is_dir() or not entry.name.startswith("sqc-"):
            continue
        # Parse run name: sqc-{version}-{sha}
        parts = entry.name.split("-", 2)  # ["sqc", version, sha]
        version = parts[1] if len(parts) > 1 else "unknown"
        sha = parts[2] if len(parts) > 2 else "unknown"

        analysis_files = list(entry.glob("*_analysis.txt"))
        summary_file = entry / "multi_cwe_summary.txt"
        log_file = entry / "benchmark.log"

        # Use directory mtime as proxy for run date
        try:
            mtime = entry.stat().st_mtime
        except Exception:
            mtime = 0

        runs.append({
            "run_name": entry.name,
            "path": str(entry),
            "version": version,
            "commit_sha": sha,
            "cwes_completed": len(analysis_files),
            "is_complete": summary_file.exists(),
            "has_log": log_file.exists(),
            "size": _dir_size_human(entry),
            "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)),
        })

    # Sort newest first
    runs.sort(key=lambda r: r["modified"], reverse=True)
    return runs


def _resolve_run(identifier: str) -> Path | None:
    """
    Resolve a run identifier to a results directory path.

    Accepts:
    - "latest" / "current" — most recent run from state file
    - Full run name: "sqc-0.1.0-abc1234"
    - Just the SHA: "abc1234"
    - Full path: "/tmp/juliet_results/sqc-0.1.0-abc1234"
    """
    ident = identifier.strip()

    # "latest" / "current" → read from state
    if ident.lower() in ("latest", "current"):
        state = _read_state()
        if state and "results_dir" in state:
            p = Path(state["results_dir"])
            if p.exists():
                return p
        # Fall back to newest directory
        runs = _list_run_dirs()
        if runs:
            return Path(runs[0]["path"])
        return None

    # Full path
    if ident.startswith("/"):
        p = Path(ident)
        return p if p.exists() else None

    # Full run name (starts with "sqc-")
    if ident.startswith("sqc-"):
        p = RESULTS_BASE / ident
        return p if p.exists() else None

    # Try as SHA suffix match
    if not RESULTS_BASE.exists():
        return None
    for entry in sorted(RESULTS_BASE.iterdir(), reverse=True):
        if entry.is_dir() and entry.name.endswith(f"-{ident}"):
            return entry

    # Try as substring anywhere in run name
    for entry in sorted(RESULTS_BASE.iterdir(), reverse=True):
        if entry.is_dir() and ident in entry.name:
            return entry

    return None


def _load_run_data(results_dir: Path) -> dict:
    """Load all analysis data from a results directory into a comparable structure."""
    data: dict = {
        "per_cwe": {},        # cwe_name → parsed analysis dict
        "per_rule_tp": {},    # rule → total TP count across CWEs
        "per_rule_fp": {},    # rule → total FP count across CWEs
        "total_tp": 0,
        "total_fp": 0,
        "cwe_count": 0,
        # CWE-aware totals
        "cwe_aware_count": 0,
        "total_cwe_matched_tp": 0,
        "total_cwe_matched_fp": 0,
        "total_noise": 0,
        "total_per_file_detected": 0,
        "total_per_file_total": 0,
        "total_flaw_hit_detected": 0,
        "total_flaw_hit_total": 0,
    }
    for f in sorted(results_dir.glob("*_analysis.txt")):
        cwe_name = f.stem.replace("_analysis", "")
        parsed = _parse_analysis(f.read_text())
        data["per_cwe"][cwe_name] = parsed
        data["total_tp"] += parsed["tp"]
        data["total_fp"] += parsed["fp"]
        data["cwe_count"] += 1
        for entry in parsed["top_tp_rules"]:
            data["per_rule_tp"][entry["rule"]] = (
                data["per_rule_tp"].get(entry["rule"], 0) + entry["count"]
            )
        for entry in parsed["top_fp_rules"]:
            data["per_rule_fp"][entry["rule"]] = (
                data["per_rule_fp"].get(entry["rule"], 0) + entry["count"]
            )
        # Accumulate CWE-aware totals
        if "cwe_matched_tp" in parsed:
            data["cwe_aware_count"] += 1
            data["total_cwe_matched_tp"] += parsed["cwe_matched_tp"]
            data["total_cwe_matched_fp"] += parsed["cwe_matched_fp"]
            if parsed.get("noise_count") is not None:
                data["total_noise"] += parsed["noise_count"]
            if parsed.get("per_file_detected") is not None:
                data["total_per_file_detected"] += parsed["per_file_detected"]
                data["total_per_file_total"] += parsed["per_file_total"]
            if parsed.get("flaw_hit_detected") is not None:
                data["total_flaw_hit_detected"] += parsed["flaw_hit_detected"]
                data["total_flaw_hit_total"] += parsed["flaw_hit_total"]
    return data


# ── Comparison tools ─────────────────────────────────────────────────────────

@mcp.tool()
def list_runs(limit: int = 10, compact: bool = True, verbose: bool = False) -> str:
    """
    List benchmark runs, newest first (from SQLite DB and legacy directories).

    By default returns only the most recent `limit` runs in a compact shape —
    the full history is 120+ runs and dumping it whole wastes context. Use the
    run_name values as identifiers in compare_runs() and compare_cwe().

    Args:
        limit: Max runs to return, newest first. Use 0 for all. Default 10.
        compact: Trim each run to the fields callers actually use
                 (run_name, version, cwes_completed, is_complete). Default True.
        verbose: Alias for compact=False — return every field per run.
    """
    if verbose:
        compact = False

    # Merge SQLite runs with legacy directory runs
    all_runs = []
    seen_names = set()

    # SQLite runs (db.list_runs already orders newest-first by started_at)
    try:
        db = _get_db()
        for r in db.list_runs():
            progress = db.get_progress(r["run_id"])
            all_runs.append({
                "run_name": r["run_id"],
                "version": r["sqc_version"],
                "commit_sha": r["commit_sha"],
                "cwes_completed": progress["done_cwes"],
                "is_complete": r["status"] == "completed",
                "status": r["status"],
                "started_at": r["started_at"],
                "cache_state": r["cache_state"],
                "backend": "sqlite",
            })
            seen_names.add(r["run_id"])
    except Exception:
        pass

    # Legacy directory runs (only add if not already seen)
    for r in _list_run_dirs():
        if r["run_name"] not in seen_names:
            r["backend"] = "legacy"
            all_runs.append(r)

    if not all_runs:
        return json.dumps({
            "runs": [],
            "message": (
                "No benchmark runs found. Use run_benchmark() to start one."
            ),
        })

    # Sort newest-first across both backends. SQLite rows carry an ISO
    # `started_at`; legacy rows carry a `modified` "YYYY-MM-DD HH:MM:SS"
    # string — both sort lexically in the same direction.
    all_runs.sort(
        key=lambda r: r.get("started_at") or r.get("modified") or "",
        reverse=True,
    )

    total = len(all_runs)
    # Mark which one is the "current" run from state
    state = _read_state()
    current_name = state.get("run_name") if state else None
    for r in all_runs:
        r["is_current"] = r["run_name"] == current_name

    shown = all_runs if limit <= 0 else all_runs[:limit]

    if compact:
        keep = ("run_name", "version", "cwes_completed", "is_complete", "cache_state")
        shown = [
            {k: r[k] for k in keep if k in r}
            | ({"is_current": True} if r.get("is_current") else {})
            for r in shown
        ]

    msg = (
        f"{total} benchmark run(s) total; showing {len(shown)} (newest first). "
        "Use run names as identifiers in compare_runs() and compare_cwe()."
    )
    if 0 < limit < total:
        msg += f" Pass limit=0 to see all {total}."

    return json.dumps({
        "runs": shown,
        "count": len(shown),
        "total": total,
        "message": msg,
    })


@mcp.tool()
def get_run_timings(limit: int = 10) -> str:
    """
    Runtime of the last N Juliet benchmark runs, newest first (SQLite runs only).

    Returns, per run: wall_s (real elapsed start-to-finish time, when the run
    has finished) and analysis_s (summed per-CWE sqc-subprocess time — exceeds
    wall_s under parallelism, and is the more stable axis for comparing the
    cost of analysis-depth changes across versions; see task 202).

    Args:
        limit: Max runs to return, newest first. Use 0 for all. Default 10.
    """
    try:
        db = _get_db()
        timings = db.list_run_timings(limit=limit)
    except Exception as e:
        return json.dumps({"error": f"Failed to load run timings: {e}"})

    for t in timings:
        if t.get("wall_s") is not None:
            t["wall_human"] = _fmt_duration(int(t["wall_s"]))
        if t.get("analysis_s") is not None:
            t["analysis_human"] = _fmt_duration(int(t["analysis_s"]))

    return json.dumps({
        "timings": timings,
        "count": len(timings),
        "message": (
            f"Runtime for the last {len(timings)} run(s), newest first. "
            "wall_s is real elapsed time (finished runs only); analysis_s is "
            "summed per-CWE sqc time (parallelism-independent compute cost)."
        ),
    })


@mcp.tool()
def compare_runs(base: str, target: str, compact: bool = True) -> str:
    """
    Compare two benchmark runs showing TP/FP deltas.

    Args:
        base: Base (older) run — run name, commit SHA, or "latest"
        target: Target (newer) run — run name, commit SHA, or "latest"
        compact: Omit the full `all_cwe_deltas` table (~118 rows) and keep only
                 the overall summary plus top-15 CWE / top-10 rule movers.
                 Default True. Pass False for the exhaustive per-CWE table.

    Returns overall TP/FP delta, top CWEs improved/regressed, and per-rule
    changes. Positive FP delta = regression (more FPs), negative = improvement.
    """
    # Try SQLite first
    try:
        db = _get_db()
        base_id = db.resolve_run(base)
        target_id = db.resolve_run(target)
        if base_id and target_id:
            if base_id == target_id:
                return json.dumps({
                    "error": "Base and target resolve to the same run.",
                    "resolved": base_id,
                })
            result = db.compare_runs(base_id, target_id)
            if "error" not in result:
                if compact:
                    result.pop("all_cwe_deltas", None)
                return json.dumps(result)
    except Exception:
        pass

    # Legacy fallback
    base_dir = _resolve_run(base)
    target_dir = _resolve_run(target)

    if base_dir is None:
        avail = [r["run_name"] for r in _list_run_dirs()]
        return json.dumps({
            "error": f"Could not resolve base run '{base}'.",
            "available_runs": avail,
        })
    if target_dir is None:
        avail = [r["run_name"] for r in _list_run_dirs()]
        return json.dumps({
            "error": f"Could not resolve target run '{target}'.",
            "available_runs": avail,
        })
    if base_dir == target_dir:
        return json.dumps({
            "error": "Base and target resolve to the same run directory.",
            "resolved_path": str(base_dir),
        })

    base_data = _load_run_data(base_dir)
    target_data = _load_run_data(target_dir)

    if base_data["cwe_count"] == 0:
        return json.dumps({"error": f"No analysis files in base run: {base_dir}"})
    if target_data["cwe_count"] == 0:
        return json.dumps({"error": f"No analysis files in target run: {target_dir}"})

    # ── Overall summary ──────────────────────────────────────────────────
    base_total = base_data["total_tp"] + base_data["total_fp"]
    target_total = target_data["total_tp"] + target_data["total_fp"]
    base_tp_rate = round(base_data["total_tp"] / base_total * 100, 1) if base_total else 0
    target_tp_rate = round(target_data["total_tp"] / target_total * 100, 1) if target_total else 0

    summary = {
        "base_run": base_dir.name,
        "target_run": target_dir.name,
        "base": {
            "tp": base_data["total_tp"],
            "fp": base_data["total_fp"],
            "total": base_total,
            "tp_rate_pct": base_tp_rate,
            "cwes": base_data["cwe_count"],
        },
        "target": {
            "tp": target_data["total_tp"],
            "fp": target_data["total_fp"],
            "total": target_total,
            "tp_rate_pct": target_tp_rate,
            "cwes": target_data["cwe_count"],
        },
        "delta": {
            "tp": target_data["total_tp"] - base_data["total_tp"],
            "fp": target_data["total_fp"] - base_data["total_fp"],
            "total": target_total - base_total,
            "tp_rate_pp": round(target_tp_rate - base_tp_rate, 2),
        },
    }

    # ── Per-CWE deltas ───────────────────────────────────────────────────
    all_cwes = set(base_data["per_cwe"]) | set(target_data["per_cwe"])
    cwe_deltas: list[dict] = []
    for cwe in sorted(all_cwes):
        b = base_data["per_cwe"].get(cwe, {"tp": 0, "fp": 0})
        t = target_data["per_cwe"].get(cwe, {"tp": 0, "fp": 0})
        b_total = b["tp"] + b["fp"]
        t_total = t["tp"] + t["fp"]
        b_tp_pct = round(b["tp"] / b_total * 100, 1) if b_total else 0
        t_tp_pct = round(t["tp"] / t_total * 100, 1) if t_total else 0

        cwe_deltas.append({
            "cwe": cwe,
            "base_tp": b["tp"],
            "base_fp": b["fp"],
            "target_tp": t["tp"],
            "target_fp": t["fp"],
            "delta_tp": t["tp"] - b["tp"],
            "delta_fp": t["fp"] - b["fp"],
            "base_tp_pct": b_tp_pct,
            "target_tp_pct": t_tp_pct,
            "delta_tp_rate_pp": round(t_tp_pct - b_tp_pct, 2),
        })

    # Sort by FP delta (biggest improvements first = most negative)
    cwe_deltas.sort(key=lambda x: x["delta_fp"])

    # Top improvements (FP decreased) and regressions (FP increased)
    improvements = [d for d in cwe_deltas if d["delta_fp"] < 0][:15]
    regressions = [d for d in cwe_deltas if d["delta_fp"] > 0]
    regressions.sort(key=lambda x: -x["delta_fp"])
    regressions = regressions[:15]

    # ── Per-rule deltas ──────────────────────────────────────────────────
    all_rules = set(base_data["per_rule_tp"]) | set(base_data["per_rule_fp"]) | \
                set(target_data["per_rule_tp"]) | set(target_data["per_rule_fp"])

    rule_deltas: list[dict] = []
    for rule in sorted(all_rules):
        b_tp = base_data["per_rule_tp"].get(rule, 0)
        b_fp = base_data["per_rule_fp"].get(rule, 0)
        t_tp = target_data["per_rule_tp"].get(rule, 0)
        t_fp = target_data["per_rule_fp"].get(rule, 0)
        rule_deltas.append({
            "rule": rule,
            "base_tp": b_tp,
            "base_fp": b_fp,
            "target_tp": t_tp,
            "target_fp": t_fp,
            "delta_tp": t_tp - b_tp,
            "delta_fp": t_fp - b_fp,
        })

    # Top rule improvements and regressions by FP delta
    rule_deltas.sort(key=lambda x: x["delta_fp"])
    rule_improvements = [d for d in rule_deltas if d["delta_fp"] < 0][:10]
    rule_regressions = [d for d in rule_deltas if d["delta_fp"] > 0]
    rule_regressions.sort(key=lambda x: -x["delta_fp"])
    rule_regressions = rule_regressions[:10]

    # ── CWEs only in one run ─────────────────────────────────────────────
    only_in_base = sorted(set(base_data["per_cwe"]) - set(target_data["per_cwe"]))
    only_in_target = sorted(set(target_data["per_cwe"]) - set(base_data["per_cwe"]))

    result: dict = {
        "summary": summary,
        "cwe_improvements": improvements,
        "cwe_regressions": regressions,
        "rule_improvements": rule_improvements,
        "rule_regressions": rule_regressions,
        "cwes_only_in_base": only_in_base,
        "cwes_only_in_target": only_in_target,
    }
    if not compact:
        result["all_cwe_deltas"] = cwe_deltas

    # ── CWE-aware comparison (when both runs have data) ──────────────────
    if base_data["cwe_aware_count"] > 0 and target_data["cwe_aware_count"] > 0:
        def _cwe_aware_summary(d: dict) -> dict:
            cm_total = d["total_cwe_matched_tp"] + d["total_cwe_matched_fp"]
            all_total = cm_total + d["total_noise"]
            return {
                "cwe_matched_tp": d["total_cwe_matched_tp"],
                "cwe_matched_fp": d["total_cwe_matched_fp"],
                "cwe_matched_tp_rate_pct": (
                    round(d["total_cwe_matched_tp"] / cm_total * 100, 1) if cm_total else 0
                ),
                "noise_total": d["total_noise"],
                "noise_ratio_pct": (
                    round(d["total_noise"] / all_total * 100, 1) if all_total else 0
                ),
                "per_file_detected": d["total_per_file_detected"],
                "per_file_total": d["total_per_file_total"],
                "per_file_rate_pct": (
                    round(d["total_per_file_detected"] / d["total_per_file_total"] * 100, 1)
                    if d["total_per_file_total"] else 0
                ),
                "flaw_hit_detected": d["total_flaw_hit_detected"],
                "flaw_hit_total": d["total_flaw_hit_total"],
                "flaw_hit_rate_pct": (
                    round(d["total_flaw_hit_detected"] / d["total_flaw_hit_total"] * 100, 1)
                    if d["total_flaw_hit_total"] else 0
                ),
            }

        b_cwe = _cwe_aware_summary(base_data)
        t_cwe = _cwe_aware_summary(target_data)

        result["cwe_aware"] = {
            "base": b_cwe,
            "target": t_cwe,
            "delta": {
                "cwe_matched_tp": t_cwe["cwe_matched_tp"] - b_cwe["cwe_matched_tp"],
                "cwe_matched_fp": t_cwe["cwe_matched_fp"] - b_cwe["cwe_matched_fp"],
                "cwe_matched_tp_rate_pp": round(
                    t_cwe["cwe_matched_tp_rate_pct"] - b_cwe["cwe_matched_tp_rate_pct"], 2
                ),
                "per_file_rate_pp": round(
                    t_cwe["per_file_rate_pct"] - b_cwe["per_file_rate_pct"], 2
                ),
                "flaw_hit_rate_pp": round(
                    t_cwe["flaw_hit_rate_pct"] - b_cwe["flaw_hit_rate_pct"], 2
                ),
            },
        }

    return json.dumps(result)


@mcp.tool()
def compare_cwe(cwe_id: str, base: str, target: str) -> str:
    """
    Compare a specific CWE's results between two benchmark runs.

    Args:
        cwe_id: CWE identifier (e.g., "CWE476", "476")
        base: Base (older) run — run name, commit SHA, or "latest"
        target: Target (newer) run — run name, commit SHA, or "latest"

    Returns TP/FP delta, per-rule changes, and FLAW detection delta for the CWE.
    """
    # Try SQLite first
    try:
        db = _get_db()
        base_id = db.resolve_run(base)
        target_id = db.resolve_run(target)
        if base_id and target_id:
            b_detail = db.get_cwe_detail(base_id, cwe_id)
            t_detail = db.get_cwe_detail(target_id, cwe_id)
            if b_detail and t_detail:
                bs, ts = b_detail["summary"], t_detail["summary"]
                b_total = bs["tp"] + bs["fp"]
                t_total = ts["tp"] + ts["fp"]
                b_tp_pct = round(bs["tp"] / b_total * 100, 1) if b_total else 0
                t_tp_pct = round(ts["tp"] / t_total * 100, 1) if t_total else 0

                result = {
                    "cwe": b_detail["cwe"],
                    "base_run": base_id,
                    "target_run": target_id,
                    "summary": {
                        "base": {"tp": bs["tp"], "fp": bs["fp"], "total": b_total,
                                 "tp_rate_pct": b_tp_pct, "files": b_detail["files_analyzed"]},
                        "target": {"tp": ts["tp"], "fp": ts["fp"], "total": t_total,
                                   "tp_rate_pct": t_tp_pct, "files": t_detail["files_analyzed"]},
                        "delta": {
                            "tp": ts["tp"] - bs["tp"],
                            "fp": ts["fp"] - bs["fp"],
                            "total": t_total - b_total,
                            "tp_rate_pp": round(t_tp_pct - b_tp_pct, 2),
                        },
                    },
                    "flaw_detection": {
                        "base": {"detected": bs["flaw_lines_detected"],
                                 "total": bs["flaw_lines_total"],
                                 "rate_pct": bs["flaw_detection_rate_pct"]},
                        "target": {"detected": ts["flaw_lines_detected"],
                                   "total": ts["flaw_lines_total"],
                                   "rate_pct": ts["flaw_detection_rate_pct"]},
                        "delta": {
                            "detected": ts["flaw_lines_detected"] - bs["flaw_lines_detected"],
                            "rate_pp": round(ts["flaw_detection_rate_pct"] - bs["flaw_detection_rate_pct"], 2),
                        },
                    },
                }

                # CWE-aware comparison
                if b_detail.get("cwe_aware") and t_detail.get("cwe_aware"):
                    ba, ta = b_detail["cwe_aware"], t_detail["cwe_aware"]
                    b_cm_total = ba["cwe_matched_tp"] + ba["cwe_matched_fp"]
                    t_cm_total = ta["cwe_matched_tp"] + ta["cwe_matched_fp"]
                    b_cm_tp_pct = round(ba["cwe_matched_tp"] / b_cm_total * 100, 1) if b_cm_total else 0
                    t_cm_tp_pct = round(ta["cwe_matched_tp"] / t_cm_total * 100, 1) if t_cm_total else 0
                    result["cwe_aware"] = {
                        "base": {
                            "cwe_matched_tp": ba["cwe_matched_tp"],
                            "cwe_matched_fp": ba["cwe_matched_fp"],
                            "cwe_matched_tp_rate_pct": b_cm_tp_pct,
                        },
                        "target": {
                            "cwe_matched_tp": ta["cwe_matched_tp"],
                            "cwe_matched_fp": ta["cwe_matched_fp"],
                            "cwe_matched_tp_rate_pct": t_cm_tp_pct,
                        },
                        "delta": {
                            "cwe_matched_tp": ta["cwe_matched_tp"] - ba["cwe_matched_tp"],
                            "cwe_matched_fp": ta["cwe_matched_fp"] - ba["cwe_matched_fp"],
                            "cwe_matched_tp_rate_pp": round(t_cm_tp_pct - b_cm_tp_pct, 2),
                        },
                    }

                return json.dumps(result)
    except Exception:
        pass

    # Legacy fallback
    base_dir = _resolve_run(base)
    target_dir = _resolve_run(target)

    if base_dir is None:
        return json.dumps({"error": f"Could not resolve base run '{base}'."})
    if target_dir is None:
        return json.dumps({"error": f"Could not resolve target run '{target}'."})

    # Normalise CWE ID
    needle = cwe_id.upper()
    if not needle.startswith("CWE"):
        needle = "CWE" + needle

    def _find_analysis(results_dir: Path, needle: str) -> tuple[str, dict] | None:
        for f in results_dir.glob("*_analysis.txt"):
            if re.match(rf"^{re.escape(needle)}(_|$)", f.name.upper()):
                cwe_name = f.stem.replace("_analysis", "")
                return cwe_name, _parse_analysis(f.read_text())
        return None

    base_result = _find_analysis(base_dir, needle)
    target_result = _find_analysis(target_dir, needle)

    if base_result is None and target_result is None:
        return json.dumps({
            "error": f"CWE '{cwe_id}' not found in either run.",
        })

    # Handle CWE present in only one run
    if base_result is None:
        cwe_name, t = target_result
        return json.dumps({
            "cwe": cwe_name,
            "note": f"CWE only present in target run ({target_dir.name}), not in base.",
            "target": {
                "tp": t["tp"], "fp": t["fp"], "files": t["files"],
                "flaw_detected": t["flaw_detected"], "flaw_total": t["flaw_total"],
            },
        })
    if target_result is None:
        cwe_name, b = base_result
        return json.dumps({
            "cwe": cwe_name,
            "note": f"CWE only present in base run ({base_dir.name}), not in target.",
            "base": {
                "tp": b["tp"], "fp": b["fp"], "files": b["files"],
                "flaw_detected": b["flaw_detected"], "flaw_total": b["flaw_total"],
            },
        })

    cwe_name, b = base_result
    _, t = target_result

    b_total = b["tp"] + b["fp"]
    t_total = t["tp"] + t["fp"]
    b_tp_pct = round(b["tp"] / b_total * 100, 1) if b_total else 0
    t_tp_pct = round(t["tp"] / t_total * 100, 1) if t_total else 0

    b_flaw_pct = round(b["flaw_detected"] / b["flaw_total"] * 100, 1) if b["flaw_total"] else 0
    t_flaw_pct = round(t["flaw_detected"] / t["flaw_total"] * 100, 1) if t["flaw_total"] else 0

    # ── Per-rule comparison ──────────────────────────────────────────────
    def _rule_map(entries: list[dict]) -> dict[str, int]:
        return {e["rule"]: e["count"] for e in entries}

    b_tp_rules = _rule_map(b["top_tp_rules"])
    b_fp_rules = _rule_map(b["top_fp_rules"])
    t_tp_rules = _rule_map(t["top_tp_rules"])
    t_fp_rules = _rule_map(t["top_fp_rules"])

    all_rules = set(b_tp_rules) | set(b_fp_rules) | set(t_tp_rules) | set(t_fp_rules)
    rule_changes: list[dict] = []
    for rule in sorted(all_rules):
        b_tp = b_tp_rules.get(rule, 0)
        b_fp = b_fp_rules.get(rule, 0)
        t_tp = t_tp_rules.get(rule, 0)
        t_fp = t_fp_rules.get(rule, 0)
        if b_tp != t_tp or b_fp != t_fp:
            rule_changes.append({
                "rule": rule,
                "base_tp": b_tp, "base_fp": b_fp,
                "target_tp": t_tp, "target_fp": t_fp,
                "delta_tp": t_tp - b_tp, "delta_fp": t_fp - b_fp,
            })

    # Sort by absolute FP change (biggest changes first)
    rule_changes.sort(key=lambda x: abs(x["delta_fp"]), reverse=True)

    # Rules that appeared or disappeared
    b_all_rules = set(b_tp_rules) | set(b_fp_rules)
    t_all_rules = set(t_tp_rules) | set(t_fp_rules)
    new_rules = sorted(t_all_rules - b_all_rules)
    removed_rules = sorted(b_all_rules - t_all_rules)

    result: dict = {
        "cwe": cwe_name,
        "base_run": base_dir.name,
        "target_run": target_dir.name,
        "summary": {
            "base": {
                "tp": b["tp"], "fp": b["fp"], "total": b_total,
                "tp_rate_pct": b_tp_pct, "files": b["files"],
            },
            "target": {
                "tp": t["tp"], "fp": t["fp"], "total": t_total,
                "tp_rate_pct": t_tp_pct, "files": t["files"],
            },
            "delta": {
                "tp": t["tp"] - b["tp"],
                "fp": t["fp"] - b["fp"],
                "total": t_total - b_total,
                "tp_rate_pp": round(t_tp_pct - b_tp_pct, 2),
            },
        },
        "flaw_detection": {
            "base": {
                "detected": b["flaw_detected"], "total": b["flaw_total"],
                "rate_pct": b_flaw_pct,
            },
            "target": {
                "detected": t["flaw_detected"], "total": t["flaw_total"],
                "rate_pct": t_flaw_pct,
            },
            "delta": {
                "detected": t["flaw_detected"] - b["flaw_detected"],
                "rate_pp": round(t_flaw_pct - b_flaw_pct, 2),
            },
        },
        "rule_changes": rule_changes,
        "new_rules_in_target": new_rules,
        "removed_rules_from_base": removed_rules,
    }

    # CWE-aware comparison (when both runs have CWE-aware data for this CWE)
    if "cwe_matched_tp" in b and "cwe_matched_tp" in t:
        b_cm_total = b["cwe_matched_tp"] + b["cwe_matched_fp"]
        t_cm_total = t["cwe_matched_tp"] + t["cwe_matched_fp"]
        b_cm_tp_pct = round(b["cwe_matched_tp"] / b_cm_total * 100, 1) if b_cm_total else 0
        t_cm_tp_pct = round(t["cwe_matched_tp"] / t_cm_total * 100, 1) if t_cm_total else 0

        result["cwe_aware"] = {
            "base": {
                "cwe_matched_tp": b["cwe_matched_tp"],
                "cwe_matched_fp": b["cwe_matched_fp"],
                "cwe_matched_tp_rate_pct": b_cm_tp_pct,
                "noise_count": b.get("noise_count"),
                "per_file_rate_pct": b.get("per_file_rate"),
                "flaw_hit_rate_pct": b.get("flaw_hit_rate"),
            },
            "target": {
                "cwe_matched_tp": t["cwe_matched_tp"],
                "cwe_matched_fp": t["cwe_matched_fp"],
                "cwe_matched_tp_rate_pct": t_cm_tp_pct,
                "noise_count": t.get("noise_count"),
                "per_file_rate_pct": t.get("per_file_rate"),
                "flaw_hit_rate_pct": t.get("flaw_hit_rate"),
            },
            "delta": {
                "cwe_matched_tp": t["cwe_matched_tp"] - b["cwe_matched_tp"],
                "cwe_matched_fp": t["cwe_matched_fp"] - b["cwe_matched_fp"],
                "cwe_matched_tp_rate_pp": round(t_cm_tp_pct - b_cm_tp_pct, 2),
            },
        }

    return json.dumps(result)


if __name__ == "__main__":
    mcp.run()
