"""Run competitor tools on Juliet test cases and classify TP/FP.

Usage:
  python -m bench.competitors infer [--cwes CWE-476,CWE-690] [--jobs 8]
  python -m bench.competitors framac [--cwes CWE-190,CWE-476] [--jobs 8]
  python -m bench.competitors cppcheck [--cwes CWE-476,...] [--jobs 8]
  python -m bench.competitors clangtidy [--cwes CWE-476,...] [--jobs 8]
  python -m bench.competitors all [--jobs 8]
  python -m bench.competitors compare <results1.json> <results2.json>

Results are written to data/competitor_results/<tool>_<timestamp>.json
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from bench.analyzer import parse_c_file_sections
from bench.config import JULIET_BASE


# ── CWE sets per tool ───────────────────────────────────────────────────────

INFER_CWES = [
    "CWE476", "CWE690", "CWE416", "CWE401", "CWE415",
    "CWE761", "CWE762", "CWE121", "CWE122", "CWE124", "CWE127",
]

FRAMAC_CWES = [
    "CWE190", "CWE191", "CWE476", "CWE369", "CWE197", "CWE680",
]

# Union of all CWEs tested by any tool
ALL_CWES = sorted(set(INFER_CWES) | set(FRAMAC_CWES))

CPPCHECK_CWES = ALL_CWES
CLANGTIDY_CWES = ALL_CWES

# Infer bug_type -> CWE mapping (for CWE-matched TP classification)
INFER_BUG_CWE = {
    "NULLPTR_DEREFERENCE": {"CWE476", "CWE690"},
    "NULL_DEREFERENCE": {"CWE476", "CWE690"},
    "USE_AFTER_FREE": {"CWE416"},
    "MEMORY_LEAK": {"CWE401"},
    "PULSE_MEMORY_LEAK": {"CWE401"},
    "DOUBLE_FREE": {"CWE415"},
    "BUFFER_OVERRUN_L1": {"CWE121", "CWE122", "CWE124", "CWE127"},
    "BUFFER_OVERRUN_L2": {"CWE121", "CWE122", "CWE124", "CWE127"},
    "BUFFER_OVERRUN_L3": {"CWE121", "CWE122", "CWE124", "CWE127"},
    "BUFFER_OVERRUN_L4": {"CWE121", "CWE122", "CWE124", "CWE127"},
    "BUFFER_OVERRUN_L5": {"CWE121", "CWE122", "CWE124", "CWE127"},
    "BUFFER_OVERRUN_S2": {"CWE121", "CWE122", "CWE124", "CWE127"},
    "BUFFER_OVERRUN_U5": {"CWE121", "CWE122", "CWE124", "CWE127"},
    "PULSE_UNNECESSARY_COPY": set(),  # noise, not a CWE
}

# Frama-C alarm patterns -> CWE mapping
FRAMAC_ALARM_CWE = {
    "mem_access": {"CWE476", "CWE690", "CWE121", "CWE122", "CWE124", "CWE127"},
    "signed_overflow": {"CWE190", "CWE191", "CWE680"},
    "signed_downcast": {"CWE197", "CWE190", "CWE191"},
    "unsigned_overflow": {"CWE190", "CWE191"},
    "division_by_zero": {"CWE369"},
    "index_bound": {"CWE121", "CWE122", "CWE124", "CWE127"},
}

RESULTS_DIR = Path(__file__).resolve().parent.parent / "data" / "competitor_results"

JULIET_SUPPORT = JULIET_BASE.parent / "testcasesupport"


# ── Helpers ──────────────────────────────────────────────────────────────────

def _find_cwe_dir(cwe_id: str) -> Path | None:
    """Find the Juliet testcases directory for a CWE ID like 'CWE476'."""
    num = re.sub(r'\D', '', cwe_id)
    for entry in JULIET_BASE.iterdir():
        if entry.is_dir() and entry.name.startswith(f"CWE{num}"):
            return entry
    return None


def _collect_c_files(cwe_dir: Path) -> list[Path]:
    """Collect all .c files under a CWE directory (flat or nested)."""
    return sorted(cwe_dir.rglob("*.c"))


def _extract_function_names(filepath: Path) -> list[str]:
    """Extract bad and good function names from a Juliet test file."""
    funcs = []
    basename = filepath.stem
    try:
        text = filepath.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return funcs

    # Look for function definitions matching the file's naming pattern
    # Bad function: <basename>_bad
    bad_name = f"{basename}_bad"
    if re.search(rf'\b{re.escape(bad_name)}\s*\(', text):
        funcs.append(bad_name)

    # Good functions: <basename>_good, good1, good2, ...
    good_name = f"{basename}_good"
    if re.search(rf'\b{re.escape(good_name)}\s*\(', text):
        funcs.append(good_name)

    # Also look for goodN functions (standalone names)
    for m in re.finditer(r'\bvoid\s+(good\d+)\s*\(', text):
        funcs.append(m.group(1))

    return funcs


def _classify_by_procedure(procedure: str) -> str:
    """Classify a finding as TP/FP based on Juliet procedure naming convention.

    Returns 'tp', 'fp', or 'unknown'.
    """
    if '_bad' in procedure or 'Bad' in procedure:
        return 'tp'
    if 'good' in procedure.lower():
        return 'fp'
    # Helper functions outside guards — classify by line using file sections
    return 'unknown'


def _classify_by_line(line: int, sections: dict) -> str:
    """Classify by line number within OMITBAD/OMITGOOD sections."""
    if line in sections['bad_lines']:
        return 'tp'
    if line in sections['good_lines']:
        return 'fp'
    return 'unknown'


# ── Infer runner ─────────────────────────────────────────────────────────────

def _run_infer_cwe(cwe_id: str, cwe_dir: Path, jobs: int = 1) -> dict:
    """Run Infer on all .c files in a CWE directory.

    Uses incremental capture (--continue) then a single analyze pass.
    Returns: {cwe_id, tp, fp, unknown, findings, duration_s, files, errors}
    """
    c_files = _collect_c_files(cwe_dir)
    if not c_files:
        return {"cwe_id": cwe_id, "tp": 0, "fp": 0, "unknown": 0,
                "findings": [], "duration_s": 0, "files": 0, "errors": []}

    workdir = tempfile.mkdtemp(prefix=f"infer_{cwe_id}_")
    start = time.monotonic()
    errors = []

    try:
        # Capture phase: compile each file
        for f in c_files:
            try:
                subprocess.run(
                    ["infer", "capture", "--continue",
                     "--", "gcc", "-c",
                     f"-I{JULIET_SUPPORT}",
                     str(f), "-o", "/dev/null"],
                    capture_output=True, timeout=30,
                    cwd=workdir,
                )
            except subprocess.TimeoutExpired:
                errors.append(f"capture timeout: {f.name}")
            except Exception as e:
                errors.append(f"capture error {f.name}: {e}")

        # Analyze phase
        try:
            subprocess.run(
                ["infer", "analyze", "--no-progress-bar"],
                capture_output=True, timeout=3600,
                cwd=workdir,
            )
        except subprocess.TimeoutExpired:
            errors.append("analyze timeout")
            return {"cwe_id": cwe_id, "tp": 0, "fp": 0, "unknown": 0,
                    "findings": [], "duration_s": round(time.monotonic() - start, 1),
                    "files": len(c_files), "errors": errors}

        # Parse results
        report_path = Path(workdir) / "infer-out" / "report.json"
        if not report_path.exists():
            errors.append("no report.json produced")
            return {"cwe_id": cwe_id, "tp": 0, "fp": 0, "unknown": 0,
                    "findings": [], "duration_s": round(time.monotonic() - start, 1),
                    "files": len(c_files), "errors": errors}

        report = json.loads(report_path.read_text())
        duration_s = round(time.monotonic() - start, 1)

        # Classify findings
        tp = fp = unknown = 0
        findings = []
        # Cache file sections for line-level fallback
        sections_cache = {}

        for bug in report:
            proc = bug.get("procedure", "")
            bug_file = bug.get("file", "")
            line = bug.get("line", 0)
            bug_type = bug.get("bug_type", "")

            classification = _classify_by_procedure(proc)

            # Fallback: use line-level classification
            if classification == 'unknown' and bug_file and line:
                fpath = Path(bug_file)
                if fpath.exists():
                    if bug_file not in sections_cache:
                        sections_cache[bug_file] = parse_c_file_sections(fpath)
                    classification = _classify_by_line(line, sections_cache[bug_file])

            if classification == 'tp':
                tp += 1
            elif classification == 'fp':
                fp += 1
            else:
                unknown += 1

            findings.append({
                "file": os.path.basename(bug_file),
                "line": line,
                "bug_type": bug_type,
                "procedure": proc,
                "classification": classification,
            })

        return {
            "cwe_id": cwe_id,
            "cwe_dir": cwe_dir.name,
            "tp": tp,
            "fp": fp,
            "unknown": unknown,
            "findings": findings,
            "duration_s": duration_s,
            "files": len(c_files),
            "errors": errors,
        }

    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ── Frama-C runner ───────────────────────────────────────────────────────────

_FRAMAC_ALARM_RE = re.compile(
    r"\[eva:alarm\]\s+(.+?):(\d+):\s+Warning:\s*\n?\s*(.+?)(?:\.\s+assert\s+(.+)|$)",
    re.MULTILINE,
)

# Simpler per-line pattern for alarm extraction
_FRAMAC_ALARM_LINE_RE = re.compile(
    r"\[eva:alarm\]\s+(.+?):(\d+):")

_FRAMAC_ASSERT_RE = re.compile(
    r"assertion\s+'Eva,(\w+)'\s+got\s+final\s+status\s+(invalid|unknown)")


def _run_framac_file(filepath: Path, entry_func: str,
                     is_bad: bool) -> list[dict]:
    """Run Frama-C EVA on a single file with a specific entry point.

    Returns list of alarm dicts.
    """
    cmd = [
        "frama-c", "-eva",
        "-eva-precision", "1",
        "-machdep", "gcc_x86_64",
        "-lib-entry",
        f"-main={entry_func}",
        "-warn-signed-overflow",
        "-warn-signed-downcast",
        f"-cpp-extra-args=-I {JULIET_SUPPORT}",
        str(filepath),
    ]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return [{"file": filepath.name, "line": 0, "alarm_type": "timeout",
                 "entry_func": entry_func, "is_bad": is_bad}]
    except Exception:
        return []

    output = proc.stdout + proc.stderr
    alarms = []

    # Parse [eva:alarm] lines
    for m in _FRAMAC_ALARM_LINE_RE.finditer(output):
        alarm_file = m.group(1)
        alarm_line = int(m.group(2))
        # Only count alarms in our target file
        if filepath.name in alarm_file or filepath.stem in alarm_file:
            alarms.append({
                "file": filepath.name,
                "line": alarm_line,
                "alarm_type": "eva_alarm",
                "entry_func": entry_func,
                "is_bad": is_bad,
            })

    # Parse assertion statuses (more precise)
    for m in _FRAMAC_ASSERT_RE.finditer(output):
        alarm_kind = m.group(1)
        status = m.group(2)
        alarms.append({
            "file": filepath.name,
            "line": 0,  # not available from this pattern
            "alarm_type": alarm_kind,
            "status": status,
            "entry_func": entry_func,
            "is_bad": is_bad,
        })

    # Deduplicate by (file, line, alarm_type)
    seen = set()
    unique = []
    for a in alarms:
        key = (a["file"], a["line"], a["alarm_type"])
        if key not in seen:
            seen.add(key)
            unique.append(a)

    return unique


def _run_framac_cwe(cwe_id: str, cwe_dir: Path) -> dict:
    """Run Frama-C on all .c files in a CWE directory.

    For each file: run EVA on the _bad function, then the _good function.
    Alarms in _bad = TP, alarms in _good = FP.
    """
    c_files = _collect_c_files(cwe_dir)
    if not c_files:
        return {"cwe_id": cwe_id, "tp": 0, "fp": 0, "unknown": 0,
                "findings": [], "duration_s": 0, "files": 0, "errors": []}

    start = time.monotonic()
    tp = fp = unknown = 0
    findings = []
    errors = []
    files_processed = 0

    for filepath in c_files:
        funcs = _extract_function_names(filepath)
        if not funcs:
            continue
        files_processed += 1

        for func in funcs:
            is_bad = '_bad' in func or 'Bad' in func
            is_good = 'good' in func.lower()

            alarms = _run_framac_file(filepath, func, is_bad)

            for alarm in alarms:
                if alarm.get("alarm_type") == "timeout":
                    errors.append(f"timeout: {filepath.name}:{func}")
                    continue

                if is_bad:
                    tp += 1
                    alarm["classification"] = "tp"
                elif is_good:
                    fp += 1
                    alarm["classification"] = "fp"
                else:
                    unknown += 1
                    alarm["classification"] = "unknown"

                findings.append(alarm)

    duration_s = round(time.monotonic() - start, 1)

    return {
        "cwe_id": cwe_id,
        "cwe_dir": cwe_dir.name,
        "tp": tp,
        "fp": fp,
        "unknown": unknown,
        "findings": findings,
        "duration_s": duration_s,
        "files": files_processed,
        "errors": errors,
    }


# ── cppcheck runner ──────────────────────────────────────────────────────────

def _run_cppcheck_cwe(cwe_id: str, cwe_dir: Path) -> dict:
    """Run cppcheck on all .c files in a CWE directory.

    Uses --xml for structured output, classifies by line number.
    """
    c_files = _collect_c_files(cwe_dir)
    if not c_files:
        return {"cwe_id": cwe_id, "tp": 0, "fp": 0, "unknown": 0,
                "findings": [], "duration_s": 0, "files": 0, "errors": []}

    start = time.monotonic()
    tp = fp = unknown = 0
    findings = []
    errors = []
    sections_cache = {}

    for filepath in c_files:
        try:
            proc = subprocess.run(
                ["cppcheck", "--enable=all", "--std=c11",
                 "--xml", "--xml-version=2",
                 "--suppress=missingIncludeSystem",
                 f"-I{JULIET_SUPPORT}",
                 str(filepath)],
                capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            errors.append(f"timeout: {filepath.name}")
            continue
        except Exception as e:
            errors.append(f"error {filepath.name}: {e}")
            continue

        # Parse XML from stderr
        xml_output = proc.stderr
        if not xml_output.strip() or '<results' not in xml_output:
            continue

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            continue

        for error_elem in root.findall('.//error'):
            error_id = error_elem.get('id', '')
            severity = error_elem.get('severity', '')
            # Skip style/information findings that aren't real bugs
            if severity in ('information',):
                continue

            loc = error_elem.find('location')
            if loc is None:
                continue
            line = int(loc.get('line', 0))
            loc_file = loc.get('file', '')

            # Only count findings in our target file
            if filepath.name not in loc_file:
                continue

            # Classify by line
            fpath_str = str(filepath)
            if fpath_str not in sections_cache:
                sections_cache[fpath_str] = parse_c_file_sections(filepath)
            classification = _classify_by_line(line, sections_cache[fpath_str])

            if classification == 'tp':
                tp += 1
            elif classification == 'fp':
                fp += 1
            else:
                unknown += 1

            findings.append({
                "file": filepath.name,
                "line": line,
                "check_id": error_id,
                "severity": severity,
                "classification": classification,
            })

    duration_s = round(time.monotonic() - start, 1)
    return {
        "cwe_id": cwe_id,
        "cwe_dir": cwe_dir.name,
        "tp": tp, "fp": fp, "unknown": unknown,
        "findings": findings,
        "duration_s": duration_s,
        "files": len(c_files),
        "errors": errors,
    }


# ── clang-tidy runner ────────────────────────────────────────────────────────

_CLANGTIDY_WARN_RE = re.compile(
    r'^(.+?):(\d+):\d+:\s+warning:\s+(.+?)\s+\[([^\]]+)\]',
)


def _run_clangtidy_cwe(cwe_id: str, cwe_dir: Path) -> dict:
    """Run clang-tidy on all .c files in a CWE directory.

    Uses cert-* and clang-analyzer-* checks.
    """
    c_files = _collect_c_files(cwe_dir)
    if not c_files:
        return {"cwe_id": cwe_id, "tp": 0, "fp": 0, "unknown": 0,
                "findings": [], "duration_s": 0, "files": 0, "errors": []}

    start = time.monotonic()
    tp = fp = unknown = 0
    findings = []
    errors = []
    sections_cache = {}

    for filepath in c_files:
        try:
            proc = subprocess.run(
                ["clang-tidy",
                 "-checks=-*,cert-*,clang-analyzer-*",
                 str(filepath),
                 "--", "-std=c11",
                 f"-I{JULIET_SUPPORT}"],
                capture_output=True, text=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            errors.append(f"timeout: {filepath.name}")
            continue
        except Exception as e:
            errors.append(f"error {filepath.name}: {e}")
            continue

        output = proc.stdout + proc.stderr

        for m in _CLANGTIDY_WARN_RE.finditer(output):
            warn_file = m.group(1)
            line = int(m.group(2))
            check_id = m.group(4)

            # Only count findings in our target file
            if filepath.name not in warn_file:
                continue

            fpath_str = str(filepath)
            if fpath_str not in sections_cache:
                sections_cache[fpath_str] = parse_c_file_sections(filepath)
            classification = _classify_by_line(line, sections_cache[fpath_str])

            if classification == 'tp':
                tp += 1
            elif classification == 'fp':
                fp += 1
            else:
                unknown += 1

            findings.append({
                "file": filepath.name,
                "line": line,
                "check_id": check_id,
                "classification": classification,
            })

    duration_s = round(time.monotonic() - start, 1)
    return {
        "cwe_id": cwe_id,
        "cwe_dir": cwe_dir.name,
        "tp": tp, "fp": fp, "unknown": unknown,
        "findings": findings,
        "duration_s": duration_s,
        "files": len(c_files),
        "errors": errors,
    }


# ── Parallel orchestration ───────────────────────────────────────────────────

def run_tool(tool: str, cwe_list: list[str] | None = None,
             jobs: int = 8) -> dict:
    """Run a competitor tool on specified CWEs.

    Args:
        tool: 'infer', 'framac', 'cppcheck', or 'clangtidy'
        cwe_list: list of CWE IDs (e.g. ['CWE476']). None = use defaults.
        jobs: parallel workers (for Infer capture; Frama-C is per-CWE serial)
    """
    default_cwes = {
        "infer": INFER_CWES, "framac": FRAMAC_CWES,
        "cppcheck": CPPCHECK_CWES, "clangtidy": CLANGTIDY_CWES,
    }
    if cwe_list is None:
        cwe_list = default_cwes.get(tool, ALL_CWES)

    print(f"{'='*70}")
    print(f"COMPETITOR BENCHMARK: {tool}")
    print(f"CWEs: {', '.join(cwe_list)} | Jobs: {jobs}")
    print(f"{'='*70}")

    results = {
        "tool": tool,
        "tool_version": _get_tool_version(tool),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "cwes": {},
        "totals": {"tp": 0, "fp": 0, "unknown": 0, "files": 0},
    }

    overall_start = time.monotonic()

    for cwe_id in cwe_list:
        cwe_dir = _find_cwe_dir(cwe_id)
        if cwe_dir is None:
            print(f"SKIP: {cwe_id} — directory not found")
            continue

        print(f"\nRunning {tool} on {cwe_id} ({cwe_dir.name})...")

        if tool == "infer":
            cwe_result = _run_infer_cwe(cwe_id, cwe_dir, jobs=jobs)
        elif tool == "framac":
            cwe_result = _run_framac_cwe(cwe_id, cwe_dir)
        elif tool == "cppcheck":
            cwe_result = _run_cppcheck_cwe(cwe_id, cwe_dir)
        elif tool == "clangtidy":
            cwe_result = _run_clangtidy_cwe(cwe_id, cwe_dir)
        else:
            raise ValueError(f"Unknown tool: {tool}")

        total = cwe_result["tp"] + cwe_result["fp"] + cwe_result["unknown"]
        tp_rate = (cwe_result["tp"] / total * 100) if total else 0

        print(f"  DONE: {cwe_result['duration_s']}s | "
              f"{cwe_result['files']} files | "
              f"{cwe_result['tp']} TP / {cwe_result['fp']} FP "
              f"({tp_rate:.1f}% TP rate)")

        if cwe_result["errors"]:
            print(f"  ERRORS: {len(cwe_result['errors'])}")
            for e in cwe_result["errors"][:3]:
                print(f"    {e}")

        # Store summary (not full findings list for the main output)
        results["cwes"][cwe_id] = {
            "cwe_dir": cwe_result.get("cwe_dir", ""),
            "tp": cwe_result["tp"],
            "fp": cwe_result["fp"],
            "unknown": cwe_result["unknown"],
            "files": cwe_result["files"],
            "duration_s": cwe_result["duration_s"],
            "errors": cwe_result["errors"],
            "finding_count": len(cwe_result["findings"]),
        }

        results["totals"]["tp"] += cwe_result["tp"]
        results["totals"]["fp"] += cwe_result["fp"]
        results["totals"]["unknown"] += cwe_result["unknown"]
        results["totals"]["files"] += cwe_result["files"]

    total_duration = round(time.monotonic() - overall_start, 1)
    results["duration_s"] = total_duration
    results["finished_at"] = datetime.now(timezone.utc).isoformat()

    t = results["totals"]
    total_findings = t["tp"] + t["fp"] + t["unknown"]
    tp_rate = (t["tp"] / total_findings * 100) if total_findings else 0
    results["totals"]["tp_rate_pct"] = round(tp_rate, 1)

    # Save results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = RESULTS_DIR / f"{tool}_{timestamp}.json"
    out_path.write_text(json.dumps(results, indent=2))

    print(f"\n{'='*70}")
    print(f"COMPLETE: {tool} | {total_duration}s total")
    print(f"  {t['tp']} TP / {t['fp']} FP / {t['unknown']} unknown "
          f"({tp_rate:.1f}% TP rate)")
    print(f"  Results: {out_path}")
    print(f"{'='*70}")

    return results


def _get_tool_version(tool: str) -> str:
    """Get version string for a tool."""
    try:
        if tool == "infer":
            r = subprocess.run(["infer", "--version"], capture_output=True,
                               text=True, timeout=5)
            return r.stdout.strip().split('\n')[0]
        elif tool == "framac":
            r = subprocess.run(
                ["bash", "-c", "eval $(opam env) && frama-c -version"],
                capture_output=True, text=True, timeout=10)
            return f"Frama-C {r.stdout.strip()}"
        elif tool == "cppcheck":
            r = subprocess.run(["cppcheck", "--version"], capture_output=True,
                               text=True, timeout=5)
            return r.stdout.strip()
        elif tool == "clangtidy":
            r = subprocess.run(["clang-tidy", "--version"], capture_output=True,
                               text=True, timeout=5)
            for line in r.stdout.splitlines():
                if 'LLVM version' in line:
                    return f"clang-tidy {line.strip()}"
            return r.stdout.strip().split('\n')[0]
    except Exception:
        pass
    return "unknown"


# ── Comparison ───────────────────────────────────────────────────────────────

def compare_results(file1: str, file2: str):
    """Compare two result files side by side."""
    r1 = json.loads(Path(file1).read_text())
    r2 = json.loads(Path(file2).read_text())

    all_cwes = sorted(set(r1.get("cwes", {}).keys()) |
                      set(r2.get("cwes", {}).keys()))

    name1 = f"{r1['tool']} ({r1.get('tool_version', '?')})"
    name2 = f"{r2['tool']} ({r2.get('tool_version', '?')})"

    print(f"\n{'CWE':<10} {'':>4} {name1:>30}  {name2:>30}")
    print(f"{'':─<10} {'':─>4} {'':─>30}  {'':─>30}")

    for cwe in all_cwes:
        c1 = r1.get("cwes", {}).get(cwe, {})
        c2 = r2.get("cwes", {}).get(cwe, {})

        tp1, fp1 = c1.get("tp", 0), c1.get("fp", 0)
        tp2, fp2 = c2.get("tp", 0), c2.get("fp", 0)
        tot1 = tp1 + fp1
        tot2 = tp2 + fp2
        rate1 = f"{tp1/tot1*100:.1f}%" if tot1 else "—"
        rate2 = f"{tp2/tot2*100:.1f}%" if tot2 else "—"

        s1 = f"{tp1} TP / {fp1} FP ({rate1})" if tot1 else "—"
        s2 = f"{tp2} TP / {fp2} FP ({rate2})" if tot2 else "—"

        print(f"{cwe:<10} {'':>4} {s1:>30}  {s2:>30}")

    # Totals
    t1, t2 = r1.get("totals", {}), r2.get("totals", {})
    print(f"\n{'TOTAL':<10} {'':>4} "
          f"{t1.get('tp',0)} TP / {t1.get('fp',0)} FP "
          f"({t1.get('tp_rate_pct',0):.1f}%)"
          f"{'':>4}"
          f"{t2.get('tp',0)} TP / {t2.get('fp',0)} FP "
          f"({t2.get('tp_rate_pct',0):.1f}%)")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Run competitor tools on Juliet")
    sub = parser.add_subparsers(dest="command")

    p_infer = sub.add_parser("infer", help="Run Facebook Infer")
    p_infer.add_argument("--cwes", help="Comma-separated CWE IDs")
    p_infer.add_argument("--jobs", type=int, default=8)

    p_framac = sub.add_parser("framac", help="Run Frama-C EVA")
    p_framac.add_argument("--cwes", help="Comma-separated CWE IDs")
    p_framac.add_argument("--jobs", type=int, default=8)

    p_cppcheck = sub.add_parser("cppcheck", help="Run cppcheck")
    p_cppcheck.add_argument("--cwes", help="Comma-separated CWE IDs")
    p_cppcheck.add_argument("--jobs", type=int, default=8)

    p_clangtidy = sub.add_parser("clangtidy", help="Run clang-tidy")
    p_clangtidy.add_argument("--cwes", help="Comma-separated CWE IDs")
    p_clangtidy.add_argument("--jobs", type=int, default=8)

    p_all = sub.add_parser("all", help="Run all four tools")
    p_all.add_argument("--jobs", type=int, default=8)

    p_cmp = sub.add_parser("compare", help="Compare two result files")
    p_cmp.add_argument("file1")
    p_cmp.add_argument("file2")

    args = parser.parse_args()

    if args.command in ("infer", "framac", "cppcheck", "clangtidy"):
        cwes = args.cwes.split(",") if args.cwes else None
        run_tool(args.command, cwes, args.jobs)
    elif args.command == "all":
        for tool in ("cppcheck", "clangtidy", "infer", "framac"):
            run_tool(tool, jobs=args.jobs)
    elif args.command == "compare":
        compare_results(args.file1, args.file2)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
