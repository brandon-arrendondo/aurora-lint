"""TP/FP classification engine for Juliet benchmark results.

Extracted from scripts/analyze_juliet_results.py. Returns structured data
instead of printing text, suitable for direct insertion into SQLite.
"""

import csv
import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from bench.config import RULE_CWE_MAP


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class CWEAnalysis:
    """Complete analysis result for one CWE scan."""
    cwe_id: str
    cwe_dir_name: str
    files_analyzed: int = 0
    tp_count: int = 0
    fp_count: int = 0
    tp_rate_pct: float = 0.0
    flaw_lines_total: int = 0
    flaw_lines_detected: int = 0
    flaw_detection_rate_pct: float = 0.0
    # Per-rule breakdown: {rule_id: {"tp": N, "fp": N, "flaw": N}}
    rule_breakdown: dict = field(default_factory=dict)
    # CWE-aware metrics (None if not available)
    cwe_matched_tp: int = 0
    cwe_matched_fp: int = 0
    noise_count: int = 0
    noise_ratio: float = 0.0
    per_file_detected: int = 0
    per_file_total: int = 0
    per_file_rate: float = 0.0
    flaw_hit_detected: int = 0
    flaw_hit_total: int = 0
    flaw_hit_rate: float = 0.0
    cwe_rules: set = field(default_factory=set)
    # Raw violations for DB insertion
    violations: list = field(default_factory=list)


# ── Core parsing (from analyze_juliet_results.py) ────────────────────────────

def parse_c_file_sections(filepath: str | Path) -> dict:
    """Parse a Juliet C file to identify OMITBAD/OMITGOOD line ranges and FLAW lines.

    Also performs call-graph analysis to reclassify helper functions defined
    outside guards but called exclusively from one guard section.

    Returns: {'bad_lines': set, 'good_lines': set, 'flaw_lines': set}
    """
    result = {'bad_lines': set(), 'good_lines': set(), 'flaw_lines': set()}

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    in_bad = False
    in_good = False

    for i, line in enumerate(lines, start=1):
        if 'FLAW:' in line or 'POTENTIAL FLAW:' in line:
            result['flaw_lines'].add(i)

        if '#ifndef OMITBAD' in line:
            in_bad = True
            in_good = False
        elif '#endif /* OMITBAD */' in line or '#endif  /* OMITBAD */' in line:
            in_bad = False
        elif '#ifndef OMITGOOD' in line:
            in_good = True
            in_bad = False
        elif '#endif /* OMITGOOD */' in line or '#endif  /* OMITGOOD */' in line:
            in_good = False

        if in_bad:
            result['bad_lines'].add(i)
        elif in_good:
            result['good_lines'].add(i)

    # Reclassify helper functions defined outside guards based on call sites
    _reclassify_helpers(lines, result)

    return result


# Matches file-scope function definitions (static or non-static, not indented)
_FUNC_DEF_RE = re.compile(
    r'^(?:static\s+)?'           # optional static
    r'(?:[\w*\s]+\s+)'          # return type (may include pointers/qualifiers)
    r'(\w+)'                     # function name (capture group 1)
    r'\s*\([^)]*\)\s*$'         # parameter list, line ends after )
)


def _parse_function_ranges(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Find file-scope function definitions and their line ranges.

    Returns: {func_name: (start_line, end_line)} using 1-based line numbers.
    """
    functions = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        # Skip preprocessor directives and indented lines (not file-scope)
        if line.startswith('#') or (line and line[0] in ' \t'):
            i += 1
            continue

        m = _FUNC_DEF_RE.match(line.rstrip())
        if m:
            func_name = m.group(1)
            # Look for opening brace on this line or next few lines
            brace_line = None
            for j in range(i, min(i + 3, len(lines))):
                if '{' in lines[j]:
                    brace_line = j
                    break
            if brace_line is not None:
                # Track brace depth to find function end
                depth = 0
                start = i + 1  # 1-based
                end = start
                for j in range(brace_line, len(lines)):
                    for ch in lines[j]:
                        if ch == '{':
                            depth += 1
                        elif ch == '}':
                            depth -= 1
                            if depth == 0:
                                end = j + 1  # 1-based
                                functions[func_name] = (start, end)
                                i = j + 1
                                break
                    if depth == 0 and func_name in functions:
                        break
                else:
                    i += 1
                continue
        i += 1
    return functions


def _reclassify_helpers(lines: list[str], result: dict) -> None:
    """Reclassify helper functions outside guards based on call-site analysis.

    If a function defined outside both OMITBAD/OMITGOOD guards is called
    exclusively from bad sections, its lines are added to bad_lines (TP).
    If exclusively from good sections, added to good_lines (FP).
    Mixed or uncalled functions stay unclassified (unknown).
    """
    bad_lines = result['bad_lines']
    good_lines = result['good_lines']

    functions = _parse_function_ranges(lines)
    if not functions:
        return

    # Find functions defined outside both guard sections
    outside_funcs = {}
    for name, (start, end) in functions.items():
        if start not in bad_lines and start not in good_lines:
            outside_funcs[name] = (start, end)

    if not outside_funcs:
        return

    # Scan classified lines for references to outside functions.
    # Matches both direct calls (helperBad(...)) and function pointer
    # references (signal(SIGINT, helperBad)).
    calls_from_bad = set()   # func names referenced from bad sections
    calls_from_good = set()  # func names referenced from good sections

    # Pre-compile word-boundary patterns for each outside function
    func_patterns = {
        name: re.compile(r'(?<![a-zA-Z0-9_])' + re.escape(name) + r'(?![a-zA-Z0-9_])')
        for name in outside_funcs
    }

    for i, line in enumerate(lines, start=1):
        if i not in bad_lines and i not in good_lines:
            continue
        for func_name, pattern in func_patterns.items():
            if pattern.search(line):
                if i in bad_lines:
                    calls_from_bad.add(func_name)
                if i in good_lines:
                    calls_from_good.add(func_name)

    # Reclassify: extend bad_lines/good_lines for exclusively-called helpers
    for func_name, (start, end) in outside_funcs.items():
        in_bad_only = func_name in calls_from_bad and func_name not in calls_from_good
        in_good_only = func_name in calls_from_good and func_name not in calls_from_bad
        if in_bad_only:
            for line_num in range(start, end + 1):
                bad_lines.add(line_num)
        elif in_good_only:
            for line_num in range(start, end + 1):
                good_lines.add(line_num)


def parse_sqc_csv(csv_path: str | Path) -> dict:
    """Parse SqC CSV output to violations by file and line.

    Returns: {filename: {line_num: [(rule_id, filepath)]}}
    """
    violations = defaultdict(lambda: defaultdict(list))

    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            title = row['Title']
            # Strip " version:HASH" suffix added by sqc export
            title = re.sub(r'\s+version:\S+$', '', title)
            match = re.match(r'([A-Z0-9-]+):(.+):(\d+)', title)
            if match:
                rule_id = match.group(1)
                filepath = match.group(2)
                line_num = int(match.group(3))
                filename = os.path.basename(filepath)
                violations[filename][line_num].append((rule_id, filepath))

    return violations


def _normalize_cwe_id(raw: str) -> str:
    """Normalize CWE ID to 'CWE-NNN' format."""
    raw = raw.strip().upper()
    if raw.startswith("CWE-"):
        return raw
    if raw.startswith("CWE"):
        return "CWE-" + raw[3:]
    if raw.isdigit():
        return "CWE-" + raw
    return raw


def _extract_cwe_from_dir(dir_path: str) -> str | None:
    """Extract CWE ID from a Juliet directory name."""
    dirname = Path(dir_path).name
    m = re.match(r'(CWE)(\d+)', dirname)
    if m:
        return f"CWE-{m.group(2)}"
    return None


def _hits_flaw_line(line_num: int, flaw_lines: set) -> bool:
    """Check if a violation line hits a FLAW line with +/-1 tolerance."""
    return (line_num in flaw_lines or
            line_num - 1 in flaw_lines or
            line_num + 1 in flaw_lines)


def _load_cwe_rules(cwe_id: str) -> set:
    """Load the set of rule IDs mapped to a CWE from rule_cwe_map.json."""
    if not RULE_CWE_MAP.exists():
        return set()
    try:
        with open(RULE_CWE_MAP) as f:
            data = json.load(f)
        return set(data.get("cwe_to_rules", {}).get(cwe_id, []))
    except Exception:
        return set()


# ── Main orchestrator ─────────────────────────────────────────────────────────

def analyze_cwe(csv_path: str | Path, cwe_dir: str | Path,
                cwe_scan_id: int | None = None) -> CWEAnalysis:
    """Analyze a single CWE scan result.

    Args:
        csv_path: Path to sqc CSV output for this CWE.
        cwe_dir: Path to the Juliet CWE test directory.
        cwe_scan_id: Optional DB foreign key for violation records.

    Returns:
        CWEAnalysis with all metrics and raw violations.
    """
    cwe_dir = Path(cwe_dir)
    csv_path = Path(csv_path)
    cwe_dir_name = cwe_dir.name
    cwe_id = _extract_cwe_from_dir(str(cwe_dir)) or cwe_dir_name
    cwe_rules = _load_cwe_rules(cwe_id)

    analysis = CWEAnalysis(cwe_id=cwe_id, cwe_dir_name=cwe_dir_name)
    analysis.cwe_rules = cwe_rules

    # Parse CSV violations
    violations_dict = parse_sqc_csv(csv_path)

    # Find all C files (handle subdirectory layout like CWE-121)
    subdirs = sorted(cwe_dir.glob('s*'))
    if subdirs and subdirs[0].is_dir():
        search_dirs = subdirs
    else:
        search_dirs = [cwe_dir]

    # Per-rule counters
    rule_tp = defaultdict(int)
    rule_fp = defaultdict(int)
    rule_flaw = defaultdict(int)

    # CWE-aware counters
    files_with_bad_section = 0
    files_detected = 0
    total_flaw_lines_for_hit = 0

    for search_dir in search_dirs:
        if not search_dir.is_dir():
            continue
        for c_file in sorted(search_dir.glob('*.c')):
            result = _process_cwe_file(
                c_file, violations_dict, cwe_rules, analysis, cwe_scan_id,
                rule_tp, rule_fp, rule_flaw)
            if result is None:
                continue
            has_bad, file_has_cwe_tp, flaw_line_count = result
            total_flaw_lines_for_hit += flaw_line_count
            if has_bad:
                files_with_bad_section += 1
            if file_has_cwe_tp:
                files_detected += 1

    _finalize_cwe_rates(analysis, files_with_bad_section, files_detected,
                        total_flaw_lines_for_hit)
    _build_rule_breakdown(analysis, rule_tp, rule_fp, rule_flaw, cwe_rules)

    return analysis


def _process_cwe_file(c_file, violations_dict, cwe_rules, analysis, cwe_scan_id,
                      rule_tp, rule_fp, rule_flaw):
    """Classify one Juliet C file's violations against its bad/good sections.

    Updates `analysis`/`rule_tp`/`rule_fp`/`rule_flaw` in place. Returns
    `None` if the file has no labeled bad/good sections (skip it), else
    `(has_bad_section, file_has_cwe_tp, flaw_line_count)`.
    """
    sections = parse_c_file_sections(c_file)
    filename = c_file.name
    file_violations = violations_dict.get(filename, {})

    if not sections['bad_lines'] and not sections['good_lines']:
        return None

    analysis.files_analyzed += 1
    analysis.flaw_lines_total += len(sections['flaw_lines'])

    file_has_cwe_tp = False
    for line_num, rule_entries in file_violations.items():
        for rule_id, filepath in rule_entries:
            if _classify_and_record_violation(
                line_num, rule_id, filepath, sections, cwe_rules, analysis,
                cwe_scan_id, rule_tp, rule_fp, rule_flaw,
            ):
                file_has_cwe_tp = True

    return bool(sections['bad_lines']), file_has_cwe_tp, len(sections['flaw_lines'])


def _classify_and_record_violation(line_num, rule_id, filepath, sections, cwe_rules,
                                   analysis, cwe_scan_id, rule_tp, rule_fp, rule_flaw):
    """Classify one violation as tp/fp/unknown against a file's labeled
    sections, update the running counters, and optionally append a DB
    violation record. Returns True iff this is a CWE-matched true positive.
    """
    in_bad = line_num in sections['bad_lines']
    in_good = line_num in sections['good_lines']
    on_flaw = _hits_flaw_line(line_num, sections['flaw_lines'])
    is_matched = rule_id in cwe_rules if cwe_rules else False
    is_cwe_matched_tp = False

    if in_bad:
        classification = "tp"
        analysis.tp_count += 1
        rule_tp[rule_id] += 1
        if line_num in sections['flaw_lines']:
            analysis.flaw_lines_detected += 1
            rule_flaw[rule_id] += 1

        if is_matched:
            analysis.cwe_matched_tp += 1
            is_cwe_matched_tp = True
            if on_flaw:
                analysis.flaw_hit_detected += 1
        else:
            analysis.noise_count += 1
    elif in_good:
        classification = "fp"
        analysis.fp_count += 1
        rule_fp[rule_id] += 1

        if is_matched:
            analysis.cwe_matched_fp += 1
        else:
            analysis.noise_count += 1
    else:
        classification = "unknown"

    # Build violation record for DB
    if cwe_scan_id is not None:
        analysis.violations.append({
            "cwe_scan_id": cwe_scan_id,
            "rule_id": rule_id,
            "file_path": filepath,
            "line": line_num,
            "classification": classification,
            "in_bad_section": int(in_bad),
            "in_good_section": int(in_good),
            "hits_flaw_line": int(on_flaw),
            "is_cwe_matched": int(is_matched),
        })

    return is_cwe_matched_tp


def _finalize_cwe_rates(analysis, files_with_bad_section, files_detected,
                        total_flaw_lines_for_hit):
    """Compute the derived rate fields on `analysis` from the raw counters."""
    total_violations = analysis.tp_count + analysis.fp_count
    if total_violations > 0:
        analysis.tp_rate_pct = round(analysis.tp_count / total_violations * 100, 1)

    if analysis.flaw_lines_total > 0:
        analysis.flaw_detection_rate_pct = round(
            analysis.flaw_lines_detected / analysis.flaw_lines_total * 100, 1)

    # CWE-aware rates
    cwe_matched_total = analysis.cwe_matched_tp + analysis.cwe_matched_fp
    all_total = cwe_matched_total + analysis.noise_count
    if all_total > 0:
        analysis.noise_ratio = round(analysis.noise_count / all_total * 100, 1)

    analysis.per_file_detected = files_detected
    analysis.per_file_total = files_with_bad_section
    if files_with_bad_section > 0:
        analysis.per_file_rate = round(files_detected / files_with_bad_section * 100, 1)

    analysis.flaw_hit_total = total_flaw_lines_for_hit
    if total_flaw_lines_for_hit > 0:
        analysis.flaw_hit_rate = round(
            analysis.flaw_hit_detected / total_flaw_lines_for_hit * 100, 1)


def _build_rule_breakdown(analysis, rule_tp, rule_fp, rule_flaw, cwe_rules):
    """Populate `analysis.rule_breakdown` from the per-rule counters."""
    all_rules = set(rule_tp) | set(rule_fp) | set(rule_flaw)
    for rule in all_rules:
        analysis.rule_breakdown[rule] = {
            "tp": rule_tp.get(rule, 0),
            "fp": rule_fp.get(rule, 0),
            "flaw": rule_flaw.get(rule, 0),
            "is_cwe_matched": int(rule in cwe_rules) if cwe_rules else 0,
        }
