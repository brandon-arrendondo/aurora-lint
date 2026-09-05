#!/usr/bin/env python3
"""Generate docs/juliet-coverage.md from the latest Juliet benchmark run in SQLite.

Usage:
    python scripts/generate_juliet_coverage.py            # latest run
    python scripts/generate_juliet_coverage.py RUN_ID     # specific run
"""

import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "benchmarks.db"
OUT_PATH = Path(__file__).resolve().parent.parent / "docs" / "juliet-coverage.md"


def _cwe_description(cwe_dir_name: str) -> str:
    """Extract human-readable description from cwe_dir_name.

    e.g. 'CWE121_Stack_Based_Buffer_Overflow' -> 'Stack buffer overflow'
    """
    parts = cwe_dir_name.split("_", 1)
    if len(parts) < 2:
        return cwe_dir_name
    return parts[1].replace("_", " ").strip()


def main():
    if not DB_PATH.exists():
        print(f"Error: database not found at {DB_PATH}", file=sys.stderr)
        sys.exit(1)

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Resolve run
    if len(sys.argv) > 1:
        run_id = sys.argv[1]
        row = conn.execute(
            "SELECT run_id, sqc_version FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if not row:
            print(f"Error: run '{run_id}' not found", file=sys.stderr)
            sys.exit(1)
    else:
        row = conn.execute(
            "SELECT run_id, sqc_version FROM runs "
            "WHERE status = 'completed' ORDER BY finished_at DESC LIMIT 1"
        ).fetchone()
        if not row:
            print("Error: no completed runs found", file=sys.stderr)
            sys.exit(1)

    run_id = row["run_id"]
    version = row["sqc_version"]

    # Fetch all CWE metrics
    cwes = conn.execute(
        """
        SELECT cs.cwe_id, cs.cwe_dir_name, cs.file_count,
               cm.tp_count, cm.fp_count, cm.tp_rate_pct, cm.per_file_rate
        FROM cwe_scans cs
        JOIN cwe_metrics cm ON cm.cwe_scan_id = cs.id
        WHERE cs.run_id = ?
        ORDER BY cm.tp_rate_pct DESC, cm.tp_count DESC
        """,
        (run_id,),
    ).fetchall()

    # Totals
    total_tp = sum(c["tp_count"] for c in cwes)
    total_fp = sum(c["fp_count"] for c in cwes)
    total_files = sum(c["file_count"] for c in cwes)
    total = total_tp + total_fp
    overall_tp_rate = total_tp / total * 100 if total else 0
    n_cwes = len(cwes)

    # Categorize CWEs
    perfect = []   # 100% precision (0 FP, >0 TP)
    high = []      # >50% TP rate
    medium = []    # 33-50%
    low = []       # >0% and <33%
    zero = []      # 0 TP

    for c in cwes:
        tp, fp = c["tp_count"], c["fp_count"]
        rate = c["tp_rate_pct"]
        if tp == 0:
            zero.append(c)
        elif fp == 0:
            perfect.append(c)
        elif rate > 50:
            high.append(c)
        elif rate >= 33:
            medium.append(c)
        else:
            low.append(c)

    # Sort each bucket
    perfect.sort(key=lambda c: c["per_file_rate"], reverse=True)
    high.sort(key=lambda c: c["tp_rate_pct"], reverse=True)
    medium.sort(key=lambda c: c["tp_rate_pct"], reverse=True)
    low.sort(key=lambda c: c["tp_rate_pct"], reverse=True)
    zero.sort(key=lambda c: c["file_count"], reverse=True)

    # Top rules by TP volume
    rules = conn.execute(
        """
        SELECT rb.rule_id, SUM(rb.tp_count) as tp, SUM(rb.fp_count) as fp
        FROM rule_cwe_breakdown rb
        JOIN cwe_scans cs ON rb.cwe_scan_id = cs.id
        WHERE cs.run_id = ?
        GROUP BY rb.rule_id
        ORDER BY tp DESC
        LIMIT 18
        """,
        (run_id,),
    ).fetchall()

    # Rule-to-CWE mapping (top CWEs per rule)
    rule_cwes_raw = conn.execute(
        """
        SELECT rb.rule_id, cs.cwe_id, rb.tp_count
        FROM rule_cwe_breakdown rb
        JOIN cwe_scans cs ON rb.cwe_scan_id = cs.id
        WHERE cs.run_id = ? AND rb.tp_count > 0
        ORDER BY rb.rule_id, rb.tp_count DESC
        """,
        (run_id,),
    ).fetchall()

    rule_cwes = defaultdict(list)
    for r in rule_cwes_raw:
        rule_cwes[r["rule_id"]].append(r["cwe_id"])

    # Check which zero-detection CWEs have any rule_cwe_breakdown entries
    zero_has_rules = {}
    for c in zero:
        count = conn.execute(
            """
            SELECT COUNT(*) FROM rule_cwe_breakdown rb
            JOIN cwe_scans cs ON rb.cwe_scan_id = cs.id
            WHERE cs.run_id = ? AND cs.cwe_id = ?
            """,
            (run_id, c["cwe_id"]),
        ).fetchone()[0]
        zero_has_rules[c["cwe_id"]] = count > 0

    conn.close()

    # Generate markdown
    lines = []
    lines.append("# Juliet C Test Suite — Coverage Report")
    lines.append("")
    lines.append(
        f"**Version**: sqc v{version} ({run_id})\n"
        f"**Overall**: {total_tp:,} TP / {total_fp:,} FP — "
        f"**{overall_tp_rate:.1f}% TP rate** across {n_cwes} CWEs "
        f"({total_files:,} files)"
    )
    lines.append("")
    lines.append(
        "*Auto-generated by `scripts/generate_juliet_coverage.py` from "
        "`data/benchmarks.db`.*"
    )
    lines.append("")
    lines.append("---")
    lines.append("")

    # 100% precision
    lines.append(f"## 100% Precision ({len(perfect)} CWEs — zero FP)")
    lines.append("")
    lines.append("| CWE | Description | TP | Files | Per-File |")
    lines.append("|-----|------------|---:|------:|--------:|")
    for c in perfect:
        desc = _cwe_description(c["cwe_dir_name"])
        lines.append(
            f"| {c['cwe_id']} | {desc} | {c['tp_count']} "
            f"| {c['file_count']} | {c['per_file_rate']:.1f}% |"
        )
    lines.append("")

    # High precision
    lines.append(f"## High Precision (>50% TP rate, {len(high)} CWEs)")
    lines.append("")
    lines.append("| CWE | Description | TP | FP | TP Rate | Per-File |")
    lines.append("|-----|------------|---:|---:|--------:|--------:|")
    for c in high:
        desc = _cwe_description(c["cwe_dir_name"])
        lines.append(
            f"| {c['cwe_id']} | {desc} | {c['tp_count']} "
            f"| {c['fp_count']} | {c['tp_rate_pct']:.1f}% "
            f"| {c['per_file_rate']:.1f}% |"
        )
    lines.append("")

    # Medium precision
    lines.append(
        f"## Medium Precision (33–50% TP rate, {len(medium)} CWEs)"
    )
    lines.append("")
    lines.append("| CWE | Description | TP | FP | TP Rate | Per-File |")
    lines.append("|-----|------------|---:|---:|--------:|--------:|")
    for c in medium:
        desc = _cwe_description(c["cwe_dir_name"])
        lines.append(
            f"| {c['cwe_id']} | {desc} | {c['tp_count']} "
            f"| {c['fp_count']} | {c['tp_rate_pct']:.1f}% "
            f"| {c['per_file_rate']:.1f}% |"
        )
    lines.append("")

    # Low precision
    lines.append(f"## Low Precision (<33% TP rate, {len(low)} CWEs)")
    lines.append("")
    lines.append("| CWE | Description | TP | FP | TP Rate | Per-File |")
    lines.append("|-----|------------|---:|---:|--------:|--------:|")
    for c in low:
        desc = _cwe_description(c["cwe_dir_name"])
        lines.append(
            f"| {c['cwe_id']} | {desc} | {c['tp_count']} "
            f"| {c['fp_count']} | {c['tp_rate_pct']:.1f}% "
            f"| {c['per_file_rate']:.1f}% |"
        )
    lines.append("")

    # Zero detection
    # Filter out CWEs with 0 files (no test data)
    zero_with_files = [c for c in zero if c["file_count"] > 0]
    zero_no_files = [c for c in zero if c["file_count"] == 0]

    lines.append(f"## Zero Detection ({len(zero_with_files)} CWEs)")
    lines.append("")
    lines.append("| CWE | Description | Files | Notes |")
    lines.append("|-----|------------|------:|-------|")
    for c in zero_with_files:
        desc = _cwe_description(c["cwe_dir_name"])
        cwe_id = c["cwe_id"]
        has_rules = zero_has_rules.get(cwe_id, False)
        if has_rules:
            fp = c["fp_count"]
            note = f"0 TP, {fp} FP" if fp > 0 else "Rules mapped but no detections"
        else:
            note = "No rule mapped"
        lines.append(
            f"| {cwe_id} | {desc} | {c['file_count']} | {note} |"
        )

    if zero_no_files:
        lines.append("")
        lines.append(
            f"*{len(zero_no_files)} additional CWEs had no test files: "
            + ", ".join(c["cwe_id"] for c in zero_no_files)
            + ".*"
        )
    lines.append("")

    # Top rules
    lines.append("## Top Rules by TP Volume")
    lines.append("")
    lines.append("| Rule | TP | FP | FP Rate | Primary CWEs |")
    lines.append("|------|---:|---:|--------:|-------------|")
    for r in rules:
        tp, fp = r["tp"], r["fp"]
        total_r = tp + fp
        fp_rate = fp / total_r * 100 if total_r else 0
        primary = ", ".join(rule_cwes[r["rule_id"]][:4])
        lines.append(
            f"| {r['rule_id']} | {tp:,} | {fp:,} | {fp_rate:.1f}% | {primary} |"
        )
    lines.append("")

    # Write output
    content = "\n".join(lines)
    OUT_PATH.write_text(content)
    print(f"Generated {OUT_PATH} from run {run_id} (v{version})")
    print(
        f"  {n_cwes} CWEs: {len(perfect)} perfect, {len(high)} high, "
        f"{len(medium)} medium, {len(low)} low, {len(zero_with_files)} zero"
    )


if __name__ == "__main__":
    main()
