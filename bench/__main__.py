"""CLI entry point: python -m bench <command> [options]

Commands:
  juliet [--full] [--jobs N] [--keep-csv] [--compile-commands]
                                           Run Juliet benchmark
  status [RUN_ID]                          Show benchmark progress/results
  compare BASE TARGET                      Compare two runs
  runs                                     List all runs
  realworld [RUN] [--compare BASE]         Real-world FP dashboard
  realworld-run [--tool T,T] [--codebase C,C] [--compile-commands]
                                            Run sqc/cppcheck/clang-tidy against
                                            real codebases (local, sequential),
                                            ingest + score against the oracle
  realworld-runs                           List real-world benchmark runs
  realworld-score [RUN]                    Measured precision/recall vs oracle
  realworld-import-labels CSV --run R      Append TP/FP labels to the oracle
  realworld-unlabeled [RUN]                Findings lacking a ground-truth label
  ground-truth                             Ground-truth label inventory
  calibration-sample [--n N] [--seed S]    Blind stratified sample of already-
                                            labeled findings for a 2nd verdict
                                            (--gavel: emit gavel-import JSON
                                            with source excerpts instead)
  calibration-import CSV                   Import a filled-in calibration batch
  calibration-import-gavel EXPORT.JSON     Import a gavel adjudicated export
  calibration-report                       Claude-vs-human agreement report
  concurrency-context [--project P]        CON03/07/33-C precision split by
                                            concurrency-context evidence
  corpus-check                             Verify every real-world checkout is
                                            still on its pinned commit
  render-docs --realworld-run R [--juliet-run R] [--check] [--force]
                                            Regenerate the DB-derived tables in
                                            README/JULIET_RESULTS/
                                            REALWORLD_RESULTS.md
"""

import argparse
import json
import sys

from bench.config import DEFAULT_JOBS
from bench.db import BenchDB


def cmd_juliet(args):
    from bench.runner import run_benchmark
    run_benchmark(fast=not args.full, jobs=args.jobs, keep_csv=args.keep_csv,
                  compile_commands=args.compile_commands)


def cmd_realworld_run(args):
    from bench.realworld_runner import CODEBASES, VALID_TOOLS, run_and_ingest

    tools = [t.strip().lower() for t in args.tool.split(",")] if args.tool else ["sqc"]
    for t in tools:
        if t not in VALID_TOOLS:
            print(f"Unknown tool '{t}'. Must be one of: {', '.join(VALID_TOOLS)}")
            return
    codebases = ([c.strip().lower() for c in args.codebase.split(",")]
                 if args.codebase else sorted(CODEBASES))
    for cb in codebases:
        if cb not in CODEBASES:
            print(f"Unknown codebase '{cb}'. Must be one of: {', '.join(sorted(CODEBASES))}")
            return

    print(f"Running {'+'.join(tools)} against {len(codebases)} codebase(s): "
          f"{', '.join(codebases)}\n")
    run_and_ingest(tools, codebases, compile_commands=args.compile_commands)


def cmd_status(args):
    db = BenchDB()
    run_id = args.run_id

    if not run_id:
        resolved = db.resolve_run("latest")
        if not resolved:
            print("No runs found.")
            return
        run_id = resolved

    resolved = db.resolve_run(run_id)
    if not resolved:
        print(f"Run '{run_id}' not found.")
        runs = db.list_runs()
        if runs:
            print("Available runs:")
            for r in runs:
                print(f"  {r['run_id']}  ({r['status']})")
        return

    run = db.get_run(resolved)
    if run["status"] == "running":
        progress = db.get_progress(resolved)
        print(f"Run: {resolved}  Status: running")
        print(f"Progress: {progress['done_cwes']}/{progress['total_cwes']} "
              f"({progress['progress_pct']}%)")
        if progress["recently_completed"]:
            print("\nRecently completed:")
            for c in progress["recently_completed"]:
                print(f"  {c['cwe_dir_name']} | {c['duration_s']}s | "
                      f"{c['violation_count']} violations")
    else:
        summary = db.get_run_summary(resolved)
        s = summary["summary"]
        print(f"Run: {resolved}  Status: {run['status']}  "
              f"Cache: {s['cache_state']}")
        print(f"CWEs: {s['cwes_analyzed']}  "
              f"TP: {s['total_tp']}  FP: {s['total_fp']}  "
              f"TP Rate: {s['tp_rate_pct']}%")
        if summary.get("cwe_aware"):
            ca = summary["cwe_aware"]
            print(f"\nCWE-Aware: TP {ca['cwe_matched_tp']}  FP {ca['cwe_matched_fp']}  "
                  f"TP Rate {ca['cwe_matched_tp_rate_pct']}%  "
                  f"Noise {ca['noise_ratio_pct']}%")


def cmd_compare(args):
    db = BenchDB()
    base = db.resolve_run(args.base)
    target = db.resolve_run(args.target)

    if not base:
        print(f"Cannot resolve base run '{args.base}'.")
        return
    if not target:
        print(f"Cannot resolve target run '{args.target}'.")
        return

    result = db.compare_runs(base, target)
    if "error" in result:
        print(f"Error: {result['error']}")
        return

    s = result["summary"]
    d = s["delta"]
    print(f"Comparing: {s['base_run']} → {s['target_run']}")
    print(f"\nOverall Delta: TP {d['tp']:+d}  FP {d['fp']:+d}  "
          f"TP Rate {d['tp_rate_pp']:+.2f}pp")
    base_cache = s["base"]["cache_state"]
    target_cache = s["target"]["cache_state"]
    if base_cache != "cold" or target_cache != "cold":
        print(f"Cache: base={base_cache} target={target_cache} "
              "— a cache-warm run can under-report movement")

    t = s.get("timing")
    if t and t["delta"].get("analysis_s") is not None:
        td = t["delta"]
        line = f"\nTiming Delta: analysis {td['analysis_s']:+.0f}s"
        if td.get("analysis_pct") is not None:
            line += f" ({td['analysis_pct']:+.1f}%)"
        if td.get("wall_s") is not None:
            line += f"  wall {td['wall_s']:+.0f}s"
        print(line)
        print(f"  analysis_s {t['base']['analysis_s']:.0f} → {t['target']['analysis_s']:.0f}"
              f"  (summed per-CWE sqc time; jobs={t['target'].get('jobs')})")

    if result.get("timing_movers"):
        print(f"\nTop Timing Movers (per-CWE scan time):")
        for m in result["timing_movers"][:5]:
            print(f"  {m['cwe_id']}: {m['delta_duration_s']:+.1f}s  "
                  f"({m['base_duration_s']:.0f}→{m['target_duration_s']:.0f}s)  "
                  f"FP {m['delta_fp']:+d}")

    if result.get("cwe_improvements"):
        print(f"\nTop CWE Improvements (FP reduced):")
        for c in result["cwe_improvements"][:5]:
            print(f"  {c['cwe_id']}: FP {c['delta_fp']:+d}  TP {c['delta_tp']:+d}")

    if result.get("cwe_regressions"):
        print(f"\nTop CWE Regressions (FP increased):")
        for c in result["cwe_regressions"][:5]:
            print(f"  {c['cwe_id']}: FP {c['delta_fp']:+d}  TP {c['delta_tp']:+d}")


def cmd_runs(args):
    db = BenchDB()
    runs = db.list_runs()
    if not runs:
        print("No benchmark runs found.")
        return
    print(f"{'Run ID':<35} {'Status':<12} {'CWEs':<6} {'Cache':<6} {'Started'}")
    print("-" * 82)
    for r in runs:
        # Count CWEs from DB
        progress = db.get_progress(r["run_id"])
        done = progress["done_cwes"]
        total = progress["total_cwes"]
        started = r.get("started_at", "")[:19]
        cache = r.get("cache_state", "cold")
        print(f"{r['run_id']:<35} {r['status']:<12} {done}/{total:<4} {cache:<6} {started}")


def cmd_realworld(args):
    db = BenchDB()

    # Resolve target run
    target_id = db.resolve_realworld_run(args.run or "latest")
    if not target_id:
        print("No real-world runs found.")
        return

    # Resolve base run for comparison
    base_id = None
    if args.compare:
        base_id = db.resolve_realworld_run(args.compare)
        if not base_id:
            print(f"Cannot resolve base run '{args.compare}'.")
            return
    else:
        # Default: compare against previous run
        runs = db.list_realworld_runs()
        for i, r in enumerate(runs):
            if r["id"] == target_id and i + 1 < len(runs):
                base_id = runs[i + 1]["id"]
                break

    dashboard = db.get_realworld_dashboard(target_id, base_id, top_n=args.top)
    if "error" in dashboard:
        print(f"Error: {dashboard['error']}")
        return

    run = dashboard["run"]
    total = dashboard["total_violations"]

    # Header
    print(f"Real-world FP Dashboard — v{run['sqc_version']}"
          f" ({run.get('commit_sha', '?')[:8]})")
    if base_id and "base_run" in dashboard:
        base = dashboard["base_run"]
        delta = dashboard["total_delta"]
        sign = "+" if delta >= 0 else ""
        print(f"  vs v{base['sqc_version']}"
              f" ({base.get('commit_sha', '?')[:8]})"
              f": {sign}{delta} ({sign}{delta / dashboard['base_total'] * 100:.1f}%)"
              if dashboard["base_total"] > 0
              else f"  vs v{base['sqc_version']}")
    print(f"  Total violations: {total:,}")
    print()

    # Per-project summary
    print(f"{'Project':<12} {'Violations':>10}  {'Duration':>10}")
    print("-" * 36)
    for p in sorted(dashboard["per_project"], key=lambda x: -x["violation_count"]):
        dur = f"{p['duration_s']:.0f}s" if p.get("duration_s") else "—"
        print(f"{p['project']:<12} {p['violation_count']:>10,}  {dur:>10}")
    print()

    # Top rules
    if base_id:
        print(f"{'Rule':<12} {'Count':>8} {'Base':>8} {'Delta':>8}")
        print("-" * 40)
        for r in dashboard["top_rules"]:
            delta = r.get("delta", 0)
            base_count = r.get("base_count", "—")
            sign = "+" if delta > 0 else ""
            delta_str = f"{sign}{delta}" if delta != 0 else "="
            base_str = f"{base_count:>8,}" if isinstance(base_count, int) else f"{'—':>8}"
            print(f"{r['rule_id']:<12} {r['count']:>8,} {base_str} {delta_str:>8}")
    else:
        print(f"{'Rule':<12} {'Count':>8}")
        print("-" * 22)
        for r in dashboard["top_rules"]:
            print(f"{r['rule_id']:<12} {r['count']:>8,}")
    print()

    # Per-project top 5 rules
    if not args.compact:
        for p in sorted(dashboard["per_project"], key=lambda x: -x["violation_count"]):
            print(f"  {p['project']}:")
            for r in p.get("top_rules", [])[:5]:
                print(f"    {r['rule_id']:<12} {r['count']:>6,}")
        print()


def cmd_realworld_runs(args):
    db = BenchDB()
    runs = db.list_realworld_runs()
    if not runs:
        print("No real-world runs found.")
        return
    print(f"{'ID':>4}  {'Version':<10} {'Commit':<10} {'Scanned At':<20} {'Host'}")
    print("-" * 65)
    for r in runs:
        sha = (r.get("commit_sha") or "—")[:8]
        scanned = (r.get("scanned_at") or "—")[:19]
        host = r.get("hostname") or "—"
        print(f"{r['id']:>4}  {r['sqc_version']:<10} {sha:<10} {scanned:<20} {host}")


def cmd_realworld_score(args):
    db = BenchDB()
    target_id = db.resolve_realworld_run(args.run or "latest")
    if not target_id:
        print("No real-world runs found.")
        return

    result = db.score_realworld_run(target_id)
    if "error" in result:
        print(f"Error: {result['error']}")
        return

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    run = result["run"]
    o = result["overall"]
    print(f"Real-world measured precision/recall — v{run['sqc_version']}"
          f" ({(run.get('commit_sha') or '?')[:8]})  run #{target_id}")
    print("(scored against ground-truth labels for each project's pinned commit)")
    print()

    def pct(v):
        return f"{v:.1f}%" if v is not None else "—"

    if o["labeled_total"] == 0:
        print("No findings in this run matched any ground-truth label.")
    else:
        print(f"Overall: precision {pct(o['precision_pct'])} "
              f"(TP {o['labeled_tp']} / labeled {o['labeled_tp'] + o['labeled_fp']}), "
              f"recall {pct(o['recall_pct'])} "
              f"(known TPs flagged {o['tp_detected']}/{o['tp_labels']})")
        if o["labeled_uncertain"]:
            print(f"  ({o['labeled_uncertain']} matched labels are 'uncertain', "
                  "excluded from precision)")
        print(f"  Label coverage: {o['labeled_total']} of "
              f"{o['run_findings']} findings labeled "
              f"({pct(100 - (o['unlabeled_fraction'] or 0) * 100)} labeled, "
              f"{o['unlabeled_count']} unlabeled)")
        print()

        print(f"{'Rule':<12} {'Prec':>7} {'TP':>4} {'FP':>4} {'Unc':>4} "
              f"{'Recall':>7} {'Detect':>8} {'Run#':>8} {'Unlbl':>6}")
        print("-" * 70)
        high_unlabeled = []
        for r in result["per_rule"]:
            detect = f"{r['tp_detected']}/{r['tp_labels']}"
            unlbl_frac = r["unlabeled_fraction"]
            flag = "!" if unlbl_frac is not None and unlbl_frac > 0.5 else " "
            print(f"{r['rule_id']:<12} {pct(r['precision_pct']):>7} "
                  f"{r['labeled_tp']:>4} {r['labeled_fp']:>4} "
                  f"{r['labeled_uncertain']:>4} {pct(r['recall_pct']):>7} "
                  f"{detect:>8} {r['run_findings']:>8,} "
                  f"{pct((unlbl_frac or 0) * 100):>5}{flag}")
            if unlbl_frac is not None and unlbl_frac > 0.5:
                high_unlabeled.append(r)
        print()

        if high_unlabeled:
            print("Rules with >50% of this run's findings unlabeled "
                  "(precision/recall above are computed on a shrinking slice):")
            for r in high_unlabeled:
                print(f"  ! {r['rule_id']}: {r['unlabeled_count']}/"
                      f"{r['run_findings']} unlabeled ({pct(r['unlabeled_fraction'] * 100)})")
            print()

    if result["warnings"]:
        print("Warnings:")
        for w in result["warnings"]:
            print(f"  ! {w}")


def cmd_realworld_import_labels(args):
    import csv
    from datetime import datetime, timezone
    db = BenchDB()

    # Map project -> codebase_commit from the run the audit was sampled against.
    src_run_id = db.resolve_realworld_run(args.run)
    if not src_run_id:
        print(f"Cannot resolve --run '{args.run}' (need the run the audit "
              "was sampled from, to pin labels to its codebase commits).")
        return
    commits = {r["project"]: r.get("codebase_commit")
               for r in db.get_realworld_results(src_run_id)
               if r["tool"] == "sqc"}

    rows = list(csv.DictReader(open(args.csv)))
    labels, skipped_no_commit = [], 0
    adjudicated_at = args.date or datetime.now(timezone.utc).isoformat()
    for row in rows:
        project = row["project"]
        commit = commits.get(project)
        if not commit:
            skipped_no_commit += 1
            continue
        labels.append({
            "project": project,
            "codebase_commit": commit,
            "file_path": row["file"],
            "line": int(row["line"]),
            "rule_id": row["rule"],
            "verdict": row["verdict"],
            "adjudicator": args.adjudicator,
            "reason": row.get("reason"),
            "source": args.source,
            "adjudicated_at": adjudicated_at,
            "provenance": row.get("provenance"),
            "confidence": row.get("confidence"),
        })

    res = db.insert_ground_truth_labels(
        labels, on_conflict="update" if args.update else "ignore")
    print(f"Imported from {args.csv} (commits pinned to run #{src_run_id}):")
    print(f"  inserted {res['inserted']}, updated {res['updated']}, "
          f"skipped {res['skipped']} (already labeled)")
    if skipped_no_commit:
        print(f"  ! {skipped_no_commit} rows skipped: project not in run "
              f"#{src_run_id} or no codebase_commit recorded")


def cmd_realworld_unlabeled(args):
    db = BenchDB()
    target_id = db.resolve_realworld_run(args.run or "latest")
    if not target_id:
        print("No real-world runs found.")
        return
    findings = db.get_unlabeled_findings(
        target_id, rule_id=args.rule, project=args.project,
        limit=args.limit, seed=args.seed, file=args.file,
        enforce_scope=not args.no_scope)
    if args.json:
        print(json.dumps(findings, indent=2, default=str))
        return
    print(f"{len(findings)} unlabeled finding(s) in run #{target_id}"
          + (f" for {args.rule}" if args.rule else "")
          + (f" in {args.project}" if args.project else "")
          + ("" if args.no_scope else " (in-scope only; pass --no-scope for raw)"))
    for f in findings:
        print(f"  {f['rule_id']:<10} {f['project']}/{f['file_path']}:"
              f"{f['line']}  {f['message'] or ''}")


def cmd_ground_truth(args):
    db = BenchDB()
    cov = db.ground_truth_coverage()
    if args.json:
        print(json.dumps(cov, indent=2, default=str))
        return
    if not cov:
        print("No ground-truth labels yet. Seed with "
              "'realworld-import-labels'.")
        return
    print(f"{'Project':<10} {'Commit':<12} {'Rule':<12} "
          f"{'TP':>4} {'FP':>4} {'Unc':>4} {'Total':>6}")
    print("-" * 56)
    tot = 0
    for r in cov:
        print(f"{r['project']:<10} {(r['codebase_commit'] or '?'):<12} "
              f"{r['rule_id']:<12} {r['tp']:>4} {r['fp']:>4} "
              f"{r['uncertain']:>4} {r['total']:>6}")
        tot += r["total"]
    print("-" * 56)
    print(f"{'TOTAL':<10} {'':<12} {'':<12} {'':>4} {'':>4} {'':>4} {tot:>6}")


def _code_excerpt(project, file_path, line):
    """The enclosing function's full text for a gavel `code` field -- a
    fixed line window isn't enough context to judge most findings (a
    reviewer needs to see the whole function, not 15/10 lines around one
    line of it). gavel now scrolls, so there's no size reason to trim it.

    Bounds the region by the nearest top-level '}' (column 0) before and
    after `line` -- the same heuristic verified in task 166's context-
    enrichment experiment (see docs/design or that task's notes: an
    earlier signature-regex extractor silently produced SMALLER regions
    on sqlite's multi-line signatures ending '){' on their own line; this
    column-0-brace bound sidesteps that by not caring how the signature is
    written at all). Not a real parse -- a string/char literal or comment
    containing a column-0 '}' can still fool it -- but it's a closer
    approximation of 'the function' than a fixed window, and wrong in the
    same rare direction (too much context) rather than too little.

    Reads from the pinned checkout under BENCH_ROOT -- not from any run's
    stored text, so it reflects the file as it stands right now. Returns
    (excerpt, start_line); (None, line) if the file can't be read (moved
    checkout, drifted pin -- see corpus-check)."""
    from bench.config import BENCH_ROOT
    path = BENCH_ROOT / project / file_path
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return None, line
    idx = line - 1
    if not (0 <= idx < len(lines)):
        return None, line

    start = 0
    for i in range(idx - 1, -1, -1):
        if lines[i].startswith("}"):
            start = i + 1
            break
    end = len(lines) - 1
    for i in range(idx, len(lines)):
        if lines[i].startswith("}"):
            end = i
            break
    while start < end and not lines[start].strip():
        start += 1

    return "\n".join(lines[start:end + 1]), start + 1


def cmd_calibration_sample(args):
    import csv
    db = BenchDB()
    rows = db.sample_calibration_batch(n=args.n, seed=args.seed)
    if not rows:
        print("No non-manual ground-truth rows to sample from.")
        return

    if args.gavel:
        items, missing_code = [], 0
        for r in rows:
            code, start_line = _code_excerpt(
                r["project"], r["file_path"], r["line"])
            if code is None:
                missing_code += 1
            items.append({
                "external_id": str(r["gt_id"]),
                "title": r["message"] or f"{r['rule_id']} finding",
                "rule_id": r["rule_id"],
                "language": "c",
                "file_path": f"{r['project']}/{r['file_path']}",
                "start_line": start_line,
                "code": code or "(source unreadable -- see project/file_path "
                                "above and read it directly; corpus-check "
                                "may show a drifted/missing checkout)",
            })
        with open(args.out, "w") as f:
            json.dump(items, f, indent=2)
        if missing_code:
            print(f"  ! {missing_code} item(s) had unreadable source "
                  "(run 'python -m bench corpus-check')")
    else:
        with open(args.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=[
                "gt_id", "project", "file_path", "line", "rule_id", "message",
                "verdict", "reason"])
            w.writeheader()
            for r in rows:
                w.writerow({
                    "gt_id": r["gt_id"], "project": r["project"],
                    "file_path": r["file_path"], "line": r["line"],
                    "rule_id": r["rule_id"], "message": r["message"] or "",
                    "verdict": "", "reason": "",
                })

    n_projects = len({r["project"] for r in rows})
    n_rules = len({r["rule_id"] for r in rows})
    print(f"Wrote {len(rows)} row(s) across {n_projects} project(s), "
          f"{n_rules} rule(s) to {args.out}"
          + (" (gavel import format)" if args.gavel else ""))
    if args.gavel:
        print(f"Import with: gavel import {args.out}. This is BLIND -- no "
              "verdict field is populated, and gavel has no slot for one "
              "during review. After adjudication, export with "
              "'gavel export --status adjudicated -o verdicts.json' and "
              "import back with 'calibration-import-gavel verdicts.json'.")
    else:
        print("This is BLIND: the existing ground_truth verdict is not "
              "shown. Read the actual code at each project/file_path:line, "
              "fill in 'verdict' (TP/FP/uncertain) and 'reason', then "
              "re-run with 'calibration-import'.")


def cmd_calibration_import(args):
    import csv
    from datetime import datetime, timezone
    db = BenchDB()
    adjudicated_at = args.date or datetime.now(timezone.utc).isoformat()
    labels, blank = [], 0
    for row in csv.DictReader(open(args.csv)):
        verdict = (row.get("verdict") or "").strip()
        if not verdict:
            blank += 1
            continue
        labels.append({
            "gt_id": int(row["gt_id"]),
            "verdict": verdict,
            "adjudicator": args.adjudicator,
            "reason": row.get("reason") or None,
            "source": args.source,
            "adjudicated_at": adjudicated_at,
        })
    res = db.insert_calibration_labels(labels)
    print(f"Imported from {args.csv}: inserted {res['inserted']}, "
          f"skipped {res['skipped']} (already labeled by this adjudicator), "
          f"missing_gt {res['missing_gt']}")
    if blank:
        print(f"  ({blank} row(s) had no verdict filled in, left for later)")


# gavel's verdict.decision (compliant/violation/false_positive/
# needs_more_context/uncertain) -> ground_truth's TP/FP/uncertain. compliant
# and needs_more_context have no equivalent here and are skipped, not
# guessed at -- see gavel's docs/data-model.md#decision-vocabulary.
_GAVEL_DECISION_MAP = {"violation": "TP", "false_positive": "FP",
                       "uncertain": "uncertain"}


def cmd_calibration_import_gavel(args):
    db = BenchDB()
    items = json.load(open(args.export_json))
    labels, skipped_unmapped, skipped_no_verdict = [], 0, 0
    for item in items:
        verdict = item.get("verdict")
        if not verdict:
            skipped_no_verdict += 1
            continue
        decision = _GAVEL_DECISION_MAP.get(verdict.get("decision"))
        if decision is None:
            skipped_unmapped += 1
            continue
        ext_id = item.get("external_id")
        if not ext_id:
            continue
        labels.append({
            "gt_id": int(ext_id),
            "verdict": decision,
            "adjudicator": verdict.get("reviewer") or args.adjudicator,
            "reason": verdict.get("rationale"),
            "source": "gavel",
            "adjudicated_at": verdict.get("reviewed_at"),
        })
    res = db.insert_calibration_labels(labels)
    print(f"Imported from {args.export_json}: inserted {res['inserted']}, "
          f"skipped {res['skipped']} (already labeled by this adjudicator), "
          f"missing_gt {res['missing_gt']}")
    if skipped_no_verdict:
        print(f"  ({skipped_no_verdict} item(s) not yet adjudicated in gavel)")
    if skipped_unmapped:
        print(f"  ({skipped_unmapped} item(s) used a decision "
              "(compliant/needs_more_context) with no ground_truth "
              "equivalent -- left out, not guessed at)")


def cmd_calibration_report(args):
    db = BenchDB()
    rep = db.calibration_agreement_report()
    if args.json:
        print(json.dumps(rep, indent=2, default=str))
        return
    if not rep["n"]:
        print("No calibration labels yet. Run 'calibration-sample', have a "
              "human re-adjudicate it blind, then 'calibration-import'.")
        return
    print(f"Overall agreement: {rep['agree']}/{rep['n']} "
          f"({rep['overall_agreement_pct']:.1f}%)\n")
    print(f"{'Rule':<12} {'N':>5} {'Agree':>6} {'Pct':>7}")
    print("-" * 32)
    for r in rep["by_rule"]:
        pct = f"{r['agreement_pct']:.1f}%" if r["agreement_pct"] is not None else "-"
        print(f"{r['rule_id']:<12} {r['n']:>5} {r['agree']:>6} {pct:>7}")
    print("\nConfusion (original_verdict -> calibration_verdict):")
    for k, v in sorted(rep["confusion"].items(), key=lambda kv: -kv[1]):
        print(f"  {k:<20} {v}")


def cmd_concurrency_context(args):
    from bench.concurrency_context import (
        CONCURRENCY_RULES,
        concurrency_context_precision_split,
    )
    from bench.config import BENCH_ROOT

    db = BenchDB()
    rules = tuple(args.rules.split(",")) if args.rules else CONCURRENCY_RULES
    result = concurrency_context_precision_split(
        db, BENCH_ROOT, project=args.project, rules=rules
    )

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return

    if result["labeled_total"] == 0:
        print(f"No ground-truth labels for {', '.join(rules)}"
              + (f" in {args.project}" if args.project else "") + ".")
        return

    def pct(v):
        return f"{v:.1f}%" if v is not None else "—"

    print(f"Concurrency-context precision split — {', '.join(rules)}"
          + (f" ({args.project})" if args.project else " (all projects)"))
    print(f"({result['labeled_total']} labeled findings"
          + (f", {len(result['missing_files'])} source file(s) not found "
             "locally -- run playbooks/setup-benchmark-repos.yml"
             if result["missing_files"] else "") + ")")
    print()
    print(f"{'Bucket':<18} {'Prec':>7} {'TP':>4} {'FP':>4} {'Unc':>4}")
    print("-" * 42)
    for name, label in (("context_present", "Context present"),
                        ("context_absent", "Context absent")):
        b = result["buckets"][name]
        print(f"{label:<18} {pct(b['precision_pct']):>7} {b['tp']:>4} "
              f"{b['fp']:>4} {b['uncertain']:>4}")


def cmd_audit_complete(args):
    db = BenchDB()
    run_id = db.resolve_realworld_run(args.run or "latest")
    if not run_id:
        print("No real-world runs found.")
        return
    res = db.mark_file_audited(run_id, args.project, args.file,
                               adjudicator=args.adjudicator, notes=args.notes,
                               force=args.force)
    if args.json:
        print(json.dumps(res, indent=2, default=str))
        return
    if "error" in res:
        print(f"Not marked: {res['error']}")
        if res.get("unlabeled"):
            print(f"  {len(res['unlabeled'])} unlabeled finding(s) in "
                  f"{args.project}/{args.file}:")
            for u in res["unlabeled"]:
                print(f"    {u['rule_id']:<10} :{u['line']}")
        return
    print(f"Audited {res['project']}/{res['file_path']} @ {res['commit'][:12]}: "
          f"{res['n_findings']} findings "
          f"(TP {res['n_tp']} / FP {res['n_fp']} / Unc {res['n_uncertain']}), "
          f"FN {res['n_fn']}"
          + (f"  [forced past {res['forced_unlabeled']} unlabeled]"
             if res.get("forced_unlabeled") else ""))


def cmd_audit_score(args):
    db = BenchDB()
    run_id = db.resolve_realworld_run(args.run or "latest")
    if not run_id:
        print("No real-world runs found.")
        return
    result = db.score_audited_corpus(run_id)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return
    if "error" in result:
        print(f"Error: {result['error']}")
        return
    run = result["run"]
    o = result["overall"]

    def pct(v):
        return f"{v:.1f}%" if v is not None else "—"

    print(f"Audited-file corpus — precision/recall  (sqc v{run['sqc_version']}, "
          f"run #{run_id})")
    print("(restricted to files swept end-to-end: every finding labeled + read "
          "for missed bugs)")
    print()
    if o["labeled_total"] == 0:
        print("No audited files yet. Mark files with 'audit-complete'.")
    else:
        print(f"Overall: precision {pct(o['precision_pct'])} "
              f"(TP {o['labeled_tp']} / labeled {o['labeled_tp'] + o['labeled_fp']}), "
              f"recall {pct(o['recall_pct'])} "
              f"(real bugs flagged {o['tp_detected']}/{o['tp_labels']}; "
              f"recall denom incl. standing FNs)")
        print()
        print(f"{'Rule':<12} {'Prec':>7} {'TP':>4} {'FP':>4} {'Unc':>4} "
              f"{'Recall':>7} {'Detect':>8}")
        print("-" * 54)
        for r in result["per_rule"]:
            detect = f"{r['tp_detected']}/{r['tp_labels']}"
            print(f"{r['rule_id']:<12} {pct(r['precision_pct']):>7} "
                  f"{r['labeled_tp']:>4} {r['labeled_fp']:>4} "
                  f"{r['labeled_uncertain']:>4} {pct(r['recall_pct']):>7} "
                  f"{detect:>8}")
    print()
    _print_coverage(result["coverage"])


def _print_coverage(cov):
    print(f"{'Project':<10} {'Audited':>8} {'Total':>7} {'Cov%':>6} "
          f"{'Flagged':>8} {'TP':>4} {'FP':>4} {'FN':>4}")
    print("-" * 56)
    for r in cov["per_project"]:
        total = r["total_inscope_files"]
        covpct = f"{r['coverage_pct']:.1f}" if r["coverage_pct"] is not None else "—"
        print(f"{r['project']:<10} {r['audited_files']:>8} "
              f"{(total if total is not None else '—'):>7} {covpct:>6} "
              f"{r['files_with_findings']:>8} {r['tp']:>4} {r['fp']:>4} "
              f"{r['fn']:>4}")


def cmd_audit_coverage(args):
    db = BenchDB()
    run_id = db.resolve_realworld_run(args.run or "latest")
    if not run_id:
        print("No real-world runs found.")
        return
    if args.set_total is not None:
        if not args.project:
            print("--set-total requires --project.")
            return
        commit = next((r.get("codebase_commit")
                       for r in db.get_realworld_results(run_id)
                       if r["tool"] == "sqc" and r["project"] == args.project),
                      None)
        if not commit:
            print(f"No sqc commit for {args.project} in run #{run_id}.")
            return
        db.set_corpus_scope(args.project, commit, args.set_total, args.note)
        print(f"Recorded {args.project}@{commit[:12]} in-scope total = "
              f"{args.set_total}"
              + (f" ({args.note})" if args.note else ""))
        return
    cov = db.audit_coverage(run_id)
    if args.json:
        print(json.dumps(cov, indent=2, default=str))
        return
    _print_coverage(cov)


def cmd_oracle_freeze(args):
    db = BenchDB()
    run_id = db.resolve_realworld_run(args.run or "latest")
    if not run_id:
        print("No real-world runs found.")
        return
    res = db.freeze_oracle_version(args.version, run_id, notes=args.notes)
    print(f"Froze oracle '{res['version']}' at {res['frozen_at']} "
          f"(run #{run_id}).")


def cmd_oracle_versions(args):
    db = BenchDB()
    vers = db.list_oracle_versions()
    if args.json:
        print(json.dumps(vers, indent=2, default=str))
        return
    if not vers:
        print("No frozen oracle versions yet. Freeze with 'oracle-freeze'.")
        return
    print(f"{'Version':<16} {'Frozen':<28} Notes")
    print("-" * 70)
    for v in vers:
        print(f"{v['version']:<16} {(v['frozen_at'] or ''):<28} "
              f"{v['notes'] or ''}")


def cmd_corpus_check(args):
    from bench.corpus import report
    # Exits nonzero on drift so this can gate a benchmark run or CI step;
    # `args.func`'s return value is discarded, hence the explicit exit.
    sys.exit(report(bench_root=args.bench_root, as_json=args.json))


def cmd_render_docs(args):
    from bench.render_docs import (PROJECT_COVERAGE_WARN,
                                    UNLABELED_FRACTION_WARN, render_all,
                                    realworld_project_count,
                                    published_realworld_project_count,
                                    resolve_latest_fast_juliet_run)
    db = BenchDB()

    realworld_run_id = db.resolve_realworld_run(args.realworld_run)
    if not realworld_run_id:
        print(f"Real-world run '{args.realworld_run}' not found.")
        sys.exit(1)

    if args.juliet_run in (None, "latest"):
        juliet_run_id = resolve_latest_fast_juliet_run(db)
        if not juliet_run_id:
            print("No completed fast-mode Juliet run found; pass --juliet-run "
                  "explicitly.")
            sys.exit(1)
    else:
        juliet_run_id = db.resolve_run(args.juliet_run)
        if not juliet_run_id:
            print(f"Juliet run '{args.juliet_run}' not found.")
            sys.exit(1)

    score = db.score_realworld_run(realworld_run_id)
    unlabeled = score["overall"].get("unlabeled_fraction") or 0.0
    if unlabeled > UNLABELED_FRACTION_WARN and not args.force:
        print(f"Real-world run #{realworld_run_id} is {unlabeled:.1%} "
              "unlabeled -- its precision/recall likely isn't safely "
              "measured yet (see CLAUDE.md's delta-adjudication protocol). "
              "Delta-adjudicate first, or pass --force to cite it anyway.")
        sys.exit(1)

    this_count = realworld_project_count(db, realworld_run_id)
    published_count = published_realworld_project_count()
    if (published_count and this_count
            and this_count < published_count * PROJECT_COVERAGE_WARN
            and not args.force):
        print(f"Real-world run #{realworld_run_id} only covers "
              f"{this_count} project(s), vs {published_count} in the "
              "currently-published table -- likely a narrow/targeted scan, "
              "not a full-suite run. Pass --force to cite it anyway.")
        sys.exit(1)

    try:
        rendered = render_all(db, juliet_run_id, realworld_run_id)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    changed = {path: text for path, text in rendered.items()
               if path.read_text() != text}

    if args.check:
        if not changed:
            print("Up to date.")
            return
        print("Out of date:")
        for path in changed:
            print(f"  {path}")
        sys.exit(1)

    if not changed:
        print("Already up to date.")
        return
    for path, text in changed.items():
        path.write_text(text)
        print(f"Updated {path}")


def main():
    parser = argparse.ArgumentParser(
        prog="bench",
        description="sqc Juliet benchmark infrastructure",
    )
    sub = parser.add_subparsers(dest="command")

    # juliet
    p_juliet = sub.add_parser("juliet", help="Run Juliet benchmark")
    p_juliet.add_argument("--full", action="store_true",
                          help="Use all rules (default: fast/CWE-matched only)")
    p_juliet.add_argument("--jobs", "-j", type=int, default=DEFAULT_JOBS,
                          help=f"Parallel workers (default: {DEFAULT_JOBS})")
    p_juliet.add_argument("--keep-csv", action="store_true",
                          help="Keep intermediate CSV files")
    p_juliet.add_argument("--compile-commands", action="store_true",
                          help="Pass --compile-commands to sqc using the synthesized "
                               "Juliet compile database. Suffixes the run_id with "
                               "'-cdb' so it does not collide with the plain run of "
                               "the same build")
    p_juliet.set_defaults(func=cmd_juliet)

    # status
    p_status = sub.add_parser("status", help="Show run status")
    p_status.add_argument("run_id", nargs="?", default=None,
                          help="Run ID (default: latest)")
    p_status.set_defaults(func=cmd_status)

    # compare
    p_compare = sub.add_parser("compare", help="Compare two runs")
    p_compare.add_argument("base", help="Base run (older)")
    p_compare.add_argument("target", help="Target run (newer)")
    p_compare.set_defaults(func=cmd_compare)

    # runs
    p_runs = sub.add_parser("runs", help="List all runs")
    p_runs.set_defaults(func=cmd_runs)

    # realworld
    p_rw = sub.add_parser("realworld", help="Real-world FP dashboard")
    p_rw.add_argument("run", nargs="?", default=None,
                      help="Run identifier (version, ID, or 'latest')")
    p_rw.add_argument("--compare", "-c", default=None,
                      help="Base run to compare against (default: previous)")
    p_rw.add_argument("--top", "-n", type=int, default=25,
                      help="Number of top rules to show (default: 25)")
    p_rw.add_argument("--compact", action="store_true",
                      help="Skip per-project rule breakdown")
    p_rw.set_defaults(func=cmd_realworld)

    # realworld-run
    p_rw_run = sub.add_parser(
        "realworld-run",
        help="Run sqc/cppcheck/clang-tidy against real codebases, ingest + score")
    p_rw_run.add_argument("--tool", default=None,
                          help="Comma-separated: sqc,cppcheck,clang-tidy (default: sqc)")
    p_rw_run.add_argument("--codebase", default=None,
                          help="Comma-separated codebase key(s) (default: all)")
    p_rw_run.add_argument("--compile-commands", action="store_true",
                          help="sqc only: pass --compile-commands using the codebase's "
                               "compile_commands.json")
    p_rw_run.set_defaults(func=cmd_realworld_run)

    # realworld-runs
    p_rw_runs = sub.add_parser("realworld-runs", help="List real-world runs")
    p_rw_runs.set_defaults(func=cmd_realworld_runs)

    # realworld-score
    p_score = sub.add_parser(
        "realworld-score",
        help="Measured precision/recall vs the ground-truth oracle")
    p_score.add_argument("run", nargs="?", default=None,
                         help="Run identifier (version, ID, or 'latest')")
    p_score.add_argument("--json", action="store_true", help="Emit JSON")
    p_score.set_defaults(func=cmd_realworld_score)

    # realworld-import-labels
    p_imp = sub.add_parser(
        "realworld-import-labels",
        help="Append adjudicated TP/FP labels to the ground-truth oracle")
    p_imp.add_argument("csv", help="CSV: rule,idx,project,file,line,verdict,reason")
    p_imp.add_argument("--run", required=True,
                       help="Run the audit was sampled from (pins labels to "
                            "its per-project codebase commits)")
    p_imp.add_argument("--source", default=None,
                       help="Provenance tag, e.g. 'precision_audit_0.4.22'")
    p_imp.add_argument("--adjudicator", default="manual",
                       help="Who/what adjudicated (default: manual)")
    p_imp.add_argument("--date", default=None,
                       help="Adjudication date (ISO; default: now)")
    p_imp.add_argument("--update", action="store_true",
                       help="Overwrite existing labels (re-adjudication) "
                            "instead of skipping them")
    p_imp.set_defaults(func=cmd_realworld_import_labels)

    # realworld-unlabeled
    p_unl = sub.add_parser(
        "realworld-unlabeled",
        help="List a run's findings that have no ground-truth label yet")
    p_unl.add_argument("run", nargs="?", default=None,
                       help="Run identifier (default: latest)")
    p_unl.add_argument("--rule", default=None, help="Filter to one rule")
    p_unl.add_argument("--project", default=None, help="Filter to one project")
    p_unl.add_argument("--limit", type=int, default=None, help="Max findings")
    p_unl.add_argument("--seed", type=int, default=None,
                       help="Sample reproducibly with this seed")
    p_unl.add_argument("--file", default=None,
                       help="Filter to one project-relative file (file-at-a-"
                            "time workflow: pull all findings in this file)")
    p_unl.add_argument("--no-scope", action="store_true",
                       help="Don't apply each project's scope_include/"
                            "scope_exclude predicate (task 636) -- show the "
                            "raw unfiltered set, including out-of-scope files")
    p_unl.add_argument("--json", action="store_true", help="Emit JSON")
    p_unl.set_defaults(func=cmd_realworld_unlabeled)

    # ground-truth
    p_gt = sub.add_parser("ground-truth",
                          help="Inventory of ground-truth labels")
    p_gt.add_argument("--json", action="store_true", help="Emit JSON")
    p_gt.set_defaults(func=cmd_ground_truth)

    # calibration-sample (task 637)
    p_cs = sub.add_parser(
        "calibration-sample",
        help="Blind stratified sample of already-labeled ground-truth rows "
             "for a second, independent adjudicator")
    p_cs.add_argument("--n", type=int, default=180,
                      help="Total rows to sample (default: 180)")
    p_cs.add_argument("--seed", type=int, default=None,
                      help="Sample reproducibly with this seed")
    p_cs.add_argument("--out", default="calibration_batch.csv",
                      help="Output path (default: calibration_batch.csv; "
                           "use a .json extension with --gavel)")
    p_cs.add_argument("--gavel", action="store_true",
                      help="Emit gavel-import JSON (external_id=gt_id, "
                           "embedded source excerpt) instead of the plain "
                           "CSV, for review with 'gavel import'/'gavel "
                           "review' instead of hand-editing a CSV")
    p_cs.set_defaults(func=cmd_calibration_sample)

    # calibration-import (task 637)
    p_ci = sub.add_parser(
        "calibration-import",
        help="Import a filled-in calibration batch (verdict/reason columns)")
    p_ci.add_argument("csv", help="Filled-in CSV from calibration-sample")
    p_ci.add_argument("--adjudicator", default="manual",
                      help="Who produced these verdicts (default: manual)")
    p_ci.add_argument("--source", default="calibration",
                      help="Provenance tag (default: calibration)")
    p_ci.add_argument("--date", default=None,
                      help="Adjudication date (ISO; default: now)")
    p_ci.set_defaults(func=cmd_calibration_import)

    # calibration-import-gavel (task 637)
    p_cig = sub.add_parser(
        "calibration-import-gavel",
        help="Import a gavel 'export --status adjudicated' JSON file")
    p_cig.add_argument("export_json", help="Output of 'gavel export'")
    p_cig.add_argument("--adjudicator", default="manual",
                       help="Fallback adjudicator name if an item's "
                            "verdict.reviewer is empty (default: manual)")
    p_cig.set_defaults(func=cmd_calibration_import_gavel)

    # calibration-report (task 637)
    p_cr = sub.add_parser(
        "calibration-report",
        help="Claude-vs-human agreement report from calibration_labels")
    p_cr.add_argument("--json", action="store_true", help="Emit JSON")
    p_cr.set_defaults(func=cmd_calibration_report)

    # concurrency-context (task 607)
    p_cc = sub.add_parser(
        "concurrency-context",
        help="CON03/07/33-C ground-truth precision split by whether the "
             "flagged TU shows evidence of a concurrent execution path")
    p_cc.add_argument("--project", default=None, help="Filter to one project")
    p_cc.add_argument("--rules", default=None,
                      help="Comma-separated rule IDs (default: "
                           "CON03-C,CON07-C,CON33-C,CON34-C,CON37-C)")
    p_cc.add_argument("--json", action="store_true", help="Emit JSON")
    p_cc.set_defaults(func=cmd_concurrency_context)

    # audit-complete (mark a file as exhaustively audited = the 'done' unit)
    p_ac = sub.add_parser(
        "audit-complete",
        help="Mark a file exhaustively audited (every finding labeled + read "
             "for missed bugs)")
    p_ac.add_argument("--run", default=None,
                      help="Run providing the findings/commit (default: latest)")
    p_ac.add_argument("--project", required=True)
    p_ac.add_argument("--file", required=True,
                      help="Project-relative file path")
    p_ac.add_argument("--adjudicator", default="claude")
    p_ac.add_argument("--notes", default=None)
    p_ac.add_argument("--force", action="store_true",
                      help="Mark done even if some findings are unlabeled")
    p_ac.add_argument("--json", action="store_true", help="Emit JSON")
    p_ac.set_defaults(func=cmd_audit_complete)

    # audit-score (precision + recall over the audited-file corpus)
    p_as = sub.add_parser(
        "audit-score",
        help="Precision/recall restricted to the audited-file corpus")
    p_as.add_argument("run", nargs="?", default=None,
                      help="Run identifier (default: latest)")
    p_as.add_argument("--json", action="store_true", help="Emit JSON")
    p_as.set_defaults(func=cmd_audit_score)

    # audit-coverage (progress toward 'done'; also records scope denominator)
    p_av = sub.add_parser(
        "audit-coverage",
        help="File-coverage of the audit; --set-total records the in-scope "
             "denominator")
    p_av.add_argument("run", nargs="?", default=None,
                      help="Run identifier (default: latest)")
    p_av.add_argument("--project", default=None)
    p_av.add_argument("--set-total", type=int, default=None,
                      help="Record total in-scope files for --project (the "
                           "coverage denominator)")
    p_av.add_argument("--note", default=None, help="Scope note for --set-total")
    p_av.add_argument("--json", action="store_true", help="Emit JSON")
    p_av.set_defaults(func=cmd_audit_coverage)

    # oracle-freeze / oracle-versions (citable, versioned snapshots)
    p_of = sub.add_parser(
        "oracle-freeze",
        help="Freeze the audited corpus under a version tag for citation")
    p_of.add_argument("version", help="Version tag, e.g. 'v1.0'")
    p_of.add_argument("--run", default=None, help="Run to score (default: latest)")
    p_of.add_argument("--notes", default=None)
    p_of.set_defaults(func=cmd_oracle_freeze)

    p_ov = sub.add_parser("oracle-versions",
                          help="List frozen oracle versions")
    p_ov.add_argument("--json", action="store_true", help="Emit JSON")
    p_ov.set_defaults(func=cmd_oracle_versions)

    p_cchk = sub.add_parser(
        "corpus-check",
        help="Verify every real-world checkout is still on its pinned commit")
    p_cchk.add_argument("--bench-root", default=None,
                        help="Override BENCH_ROOT for this check")
    p_cchk.add_argument("--json", action="store_true", help="Emit JSON")
    p_cchk.set_defaults(func=cmd_corpus_check)

    p_rd = sub.add_parser(
        "render-docs",
        help="Regenerate the DB-derived tables in README/JULIET_RESULTS/"
             "REALWORLD_RESULTS.md")
    p_rd.add_argument("--realworld-run", required=True,
                      help="Real-world run to cite (no default -- must be an "
                           "explicitly-chosen, validly-adjudicated run)")
    p_rd.add_argument("--juliet-run", default="latest",
                      help="Juliet run to cite (default: latest completed "
                           "fast-mode run)")
    p_rd.add_argument("--check", action="store_true",
                      help="Report whether the docs are stale; exit nonzero "
                           "if so, without writing")
    p_rd.add_argument("--force", action="store_true",
                      help="Cite the real-world run even if its unlabeled "
                           "fraction is high")
    p_rd.set_defaults(func=cmd_render_docs)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
