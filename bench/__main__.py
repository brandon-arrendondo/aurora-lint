"""CLI entry point: python -m bench <command> [options]

Commands:
  juliet [--full] [--jobs N] [--keep-csv]  Run Juliet benchmark
  status [RUN_ID]                          Show benchmark progress/results
  compare BASE TARGET                      Compare two runs
  runs                                     List all runs
  realworld [RUN] [--compare BASE]         Real-world FP dashboard
  realworld-runs                           List real-world benchmark runs
  realworld-score [RUN]                    Measured precision/recall vs oracle
  realworld-import-labels CSV --run R      Append TP/FP labels to the oracle
  realworld-unlabeled [RUN]                Findings lacking a ground-truth label
  ground-truth                             Ground-truth label inventory
"""

import argparse
import json
import sys

from bench.config import DEFAULT_JOBS
from bench.db import BenchDB


def cmd_juliet(args):
    from bench.runner import run_benchmark
    run_benchmark(fast=not args.full, jobs=args.jobs, keep_csv=args.keep_csv)


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
        print(f"Run: {resolved}  Status: {run['status']}")
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
    print(f"{'Run ID':<35} {'Status':<12} {'CWEs':<6} {'Started'}")
    print("-" * 75)
    for r in runs:
        # Count CWEs from DB
        progress = db.get_progress(r["run_id"])
        done = progress["done_cwes"]
        total = progress["total_cwes"]
        started = r.get("started_at", "")[:19]
        print(f"{r['run_id']:<35} {r['status']:<12} {done}/{total:<4} {started}")


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
              f"{o['run_findings']} findings labeled")
        print()

        print(f"{'Rule':<12} {'Prec':>7} {'TP':>4} {'FP':>4} {'Unc':>4} "
              f"{'Recall':>7} {'Detect':>8} {'Run#':>8}")
        print("-" * 62)
        for r in result["per_rule"]:
            detect = f"{r['tp_detected']}/{r['tp_labels']}"
            print(f"{r['rule_id']:<12} {pct(r['precision_pct']):>7} "
                  f"{r['labeled_tp']:>4} {r['labeled_fp']:>4} "
                  f"{r['labeled_uncertain']:>4} {pct(r['recall_pct']):>7} "
                  f"{detect:>8} {r['run_findings']:>8,}")
        print()

    if result["warnings"]:
        print("Warnings:")
        for w in result["warnings"]:
            print(f"  ! {w}")


def cmd_realworld_import_labels(args):
    import csv
    from datetime import datetime
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
    adjudicated_at = args.date or datetime.now().isoformat()
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
        limit=args.limit, seed=args.seed, file=args.file)
    if args.json:
        print(json.dumps(findings, indent=2, default=str))
        return
    print(f"{len(findings)} unlabeled finding(s) in run #{target_id}"
          + (f" for {args.rule}" if args.rule else "")
          + (f" in {args.project}" if args.project else ""))
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
    p_unl.add_argument("--json", action="store_true", help="Emit JSON")
    p_unl.set_defaults(func=cmd_realworld_unlabeled)

    # ground-truth
    p_gt = sub.add_parser("ground-truth",
                          help="Inventory of ground-truth labels")
    p_gt.add_argument("--json", action="store_true", help="Emit JSON")
    p_gt.set_defaults(func=cmd_ground_truth)

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

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
