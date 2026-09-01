"""Regenerate the DB-derived presentation blocks in README.md,
JULIET_RESULTS.md and REALWORLD_RESULTS.md.

Each file has one or more `<!-- BENCH:NAME:START -->` / `<!-- BENCH:NAME:END
-->` marker pairs bracketing a block that is a pure projection of a benchmark
DB (plus `rules_templates/rules-all.toml`'s rule counts) -- nothing outside a
marker pair is ever touched, so hand-written narrative/history sections stay
hand-written.

Every function here takes `db` as a plain argument and never imports a
concrete DB class -- callers decide what `db` is (see `bench/__main__.py`'s
`render-docs` command, which always uses `bench.db.BenchDB` against the local
SQLite file, same as every other `bench` subcommand).
"""

from __future__ import annotations

import re
import tomllib

from bench.config import PROJECT_DIR

RULES_ALL_TOML = PROJECT_DIR / "rules_templates" / "rules-all.toml"

README = PROJECT_DIR / "README.md"
JULIET_RESULTS = PROJECT_DIR / "JULIET_RESULTS.md"
REALWORLD_RESULTS = PROJECT_DIR / "REALWORLD_RESULTS.md"

# Above this fraction of a real-world run's findings being unlabeled, its
# precision/recall is more "unmeasured" than "measured" -- see CLAUDE.md's
# delta-adjudication protocol (item 6).
UNLABELED_FRACTION_WARN = 0.20

# Below this fraction of the currently-published project count, a run is
# probably a narrow/targeted scan (e.g. one project re-run for a delta-
# adjudication check), not a full-suite run fit to cite as "the" aggregate
# figure -- even if it happens to be 100% labeled (see run #208: a
# libcrc-only scan with 0% unlabeled findings, which the unlabeled-fraction
# guard alone can't catch).
PROJECT_COVERAGE_WARN = 0.5

TOOL_ORDER = ["sqc", "cppcheck", "clang-tidy"]

# realworld_results.project is the checkout dir basename (hyphen-free, e.g.
# "pureftpd" not "pure-ftpd" -- see memory note on the hyphen pitfall); these
# are the doc-facing display spellings for the handful that differ.
PROJECT_DISPLAY_NAMES = {
    "pureftpd": "pure-ftpd",
    "sel4": "seL4",
}


def display_project(project: str) -> str:
    return PROJECT_DISPLAY_NAMES.get(project, project)


def realworld_project_count(db, realworld_run_id: int) -> int:
    results = db.get_realworld_results(realworld_run_id)
    return len({r["project"] for r in results if r["tool"] == "sqc"})


def rule_counts() -> dict:
    with RULES_ALL_TOML.open("rb") as f:
        data = tomllib.load(f)
    rules = data["rules"]["cert_c"]
    enabled = sum(1 for v in rules.values() if v.get("enabled"))
    return {"implemented": len(rules), "enabled": enabled}


def resolve_latest_fast_juliet_run(db) -> str | None:
    """Most recent completed fast-mode Juliet run.

    Every published "current state" table has always cited a fast-mode run
    -- it's the routine benchmark (CLAUDE.md); full-mode runs are periodic
    spot checks and aren't comparable to the fast-mode trend history.
    """
    candidates = [r for r in db.list_runs()
                  if r["status"] == "completed" and r["mode"] == "fast"]
    if not candidates:
        return None
    candidates.sort(key=lambda r: r["started_at"], reverse=True)
    return candidates[0]["run_id"]


def replace_between(text: str, begin_marker: str, end_marker: str,
                    new_block: str) -> str:
    pattern = re.compile(
        re.escape(begin_marker) + r".*?" + re.escape(end_marker), re.DOTALL)
    if not pattern.search(text):
        raise ValueError(f"markers {begin_marker!r} / {end_marker!r} not "
                          f"found (or out of order)")
    replacement = f"{begin_marker}\n{new_block}\n{end_marker}"
    return pattern.sub(lambda _m: replacement, text, count=1)


def published_realworld_project_count() -> int | None:
    """Project count in README's *currently published* highlights block, or
    None if the marker/row isn't found. Used as the baseline for
    PROJECT_COVERAGE_WARN -- a run covering far fewer projects than what's
    already published is almost certainly a narrow/targeted scan, not a
    full-suite citation."""
    if not README.is_file():
        return None
    m = re.search(r"\*\*Real-World Projects\*\*\s*\|\s*([^|]+)\|", README.read_text())
    if not m:
        return None
    return len([p for p in m.group(1).split(",") if p.strip()])


def realworld_citation_warnings(db, realworld_run_id: int) -> list[str]:
    """Reasons NOT to cite this run without an explicit override, or [] if
    it's safely citable as-is.

    Shared by every caller of `render_all` (tools_sqc's own `render-docs`
    CLI, and any other script pointing these functions at a differently-
    backed `db`, e.g. a Postgres-backed refresh run from the benchmark
    node) so the guard logic lives in exactly one place rather than being
    re-implemented per caller.
    """
    warnings = []

    score = db.score_realworld_run(realworld_run_id)
    unlabeled = score["overall"].get("unlabeled_fraction") or 0.0
    if unlabeled > UNLABELED_FRACTION_WARN:
        warnings.append(
            f"{unlabeled:.1%} unlabeled -- its precision/recall likely "
            "isn't safely measured yet (see CLAUDE.md's delta-adjudication "
            "protocol). Delta-adjudicate first, or force past this.")

    this_count = realworld_project_count(db, realworld_run_id)
    published_count = published_realworld_project_count()
    if published_count and this_count and this_count < published_count * PROJECT_COVERAGE_WARN:
        warnings.append(
            f"only covers {this_count} project(s), vs {published_count} in "
            "the currently-published table -- likely a narrow/targeted "
            "scan, not a full-suite run.")

    return warnings


def _zero_fp_cwe_lists(per_cwe: list[dict]) -> tuple[list[str], list[str]]:
    """(with-detections, zero-detection) CWE id lists, ordered by numeric id.

    Uses the CWE-matched counters (not raw tp/fp) so a full-mode run's noise
    from off-CWE rules doesn't corrupt the split.
    """
    def cwe_num(cwe_id: str) -> int:
        return int(cwe_id.split("-")[-1])

    with_detections, zero_detection = [], []
    for row in per_cwe:
        tp, fp = row.get("cwe_matched_tp") or 0, row.get("cwe_matched_fp") or 0
        if fp == 0 and tp > 0:
            with_detections.append(row["cwe_id"])
        elif fp == 0 and tp == 0:
            zero_detection.append(row["cwe_id"])
    with_detections.sort(key=cwe_num)
    zero_detection.sort(key=cwe_num)
    return with_detections, zero_detection


def _cwe_list_str(ids: list[str]) -> str:
    """'CWE-78, 114, 188, ...' -- prefix once, bare numbers after (matches
    the existing hand-written style in JULIET_RESULTS.md)."""
    if not ids:
        return "none"
    nums = [i.split("-")[-1] for i in ids]
    return f"CWE-{nums[0]}" + (", " + ", ".join(nums[1:]) if len(nums) > 1 else "")


def render_readme_highlights(db, juliet_run_id: str, realworld_run_id: int) -> str:
    juliet = db.get_run_summary(juliet_run_id)
    ca = juliet["cwe_aware"]
    juliet_run = db.get_run(juliet_run_id)
    juliet_version = juliet_run["sqc_version"]
    mode_word = "fast" if juliet_run["mode"] == "fast" else "full"
    with_detections, zero_detection = _zero_fp_cwe_lists(juliet["per_cwe"])

    rw_score = db.score_realworld_run(realworld_run_id)
    overall = rw_score["overall"]
    rw_run = db.get_realworld_run(realworld_run_id)
    rw_results = db.get_realworld_results(realworld_run_id)
    projects = sorted({display_project(r["project"]) for r in rw_results
                       if r["tool"] == "sqc"}, key=str.lower)
    coverage_pct = round(overall["labeled_total"] / overall["run_findings"] * 100, 1) \
        if overall["run_findings"] else 0.0

    lines = [
        "| Metric | Value |",
        "|--------|-------|",
        f"| **Juliet TP Rate** | {ca['cwe_matched_tp_rate_pct']}% (v{juliet_version}) |",
        f"| **Juliet CWEs Scanned** | {juliet['summary']['cwes_analyzed']} "
        f"({mode_word} mode, CWE-matched rules) |",
        f"| **100% Precision CWEs** | {len(with_detections)} "
        "(zero false positives, with real detections) |",
        f"| **Per-File Detection** | {ca['per_file_rate_pct']}% "
        f"({ca['per_file_detected']:,} / {ca['per_file_total']:,} files) |",
        f"| **Real-World Precision / Recall** | {overall['precision_pct']}% / "
        f"{overall['recall_pct']}% (v{rw_run['sqc_version']}, run #{realworld_run_id}, "
        f"{coverage_pct}% label coverage) |",
        f"| **Real-World Projects** | {', '.join(projects)} |",
    ]
    return "\n".join(lines)


def render_juliet_current_state(db, juliet_run_id: str) -> str:
    juliet = db.get_run_summary(juliet_run_id)
    s, ca = juliet["summary"], juliet["cwe_aware"]
    run = db.get_run(juliet_run_id)
    rule_c = rule_counts()
    with_detections, zero_detection = _zero_fp_cwe_lists(juliet["per_cwe"])
    is_fast = run["mode"] == "fast"
    mode_word = "fast" if is_fast else "full"
    mode_label = "Fast (per-CWE manifests" if is_fast else "Full (all rules"

    wall_min = round(s["wall_s"] / 60) if s.get("wall_s") else None
    wall_str = f", ~{wall_min} min wall time" if wall_min else ""

    lines = [
        f"## Current State (v{run['sqc_version']})",
        "",
        f"Run `{juliet_run_id}`, completed "
        f"{s.get('finished_at', '')[:10]} ({mode_word} mode{wall_str}).",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| **Rules Implemented** | {rule_c['implemented']} CERT C rules "
        f"({rule_c['enabled']} enabled by default) |",
        f"| **Juliet CWEs Scanned** | {s['cwes_analyzed']} ({mode_word} mode, CWE-matched rules) |",
        f"| **True Positives** | {ca['cwe_matched_tp']:,} |",
        f"| **False Positives** | {ca['cwe_matched_fp']:,} |",
        f"| **TP Rate** | **{ca['cwe_matched_tp_rate_pct']}%** |",
        f"| **Per-file Detection Rate** | {ca['per_file_rate_pct']}% "
        f"({ca['per_file_detected']:,} / {ca['per_file_total']:,} files) |",
        f"| **Zero-FP CWEs** | {len(with_detections)} of {s['cwes_analyzed']} "
        f"(with real detections; {len(zero_detection)} more scanned CWEs "
        "have zero detections) |",
        f"| **Benchmark Mode** | {mode_label}, "
        f"{ca['noise_ratio_pct']}% noise) |",
        "",
        f"**100% precision, with detections ({len(with_detections)})**: "
        f"{_cwe_list_str(with_detections)}.",
        "",
        f"**Zero-detection CWEs** (rules mapped but 0 violations, "
        f"{len(zero_detection)}): {_cwe_list_str(zero_detection)}.",
    ]
    return "\n".join(lines)


def _backfill_from_history(db, by_project: dict, max_scan_runs: int = 60) -> None:
    """Fill in missing C-files/LOC and cppcheck/clang-tidy counts from recent
    run history.

    Competitor tools and per-project file/LOC counts are deliberately not
    re-scanned on every routine (sqc-only) run -- see CLAUDE.md ("only
    re-run [cppcheck/clang-tidy] when adding a new codebase to the suite")
    -- so a single run's own rows are usually incomplete by design, not by
    error. This mirrors the existing hand-maintained doc's practice of
    quietly carrying those numbers forward.
    """
    def missing(project):
        row = by_project.get(project, {})
        return (not row.get("c_files") or not row.get("loc")
                or any(row.get(t) is None for t in ("cppcheck", "clang-tidy")))

    needed = {p for p in by_project if missing(p)}
    for run in db.list_realworld_runs()[:max_scan_runs]:
        if not needed:
            break
        for r in db.get_realworld_results(run["id"]):
            project = r["project"]
            if project not in needed:
                continue
            row = by_project[project]
            if not row.get("c_files") and r["c_files"]:
                row["c_files"] = r["c_files"]
            if not row.get("loc") and r["loc"]:
                row["loc"] = r["loc"]
            if r["tool"] in ("cppcheck", "clang-tidy") and row.get(r["tool"]) is None \
                    and r["violation_count"] is not None:
                row[r["tool"]] = r["violation_count"]
        needed = {p for p in needed if missing(p)}


def render_realworld_latest(db, realworld_run_id: int) -> str:
    results = db.get_realworld_results(realworld_run_id)
    by_project: dict[str, dict] = {}
    for r in results:
        row = by_project.setdefault(
            r["project"], {"c_files": r["c_files"], "loc": r["loc"]})
        row[r["tool"]] = r["violation_count"]
    _backfill_from_history(db, by_project)

    lines = [
        "### Violation Counts — All Three Tools",
        "",
        "| Project | C Files | LOC | sqc | cppcheck | clang-tidy |",
        "|---------|--------:|----:|----:|--------:|-----------:|",
    ]
    tot_files = tot_loc = 0
    tot = {t: 0 for t in TOOL_ORDER}
    tot_present = {t: False for t in TOOL_ORDER}
    for project in sorted(by_project, key=lambda p: display_project(p).lower()):
        row = by_project[project]
        tot_files += row["c_files"]
        tot_loc += row["loc"]
        cells = []
        for tool in TOOL_ORDER:
            v = row.get(tool)
            cells.append(f"{v:,}" if v is not None else "—")
            if v is not None:
                tot[tool] += v
                tot_present[tool] = True
        lines.append(
            f"| **{display_project(project)}** | {row['c_files']} | "
            f"{row['loc']:,} | {cells[0]} | {cells[1]} | {cells[2]} |")
    tot_cells = [f"**{tot[t]:,}**" if tot_present[t] else "—" for t in TOOL_ORDER]
    lines.append(
        f"| **Total** | **{tot_files:,}** | **{tot_loc:,}** | "
        f"{tot_cells[0]} | {tot_cells[1]} | {tot_cells[2]} |")

    score = db.score_realworld_run(realworld_run_id)
    overall = score["overall"]
    coverage_pct = round(overall["labeled_total"] / overall["run_findings"] * 100, 1) \
        if overall["run_findings"] else 0.0
    lines += [
        "",
        f"Aggregate measured precision (adjudicated oracle, "
        f"`bench realworld-score {realworld_run_id}`): "
        f"**{overall['precision_pct']}%** (TP {overall['labeled_tp']:,} / "
        f"{overall['labeled_total']:,} labeled of {overall['run_findings']:,} "
        f"findings), **recall {overall['recall_pct']}%** "
        f"({overall['tp_detected']:,} / {overall['tp_labels']:,} known TPs "
        f"flagged); label coverage {overall['labeled_total']:,} / "
        f"{overall['run_findings']:,} findings ({coverage_pct}%; "
        f"{overall['labeled_uncertain']:,} matched labels are \"uncertain\" "
        "and excluded from precision).",
    ]
    return "\n".join(lines)


def render_all(db, juliet_run_id: str, realworld_run_id: int) -> dict:
    """Returns {path: new_text} for every doc with a marker pair found."""
    blocks = {
        README: [("BENCH:HIGHLIGHTS",
                  render_readme_highlights(db, juliet_run_id, realworld_run_id))],
        JULIET_RESULTS: [("BENCH:JULIET_CURRENT",
                          render_juliet_current_state(db, juliet_run_id))],
        REALWORLD_RESULTS: [("BENCH:REALWORLD_LATEST",
                             render_realworld_latest(db, realworld_run_id))],
    }
    out = {}
    for path, regions in blocks.items():
        text = path.read_text()
        for name, block in regions:
            text = replace_between(
                text, f"<!-- {name}:START -->", f"<!-- {name}:END -->", block)
        out[path] = text
    return out
