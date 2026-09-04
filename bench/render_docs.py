"""Regenerate the DB-derived presentation block in README.md.

The one file has one `<!-- BENCH:NAME:START -->` / `<!-- BENCH:NAME:END -->`
marker pair bracketing a block that is a pure projection of a benchmark DB
-- nothing outside a marker pair is ever touched, so hand-written narrative
sections stay hand-written.

(This used to also cover JULIET_RESULTS.md and REALWORLD_RESULTS.md, each
with its own generated block. Both retired 2026-09-03 once every figure they
generated had become redundant with this one table plus `data/benchmarks.db`
/`sqc_bench` Postgres -- see git history for `render_juliet_current_state`/
`render_realworld_latest` if you need the old block shapes.)

Every function here takes `db` as a plain argument and never imports a
concrete DB class -- callers decide what `db` is (see `bench/__main__.py`'s
`render-docs` command, which always uses `bench.db.BenchDB` against the local
SQLite file, same as every other `bench` subcommand).

CROSS-REPO CONTRACT (task 707). The other caller is `benchmarking_db`'s
`bin/refresh_tools_sqc_docs.py`, which imports these functions and hands them
its own Postgres-backed handle so the same blocks render from the shared
multi-node database. That makes `db` an implicit protocol owned by this
module, and it used to be an undeclared one: a foreign class with ~90 methods
was satisfying it by accident, and any method added here became a silent
cross-repo break found at runtime. Two things fix that, and both are load-
bearing rather than cosmetic:

  1. `BenchDBLike` below declares the *entire* required surface. It is six
     read-only run/result accessors. Adding a call to anything outside it is
     a breaking change to another repo and belongs in that list first.
  2. Scoring is no longer asked of `db` at all. Precision/recall over a
     historical run is the benchmark DB's metric to compute, not this
     module's to request, so callers pass the already-computed
     `score_realworld_run(...)` result as a plain dict (`rw_score`). The
     contract for the interesting half is now a data shape, which can be
     captured in a fixture and tested without a database of either kind.

`rw_score` fields this module reads:

  - `overall.published_basis` / `overall.definition_version` -- the basis the
    figures were computed on, printed as a table row by `_basis_cell`.
    Supplied by benchmarking_db's metrics layer (task 701); ABSENT from this
    repo's local scorer, which is a supported case and prints "not recorded"
    rather than nothing. Read with `.get`.
  - `overall.unlabeled_fraction`, `per_rule`, `per_project`
  - `unscoreable` -- list[dict], each `{project, reason, excluded_findings}`:
    projects dropped from every figure because no codebase_commit was
    recorded. THIS is the one the guard reads.
  - `unscoreable_projects` -- list[str], the same projects by name only. The
    `_projects` suffix means "names" on both sides; the counts live on the
    dicts. Not read here, listed so the two are not confused again: reading
    the name list as dicts raises TypeError, which `.get` does not prevent
    because the field is present, just differently shaped.

`unscoreable` is read with `.get`, so a scorer predating it degrades to "no
such projects" rather than raising. A scorer that HAS such projects and does
not report them will publish a table short a codebase, which is the failure
this contract exists to make impossible to hit by accident.
"""

from __future__ import annotations

import re
from typing import Protocol

from bench.config import PROJECT_DIR


class BenchDBLike(Protocol):
    """The complete `db` surface this module uses. See CROSS-REPO CONTRACT.

    Deliberately excludes `score_realworld_run`: its result is passed in as
    `rw_score` instead. Structural, so no implementation needs to import or
    subclass anything -- `bench.db.BenchDB` and `bench_db.BenchDB` both
    satisfy it as they stand.
    """

    def get_run(self, run_id: str) -> dict: ...
    def get_run_summary(self, run_id: str) -> dict: ...
    def list_runs(self) -> list[dict]: ...
    def get_realworld_run(self, run_id: int) -> dict: ...
    def get_realworld_results(self, run_id: int) -> list[dict]: ...
    def list_realworld_runs(self) -> list[dict]: ...


README = PROJECT_DIR / "README.md"

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


def realworld_project_count(db: BenchDBLike, realworld_run_id: int) -> int:
    results = db.get_realworld_results(realworld_run_id)
    return len({r["project"] for r in results if r["tool"] == "sqc"})


def resolve_latest_fast_juliet_run(db: BenchDBLike) -> str | None:
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


def realworld_citation_warnings(db: BenchDBLike, realworld_run_id: int,
                                rw_score: dict) -> list[str]:
    """Reasons NOT to cite this run without an explicit override, or [] if
    it's safely citable as-is.

    `rw_score` is the caller's `score_realworld_run(realworld_run_id)` result.

    Shared by every caller of `render_all` (tools_sqc's own `render-docs`
    CLI, and any other script pointing these functions at a differently-
    backed `db`, e.g. a Postgres-backed refresh run from the benchmark
    node) so the guard logic lives in exactly one place rather than being
    re-implemented per caller.
    """
    warnings = []

    # First, because it is the only one of these that is a FACT rather than a
    # judgement call: the other two say a run is probably not worth citing,
    # this one says the numbers already exclude data. A project with no
    # codebase_commit is dropped from every figure score_realworld_run
    # produces, so the rendered table is complete-looking and short a
    # codebase. Added 2026-09-03 -- the gate was attached and blocking (unlike
    # benchmarking_db's, which had the right predicate and no caller), but it
    # only knew about unlabeled fraction and project coverage, so this walked
    # straight past it.
    #
    # `unscoreable`, NOT `unscoreable_projects`: the first is list[dict], the
    # second is list[str] of names. Reading the wrong one crashed
    # benchmarking_db's publishing path with `TypeError: string indices must
    # be integers` -- which is the sharper version of the lesson that put this
    # guard here. `.get` protects against the field being ABSENT; it does
    # nothing about the field being present in a different SHAPE, and this
    # function runs against two repos' scorers. A guard that dies on its own
    # input is worse than one that is missing: it has a caller, a test and a
    # plausible read, and the error it raises tells an operator nothing about
    # their data.
    #
    # `.get` is still right for absence (an older scorer predating the field),
    # and the two shapes are now identical on both sides rather than merely
    # tolerated here -- shape-sniffing would have preserved the divergence
    # instead of ending it.
    unscoreable = rw_score.get("unscoreable") or []
    if unscoreable:
        names = ", ".join(u["project"] for u in unscoreable)
        n = sum(u.get("excluded_findings") or 0 for u in unscoreable)
        warnings.append(
            f"{len(unscoreable)} project(s) could not be scored -- no "
            f"codebase_commit recorded ({names}; {n:,} findings excluded "
            "from every figure). The table would read as full-suite while "
            "missing a codebase. Re-ingest with a sidecar rather than "
            "forcing past this.")

    unlabeled = rw_score["overall"].get("unlabeled_fraction") or 0.0
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


def _basis_cell(overall: dict) -> str:
    """The basis the real-world figures were computed on, as a table cell.

    dbbd7f84 put this under REALWORLD_RESULTS.md's generated block; e4469380
    retired that file and the line went with it, on the reasoning that the
    hazard -- canonical figures landing directly above hand-written prose
    carrying an older, unrecorded basis -- died with the document. It did not.
    It moved here, and it had already fired: a7f2771e refreshed this table to
    24.2% / 93.9% / 89.8% coverage and left the caveat paragraph eight lines
    below saying 93.7% recall and 11.8% unlabeled -- both exact fossils of the
    pre-canonical basis (100 - 88.2 = 11.8). README stated two recalls for one
    run.

    The prose is now written so it restates no generated number, which removes
    that particular collision. This cell is the general guard: any figure not
    on the named basis is not comparable to these, and a reader can see which
    basis they are holding instead of inferring it from the commit that last
    touched the file.

    Absent basis -- the normal case for this repo's local SQLite scorer, since
    `published_basis` comes from benchmarking_db's metrics layer -- prints
    "not recorded" rather than nothing. Printing nothing is the defect this
    exists to prevent, and stating it makes a locally-rendered table visibly
    distinct from a canonical one, which is the first actual enforcement of
    CLAUDE.md's rule against committing local figures as project numbers.
    """
    basis = overall.get("published_basis")
    version = overall.get("definition_version")
    if not basis:
        return ("**not recorded** — local scorer; describes one checkout's "
                "runs, not a project measurement")
    return f"`{basis}`" + (f" (definitions `{version}`)" if version else "")


def render_readme_highlights(db: BenchDBLike, juliet_run_id: str,
                             realworld_run_id: int, rw_score: dict) -> str:
    juliet = db.get_run_summary(juliet_run_id)
    ca = juliet["cwe_aware"]
    juliet_run = db.get_run(juliet_run_id)
    juliet_version = juliet_run["sqc_version"]
    mode_word = "fast" if juliet_run["mode"] == "fast" else "full"
    with_detections, zero_detection = _zero_fp_cwe_lists(juliet["per_cwe"])

    overall = rw_score["overall"]
    rw_run = db.get_realworld_run(realworld_run_id)
    rw_results = db.get_realworld_results(realworld_run_id)
    projects = sorted({display_project(r["project"]) for r in rw_results
                       if r["tool"] == "sqc"}, key=str.lower)
    coverage_pct = overall.get("label_coverage_pct") or 0.0

    lines = [
        "| Metric | Value |",
        "|--------|-------|",
        f"| **Juliet Precision** | {ca['cwe_matched_tp_rate_pct']}% (v{juliet_version}) |",
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
        f"| **Basis** | {_basis_cell(overall)} |",
    ]
    return "\n".join(lines)


def render_all(db: BenchDBLike, juliet_run_id: str, realworld_run_id: int,
               rw_score: dict) -> dict:
    """Returns {path: new_text} for every doc with a marker pair found.

    `rw_score` is the caller's `score_realworld_run(realworld_run_id)` result;
    pass the same dict given to `realworld_citation_warnings` so the guard and
    the rendered numbers describe one scoring pass rather than two.
    """
    blocks = {
        README: [("BENCH:HIGHLIGHTS",
                  render_readme_highlights(db, juliet_run_id,
                                           realworld_run_id, rw_score))],
    }
    out = {}
    for path, regions in blocks.items():
        text = path.read_text()
        for name, block in regions:
            text = replace_between(
                text, f"<!-- {name}:START -->", f"<!-- {name}:END -->", block)
        out[path] = text
    return out
