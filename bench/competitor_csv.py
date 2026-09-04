"""Export data/competitor_results/*.json to CSV for ingest into sqc_bench.

WHY CSV AND WHY HERE. The competitor Juliet runs are the one benchmark
artifact this repo holds directly -- `bench/competitors.py` writes a JSON blob
per run into `data/competitor_results/`, and those blobs are committed. That
made them durable but not ingestible: the shape is nested, the per-CWE map is
keyed by CWE id, and a Postgres loader would have to know this module's
internal layout to read it.

CSV is the handoff format. This repo stays Postgres-blind (no DSN, no
connection code, no awareness of the shared instance -- see CLAUDE.md), so it
EMITS a flat, stable, diffable table and `benchmarking_db` OWNS the ingest.
The seam is deliberate: nothing here needs to change when the target schema
does.

WHAT IT IS NOT. These CSVs are a transport, not a source of truth. Postgres
remains the only place an official number comes from. Re-exporting is
idempotent and lossless with respect to the JSON, so the JSON stays the
archival form and the CSV can be regenerated at any time.

THREE FILES, because one flat table cannot hold all three grains without
either nulls or repetition:

  competitor_runs.csv        one row per run       (tool, version, totals)
  competitor_cwe_results.csv one row per run x CWE (the actual measurements)
  competitor_cwe_errors.csv  one row per error     (usually empty)

`run_key` joins them and is the JSON's own basename (e.g.
`framac_20260403_222053`) -- already unique, already the file's identity, and
stable across re-exports in a way a synthesised id would not be.

Rows are sorted deterministically so a re-export produces no spurious diff.
"""

import csv
import json
from pathlib import Path

from bench.config import PROJECT_DIR

RESULTS_DIR = PROJECT_DIR / "data" / "competitor_results"

RUNS_CSV = RESULTS_DIR / "competitor_runs.csv"
CWE_CSV = RESULTS_DIR / "competitor_cwe_results.csv"
ERRORS_CSV = RESULTS_DIR / "competitor_cwe_errors.csv"

RUN_FIELDS = [
    "run_key", "tool", "tool_version", "hostname",
    "started_at", "finished_at", "duration_s",
    "cwe_count", "tp", "fp", "unknown", "files", "finding_count",
    "tp_rate_pct", "source_file",
]

CWE_FIELDS = [
    "run_key", "tool", "tool_version", "cwe_id", "cwe_dir",
    "tp", "fp", "unknown", "files", "finding_count", "duration_s",
    "error_count",
]

ERROR_FIELDS = ["run_key", "tool", "cwe_id", "error"]


def _tp_rate(tp: int, fp: int, unknown: int) -> float | None:
    """Share of findings that hit a planted flaw.

    Recomputed rather than read from the JSON's `totals.tp_rate_pct`: the
    one-CWE smoke runs predate that field, and a value derived here is
    guaranteed to agree with the tp/fp/unknown columns beside it."""
    total = tp + fp + unknown
    return round(tp / total * 100, 1) if total else None


def collect(results_dir: Path = RESULTS_DIR) -> tuple[list, list, list]:
    """Read every run JSON and flatten it into the three row sets."""
    runs, cwes, errors = [], [], []
    for path in sorted(results_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except Exception as e:
            raise ValueError(f"{path.name}: not readable as JSON ({e})") from e
        if "cwes" not in data or "tool" not in data:
            # Not a run blob (a stray file, or a future artifact). Skip rather
            # than fail: this directory is the tool's own output dir.
            continue

        run_key = path.stem
        tool = data.get("tool", "")
        version = data.get("tool_version", "")
        per_cwe = data.get("cwes", {})
        totals = data.get("totals", {})

        run_findings = 0
        for cwe_id in sorted(per_cwe):
            c = per_cwe[cwe_id]
            errs = c.get("errors") or []
            run_findings += int(c.get("finding_count") or 0)
            cwes.append({
                "run_key": run_key, "tool": tool, "tool_version": version,
                "cwe_id": cwe_id, "cwe_dir": c.get("cwe_dir", ""),
                "tp": c.get("tp", 0), "fp": c.get("fp", 0),
                "unknown": c.get("unknown", 0), "files": c.get("files", 0),
                "finding_count": c.get("finding_count", 0),
                "duration_s": c.get("duration_s"),
                "error_count": len(errs),
            })
            for e in errs:
                errors.append({"run_key": run_key, "tool": tool,
                               "cwe_id": cwe_id, "error": str(e)})

        tp = int(totals.get("tp", 0))
        fp = int(totals.get("fp", 0))
        unknown = int(totals.get("unknown", 0))
        runs.append({
            "run_key": run_key, "tool": tool, "tool_version": version,
            # Absent from every run recorded before 2026-09-04. Wall clock is
            # hardware-dependent, so a blank here means "do not compare this
            # run's duration against another host's", not "same host".
            "hostname": data.get("hostname", ""),
            "started_at": data.get("started_at", ""),
            "finished_at": data.get("finished_at", ""),
            "duration_s": data.get("duration_s"),
            "cwe_count": len(per_cwe),
            "tp": tp, "fp": fp, "unknown": unknown,
            "files": totals.get("files", 0),
            "finding_count": run_findings,
            "tp_rate_pct": _tp_rate(tp, fp, unknown),
            "source_file": path.name,
        })

    runs.sort(key=lambda r: (r["tool"], r["started_at"], r["run_key"]))
    cwes.sort(key=lambda r: (r["tool"], r["run_key"], r["cwe_id"]))
    errors.sort(key=lambda r: (r["tool"], r["run_key"], r["cwe_id"], r["error"]))
    return runs, cwes, errors


def _write(path: Path, fields: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def _render(fields: list[str], rows: list[dict]) -> str:
    import io
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()


def export(results_dir: Path = RESULTS_DIR, check: bool = False) -> dict:
    """Write the three CSVs, or in `check` mode report which are stale.

    `check` exists so a benchmark run that forgets the export is caught here
    rather than by `benchmarking_db` ingesting a table that is missing its
    newest run -- a silently short table looks exactly like a run that never
    happened."""
    runs, cwes, errors = collect(results_dir)
    targets = [(RUNS_CSV, RUN_FIELDS, runs),
               (CWE_CSV, CWE_FIELDS, cwes),
               (ERRORS_CSV, ERROR_FIELDS, errors)]
    stale = []
    for path, fields, rows in targets:
        rendered = _render(fields, rows)
        if check:
            current = path.read_text() if path.is_file() else None
            if current != rendered:
                stale.append(path)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered)
    return {"runs": len(runs), "cwe_rows": len(cwes), "errors": len(errors),
            "files": [RUNS_CSV, CWE_CSV, ERRORS_CSV], "stale": stale}
