"""SQLite database for benchmark results.

Single persistent DB at data/benchmarks.db with WAL mode for concurrent
read (MCP server) + write (runner). SQLite-only, deliberately: this is the
zero-setup path for an individual running a Juliet or real-world benchmark
locally, with no shared-infrastructure dependency. The maintainer's shared
Postgres instance (multi-node querying/queueing) lives entirely in the
separate benchmarking_db repo -- this module has no knowledge of it.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bench.config import DB_PATH


def _wall_seconds(started_at: str, finished_at: str) -> float | None:
    """Elapsed wall-clock seconds between two ISO-8601 timestamps, or None if
    either fails to parse (e.g. a still-running or legacy run)."""
    try:
        start = datetime.fromisoformat(started_at)
        end = datetime.fromisoformat(finished_at)
    except (ValueError, TypeError):
        return None
    return round((end - start).total_seconds(), 1)


# Configuration-variant token, kept in step with bench/config.py's
# COMPILE_DB_RUN_SUFFIX (the "-cdb" a compile-database run appends to its
# run_id). Duplicated as a literal rather than imported so this module stays
# importable on its own.
_COMPILE_DB_VARIANT = "cdb"

# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    sqc_version     TEXT NOT NULL,
    commit_sha      TEXT NOT NULL,
    mode            TEXT NOT NULL DEFAULT 'fast',
    status          TEXT NOT NULL DEFAULT 'running',
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    pid             INTEGER,
    jobs            INTEGER,
    total_cwes      INTEGER,
    hostname        TEXT,
    cpu_model       TEXT,
    cpu_cores       INTEGER,
    ram_gb          REAL,
    os_version      TEXT,
    -- Juliet runner never passes --load-prescan (bench/runner.py), so every
    -- run is a fresh prescan; always 'cold' until a warm path is wired (task 209).
    cache_state     TEXT NOT NULL DEFAULT 'cold'
);

CREATE TABLE IF NOT EXISTS cwe_scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL REFERENCES runs(run_id),
    cwe_id          TEXT NOT NULL,
    cwe_dir_name    TEXT NOT NULL,
    file_count      INTEGER DEFAULT 0,
    violation_count INTEGER DEFAULT 0,
    duration_s      REAL,
    status          TEXT NOT NULL DEFAULT 'pending',
    UNIQUE(run_id, cwe_dir_name)
);

CREATE TABLE IF NOT EXISTS violations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_scan_id     INTEGER NOT NULL REFERENCES cwe_scans(id),
    rule_id         TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line            INTEGER NOT NULL,
    classification  TEXT,
    in_bad_section  INTEGER DEFAULT 0,
    in_good_section INTEGER DEFAULT 0,
    hits_flaw_line  INTEGER DEFAULT 0,
    is_cwe_matched  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cwe_metrics (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_scan_id             INTEGER NOT NULL UNIQUE REFERENCES cwe_scans(id),
    tp_count                INTEGER DEFAULT 0,
    fp_count                INTEGER DEFAULT 0,
    tp_rate_pct             REAL DEFAULT 0,
    flaw_lines_total        INTEGER DEFAULT 0,
    flaw_lines_detected     INTEGER DEFAULT 0,
    flaw_detection_rate_pct REAL DEFAULT 0,
    cwe_matched_tp          INTEGER DEFAULT 0,
    cwe_matched_fp          INTEGER DEFAULT 0,
    noise_count             INTEGER DEFAULT 0,
    noise_ratio             REAL DEFAULT 0,
    per_file_detected       INTEGER DEFAULT 0,
    per_file_total          INTEGER DEFAULT 0,
    per_file_rate           REAL DEFAULT 0,
    flaw_hit_detected       INTEGER DEFAULT 0,
    flaw_hit_total          INTEGER DEFAULT 0,
    flaw_hit_rate           REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rule_cwe_breakdown (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_scan_id     INTEGER NOT NULL REFERENCES cwe_scans(id),
    rule_id         TEXT NOT NULL,
    tp_count        INTEGER DEFAULT 0,
    fp_count        INTEGER DEFAULT 0,
    flaw_line_count INTEGER DEFAULT 0,
    is_cwe_matched  INTEGER DEFAULT 0,
    UNIQUE(cwe_scan_id, rule_id)
);

CREATE TABLE IF NOT EXISTS realworld_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    -- The canonical run identifier ("sqc-0.4.320-742e92a6-cdb"). Before this
    -- column existed it lived only inside the free-text `notes`, so addressing
    -- a run by its id meant substring-matching prose -- which could not
    -- distinguish a run from one whose id merely extends it (see
    -- resolve_realworld_run). NULL for six pre-ingest historical rows whose
    -- notes never carried an id.
    run_id          TEXT,
    sqc_version     TEXT NOT NULL,
    -- The real commit SHA, and nothing else. A configuration variant belongs
    -- in `variant`, not glued onto the end of this: an exact-SHA lookup that
    -- silently skips half an A/B pair is worse than no lookup.
    commit_sha      TEXT,
    -- Configuration this run used, NULL for a default run. "cdb" = run with
    -- --compile-commands (bench/config.py COMPILE_DB_RUN_SUFFIX).
    variant         TEXT,
    scanned_at      TEXT,
    hostname        TEXT,
    cpu_model       TEXT,
    cpu_cores       INTEGER,
    notes           TEXT
);
-- The identity indexes are NOT declared here: _SCHEMA runs before
-- _migrate_realworld_run_identity, so on a pre-migration database they would
-- reference a column that does not exist yet. That function creates them for
-- fresh and migrated databases alike.

CREATE TABLE IF NOT EXISTS realworld_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          INTEGER NOT NULL REFERENCES realworld_runs(id),
    project         TEXT NOT NULL,
    tool            TEXT NOT NULL,
    c_files         INTEGER DEFAULT 0,
    loc             INTEGER DEFAULT 0,
    violation_count INTEGER DEFAULT 0,
    duration_s      REAL,
    codebase_commit TEXT,
    UNIQUE(run_id, project, tool)
);

CREATE TABLE IF NOT EXISTS realworld_violations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id       INTEGER NOT NULL REFERENCES realworld_results(id),
    rule_id         TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line            INTEGER NOT NULL,
    column_num      INTEGER DEFAULT 0,
    severity        TEXT,
    message         TEXT,
    suggestion      TEXT,
    requires_manual_review INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ground_truth (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project         TEXT NOT NULL,
    codebase_commit TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    line            INTEGER NOT NULL,
    rule_id         TEXT NOT NULL,
    verdict         TEXT NOT NULL,           -- 'TP' | 'FP' | 'uncertain'
    adjudicator     TEXT,                    -- 'manual', 'claude-opus-4.8', ...
    reason          TEXT,
    source          TEXT,                    -- provenance, e.g. 'precision_audit_0.4.22'
    adjudicated_at  TEXT NOT NULL,
    UNIQUE(project, codebase_commit, file_path, line, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_gt_lookup
    ON ground_truth(project, codebase_commit, rule_id);
CREATE INDEX IF NOT EXISTS idx_gt_verdict ON ground_truth(verdict);

-- Task 637: a second, independent verdict on a finding ALREADY labeled in
-- ground_truth, so Claude-vs-human adjudicator agreement can be measured.
-- Side table rather than relaxing ground_truth's UNIQUE(...) -- the oracle's
-- one-label-per-finding invariant stays intact for every precision/recall
-- query already written against it; a calibration round just adds rows here
-- that reference the original by gt_id. original_verdict/original_adjudicator
-- are captured at insert time (not read live) so a later re-adjudication of
-- the ground_truth row can't quietly rewrite what this round was actually
-- compared against.
CREATE TABLE IF NOT EXISTS calibration_labels (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    gt_id               INTEGER NOT NULL REFERENCES ground_truth(id),
    project             TEXT NOT NULL,
    codebase_commit     TEXT NOT NULL,
    file_path           TEXT NOT NULL,
    line                INTEGER NOT NULL,
    rule_id             TEXT NOT NULL,
    verdict             TEXT NOT NULL,           -- this round's verdict
    adjudicator         TEXT NOT NULL,           -- who produced THIS verdict
    reason              TEXT,
    source              TEXT,                    -- e.g. 'calibration_batch1'
    adjudicated_at      TEXT NOT NULL,
    original_verdict    TEXT NOT NULL,           -- ground_truth.verdict, snapshotted
    original_adjudicator TEXT,                   -- ground_truth.adjudicator, snapshotted
    UNIQUE(gt_id, adjudicator)
);
CREATE INDEX IF NOT EXISTS idx_calib_lookup ON calibration_labels(rule_id, project);

-- File-at-a-time audit: a row here means the file was exhaustively swept
-- (every sqc finding in it labeled, AND read independently for missed bugs).
-- This is the atomic "done" unit; the audited-file set grows monotonically
-- and is the denominator for honest precision AND recall.
CREATE TABLE IF NOT EXISTS audited_files (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    project         TEXT NOT NULL,
    codebase_commit TEXT NOT NULL,
    file_path       TEXT NOT NULL,           -- project-relative
    adjudicator     TEXT,
    audited_at      TEXT NOT NULL,
    n_findings      INTEGER DEFAULT 0,       -- sqc findings in this file (precision denom)
    n_tp            INTEGER DEFAULT 0,
    n_fp            INTEGER DEFAULT 0,
    n_uncertain     INTEGER DEFAULT 0,
    n_fn            INTEGER DEFAULT 0,        -- real bugs sqc missed (recall)
    notes           TEXT,
    UNIQUE(project, codebase_commit, file_path)
);
CREATE INDEX IF NOT EXISTS idx_audited_lookup
    ON audited_files(project, codebase_commit);

-- The coverage denominator: how many in-scope files exist at a pinned commit.
-- Recorded once per (project, commit) so "done = audited/total" is well-defined
-- and survives into the frozen, versioned oracle.
CREATE TABLE IF NOT EXISTS audit_corpus_meta (
    project             TEXT NOT NULL,
    codebase_commit     TEXT NOT NULL,
    total_inscope_files INTEGER,
    scope_note          TEXT,
    updated_at          TEXT,
    PRIMARY KEY (project, codebase_commit)
);

-- Frozen, citable snapshots of the oracle for the paper. Any post-freeze
-- correction (incl. an FN that re-adjudication overturns) bumps the version.
CREATE TABLE IF NOT EXISTS oracle_versions (
    version         TEXT PRIMARY KEY,
    frozen_at       TEXT NOT NULL,
    notes           TEXT,
    snapshot_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_violations_cwe_scan ON violations(cwe_scan_id);
CREATE INDEX IF NOT EXISTS idx_violations_rule ON violations(rule_id);
CREATE INDEX IF NOT EXISTS idx_violations_class ON violations(classification);
CREATE INDEX IF NOT EXISTS idx_cwe_scans_run ON cwe_scans(run_id);
CREATE INDEX IF NOT EXISTS idx_cwe_scans_cwe ON cwe_scans(cwe_id);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
CREATE INDEX IF NOT EXISTS idx_rw_results_run ON realworld_results(run_id);
CREATE INDEX IF NOT EXISTS idx_rw_results_project ON realworld_results(project);
CREATE INDEX IF NOT EXISTS idx_rw_violations_result ON realworld_violations(result_id);
CREATE INDEX IF NOT EXISTS idx_rw_violations_rule ON realworld_violations(rule_id);
"""


class BenchDB:
    """Interface to the benchmark SQLite database."""

    def __init__(self, db_path: Path | str | None = None):
        self._db_path = str(db_path or DB_PATH)
        self._ensure_schema()

    def _connect(self):
        conn = sqlite3.connect(self._db_path, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _cursor(self):
        conn = self._connect()
        try:
            yield conn.cursor()
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _table_columns(self, conn, table: str) -> set[str]:
        """Column names for `table` -- used by the migration checks below so
        a schema from an older version of this module self-heals."""
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}

    def _ensure_schema(self):
        conn = self._connect()
        try:
            conn.executescript(_SCHEMA)
            # Migrations for columns added after a table already exists
            # (CREATE TABLE IF NOT EXISTS does not update existing tables).
            cols = self._table_columns(conn, "realworld_results")
            if "codebase_commit" not in cols:
                conn.execute(
                    "ALTER TABLE realworld_results ADD COLUMN codebase_commit TEXT")
            # ground_truth gained provenance/confidence for FN corroboration.
            gt_cols = self._table_columns(conn, "ground_truth")
            if "provenance" not in gt_cols:
                conn.execute(
                    "ALTER TABLE ground_truth ADD COLUMN provenance TEXT")
            if "confidence" not in gt_cols:
                conn.execute(
                    "ALTER TABLE ground_truth ADD COLUMN confidence TEXT")
            # runs gained cache_state (task 208); backfill existing rows as
            # 'cold' since no run ever used a prescan cache.
            run_cols = self._table_columns(conn, "runs")
            if "cache_state" not in run_cols:
                conn.execute(
                    "ALTER TABLE runs ADD COLUMN cache_state TEXT NOT NULL DEFAULT 'cold'")
            # realworld_violations gained requires_manual_review (task 478):
            # sqc's JSON export now carries this per-finding confidence flag
            # (RuleViolation.requires_manual_review), used by rules that
            # can't structurally distinguish a real violation from an
            # intentional idiom (e.g. MSC12-C's empty-switch-case check).
            rv_cols = self._table_columns(conn, "realworld_violations")
            if "requires_manual_review" not in rv_cols:
                conn.execute(
                    "ALTER TABLE realworld_violations "
                    "ADD COLUMN requires_manual_review INTEGER NOT NULL DEFAULT 0")
            conn.commit()
        finally:
            conn.close()
        self._migrate_realworld_run_identity()

    def _migrate_realworld_run_identity(self):
        """Give `realworld_runs` a first-class identity (run_id + variant).

        Rebuilds the table rather than ALTER-ing it, because the old schema
        carries a table-level ``UNIQUE(sqc_version, commit_sha)`` that SQLite
        cannot drop in place -- and it has to go. That constraint was only
        satisfiable for an A/B pair because the variant suffix was being stored
        *inside* ``commit_sha`` ("742e92a6-cdb"), an accident of
        ``ingest_realworld_run`` splitting the results-directory name with
        maxsplit 2. The cost was that ``WHERE commit_sha = '742e92a6'`` matched
        only the plain half of a pair, silently.

        Migration is a no-op once `run_id` exists, so this is safe to call on
        every connect. Existing rows are backfilled from what they already
        carry: `run_id` out of the "ingested from <id>" notes (NULL for the six
        historical rows predating that convention), `variant` and a cleaned
        `commit_sha` out of the polluted SHA.
        """
        conn = self._connect()
        try:
            if "run_id" in self._table_columns(conn, "realworld_runs"):
                self._create_realworld_identity_indexes(conn)
                conn.commit()
                return
            # PRAGMA foreign_keys is a no-op inside a transaction, and the
            # child table realworld_results REFERENCES realworld_runs(id), so
            # it must be disabled around the drop/rename. Row ids are
            # preserved, so every child row stays pointed at its own parent.
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("BEGIN")
            conn.execute("""
                CREATE TABLE realworld_runs_new (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id          TEXT,
                    sqc_version     TEXT NOT NULL,
                    commit_sha      TEXT,
                    variant         TEXT,
                    scanned_at      TEXT,
                    hostname        TEXT,
                    cpu_model       TEXT,
                    cpu_cores       INTEGER,
                    notes           TEXT
                )
            """)
            conn.execute("""
                INSERT INTO realworld_runs_new
                    (id, run_id, sqc_version, commit_sha, variant,
                     scanned_at, hostname, cpu_model, cpu_cores, notes)
                SELECT
                    id,
                    CASE WHEN notes LIKE 'ingested from %'
                         THEN substr(notes, length('ingested from ') + 1)
                    END,
                    sqc_version,
                    CASE WHEN commit_sha LIKE '%-' || ?
                         THEN substr(commit_sha, 1,
                                     length(commit_sha) - length(?) - 1)
                         ELSE commit_sha END,
                    CASE WHEN commit_sha LIKE '%-' || ? THEN ? END,
                    scanned_at, hostname, cpu_model, cpu_cores, notes
                FROM realworld_runs
            """, (_COMPILE_DB_VARIANT,) * 4)
            conn.execute("DROP TABLE realworld_runs")
            conn.execute("ALTER TABLE realworld_runs_new RENAME TO realworld_runs")
            self._create_realworld_identity_indexes(conn)
            violations = list(conn.execute("PRAGMA foreign_key_check"))
            if violations:
                conn.execute("ROLLBACK")
                raise RuntimeError(
                    "realworld_runs identity migration would orphan "
                    f"{len(violations)} child row(s); left unchanged")
            conn.execute("COMMIT")
        finally:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.close()

    @staticmethod
    def _create_realworld_identity_indexes(conn):
        """One row per run identifier, and one per (version, commit, variant).

        The second replaces the old table-level ``UNIQUE(sqc_version,
        commit_sha)``: with a clean SHA an A/B pair collides on it, and
        COALESCE keeps the original protection for default runs while letting
        a variant run sit alongside its sibling. SQLite treats NULLs in a
        unique index as distinct, which is what the historical rows with no
        `run_id` need.
        """
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_rw_runs_run_id "
                     "ON realworld_runs(run_id)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_rw_runs_identity "
                     "ON realworld_runs(sqc_version, commit_sha, "
                     "COALESCE(variant, ''))")

    # ── Run CRUD ──────────────────────────────────────────────────────────

    def create_run(self, run_id: str, sqc_version: str, commit_sha: str,
                   mode: str, started_at: str, pid: int, jobs: int,
                   total_cwes: int, machine: dict) -> None:
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO runs (run_id, sqc_version, commit_sha, mode, status,
                                  started_at, pid, jobs, total_cwes,
                                  hostname, cpu_model, cpu_cores, ram_gb, os_version)
                VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (run_id, sqc_version, commit_sha, mode, started_at,
                  pid, jobs, total_cwes,
                  machine.get("hostname"), machine.get("cpu_model"),
                  machine.get("cpu_cores"), machine.get("ram_gb"),
                  machine.get("os_version")))

    def finish_run(self, run_id: str, status: str, finished_at: str) -> None:
        with self._cursor() as cur:
            cur.execute("""
                UPDATE runs SET status = ?, finished_at = ? WHERE run_id = ?
            """, (status, finished_at, run_id))

    def update_run_status(self, run_id: str, status: str) -> None:
        with self._cursor() as cur:
            cur.execute("UPDATE runs SET status = ? WHERE run_id = ?",
                        (status, run_id))

    def get_run(self, run_id: str) -> dict | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_runs(self) -> list[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM runs ORDER BY started_at DESC")
            return [dict(r) for r in cur.fetchall()]

    def list_run_timings(self, limit: int = 10) -> list[dict]:
        """Runtime (wall + summed analysis time) for the most recent Juliet
        runs, newest first. `analysis_s` sums each CWE's own sqc-subprocess
        duration (see get_run_summary's note on why it exceeds wall_s under
        parallelism); `wall_s` is the run's real start-to-finish elapsed time.
        """
        with self._cursor() as cur:
            query = "SELECT * FROM runs ORDER BY started_at DESC"
            if limit and limit > 0:
                query += " LIMIT ?"
                cur.execute(query, (limit,))
            else:
                cur.execute(query)
            runs = [dict(r) for r in cur.fetchall()]

            timings = []
            for run in runs:
                cur.execute(
                    "SELECT SUM(duration_s) as total FROM cwe_scans WHERE run_id = ? AND status = 'completed'",
                    (run["run_id"],),
                )
                analysis_s = cur.fetchone()["total"]
                entry = {
                    "run_id": run["run_id"],
                    "sqc_version": run["sqc_version"],
                    "commit_sha": run["commit_sha"],
                    "mode": run["mode"],
                    "status": run["status"],
                    "started_at": run["started_at"],
                    "finished_at": run.get("finished_at"),
                    "jobs": run.get("jobs"),
                    "cache_state": run.get("cache_state"),
                    "analysis_s": round(analysis_s, 1) if analysis_s else None,
                }
                if run.get("started_at") and run.get("finished_at"):
                    wall_s = _wall_seconds(run["started_at"], run["finished_at"])
                    if wall_s is not None:
                        entry["wall_s"] = wall_s
                timings.append(entry)
            return timings

    # ── CWE Scan CRUD ────────────────────────────────────────────────────

    def create_cwe_scan(self, run_id: str, cwe_id: str,
                        cwe_dir_name: str, file_count: int = 0) -> int:
        with self._cursor() as cur:
            # Resume support: an interrupted run leaves non-completed rows
            # behind. Reuse the row, reset it, and purge partial child data.
            cur.execute("""
                SELECT id FROM cwe_scans
                WHERE run_id = ? AND cwe_dir_name = ?
            """, (run_id, cwe_dir_name))
            row = cur.fetchone()
            if row:
                scan_id = row["id"]
                cur.execute("DELETE FROM violations WHERE cwe_scan_id = ?", (scan_id,))
                cur.execute("DELETE FROM cwe_metrics WHERE cwe_scan_id = ?", (scan_id,))
                cur.execute("DELETE FROM rule_cwe_breakdown WHERE cwe_scan_id = ?", (scan_id,))
                cur.execute("""
                    UPDATE cwe_scans
                    SET status = 'pending', file_count = ?, cwe_id = ?
                    WHERE id = ?
                """, (file_count, cwe_id, scan_id))
                return scan_id
            cur.execute("""
                INSERT INTO cwe_scans (run_id, cwe_id, cwe_dir_name, file_count, status)
                VALUES (?, ?, ?, ?, 'pending')
                RETURNING id
            """, (run_id, cwe_id, cwe_dir_name, file_count))
            return cur.fetchone()["id"]

    def update_cwe_scan(self, scan_id: int, **kwargs) -> None:
        if not kwargs:
            return
        cols = ", ".join(f"{k} = ?" for k in kwargs)
        vals = list(kwargs.values()) + [scan_id]
        with self._cursor() as cur:
            cur.execute(f"UPDATE cwe_scans SET {cols} WHERE id = ?", vals)

    def get_cwe_scan(self, scan_id: int) -> dict | None:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM cwe_scans WHERE id = ?", (scan_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_completed_cwes(self, run_id: str) -> set[str]:
        """Return set of cwe_dir_name values with status='completed' for a run."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT cwe_dir_name FROM cwe_scans
                WHERE run_id = ? AND status = 'completed'
            """, (run_id,))
            return {row["cwe_dir_name"] for row in cur.fetchall()}

    # ── Violation CRUD ────────────────────────────────────────────────────

    def insert_violations(self, violations: list[dict]) -> None:
        """Bulk insert violations. Each dict must have: cwe_scan_id, rule_id,
        file_path, line, classification, in_bad_section, in_good_section,
        hits_flaw_line, is_cwe_matched."""
        if not violations:
            return
        with self._cursor() as cur:
            cur.executemany("""
                INSERT INTO violations
                    (cwe_scan_id, rule_id, file_path, line, classification,
                     in_bad_section, in_good_section, hits_flaw_line, is_cwe_matched)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [(v["cwe_scan_id"], v["rule_id"], v["file_path"], v["line"],
                   v["classification"], v["in_bad_section"], v["in_good_section"],
                   v["hits_flaw_line"], v["is_cwe_matched"])
                  for v in violations])

    # ── Metrics CRUD ──────────────────────────────────────────────────────

    def insert_cwe_metrics(self, metrics: dict) -> None:
        """Insert or replace pre-computed CWE metrics."""
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO cwe_metrics
                    (cwe_scan_id, tp_count, fp_count, tp_rate_pct,
                     flaw_lines_total, flaw_lines_detected, flaw_detection_rate_pct,
                     cwe_matched_tp, cwe_matched_fp, noise_count, noise_ratio,
                     per_file_detected, per_file_total, per_file_rate,
                     flaw_hit_detected, flaw_hit_total, flaw_hit_rate)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (cwe_scan_id) DO UPDATE SET
                    tp_count = excluded.tp_count,
                    fp_count = excluded.fp_count,
                    tp_rate_pct = excluded.tp_rate_pct,
                    flaw_lines_total = excluded.flaw_lines_total,
                    flaw_lines_detected = excluded.flaw_lines_detected,
                    flaw_detection_rate_pct = excluded.flaw_detection_rate_pct,
                    cwe_matched_tp = excluded.cwe_matched_tp,
                    cwe_matched_fp = excluded.cwe_matched_fp,
                    noise_count = excluded.noise_count,
                    noise_ratio = excluded.noise_ratio,
                    per_file_detected = excluded.per_file_detected,
                    per_file_total = excluded.per_file_total,
                    per_file_rate = excluded.per_file_rate,
                    flaw_hit_detected = excluded.flaw_hit_detected,
                    flaw_hit_total = excluded.flaw_hit_total,
                    flaw_hit_rate = excluded.flaw_hit_rate
            """, (metrics["cwe_scan_id"],
                  metrics.get("tp_count", 0), metrics.get("fp_count", 0),
                  metrics.get("tp_rate_pct", 0),
                  metrics.get("flaw_lines_total", 0),
                  metrics.get("flaw_lines_detected", 0),
                  metrics.get("flaw_detection_rate_pct", 0),
                  metrics.get("cwe_matched_tp", 0),
                  metrics.get("cwe_matched_fp", 0),
                  metrics.get("noise_count", 0),
                  metrics.get("noise_ratio", 0),
                  metrics.get("per_file_detected", 0),
                  metrics.get("per_file_total", 0),
                  metrics.get("per_file_rate", 0),
                  metrics.get("flaw_hit_detected", 0),
                  metrics.get("flaw_hit_total", 0),
                  metrics.get("flaw_hit_rate", 0)))

    def insert_rule_breakdown(self, rows: list[dict]) -> None:
        """Bulk insert per-rule per-CWE breakdown."""
        if not rows:
            return
        with self._cursor() as cur:
            cur.executemany("""
                INSERT INTO rule_cwe_breakdown
                    (cwe_scan_id, rule_id, tp_count, fp_count,
                     flaw_line_count, is_cwe_matched)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (cwe_scan_id, rule_id) DO UPDATE SET
                    tp_count = excluded.tp_count,
                    fp_count = excluded.fp_count,
                    flaw_line_count = excluded.flaw_line_count,
                    is_cwe_matched = excluded.is_cwe_matched
            """, [(r["cwe_scan_id"], r["rule_id"],
                   r.get("tp_count", 0), r.get("fp_count", 0),
                   r.get("flaw_line_count", 0), r.get("is_cwe_matched", 0))
                  for r in rows])

    # ── Query API ─────────────────────────────────────────────────────────

    def get_progress(self, run_id: str) -> dict:
        """Get progress for a running benchmark."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT status, COUNT(*) as cnt
                FROM cwe_scans WHERE run_id = ?
                GROUP BY status
            """, (run_id,))
            status_counts = {row["status"]: row["cnt"] for row in cur.fetchall()}

            cur.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
            run_row = cur.fetchone()
            run = dict(run_row) if run_row else {}

            # Recent completions
            cur.execute("""
                SELECT cwe_dir_name, cwe_id, file_count, violation_count, duration_s
                FROM cwe_scans
                WHERE run_id = ? AND status = 'completed'
                ORDER BY id DESC LIMIT 5
            """, (run_id,))
            recent = [dict(r) for r in cur.fetchall()]

        total = sum(status_counts.values())
        done = status_counts.get("completed", 0)
        progress_pct = round(done / total * 100, 1) if total else 0

        return {
            "run": run,
            "status_counts": status_counts,
            "total_cwes": total,
            "done_cwes": done,
            "progress_pct": progress_pct,
            "recently_completed": recent,
        }

    def get_run_summary(self, run_id: str) -> dict:
        """Aggregated TP/FP results for a completed run."""
        with self._cursor() as cur:
            # Check if this run has a synthetic aggregate "ALL" row
            cur.execute("""
                SELECT m.* FROM cwe_metrics m
                JOIN cwe_scans s ON s.id = m.cwe_scan_id
                WHERE s.run_id = ? AND s.cwe_id = 'ALL'
            """, (run_id,))
            agg_row = cur.fetchone()

            # Check count of per-CWE rows (excluding aggregate)
            cur.execute("""
                SELECT COUNT(*) as cnt FROM cwe_scans
                WHERE run_id = ? AND cwe_id != 'ALL'
            """, (run_id,))
            per_cwe_count = cur.fetchone()["cnt"]

            if agg_row:
                # Use the authoritative aggregate row for totals
                totals = {
                    "total_tp": agg_row["tp_count"],
                    "total_fp": agg_row["fp_count"],
                    "total_flaw_lines": agg_row["flaw_lines_total"],
                    "total_flaw_detected": agg_row["flaw_lines_detected"],
                    "total_cwe_matched_tp": agg_row["cwe_matched_tp"],
                    "total_cwe_matched_fp": agg_row["cwe_matched_fp"],
                    "total_noise": agg_row["noise_count"],
                    "total_per_file_detected": agg_row["per_file_detected"],
                    "total_per_file_total": agg_row["per_file_total"],
                    "total_flaw_hit_detected": agg_row["flaw_hit_detected"],
                    "total_flaw_hit_total": agg_row["flaw_hit_total"],
                    "cwes_analyzed": per_cwe_count or 1,
                }
            else:
                # Sum from per-CWE rows (live benchmark runs)
                cur.execute("""
                    SELECT
                        SUM(m.tp_count) as total_tp,
                        SUM(m.fp_count) as total_fp,
                        SUM(m.flaw_lines_total) as total_flaw_lines,
                        SUM(m.flaw_lines_detected) as total_flaw_detected,
                        SUM(m.cwe_matched_tp) as total_cwe_matched_tp,
                        SUM(m.cwe_matched_fp) as total_cwe_matched_fp,
                        SUM(m.noise_count) as total_noise,
                        SUM(m.per_file_detected) as total_per_file_detected,
                        SUM(m.per_file_total) as total_per_file_total,
                        SUM(m.flaw_hit_detected) as total_flaw_hit_detected,
                        SUM(m.flaw_hit_total) as total_flaw_hit_total,
                        COUNT(*) as cwes_analyzed
                    FROM cwe_metrics m
                    JOIN cwe_scans s ON s.id = m.cwe_scan_id
                    WHERE s.run_id = ?
                """, (run_id,))
                totals = dict(cur.fetchone())

            # Per-CWE breakdown (exclude synthetic aggregate from display)
            cur.execute(f"""
                SELECT
                    s.cwe_id, s.cwe_dir_name, s.file_count, s.duration_s,
                    m.tp_count, m.fp_count, m.tp_rate_pct,
                    m.flaw_lines_detected, m.flaw_lines_total,
                    m.flaw_detection_rate_pct,
                    m.cwe_matched_tp, m.cwe_matched_fp,
                    m.per_file_rate, m.flaw_hit_rate
                FROM cwe_metrics m
                JOIN cwe_scans s ON s.id = m.cwe_scan_id
                WHERE s.run_id = ? AND s.cwe_id != 'ALL'
                ORDER BY m.fp_count DESC
            """, (run_id,))
            per_cwe = [dict(r) for r in cur.fetchall()]

            # Top rules by FP across all CWEs (exclude aggregate)
            cur.execute("""
                SELECT
                    rb.rule_id,
                    SUM(rb.tp_count) as tp,
                    SUM(rb.fp_count) as fp,
                    SUM(rb.tp_count) + SUM(rb.fp_count) as total
                FROM rule_cwe_breakdown rb
                JOIN cwe_scans s ON s.id = rb.cwe_scan_id
                WHERE s.run_id = ? AND s.cwe_id != 'ALL'
                GROUP BY rb.rule_id
                ORDER BY fp DESC
                LIMIT 20
            """, (run_id,))
            top_rules = [dict(r) for r in cur.fetchall()]
            for r in top_rules:
                r["fp_pct"] = round(r["fp"] / r["total"] * 100, 1) if r["total"] else 0

            # Run metadata
            cur.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,))
            run_row = cur.fetchone()
            run = dict(run_row) if run_row else {}

        total_tp = totals["total_tp"] or 0
        total_fp = totals["total_fp"] or 0
        grand_total = total_tp + total_fp

        summary = {
            "total_violations": grand_total,
            "total_tp": total_tp,
            "total_fp": total_fp,
            "tp_rate_pct": round(total_tp / grand_total * 100, 1) if grand_total else 0,
            "fp_rate_pct": round(total_fp / grand_total * 100, 1) if grand_total else 0,
            "cwes_analyzed": totals["cwes_analyzed"] or 0,
            "run_name": run_id,
            "version": run.get("sqc_version"),
            "commit_sha": run.get("commit_sha"),
            "cache_state": run.get("cache_state", "cold"),
        }

        # Timing metrics. `wall_s` is the run's real elapsed time; `analysis_s`
        # is the summed per-CWE sqc-subprocess time (each `sqc` invocation does
        # its own prescan+scan). Because CWEs run in parallel, analysis_s
        # normally exceeds wall_s — it is the parallelism-independent measure of
        # total compute, which is the more stable axis for comparing the cost of
        # analysis-depth changes across versions. See task 202.
        summary["jobs"] = run.get("jobs")
        analysis_s = sum(c["duration_s"] for c in per_cwe if c.get("duration_s"))
        summary["analysis_s"] = round(analysis_s, 1)
        if run.get("started_at") and run.get("finished_at"):
            summary["started_at"] = run["started_at"]
            summary["finished_at"] = run["finished_at"]
            wall_s = _wall_seconds(run["started_at"], run["finished_at"])
            if wall_s is not None:
                summary["wall_s"] = wall_s

        # CWE-aware summary
        cwe_matched_tp = totals["total_cwe_matched_tp"] or 0
        cwe_matched_fp = totals["total_cwe_matched_fp"] or 0
        cwe_matched_total = cwe_matched_tp + cwe_matched_fp
        total_noise = totals["total_noise"] or 0
        all_findings = cwe_matched_total + total_noise
        per_file_detected = totals["total_per_file_detected"] or 0
        per_file_total = totals["total_per_file_total"] or 0
        flaw_hit_detected = totals["total_flaw_hit_detected"] or 0
        flaw_hit_total = totals["total_flaw_hit_total"] or 0

        cwe_aware = None
        if cwe_matched_total > 0:
            cwe_aware = {
                "cwe_matched_tp": cwe_matched_tp,
                "cwe_matched_fp": cwe_matched_fp,
                "cwe_matched_total": cwe_matched_total,
                "cwe_matched_tp_rate_pct": round(cwe_matched_tp / cwe_matched_total * 100, 1) if cwe_matched_total else 0,
                "noise_total": total_noise,
                "noise_ratio_pct": round(total_noise / all_findings * 100, 1) if all_findings else 0,
                "per_file_detected": per_file_detected,
                "per_file_total": per_file_total,
                "per_file_rate_pct": round(per_file_detected / per_file_total * 100, 1) if per_file_total else 0,
                "flaw_hit_detected": flaw_hit_detected,
                "flaw_hit_total": flaw_hit_total,
                "flaw_hit_rate_pct": round(flaw_hit_detected / flaw_hit_total * 100, 1) if flaw_hit_total else 0,
            }

        result = {
            "summary": summary,
            "top_rules": top_rules,
            "per_cwe": per_cwe,
        }
        if cwe_aware:
            result["cwe_aware"] = cwe_aware

        return result

    def get_cwe_detail(self, run_id: str, cwe_id: str) -> dict | None:
        """Detailed breakdown for one CWE in a run."""
        # Normalize CWE ID
        needle = cwe_id.upper()
        if not needle.startswith("CWE-"):
            if needle.startswith("CWE"):
                needle = "CWE-" + needle[3:]
            elif needle.isdigit():
                needle = "CWE-" + needle

        with self._cursor() as cur:
            cur.execute("""
                SELECT s.*, m.*
                FROM cwe_scans s
                LEFT JOIN cwe_metrics m ON m.cwe_scan_id = s.id
                WHERE s.run_id = ? AND s.cwe_id = ?
            """, (run_id, needle))
            row = cur.fetchone()
            if not row:
                return None
            data = dict(row)
            scan_id = data["id"]

            # Per-rule breakdown
            cur.execute("""
                SELECT rule_id, tp_count, fp_count, flaw_line_count, is_cwe_matched
                FROM rule_cwe_breakdown
                WHERE cwe_scan_id = ?
                ORDER BY fp_count DESC
            """, (scan_id,))
            rules = [dict(r) for r in cur.fetchall()]

        tp = data.get("tp_count", 0) or 0
        fp = data.get("fp_count", 0) or 0
        total = tp + fp

        detail = {
            "cwe": data["cwe_dir_name"],
            "cwe_id": data["cwe_id"],
            "files_analyzed": data["file_count"],
            "run_name": run_id,
            "duration_s": data.get("duration_s"),
            "summary": {
                "total_violations": total,
                "tp": tp,
                "fp": fp,
                "tp_rate_pct": round(tp / total * 100, 1) if total else 0,
                "fp_rate_pct": round(fp / total * 100, 1) if total else 0,
                "flaw_lines_detected": data.get("flaw_lines_detected", 0) or 0,
                "flaw_lines_total": data.get("flaw_lines_total", 0) or 0,
                "flaw_detection_rate_pct": data.get("flaw_detection_rate_pct", 0) or 0,
            },
            "top_tp_rules": [r for r in rules if r["tp_count"] > 0],
            "top_fp_rules": [r for r in rules if r["fp_count"] > 0],
        }

        # CWE-aware metrics
        cwe_matched_tp = data.get("cwe_matched_tp", 0) or 0
        cwe_matched_fp = data.get("cwe_matched_fp", 0) or 0
        cwe_matched_total = cwe_matched_tp + cwe_matched_fp
        if cwe_matched_total > 0:
            detail["cwe_aware"] = {
                "cwe_matched_tp": cwe_matched_tp,
                "cwe_matched_fp": cwe_matched_fp,
                "cwe_matched_total": cwe_matched_total,
                "cwe_matched_tp_rate_pct": round(cwe_matched_tp / cwe_matched_total * 100, 1) if cwe_matched_total else 0,
                "noise_count": data.get("noise_count", 0) or 0,
                "noise_ratio_pct": data.get("noise_ratio", 0) or 0,
                "per_file_detected": data.get("per_file_detected", 0) or 0,
                "per_file_total": data.get("per_file_total", 0) or 0,
                "per_file_rate_pct": data.get("per_file_rate", 0) or 0,
                "flaw_hit_detected": data.get("flaw_hit_detected", 0) or 0,
                "flaw_hit_total": data.get("flaw_hit_total", 0) or 0,
                "flaw_hit_rate_pct": data.get("flaw_hit_rate", 0) or 0,
                "cwe_matched_tp_rules": [r for r in rules if r["is_cwe_matched"] and r["tp_count"] > 0],
                "cwe_matched_fp_rules": [r for r in rules if r["is_cwe_matched"] and r["fp_count"] > 0],
            }

        return detail

    def compare_runs(self, base_id: str, target_id: str) -> dict:
        """Compare two runs, returning deltas for overall, per-CWE, and per-rule."""
        base = self.get_run_summary(base_id)
        target = self.get_run_summary(target_id)

        if not base["summary"]["cwes_analyzed"] or not target["summary"]["cwes_analyzed"]:
            return {"error": "One or both runs have no analyzed CWEs."}

        bs, ts = base["summary"], target["summary"]

        summary = {
            "base_run": base_id,
            "target_run": target_id,
            "base": {
                "tp": bs["total_tp"], "fp": bs["total_fp"],
                "total": bs["total_violations"],
                "tp_rate_pct": bs["tp_rate_pct"],
                "cwes": bs["cwes_analyzed"],
                "cache_state": bs["cache_state"],
            },
            "target": {
                "tp": ts["total_tp"], "fp": ts["total_fp"],
                "total": ts["total_violations"],
                "tp_rate_pct": ts["tp_rate_pct"],
                "cwes": ts["cwes_analyzed"],
                "cache_state": ts["cache_state"],
            },
            "delta": {
                "tp": ts["total_tp"] - bs["total_tp"],
                "fp": ts["total_fp"] - bs["total_fp"],
                "total": ts["total_violations"] - bs["total_violations"],
                "tp_rate_pp": round(ts["tp_rate_pct"] - bs["tp_rate_pct"], 2),
            },
        }

        # Timing block — so a scan-time regression is visible in the standard
        # comparison, not just precision/recall. `analysis_s` (summed per-CWE
        # subprocess time) is parallelism-independent and the better axis for the
        # cost of analysis-depth changes; `wall_s` is real elapsed time and may
        # be absent for older/running runs. See task 202.
        b_an, t_an = bs.get("analysis_s"), ts.get("analysis_s")
        b_wall, t_wall = bs.get("wall_s"), ts.get("wall_s")
        summary["timing"] = {
            "base": {"analysis_s": b_an, "wall_s": b_wall, "jobs": bs.get("jobs")},
            "target": {"analysis_s": t_an, "wall_s": t_wall, "jobs": ts.get("jobs")},
            "delta": {
                "analysis_s": round(t_an - b_an, 1) if b_an is not None and t_an is not None else None,
                "analysis_pct": round((t_an - b_an) / b_an * 100, 1) if b_an else None,
                "wall_s": round(t_wall - b_wall, 1) if b_wall is not None and t_wall is not None else None,
            },
        }

        # Per-CWE deltas
        base_cwes = {c["cwe_id"]: c for c in base["per_cwe"]}
        target_cwes = {c["cwe_id"]: c for c in target["per_cwe"]}
        all_cwe_ids = sorted(set(base_cwes) | set(target_cwes))

        cwe_deltas = []
        for cid in all_cwe_ids:
            b = base_cwes.get(cid, {"tp_count": 0, "fp_count": 0, "tp_rate_pct": 0})
            t = target_cwes.get(cid, {"tp_count": 0, "fp_count": 0, "tp_rate_pct": 0})
            b_tp = b.get("tp_count", 0) or 0
            b_fp = b.get("fp_count", 0) or 0
            t_tp = t.get("tp_count", 0) or 0
            t_fp = t.get("fp_count", 0) or 0
            b_rate = b.get("tp_rate_pct", 0) or 0
            t_rate = t.get("tp_rate_pct", 0) or 0
            # Per-CWE wall time is parallelism-immune (each CWE is one sqc
            # subprocess), so its delta is the precise timing signal.
            b_dur = b.get("duration_s")
            t_dur = t.get("duration_s")
            delta_dur = (round(t_dur - b_dur, 1)
                         if b_dur is not None and t_dur is not None else None)
            cwe_deltas.append({
                "cwe_id": cid,
                "base_tp": b_tp, "base_fp": b_fp,
                "target_tp": t_tp, "target_fp": t_fp,
                "delta_tp": t_tp - b_tp, "delta_fp": t_fp - b_fp,
                "base_tp_pct": b_rate, "target_tp_pct": t_rate,
                "delta_tp_rate_pp": round(t_rate - b_rate, 2),
                "base_duration_s": b_dur, "target_duration_s": t_dur,
                "delta_duration_s": delta_dur,
            })
        cwe_deltas.sort(key=lambda x: x["delta_fp"])

        improvements = [d for d in cwe_deltas if d["delta_fp"] < 0][:15]
        regressions = sorted([d for d in cwe_deltas if d["delta_fp"] > 0],
                             key=lambda x: -x["delta_fp"])[:15]

        # CWEs whose scan time moved the most (either direction), so an
        # analysis-depth change shows up as a timing mover next to its FP win.
        timing_movers = sorted(
            (d for d in cwe_deltas if d["delta_duration_s"] is not None
             and abs(d["delta_duration_s"]) >= 1.0),
            key=lambda x: -abs(x["delta_duration_s"]),
        )[:10]

        # Per-rule deltas
        base_rules = {r["rule_id"]: r for r in base["top_rules"]}
        target_rules = {r["rule_id"]: r for r in target["top_rules"]}
        all_rule_ids = sorted(set(base_rules) | set(target_rules))

        rule_deltas = []
        for rid in all_rule_ids:
            b = base_rules.get(rid, {"tp": 0, "fp": 0})
            t = target_rules.get(rid, {"tp": 0, "fp": 0})
            rule_deltas.append({
                "rule": rid,
                "base_tp": b["tp"], "base_fp": b["fp"],
                "target_tp": t["tp"], "target_fp": t["fp"],
                "delta_tp": t["tp"] - b["tp"],
                "delta_fp": t["fp"] - b["fp"],
            })
        rule_deltas.sort(key=lambda x: x["delta_fp"])

        rule_improvements = [d for d in rule_deltas if d["delta_fp"] < 0][:10]
        rule_regressions = sorted([d for d in rule_deltas if d["delta_fp"] > 0],
                                  key=lambda x: -x["delta_fp"])[:10]

        result = {
            "summary": summary,
            "cwe_improvements": improvements,
            "cwe_regressions": regressions,
            "rule_improvements": rule_improvements,
            "rule_regressions": rule_regressions,
            "timing_movers": timing_movers,
            "all_cwe_deltas": cwe_deltas,
        }

        # CWE-aware comparison
        if base.get("cwe_aware") and target.get("cwe_aware"):
            ba, ta = base["cwe_aware"], target["cwe_aware"]
            result["cwe_aware"] = {
                "base": ba,
                "target": ta,
                "delta": {
                    "cwe_matched_tp": ta["cwe_matched_tp"] - ba["cwe_matched_tp"],
                    "cwe_matched_fp": ta["cwe_matched_fp"] - ba["cwe_matched_fp"],
                    "cwe_matched_tp_rate_pp": round(
                        ta["cwe_matched_tp_rate_pct"] - ba["cwe_matched_tp_rate_pct"], 2),
                    "per_file_rate_pp": round(
                        ta["per_file_rate_pct"] - ba["per_file_rate_pct"], 2),
                    "flaw_hit_rate_pp": round(
                        ta["flaw_hit_rate_pct"] - ba["flaw_hit_rate_pct"], 2),
                },
            }

        return result

    # ── Real-World CRUD ──────────────────────────────────────────────────

    def create_realworld_run(self, sqc_version: str, commit_sha: str = None,
                             scanned_at: str = None, hostname: str = None,
                             cpu_model: str = None, cpu_cores: int = None,
                             notes: str = None, run_id: str = None,
                             variant: str = None) -> int:
        """Insert a real-world run row and return its numeric id.

        `run_id` is the canonical identifier ("sqc-0.4.320-742e92a6-cdb") and
        `variant` the configuration it names ("cdb", or None for a default
        run). Pass the true SHA in `commit_sha` -- never the SHA with a variant
        suffix glued on, which is what this table used to store and what made
        an exact-SHA lookup skip half of an A/B pair.
        """
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO realworld_runs
                    (run_id, sqc_version, commit_sha, variant, scanned_at,
                     hostname, cpu_model, cpu_cores, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING id
            """, (run_id, sqc_version, commit_sha, variant, scanned_at,
                  hostname, cpu_model, cpu_cores, notes))
            return cur.fetchone()["id"]

    def insert_realworld_result(self, run_id: int, project: str, tool: str,
                                c_files: int = 0, loc: int = 0,
                                violation_count: int = 0,
                                duration_s: float = None,
                                codebase_commit: str = None) -> None:
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO realworld_results
                    (run_id, project, tool, c_files, loc, violation_count,
                     duration_s, codebase_commit)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (run_id, project, tool) DO UPDATE SET
                    c_files = excluded.c_files,
                    loc = excluded.loc,
                    violation_count = excluded.violation_count,
                    duration_s = excluded.duration_s,
                    codebase_commit = excluded.codebase_commit
            """, (run_id, project, tool, c_files, loc, violation_count,
                  duration_s, codebase_commit))

    def insert_realworld_violations(self, result_id: int,
                                      violations: list[dict]) -> None:
        """Bulk insert per-violation detail for a realworld result."""
        if not violations:
            return
        with self._cursor() as cur:
            self._insert_realworld_violations_cur(cur, result_id, violations)

    def _insert_realworld_violations_cur(self, cur, result_id: int,
                                          violations: list[dict]) -> None:
        """Same as `insert_realworld_violations`, but reuses a cursor already
        inside an open transaction (task 655) — lets `ingest_realworld_run`
        do its DELETE + result-row upsert + per-violation insert as one
        atomic unit instead of two separate transactions, which is what let
        two concurrent ingests of the same (run_id, project, tool) both see
        "nothing to delete yet" and each insert their own full violation set,
        doubling (or worse) the stored rows."""
        if not violations:
            return
        cur.executemany("""
            INSERT INTO realworld_violations
                (result_id, rule_id, file_path, line, column_num,
                 severity, message, suggestion, requires_manual_review)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [(result_id, v["rule_id"], v["file"], v["line"],
               v.get("column", 0), v.get("severity"),
               v.get("message"), v.get("suggestion"),
               1 if v.get("requires_manual_review") else 0)
              for v in violations])

    def ingest_realworld_run(self, version_dir: str, results_path: str,
                              machine: dict = None,
                              durations: dict[str, float] = None,
                              metrics: dict[str, dict] = None,
                              run_id: int = None,
                              only_projects: set = None) -> int:
        """Ingest a realworld run from JSON result files.

        Args:
            version_dir: dir name like 'sqc-0.3.26-9e8e8d3b'
            results_path: path to the directory containing JSON result files
            machine: optional dict with hostname, cpu_model, cpu_cores
            durations: optional dict mapping codebase name to elapsed seconds
            metrics: optional dict mapping codebase name to {c_files, loc}
            run_id: optional existing realworld_runs *numeric row id* to merge
                into instead of creating a row. Note this is not the same
                thing as the `run_id` TEXT column, which holds the canonical
                identifier ("sqc-0.4.320-742e92a6-cdb") and is set below from
                `version_dir`.
                of creating a new run row. Lets a later (more complete) sweep
                fill in projects a partial earlier ingest missed.
            only_projects: optional set of project names to restrict ingest to
                (the rest of the dir is left untouched). Used with run_id to
                merge just the missing projects.

        Per-project sqc rows are idempotent: any prior sqc row + its violations
        for (run_id, project) are dropped before re-insert, so re-ingest never
        duplicates findings or orphans violation rows (foreign_keys=ON forbids
        leaving the children behind).

        Returns:
            The realworld_runs row id.
        """
        import os
        from datetime import datetime, timezone

        # Parse version/commit/variant from dir name:
        # sqc-{version}-{sha}[-{variant}]. A SHA is hex, so the first "-" in
        # the third field can only start a variant suffix -- splitting it off
        # here is what keeps commit_sha a real SHA.
        parts = version_dir.split("-", 2)
        version = parts[1] if len(parts) > 1 else version_dir
        commit = parts[2] if len(parts) > 2 else None
        variant = None
        if commit and "-" in commit:
            commit, variant = commit.split("-", 1)

        machine = machine or {}
        durations = durations or {}
        metrics = metrics or {}
        if run_id is None:
            run_id = self.create_realworld_run(
                sqc_version=version,
                commit_sha=commit,
                scanned_at=datetime.now(timezone.utc).isoformat(),
                hostname=machine.get("hostname"),
                cpu_model=machine.get("cpu_model"),
                cpu_cores=machine.get("cpu_cores"),
                notes=f"ingested from {version_dir}",
                # create_realworld_run's `run_id` is the TEXT identifier
                # column; the numeric row id it returns is what this local
                # `run_id` becomes.
                run_id=version_dir,
                variant=variant,
            )

        results_dir = Path(results_path)
        for json_file in sorted(results_dir.glob("*.json")):
            # Skip sidecars that also end in .json (the scan-time commit sidecar
            # and the auto-score output) — they are not finding lists.
            if json_file.name.endswith((".meta.json", ".score.json")):
                continue
            # Parse filename: sqc-{project}-{version}-{sha}.json
            stem = json_file.stem
            # Extract project: between first tool name and version
            # e.g. "sqc-curl-0.3.26-9e8e8d3b" -> project="curl"
            name_parts = stem.split("-")
            if len(name_parts) >= 3:
                project = name_parts[1]
            else:
                continue
            if only_projects is not None and project not in only_projects:
                continue

            violations = json.load(open(json_file))
            violation_count = len(violations)

            # Count per-rule
            rule_counts = {}
            for v in violations:
                rid = v.get("rule_id", "unknown")
                rule_counts[rid] = rule_counts.get(rid, 0) + 1

            duration = durations.get(project)
            proj_metrics = metrics.get(project) or {}
            c_files = proj_metrics.get("c_files", 0) or 0
            loc = proj_metrics.get("loc", 0) or 0

            # Codebase commit: the scan-time sidecar is the ONLY source. There
            # used to be a fallback here that ran `git rev-parse --short HEAD`
            # against the live checkout; it was removed (2026-09-03) because it
            # answered a different question than the one asked. The checkout's
            # HEAD *now* is not the commit the run scanned -- a re-ingest of an
            # older directory, or any checkout that drifted between scan and
            # ingest (which corpus-check exists because they silently do),
            # would have the run attributed to a commit it never saw. Since
            # ground_truth is keyed on codebase_commit, that quietly moves
            # findings into or out of the precision/recall denominator with no
            # error anywhere -- strictly worse than not knowing.
            #
            # It also emitted the abbreviated form, so it was the surviving
            # producer of the format that aborted run 227's ingest against
            # sqc_bench's CHECK (codebase_commit ~ '^[0-9a-f]{40}$'). Making it
            # full-SHA would have fixed that symptom and kept the fabricated
            # provenance, which is the more expensive of the two bugs.
            #
            # NULL is the truthful answer, and score_realworld_run already
            # handles it: it warns "run has no codebase_commit recorded;
            # cannot match labels" and leaves the run unscored, so the run is
            # visibly unscoreable rather than confidently mis-scored.
            codebase_commit = None
            meta_file = json_file.with_name(json_file.stem + ".meta.json")
            if meta_file.exists():
                try:
                    codebase_commit = json.load(
                        open(meta_file)).get("codebase_commit")
                except (OSError, json.JSONDecodeError):
                    pass

            result_id = None
            with self._cursor() as cur:
                # Drop any prior sqc row's violations for this (run, project)
                # first, so a merge/re-ingest never duplicates or orphans
                # findings — the upsert below updates the parent row in place
                # (not delete+reinsert), so result_id stays stable across
                # re-ingests, but its old children must still be cleared.
                cur.execute("""
                    DELETE FROM realworld_violations
                    WHERE result_id IN (
                        SELECT id FROM realworld_results
                        WHERE run_id = ? AND project = ? AND tool = 'sqc')
                """, (run_id, project))
                cur.execute("""
                    INSERT INTO realworld_results
                        (run_id, project, tool, c_files, loc, violation_count,
                         duration_s, codebase_commit)
                    VALUES (?, ?, 'sqc', ?, ?, ?, ?, ?)
                    ON CONFLICT (run_id, project, tool) DO UPDATE SET
                        c_files = excluded.c_files,
                        loc = excluded.loc,
                        violation_count = excluded.violation_count,
                        duration_s = excluded.duration_s,
                        codebase_commit = excluded.codebase_commit
                    RETURNING id
                """, (run_id, project, c_files, loc, violation_count, duration,
                      codebase_commit))
                result_id = cur.fetchone()["id"]

                # Insert per-violation detail in the SAME transaction as the
                # delete+upsert above (task 655) -- keeps a re-ingest atomic
                # so a crash mid-ingest can't leave a result row with no
                # violations or a stale partial set.
                if result_id and violations:
                    self._insert_realworld_violations_cur(cur, result_id, violations)

        return run_id

    def get_realworld_rule_summary(self, run_id: int, project: str = None) -> list[dict]:
        """Get per-rule violation counts for a realworld run."""
        with self._cursor() as cur:
            if project:
                cur.execute("""
                    SELECT rv.rule_id, COUNT(*) as count
                    FROM realworld_violations rv
                    JOIN realworld_results rr ON rr.id = rv.result_id
                    WHERE rr.run_id = ? AND rr.project = ?
                    GROUP BY rv.rule_id
                    ORDER BY count DESC
                """, (run_id, project))
            else:
                cur.execute("""
                    SELECT rv.rule_id, COUNT(*) as count
                    FROM realworld_violations rv
                    JOIN realworld_results rr ON rr.id = rv.result_id
                    WHERE rr.run_id = ?
                    GROUP BY rv.rule_id
                    ORDER BY count DESC
                """, (run_id,))
            return [dict(r) for r in cur.fetchall()]

    def compare_realworld_runs(self, base_run_id: int, target_run_id: int,
                                project: str = None) -> dict:
        """Compare two realworld runs with per-rule deltas."""
        base_rules = {r["rule_id"]: r["count"]
                      for r in self.get_realworld_rule_summary(base_run_id, project)}
        target_rules = {r["rule_id"]: r["count"]
                        for r in self.get_realworld_rule_summary(target_run_id, project)}

        # Labeled totals per rule (from ground_truth), so a raw finding-count
        # swing that ISN'T reflected in the labeled/precision numbers is
        # visible without manually cross-referencing ground_truth by hand.
        # See task 423.
        target_labeled = {r["rule_id"]: r["labeled_total"]
                          for r in self.score_realworld_run(
                              target_run_id, only_project=project)
                          .get("per_rule", [])}

        all_rules = sorted(set(base_rules) | set(target_rules))
        deltas = []
        for rid in all_rules:
            b = base_rules.get(rid, 0)
            t = target_rules.get(rid, 0)
            if b != t:
                t_labeled = target_labeled.get(rid, 0)
                unlabeled_count = max(t - t_labeled, 0)
                deltas.append({
                    "rule_id": rid, "base": b, "target": t, "delta": t - b,
                    "target_labeled_total": t_labeled,
                    "target_unlabeled_count": unlabeled_count,
                    "target_unlabeled_fraction": (round(unlabeled_count / t, 3)
                                                   if t else None),
                })
        deltas.sort(key=lambda x: x["delta"])

        base_total = sum(base_rules.values())
        target_total = sum(target_rules.values())

        result = {
            "base_total": base_total,
            "target_total": target_total,
            "delta_total": target_total - base_total,
            "rule_deltas": deltas,
        }

        # Deltas are only meaningful if both runs scanned the same codebase
        # commits.  Warn when they verifiably differ.
        mismatches = []
        with self._cursor() as cur:
            cur.execute("""
                SELECT b.project, b.codebase_commit AS base_commit,
                       t.codebase_commit AS target_commit
                FROM realworld_results b
                JOIN realworld_results t
                  ON t.project = b.project AND t.tool = b.tool
                WHERE b.run_id = ? AND t.run_id = ?
                  AND b.codebase_commit IS NOT NULL
                  AND t.codebase_commit IS NOT NULL
                  AND b.codebase_commit != t.codebase_commit
            """, (base_run_id, target_run_id))
            mismatches = [dict(r) for r in cur.fetchall()]
        if mismatches:
            result["warnings"] = [
                f"{m['project']}: codebase commit changed between runs "
                f"({m['base_commit']} -> {m['target_commit']}); "
                "deltas are not comparable" for m in mismatches]

        return result

    def list_realworld_runs(self) -> list[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM realworld_runs ORDER BY id DESC")
            return [dict(r) for r in cur.fetchall()]

    def list_realworld_run_timings(self, limit: int = 10, tool: str = "sqc") -> list[dict]:
        """Runtime for the most recent real-world runs, newest first.

        `total_duration_s` sums each project's `duration_s` for `tool` within
        the run (projects scan sequentially, so this is also the run's
        approximate wall-clock time, unlike Juliet's parallel-CWE analysis_s).
        """
        with self._cursor() as cur:
            query = "SELECT * FROM realworld_runs ORDER BY id DESC"
            if limit and limit > 0:
                query += " LIMIT ?"
                cur.execute(query, (limit,))
            else:
                cur.execute(query)
            runs = [dict(r) for r in cur.fetchall()]

            timings = []
            for run in runs:
                cur.execute("""
                    SELECT project, duration_s FROM realworld_results
                    WHERE run_id = ? AND tool = ?
                    ORDER BY project
                """, (run["id"], tool))
                per_project = [dict(r) for r in cur.fetchall()]
                total = sum(p["duration_s"] for p in per_project if p["duration_s"] is not None)
                timings.append({
                    "run_id": run["id"],
                    "sqc_version": run["sqc_version"],
                    "commit_sha": run.get("commit_sha"),
                    "scanned_at": run.get("scanned_at"),
                    "notes": run.get("notes"),
                    "tool": tool,
                    "project_count": len(per_project),
                    "total_duration_s": round(total, 1) if per_project else None,
                    "per_project_s": {p["project"]: p["duration_s"] for p in per_project},
                })
            return timings

    def get_realworld_results(self, run_id: int) -> list[dict]:
        with self._cursor() as cur:
            cur.execute("""
                SELECT * FROM realworld_results
                WHERE run_id = ? ORDER BY project, tool
            """, (run_id,))
            return [dict(r) for r in cur.fetchall()]

    def get_realworld_project_history(self, project: str) -> list[dict]:
        """Get violation count history for a project across sqc versions."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT r.sqc_version, r.notes, rr.tool, rr.violation_count, rr.c_files, rr.loc
                FROM realworld_results rr
                JOIN realworld_runs r ON r.id = rr.run_id
                WHERE rr.project = ?
                ORDER BY r.sqc_version, rr.tool
            """, (project,))
            return [dict(r) for r in cur.fetchall()]

    def resolve_realworld_run(self, identifier: str) -> int | None:
        """Resolve 'latest', version string, or run ID to a realworld_runs row id."""
        ident = identifier.strip()
        with self._cursor() as cur:
            if ident.lower() in ("latest", "current"):
                cur.execute("SELECT id FROM realworld_runs ORDER BY id DESC LIMIT 1")
                row = cur.fetchone()
                return row["id"] if row else None

            # Exact ID match. A purely-numeric identifier means "this row id"
            # and nothing else -- return here (found or not) rather than
            # falling through to the version/commit/notes fallbacks below,
            # which can otherwise silently match an unrelated run whose
            # version/commit/notes happens to contain that numeral as a
            # substring (e.g. "208" spuriously matching v0.4.208's run when
            # id 208 doesn't exist).
            try:
                int_id = int(ident)
            except ValueError:
                int_id = None
            if int_id is not None:
                cur.execute("SELECT id FROM realworld_runs WHERE id = ?", (int_id,))
                row = cur.fetchone()
                return row["id"] if row else None

            # Exact run identifier (e.g. "sqc-0.4.320-742e92a6-cdb"). First
            # of the string matches, so an id that is a strict prefix of
            # another ("...-742e92a6" vs "...-742e92a6-cdb") still addresses
            # its own run rather than the longer one.
            cur.execute(
                "SELECT id FROM realworld_runs WHERE run_id = ?", (ident,))
            row = cur.fetchone()
            if row:
                return row["id"]

            # Version match (e.g. "0.3.28")
            cur.execute("""
                SELECT id FROM realworld_runs
                WHERE sqc_version = ?
                ORDER BY variant IS NOT NULL, id DESC LIMIT 1
            """, (ident,))
            row = cur.fetchone()
            if row:
                return row["id"]

            # Commit SHA match. Now that a variant run stores the same SHA
            # as the default run it was paired with, this is ambiguous by
            # construction -- resolve it to the DEFAULT run, since a variant
            # is always reachable by its own explicit run_id.
            cur.execute("""
                SELECT id FROM realworld_runs
                WHERE commit_sha = ?
                ORDER BY variant IS NOT NULL, id DESC LIMIT 1
            """, (ident,))
            row = cur.fetchone()
            if row:
                return row["id"]

            # Notes match (e.g. "sqc-0.3.28-ae46ae3c"). Anchored to the END
            # of the notes first, because a plain substring match cannot
            # address a run whose id is a prefix of another's: notes read
            # "ingested from <run_id>", so "%sqc-0.4.320-742e92a6%" matches
            # both that run and its "-cdb" sibling, and ORDER BY id DESC then
            # silently returns the sibling. That defeats the whole point of
            # the compile-database run suffix (bench/config.py's
            # apply_run_suffix), which exists so a with/without pair on one
            # sqc build stays two addressable runs.
            cur.execute("""
                SELECT id FROM realworld_runs
                WHERE notes LIKE ?
                ORDER BY id DESC LIMIT 1
            """, (f"%{ident}",))
            row = cur.fetchone()
            if row:
                return row["id"]

            # Fall back to an unanchored substring match.
            cur.execute("""
                SELECT id FROM realworld_runs
                WHERE notes LIKE ?
                ORDER BY id DESC LIMIT 1
            """, (f"%{ident}%",))
            row = cur.fetchone()
            return row["id"] if row else None

    def get_realworld_run(self, run_id: int) -> dict | None:
        """Get a single realworld run by ID."""
        with self._cursor() as cur:
            cur.execute("SELECT * FROM realworld_runs WHERE id = ?", (run_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_realworld_rule_trend(self, rule_id: str,
                                  project: str = None) -> list[dict]:
        """Get a rule's violation count across all realworld runs.

        Returns rows sorted by version with: sqc_version, run_id,
        project, count. If project is given, filter to that project only.
        """
        with self._cursor() as cur:
            if project:
                cur.execute("""
                    SELECT r.sqc_version, r.id as run_id, rr.project,
                           COUNT(*) as count
                    FROM realworld_violations rv
                    JOIN realworld_results rr ON rr.id = rv.result_id
                    JOIN realworld_runs r ON r.id = rr.run_id
                    WHERE rv.rule_id = ? AND rr.project = ?
                    GROUP BY r.id, rr.project
                    ORDER BY r.id
                """, (rule_id, project))
            else:
                cur.execute("""
                    SELECT r.sqc_version, r.id as run_id, rr.project,
                           COUNT(*) as count
                    FROM realworld_violations rv
                    JOIN realworld_results rr ON rr.id = rv.result_id
                    JOIN realworld_runs r ON r.id = rr.run_id
                    WHERE rv.rule_id = ?
                    GROUP BY r.id, rr.project
                    ORDER BY r.id, rr.project
                """, (rule_id,))
            return [dict(r) for r in cur.fetchall()]

    def get_realworld_run_summary(self, run_id: int) -> dict:
        """Get full summary for a realworld run including per-rule breakdown.

        Returns dict with: run info, per-project results, per-rule counts.
        """
        run = self.get_realworld_run(run_id)
        if not run:
            return {"error": f"Run {run_id} not found"}

        results = self.get_realworld_results(run_id)
        rule_summary = self.get_realworld_rule_summary(run_id)

        # Per-project rule breakdown
        per_project_rules = {}
        with self._cursor() as cur:
            for result in results:
                if result["tool"] != "sqc":
                    continue
                cur.execute("""
                    SELECT rv.rule_id, COUNT(*) as count
                    FROM realworld_violations rv
                    WHERE rv.result_id = ?
                    GROUP BY rv.rule_id
                    ORDER BY count DESC
                """, (result["id"],))
                per_project_rules[result["project"]] = [
                    dict(r) for r in cur.fetchall()
                ]

        total_violations = sum(r["violation_count"] for r in results
                               if r["tool"] == "sqc")

        return {
            "run": run,
            "total_violations": total_violations,
            "projects": results,
            "rule_summary": rule_summary,
            "per_project_rules": per_project_rules,
        }

    def get_realworld_dashboard(self, run_id: int,
                                base_run_id: int | None = None,
                                top_n: int = 25) -> dict:
        """Get a dashboard view of realworld results: top rules, per-project, deltas.

        Args:
            run_id: The target run to display.
            base_run_id: Optional base run to compute deltas against.
            top_n: Number of top rules to show (default 25).

        Returns dict with: run info, top_rules (with optional deltas),
        per_project summaries, and timing data.
        """
        run = self.get_realworld_run(run_id)
        if not run:
            return {"error": f"Run {run_id} not found"}

        results = self.get_realworld_results(run_id)
        sqc_results = [r for r in results if r["tool"] == "sqc"]
        rule_summary = self.get_realworld_rule_summary(run_id)
        total_violations = sum(r["violation_count"] for r in sqc_results)

        # Per-project summaries
        per_project = []
        for r in sqc_results:
            proj_rules = self.get_realworld_rule_summary(run_id, r["project"])
            entry = {
                "project": r["project"],
                "violation_count": r["violation_count"],
            }
            if r.get("duration_s") is not None:
                entry["duration_s"] = r["duration_s"]
            entry["top_rules"] = proj_rules[:10]
            per_project.append(entry)

        # Top rules with optional deltas
        top_rules = []
        base_rules = {}
        if base_run_id:
            base_rules = {r["rule_id"]: r["count"]
                          for r in self.get_realworld_rule_summary(base_run_id)}

        for r in rule_summary[:top_n]:
            entry = {"rule_id": r["rule_id"], "count": r["count"]}
            if base_rules:
                base_count = base_rules.get(r["rule_id"], 0)
                entry["base_count"] = base_count
                entry["delta"] = r["count"] - base_count
            top_rules.append(entry)

        # Check for rules that disappeared (were in base but not in target top)
        if base_rules:
            target_rule_ids = {r["rule_id"] for r in rule_summary}
            for rule_id, base_count in sorted(base_rules.items(),
                                               key=lambda x: -x[1]):
                if rule_id not in target_rule_ids and base_count > 0:
                    top_rules.append({
                        "rule_id": rule_id,
                        "count": 0,
                        "base_count": base_count,
                        "delta": -base_count,
                    })

        dashboard = {
            "run": run,
            "total_violations": total_violations,
            "top_rules": top_rules,
            "per_project": per_project,
        }

        if base_run_id:
            base_run = self.get_realworld_run(base_run_id)
            base_total = sum(r["violation_count"]
                             for r in self.get_realworld_results(base_run_id)
                             if r["tool"] == "sqc")
            dashboard["base_run"] = base_run
            dashboard["base_total"] = base_total
            dashboard["total_delta"] = total_violations - base_total

        return dashboard

    # ── Ground Truth (real-world TP/FP oracle) ───────────────────────────

    @staticmethod
    def project_relpath(project: str, file_path: str) -> str:
        """Normalize an absolute scan path to a project-relative path.

        realworld_violations store machine-specific absolute paths like
        ``/home/brandon/toolchain/curl/lib/doh.c``; ground-truth labels are
        keyed on the portable ``lib/doh.c`` form so they survive a move of
        the checkout root. Strips everything up to and including the FIRST
        ``/<project>/`` segment; returns the input unchanged if absent.

        The first, not the last (task 762). This used ``rfind`` while
        documenting ``first``, and the two differ exactly when a checkout
        holds a subdirectory named after the project -- which four of the
        nine corpora in ``data/benchmark_repos.json`` do: mosquitto's
        ``include/mosquitto/``, curl's ``include/curl/``, sqlite's
        ``ext/jni/src/org/sqlite/``, and 57 ``sel4/`` directories under
        sel4's ``libsel4/``. Beneath one of those, a path lost its whole
        prefix and ``.../mosquitto/include/mosquitto/libmosquitto.h``
        normalized to the bare basename ``libmosquitto.h``.

        It is invisible to precision and recall -- findings and labels both
        come through here, so the two sides agree and every key matches.
        What it breaks is anything that resolves a label to a real file:
        ``corpus.in_scope`` is handed this path and no glob matches a bare
        basename, so such a finding reads as out of scope and
        ``realworld-unlabeled`` never offers it. It is a collision hazard
        too -- two files sharing a basename, one under the project-named
        directory, collapse to ONE key and merge two different files' labels
        with no error. sel4 is the loaded gun: 155 headers under a ``sel4/``
        directory, 53 of them named ``constants.h``.
        """
        marker = f"/{project}/"
        idx = file_path.find(marker)
        if idx != -1:
            return file_path[idx + len(marker):]
        return file_path

    def insert_ground_truth_labels(self, labels: list[dict],
                                   on_conflict: str = "ignore") -> dict:
        """Insert/append ground-truth labels.

        Each label dict needs: project, codebase_commit, file_path (relative),
        line, rule_id, verdict. Optional: adjudicator, reason, source,
        adjudicated_at (defaults to now), provenance, confidence.

        verdict is 'TP' | 'FP' | 'uncertain' | 'FN'. An 'FN' (false negative)
        is a real bug sqc did NOT flag, found by reading the file; it has no
        matching sqc finding, so it never affects precision but counts as a
        known real bug for recall (the run detects it only once sqc improves
        enough to emit a finding at that line+rule). For FN rows, `provenance`
        records corroboration (e.g. 'juliet:CWE-476', 'cross:curl', 'cve:...',
        'uncorroborated') and `confidence` is 'high'|'medium'|'low'.

        on_conflict:
          'ignore' — keep the existing label for a key (append-only seeding).
          'update' — overwrite verdict/reason/adjudicator/source/date
                     (re-adjudication of a previously labeled finding).

        Returns {'inserted': n, 'updated': n, 'skipped': n}.
        """
        from datetime import datetime, timezone
        if not labels:
            return {"inserted": 0, "updated": 0, "skipped": 0}
        now = datetime.now(timezone.utc).isoformat()
        inserted = updated = skipped = 0
        with self._cursor() as cur:
            for lbl in labels:
                key = (lbl["project"], lbl["codebase_commit"],
                       lbl["file_path"], int(lbl["line"]), lbl["rule_id"])
                cur.execute("""
                    SELECT id, verdict FROM ground_truth
                    WHERE project=? AND codebase_commit=? AND file_path=?
                      AND line=? AND rule_id=?
                """, key)
                existing = cur.fetchone()
                vals = (lbl["verdict"], lbl.get("adjudicator"),
                        lbl.get("reason"), lbl.get("source"),
                        lbl.get("adjudicated_at") or now,
                        lbl.get("provenance"), lbl.get("confidence"))
                if existing is None:
                    cur.execute("""
                        INSERT INTO ground_truth
                            (project, codebase_commit, file_path, line, rule_id,
                             verdict, adjudicator, reason, source, adjudicated_at,
                             provenance, confidence)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, key + vals)
                    inserted += 1
                elif on_conflict == "update":
                    cur.execute("""
                        UPDATE ground_truth
                        SET verdict=?, adjudicator=?, reason=?, source=?,
                            adjudicated_at=?, provenance=?, confidence=?
                        WHERE id=?
                    """, vals + (existing["id"],))
                    updated += 1
                else:
                    skipped += 1
        return {"inserted": inserted, "updated": updated, "skipped": skipped}

    def get_ground_truth_labels(self, project: str = None,
                                codebase_commit: str = None) -> list[dict]:
        """Return ground-truth labels, optionally filtered by project/commit."""
        clauses, params = [], []
        if project:
            clauses.append("project = ?")
            params.append(project)
        if codebase_commit:
            clauses.append("codebase_commit = ?")
            params.append(codebase_commit)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._cursor() as cur:
            cur.execute(f"SELECT * FROM ground_truth {where} "
                        "ORDER BY project, rule_id, file_path, line", params)
            return [dict(r) for r in cur.fetchall()]

    def sample_calibration_batch(self, n: int = 180, seed: int = None,
                                 per_stratum_cap: int = 12,
                                 exclude_adjudicators: tuple = ("manual",)
                                 ) -> list[dict]:
        """Task 637: a stratified, BLIND sample of already-labeled ground_truth
        rows for a second, independent adjudicator to re-verdict.

        Strata are (project, rule_id) pairs among non-manual-adjudicated rows
        (default excludes 'manual' -- the point is measuring the Claude
        labeler against a human, so the human's own prior manual labels are
        not eligible re-adjudication targets). Sampling takes the highest-
        volume strata first (proportional coverage of where the oracle's
        mass actually is), capped per stratum so one mega-bucket (e.g.
        hostap/DCL13-C at 4,873 rows) can't crowd out the rest, then samples
        within each stratum with `seed` for reproducibility.

        Returns rows WITHOUT verdict/reason/adjudicator -- those live only in
        ground_truth until insert_calibration_labels() snapshots them
        alongside the new verdict, so nothing here leaks the label being
        re-judged. Each row carries the opaque `gt_id` needed to import a
        verdict back with insert_calibration_labels().
        """
        import random
        rng = random.Random(seed)
        excl = ",".join("?" for _ in exclude_adjudicators)
        with self._cursor() as cur:
            cur.execute(f"""
                SELECT project, rule_id, COUNT(*) c FROM ground_truth
                WHERE adjudicator NOT IN ({excl}) OR adjudicator IS NULL
                GROUP BY project, rule_id
                ORDER BY c DESC
            """, exclude_adjudicators)
            strata = [dict(r) for r in cur.fetchall()]

            picked = []
            for s in strata:
                if len(picked) >= n:
                    break
                cur.execute(f"""
                    SELECT id, project, codebase_commit, file_path, line,
                           rule_id
                    FROM ground_truth
                    WHERE project = ? AND rule_id = ?
                      AND (adjudicator NOT IN ({excl}) OR adjudicator IS NULL)
                """, (s["project"], s["rule_id"], *exclude_adjudicators))
                rows = [dict(r) for r in cur.fetchall()]
                take = min(per_stratum_cap, len(rows), n - len(picked))
                picked.extend(rng.sample(rows, take))
        rng.shuffle(picked)
        for r in picked:
            r["gt_id"] = r.pop("id")
            r["message"] = self._finding_message(
                r["project"], r["file_path"], r["line"], r["rule_id"])
        return picked

    def _finding_message(self, project: str, file_path: str, line: int,
                         rule_id: str) -> str:
        """Best-effort sqc message text for a (project, file_path, line,
        rule_id) triple, from the most recent real-world run that has it.
        Cosmetic context for a calibration reviewer only -- returns None if
        no run currently carries this finding (e.g. a since-fixed rule)."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT rv.message
                FROM realworld_violations rv
                JOIN realworld_results rr ON rr.id = rv.result_id
                WHERE rr.project = ? AND rr.tool = 'sqc'
                  AND rv.rule_id = ? AND rv.line = ?
                  AND rv.file_path LIKE ?
                ORDER BY rr.id DESC LIMIT 1
            """, (project, rule_id, line, f"%/{file_path}"))
            row = cur.fetchone()
            return row["message"] if row else None

    def insert_calibration_labels(self, labels: list[dict]) -> dict:
        """Insert second-round verdicts from a calibration batch.

        Each label needs: gt_id, verdict, adjudicator. Optional: reason,
        source, adjudicated_at (defaults to now). original_verdict/
        original_adjudicator are snapshotted from ground_truth at insert
        time, not read live later, so a subsequent re-adjudication of the
        ground_truth row can't retroactively change what this round is
        scored against. Skips (does not overwrite) an existing
        (gt_id, adjudicator) pair.
        """
        from datetime import datetime, timezone
        if not labels:
            return {"inserted": 0, "skipped": 0, "missing_gt": 0}
        now = datetime.now(timezone.utc).isoformat()
        inserted = skipped = missing_gt = 0
        with self._cursor() as cur:
            for lbl in labels:
                cur.execute("""
                    SELECT project, codebase_commit, file_path, line,
                           rule_id, verdict, adjudicator
                    FROM ground_truth WHERE id = ?
                """, (lbl["gt_id"],))
                gt = cur.fetchone()
                if gt is None:
                    missing_gt += 1
                    continue
                cur.execute("""
                    SELECT 1 FROM calibration_labels
                    WHERE gt_id = ? AND adjudicator = ?
                """, (lbl["gt_id"], lbl["adjudicator"]))
                if cur.fetchone() is not None:
                    skipped += 1
                    continue
                cur.execute("""
                    INSERT INTO calibration_labels
                        (gt_id, project, codebase_commit, file_path, line,
                         rule_id, verdict, adjudicator, reason, source,
                         adjudicated_at, original_verdict, original_adjudicator)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (lbl["gt_id"], gt["project"], gt["codebase_commit"],
                      gt["file_path"], gt["line"], gt["rule_id"],
                      lbl["verdict"], lbl["adjudicator"], lbl.get("reason"),
                      lbl.get("source"), lbl.get("adjudicated_at") or now,
                      gt["verdict"], gt["adjudicator"]))
                inserted += 1
        return {"inserted": inserted, "skipped": skipped,
                "missing_gt": missing_gt}

    def calibration_agreement_report(self) -> dict:
        """Overall + per-rule Claude-vs-human agreement from calibration_labels.

        Compares each row's `verdict` (the calibration round's fresh,
        blind re-adjudication) against its snapshotted `original_verdict`
        (what ground_truth said when the row was sampled). Reports raw
        agreement plus a confusion breakdown, per rule and overall -- see
        task 637: this is the only measurement anywhere of whether the
        94.6%-Claude-labeled oracle is trustworthy.
        """
        with self._cursor() as cur:
            cur.execute("""
                SELECT rule_id, verdict, original_verdict
                FROM calibration_labels
            """)
            rows = [dict(r) for r in cur.fetchall()]
        if not rows:
            return {"n": 0, "overall_agreement_pct": None, "by_rule": [],
                     "confusion": {}}

        def agreement(rs):
            n = len(rs)
            agree = sum(1 for r in rs if r["verdict"] == r["original_verdict"])
            return n, agree, (100.0 * agree / n if n else None)

        confusion = {}
        for r in rows:
            key = (r["original_verdict"], r["verdict"])
            confusion[key] = confusion.get(key, 0) + 1

        by_rule = {}
        for r in rows:
            by_rule.setdefault(r["rule_id"], []).append(r)
        by_rule_report = []
        for rule_id, rs in sorted(by_rule.items(),
                                  key=lambda kv: -len(kv[1])):
            n, agree, pct = agreement(rs)
            by_rule_report.append({
                "rule_id": rule_id, "n": n, "agree": agree,
                "agreement_pct": pct,
            })

        n, agree, pct = agreement(rows)
        return {
            "n": n, "agree": agree, "overall_agreement_pct": pct,
            "by_rule": by_rule_report,
            "confusion": {f"{k[0]}->{k[1]}": v for k, v in confusion.items()},
        }

    def ground_truth_coverage(self) -> list[dict]:
        """Per-(project, commit, rule) label counts for a quick inventory."""
        with self._cursor() as cur:
            cur.execute("""
                SELECT project, codebase_commit, rule_id,
                       SUM(verdict='TP') AS tp,
                       SUM(verdict='FP') AS fp,
                       SUM(verdict='uncertain') AS uncertain,
                       COUNT(*) AS total
                FROM ground_truth
                GROUP BY project, codebase_commit, rule_id
                ORDER BY project, rule_id
            """)
            return [dict(r) for r in cur.fetchall()]

    def _run_violation_keys(self, run_id: int) -> dict:
        """Distinct (project, relpath, line, rule_id) keys a run produced.

        Returns {project: {(relpath, line, rule_id), ...}} for tool='sqc'.
        """
        keys: dict[str, set] = {}
        with self._cursor() as cur:
            cur.execute("""
                SELECT rr.project, rv.rule_id, rv.file_path, rv.line
                FROM realworld_violations rv
                JOIN realworld_results rr ON rr.id = rv.result_id
                WHERE rr.run_id = ? AND rr.tool = 'sqc'
            """, (run_id,))
            for r in cur.fetchall():
                rel = self.project_relpath(r["project"], r["file_path"])
                keys.setdefault(r["project"], set()).add(
                    (rel, r["line"], r["rule_id"]))
        return keys

    def score_realworld_run(self, run_id: int,
                            restrict_files: dict | None = None,
                            only_project: str | None = None) -> dict:
        """Measure precision/recall of a run against the ground-truth oracle.

        Joins the run's findings to ground_truth labels for the *same*
        codebase_commit per project. Precision is over the labeled subset of
        the run's findings; recall is over all known real-bug labels (verdict
        TP or FN) for the matching commit — a known true bug that is not
        flagged (a standing FN, or a TP that regressed) drops recall.

        verdict='FN' rows are real bugs sqc missed: they have no matching
        finding, so they never inflate precision, but they sit in the recall
        denominator and only count as detected once a (better) sqc run emits a
        finding at that line+rule.

        restrict_files: optional {project: set(relpath)} to score only labels
        and findings within those files (used by the audited-file corpus). When
        None, scores the whole labeled corpus (legacy behavior).

        only_project: optional project name to scope scoring to a single
        project (e.g. when comparing one codebase's rule deltas against
        ground_truth rather than the whole multi-project run).

        The returned `overall` reports label coverage on BOTH bases rather
        than leaving the ratio to callers: `label_coverage_pct` over every
        finding the run emitted (`run_findings`, the basis the published docs
        cite), and `label_coverage_pct_scored` over only the findings that had
        an oracle to be measured against (`run_findings_scored`). Computing it
        here is deliberate -- the two denominators differ whenever a run
        covers a project with no labels at its commit, and a hand-rolled
        `labeled_total / run_findings` at the call site silently mixes them.
        """
        run = self.get_realworld_run(run_id)
        if not run:
            return {"error": f"Run {run_id} not found"}

        results = [r for r in self.get_realworld_results(run_id)
                   if r["tool"] == "sqc"
                   and (only_project is None or r["project"] == only_project)]
        run_keys = self._run_violation_keys(run_id)
        if only_project is not None:
            run_keys = {proj: keys for proj, keys in run_keys.items()
                        if proj == only_project}
        if restrict_files is not None:
            run_keys = {
                proj: {k for k in keys
                       if k[0] in restrict_files.get(proj, set())}
                for proj, keys in run_keys.items()}

        warnings = []
        # Projects this run could not score AT ALL because no codebase_commit
        # was recorded -- a data defect, not a normal state, and distinct from
        # "scored, but nothing was labeled at that commit". Kept as its own
        # list rather than another free-text warning so a caller can act on it:
        # the run's aggregate silently excludes these projects, and a footnote
        # under a complete-looking table is not enough signal for that.
        #
        # Shape matches benchmarking_db's scorer exactly, and deliberately:
        # `unscoreable` is list[dict] carrying the detail, `unscoreable_projects`
        # is list[str] of names only. Their `_projects` suffix means "names"
        # throughout (basis.scored_projects / unscored_projects), and
        # render_docs' guard is shared by both repos' publishing paths, so one
        # convention has to win. Theirs did: it predates this, it is applied
        # consistently, and it is documented in their score_realworld_run
        # docstring. This field emitted list[dict] under the `_projects` name
        # for one day (2026-09-03) and crashed their caller with a TypeError --
        # a shape mismatch that `.get` cannot catch, since the field was
        # present and wrongly shaped rather than absent.
        unscoreable = []
        # rule_id -> aggregated counters
        rules: dict[str, dict] = {}
        projects = []
        # Findings from projects this run could actually score: a matching
        # codebase_commit AND at least one ground-truth label at it. Always
        # <= the raw total; the gap is findings that had no oracle to be
        # measured against. Same definition as benchmarking_db's task-708
        # `_scored` keys -- the two must not drift, since bench/render_docs.py
        # consumes whichever dict its caller supplies.
        scored_run_findings = 0

        def bump(rid):
            return rules.setdefault(rid, {
                "tp": 0, "fp": 0, "uncertain": 0,
                "tp_labels": 0, "tp_detected": 0, "run_findings": 0})

        for res in results:
            project = res["project"]
            commit = res.get("codebase_commit")
            present = run_keys.get(project, set())
            run_finding_count = len(present)
            if not commit:
                unscoreable.append({
                    "project": project,
                    "reason": "no codebase_commit recorded",
                    "excluded_findings": run_finding_count,
                })
                warnings.append(
                    f"{project}: run has no codebase_commit recorded; "
                    f"cannot match labels ({run_finding_count} findings "
                    "excluded from every figure below)")
                continue
            labels = self.get_ground_truth_labels(project, commit)
            if restrict_files is not None:
                allowed = restrict_files.get(project, set())
                labels = [l for l in labels if l["file_path"] in allowed]
            if not labels:
                warnings.append(
                    f"{project}@{commit}: no ground-truth labels for this "
                    f"commit ({run_finding_count} findings unscored)")
                projects.append({"project": project, "codebase_commit": commit,
                                 "labels": 0, "run_findings": run_finding_count,
                                 "tp": 0, "fp": 0, "uncertain": 0})
                continue

            scored_run_findings += run_finding_count
            p_tp = p_fp = p_unc = p_tp_labels = p_tp_detected = 0
            for lbl in labels:
                rid = lbl["rule_id"]
                r = bump(rid)
                key = (lbl["file_path"], lbl["line"], rid)
                in_run = key in present
                # TP and FN are both real bugs: they form the recall denominator
                # (known real bugs) and are "detected" only when this run emits
                # a finding at that key.
                is_real = lbl["verdict"] in ("TP", "FN")
                if is_real:
                    r["tp_labels"] += 1
                    p_tp_labels += 1
                    if in_run:
                        r["tp_detected"] += 1
                        p_tp_detected += 1
                if not in_run:
                    continue
                # finding present in this run AND labeled -> counts for precision
                if is_real:
                    r["tp"] += 1; p_tp += 1
                elif lbl["verdict"] == "FP":
                    r["fp"] += 1; p_fp += 1
                else:
                    r["uncertain"] += 1; p_unc += 1

            projects.append({
                "project": project, "codebase_commit": commit,
                "labels": len(labels), "run_findings": run_finding_count,
                "tp": p_tp, "fp": p_fp, "uncertain": p_unc,
                "tp_labels": p_tp_labels, "tp_detected": p_tp_detected,
            })

        # Per-rule precision/recall, attach run finding totals
        rule_run_counts: dict[str, int] = {}
        for project, keyset in run_keys.items():
            for (_rel, _line, rid) in keyset:
                rule_run_counts[rid] = rule_run_counts.get(rid, 0) + 1

        per_rule = []
        tot_tp = tot_fp = tot_unc = tot_tp_labels = tot_tp_detected = 0
        for rid, r in sorted(rules.items()):
            denom = r["tp"] + r["fp"]
            prec = round(r["tp"] / denom * 100, 1) if denom else None
            rec = (round(r["tp_detected"] / r["tp_labels"] * 100, 1)
                   if r["tp_labels"] else None)
            run_findings = rule_run_counts.get(rid, 0)
            labeled_total = r["tp"] + r["fp"] + r["uncertain"]
            unlabeled_count = max(run_findings - labeled_total, 0)
            unlabeled_fraction = (round(unlabeled_count / run_findings, 3)
                                   if run_findings else None)
            per_rule.append({
                "rule_id": rid,
                "labeled_tp": r["tp"], "labeled_fp": r["fp"],
                "labeled_uncertain": r["uncertain"],
                "labeled_total": labeled_total,
                "precision_pct": prec,
                "tp_labels": r["tp_labels"], "tp_detected": r["tp_detected"],
                "recall_pct": rec,
                "run_findings": run_findings,
                "unlabeled_count": unlabeled_count,
                "unlabeled_fraction": unlabeled_fraction,
            })
            tot_tp += r["tp"]; tot_fp += r["fp"]; tot_unc += r["uncertain"]
            tot_tp_labels += r["tp_labels"]; tot_tp_detected += r["tp_detected"]

        denom = tot_tp + tot_fp
        overall_run_findings = sum(len(s) for s in run_keys.values())
        overall_labeled_total = tot_tp + tot_fp + tot_unc
        overall_unlabeled_count = max(overall_run_findings - overall_labeled_total, 0)
        overall = {
            "labeled_tp": tot_tp, "labeled_fp": tot_fp,
            "labeled_uncertain": tot_unc,
            "labeled_total": overall_labeled_total,
            "precision_pct": round(tot_tp / denom * 100, 1) if denom else None,
            "tp_labels": tot_tp_labels, "tp_detected": tot_tp_detected,
            "recall_pct": (round(tot_tp_detected / tot_tp_labels * 100, 1)
                           if tot_tp_labels else None),
            "run_findings": overall_run_findings,
            "unlabeled_count": overall_unlabeled_count,
            "unlabeled_fraction": (round(overall_unlabeled_count / overall_run_findings, 3)
                                   if overall_run_findings else None),
            # RAW vs SCORED basis, mirroring benchmarking_db (task 708) so a
            # caller handed either dict reads the same key names with the same
            # meaning. Unsuffixed finding counts stay RAW -- every finding the
            # run emitted, including from projects with no commit or no labels
            # at it -- so callers predating this keep the meaning they had.
            #
            # `labeled_total` is necessarily a scored-basis numerator (only a
            # scoreable project can contribute a label), so dividing it by the
            # raw `run_findings` mixes bases. Both ratios are precomputed here
            # rather than left to callers, which is how that mix kept getting
            # rebuilt by hand at the call site: `label_coverage_pct` answers
            # "how much of this run has been adjudicated at all" (the figure
            # the published docs cite), `label_coverage_pct_scored` answers
            # "within the corpus that has an oracle, how much is labeled".
            # They diverge exactly when a run covers a project with no labels
            # at its commit.
            "run_findings_raw": overall_run_findings,
            "run_findings_scored": scored_run_findings,
            "label_coverage_pct": (
                round(overall_labeled_total / overall_run_findings * 100, 1)
                if overall_run_findings else 0.0),
            "label_coverage_pct_scored": (
                round(overall_labeled_total / scored_run_findings * 100, 1)
                if scored_run_findings else 0.0),
        }
        per_rule.sort(key=lambda x: x["labeled_total"], reverse=True)
        return {
            "run": run, "run_id": run_id,
            "overall": overall, "per_rule": per_rule,
            "per_project": projects, "warnings": warnings,
            "unscoreable": unscoreable,
            "unscoreable_projects": [u["project"] for u in unscoreable],
        }

    def get_unlabeled_findings(self, run_id: int, rule_id: str = None,
                               project: str = None, limit: int = None,
                               seed: int = None, file: str = None,
                               enforce_scope: bool = True) -> list[dict]:
        """Distinct findings from a run with no ground-truth label yet.

        Feeds the incremental adjudication loop: scan -> pull unlabeled ->
        adjudicate (Claude/manual) -> insert_ground_truth_labels. Matching is
        per the run's own codebase_commit, so re-adjudication is only needed
        when the pinned commit changes.

        `enforce_scope` (task 636, default True) drops findings outside each
        project's data/benchmark_repos.json scope_include/scope_exclude --
        the single largest source of wasted adjudication effort (task 420
        measured 63% of a raw pull as out-of-scope noise). Pass False
        (CLI: --no-scope) to see the raw unfiltered set.
        """
        from bench.corpus import in_scope
        results = {r["project"]: r for r in self.get_realworld_results(run_id)
                   if r["tool"] == "sqc"}
        out = []
        with self._cursor() as cur:
            for proj, res in results.items():
                if project and proj != project:
                    continue
                commit = res.get("codebase_commit")
                labeled = set()
                if commit:
                    cur.execute("""
                        SELECT file_path, line, rule_id FROM ground_truth
                        WHERE project=? AND codebase_commit=?
                    """, (proj, commit))
                    labeled = {(r["file_path"], r["line"], r["rule_id"])
                               for r in cur.fetchall()}
                q = """
                    SELECT DISTINCT rv.rule_id, rv.file_path, rv.line,
                           rv.column_num, rv.message
                    FROM realworld_violations rv
                    WHERE rv.result_id = ?
                """
                params = [res["id"]]
                if rule_id:
                    q += " AND rv.rule_id = ?"
                    params.append(rule_id)
                cur.execute(q, params)
                for r in cur.fetchall():
                    rel = self.project_relpath(proj, r["file_path"])
                    if file and rel != file:
                        continue
                    if enforce_scope and not in_scope(proj, rel):
                        continue
                    if (rel, r["line"], r["rule_id"]) in labeled:
                        continue
                    out.append({
                        "project": proj, "codebase_commit": commit,
                        "rule_id": r["rule_id"], "file_path": rel,
                        "abs_path": r["file_path"], "line": r["line"],
                        "column": r["column_num"], "message": r["message"],
                    })
        if seed is not None:
            import random
            out.sort(key=lambda x: (x["project"], x["rule_id"],
                                    x["file_path"], x["line"], x["column"]))
            rng = random.Random(seed)
            if limit and limit < len(out):
                out = rng.sample(out, limit)
            else:
                rng.shuffle(out)
        elif limit:
            out = out[:limit]
        return out

    # ── Audited-file corpus (file-at-a-time done-unit) ───────────────────

    def _run_findings_in_file(self, run_id: int, project: str,
                              relpath: str) -> set:
        """Distinct (line, rule_id) sqc emitted in one project-relative file."""
        out = set()
        with self._cursor() as cur:
            cur.execute("""
                SELECT rv.rule_id, rv.file_path, rv.line
                FROM realworld_violations rv
                JOIN realworld_results rr ON rr.id = rv.result_id
                WHERE rr.run_id = ? AND rr.project = ? AND rr.tool = 'sqc'
            """, (run_id, project))
            for r in cur.fetchall():
                if self.project_relpath(project, r["file_path"]) == relpath:
                    out.add((r["line"], r["rule_id"]))
        return out

    def files_with_findings(self, run_id: int) -> dict:
        """{project: {relpath: distinct-finding-count}} for tool='sqc'."""
        per: dict[str, dict] = {}
        for proj, keys in self._run_violation_keys(run_id).items():
            d: dict[str, int] = {}
            for (rel, _line, _rid) in keys:
                d[rel] = d.get(rel, 0) + 1
            per[proj] = d
        return per

    def mark_file_audited(self, run_id: int, project: str, file_path: str,
                          adjudicator: str = None, notes: str = None,
                          force: bool = False) -> dict:
        """Mark one project-relative file as exhaustively audited.

        Recomputes the file's TP/FP/uncertain/FN tallies from ground_truth and
        its sqc finding count from the run. Refuses (unless force) if any sqc
        finding in the file lacks a label — "done" requires every finding
        adjudicated. Returns a summary including any unlabeled findings.
        """
        from datetime import datetime, timezone
        run = self.get_realworld_run(run_id)
        if not run:
            return {"error": f"Run {run_id} not found"}
        commit = None
        for r in self.get_realworld_results(run_id):
            if r["tool"] == "sqc" and r["project"] == project:
                commit = r.get("codebase_commit")
                break
        if not commit:
            return {"error": f"No sqc result/commit for {project} in run {run_id}"}

        findings = self._run_findings_in_file(run_id, project, file_path)
        labels = [l for l in self.get_ground_truth_labels(project, commit)
                  if l["file_path"] == file_path]
        labeled_keys = {(l["line"], l["rule_id"]) for l in labels
                        if l["verdict"] != "FN"}
        unlabeled = sorted(findings - labeled_keys)
        if unlabeled and not force:
            return {
                "error": "file has unlabeled sqc findings; label them or pass "
                         "force=True",
                "project": project, "file_path": file_path,
                "commit": commit, "n_findings": len(findings),
                "unlabeled": [{"line": ln, "rule_id": rid}
                              for (ln, rid) in unlabeled],
            }

        n_tp = sum(l["verdict"] == "TP" for l in labels)
        n_fp = sum(l["verdict"] == "FP" for l in labels)
        n_unc = sum(l["verdict"] == "uncertain" for l in labels)
        n_fn = sum(l["verdict"] == "FN" for l in labels)
        now = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO audited_files
                    (project, codebase_commit, file_path, adjudicator,
                     audited_at, n_findings, n_tp, n_fp, n_uncertain, n_fn, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project, codebase_commit, file_path) DO UPDATE SET
                    adjudicator=excluded.adjudicator,
                    audited_at=excluded.audited_at,
                    n_findings=excluded.n_findings, n_tp=excluded.n_tp,
                    n_fp=excluded.n_fp, n_uncertain=excluded.n_uncertain,
                    n_fn=excluded.n_fn, notes=excluded.notes
            """, (project, commit, file_path, adjudicator, now,
                  len(findings), n_tp, n_fp, n_unc, n_fn, notes))
        return {
            "project": project, "file_path": file_path, "commit": commit,
            "n_findings": len(findings), "n_tp": n_tp, "n_fp": n_fp,
            "n_uncertain": n_unc, "n_fn": n_fn,
            "forced_unlabeled": len(unlabeled) if force else 0,
        }

    def get_audited_files(self, project: str = None,
                          commit: str = None) -> list[dict]:
        clauses, params = [], []
        if project:
            clauses.append("project = ?"); params.append(project)
        if commit:
            clauses.append("codebase_commit = ?"); params.append(commit)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._cursor() as cur:
            cur.execute(f"SELECT * FROM audited_files {where} "
                        "ORDER BY project, file_path", params)
            return [dict(r) for r in cur.fetchall()]

    def audited_files_map(self, commit_by_project: dict | None = None) -> dict:
        """{project: set(relpath)} of audited files, optionally pinned to the
        commit each project was scored at."""
        out: dict[str, set] = {}
        for af in self.get_audited_files():
            if (commit_by_project is not None
                    and commit_by_project.get(af["project"])
                    != af["codebase_commit"]):
                continue
            out.setdefault(af["project"], set()).add(af["file_path"])
        return out

    def set_corpus_scope(self, project: str, commit: str,
                         total_inscope_files: int, scope_note: str = None):
        from datetime import datetime, timezone
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO audit_corpus_meta
                    (project, codebase_commit, total_inscope_files,
                     scope_note, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(project, codebase_commit) DO UPDATE SET
                    total_inscope_files=excluded.total_inscope_files,
                    scope_note=excluded.scope_note,
                    updated_at=excluded.updated_at
            """, (project, commit, total_inscope_files, scope_note,
                  datetime.now(timezone.utc).isoformat()))

    def get_corpus_meta(self) -> dict:
        """{(project, commit): {total_inscope_files, scope_note}}."""
        out = {}
        with self._cursor() as cur:
            cur.execute("SELECT * FROM audit_corpus_meta")
            for r in cur.fetchall():
                out[(r["project"], r["codebase_commit"])] = dict(r)
        return out

    def audit_coverage(self, run_id: int) -> dict:
        """Per-project file-coverage of the audit toward 'done'.

        Reports audited-file count against (a) total in-scope files if recorded
        in audit_corpus_meta, and (b) files sqc actually flagged (always known).
        """
        commits = {r["project"]: r.get("codebase_commit")
                   for r in self.get_realworld_results(run_id)
                   if r["tool"] == "sqc"}
        fwf = self.files_with_findings(run_id)
        meta = self.get_corpus_meta()
        audited = self.get_audited_files()
        by_proj: dict[str, dict] = {}
        for af in audited:
            p = af["project"]
            if commits.get(p) != af["codebase_commit"]:
                continue
            d = by_proj.setdefault(p, {"files": 0, "findings": 0, "tp": 0,
                                       "fp": 0, "uncertain": 0, "fn": 0})
            d["files"] += 1
            d["findings"] += af["n_findings"]
            d["tp"] += af["n_tp"]; d["fp"] += af["n_fp"]
            d["uncertain"] += af["n_uncertain"]; d["fn"] += af["n_fn"]
        rows = []
        for project, commit in commits.items():
            d = by_proj.get(project, {"files": 0, "findings": 0, "tp": 0,
                                      "fp": 0, "uncertain": 0, "fn": 0})
            files_flagged = len(fwf.get(project, {}))
            total = meta.get((project, commit), {}).get("total_inscope_files")
            rows.append({
                "project": project, "codebase_commit": commit,
                "audited_files": d["files"],
                "total_inscope_files": total,
                "files_with_findings": files_flagged,
                "coverage_pct": (round(d["files"] / total * 100, 1)
                                 if total else None),
                "findings_in_audited": d["findings"],
                "tp": d["tp"], "fp": d["fp"], "uncertain": d["uncertain"],
                "fn": d["fn"],
            })
        rows.sort(key=lambda r: r["project"])
        return {"run_id": run_id, "per_project": rows}

    def score_audited_corpus(self, run_id: int) -> dict:
        """Precision AND recall restricted to the audited-file set, plus
        coverage. This is the honest, completion-tracked metric: every finding
        in an audited file is labeled, and each file was read for missed bugs,
        so both precision and recall are meaningful over this corpus."""
        commits = {r["project"]: r.get("codebase_commit")
                   for r in self.get_realworld_results(run_id)
                   if r["tool"] == "sqc"}
        restrict = self.audited_files_map(commits)
        score = self.score_realworld_run(run_id, restrict_files=restrict)
        score["coverage"] = self.audit_coverage(run_id)
        score["audited_corpus"] = True
        return score

    def freeze_oracle_version(self, version: str, run_id: int,
                              notes: str = None) -> dict:
        """Snapshot the audited corpus (coverage + P/R) under a version tag for
        citation. Re-freezing the same version overwrites it."""
        import json as _json
        from datetime import datetime, timezone
        snap = {
            "frozen_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "score": self.score_audited_corpus(run_id),
        }
        with self._cursor() as cur:
            cur.execute("""
                INSERT INTO oracle_versions (version, frozen_at, notes, snapshot_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(version) DO UPDATE SET
                    frozen_at=excluded.frozen_at, notes=excluded.notes,
                    snapshot_json=excluded.snapshot_json
            """, (version, snap["frozen_at"], notes,
                  _json.dumps(snap, default=str)))
        return {"version": version, "frozen_at": snap["frozen_at"]}

    def list_oracle_versions(self) -> list[dict]:
        with self._cursor() as cur:
            cur.execute("SELECT version, frozen_at, notes FROM oracle_versions "
                        "ORDER BY frozen_at DESC")
            return [dict(r) for r in cur.fetchall()]

    # ── Run Resolution ────────────────────────────────────────────────────

    def resolve_run(self, identifier: str) -> str | None:
        """Resolve 'latest', run_id, or SHA fragment to a run_id."""
        ident = identifier.strip()
        if ident.lower() in ("latest", "current"):
            with self._cursor() as cur:
                cur.execute("SELECT run_id FROM runs ORDER BY started_at DESC LIMIT 1")
                row = cur.fetchone()
                return row["run_id"] if row else None

        # Exact match
        if self.get_run(ident):
            return ident

        # SHA suffix match
        with self._cursor() as cur:
            cur.execute("SELECT run_id FROM runs WHERE commit_sha = ? ORDER BY started_at DESC LIMIT 1",
                        (ident,))
            row = cur.fetchone()
            if row:
                return row["run_id"]

            # Substring match on run_id
            cur.execute("SELECT run_id FROM runs WHERE run_id LIKE ? ORDER BY started_at DESC LIMIT 1",
                        (f"%{ident}%",))
            row = cur.fetchone()
            return row["run_id"] if row else None

