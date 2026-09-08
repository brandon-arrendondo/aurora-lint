"""Ingest must record only the projects the invocation actually scanned.

The export directory is keyed on (tool, version, sha), so every codebase at
one commit shares it, while run_one's pre-run cleanup unlinks only the current
run_id's own files. ingest_realworld_run then globs `*.json` over the whole
directory. Without a project restriction, any narrowed re-run at a commit
already scanned -- `--codebase hostap` after a full sweep, interrupted or not
-- swept the other projects' older exports into the new run.

The stale rows are not merely redundant. `durations` and `metrics` are keyed
by the codebase this invocation ran, so a swept-in project arrives with no
duration and zero c_files/loc; and since the scan-time sidecar is the only
source of codebase_commit, it also arrives with a NULL commit. ground_truth is
keyed on (project, commit, file, line, rule), so those findings leave the
precision/recall denominator with nothing logged anywhere.
"""

import json
import tempfile
import unittest
from pathlib import Path

from bench.db import BenchDB

VERSION_DIR = "sqc-0.4.336-deadbeef"


def _export(n, project):
    return json.dumps([
        {"rule_id": "EXP34-C", "file": f"/tc/{project}/src/f{i}.c", "line": i}
        for i in range(n)
    ])


class TestIngestProjectScoping(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.version_dir = root / VERSION_DIR
        self.version_dir.mkdir()
        # Left behind by an earlier invocation at this same commit.
        (self.version_dir / f"sqc-curl-0.4.336-deadbeef.json").write_text(
            _export(7, "curl"))
        # Written by the invocation under test.
        (self.version_dir / f"sqc-hostap-0.4.336-deadbeef.json").write_text(
            _export(3, "hostap"))
        (self.version_dir / f"sqc-hostap-0.4.336-deadbeef.meta.json").write_text(
            json.dumps({"codebase_commit": "a" * 40}))
        self._db_counter = 0
        self._root = root

    def tearDown(self):
        self._tmp.cleanup()

    def _ingest(self, **kw):
        """Ingest into a fresh DB. A fresh one per call because
        realworld_runs has a uniqueness index on run identity, so the same
        version_dir cannot be ingested twice into one database."""
        self._db_counter += 1
        db = BenchDB(self._root / f"probe{self._db_counter}.db")
        run_id = db.ingest_realworld_run(
            VERSION_DIR, str(self.version_dir),
            machine={"hostname": "test"},
            durations={"hostap": 12.0},
            metrics={"hostap": {"c_files": 700, "loc": 500000}},
            **kw)
        with db._cursor() as cur:
            cur.execute(
                "SELECT project, violation_count, duration_s, c_files, loc, "
                "codebase_commit FROM realworld_results "
                "WHERE run_id=? AND tool='sqc' ORDER BY project", (run_id,))
            return {r["project"]: dict(r) for r in cur.fetchall()}

    def test_only_projects_excludes_a_leftover_export(self):
        rows = self._ingest(only_projects={"hostap"})
        self.assertEqual(sorted(rows), ["hostap"])

    def test_the_scanned_project_is_recorded_in_full(self):
        rows = self._ingest(only_projects={"hostap"})
        hostap = rows["hostap"]
        self.assertEqual(hostap["violation_count"], 3)
        self.assertEqual(hostap["duration_s"], 12.0)
        self.assertEqual(hostap["c_files"], 700)
        self.assertEqual(hostap["codebase_commit"], "a" * 40)

    def test_unrestricted_ingest_still_sweeps_the_directory(self):
        """The un-restricted mode is deliberate, not a leftover: the
        run_id + only_projects merge path exists so a later sweep can fill in
        projects a partial earlier ingest missed, and that reads older exports
        on purpose. This pins that the parameter -- not a directory wipe or an
        mtime cutoff -- is what scopes a normal run."""
        rows = self._ingest()
        self.assertEqual(sorted(rows), ["curl", "hostap"])

    def test_a_swept_in_project_is_unusable_for_scoring(self):
        """Why the leak matters rather than merely being untidy: the stale row
        carries no commit, and ground_truth keys on it."""
        curl = self._ingest()["curl"]
        self.assertIsNone(curl["codebase_commit"])
        self.assertIsNone(curl["duration_s"])
        self.assertEqual(curl["c_files"], 0)
        self.assertEqual(curl["loc"], 0)

    def test_meta_and_score_sidecars_are_not_read_as_finding_lists(self):
        """Both end in .json and live in the same directory."""
        (self.version_dir / f"{VERSION_DIR}.score.json").write_text("{}")
        rows = self._ingest(only_projects={"hostap"})
        self.assertEqual(sorted(rows), ["hostap"])
