"""A run records the policy/environment settings it scanned under (ADR-0015),
and a non-default profile cannot be recorded under the default run's id.

The default preset keeps the bare `sqc-{version}-{sha}` id, so default runs
and every historical run share one namespace. A strict run of the same build
would otherwise land on the default run's row (the resume check would even
skip it as already completed), so until its suffix is ruled on it is refused.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from bench.config import juliet_run_id, settings_run_suffix
from bench.db import BenchDB


class TestProfileRunId(unittest.TestCase):
    def test_default_profile_keeps_the_bare_id(self):
        self.assertEqual(
            juliet_run_id("0.5.3", "2db3d605", fast=True, compile_commands=False,
                          profile="default"),
            "sqc-0.5.3-2db3d605")
        self.assertEqual(settings_run_suffix("default"), "")

    def test_a_non_default_profile_is_refused_not_guessed(self):
        with self.assertRaises(ValueError):
            juliet_run_id("0.5.3", "2db3d605", fast=True, compile_commands=False,
                          profile="strict")

    def test_an_unknown_profile_is_refused(self):
        with self.assertRaises(ValueError):
            settings_run_suffix("lenient")


class TestSettingsColumn(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.path = Path(self._tmpdir.name) / "test.db"

    def test_runs_record_their_settings(self):
        db = BenchDB(self.path)
        db.create_run("sqc-0.5.3-2db3d605", "0.5.3", "2db3d605", "fast",
                      "2026-01-01T00:00:00Z", 1, 1, 1, {}, settings='{"policy": "default"}')
        self.assertEqual(db.get_run("sqc-0.5.3-2db3d605")["settings"],
                         '{"policy": "default"}')
        rw = db.create_realworld_run("0.5.3", "2db3d605", run_id="sqc-0.5.3-2db3d605",
                                     settings='{"policy": "default"}')
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT settings FROM realworld_runs WHERE id = ?",
                               (rw,)).fetchone()
        self.assertEqual(row[0], '{"policy": "default"}')

    def test_an_older_database_gains_the_column_with_null_for_old_runs(self):
        db = BenchDB(self.path)
        db.create_run("sqc-0.5.2-aaaaaaaa", "0.5.2", "aaaaaaaa", "fast",
                      "2026-01-01T00:00:00Z", 1, 1, 1, {})
        with sqlite3.connect(self.path) as conn:
            conn.execute("ALTER TABLE runs DROP COLUMN settings")
            conn.execute("ALTER TABLE realworld_runs DROP COLUMN settings")
        db = BenchDB(self.path)
        self.assertIsNone(db.get_run("sqc-0.5.2-aaaaaaaa")["settings"])


if __name__ == "__main__":
    unittest.main()
