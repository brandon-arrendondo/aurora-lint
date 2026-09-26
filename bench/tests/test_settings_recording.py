"""A run records the policy/environment settings it scanned under (ADR-0015),
and its run_id names them: `-default-{hash12}`, `-strict-{hash12}`, or
`-preset-{hash12}` for anything that is exactly neither. Historical runs keep
their bare ids ("pre-settings"), and a bare SHA still resolves to the run
under the default preset.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from bench.config import juliet_run_id, settings_run_suffix
from bench.db import BenchDB, diff_settings

DEFAULT = {"preset": "default", "hash": "0ebfeb2b7e99" + "0" * 52}
STRICT = {"preset": "strict", "hash": "6686349f9a10" + "1" * 52}
CUSTOM = {"preset": None, "hash": "abcdefabcdef" + "2" * 52}


class TestSettingsRunId(unittest.TestCase):
    def test_every_new_run_names_its_preset_and_hash(self):
        self.assertEqual(settings_run_suffix(DEFAULT), "-default-0ebfeb2b7e99")
        self.assertEqual(settings_run_suffix(STRICT), "-strict-6686349f9a10")
        self.assertEqual(settings_run_suffix(CUSTOM), "-preset-abcdefabcdef")

    def test_suffix_follows_mode_and_compile_db_and_precedes_a_cwe_subset(self):
        self.assertEqual(
            juliet_run_id("0.5.3", "2db3d605", fast=False, compile_commands=True,
                          cwes=("CWE-78",), settings=STRICT),
            "sqc-0.5.3-2db3d605-full-cdb-strict-6686349f9a10-cwe78")

    def test_default_and_strict_runs_of_one_build_do_not_collide(self):
        ids = {juliet_run_id("0.5.3", "2db3d605", fast=True, compile_commands=False,
                             settings=s) for s in (DEFAULT, STRICT, None)}
        self.assertEqual(len(ids), 3)


class TestResolvePrefersDefaultSettings(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db = BenchDB(Path(self._tmpdir.name) / "test.db")

    def _add(self, run_id, started_at):
        self.db.create_run(run_id, "0.5.3", "2db3d605", "fast", started_at, 1, 1, 1, {})

    def test_sha_resolves_to_the_default_preset_run_even_when_strict_ran_later(self):
        self._add("sqc-0.5.3-2db3d605-default-0ebfeb2b7e99", "2026-01-01T00:00:00Z")
        self._add("sqc-0.5.3-2db3d605-strict-6686349f9a10", "2026-01-02T00:00:00Z")
        self.assertEqual(self.db.resolve_run("2db3d605"),
                         "sqc-0.5.3-2db3d605-default-0ebfeb2b7e99")

    def test_realworld_sha_resolves_to_the_default_preset_run(self):
        a = self.db.create_realworld_run("0.5.3", "2db3d605",
                                         run_id="sqc-0.5.3-2db3d605-default-0ebfeb2b7e99",
                                         variant="default-0ebfeb2b7e99")
        self.db.create_realworld_run("0.5.3", "2db3d605",
                                     run_id="sqc-0.5.3-2db3d605-strict-6686349f9a10",
                                     variant="strict-6686349f9a10")
        self.db.create_realworld_run("0.5.3", "2db3d605",
                                     run_id="sqc-0.5.3-2db3d605-cdb-default-0ebfeb2b7e99",
                                     variant="cdb-default-0ebfeb2b7e99")
        self.assertEqual(self.db.resolve_realworld_run("2db3d605"), a)


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
        # A `runs` table as it stood before settings existed, built directly
        # rather than by dropping the column (DROP COLUMN's schema rewrite is
        # fragile across SQLite versions).
        with sqlite3.connect(self.path) as conn:
            conn.execute("""
                CREATE TABLE runs (
                    run_id TEXT PRIMARY KEY, sqc_version TEXT NOT NULL,
                    commit_sha TEXT NOT NULL, mode TEXT NOT NULL DEFAULT 'fast',
                    status TEXT NOT NULL DEFAULT 'running', started_at TEXT NOT NULL,
                    finished_at TEXT, pid INTEGER, jobs INTEGER, total_cwes INTEGER,
                    hostname TEXT, cpu_model TEXT, cpu_cores INTEGER, ram_gb REAL,
                    os_version TEXT, cache_state TEXT NOT NULL DEFAULT 'cold')
            """)
            conn.execute("INSERT INTO runs (run_id, sqc_version, commit_sha, started_at) "
                         "VALUES ('sqc-0.5.2-aaaaaaaa', '0.5.2', 'aaaaaaaa', "
                         "'2026-01-01T00:00:00Z')")
        db = BenchDB(self.path)
        self.assertIsNone(db.get_run("sqc-0.5.2-aaaaaaaa")["settings"])
        with sqlite3.connect(self.path) as conn:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(realworld_runs)")}
        self.assertIn("settings", cols)


class TestDiffSettings(unittest.TestCase):
    def _s(self, preset, h, **options):
        import json
        return json.dumps({"preset": preset, "hash": h, "policy": "default",
                           "options": options}, sort_keys=True)

    def test_same_settings_print_nothing(self):
        a = self._s("default", "a" * 64, assert_is_guard=True)
        self.assertEqual(diff_settings(a, a), [])

    def test_option_by_option_diff_names_each_change(self):
        lines = diff_settings(self._s("default", "a" * 64, assert_is_guard=True),
                              self._s("strict", "b" * 64, assert_is_guard=False))
        self.assertIn("Settings: preset default -> strict", lines)
        self.assertIn("  assert_is_guard: True -> False", lines)

    def test_same_preset_name_with_a_different_hash_is_flagged(self):
        lines = diff_settings(self._s("default", "a" * 64, x=True),
                              self._s("default", "b" * 64, x=True, y=True))
        self.assertTrue(lines[0].startswith("Settings: SAME PRESET NAME 'default', DIFFERENT HASH"))
        self.assertIn("  y: (absent) -> True", lines)

    def test_a_pre_settings_run_is_named(self):
        self.assertEqual(diff_settings(None, self._s("default", "a" * 64)),
                         ["Settings: base is a pre-settings run (no recorded settings)"])


if __name__ == "__main__":
    unittest.main()
