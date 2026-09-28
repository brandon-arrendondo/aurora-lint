"""A real-world scan records the settings it actually ran under.

A compile database can change the settings: one written for cl makes
aurora-lint match #include names ignoring case, which changes the settings
hash. So one invocation over several codebases can produce scans under two
sets of settings, which land in two export directories. Each directory is its
own run and is ingested with its own settings, rather than all of it being
refused after the sweep (or, before that, recorded under one codebase's
settings).
"""

import unittest
from pathlib import Path
from unittest import mock

from bench import config, realworld_runner


class FakeDB:
    """Records what `_ingest` asks of the database."""

    def __init__(self):
        self.ingested = []
        self.attached = []

    def ingest_realworld_run(self, name, path, machine, durations, metrics,
                             only_projects, settings):
        self.ingested.append((name, set(only_projects), settings))
        return name

    def insert_realworld_result(self, run_id, codebase, tool, *args, **kwargs):
        self.attached.append((run_id, codebase, tool))

    def score_realworld_run(self, run_id):
        return {"error": "no oracle in this test"}


def _sqc(codebase, dir_name, settings_hash):
    return {"tool": "sqc", "codebase": codebase, "ok": True, "duration_s": 1,
            "version_dir": Path("/nonexistent") / dir_name,
            "settings": {"preset": "default", "hash": settings_hash}}


class TestIngestPerSettingsGroup(unittest.TestCase):
    def _ingest(self, results):
        db = FakeDB()
        summary = {}
        with mock.patch.object(realworld_runner, "BenchDB", return_value=db), \
                mock.patch.object(realworld_runner, "_count_c_source", return_value=(1, 1)):
            realworld_runner._ingest(results, summary)
        return db, summary

    def test_one_settings_group_is_one_run(self):
        db, summary = self._ingest([
            _sqc("curl", "sqc-v-sha-cdb-default-aaaa", "aaaa"),
            _sqc("lua", "sqc-v-sha-cdb-default-aaaa", "aaaa"),
        ])
        self.assertEqual(len(db.ingested), 1)
        self.assertEqual(db.ingested[0][1], {"curl", "lua"})
        self.assertEqual(summary["run_id"], "sqc-v-sha-cdb-default-aaaa")
        self.assertEqual(summary["run_ids"], ["sqc-v-sha-cdb-default-aaaa"])

    def test_mixed_settings_become_one_run_each_with_its_own_settings(self):
        db, summary = self._ingest([
            _sqc("curl", "sqc-v-sha-cdb-default-aaaa", "aaaa"),
            _sqc("ventoy", "sqc-v-sha-cdb-default-bbbb", "bbbb"),
            {"tool": "cppcheck", "codebase": "ventoy", "ok": True, "total": 3,
             "duration_s": 1},
        ])
        by_run = {name: (projects, settings) for name, projects, settings in db.ingested}
        self.assertEqual(set(by_run), {"sqc-v-sha-cdb-default-aaaa",
                                       "sqc-v-sha-cdb-default-bbbb"})
        self.assertEqual(by_run["sqc-v-sha-cdb-default-aaaa"][0], {"curl"})
        self.assertEqual(by_run["sqc-v-sha-cdb-default-bbbb"][0], {"ventoy"})
        self.assertIn('"hash": "bbbb"', by_run["sqc-v-sha-cdb-default-bbbb"][1])
        # A comparison tool's row rides on the run that scanned its codebase.
        self.assertEqual(db.attached, [("sqc-v-sha-cdb-default-bbbb", "ventoy", "cppcheck")])
        self.assertEqual(len(summary["run_ids"]), 2)


class TestSettingsResolution(unittest.TestCase):
    def test_settings_options_are_picked_out_of_extra_args(self):
        extra = ["-d", "/src", "--exclude", "x/**", "--include-names", "case-insensitive",
                 "--set=assert_is_guard=false", "--libc", "musl"]
        self.assertEqual(config.settings_args(extra),
                         ["--include-names", "case-insensitive",
                          "--set=assert_is_guard=false", "--libc", "musl"])
        self.assertEqual(config.settings_args(["-d", "/src", "--exclude", "x"]), [])

    def test_the_compile_database_and_settings_options_reach_the_binary(self):
        seen = {}

        def fake_run(cmd, **kwargs):
            seen["cmd"] = cmd
            return mock.Mock(stdout='{"current": {"hash": "h", "preset": "default"}}')

        with mock.patch.object(config.subprocess, "run", side_effect=fake_run):
            config.resolve_settings("default", compile_db="/b/compile_commands.json",
                                    extra_args=["-d", "/src", "--include-names", "exact"])
        cmd = seen["cmd"]
        self.assertEqual(cmd[cmd.index("--compile-commands") + 1], "/b/compile_commands.json")
        self.assertEqual(cmd[cmd.index("--include-names") + 1], "exact")
        self.assertNotIn("-d", cmd)


if __name__ == "__main__":
    unittest.main()
