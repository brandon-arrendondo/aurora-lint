"""Juliet run ids distinguish mode and compile-db configuration.

Regression for a fast and a full run of the same sqc build colliding on one
run_id: the resume check (`db.get_run(run_id)` already "completed") made the
second run return without scanning. The id is the runs table's primary key, so
the `mode` column alone could not keep the two apart.
"""

import tempfile
import unittest
from pathlib import Path

from bench.config import juliet_run_id
from bench.db import BenchDB
from bench.runner import _select_cwes


class TestJulietRunId(unittest.TestCase):
    def test_fast_keeps_the_bare_historical_id(self):
        self.assertEqual(juliet_run_id("0.5.3", "2db3d605", fast=True, compile_commands=False),
                         "sqc-0.5.3-2db3d605")

    def test_every_configuration_gets_its_own_id(self):
        ids = {
            juliet_run_id("0.5.3", "2db3d605", fast=fast, compile_commands=cdb)
            for fast in (True, False) for cdb in (True, False)
        }
        self.assertEqual(ids, {
            "sqc-0.5.3-2db3d605",
            "sqc-0.5.3-2db3d605-full",
            "sqc-0.5.3-2db3d605-cdb",
            "sqc-0.5.3-2db3d605-full-cdb",
        })

    def test_a_cwe_subset_gets_its_own_id(self):
        self.assertEqual(
            juliet_run_id("0.5.3", "2db3d605", fast=True, compile_commands=False,
                          cwes=("CWE-476", "CWE-78")),
            "sqc-0.5.3-2db3d605-cwe78_476")


class TestSelectCwes(unittest.TestCase):
    ALL = ["CWE476_NULL_Pointer_Dereference", "CWE78_OS_Command_Injection",
           "CWE789_Uncontrolled_Mem_Alloc"]

    def test_accepts_every_spelling_and_does_not_prefix_match(self):
        for spelling in ("78", "CWE78", "cwe-78"):
            self.assertEqual(_select_cwes(self.ALL, [spelling]),
                             ["CWE78_OS_Command_Injection"])

    def test_unknown_cwe_is_an_error_not_an_empty_or_full_run(self):
        with self.assertRaises(ValueError):
            _select_cwes(self.ALL, ["78", "99999"])


class TestResolveRunPrefersFast(unittest.TestCase):
    SHA = "2db3d605"

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db = BenchDB(Path(self._tmpdir.name) / "test.db")

    def _add(self, run_id, mode, started_at):
        self.db.create_run(run_id, sqc_version="0.5.3", commit_sha=self.SHA, mode=mode,
                           started_at=started_at, pid=1, jobs=1, total_cwes=1, machine={})
        self.db.finish_run(run_id, "completed", started_at)

    def test_sha_resolves_to_the_fast_run_even_when_full_ran_later(self):
        self._add("sqc-0.5.3-2db3d605", "fast", "2026-01-01T00:00:00Z")
        self._add("sqc-0.5.3-2db3d605-full", "full", "2026-01-02T00:00:00Z")
        self.assertEqual(self.db.resolve_run(self.SHA), "sqc-0.5.3-2db3d605")

    def test_the_full_run_is_still_addressable_by_its_own_id(self):
        self._add("sqc-0.5.3-2db3d605", "fast", "2026-01-01T00:00:00Z")
        self._add("sqc-0.5.3-2db3d605-full", "full", "2026-01-02T00:00:00Z")
        self.assertEqual(self.db.resolve_run("sqc-0.5.3-2db3d605-full"),
                         "sqc-0.5.3-2db3d605-full")

    def test_a_full_only_sha_still_resolves(self):
        self._add("sqc-0.5.3-2db3d605-full", "full", "2026-01-02T00:00:00Z")
        self.assertEqual(self.db.resolve_run(self.SHA), "sqc-0.5.3-2db3d605-full")

    def test_sha_skips_a_cwe_subset_run(self):
        self._add("sqc-0.5.3-2db3d605", "fast", "2026-01-01T00:00:00Z")
        self._add("sqc-0.5.3-2db3d605-cwe78", "fast +cwe=CWE-78", "2026-01-02T00:00:00Z")
        self.assertEqual(self.db.resolve_run(self.SHA), "sqc-0.5.3-2db3d605")


if __name__ == "__main__":
    unittest.main()
