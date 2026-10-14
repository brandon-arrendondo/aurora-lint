"""The reference shadow set: its declaration, its diff, and its label wall.

The shadow set is only a check against overfitting while nothing is tuned to
it, so the tests that matter most are structural: it shares no name with an
oracle corpus, every pin is a full SHA, and a label batch naming one of its
projects is refused before anything is written.
"""

import argparse
import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bench import reference
from bench.__main__ import _validate_label_rows
from bench.config import PROJECT_DIR


def _f(rule, file, line, column=1, message="m"):
    return {"rule": rule, "file": file, "line": line, "column": column,
            "message": message}


class TestDeclaration(unittest.TestCase):
    def setUp(self):
        self.repos = json.loads(reference.CORPUS_FILE.read_text())["repos"]

    def test_disjoint_from_oracle_corpora(self):
        oracle = json.loads((PROJECT_DIR / "data" / "benchmark_repos.json").read_text())
        oracle_names = {r["name"] for r in oracle["repos"]}
        oracle_urls = {r["repo"].lower().removesuffix(".git") for r in oracle["repos"]}
        self.assertFalse(reference.shadow_names() & oracle_names)
        self.assertFalse({r["repo"].lower().removesuffix(".git") for r in self.repos}
                         & oracle_urls)

    def test_pins_are_full_shas_and_names_unique(self):
        for r in self.repos:
            self.assertRegex(r["commit"], r"^[0-9a-f]{40}$", r["name"])
            self.assertIn(r["tier"], reference.TIERS, r["name"])
            self.assertTrue(re.fullmatch(r"[a-z0-9._-]+", r["name"]), r["name"])
        self.assertEqual(len(self.repos), len(reference.shadow_names()))

    def test_tiers_are_cumulative(self):
        quick, standard, everything = (reference.load(t) for t in ("quick", "standard", "all"))
        self.assertLess(len(quick), len(standard))
        self.assertLess(len(standard), len(everything))
        self.assertTrue({r["name"] for r in quick} <= {r["name"] for r in standard})


class TestDiff(unittest.TestCase):
    def test_added_removed_changed(self):
        base = [_f("EXP33-C", "a.c", 1), _f("EXP34-C", "a.c", 2), _f("INT31-C", "b.c", 3, message="old")]
        target = [_f("EXP33-C", "a.c", 1), _f("MEM30-C", "a.c", 9), _f("INT31-C", "b.c", 3, message="new")]
        d = reference.diff(base, target)
        self.assertEqual([f["rule"] for f in d["removed"]], ["EXP34-C"])
        self.assertEqual([f["rule"] for f in d["added"]], ["MEM30-C"])
        self.assertEqual(len(d["changed"]), 1)

    def test_duplicates_are_counted_not_collapsed(self):
        # Two findings at one location are two findings; losing one is a removal.
        base = [_f("EXP33-C", "a.c", 1)] * 2
        d = reference.diff(base, base[:1])
        self.assertEqual(len(d["removed"]), 1)
        self.assertEqual(d["added"], [])


class TestHeaders(unittest.TestCase):
    def _report(self, data):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = Path(d.name) / "h.json"
        path.write_text(json.dumps(data))
        return path

    def test_no_search_path_is_not_attempted_rather_than_clean(self):
        h = reference._headers(self._report(
            {"search_paths": [], "forced_includes": [], "unresolved": []}))
        self.assertEqual(h, {"attempted": False, "unresolved": None})

    def test_unresolved_counted_when_attempted(self):
        rows = [{"spelling": "a.h", "includer_outside_project": False},
                {"spelling": "a.h", "includer_outside_project": False},
                {"spelling": "b.h", "includer_outside_project": False},
                {"spelling": "gnu/stubs-32.h", "includer_outside_project": True}]
        h = reference._headers(self._report(
            {"search_paths": ["/x"], "forced_includes": [], "unresolved": rows}))
        self.assertEqual(h, {"attempted": True, "unresolved": 2, "top": ["a.h", "b.h"]})

    def test_a_binary_without_the_report_records_nothing(self):
        self.assertEqual(reference._headers(Path("/nonexistent/h.json")), {})

    def test_summary_names_every_scan_that_missed_headers(self):
        report = {"codebases": {
            "a": {"headers": {"attempted": False, "unresolved": None}},
            "b": {"headers": {"attempted": True, "unresolved": 3, "top": ["x.h", "y.h", "z.h"]}},
            "c": {"headers": {"attempted": True, "unresolved": 0}}}}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            reference._print_headers(report)
        self.assertIn("no search path, include resolution not counted: 1 codebase", out.getvalue())
        self.assertIn("b: 3 header(s) not found (x.h, y.h, z.h)", out.getvalue())
        self.assertNotIn("c:", out.getvalue())


class TestOwnIncludes(unittest.TestCase):
    def test_header_directories_shallowest_first_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for rel in ("x.h", "include/a/b.h", "include/c.h", "src/only.c", ".git/x.h"):
                f = root / rel
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text("")
            dirs = [str(p.relative_to(root)) for p in reference.own_include_dirs(root)]
            self.assertEqual(dirs, [".", "include", "include/a"])


class TestJobs(unittest.TestCase):
    large = [{"tier": "quick"}, {"tier": "large"}]

    def _jobs(self, repos, requested, ram):
        with mock.patch.object(reference, "total_ram_gib", return_value=ram), \
                mock.patch.object(reference.os, "cpu_count", return_value=8), \
                contextlib.redirect_stderr(io.StringIO()):
            return reference.jobs_for(repos, requested)

    def test_large_tier_on_a_small_node_halves_the_default(self):
        self.assertEqual(self._jobs(self.large, None, 14), 4)

    def test_an_explicit_jobs_is_kept(self):
        self.assertEqual(self._jobs(self.large, 8, 14), 8)

    def test_no_large_tier_or_enough_ram_keeps_the_default(self):
        self.assertEqual(self._jobs([{"tier": "standard"}], None, 14), 8)
        self.assertEqual(self._jobs(self.large, None, 32), 8)


class TestCacheKey(unittest.TestCase):
    def test_settings_id_follows_the_manifest_content(self):
        with tempfile.TemporaryDirectory() as d:
            m = Path(d) / "rules.toml"
            m.write_text("[rules]\n")
            with mock.patch.object(reference, "MANIFEST", m):
                before = reference.settings_id()
                m.write_text("[rules]\nX = 1\n")
                self.assertNotEqual(before, reference.settings_id())


_FAKE_BINARY = """#!/bin/sh
# Writes an export, reports a contained failure, and exits as an incomplete
# scan does (ADR-0017).
while [ $# -gt 0 ]; do
  if [ "$1" = "--export" ]; then echo '[]' > "$2"; fi
  shift
done
echo 'Error: rule failure (timeout): EXP33-C: x.c: ran out of time' >&2
exit {code}
"""


class TestIncompleteScan(unittest.TestCase):
    def _scan(self, code):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        root = Path(d.name)
        binary = root / "fake"
        binary.write_text(_FAKE_BINARY.format(code=code))
        binary.chmod(0o755)
        (root / "corpus" / "c").mkdir(parents=True)
        repo = {"name": "c", "commit": "0" * 40}
        with mock.patch.object(reference, "OUT_DIR", root / "out"):
            result = reference.scan(binary, "bid", repo, root / "corpus", 1, 60)
            cached = list((root / "out").rglob("c-*.json"))
        return result, cached

    def test_an_export_with_exit_3_is_incomplete_and_not_cached(self):
        result, cached = self._scan(3)
        self.assertTrue(result["status"].startswith("incomplete:"), result["status"])
        self.assertIn("EXP33-C", result["status"])
        self.assertNotIn("x.c", result["status"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(cached, [])

    def test_a_complete_scan_is_ok_and_cached(self):
        result, cached = self._scan(0)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(cached), 1)

    def test_status_never_carries_stderr_text(self):
        self.assertEqual(reference._status(2, "error: /some/shadow/path.c", False), "exit 2")
        self.assertIn("stall watchdog",
                      reference._status(3, "Error: hang: R on f.c has run 600s", True))

    def test_an_incomplete_codebase_is_not_compared(self):
        report = {"codebases": {
            "a": {"base_status": "ok", "target_status": "ok"},
            "b": {"base_status": "ok", "target_status": "incomplete: INCOMPLETE: 1 failure(s)"},
            "c": {"error": "fetch: x"}}}
        self.assertEqual(reference.not_compared(report), 2)


class TestLabelWall(unittest.TestCase):
    def test_import_refuses_shadow_project(self):
        name = sorted(reference.shadow_names())[0]
        rows = [{"project": name, "file": "x.c", "line": "1", "rule": "EXP33-C", "verdict": "TP"}]
        args = argparse.Namespace(csv="batch.csv", allow_unknown_rule=False)
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()):
            _validate_label_rows(rows, args)

    def test_import_refuses_shadow_project_in_any_case(self):
        name = sorted(reference.shadow_names())[0].upper()
        rows = [{"project": name, "file": "x.c", "line": "1", "rule": "EXP33-C", "verdict": "TP"}]
        args = argparse.Namespace(csv="batch.csv", allow_unknown_rule=False)
        with self.assertRaises(SystemExit), contextlib.redirect_stdout(io.StringIO()):
            _validate_label_rows(rows, args)


if __name__ == "__main__":
    unittest.main()
