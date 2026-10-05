"""The reference shadow set: its declaration, its diff, and its label wall.

The shadow set is only a check against overfitting while nothing is tuned to
it, so the tests that matter most are structural: it shares no name with an
oracle corpus, every pin is a full SHA, and a label batch naming one of its
projects is refused before anything is written.
"""

import argparse
import json
import re
import unittest

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


class TestLabelWall(unittest.TestCase):
    def test_import_refuses_shadow_project(self):
        name = sorted(reference.shadow_names())[0]
        rows = [{"project": name, "file": "x.c", "line": "1", "rule": "EXP33-C", "verdict": "TP"}]
        args = argparse.Namespace(csv="batch.csv", allow_unknown_rule=False)
        with self.assertRaises(SystemExit):
            _validate_label_rows(rows, args)


if __name__ == "__main__":
    unittest.main()
