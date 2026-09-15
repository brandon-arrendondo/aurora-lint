"""bench/juliet_coverage.py against a real (seeded, temp-file) BenchDB.

Pure-function pieces (`_cwe_description`, `_categorize`) are tested directly;
`render_juliet_coverage` is exercised against a real `bench.db.BenchDB`
rather than a hand-rolled fixture object, so a shape drift in `get_run_
summary`/`get_cwe_detail`/`get_rule_totals` shows up here instead of only at
the benchmarking_db cross-repo seam (see that repo's
tests/test_render_docs_contract.py for why a fixture is the wrong tool for
this kind of bug).
"""

import tempfile
import unittest
from pathlib import Path

from bench.db import BenchDB
from bench.juliet_coverage import _categorize, _cwe_description, render_juliet_coverage


class TestCweDescription(unittest.TestCase):
    def test_splits_dir_name(self):
        self.assertEqual(
            _cwe_description("CWE121_Stack_Based_Buffer_Overflow"),
            "Stack Based Buffer Overflow",
        )

    def test_no_underscore_returns_as_is(self):
        self.assertEqual(_cwe_description("CWE121"), "CWE121")


class TestCategorize(unittest.TestCase):
    def _row(self, cwe_id, tp, fp, file_count=10, per_file_rate=0.0):
        total = tp + fp
        return {
            "cwe_id": cwe_id, "cwe_dir_name": f"{cwe_id}_X",
            "file_count": file_count, "tp_count": tp, "fp_count": fp,
            "tp_rate_pct": round(tp / total * 100, 1) if total else 0,
            "per_file_rate": per_file_rate,
        }

    def test_buckets_by_precision(self):
        rows = [
            self._row("CWE-1", 5, 0),     # perfect
            self._row("CWE-2", 6, 4),     # high (60%)
            self._row("CWE-3", 4, 6),     # medium (40%)
            self._row("CWE-4", 1, 9),     # low (10%)
            self._row("CWE-5", 0, 3),     # zero
        ]
        buckets = _categorize(rows)
        self.assertEqual([c["cwe_id"] for c in buckets["perfect"]], ["CWE-1"])
        self.assertEqual([c["cwe_id"] for c in buckets["high"]], ["CWE-2"])
        self.assertEqual([c["cwe_id"] for c in buckets["medium"]], ["CWE-3"])
        self.assertEqual([c["cwe_id"] for c in buckets["low"]], ["CWE-4"])
        self.assertEqual([c["cwe_id"] for c in buckets["zero"]], ["CWE-5"])


class TestRenderJulietCoverage(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.db = BenchDB(Path(self._tmpdir.name) / "test.db")
        self.run_id = "sqc-0.0.0-deadbeef"
        self.db.create_run(
            self.run_id, sqc_version="0.0.0", commit_sha="deadbeef",
            mode="fast", started_at="2026-01-01T00:00:00Z", pid=1, jobs=1,
            total_cwes=3, machine={})
        self.db.finish_run(self.run_id, "completed", "2026-01-01T00:00:00Z")

        # CWE-1: perfect precision, one rule.
        scan1 = self.db.create_cwe_scan(self.run_id, "CWE-1", "CWE1_Perfect", 10)
        self.db.update_cwe_scan(scan1, status="completed")
        self.db.insert_cwe_metrics({
            "cwe_scan_id": scan1, "tp_count": 5, "fp_count": 0,
            "tp_rate_pct": 100.0, "per_file_rate": 50.0, "per_file_detected": 5,
            "per_file_total": 10, "cwe_matched_tp": 5, "cwe_matched_fp": 0,
        })
        self.db.insert_rule_breakdown([
            {"cwe_scan_id": scan1, "rule_id": "MEM31-C", "tp_count": 5,
             "fp_count": 0, "is_cwe_matched": 1},
        ])

        # CWE-2: zero detection, but a rule is mapped and found FPs only.
        scan2 = self.db.create_cwe_scan(self.run_id, "CWE-2", "CWE2_Zero", 8)
        self.db.update_cwe_scan(scan2, status="completed")
        self.db.insert_cwe_metrics({
            "cwe_scan_id": scan2, "tp_count": 0, "fp_count": 3,
            "tp_rate_pct": 0.0, "per_file_rate": 0.0,
        })
        self.db.insert_rule_breakdown([
            {"cwe_scan_id": scan2, "rule_id": "MEM31-C", "tp_count": 0,
             "fp_count": 3, "is_cwe_matched": 1},
        ])

        # CWE-3: zero detection, no rule mapped at all.
        scan3 = self.db.create_cwe_scan(self.run_id, "CWE-3", "CWE3_Unmapped", 4)
        self.db.update_cwe_scan(scan3, status="completed")
        self.db.insert_cwe_metrics({
            "cwe_scan_id": scan3, "tp_count": 0, "fp_count": 0,
            "tp_rate_pct": 0.0, "per_file_rate": 0.0,
        })

    def test_renders_without_crashing_and_includes_source_note(self):
        text = render_juliet_coverage(self.db, self.run_id, "Auto-generated from a test fixture.")
        self.assertIn("Auto-generated from a test fixture.", text)
        self.assertIn("aurora-lint v0.0.0", text)

    def test_perfect_cwe_lands_in_the_right_table(self):
        text = render_juliet_coverage(self.db, self.run_id, "note")
        self.assertIn("## 100% Precision (1 CWEs — zero FP)", text)
        self.assertIn("CWE-1 | Perfect", text)

    def test_zero_detection_distinguishes_mapped_from_unmapped(self):
        text = render_juliet_coverage(self.db, self.run_id, "note")
        self.assertIn("CWE-2 | Zero | 8 | 0 TP, 3 FP", text)
        self.assertIn("CWE-3 | Unmapped | 4 | No rule mapped", text)

    def test_top_rules_includes_the_mapped_rule_with_its_primary_cwe(self):
        text = render_juliet_coverage(self.db, self.run_id, "note")
        self.assertIn("MEM31-C | 5 | 3", text)
        self.assertIn("CWE-1", text.split("## Top Rules by TP Volume")[1])


if __name__ == "__main__":
    unittest.main()
