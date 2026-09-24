"""scripts/sarif_convert.py: the spreadsheet view of an aurora-lint SARIF report.

The tool writes only SARIF; CSV/XLSX rows are rebuilt from it here, so these
tests pin that every field a row used to take from the scanned tree (rule
description, source line, file hash) is read back out of the report, and
that suppressed findings stay out unless asked for.
"""

import csv
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import sarif_convert  # noqa: E402

SHA = "0123456789abcdef" * 4


def result(line, snippet=None, suppressed=False, review=False):
    region = {"startLine": line, "startColumn": 1}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    r = {
        "ruleId": "MSC04-C",
        "ruleIndex": 0,
        "message": {"text": "finding message"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/a.c", "index": 0},
            "region": region,
        }}],
    }
    if suppressed:
        r["suppressions"] = [{"kind": "inSource", "justification": "ok"}]
    if review:
        r["properties"] = {"requiresManualReview": True}
    return r


def report(*results):
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {
            "name": "aurora-lint",
            "rules": [{"id": "MSC04-C", "shortDescription": {"text": "Rule description"}}],
        }},
        "artifacts": [{"location": {"uri": "src/a.c"}, "hashes": {"sha-256": SHA}}],
        "results": list(results),
    }]}


class SarifRowsTest(unittest.TestCase):
    def test_row_is_rebuilt_from_the_report_alone(self):
        [row] = sarif_convert.sarif_rows(report(result(7, "infinite();")))
        self.assertEqual(row, [
            "MSC04-C:src/a.c:7 version:01234567",
            "MSC04-C - Rule description: infinite();",
            "Bug", "Proposed", "1 - Critical", "1",
            "aurora-lint",
        ])

    def test_missing_snippet_and_hash_degrade_rather_than_fail(self):
        sarif = report(result(7))
        del sarif["runs"][0]["artifacts"][0]["hashes"]
        [row] = sarif_convert.sarif_rows(sarif)
        self.assertTrue(row[0].endswith("version:unknown"))
        self.assertTrue(row[1].endswith("(line not found)"))

    def test_manual_review_marks_title_and_description(self):
        [row] = sarif_convert.sarif_rows(report(result(7, "x;", review=True)))
        self.assertTrue(row[0].startswith("[NEEDS MANUAL REVIEW] "))
        self.assertIn("review before acting", row[1])

    def test_suppressed_findings_are_opt_in(self):
        sarif = report(result(1, "a;"), result(2, "b;", suppressed=True))
        self.assertEqual(len(sarif_convert.sarif_rows(sarif)), 1)
        self.assertEqual(len(sarif_convert.sarif_rows(sarif, include_suppressed=True)), 2)


class CsvOutputTest(unittest.TestCase):
    def test_csv_has_headers_then_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.csv"
            sarif_convert.write_csv(sarif_convert.sarif_rows(report(result(7, "x;"))), out)
            with out.open(newline="") as f:
                rows = list(csv.reader(f))
        self.assertEqual(rows[0], sarif_convert.HEADERS)
        self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
