"""Juliet flaw-line scoring in bench/analyzer.py, through to the stored rows.

The flaw-line units (ADR-0005: a Juliet hit means "fired in the flawed
function", the flaw-line rate says whether it named the flaw) once read 0
for every rule in every run: the scorer took the `FLAW:` comment's own line
as the flaw, and no rule reports on a comment. These tests pin the flaw to
the code the comment annotates, and check that a hit survives into the db.
"""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from bench.analyzer import _flaw_target_line, analyze_cwe, parse_c_file_sections
from bench.db import BenchDB

# A Juliet-shaped file. Line numbers matter; they're asserted below.
JULIET_FILE = """\
#include <stdio.h>

#ifndef OMITBAD

void CWE999_Example__bad()
{
    char *data = NULL;
    /* FLAW: a one-line flaw comment */
    data = getenv("X");
    {
        /* POTENTIAL FLAW: a flaw comment that
         * spans two lines */
        system(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

static void goodG2B()
{
    char *data = "ls";
    {
        /* POTENTIAL FLAW: the sink is the same, but the source is fixed */
        system(data);
    }
}

#endif /* OMITGOOD */
"""
BAD_FLAW_1 = 9    # data = getenv("X");
BAD_FLAW_2 = 13   # system(data);   (two lines below its comment)
GOOD_SINK = 26    # system(data);   in goodG2B: not a flaw


class TestFlawTarget(unittest.TestCase):
    def test_comment_above_code(self):
        lines = ["/* FLAW: x */\n", "    f();\n"]
        self.assertEqual(_flaw_target_line(lines, 1), 2)

    def test_multiline_comment_targets_code_after_it_closes(self):
        lines = ["/* POTENTIAL FLAW: a\n", " * b */\n", "\n", "    f();\n"]
        self.assertEqual(_flaw_target_line(lines, 1), 4)

    def test_trailing_comment_targets_its_own_line(self):
        lines = ["    f(); /* FLAW: x */\n", "    g();\n"]
        self.assertEqual(_flaw_target_line(lines, 1), 1)

    def test_skips_a_second_comment_block(self):
        lines = ["/* FLAW: x */\n", "/* more\n", " text */\n", "    f();\n"]
        self.assertEqual(_flaw_target_line(lines, 1), 4)


class TestFlawLineScoring(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.cwe_dir = root / "CWE999_Example"
        self.cwe_dir.mkdir()
        self.c_file = self.cwe_dir / "CWE999_Example__a_01.c"
        self.c_file.write_text(JULIET_FILE)
        self.report = root / "report.json"

    def _report(self, *hits):
        self.report.write_text(json.dumps([
            {"file": str(self.c_file), "line": line, "rule_id": rule}
            for rule, line in hits
        ]))

    def test_flaw_lines_are_the_bad_section_code_lines(self):
        sections = parse_c_file_sections(self.c_file)
        self.assertEqual(sections['flaw_lines'], {BAD_FLAW_1, BAD_FLAW_2})
        self.assertNotIn(GOOD_SINK, sections['flaw_lines'])

    def test_hits_count_distinct_flaw_lines(self):
        # Two rules on one flaw line, one rule one line off the other, one
        # finding in the good function.
        self._report(("ENV33-C", BAD_FLAW_2), ("ENV03-C", BAD_FLAW_2),
                     ("ENV03-C", BAD_FLAW_1 + 1), ("ENV33-C", GOOD_SINK))
        a = analyze_cwe(self.report, self.cwe_dir)

        self.assertEqual(a.flaw_lines_total, 2)
        self.assertEqual(a.flaw_lines_detected, 2)
        self.assertEqual(a.rule_breakdown["ENV03-C"]["flaw"], 2)
        self.assertEqual(a.rule_breakdown["ENV33-C"]["flaw"], 1)
        # A rate never passes 100%, however many rules pile onto a line.
        self.assertLessEqual(a.flaw_detection_rate_pct, 100.0)

    def test_a_hit_is_stored_nonzero(self):
        self._report(("ENV33-C", BAD_FLAW_2))
        a = analyze_cwe(self.report, self.cwe_dir)

        db_path = Path(self._tmp.name) / "bench.db"
        db = BenchDB(db_path)
        run_id = "sqc-0.0.0-deadbeef"
        db.create_run(run_id, sqc_version="0.0.0", commit_sha="deadbeef",
                      mode="fast", started_at="2026-01-01T00:00:00Z", pid=1,
                      jobs=1, total_cwes=1, machine={})
        scan = db.create_cwe_scan(run_id, "CWE-999", self.cwe_dir.name, 1)
        db.insert_cwe_metrics({
            "cwe_scan_id": scan, "tp_count": a.tp_count, "fp_count": a.fp_count,
            "tp_rate_pct": a.tp_rate_pct,
            "flaw_lines_total": a.flaw_lines_total,
            "flaw_lines_detected": a.flaw_lines_detected,
            "flaw_detection_rate_pct": a.flaw_detection_rate_pct,
            "cwe_matched_tp": a.cwe_matched_tp, "cwe_matched_fp": a.cwe_matched_fp,
            "noise_count": a.noise_count, "noise_ratio": a.noise_ratio,
            "per_file_detected": a.per_file_detected,
            "per_file_total": a.per_file_total, "per_file_rate": a.per_file_rate,
            "flaw_hit_detected": a.flaw_hit_detected,
            "flaw_hit_total": a.flaw_hit_total, "flaw_hit_rate": a.flaw_hit_rate,
        })
        db.insert_rule_breakdown([
            {"cwe_scan_id": scan, "rule_id": r, "tp_count": c["tp"],
             "fp_count": c["fp"], "flaw_line_count": c["flaw"],
             "is_cwe_matched": c["is_cwe_matched"]}
            for r, c in a.rule_breakdown.items()
        ])

        con = sqlite3.connect(db_path)
        (flaw,) = con.execute(
            "SELECT flaw_line_count FROM rule_cwe_breakdown WHERE rule_id = 'ENV33-C'"
        ).fetchone()
        (detected,) = con.execute(
            "SELECT flaw_lines_detected FROM cwe_metrics WHERE cwe_scan_id = ?", (scan,)
        ).fetchone()
        con.close()
        self.assertEqual(flaw, 1)
        self.assertEqual(detected, 1)

    def test_a_missing_key_is_an_error_not_zero(self):
        db = BenchDB(Path(self._tmp.name) / "bench.db")
        with self.assertRaises(KeyError):
            db.insert_rule_breakdown([
                {"cwe_scan_id": 1, "rule_id": "ENV33-C", "tp_count": 1,
                 "fp_count": 0, "is_cwe_matched": 1},  # no flaw_line_count
            ])
        with self.assertRaises(KeyError):
            db.insert_cwe_metrics({"cwe_scan_id": 1, "tp_count": 1, "fp_count": 0})


if __name__ == "__main__":
    unittest.main()
