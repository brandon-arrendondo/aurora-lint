"""bench/incomplete.py reads the failure lines aurora-lint prints when it
exits 3 (ADR-0017). The lines below are copied from the binary's output, so a
change to their format fails here instead of silently emptying a run's
scan_failures."""

import unittest

from bench.incomplete import merge_not_converged, parse_failures, parse_not_converged, summary

LOG = """\
src/a.c:2:34: [medium] STR31-C: Potential buffer overflow with strcpy().
Total violations: 1 (0 suppressed)
Error: rule failure (crashed): MEM35-C: /scan/x/f1.c: begin > end (16 > 11) when slicing `sizeof *new) + (sizeof p)` [at src/rules/cert_c/MEM/MEM35-C/mem35_c.rs:180:50]
Error: rule failure (step limit): STR31-C: /scan/x/f2.c: stopped after 1000 steps (--rule-step-limit) [at src/analyze/containment.rs:247:13]
Error: file failure (crashed): /scan/x/f3.c: index out of bounds [at src/analyze/cfg.rs:10:5]
Error: prescan failure (time limit): /scan/x/h.h: stopped after 300s (--rule-time-limit)
Error: input skipped (not source text): /scan/x/blob.c: starts like an ELF binary
Error: rule abandoned: MEM35-C: failed on 3 or more files; none of its findings are reported
Error: scan INCOMPLETE: 4 unit(s) of work did not finish in 4 file(s) (rules MEM35-C, STR31-C); ...
"""


class TestParseFailures(unittest.TestCase):
    def test_every_kind_of_line(self):
        f = parse_failures(LOG)
        self.assertEqual([x["stage"] for x in f],
                         ["rule", "rule", "file", "prescan", "input", "abandoned"])
        self.assertEqual(f[0]["rule"], "MEM35-C")
        self.assertEqual(f[0]["file"], "/scan/x/f1.c")
        self.assertEqual(f[0]["cause"], "crashed")
        self.assertIn("begin > end", f[0]["message"])
        self.assertEqual(f[0]["location"], "src/rules/cert_c/MEM/MEM35-C/mem35_c.rs:180:50")
        self.assertEqual(f[1]["cause"], "step limit")
        self.assertIsNone(f[2]["rule"])
        self.assertEqual(f[2]["file"], "/scan/x/f3.c")
        self.assertIsNone(f[3]["location"])
        self.assertEqual(f[4]["file"], "/scan/x/blob.c")
        self.assertEqual(f[4]["cause"], "not source text")
        self.assertEqual(f[5]["rule"], "MEM35-C")

    def test_a_clean_log_has_none(self):
        self.assertEqual(parse_failures("Total violations: 3 (0 suppressed)\n"), [])

    def test_summary(self):
        self.assertEqual(
            summary(parse_failures(LOG)),
            "INCOMPLETE: 5 failure(s) (rules MEM35-C, STR31-C), abandoned: MEM35-C")


class TestNotConverged(unittest.TestCase):
    def test_counts_are_read_and_merged(self):
        log = ("Warning: value-range analysis did not converge 2 time(s); results there may be incomplete (a known issue, see docs/error-handling.rst)\n"
               "Warning: the initialization-state worklist did not converge 1 time(s); results there may be incomplete (a known issue, see docs/error-handling.rst)\n")
        got = parse_not_converged(log)
        self.assertEqual(got, {"value-range analysis": 2,
                               "the initialization-state worklist": 1})
        self.assertEqual(merge_not_converged(dict(got), {"value-range analysis": 3}),
                         {"value-range analysis": 5,
                          "the initialization-state worklist": 1})
        self.assertEqual(parse_not_converged("Total violations: 1\n"), {})


if __name__ == "__main__":
    unittest.main()
