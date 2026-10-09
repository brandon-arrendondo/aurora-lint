"""`bench realworld-run` exits nonzero when a requested scan did not complete.

A scan that fails to start (a missing compile-database cache) is reported on a
line of the log and was otherwise invisible: the command exited 0, so a queue
worker or CI read a run that scanned nothing as a success.
"""

import argparse
import contextlib
import io
import unittest
from unittest import mock

from bench import __main__ as cli
from bench import realworld_runner


def _ok(codebase, tool="sqc"):
    return {"tool": tool, "codebase": codebase, "ok": True}


def _bad(codebase, tool="sqc"):
    return {"tool": tool, "codebase": codebase, "ok": False,
            "error": "boom", "duration_s": None, "total": 0}


class TestScanExitCode(unittest.TestCase):
    def test_none_failed(self):
        self.assertEqual(realworld_runner.scan_exit_code([_ok("a"), _ok("b")]), 0)
        self.assertEqual(realworld_runner.failure_summary([_ok("a")]), "")

    def test_all_failed(self):
        results = [_bad("a"), _bad("b")]
        self.assertEqual(realworld_runner.scan_exit_code(results),
                         realworld_runner.EXIT_NOTHING_RAN)
        self.assertEqual(realworld_runner.failure_summary(results),
                         "no scan completed: sqc:a, sqc:b")

    def test_some_failed(self):
        results = [_ok("a"), _bad("b", "cppcheck")]
        self.assertEqual(realworld_runner.scan_exit_code(results),
                         realworld_runner.EXIT_PARTIAL)
        self.assertEqual(realworld_runner.failure_summary(results),
                         "1 of 2 scans did not complete: cppcheck:b")

    def test_partial_and_nothing_ran_codes_are_distinct_and_not_reserved(self):
        codes = {realworld_runner.EXIT_NOTHING_RAN, realworld_runner.EXIT_PARTIAL}
        self.assertEqual(len(codes), 2)
        # 1 is an ingest failure, 3 is aurora-lint's incomplete-scan code.
        self.assertFalse(codes & {0, 1, 3})


class TestRealworldRunCommand(unittest.TestCase):
    def _run(self, results, ingest_error=None):
        args = argparse.Namespace(tool="sqc", codebase="libcrc", header_tree=None,
                                  dirs_out=None, compile_commands=False,
                                  profile="default")
        summary = {"results": results, "ingest_error": ingest_error}
        out = io.StringIO()
        with mock.patch.object(realworld_runner, "run_and_ingest",
                               return_value=summary), \
             mock.patch.object(realworld_runner, "_get_git_sha", return_value="abc"), \
             mock.patch("bench.config.require_known_commit"), \
             contextlib.redirect_stdout(out):
            try:
                cli.cmd_realworld_run(args)
                code = 0
            except SystemExit as e:
                code = e.code
        return code, out.getvalue()

    def test_none_failed_exits_zero(self):
        code, out = self._run([_ok("libcrc")])
        self.assertEqual(code, 0)
        self.assertNotIn("FAILED", out)

    def test_all_failed_exits_two_and_names_the_codebase(self):
        code, out = self._run([_bad("libcrc")])
        self.assertEqual(code, 2)
        self.assertIn("FAILED: no scan completed: sqc:libcrc", out)

    def test_some_failed_exits_four(self):
        code, out = self._run([_ok("lua"), _bad("libcrc")])
        self.assertEqual(code, 4)
        self.assertIn("sqc:libcrc", out)

    def test_ingest_failure_alone_still_exits_one(self):
        code, _ = self._run([_ok("libcrc")], ingest_error="db locked")
        self.assertEqual(code, 1)

    def test_unknown_codebase_or_tool_exits_two(self):
        for kw in ({"codebase": "nonesuch"}, {"tool": "nonesuch"}):
            args = argparse.Namespace(tool="sqc", codebase="libcrc",
                                      header_tree=None, dirs_out=None,
                                      compile_commands=False, profile="default")
            for k, v in kw.items():
                setattr(args, k, v)
            with contextlib.redirect_stdout(io.StringIO()), \
                 self.assertRaises(SystemExit) as cm:
                cli.cmd_realworld_run(args)
            self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
