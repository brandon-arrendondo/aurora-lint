"""A Juliet submission may pass --allow-empty only if it is all C++ variants.

Some submissions hold only Juliet's C++ variants, and a scan that skips all of
them exits 3 without the flag, which leaves the whole run unscored. Passing the
flag anywhere else would hide a submission that really did select nothing.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bench import runner


class TestShardAllowEmpty(unittest.TestCase):
    def _cmd(self, *files):
        done = subprocess.CompletedProcess([], 1, b"", b"stop")
        with tempfile.TemporaryDirectory() as d:
            for name in files:
                path = Path(d) / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            with mock.patch.object(runner.subprocess, "run", return_value=done) as run:
                runner._scan_one_shard("CWE1_Test", "CWE-1", d, d, "m.toml", 1)
        return run.call_args.args[0]

    def test_only_cpp_files_and_headers_are_accepted_as_empty(self):
        self.assertIn("--allow-empty", self._cmd("a.cpp", "a.h"))

    def test_a_directory_with_a_c_file_keeps_the_guard(self):
        self.assertNotIn("--allow-empty", self._cmd("a.cpp", "a.h", "b.c"))

    def test_an_unsplit_cwe_counts_the_c_files_in_its_shard_dirs(self):
        self.assertNotIn("--allow-empty", self._cmd("s01/a.cpp", "s02/b.c"))

    def test_an_unsplit_cwe_of_only_cpp_shard_dirs_is_accepted_as_empty(self):
        self.assertIn("--allow-empty", self._cmd("s01/a.cpp", "s02/b.cpp"))

    def test_an_empty_submission_keeps_the_guard(self):
        self.assertNotIn("--allow-empty", self._cmd())

    def test_a_submission_of_only_headers_keeps_the_guard(self):
        self.assertNotIn("--allow-empty", self._cmd("a.h"))


if __name__ == "__main__":
    unittest.main()
