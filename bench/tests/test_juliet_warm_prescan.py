"""A sharded CWE's warm prescan runs under the same settings as its shards.

The data model decides the limit macros and sizes a prescan evaluates, so the
binary refuses a cache built under another one; a warm pass that left out
JULIET_SETTING_OVERRIDES failed every shard that loaded it.
"""

import subprocess
import unittest
from unittest import mock

from bench import runner
from bench.config import JULIET_SETTING_OVERRIDES


class TestWarmPrescanSettings(unittest.TestCase):
    def _warm_cmd(self, profile):
        done = subprocess.CompletedProcess([], 1, b"", b"stop")
        with mock.patch.object(runner.subprocess, "run", return_value=done) as run:
            runner._warm_prescan("CWE1_Test", "/nonexistent", "m.toml",
                                 "/nonexistent/c.prescan", None, profile)
        return run.call_args.args[0]

    def test_warm_pass_carries_the_profile_and_every_override(self):
        cmd = self._warm_cmd("strict")
        self.assertEqual(cmd[cmd.index("--profile") + 1], "strict")
        sets = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--set"]
        self.assertEqual(sets, list(JULIET_SETTING_OVERRIDES))

    def test_warm_pass_and_shard_share_one_settings_list(self):
        self.assertEqual(runner._settings_args("default")[:2],
                         ["--profile", "default"])
        self.assertIn("data_model=lp64", runner._settings_args("default"))


if __name__ == "__main__":
    unittest.main()
