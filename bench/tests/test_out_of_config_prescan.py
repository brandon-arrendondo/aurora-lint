"""hostap's prescan-only exclusions are its out-of-configuration files.

data/benchmark_repos.json names the in-scope files outside a corpus's primary
build configuration (`primary_build_config.out_of_config`, ADR-0010); the
runner keeps hostap's out of the cross-file prescan with --prescan-exclude, so
another configuration's definitions (os_none.c's empty os_free) do not decide
what the Linux build's code is judged by. The two lists are written in two
places and must name the same files: one added to the declaration and not the
runner would quietly feed the prescan again, and one excluded without being
declared out of configuration would hide a definition the build links.

--prescan-exclude only: the files are still scanned and reported, so neither
--exclude-all nor --report-exclude may name them.
"""

import unittest

from bench import corpus
from bench import realworld_runner as rr


def _flag_values(args, flag):
    return [args[i + 1] for i in range(len(args) - 1) if args[i] == flag]


class TestHostapOutOfConfigPrescan(unittest.TestCase):
    def setUp(self):
        repo = next(r for r in corpus.load_repos() if r["name"] == "hostap")
        self.out_of_config = repo["primary_build_config"]["out_of_config"]
        self.args = rr.CODEBASES["hostap"]["sqc"]["extra_args"]

    def test_prescan_excludes_are_exactly_the_out_of_config_files(self):
        self.assertEqual(
            sorted(_flag_values(self.args, "--prescan-exclude")),
            sorted(self.out_of_config),
        )

    def test_out_of_config_files_are_still_scanned_and_reported(self):
        excluded = set(_flag_values(self.args, "--exclude-all"))
        excluded |= set(_flag_values(self.args, "--report-exclude"))
        excluded |= set(_flag_values(self.args, "--exclude"))
        patterns = rr._sqc_exclude_patterns(rr.CODEBASES["hostap"])
        for path in self.out_of_config:
            self.assertNotIn(path, excluded)
            self.assertFalse(
                any(p.search(path) for p in patterns),
                f"{path} would no longer be reported",
            )


if __name__ == "__main__":
    unittest.main()
