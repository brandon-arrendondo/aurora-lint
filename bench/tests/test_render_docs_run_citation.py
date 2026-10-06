"""render_docs.realworld_run_citation -- how the highlights name the run.

A release whose real-world scans split across settings groups is cited as
the set of runs it produced. benchmarking_db reads this phrase back as the
next release's baseline, so the set form must name exactly its members and
the single-run form must stay "run #N".
"""

import unittest

from bench.render_docs import realworld_run_citation


class TestRealworldRunCitation(unittest.TestCase):
    def test_single_run_keeps_the_hash_form(self):
        self.assertEqual(realworld_run_citation(265), "run #265")

    def test_consecutive_set_is_a_range(self):
        self.assertEqual(realworld_run_citation((409, 402, 403, 404, 405, 406, 407, 408)),
                         "runs 402-409 (one per settings group)")

    def test_gapped_set_is_listed_not_ranged(self):
        """A range over a gap would claim a run that is not a member."""
        self.assertEqual(realworld_run_citation([402, 405, 407]),
                         "runs 402,405,407 (one per settings group)")

    def test_set_of_one_is_that_run(self):
        self.assertEqual(realworld_run_citation((402, 402)), "run #402")


if __name__ == "__main__":
    unittest.main()
