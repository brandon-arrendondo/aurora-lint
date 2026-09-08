"""render_docs.replace_between -- the marker-bounded rewrite.

This function edits README.md in place. Everything outside the
`<!-- BENCH:*:START -->` / `:END` markers is hand-written prose that the tool
deliberately leaves alone, so the boundary IS the contract: a rewrite that
reached one character past it would put generated numbers into hand-written
text, or delete text nobody could get back from the generator.
"""

import unittest

from bench.render_docs import replace_between

BEGIN = "<!-- BENCH:HIGHLIGHTS:START -->"
END = "<!-- BENCH:HIGHLIGHTS:END -->"

DOC = f"""# Title

Hand-written intro that must not move.

{BEGIN}
| old | table |
{END}

Hand-written outro that must not move.
"""


class TestReplaceBetween(unittest.TestCase):
    def test_replaces_only_the_bounded_block(self):
        out = replace_between(DOC, BEGIN, END, "| new | table |")
        self.assertIn("Hand-written intro that must not move.", out)
        self.assertIn("Hand-written outro that must not move.", out)
        self.assertIn("| new | table |", out)
        self.assertNotIn("| old | table |", out)

    def test_markers_survive_the_rewrite(self):
        """They must, or the next refresh cannot find the block."""
        out = replace_between(DOC, BEGIN, END, "x")
        self.assertEqual(out.count(BEGIN), 1)
        self.assertEqual(out.count(END), 1)
        self.assertLess(out.index(BEGIN), out.index(END))

    def test_text_outside_the_block_is_byte_identical(self):
        out = replace_between(DOC, BEGIN, END, "| new | table |")
        self.assertEqual(DOC[:DOC.index(BEGIN)], out[:out.index(BEGIN)])
        self.assertEqual(DOC[DOC.index(END) + len(END):],
                         out[out.index(END) + len(END):])

    def test_is_idempotent_for_one_block(self):
        once = replace_between(DOC, BEGIN, END, "| new |")
        twice = replace_between(once, BEGIN, END, "| new |")
        self.assertEqual(once, twice)

    def test_missing_markers_raise_rather_than_silently_no_op(self):
        """A silent no-op would leave stale published numbers in place while
        the command reported success."""
        with self.assertRaises(ValueError):
            replace_between("# Title\n\nno markers here\n", BEGIN, END, "x")

    def test_markers_out_of_order_raise(self):
        with self.assertRaises(ValueError):
            replace_between(f"{END}\nbody\n{BEGIN}\n", BEGIN, END, "x")

    def test_only_the_first_block_is_rewritten(self):
        two = f"{BEGIN}\nA\n{END}\nmiddle\n{BEGIN}\nB\n{END}\n"
        out = replace_between(two, BEGIN, END, "NEW")
        self.assertIn("NEW", out)
        self.assertIn("B", out)
        self.assertNotIn("\nA\n", out)

    def test_backslashes_in_the_new_block_are_literal(self):
        """The substitution passes a function to re.sub precisely so the
        replacement is not scanned for backslash escapes. A plain string
        replacement would turn `\\g` into an error and `\\1` into a group
        reference, corrupting a table containing either."""
        block = r"| a\1 | b\g | c\\ |"
        out = replace_between(DOC, BEGIN, END, block)
        self.assertIn(block, out)
