"""check_realworld_manifests.py: a disable needs its reason written down.

A comment in or above the rule's block states it, and so does a non-empty
``disabled_reason``, which the tool itself prints. A bare
``enabled = false`` is still flagged.
"""

import tempfile
import unittest
from pathlib import Path

import check_realworld_manifests as check


class UndocumentedDisableTests(unittest.TestCase):
    def _flagged(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x-rules.toml"
            path.write_text(text)
            return check.undocumented_disables(path)

    def test_a_disabled_reason_documents_a_disable(self):
        self.assertEqual(self._flagged(
            '[rules.cert_c.ARR30-C]\nenabled = false\n'
            'disabled_reason = "categorically inapplicable: no arrays"\n'), [])

    def test_a_bare_disable_is_still_flagged(self):
        self.assertEqual(self._flagged(
            '[rules.cert_c.ARR30-C]\nenabled = false\n'
            'disabled_reason = "x"\n\n'
            '[rules.cert_c.STR31-C]\nenabled = false\n'), ["STR31-C"])

    def test_an_empty_disabled_reason_states_nothing(self):
        self.assertEqual(self._flagged(
            '[rules.cert_c.ARR30-C]\nenabled = false\ndisabled_reason = " "\n'),
            ["ARR30-C"])

    def test_a_comment_still_documents_a_disable(self):
        self.assertEqual(self._flagged(
            '# dead config: no implementation yet\n'
            '[rules.cert_c.ARR30-C]\nenabled = false\n'), [])


if __name__ == "__main__":
    unittest.main()
