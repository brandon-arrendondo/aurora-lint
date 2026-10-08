"""Exercise the commit hook through Git's real trailer parser."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from check_commit_message import AI_TOOL_NAMES


class CommitMessageTests(unittest.TestCase):
    def check_message(self, message, expected):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "message"
            path.write_text(message, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name("check_commit_message.py")),
                 str(path)], capture_output=True, text=True,
            )
        self.assertEqual(result.returncode, expected, result.stderr)

    def test_ai_trailers_are_rejected(self):
        for name in AI_TOOL_NAMES:
            for trailer in [f"Co-Authored-By: {name.lower()} (AI)",
                            f"{name}-Session: session-reference"]:
                with self.subTest(trailer=trailer):
                    self.check_message(f"Update guidance\n\n{trailer}\n", 1)

    def test_human_coauthors_are_allowed(self):
        for person in ["Alex Example <alex@google.com>",
                       "Sam Example <sam@microsoft.com>",
                       "Alex Example (Google)", "Sam Example (Microsoft)"]:
            with self.subTest(person=person):
                self.check_message(f"Update guidance\n\nCo-Authored-By: {person}\n", 0)

    def test_body_and_subject_mentions_are_allowed(self):
        for name in AI_TOOL_NAMES:
            with self.subTest(name=name):
                self.check_message(
                    f"docs: describe {name}\n\nExplain {name} in ordinary prose.\n", 0)

    def test_git_comments_are_ignored(self):
        self.check_message("Update guidance\n\n# Co-Authored-By: Codex\n", 0)

    def test_word_boundaries_allow_unrelated_names(self):
        self.check_message("Update guidance\n\nCo-Authored-By: Claudette Example\n", 0)


if __name__ == "__main__":
    unittest.main()
