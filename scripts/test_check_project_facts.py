"""check_project_facts.py: a commit must not depend on gitignored local state.

docs/test-summary.md is generated and gitignored, so a copy made before a
rule-count change goes stale on that machine alone. The hook skips it,
saying so, and `--generated` (run by CI right after `cargo test`) checks it.
Tracked docs are checked as before.
"""

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_project_facts as facts

# 120 rules, 118 enabled: the count patterns match three-digit numbers.
TRACKED, ENABLED = 120, 118
MANIFEST = "".join(
    f"[rules.cert_c.ABC{i:02d}-C]\nenabled = {'true' if i < ENABLED else 'false'}\n\n"
    for i in range(TRACKED))


def _summary(tracked, enabled):
    return f"# Test Summary\n\n- **Tracked Rules:** {tracked}\n- **Enabled By Default:** {enabled}\n"


class TrackedOnlyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "rules_templates").mkdir()
        (self.root / "docs").mkdir()
        (self.root / "rules_templates" / "rules-all.toml").write_text(MANIFEST)
        (self.root / "docs" / "index.rst").write_text(f"There are {TRACKED} tracked rules.\n")
        (self.root / ".gitignore").write_text("/docs/test-summary.md\n")
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        for cmd in (["init", "-q"], ["add", "."]):
            subprocess.run(["git", "-C", str(self.root), *cmd], check=True, env=env)
        self._patches = [
            mock.patch.object(facts, "ROOT", self.root),
            mock.patch.object(facts, "MANIFEST", self.root / "rules_templates" / "rules-all.toml"),
            mock.patch.object(facts, "REMOVED", self.root / "rules_templates" / "removed-rules.toml"),
            mock.patch.object(facts, "TARGETS", ["docs/index.rst", "docs/test-summary.md"]),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        self._tmp.cleanup()

    def _lint(self, **kw):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = facts.lint(**kw)
        return code, out.getvalue()

    def _write_summary(self, tracked, enabled):
        (self.root / "docs" / "test-summary.md").write_text(_summary(tracked, enabled))

    def test_a_stale_untracked_summary_does_not_block_the_commit(self):
        self._write_summary(TRACKED + 2, ENABLED + 2)
        code, out = self._lint()
        self.assertEqual(code, 0)
        self.assertIn("docs/test-summary.md: not tracked by git, so not checked here; "
                      "regenerate it with `cargo test", out)

    def test_generated_checks_the_summary(self):
        self._write_summary(TRACKED + 2, ENABLED + 2)
        code, out = self._lint(include_generated=True)
        self.assertEqual(code, 1)
        self.assertIn(f"docs/test-summary.md:3  says {TRACKED + 2} tracked", out)

    def test_generated_passes_a_fresh_summary(self):
        self._write_summary(TRACKED, ENABLED)
        self.assertEqual(self._lint(include_generated=True)[0], 0)

    def test_a_tracked_doc_is_still_checked(self):
        (self.root / "docs" / "index.rst").write_text(f"There are {TRACKED + 1} tracked rules.\n")
        code, out = self._lint()
        self.assertEqual(code, 1)
        self.assertIn(f"docs/index.rst:1  says {TRACKED + 1} tracked", out)

    def test_without_git_every_target_is_checked(self):
        self._write_summary(TRACKED + 2, ENABLED + 2)
        with mock.patch.object(facts.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(self._lint()[0], 1)


if __name__ == "__main__":
    unittest.main()
