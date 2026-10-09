"""bench/corpus.py: corpus-check's submodule verification.

A pinned superproject commit records each submodule's commit, but a clone
that skips `git submodule update --init` sits on the right commit with the
submodule directory empty -- the state that broke mbedtls's compile-database
build. These tests build a real superproject with one submodule in a temporary
directory and check every state corpus-check reports.
"""

import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bench import corpus

# Local file:// submodule URLs are refused by default since git 2.38.1, and
# the commits need an identity that does not depend on the machine's config.
GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "protocol.file.allow", "GIT_CONFIG_VALUE_0": "always",
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(cwd, *args):
    return subprocess.run(["git", "-C", str(cwd), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def _commit(repo, rel, text):
    (repo / rel).write_text(text)
    _git(repo, "add", rel)
    _git(repo, "commit", "-q", "-m", rel)
    return _git(repo, "rev-parse", "HEAD")


class TestSubmodules(unittest.TestCase):
    def setUp(self):
        self._env = mock.patch.dict(os.environ, GIT_ENV)
        self._env.start()
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        self.bench = tmp / "bench"
        self.bench.mkdir()

        self.sub_src = tmp / "fw"
        self.sub_src.mkdir()
        _git(self.sub_src, "init", "-q")
        self.sub_old = _commit(self.sub_src, "a.py", "old\n")
        self.sub_pin = _commit(self.sub_src, "a.py", "new\n")

        up = tmp / "upstream"
        up.mkdir()
        _git(up, "init", "-q")
        _commit(up, "main.c", "int main(void) { return 0; }\n")
        _git(up, "submodule", "add", "-q", str(self.sub_src), "framework")
        _git(up, "commit", "-q", "-m", "submodule")
        self.pin = _git(up, "rev-parse", "HEAD")

        # Cloned the way provisioning clones: detached at the pin, and the
        # submodule left uninitialised until a test asks for it.
        self.repo = self.bench / "proj"
        _git(tmp, "clone", "-q", str(up), str(self.repo))
        _git(self.repo, "checkout", "-q", "--detach", self.pin)
        self.entry = {"name": "proj", "version": self.pin,
                      "submodules": ["framework"]}

    def tearDown(self):
        self._tmp.cleanup()
        self._env.stop()

    def _init(self):
        _git(self.repo, "submodule", "update", "-q", "--init", "--", "framework")

    def _check(self, entry=None):
        return corpus.check_repo(entry or self.entry, self.bench)

    def _status(self, entry=None):
        return [(s["path"], s["status"]) for s in self._check(entry)["submodules"]]

    def _report(self, entry=None):
        out = io.StringIO()
        with mock.patch.object(corpus, "load_repos", return_value=[entry or self.entry]), \
                contextlib.redirect_stdout(out):
            code = corpus.report(bench_root=self.bench, mode="host")
        return code, out.getvalue()

    def test_initialised_at_the_gitlink_is_ok(self):
        self._init()
        r = self._check()
        self.assertEqual(r["status"], "OK")
        self.assertEqual(r["submodules"], [{"path": "framework", "expected": self.sub_pin,
                                            "head": self.sub_pin, "status": "OK"}])
        self.assertFalse(corpus.submodules_bad(r))
        self.assertEqual(self._report()[0], 0)

    def test_an_uninitialised_submodule_fails_with_the_fix_line(self):
        r = self._check()
        # The superproject itself is exactly at its pin and clean, which is
        # why this state went unnoticed before.
        self.assertEqual((r["status"], r["dirty"]), ("OK", 0))
        self.assertEqual(self._status(), [("framework", "UNINITIALIZED")])
        code, out = self._report()
        self.assertEqual(code, 1)
        self.assertIn(f"git -C {self.repo} submodule update --init -- framework", out)

    def test_a_submodule_at_another_commit_is_drifted_not_a_modified_file(self):
        self._init()
        _git(self.repo / "framework", "checkout", "-q", "--detach", self.sub_old)
        r = self._check()
        self.assertEqual(self._status(), [("framework", "DRIFTED")])
        self.assertEqual(r["submodules"][0]["head"], self.sub_old)
        self.assertEqual(r["dirty"], 0)
        self.assertEqual(self._report()[0], 1)

    def test_local_changes_inside_a_submodule_are_modified(self):
        self._init()
        (self.repo / "framework" / "a.py").write_text("edited\n")
        self.assertEqual(self._status(), [("framework", "MODIFIED")])
        self.assertEqual(self._check()["dirty"], 0)

    def test_untracked_files_inside_a_submodule_are_modified(self):
        self._init()
        (self.repo / "framework" / "gen.c").write_text("int x;\n")
        self.assertEqual(self._status(), [("framework", "MODIFIED")])

    def test_a_gitlink_the_entry_does_not_declare_fails(self):
        self._init()
        entry = {"name": "proj", "version": self.pin}
        self.assertEqual(self._status(entry), [("framework", "UNDECLARED")])
        code, out = self._report(entry)
        self.assertEqual(code, 1)
        self.assertIn("declare it under 'submodules'", out)

    def test_a_declared_path_the_pin_does_not_record_fails(self):
        self._init()
        entry = dict(self.entry, submodules=["framework", "vendor/x"])
        self.assertEqual(self._status(entry),
                         [("framework", "OK"), ("vendor/x", "NOT_IN_PIN")])
        self.assertEqual(self._report(entry)[0], 1)

    def test_a_pin_absent_locally_skips_the_submodule_check(self):
        entry = dict(self.entry, version="1" * 40)
        r = self._check(entry)
        self.assertEqual(r["status"], "PIN_ABSENT")
        self.assertEqual(r["submodules"], [])

    def test_a_corpus_without_submodules_reports_none(self):
        plain = self.bench / "plain"
        plain.mkdir()
        _git(plain, "init", "-q")
        sha = _commit(plain, "x.c", "int x;\n")
        _git(plain, "checkout", "-q", "--detach", sha)
        r = self._check({"name": "plain", "version": sha})
        self.assertEqual((r["status"], r["submodules"]), ("OK", []))


if __name__ == "__main__":
    unittest.main()
