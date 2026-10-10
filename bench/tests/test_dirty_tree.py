"""A run is labelled with HEAD (bench/config.py aurora_lint_commit), so a
working tree whose measured paths (config.DIRTY_PATHS) differ from HEAD is
refused, and with --allow-dirty is labelled <sha>+dirty<hash> instead of the
clean commit. container-run decides it on the host, where git can always
answer, and passes the hash in."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bench import config, container, runner
from bench.config import (ALLOW_DIRTY_ENV, COMMIT_ENV, COMMIT_SHORT_ENV, DIRTY_ENV,
                          DIRTY_MARK)

_CLEAN_ENV = {COMMIT_ENV: "", COMMIT_SHORT_ENV: "", DIRTY_ENV: "", ALLOW_DIRTY_ENV: ""}


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


@unittest.skipUnless(shutil.which("git"), "needs git")
class TestDirtyTree(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = Path(self._tmp.name)
        for rel in ("src/main.rs", "conf/realworld/x-rules.toml", "bench/runner.py",
                    "rust-toolchain.toml", ".cargo/config.toml",
                    "bench/tests/test_x.py", "docs/index.rst", "tests/fixture.c",
                    "data/benchmark_repos.json"):
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / rel).write_text("committed\n")
        (self.repo / ".gitignore").write_text("target/\n")
        _git(self.repo, "init", "-q")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-q", "-m", "c")
        self.full, self.short = config.host_commit(self.repo)
        env = mock.patch.dict(os.environ, _CLEAN_ENV)
        env.start()
        self.addCleanup(env.stop)

    def label(self):
        return config.aurora_lint_commit(self.repo)

    def test_a_clean_tree_is_labelled_with_its_commit(self):
        self.assertEqual(config.dirty_hash(self.repo), "")
        self.assertEqual(self.label(), self.short)

    def test_a_change_to_the_source_is_refused_by_name(self):
        (self.repo / "src/main.rs").write_text("edited\n")
        with self.assertRaisesRegex(ValueError, r"uncommitted changes(.|\n)*src/main\.rs"):
            self.label()

    def test_a_staged_change_and_an_untracked_file_are_refused(self):
        (self.repo / "conf/realworld/x-rules.toml").write_text("edited\n")
        _git(self.repo, "add", "conf")
        with self.assertRaises(ValueError):
            self.label()
        _git(self.repo, "reset", "-q", "--hard")
        (self.repo / "src/new_rule.toml").write_text("new\n")
        with self.assertRaisesRegex(ValueError, "src/new_rule.toml"):
            self.label()

    def test_the_toolchain_pin_and_cargo_config_are_measured(self):
        for rel in ("rust-toolchain.toml", ".cargo/config.toml"):
            (self.repo / rel).write_text("edited\n")
            with self.assertRaisesRegex(ValueError, rel.replace(".", r"\.")):
                self.label()
            _git(self.repo, "checkout", "-q", "--", rel)

    def test_the_hash_ignores_git_diff_configuration(self):
        (self.repo / "src/main.rs").write_text("edited\n")
        plain = config.dirty_hash(self.repo)
        for key, value in (("diff.noprefix", "true"), ("diff.mnemonicPrefix", "true"),
                           ("diff.relative", "true")):
            _git(self.repo, "config", key, value)
        self.assertEqual(config.dirty_hash(self.repo), plain)

    def test_changes_outside_what_a_run_measures_are_not_dirty(self):
        for rel in ("docs/index.rst", "tests/fixture.c", "bench/tests/test_x.py"):
            (self.repo / rel).write_text("edited\n")
        (self.repo / "notes.txt").write_text("untracked\n")
        (self.repo / "target").mkdir()
        (self.repo / "target/build.rs").write_text("ignored\n")
        self.assertEqual(self.label(), self.short)

    def test_allow_dirty_labels_the_run_and_the_label_follows_the_changes(self):
        (self.repo / "src/main.rs").write_text("edit one\n")
        with mock.patch.dict(os.environ, {ALLOW_DIRTY_ENV: "1"}):
            first = self.label()
            self.assertRegex(first, rf"^{self.short}\+dirty[0-9a-f]{{8}}$")
            self.assertEqual(self.label(), first)
            (self.repo / "src/main.rs").write_text("edit two\n")
            self.assertNotEqual(self.label(), first)
            # The label never names a clean commit's run id.
            self.assertNotEqual(self.label(), self.short)

    def test_an_unknown_commit_stays_unknown_when_dirty(self):
        with self.assertRaisesRegex(ValueError, "commit is unknown"):
            config.require_known_commit(f"unknown{DIRTY_MARK}0123abcd", "x")
        config.require_known_commit(f"{self.short}{DIRTY_MARK}0123abcd", "x")

    def test_a_passed_in_hash_must_agree_with_git(self):
        # Inside the container, where git can answer: the host's hash and
        # this tree's must be the same tree.
        (self.repo / "src/main.rs").write_text("edited\n")
        dirty = config.dirty_hash(self.repo)
        with mock.patch.dict(os.environ, {COMMIT_ENV: self.full, COMMIT_SHORT_ENV: self.short,
                                          ALLOW_DIRTY_ENV: "1"}):
            with mock.patch.dict(os.environ, {DIRTY_ENV: ""}):
                with self.assertRaisesRegex(ValueError, "disagrees with git"):
                    self.label()
            with mock.patch.dict(os.environ, {DIRTY_ENV: dirty}):
                self.assertEqual(self.label(), f"{self.short}{DIRTY_MARK}{dirty}")

    def test_where_git_cannot_answer_the_passed_in_hash_labels_the_run(self):
        with mock.patch.object(config, "host_commit", return_value=None), \
             mock.patch.dict(os.environ, {COMMIT_ENV: self.full, COMMIT_SHORT_ENV: self.short,
                                          DIRTY_ENV: "0123abcd", ALLOW_DIRTY_ENV: "1"}):
            self.assertEqual(self.label(), f"{self.short}{DIRTY_MARK}0123abcd")


class TestJulietRegeneration(unittest.TestCase):
    def _run(self, allow, git_sha):
        """run_benchmark up to the label, recording the order of the map's
        regeneration and the commit lookups."""
        calls = mock.Mock()
        calls.sha.side_effect = git_sha
        with mock.patch.dict(os.environ, {ALLOW_DIRTY_ENV: "1" if allow else ""}), \
             mock.patch.object(runner, "_get_git_sha", calls.sha), \
             mock.patch.object(runner, "_ensure_rule_cwe_map", calls.regenerate), \
             mock.patch.object(runner, "SQC_BIN", Path(__file__)), \
             mock.patch.object(runner, "JULIET_BASE", Path(__file__).parent), \
             mock.patch.object(runner, "_enumerate_cwes", return_value=["CWE78_x"]), \
             mock.patch.object(runner, "_get_sqc_version", side_effect=RuntimeError("labelled")):
            try:
                runner.run_benchmark()
            except RuntimeError:
                pass
        return [c[0] for c in calls.mock_calls]

    def test_a_clean_run_whose_regeneration_changes_committed_files_is_refused(self):
        # Clean, then the regenerated map makes the tree dirty, which
        # aurora_lint_commit refuses.
        with self.assertRaisesRegex(ValueError, "would not measure its commit"):
            self._run(False, ["abc1234", ValueError("uncommitted changes")])
        with self.assertRaisesRegex(ValueError, "would not measure its commit"):
            self._run(False, ["abc1234", "abc1234+dirty1"])
        self.assertEqual(self._run(False, ["abc1234", "abc1234"]),
                         ["sha", "regenerate", "sha"])

    def test_an_allow_dirty_run_is_labelled_after_the_regeneration(self):
        # A dirty change to a rule's CWE mapping: regenerating moves the
        # hash, so the label is taken once, after it, and not refused.
        self.assertEqual(self._run(True, ["abc1234+dirty0123abcd"]), ["regenerate", "sha"])


class TestContainerRun(unittest.TestCase):
    FULL, SHORT = "a" * 40, "aaaaaaa"

    def _run(self, run_args, dirty):
        with mock.patch("shutil.which", return_value="/usr/bin/podman"), \
             mock.patch.object(container, "host_commit", return_value=(self.FULL, self.SHORT)), \
             mock.patch.object(container, "dirty_hash", return_value=dirty), \
             mock.patch.object(container, "tree_changes", return_value=[" M src/main.rs"]), \
             mock.patch.object(container, "image_pin", return_value="p" * 64), \
             mock.patch.object(runner, "_ensure_rule_cwe_map") as self.regenerate, \
             mock.patch("subprocess.run") as run:
            run.return_value.returncode = 0
            rc = container.run(run_args, "img")
        return rc, run

    def test_a_juliet_run_regenerates_its_map_on_the_host_before_the_hash(self):
        order = mock.Mock()
        with mock.patch("shutil.which", return_value="/usr/bin/podman"), \
             mock.patch.object(container, "host_commit", return_value=(self.FULL, self.SHORT)), \
             mock.patch.object(runner, "_ensure_rule_cwe_map", order.regenerate), \
             mock.patch.object(container, "dirty_hash", order.hash), \
             mock.patch.object(container, "image_pin", return_value="p" * 64), \
             mock.patch("subprocess.run") as run:
            order.hash.return_value = ""
            run.return_value.returncode = 0
            container.run(["juliet"], "img")
            self.assertEqual([c[0] for c in order.mock_calls], ["regenerate", "hash"])
            order.reset_mock()
            container.run(["realworld-run"], "img")
            self.assertEqual([c[0] for c in order.mock_calls], ["hash"])

    def test_a_dirty_tree_is_refused_before_any_container_starts(self):
        rc, run = self._run(["juliet"], "0123abcd")
        self.assertEqual(rc, 2)
        run.assert_not_called()

    def test_allow_dirty_builds_and_checks_the_dirty_label(self):
        rc, run = self._run(["juliet", "--allow-dirty"], "0123abcd")
        self.assertEqual(rc, 0)
        cmd = run.call_args.args[0]
        self.assertIn(f"{container.BUILD_COMMIT_ENV}={self.FULL}{DIRTY_MARK}0123abcd", cmd)
        self.assertIn(f"{DIRTY_ENV}=0123abcd", cmd)
        self.assertIn(f"{ALLOW_DIRTY_ENV}=1", cmd)
        self.assertIn("--allow-dirty", cmd[-1])

    def test_a_clean_tree_runs_as_before(self):
        rc, run = self._run(["juliet"], "")
        self.assertEqual(rc, 0)
        cmd = run.call_args.args[0]
        self.assertIn(f"{container.BUILD_COMMIT_ENV}={self.FULL}", cmd)
        self.assertNotIn(f"{ALLOW_DIRTY_ENV}=1", cmd)

    def test_check_binary_expects_the_dirty_build(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td) / "aurora-lint"
            b.write_text(f"#!/bin/sh\necho 'aurora-lint 0.6.0 (commit {self.FULL}+dirty0123abcd)'\n")
            b.chmod(0o755)
            with mock.patch.dict(os.environ, {COMMIT_ENV: self.FULL, DIRTY_ENV: "0123abcd"}):
                self.assertEqual(container.check_binary(b), 0)
            with mock.patch.dict(os.environ, {COMMIT_ENV: self.FULL, DIRTY_ENV: ""}):
                self.assertEqual(container.check_binary(b), 2)


class TestCli(unittest.TestCase):
    def test_run_listings_keep_the_dirty_mark_after_cutting_the_sha(self):
        from bench import __main__ as cli
        clean = {"commit_sha": "abcdef0123456"}
        dirty = {"commit_sha": f"abcdef0123456{DIRTY_MARK}0123abcd"}
        self.assertEqual(cli._run_ident(clean), "abcdef01")
        self.assertEqual(cli._run_ident(dirty), f"abcdef01{DIRTY_MARK}0123abcd")
        self.assertEqual(cli._run_ident({**dirty, "variant": "cdb"}),
                         f"abcdef01{DIRTY_MARK}0123abcd+cdb")

    def test_allow_dirty_sets_the_variable_only_when_given(self):
        from bench import __main__ as cli
        with mock.patch.dict(os.environ, {ALLOW_DIRTY_ENV: ""}):
            cli._allow_dirty(mock.Mock())  # a Mock's attribute is not True
            self.assertEqual(os.environ[ALLOW_DIRTY_ENV], "")
            cli._allow_dirty(mock.Mock(allow_dirty=True))
            self.assertEqual(os.environ[ALLOW_DIRTY_ENV], "1")

    def test_both_runners_take_the_flag(self):
        from bench import __main__ as cli
        for sub in ("juliet", "realworld-run"):
            out = subprocess.run(["python3", "-m", "bench", sub, "--help"],
                                 capture_output=True, text=True,
                                 cwd=Path(cli.__file__).resolve().parent.parent)
            self.assertIn("--allow-dirty", out.stdout, sub)


if __name__ == "__main__":
    unittest.main()
