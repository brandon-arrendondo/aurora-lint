"""The aurora-lint commit a benchmark run records (bench/config.py
aurora_lint_commit). Inside the benchmark container git cannot always
resolve it: a worktree checkout's .git names a directory on the host that is
not mounted. So `bench container-run` passes the host's commit in, both
runners prefer it, and a run or ingest whose commit is unknown is refused
rather than written under a run id every such run would share."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bench import config, container, realworld_runner, runner
from bench.config import COMMIT_ENV, COMMIT_SHORT_ENV, UNKNOWN_COMMIT
from bench.db import BenchDB

_NO_COMMIT_ENV = {COMMIT_ENV: "", COMMIT_SHORT_ENV: ""}


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


@unittest.skipUnless(shutil.which("git"), "needs git")
class TestWorktreeMountedAlone(unittest.TestCase):
    """A worktree whose gitdir is not reachable, as when only the worktree is
    mounted into the container."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.repo, self.worktree = root / "repo", root / "slot"
        self.repo.mkdir()
        _git(self.repo, "init", "-q")
        (self.repo / "f").write_text("x")
        _git(self.repo, "add", "f")
        _git(self.repo, "commit", "-q", "-m", "c")
        _git(self.repo, "worktree", "add", "-q", "--detach", str(self.worktree))
        self.full, self.short = config.host_commit(self.repo)

    def tearDown(self):
        self._tmp.cleanup()

    def test_the_host_resolves_a_worktree(self):
        self.assertEqual(config.host_commit(self.worktree), (self.full, self.short))

    def test_without_its_gitdir_the_commit_is_unknown(self):
        shutil.rmtree(self.repo / ".git" / "worktrees")
        self.assertIsNone(config.host_commit(self.worktree))
        with mock.patch.dict(os.environ, _NO_COMMIT_ENV):
            self.assertEqual(config.aurora_lint_commit(self.worktree), UNKNOWN_COMMIT)

    def test_the_passed_in_commit_is_used_when_git_cannot_answer(self):
        shutil.rmtree(self.repo / ".git" / "worktrees")
        with mock.patch.dict(os.environ, {COMMIT_ENV: self.full, COMMIT_SHORT_ENV: self.short}):
            self.assertEqual(config.aurora_lint_commit(self.worktree), self.short)


class TestPassedInCommit(unittest.TestCase):
    def test_both_runners_prefer_it_over_git(self):
        env = {COMMIT_ENV: "abcdef0123" + "0" * 30, COMMIT_SHORT_ENV: "abcdef012"}
        with mock.patch.dict(os.environ, env), \
             mock.patch.object(config, "host_commit", side_effect=AssertionError("git asked")):
            self.assertEqual(realworld_runner._get_git_sha(), "abcdef012")
            self.assertEqual(runner._get_git_sha(), "abcdef012")

    def test_a_short_sha_that_is_not_a_prefix_of_the_full_one_is_refused(self):
        with mock.patch.dict(os.environ, {COMMIT_ENV: "1" * 40, COMMIT_SHORT_ENV: "abcdef012"}):
            with self.assertRaises(ValueError):
                config.aurora_lint_commit()

    def test_container_run_passes_the_hosts_commit_in(self):
        cmd = container.command(["--codebase", "lua"], "img", "ab" * 32,
                                bench_root=Path("/nonexistent"), project_dir=Path("/repo"),
                                commit=("f" * 40, "fffffffff"))
        self.assertIn(f"{COMMIT_ENV}={'f' * 40}", cmd)
        self.assertIn(f"{COMMIT_SHORT_ENV}=fffffffff", cmd)
        self.assertLess(cmd.index(f"{COMMIT_SHORT_ENV}=fffffffff"), cmd.index("img"))

    def test_container_run_refuses_a_checkout_git_cannot_resolve(self):
        with mock.patch("shutil.which", return_value="/usr/bin/podman"), \
             mock.patch.object(container, "host_commit", return_value=None), \
             mock.patch.object(container, "image_pin") as pin, \
             mock.patch("subprocess.run") as run:
            self.assertEqual(container.run(["--codebase", "lua"]), 2)
        pin.assert_not_called()
        run.assert_not_called()


class TestUnknownIsRefused(unittest.TestCase):
    def test_a_real_world_scan(self):
        with mock.patch.object(realworld_runner, "_get_git_sha", return_value=UNKNOWN_COMMIT), \
             mock.patch.object(realworld_runner, "_get_tool_version", return_value="0.6.0"):
            with self.assertRaisesRegex(ValueError, "commit is unknown"):
                realworld_runner.run_one("sqc", "libcrc")

    def test_a_juliet_run_before_any_work(self):
        with mock.patch.object(runner, "_get_git_sha", return_value=UNKNOWN_COMMIT), \
             mock.patch.object(runner, "_enumerate_cwes", side_effect=AssertionError("ran")):
            with self.assertRaisesRegex(ValueError, "commit is unknown"):
                runner.run_benchmark()

    def test_the_realworld_run_command_exits_2(self):
        from bench import __main__ as cli
        args = mock.Mock(tool="sqc", codebase="libcrc", header_tree=None, dirs_out=None)
        with mock.patch.object(realworld_runner, "_get_git_sha", return_value=UNKNOWN_COMMIT), \
             mock.patch.object(realworld_runner, "run_and_ingest",
                               side_effect=AssertionError("ran")):
            with self.assertRaises(SystemExit) as e:
                cli.cmd_realworld_run(args)
        self.assertEqual(e.exception.code, 2)

    def test_an_ingest(self):
        with tempfile.TemporaryDirectory() as td:
            db = BenchDB(Path(td) / "b.db")
            with self.assertRaisesRegex(ValueError, "commit is unknown"):
                db.ingest_realworld_run("sqc-0.6.0-unknown-default-f8d20bf6960d", td)
            self.assertEqual(db.list_realworld_runs(), [])


if __name__ == "__main__":
    unittest.main()
