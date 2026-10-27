"""bench/environment.py and bench/container.py: the benchmark image's
environment manifest and pin, and the podman command a container-run uses.
No container runtime is needed: the manifest is built from stubs and the
command is only constructed."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bench import container, environment


class TestPin(unittest.TestCase):
    def test_the_pin_ignores_key_order_and_whitespace(self):
        a = {"tools": {"rustc": "1", "cargo": "2"}, "sets": {}}
        b = {"sets": {}, "tools": {"cargo": "2", "rustc": "1"}}
        self.assertEqual(environment.pin(a), environment.pin(b))
        self.assertNotEqual(environment.pin(a), environment.pin(dict(a, sets={"x": "y"})))

    def test_the_manifest_holds_nothing_host_or_time_dependent(self):
        with mock.patch.object(environment, "packages", return_value={"libc6:amd64": "2.36"}), \
             mock.patch.object(environment, "sets", return_value={"s": "h"}), \
             mock.patch.object(environment, "_first_line", return_value="v1"), \
             mock.patch.dict("os.environ", {"AURORA_BENCH_BASE": "img@sha256:x",
                                            "AURORA_BENCH_SNAPSHOT": "20260915T000000Z"}):
            m = environment.collect()
        self.assertEqual(set(m), {"base", "packages", "tools", "sets"})
        self.assertEqual(m["base"], {"image": "img@sha256:x", "snapshot": "20260915T000000Z"})
        self.assertEqual(set(m["tools"]), set(environment.TOOLS))


class TestCommand(unittest.TestCase):
    def test_corpora_are_mounted_read_only_and_the_target_follows_the_pin(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "mosquitto").mkdir()
            out = root / "out"
            out.mkdir()
            with mock.patch.dict("os.environ", {"BENCH_DB": str(out / "a.db")}):
                cmd = container.command(["--codebase", "mosquitto", "--dirs-out",
                                         str(out / "d.json")], "img", "ab" * 32,
                                        bench_root=root, project_dir=Path("/repo"))
        joined = " ".join(cmd)
        self.assertIn(f"{root}/mosquitto:/bench/mosquitto:ro", joined)
        self.assertIn("/repo:/work", joined)
        self.assertIn(f"{container.target_volume('ab' * 32, '/repo')}:/work/target", joined)
        self.assertTrue(container.target_volume("ab" * 32, "/repo")
                        .startswith("aurora-bench-target-abababababab-"))
        self.assertIn(f"{out}:{out}", joined)
        self.assertIn(f"BENCH_DB={out}/a.db", joined)
        self.assertIn("--platform linux/amd64", joined)
        self.assertTrue(cmd[-1].startswith("cargo build --release --locked"))
        self.assertIn("realworld-run --codebase mosquitto", cmd[-1])

    def test_the_binary_is_checked_between_the_build_and_the_scan(self):
        cmd = container.command(["juliet"], "img", "ab" * 32, project_dir=Path("/repo"),
                                commit=("f" * 40, "fffffff"))
        inner = cmd[-1]
        build, check, scan = (inner.index("cargo build"),
                              inner.index("python3 -m bench.container check-binary"),
                              inner.index("python3 -m bench juliet"))
        self.assertLess(build, check)
        self.assertLess(check, scan)
        # Chained with &&, so a refused binary stops the scan.
        self.assertIn("check-binary && python3 -m bench juliet", inner)
        self.assertIn(f"{container.BUILD_COMMIT_ENV}={'f' * 40}", cmd)


class TestTargetPerCheckout(unittest.TestCase):
    """Every checkout is mounted at the same /work and cargo trusts source
    mtimes, so a target volume shared between checkouts runs one checkout's
    binary for another. Each checkout gets its own."""

    def test_two_checkouts_never_share_a_target(self):
        pin = "ab" * 32
        a = container.target_volume(pin, "/srv/slots/1/aurora-lint")
        b = container.target_volume(pin, "/srv/slots/2/aurora-lint")
        self.assertNotEqual(a, b)
        cmd_a = container.command(["juliet"], "img", pin, project_dir=Path("/srv/slots/1/aurora-lint"))
        cmd_b = container.command(["juliet"], "img", pin, project_dir=Path("/srv/slots/2/aurora-lint"))
        self.assertIn(f"{a}:/work/target", cmd_a)
        self.assertIn(f"{b}:/work/target", cmd_b)

    def test_one_checkout_keeps_its_target_and_each_environment_its_own(self):
        with tempfile.TemporaryDirectory() as td:
            link = Path(td) / "link"
            link.symlink_to(td)
            # The same checkout reached by another spelling is the same target.
            self.assertEqual(container.target_volume("ab" * 32, td),
                             container.target_volume("ab" * 32, link))
        self.assertNotEqual(container.target_volume("ab" * 32, "/repo"),
                            container.target_volume("cd" * 32, "/repo"))


class TestPrune(unittest.TestCase):
    """container-prune removes only what no run can use again: target volumes
    of checkouts that are gone, old per-pin-only volumes and dangling images.
    podman is mocked; nothing here needs a container runtime."""

    PIN = "ab" * 32

    def _podman(self, volumes, ps="", dangling="", fail=()):
        """A stand-in for subprocess.run answering the podman calls prune
        makes, recording each; `fail` names subcommands that exit 1."""
        calls = []

        def run(cmd, **_):
            calls.append(cmd)
            sub = cmd[1]
            out = {"ps": ps, "volume": "\n".join(volumes) if cmd[2] == "ls" else "",
                   "images": dangling}.get(sub, "")
            return mock.Mock(returncode=1 if sub in fail else 0, stdout=out, stderr="")
        return run, calls

    def _prune(self, run, checkouts, **kw):
        with mock.patch("shutil.which", return_value="/usr/bin/podman"), \
             mock.patch.object(container, "live_checkouts", return_value=checkouts), \
             mock.patch.object(container.subprocess, "run", side_effect=run), \
             mock.patch("builtins.print") as out:
            rc = container.prune(**kw)
        return rc, " ".join(str(c) for c in out.call_args_list)

    def test_only_volumes_of_gone_checkouts_and_old_names_are_orphans(self):
        with tempfile.TemporaryDirectory() as live:
            mine = container.target_volume(self.PIN, live)
            gone = container.target_volume(self.PIN, "/no/such/worktree")
            other_pin = container.target_volume("cd" * 32, live)
            old = "aurora-bench-target-" + "1" * 12
            vols = [mine, gone, other_pin, old, container.CARGO_REGISTRY_VOLUME,
                    "aurora-bench-target-notahash", "someone-elses-volume"]
            self.assertEqual(container.orphaned_target_volumes(vols, [Path(live).resolve()]),
                             sorted([gone, old]))

    def test_a_dry_run_lists_and_removes_nothing(self):
        gone = container.target_volume(self.PIN, "/no/such/worktree")
        run, calls = self._podman([gone], dangling="d1\nd2\n")
        rc, out = self._prune(run, [])
        self.assertEqual(rc, 0)
        self.assertIn(gone, out)
        self.assertIn("dangling images: 2", out)
        self.assertFalse([c for c in calls if c[1:3] in (["volume", "rm"], ["image", "prune"])])

    def test_yes_removes_orphans_without_force_and_prunes_dangling_images(self):
        with tempfile.TemporaryDirectory() as live:
            mine = container.target_volume(self.PIN, live)
            gone = container.target_volume(self.PIN, "/no/such/worktree")
            run, calls = self._podman([mine, gone, container.CARGO_REGISTRY_VOLUME], dangling="d1")
            rc, _ = self._prune(run, [Path(live).resolve()], yes=True)
        self.assertEqual(rc, 0)
        removed = [c for c in calls if c[1:3] == ["volume", "rm"]]
        self.assertEqual(removed, [["podman", "volume", "rm", gone]])
        self.assertIn(["podman", "image", "prune", "-f"], calls)

    def test_keep_spares_another_clones_volumes(self):
        clone = container.target_volume(self.PIN, "/elsewhere/clone")
        run, calls = self._podman([clone])
        rc, _ = self._prune(run, [], yes=True, keep=["/elsewhere/clone"])
        self.assertEqual(rc, 0)
        self.assertFalse([c for c in calls if c[1:3] == ["volume", "rm"]])

    def test_a_running_benchmark_container_refuses_the_prune(self):
        gone = container.target_volume(self.PIN, "/no/such/worktree")
        run, calls = self._podman([gone], ps="jovial\tlocalhost/aurora-bench:dev\n")
        rc, out = self._prune(run, [], yes=True)
        self.assertEqual(rc, 2)
        self.assertIn("refusing to prune", out)
        self.assertFalse([c for c in calls if c[1] in ("volume", "image", "images")])

    def test_a_compile_database_build_also_refuses_the_prune(self):
        run, _ = self._podman([], ps="aurora-bench-build-curl-42\tsome/tools:x\n")
        rc, _ = self._prune(run, [], yes=True)
        self.assertEqual(rc, 2)

    def test_an_unlistable_runtime_refuses_rather_than_guessing(self):
        run, _ = self._podman([], fail=("ps",))
        rc, out = self._prune(run, [], yes=True)
        self.assertEqual(rc, 2)
        self.assertIn("refusing to prune", out)

    def test_a_volume_podman_refuses_to_remove_is_reported_and_kept(self):
        gone = container.target_volume(self.PIN, "/no/such/worktree")

        def run(cmd, **_):
            if cmd[1:3] == ["volume", "rm"]:
                return mock.Mock(returncode=1, stdout="", stderr="volume is being used")
            return mock.Mock(returncode=0, stdout=gone if cmd[1:3] == ["volume", "ls"] else "",
                             stderr="")
        rc, out = self._prune(run, [], yes=True)
        self.assertEqual(rc, 1)
        self.assertIn(f"kept {gone}", out)

    def test_live_checkouts_reads_git_worktrees_that_still_exist(self):
        with tempfile.TemporaryDirectory() as main, tempfile.TemporaryDirectory() as wt:
            porcelain = (f"worktree {main}\nHEAD {'a' * 40}\nbranch refs/heads/main\n\n"
                         f"worktree {wt}\nHEAD {'b' * 40}\ndetached\n\n"
                         f"worktree /no/such/worktree\nHEAD {'c' * 40}\nprunable\n")
            with mock.patch.object(container.subprocess, "run",
                                   return_value=mock.Mock(returncode=0, stdout=porcelain)):
                got = container.live_checkouts(main)
            self.assertEqual(got, sorted({Path(main).resolve(), Path(wt).resolve()}))


class TestCheckBinary(unittest.TestCase):
    """The scan refuses a binary that does not report the commit it measures."""

    def _binary(self, td, version_line):
        b = Path(td) / "aurora-lint"
        b.write_text(f"#!/bin/sh\necho '{version_line}'\n")
        b.chmod(0o755)
        return b

    def test_the_binary_built_from_this_commit_passes(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._binary(td, f"aurora-lint 0.6.0 (commit {'a' * 40})")
            self.assertEqual(container.built_commit(b), "a" * 40)
            self.assertEqual(container.check_binary(b, "a" * 40), 0)

    def test_another_commits_binary_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._binary(td, f"aurora-lint 0.6.0 (commit {'b' * 40})")
            self.assertEqual(container.check_binary(b, "a" * 40), 2)

    def test_a_binary_that_records_no_commit_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            b = self._binary(td, "aurora-lint 0.6.0")
            self.assertIsNone(container.built_commit(b))
            self.assertEqual(container.check_binary(b, "a" * 40), 2)

    def test_a_missing_binary_or_commit_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(container.check_binary(Path(td) / "absent", "a" * 40), 2)
            b = self._binary(td, f"aurora-lint 0.6.0 (commit {'a' * 40})")
            with mock.patch.dict("os.environ", {}, clear=True):
                self.assertEqual(container.check_binary(b), 2)


class TestToolsStage(unittest.TestCase):
    def test_a_tools_image_from_another_build_is_refused(self):
        with mock.patch("shutil.which", return_value="/usr/bin/podman"), \
             mock.patch.object(container, "image_pin", return_value="p" * 64), \
             mock.patch.object(container, "_read_in_image",
                               side_effect=lambda image, code, rt="podman":
                               "a" * 64 if image == "bench" else "b" * 64), \
             mock.patch.object(container.subprocess, "run") as run:
            self.assertEqual(container.build_db("lua", "bench", "tools"), 2)
        run.assert_not_called()

    def test_the_bench_manifest_records_the_tools_stage(self):
        with tempfile.TemporaryDirectory() as td:
            tools = Path(td) / "tools.json"
            tools.write_text(json.dumps({"base": {}, "packages": {"a": "1"}}))
            with mock.patch.object(environment, "TOOLS_MANIFEST_PATH", tools), \
                 mock.patch.object(environment, "packages", return_value={}), \
                 mock.patch.object(environment, "sets", return_value={}), \
                 mock.patch.object(environment, "_first_line", return_value="v"):
                m = environment.collect()
        self.assertEqual(m["tools_stage"],
                         environment.pin({"base": {}, "packages": {"a": "1"}}))


class TestScoringKeys(unittest.TestCase):
    """A finding's scoring key is the same whether the scan ran in the
    container (/bench/<project>/...) or on the host."""

    def test_every_checkout_directory_is_named_after_its_project(self):
        from bench.realworld_runner import CODEBASES
        for name, cfg in CODEBASES.items():
            self.assertEqual(Path(cfg["path"]).name, name)

    def test_container_and_host_paths_normalize_to_one_key(self):
        from bench.db import BenchDB
        # mosquitto holds an include/mosquitto/ of its own: the case where
        # stripping to the last /mosquitto/ instead of the first went wrong.
        for rel in ("include/mosquitto/libmosquitto.h", "lib/send_mosq.c"):
            host = BenchDB.project_relpath("mosquitto", f"/home/a/toolchain/mosquitto/{rel}")
            ctr = BenchDB.project_relpath("mosquitto", f"/bench/mosquitto/{rel}")
            self.assertEqual(host, rel)
            self.assertEqual(ctr, rel)


class TestDeclared(unittest.TestCase):
    """data/benchmark_environment.json: both images by digest and every
    pin, read through one validated reader."""

    def _write(self, td, **over):
        d = json.loads(environment.DECLARED_PATH.read_text())
        d.update(over)
        p = Path(td) / "e.json"
        p.write_text(json.dumps(d))
        return p

    def test_the_committed_file_declares_both_images_and_every_pin(self):
        d = environment.declared()
        for key in environment.DECLARED_PINS + environment.DECLARED_IMAGES:
            self.assertIn(key, d)
        self.assertTrue(d["tools_image"].startswith("aurora-bench-tools@sha256:"))

    def test_a_missing_or_malformed_field_is_refused_by_name(self):
        with tempfile.TemporaryDirectory() as td:
            for key, bad in (("tools_image", None), ("tools_stage", "cfcaf98f"),
                             ("shared_image", "aurora-bench:dev")):
                with self.assertRaisesRegex(ValueError, key):
                    environment.declared(self._write(td, **{key: bad}))

    def test_an_image_with_a_registry_host_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ValueError, "registry host"):
                environment.declared(self._write(
                    td, tools_image="registry.example:5000/aurora-bench-tools@sha256:" + "a" * 64))

    def test_a_bad_declared_file_exits_2_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as td:
            bad = Path(td) / "e.json"
            bad.write_text("{not json")
            with mock.patch.object(environment, "DECLARED_PATH", bad), \
                 mock.patch("builtins.print"):
                self.assertEqual(environment.main(["declared", "tools_image"]), 2)
            with mock.patch.object(environment, "declared",
                                   side_effect=ValueError("tools_image must be")), \
                 mock.patch("shutil.which", return_value="/usr/bin/podman"), \
                 mock.patch.object(container, "image_pin", return_value="p" * 64), \
                 mock.patch.object(container, "_read_in_image", return_value="a" * 64), \
                 mock.patch.object(container.subprocess, "run") as run, \
                 mock.patch("builtins.print"):
                self.assertEqual(container.build_db("lua", "bench", "tools"), 2)
            run.assert_not_called()

    def test_a_tools_image_other_than_the_declared_one_is_noted(self):
        from bench import realworld_runner
        with mock.patch("shutil.which", return_value="/usr/bin/podman"), \
             mock.patch.object(container, "image_pin", return_value="p" * 64), \
             mock.patch.object(container, "_read_in_image", return_value="a" * 64), \
             mock.patch.object(realworld_runner, "_get_codebase_sha", return_value=""), \
             mock.patch("builtins.print") as out:
            container.build_db("lua", "bench", "tools")
        self.assertTrue(any("note:" in str(c) and "not the declared" in str(c)
                            for c in out.call_args_list))

    def test_the_cli_prints_a_field(self):
        with mock.patch("builtins.print") as out:
            self.assertEqual(environment.main(["declared", "tools_image"]), 0)
        out.assert_called_once_with(environment.declared()["tools_image"])
        self.assertEqual(environment.main(["declared", "nope"]), 2)


if __name__ == "__main__":
    unittest.main()
