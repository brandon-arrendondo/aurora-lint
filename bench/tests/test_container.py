"""bench/environment.py and bench/container.py: the benchmark image's
environment manifest and pin, and the podman command a container-run uses.
No container runtime is needed: the manifest is built from stubs and the
command is only constructed."""

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
        self.assertIn("aurora-bench-target-abababababab:/work/target", joined)
        self.assertIn(f"{out}:{out}", joined)
        self.assertIn(f"BENCH_DB={out}/a.db", joined)
        self.assertIn("--platform linux/amd64", joined)
        self.assertTrue(cmd[-1].startswith("cargo build --release --locked"))
        self.assertIn("realworld-run --codebase mosquitto", cmd[-1])


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


if __name__ == "__main__":
    unittest.main()
