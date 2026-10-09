"""A Juliet run in the benchmark environment (docs/adr/0018): its dependency
set's headers, its `environment` record, its run-id suffix, and how
container-run starts it."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bench import container, deps, environment, runner
from bench import realworld_runner as rr
from bench.db import BenchDB

DECL = {"corpus": "juliet", "platform": "linux-x86_64", "roots": ["usr/include"],
        "include_dirs": ["usr/include"], "sources": [], "manifest_sha256": "c" * 64}


class TestJulietEnvironment(unittest.TestCase):
    def env(self, status=deps.OK, manifest=None, declared="e" * 64):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "benchmark_deps"
            d.mkdir()
            (d / "juliet.json").write_text(json.dumps(DECL))
            pin_file = Path(td) / "env.json"
            pin_file.write_text(json.dumps({"manifest_sha256": declared}))
            with mock.patch.object(deps, "DEPS_DIR", d), \
                 mock.patch.object(deps, "check", return_value={"status": status, "path": "/t"}), \
                 mock.patch.object(deps, "include_args", return_value=["-I", "/t/usr/include"]), \
                 mock.patch.object(environment, "load", return_value=manifest), \
                 mock.patch.object(rr, "ENVIRONMENT_PIN", pin_file):
                return runner._juliet_environment()

    def test_a_missing_set_refuses_the_run(self):
        with self.assertRaises(FileNotFoundError):
            self.env(status=deps.MISSING)

    def test_outside_the_image_the_run_id_says_so(self):
        incs, record, suffix = self.env()
        self.assertEqual(incs, ("-I", "/t/usr/include"))
        self.assertEqual(suffix, "-hostenv")
        rec = json.loads(record)
        self.assertIsNone(rec["manifest_sha256"])
        self.assertEqual(rec["set"]["manifest_sha256"], "c" * 64)

    def test_in_the_declared_environment_the_run_id_is_bare(self):
        manifest = {"base": {"image": "x"}, "packages": {}, "tools": {}, "sets": {}}
        pin = environment.pin(manifest)
        _, record, suffix = self.env(manifest=manifest, declared=pin)
        self.assertEqual(suffix, "")
        self.assertEqual(json.loads(record)["manifest_sha256"], pin)
        _, _, other = self.env(manifest=manifest, declared="f" * 64)
        self.assertEqual(other, f"-env{pin[:8]}")

    def test_no_declared_set_changes_nothing(self):
        with tempfile.TemporaryDirectory() as td, \
             mock.patch.object(deps, "DEPS_DIR", Path(td)):
            self.assertEqual(runner._juliet_environment(), ((), None, ""))

    def test_every_scan_gets_the_sets_headers(self):
        args = runner._prescan_args("/j/CWE1", None, ("-I", "/t/usr/include"))
        self.assertEqual(args[-2:], ["-I", "/t/usr/include"])


class TestEnvironmentColumns(unittest.TestCase):
    def test_the_record_is_canonical_json_of_pin_base_and_set(self):
        self.assertIsNone(BenchDB.environment_json({}))
        self.assertIsNone(BenchDB.environment_json({"codebase_commit": "a"}))
        rec = BenchDB.environment_json({"environment": {"manifest_sha256": "p", "base": {"b": 1}},
                                        "deps": {"id": "s"}})
        self.assertEqual(rec, '{"base":{"b":1},"manifest_sha256":"p","set":{"id":"s"}}')

    def test_both_tables_have_the_column(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "b.db"
            with mock.patch.dict("os.environ", {"BENCH_DB": str(db)}):
                BenchDB(str(db))
            conn = sqlite3.connect(db)
            for table in ("runs", "realworld_results"):
                cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
                self.assertIn("environment", cols)


class TestContainerJuliet(unittest.TestCase):
    def test_juliet_runs_in_the_image_with_its_tree_and_run_id_file_mounted(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "benchmarks" / "juliet-test-suite-c").mkdir(parents=True)
            out = root / "out"
            out.mkdir()
            cmd = container.command(["juliet", "--run-id-out", str(out / "id")], "img",
                                    "ab" * 32, bench_root=root, project_dir=Path("/repo"))
        joined = " ".join(cmd)
        self.assertIn(f"{root}/benchmarks/juliet-test-suite-c:/bench/benchmarks/juliet-test-suite-c:ro",
                      joined)
        self.assertIn(f"{out}:{out}", joined)
        self.assertIn("python3 -m bench juliet --run-id-out", cmd[-1])

    def test_no_subcommand_is_a_realworld_run(self):
        cmd = container.command(["--codebase", "lua"], "img", "ab" * 32,
                                bench_root=Path("/nonexistent"), project_dir=Path("/repo"))
        self.assertIn("python3 -m bench realworld-run --codebase lua", cmd[-1])


if __name__ == "__main__":
    unittest.main()
