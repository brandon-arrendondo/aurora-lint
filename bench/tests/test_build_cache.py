"""`bench container-build-db` reuses an intact build cache and replaces a
missing, stale or damaged one atomically (bench/container.py build_db,
bench/deps.py cache_lock and check_cache). No container runtime is needed:
the build container is replaced by a stub that writes a cache the way
bench/dbbuild.py does."""

import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from bench import container, deps, realworld_runner

COMMIT, PIN = "c" * 40, "p" * 64
DECL = {"corpus": "toy", "build": {"steps": ["make"], "db": "$BUILD/compile_commands.json"}}


def write_cache(cache: Path, decl: dict, header: bytes = b"#define X 1\n") -> None:
    (cache / "generated" / "build").mkdir(parents=True)
    body = json.dumps([{"directory": "${CORPUS}", "file": "${CORPUS}/a.c",
                        "arguments": ["cc", "-I", "${GEN}/build", "-c", "a.c"]}]).encode()
    (cache / "compile_commands.json").write_bytes(body)
    (cache / "generated" / "build" / "config.h").write_bytes(header)
    (cache / "cache.json").write_text(json.dumps({
        "corpus": decl["corpus"], "corpus_commit": COMMIT, "environment": PIN,
        "recipe_sha256": deps.recipe_sha256(decl), "entries": 1,
        "db_sha256": hashlib.sha256(body).hexdigest(),
        "generated": {"build/config.h": hashlib.sha256(header).hexdigest()}}))


class BuildCacheTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.cache = deps.build_cache_dir(DECL, COMMIT, PIN, self.root)
        self.builds = []
        self.decl = DECL
        patches = [
            mock.patch("shutil.which", return_value="/usr/bin/podman"),
            mock.patch.object(container, "image_pin", return_value=PIN),
            mock.patch.object(container, "_read_in_image", return_value="t" * 64),
            mock.patch.object(container, "build_db_command",
                              side_effect=lambda *a, out_name, **kw: ["build", out_name]),
            mock.patch.object(container.subprocess, "run", side_effect=self._fake_build),
            mock.patch.object(realworld_runner, "_get_codebase_sha", return_value=COMMIT),
            mock.patch.object(deps, "declared_for", side_effect=lambda p: self.decl),
            mock.patch.dict(realworld_runner.CODEBASES, {"toy": {"path": self.root / "toy"}}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def _fake_build(self, cmd, **kw):
        """What dbbuild does in the container: write a fresh cache under
        the name it is given, beside the real one."""
        self.builds.append(cmd[1])
        time.sleep(0.05)
        write_cache(self.cache.parent / cmd[1], self.decl)
        return mock.Mock(returncode=0)

    def build(self, **kw):
        return container.build_db("toy", "bench", "tools", bench_root=self.root, **kw)

    def test_an_intact_cache_is_a_hit_and_starts_no_build(self):
        write_cache(self.cache, self.decl)
        with mock.patch("builtins.print") as out:
            self.assertEqual(self.build(), 0)
        self.assertEqual(self.builds, [])
        self.assertTrue(any("cache hit" in str(c) for c in out.call_args_list))

    def test_a_missing_cache_is_built_through_a_temporary_directory(self):
        with mock.patch("builtins.print") as out:
            self.assertEqual(self.build(), 0)
        self.assertEqual(len(self.builds), 1)
        self.assertTrue(self.builds[0].startswith(self.cache.name + ".tmp-"))
        deps.check_cache(self.decl, self.cache, COMMIT, PIN)
        self.assertTrue(any("rebuilt" in str(c) for c in out.call_args_list))
        self.assertEqual(sorted(p.name for p in self.cache.parent.iterdir()),
                         [self.cache.name, self.cache.name + ".lock"])

    def test_a_cache_from_another_recipe_is_rebuilt(self):
        write_cache(self.cache, self.decl)
        self.decl = {**DECL, "build": {**DECL["build"], "steps": ["make", "make check"]}}
        self.assertEqual(self.build(), 0)
        self.assertEqual(len(self.builds), 1)
        deps.check_cache(self.decl, self.cache, COMMIT, PIN)

    def test_a_damaged_cache_is_rebuilt(self):
        write_cache(self.cache, self.decl)
        (self.cache / "generated" / "build" / "config.h").write_bytes(b"tampered\n")
        self.assertEqual(self.build(), 0)
        self.assertEqual(len(self.builds), 1)
        deps.check_cache(self.decl, self.cache, COMMIT, PIN)

    def test_rebuild_builds_over_an_intact_cache(self):
        write_cache(self.cache, self.decl)
        self.assertEqual(self.build(rebuild=True), 0)
        self.assertEqual(len(self.builds), 1)

    def test_a_build_whose_output_does_not_check_out_leaves_the_cache_alone(self):
        write_cache(self.cache, self.decl, header=b"old\n")
        (self.cache / "cache.json").write_text("{}")  # damaged: forces a build

        def bad_build(cmd, **kw):
            (self.cache.parent / cmd[1]).mkdir()
            return mock.Mock(returncode=0)
        with mock.patch.object(container.subprocess, "run", side_effect=bad_build):
            self.assertEqual(self.build(), 1)
        self.assertEqual((self.cache / "generated" / "build" / "config.h").read_bytes(), b"old\n")
        self.assertFalse(any(".tmp-" in p.name for p in self.cache.parent.iterdir()))

    def test_concurrent_builders_build_once(self):
        results = []
        threads = [threading.Thread(target=lambda: results.append(self.build()))
                   for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results, [0, 0, 0, 0])
        self.assertEqual(len(self.builds), 1)
        deps.check_cache(self.decl, self.cache, COMMIT, PIN)

    def test_a_reader_never_sees_a_cache_mid_swap(self):
        write_cache(self.cache, self.decl)
        seen = []

        def read_while_rebuilding():
            for _ in range(20):
                with deps.cache_lock(self.cache, exclusive=False):
                    seen.append(deps.check_cache(self.decl, self.cache, COMMIT, PIN)[0]["entries"])
        reader = threading.Thread(target=read_while_rebuilding)
        reader.start()
        self.assertEqual(self.build(rebuild=True), 0)
        reader.join()
        self.assertEqual(seen, [1] * 20)


if __name__ == "__main__":
    unittest.main()
