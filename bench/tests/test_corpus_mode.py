"""bench/corpus.py: where corpus-check looks for the dependency sets.

A machine that runs every benchmark through `bench container-run` reads the
sets from the image, so their absence on the host is not a problem there,
but the image is. A machine that scans on the host needs the host sets
whatever images it holds. The container runtime is mocked: what is pinned
here is which answer each state gets.
"""

import contextlib
import io
import json
import os
import subprocess
import unittest
from unittest import mock

from bench import corpus

FULL, SHARED, OTHER = "f" * 64, "5" * 64, "0" * 64
DECLARED = {"manifest_sha256": FULL, "shared_manifest_sha256": SHARED}


def _repo(name, tree):
    return {"name": name, "path": f"/b/{name}", "expected": "a" * 40,
            "head": "a" * 40, "branch": "HEAD", "status": "OK", "dirty": 0,
            "untracked_scanned": 0, "untracked_ignored": 0, "gitignored_scanned": 0,
            "untracked_scanned_but_excluded": 0,
            "gitignored_scanned_but_excluded": 0, "header_tree": tree,
            "submodules": []}


def _set(name, status="MISSING"):
    """A dependency set as check_repo reports it."""
    return {"id": f"{name}-x", "path": f"/b/deps/{name}-x", "expected": "e" * 64,
            "actual": None, "status": status, "deps": name}


def _tree(status="MISSING"):
    """A pinned header tree that is not a dependency set."""
    return {"id": "t", "path": "/b/header-trees/t", "expected": "e" * 64,
            "actual": None, "status": status}


class TestMode(unittest.TestCase):
    def _report(self, repos, mode=None, runtime_found=True, image_exists=True,
                pin=FULL, env=None, as_json=False):
        exists = subprocess.CompletedProcess([], 0 if image_exists else 1)
        out = io.StringIO()
        with mock.patch.object(corpus, "check_all", return_value=repos), \
                mock.patch("bench.environment.declared", return_value=DECLARED), \
                mock.patch.object(corpus.shutil, "which",
                                  return_value="/usr/bin/podman" if runtime_found else None), \
                mock.patch.object(corpus.subprocess, "run", return_value=exists) as run, \
                mock.patch("bench.container.image_pin", return_value=pin), \
                mock.patch.dict(os.environ, env or {}, clear=False), \
                contextlib.redirect_stdout(out):
            if env is None:
                os.environ.pop(corpus.MODE_ENV, None)
            code = corpus.report(as_json=as_json, mode=mode, image="img")
        self.run_calls = run.call_args_list
        return code, out.getvalue()

    def test_host_mode_fails_a_missing_set_and_names_container_mode(self):
        code, out = self._report([_repo("curl", _set("curl"))], mode="host")
        self.assertEqual(code, 1)
        self.assertIn("pass --mode container", out)
        # Host mode never asks the container runtime anything.
        self.assertEqual(self.run_calls, [])

    def test_host_mode_is_the_default(self):
        code, out = self._report([_repo("curl", _set("curl"))])
        self.assertEqual(code, 1)
        self.assertIn("mode: host", out)

    def test_container_mode_with_the_declared_image_does_not_need_host_sets(self):
        code, out = self._report([_repo("curl", _set("curl"))], mode="container")
        self.assertEqual(code, 0)
        self.assertIn("dependency set not needed (container runs use the image's sets)", out)
        self.assertNotIn("header tree(s) missing", out)

    def test_container_mode_reads_the_mode_from_the_environment(self):
        code, out = self._report([_repo("curl", _set("curl"))],
                                 env={corpus.MODE_ENV: "container"})
        self.assertEqual(code, 0)
        self.assertIn("mode: container", out)

    def test_a_mode_that_is_neither_is_refused_not_read_as_host(self):
        with mock.patch.dict(os.environ, {corpus.MODE_ENV: "contianer"}):
            with self.assertRaises(ValueError):
                corpus.default_mode()

    def test_container_mode_fails_without_the_image(self):
        code, out = self._report([_repo("curl", _set("curl"))], mode="container",
                                 image_exists=False)
        self.assertEqual(code, 1)
        self.assertIn("Benchmark image img ABSENT", out)

    def test_container_mode_fails_without_a_runtime(self):
        code, out = self._report([_repo("curl", _set("curl"))], mode="container",
                                 runtime_found=False)
        self.assertEqual(code, 1)
        self.assertIn("NO_RUNTIME", out)

    def test_container_mode_fails_an_image_of_another_environment(self):
        code, out = self._report([_repo("curl", _set("curl"))], mode="container",
                                 pin=OTHER)
        self.assertEqual(code, 1)
        self.assertIn("MISMATCH: environment 000000000000, declared ffffffffffff", out)

    def test_the_shared_image_alone_lacks_the_licence_layer(self):
        code, out = self._report([_repo("curl", _set("curl"))], mode="container",
                                 pin=SHARED)
        self.assertEqual(code, 1)
        self.assertIn("NO_LICENCE_LAYER", out)
        self.assertIn("container/licence.Dockerfile", out)

    def test_container_mode_still_needs_a_header_tree_mounted_from_the_host(self):
        code, out = self._report([_repo("v", _tree())], mode="container")
        self.assertEqual(code, 1)
        self.assertIn("header tree MISSING", out)

    def test_json_records_the_mode_and_the_image(self):
        code, out = self._report([_repo("curl", _set("curl"))], mode="container",
                                 as_json=True)
        doc = json.loads(out)
        self.assertEqual((code, doc["mode"], doc["clean"]), (0, "container", True))
        self.assertEqual(doc["image"]["status"], "OK")
        self.assertFalse(doc["repos"][0]["header_tree"]["needed"])

    def test_json_in_host_mode_has_no_image(self):
        code, out = self._report([_repo("curl", _set("curl", "OK"))], mode="host",
                                 as_json=True)
        doc = json.loads(out)
        self.assertEqual((code, doc["mode"], doc["image"]), (0, "host", None))


if __name__ == "__main__":
    unittest.main()
