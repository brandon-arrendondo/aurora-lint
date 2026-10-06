"""bench/header_tree.py: the pinned system-header tree a corpus is scanned
against, its manifest hash, and the two places that enforce it (corpus-check
and the real-world runner).

The hash is what tells two machines they hold the same headers, so its
definition is pinned here on a synthetic tree rather than on the real one:
a change to how it is computed silently invalidates every declared hash.
"""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bench import corpus, header_tree
from bench import realworld_runner as rr

HASHED = ["crt/include", "sdk/include"]


def _write(root: Path, rel: str, data: bytes) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _tree(root: Path) -> None:
    _write(root, "crt/include/stdio.h", b"crt stdio\n")
    _write(root, "sdk/include/um/Windows.h", b"windows\n")
    _write(root, "sdk/lib/x86/kernel32.lib", b"not hashed\n")
    os.symlink(".", root / "sdk/include/10.0.26100")


def _spec(tree_id: str, sha: str) -> dict:
    return {"id": tree_id, "fetch": {"tool": "xwin"}, "hashed_dirs": HASHED,
            "manifest_sha256": sha,
            "include_dirs": ["crt/include", "sdk/include/um"]}


class TestManifest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _tree(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_lines_are_files_by_content_and_links_by_target(self):
        sha = lambda b: hashlib.sha256(b).hexdigest()
        self.assertEqual(header_tree.manifest_lines(self.root, HASHED), [
            f"F crt/include/stdio.h {sha(b'crt stdio' + bytes([10]))}",
            f"F sdk/include/um/Windows.h {sha(b'windows' + bytes([10]))}",
            # Hashed as a link, not followed: following '.' would loop.
            "L sdk/include/10.0.26100 .",
        ])

    def test_hash_is_sha256_of_newline_terminated_lines(self):
        body = "".join(l + "\n" for l in header_tree.manifest_lines(self.root, HASHED))
        self.assertEqual(header_tree.manifest_sha256(self.root, HASHED),
                         hashlib.sha256(body.encode()).hexdigest())

    def test_libraries_outside_hashed_dirs_do_not_count(self):
        before = header_tree.manifest_sha256(self.root, HASHED)
        _write(self.root, "sdk/lib/x86/user32.lib", b"more\n")
        self.assertEqual(header_tree.manifest_sha256(self.root, HASHED), before)

    def test_any_header_change_changes_the_hash(self):
        before = header_tree.manifest_sha256(self.root, HASHED)
        _write(self.root, "sdk/include/um/Windows.h", b"windows, serviced\n")
        self.assertNotEqual(header_tree.manifest_sha256(self.root, HASHED), before)

    def test_a_renamed_header_changes_the_hash(self):
        before = header_tree.manifest_sha256(self.root, HASHED)
        os.rename(self.root / "crt/include/stdio.h", self.root / "crt/include/Stdio.h")
        self.assertNotEqual(header_tree.manifest_sha256(self.root, HASHED), before)


class TestCheck(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.bench = Path(self._tmp.name)
        _tree(self.bench / "header-trees" / "t1")
        self.good = header_tree.manifest_sha256(self.bench / "header-trees" / "t1", HASHED)

    def tearDown(self):
        self._tmp.cleanup()

    def test_statuses(self):
        self.assertEqual(header_tree.check(_spec("t1", self.good), self.bench)["status"],
                         header_tree.OK)
        self.assertEqual(header_tree.check(_spec("t1", "0" * 64), self.bench)["status"],
                         header_tree.MISMATCH)
        self.assertEqual(header_tree.check(_spec("absent", self.good), self.bench)["status"],
                         header_tree.MISSING)

    def test_include_args_follow_the_declared_order(self):
        base = self.bench / "header-trees" / "t1"
        self.assertEqual(header_tree.include_args(_spec("t1", self.good), self.bench),
                         ["-I", str(base / "crt/include"), "-I", str(base / "sdk/include/um")])

    def test_corpus_check_fails_a_missing_tree_even_with_the_checkout_missing(self):
        entry = {"name": "nope", "version": "0" * 40,
                 "header_tree": _spec("absent", self.good)}
        r = corpus.check_repo(entry, self.bench)
        self.assertEqual(r["header_tree"]["status"], header_tree.MISSING)
        self.assertTrue(corpus.header_tree_bad(r))

    def test_corpus_check_ignores_a_corpus_without_a_tree(self):
        r = corpus.check_repo({"name": "nope", "version": "0" * 40}, self.bench)
        self.assertIsNone(r["header_tree"])
        self.assertFalse(corpus.header_tree_bad(r))


class TestRunner(unittest.TestCase):
    def test_no_declaration_means_no_tree(self):
        with mock.patch.object(header_tree, "spec_for", return_value=None):
            self.assertIsNone(rr._verified_header_tree("lua"))

    def test_a_missing_tree_refuses_the_scan(self):
        spec = _spec("absent", "0" * 64)
        with mock.patch.object(header_tree, "spec_for", return_value=spec), \
             mock.patch.object(header_tree, "check",
                               return_value={"status": header_tree.MISSING,
                                             "path": "/x", "actual": None,
                                             "expected": spec["manifest_sha256"]}):
            with self.assertRaises(FileNotFoundError) as cm:
                rr._verified_header_tree("ventoy")
        self.assertIn("accept_microsoft_license", str(cm.exception))

    def test_a_mismatched_tree_refuses_the_scan(self):
        spec = _spec("t1", "a" * 64)
        with mock.patch.object(header_tree, "spec_for", return_value=spec), \
             mock.patch.object(header_tree, "check",
                               return_value={"status": header_tree.MISMATCH,
                                             "path": "/x", "actual": "b" * 64,
                                             "expected": "a" * 64}):
            with self.assertRaises(FileNotFoundError) as cm:
                rr._verified_header_tree("ventoy")
        self.assertIn("bbbbbbbbbbbb", str(cm.exception))

    def test_header_includes_come_after_the_codebase_includes(self):
        cfg = {"path": Path("/cb"), "sqc": {"manifest": rr.CODEBASES["ventoy"]["sqc"]["manifest"],
                                            "includes": ["-I", "{path}/inc"]}}
        cmd = rr._build_sqc_cmd(cfg, Path("/out"), "rid",
                                header_includes=["-I", "/h/crt/include"])
        self.assertEqual(cmd[-4:], ["-I", "/cb/inc", "-I", "/h/crt/include"])


class TestVentoyDeclaration(unittest.TestCase):
    """The real declaration is self-consistent. Not its values: those are a
    pin, and changing one is a deliberate re-pin."""

    def test_include_dirs_lie_inside_the_hashed_dirs(self):
        spec = header_tree.spec_for("ventoy")
        self.assertIsNotNone(spec)
        for d in spec["include_dirs"]:
            with self.subTest(include_dir=d):
                self.assertTrue(any(d == h or d.startswith(h + "/")
                                    for h in spec["hashed_dirs"]))

    def test_fetch_names_every_pinned_version(self):
        fetch = header_tree.spec_for("ventoy")["fetch"]
        for key in ("tool", "tool_version", "manifest_version", "channel", "arch",
                    "variant", "sdk_version", "crt_version", "case_symlinks"):
            with self.subTest(key=key):
                self.assertIn(key, fetch)


if __name__ == "__main__":
    unittest.main()
