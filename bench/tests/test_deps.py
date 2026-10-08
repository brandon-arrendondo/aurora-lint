"""bench/deps.py: a real-world benchmark's dependency set (docs/adr/0018),
its tree, its manifest hash (the fifth pin), and the runner and corpus-check
that enforce it.

Everything runs against synthetic .debs at file:// URLs: the code path a
machine runs against snapshot.debian.org, without the network.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bench import corpus, deps, header_tree
from bench import realworld_runner as rr
from bench.tests.test_header_tree import _deb

BASE = {"archive": "debian", "suite": "bookworm", "arch": "amd64",
        "snapshot": "20260915T000000Z"}
ROOTS = ["usr/include"]


def _decl(debs, **kw) -> dict:
    d = {"corpus": "toy", "platform": "linux-x86_64", "base": BASE,
         "sources": [{"kind": "debs", "debs": debs}], "roots": ROOTS,
         "include_dirs": ["usr/include/x86_64-linux-gnu", "usr/include"],
         "manifest_sha256": None}
    d.update(kw)
    return d


class _Debs(unittest.TestCase):
    PACKAGES = {
        "libc": {"usr/include/stdio.h": b'#include <bits/types.h>\n#include "local.h"\n',
                 "usr/include/local.h": b"local\n",
                 "usr/include/x86_64-linux-gnu/bits/types.h": b"#include <gnu/stubs-32.h>\n",
                 "usr/share/doc/libc/README": b"not a header\n"},
        "multilib": {"usr/include/x86_64-linux-gnu/gnu/stubs-32.h": b"32\n"},
        "kernel": {"usr/include/linux/errno.h": b"errno\n",
                   "usr/include/linux/netfilter/xt_dscp.h": b"lower\n",
                   "usr/include/linux/netfilter/xt_DSCP.h": b"upper\n"},
    }

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.bench = self.tmp / "bench"
        self.debs = {}
        for name, files in self.PACKAGES.items():
            f = self.tmp / f"{name}_1.0_amd64.deb"
            f.write_bytes(_deb(files))
            self.debs[name] = {"package": name, "version": "1.0", "file": f.name,
                               "url": f.as_uri(), "sha256": header_tree._sha256_file(f)}

    def tearDown(self):
        self._tmp.cleanup()

    def fetch(self, decl):
        return deps.fetch(decl, self.bench, log=lambda m: None)


class TestIdentity(unittest.TestCase):
    def test_the_tree_id_follows_contents_not_presentation(self):
        d = _decl([{"package": "p", "sha256": "a" * 64}])
        same = dict(d, include_dirs=["usr/include"], why={"p": "x.h"},
                    manifest_sha256="b" * 64)
        self.assertEqual(deps.set_id(d), deps.set_id(same))
        self.assertTrue(deps.set_id(d).startswith("toy-linux-x86_64-"))
        self.assertNotEqual(deps.set_id(d), deps.set_id(dict(d, prune=["usr/include/linux"])))
        self.assertNotEqual(deps.set_id(d), deps.set_id(
            _decl([{"package": "p", "sha256": "c" * 64}])))

    def test_the_declaration_hash_ignores_its_result_and_review_notes(self):
        d = _decl([])
        self.assertEqual(deps.decl_sha256(d),
                         deps.decl_sha256(dict(d, manifest_sha256="b" * 64, why={"p": "x"})))
        self.assertNotEqual(deps.decl_sha256(d),
                            deps.decl_sha256(dict(d, include_dirs=["usr/include"])))

    def test_case_collisions_group_paths_that_differ_only_in_case(self):
        self.assertEqual(deps.case_collisions(["a/X.h", "a/x.h", "a/y.h", "B/z.h", "b/z.h"]),
                         [["B/z.h", "b/z.h"], ["a/X.h", "a/x.h"]])


class TestFetch(_Debs):
    def test_an_unpinned_set_reports_the_hash_to_declare(self):
        decl = _decl([self.debs["libc"]])
        res = self.fetch(decl)
        self.assertEqual(res["status"], deps.UNPINNED)
        # Computed from the archive members, and equal to the disk's.
        self.assertEqual(res["archive_manifest"], res["actual"])
        tree = Path(res["path"])
        self.assertTrue((tree / "usr/include/stdio.h").is_file())
        self.assertFalse((tree / "usr/share").exists())

    def test_a_pinned_set_verifies_and_a_second_fetch_reuses_the_cache(self):
        decl = _decl([self.debs["libc"]])
        decl["manifest_sha256"] = self.fetch(decl)["actual"]
        self.assertEqual(self.fetch(decl)["status"], deps.OK)
        self.assertEqual(deps.check(decl, self.bench)["status"], deps.OK)
        Path(self.debs["libc"]["url"][len("file://"):]).unlink()
        self.assertEqual(self.fetch(decl)["status"], deps.OK)

    def test_a_different_manifest_leaves_no_tree(self):
        decl = _decl([self.debs["libc"]], manifest_sha256="0" * 64)
        with self.assertRaises(ValueError):
            self.fetch(decl)
        self.assertEqual(deps.check(decl, self.bench)["status"], deps.MISSING)
        self.assertFalse(any(p.name.endswith(".partial") for p in (self.bench / "deps").iterdir()))

    def test_a_deb_whose_hash_differs_is_not_cached(self):
        bad = dict(self.debs["libc"], sha256="0" * 64)
        with self.assertRaises(ValueError):
            self.fetch(_decl([bad]))
        self.assertFalse((self.bench / "deps/.cache" / ("0" * 64)).exists())

    def test_a_tree_edited_after_fetch_no_longer_verifies(self):
        decl = _decl([self.debs["libc"]])
        decl["manifest_sha256"] = self.fetch(decl)["actual"]
        (deps.tree_path(decl, self.bench) / "usr/include/local.h").write_bytes(b"edited\n")
        self.assertEqual(deps.check(decl, self.bench)["status"], deps.MISMATCH)

    def test_case_colliding_paths_are_refused_where_the_filesystem_folds_case(self):
        decl = _decl([self.debs["kernel"]])
        with mock.patch.object(deps, "is_case_insensitive", return_value=True):
            with self.assertRaises(ValueError) as cm:
                self.fetch(decl)
        self.assertIn("usr/include/linux/netfilter/xt_DSCP.h / "
                      "usr/include/linux/netfilter/xt_dscp.h", str(cm.exception))
        self.assertEqual(deps.check(decl, self.bench)["status"], deps.MISSING)

    def test_a_pruned_subtree_is_neither_unpacked_nor_hashed(self):
        pruned = _decl([self.debs["kernel"]], prune=["usr/include/linux/netfilter"])
        with mock.patch.object(deps, "is_case_insensitive", return_value=True):
            res = self.fetch(pruned)
        tree = Path(res["path"])
        self.assertTrue((tree / "usr/include/linux/errno.h").is_file())
        self.assertFalse((tree / "usr/include/linux/netfilter").exists())
        whole = self.fetch(_decl([self.debs["kernel"]]))
        self.assertNotEqual(res["actual"], whole["actual"])

    def test_the_same_packages_pin_the_same_on_another_host(self):
        decl = _decl([self.debs["libc"], self.debs["kernel"]])
        a = self.fetch(decl)["actual"]
        other = self.tmp / "other-host"
        b = deps.fetch(decl, other, log=lambda m: None)["actual"]
        self.assertEqual(a, b)


class TestResolve(_Debs):
    def setUp(self):
        super().setUp()
        contents = {}
        for name, files in self.PACKAGES.items():
            for path in files:
                if path.startswith("usr/include/"):
                    contents.setdefault(path, []).append(name)
        index = {n: {"version": "1.0", "filename": f"pool/main/{d['file']}",
                     "sha256": d["sha256"]} for n, d in self.debs.items()}
        urls = {d["file"]: d["url"] for d in self.debs.values()}
        real_entry = deps.deb_entry
        self.patches = [
            mock.patch.object(deps, "packages_index", return_value=index),
            mock.patch.object(deps, "contents_index", return_value=contents),
            mock.patch.object(deps, "deb_entry", side_effect=lambda base, p, info: dict(
                real_entry(base, p, info), url=urls[info["filename"].rsplit("/", 1)[-1]])),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        super().tearDown()

    def resolve(self, decl, spellings):
        return deps.resolve(decl, spellings, self.bench, log=lambda m: None)

    def test_the_closure_follows_includes_into_other_packages(self):
        out = self.resolve(_decl([]), ["stdio.h"])
        self.assertEqual([d["package"] for d in out["debs"]], ["libc", "multilib"])
        self.assertEqual(out["why"], {"libc": "stdio.h", "multilib": "gnu/stubs-32.h"})
        self.assertEqual(out["unresolved"], [])

    def test_an_excluded_package_is_never_picked(self):
        out = self.resolve(_decl([], exclude={"multilib": "-m32 only"}), ["stdio.h"])
        self.assertEqual([d["package"] for d in out["debs"]], ["libc"])
        self.assertEqual(out["missed_in_closure"],
                         {"gnu/stubs-32.h": "usr/include/x86_64-linux-gnu/bits/types.h"})

    def test_an_inventory_spelling_no_package_provides_is_unresolved(self):
        out = self.resolve(_decl([]), ["windows.h", "linux/errno.h"])
        self.assertEqual(out["unresolved"], ["windows.h"])
        self.assertEqual([d["package"] for d in out["debs"]], ["kernel"])

    def test_a_pruned_path_an_include_reaches_is_reported(self):
        out = self.resolve(_decl([], prune=["usr/include/linux/netfilter"]),
                           ["linux/netfilter/xt_dscp.h"])
        self.assertEqual(out["pruned_but_reached"],
                         {"usr/include/linux/netfilter/xt_dscp.h": "(inventory)"})


class TestRunner(unittest.TestCase):
    def test_no_declaration_means_no_set(self):
        with mock.patch.object(deps, "declared_for", return_value=None):
            self.assertIsNone(rr._verified_deps("lua"))

    def _refusal(self, status, actual=None, expected="a" * 64):
        decl = _decl([], manifest_sha256=expected)
        with mock.patch.object(deps, "declared_for", return_value=decl), \
             mock.patch.object(deps, "check", return_value={
                 "status": status, "path": "/d", "actual": actual, "expected": expected}):
            with self.assertRaises(FileNotFoundError) as cm:
                rr._verified_deps("toy")
        return str(cm.exception)

    def test_a_missing_unpinned_or_different_set_refuses_the_scan(self):
        self.assertIn("is missing", self._refusal(deps.MISSING))
        self.assertIn("bench.deps fetch toy", self._refusal(deps.MISSING))
        self.assertIn("no manifest_sha256", self._refusal(deps.UNPINNED, "b" * 64, None))
        self.assertIn("bbbbbbbbbbbb", self._refusal(deps.MISMATCH, "b" * 64))

    def test_the_set_replaces_every_include_outside_the_checkout(self):
        cfg = {"path": Path("/cb"), "sqc": {
            "manifest": rr.CODEBASES["lua"]["sqc"]["manifest"],
            "includes": ["-I", "/usr/include", "-I", "{path}/lib",
                         "-I", "/usr/include/tcl8.6", "-I", "{path}/include"]}}
        cmd = rr._build_sqc_cmd(cfg, Path("/out"), "rid",
                                deps_includes=["-I", "/d/usr/include"])
        self.assertEqual(cmd[-6:], ["-I", "/cb/lib", "-I", "/cb/include",
                                    "-I", "/d/usr/include"])
        self.assertNotIn("/usr/include/tcl8.6", cmd)

    def test_provenance_is_the_fifth_pin(self):
        decl = _decl([], manifest_sha256="c" * 64)
        self.assertEqual(deps.provenance(decl), {
            "id": deps.set_id(decl), "platform": "linux-x86_64",
            "decl_sha256": deps.decl_sha256(decl), "manifest_sha256": "c" * 64})


class TestCorpusCheck(_Debs):
    def test_a_declared_set_is_checked_like_a_pinned_tree(self):
        decl = _decl([self.debs["libc"]])
        decl["manifest_sha256"] = self.fetch(decl)["actual"]
        f = self.tmp / "toy.json"
        f.write_text(json.dumps(decl))
        entry = {"name": "toy", "version": "0" * 40, "deps": str(f)}
        res = corpus.check_repo(entry, self.bench)
        self.assertEqual(res["header_tree"]["status"], deps.OK)
        self.assertFalse(corpus.header_tree_bad(res))
        decl["manifest_sha256"] = "0" * 64
        f.write_text(json.dumps(decl))
        self.assertTrue(corpus.header_tree_bad(corpus.check_repo(entry, self.bench)))


if __name__ == "__main__":
    unittest.main()
