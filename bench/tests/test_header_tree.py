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

    def test_only_a_tree_standing_in_for_host_headers_changes_the_run_id(self):
        self.assertEqual(rr._header_tree_suffix(None), "")
        self.assertEqual(rr._header_tree_suffix(header_tree.host_spec("/usr/include")), "")
        self.assertEqual(rr._header_tree_suffix(_spec("win", "0" * 64)), "")
        self.assertEqual(rr._header_tree_suffix({"id": "deb", "replaces": "/usr/include"}),
                         "-hdr-deb")

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



def _ar_member(name: str, body: bytes) -> bytes:
    hdr = f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n".encode()
    return hdr + body + (b"\n" if len(body) % 2 else b"")


def _deb_members(members: list, compression: str = "xz") -> bytes:
    """A .deb from an ordered list of (kind, name, payload) members, kind
    one of 'file' (payload bytes), 'sym' (payload target), 'hard' (payload
    the ./-prefixed name of an earlier member) or 'dir'. Names are written
    exactly as given, so a test can craft ../ names."""
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=f"w:{compression}") as tar:
        for kind, name, payload in members:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                ti.size = len(payload)
                tar.addfile(ti, io.BytesIO(payload))
                continue
            ti.type = {"sym": tarfile.SYMTYPE, "hard": tarfile.LNKTYPE,
                       "dir": tarfile.DIRTYPE}[kind]
            if kind != "dir":
                ti.linkname = payload
            tar.addfile(ti)
    return (b"!<arch>\n" + _ar_member("debian-binary", b"2.0\n")
            + _ar_member("control.tar.xz", b"")
            + _ar_member(f"data.tar.{compression}", buf.getvalue()))


def _deb(files: dict, links: dict | None = None, compression: str = "xz") -> bytes:
    """A minimal .deb: an ar archive whose data.tar.<compression> holds
    `files` ({path: bytes}) and `links` ({path: target}) as ./-prefixed
    members, the way dpkg-deb writes them."""
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=f"w:{compression}") as tar:
        for name, body in files.items():
            ti = tarfile.TarInfo("./" + name)
            ti.size = len(body)
            tar.addfile(ti, io.BytesIO(body))
        for name, target in (links or {}).items():
            ti = tarfile.TarInfo("./" + name)
            ti.type = tarfile.SYMTYPE
            ti.linkname = target
            tar.addfile(ti)
    return (b"!<arch>\n" + _ar_member("debian-binary", b"2.0\n")
            + _ar_member("control.tar.xz", b"")
            + _ar_member(f"data.tar.{compression}", buf.getvalue()))


class TestExtractHeaders(unittest.TestCase):
    def setUp(self):
        # dest sits one level down, so a member that escapes it lands in a
        # directory this test owns and can check, never in the shared /tmp.
        self._tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self._tmp.name) / "tree"
        self.dest.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def test_only_usr_include_is_unpacked(self):
        n = header_tree.extract_headers(_deb({
            "usr/include/a.h": b"a\n",
            "usr/include/x86_64-linux-gnu/sys/wait.h": b"w\n",
            "usr/lib/x86_64-linux-gnu/liba.so": b"elf\n",
            "usr/share/doc/a/copyright": b"c\n"}), self.dest)
        self.assertEqual(n, 2)
        self.assertEqual((self.dest / "usr/include/a.h").read_bytes(), b"a\n")
        self.assertFalse((self.dest / "usr/lib").exists())
        self.assertFalse((self.dest / "usr/share").exists())

    def test_relative_symlinks_are_kept_as_links(self):
        header_tree.extract_headers(_deb(
            {"usr/include/x86_64-linux-gnu/bits/t.h": b"t\n"},
            {"usr/include/bits": "x86_64-linux-gnu/bits"}), self.dest)
        link = self.dest / "usr/include/bits"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "x86_64-linux-gnu/bits")

    def test_an_absolute_or_escaping_symlink_is_refused(self):
        for target in ("/etc/passwd", "../../../../etc/passwd"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as d:
                with self.assertRaises(ValueError):
                    header_tree.extract_headers(
                        _deb({}, {"usr/include/evil.h": target}), d)

    def test_identical_overlap_is_fine_and_a_differing_one_is_refused(self):
        header_tree.extract_headers(_deb({"usr/include/a.h": b"a\n"}), self.dest)
        header_tree.extract_headers(_deb({"usr/include/a.h": b"a\n"}), self.dest)
        with self.assertRaises(ValueError):
            header_tree.extract_headers(_deb({"usr/include/a.h": b"b\n"}), self.dest)

    def test_gzip_payload_reads_too(self):
        header_tree.extract_headers(_deb({"usr/include/g.h": b"g\n"}, compression="gz"),
                                    self.dest)
        self.assertTrue((self.dest / "usr/include/g.h").is_file())

    def test_a_symlink_chain_that_resolves_outside_is_refused(self):
        # a -> ../.. reads as inside (usr/include/../.. is the tree root);
        # b -> a/.. reads as inside too, but through a it resolves to the
        # tree's parent, so a file under b would land outside the tree.
        with self.assertRaises(ValueError):
            header_tree.extract_headers(_deb_members([
                ("dir", "./usr/include", None),
                ("sym", "./usr/include/a", "../.."),
                ("sym", "./usr/include/b", "a/.."),
                ("file", "./usr/include/b/x", b"x\n")]), self.dest)
        self.assertEqual(sorted(p.name for p in self.dest.parent.iterdir()), ["tree"])

    def test_member_names_are_normalized_before_the_prefix_test(self):
        # usr/include/../../x is x: outside the prefix, so it is never written.
        n = header_tree.extract_headers(_deb_members([
            ("file", "./usr/include/../../x", b"x\n"),
            ("file", "./usr/include/ok.h", b"ok\n")]), self.dest)
        self.assertEqual(n, 1)
        self.assertFalse((self.dest / "x").exists())
        self.assertEqual(sorted(p.name for p in self.dest.parent.iterdir()), ["tree"])

    def test_a_member_climbing_out_of_the_archive_is_refused(self):
        with self.assertRaises(ValueError):
            header_tree.extract_headers(_deb_members([
                ("file", "./../usr/include/x.h", b"x\n")]), self.dest)

    def test_a_hardlink_is_unpacked_as_a_copy(self):
        header_tree.extract_headers(_deb_members([
            ("file", "./usr/include/a.h", b"a\n"),
            ("hard", "./usr/include/b.h", "./usr/include/a.h")]), self.dest)
        b = self.dest / "usr/include/b.h"
        self.assertFalse(b.is_symlink())
        self.assertEqual(b.read_bytes(), b"a\n")

    def test_not_a_deb_is_refused(self):
        with self.assertRaises(ValueError):
            header_tree.extract_headers(b"PK\x03\x04 a zip", self.dest)


class TestFetchDebs(unittest.TestCase):
    """End to end against file:// URLs: the same code path a node runs
    against snapshot.debian.org, without the network."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.bench = self.tmp / "bench"
        debs = []
        for i, files in enumerate([{"usr/include/a.h": b"a\n"},
                                   {"usr/include/x86_64-linux-gnu/sys/w.h": b"w\n"}]):
            f = self.tmp / f"p{i}_1.0_amd64.deb"
            f.write_bytes(_deb(files))
            debs.append({"package": f"p{i}", "version": "1.0", "file": f.name,
                         "url": f.as_uri(), "sha256": header_tree._sha256_file(f)})
        ref = self.tmp / "ref"
        for d in debs:
            header_tree.extract_headers((self.tmp / d["file"]).read_bytes(), ref)
        self.spec = {"id": "deb-test", "fetch": {"kind": "debs", "debs": debs},
                     "replaces": "/usr/include", "hashed_dirs": ["usr/include"],
                     "manifest_sha256": header_tree.manifest_sha256(ref, ["usr/include"]),
                     "include_dirs": ["usr/include/x86_64-linux-gnu"]}

    def tearDown(self):
        self._tmp.cleanup()

    def test_fetch_provisions_a_verified_tree(self):
        res = header_tree.fetch(self.spec, self.bench, log=lambda m: None)
        self.assertEqual(res["status"], header_tree.OK)
        self.assertTrue((self.bench / "header-trees/deb-test/usr/include/a.h").is_file())
        # A second fetch reuses the cache and lands on the same tree.
        res = header_tree.fetch(self.spec, self.bench, log=lambda m: None)
        self.assertEqual(res["status"], header_tree.OK)

    def test_a_deb_whose_hash_differs_leaves_no_tree(self):
        self.spec["fetch"]["debs"][1]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            header_tree.fetch(self.spec, self.bench, log=lambda m: None)
        trees = self.bench / "header-trees"
        self.assertFalse((trees / "deb-test").exists())
        self.assertFalse((trees / ".deb-test.partial").exists())

    def test_a_tree_whose_manifest_differs_leaves_no_tree(self):
        self.spec["manifest_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            header_tree.fetch(self.spec, self.bench, log=lambda m: None)
        self.assertFalse((self.bench / "header-trees/deb-test").exists())

    def test_a_failed_download_leaves_no_part_file(self):
        missing = self.tmp / "gone_1.0_amd64.deb"
        with self.assertRaises(OSError):
            header_tree._download(missing.as_uri(), self.tmp / "out.deb")
        self.assertFalse((self.tmp / "out.deb.part").exists())
        self.assertFalse((self.tmp / "out.deb").exists())

    def test_only_debs_trees_are_fetched(self):
        with self.assertRaises(ValueError):
            header_tree.fetch(_spec("x", "0" * 64), self.bench, log=lambda m: None)


class TestSharedTrees(unittest.TestCase):
    DATA = {"header_trees": {
                "deb-a": {"id": "deb-a", "replaces": "/usr/include"},
                "other": {"id": "other", "replaces": "/opt/include"}},
            "repos": [
                {"name": "hosty", "host_headers": "/usr/include"},
                {"name": "win", "header_tree": _spec("win-tree", "0" * 64)},
                {"name": "plain"}]}

    def setUp(self):
        p = mock.patch.object(header_tree, "_repos", return_value=self.DATA)
        p.start()
        self.addCleanup(p.stop)
        e = mock.patch.dict("os.environ")
        e.start()
        self.addCleanup(e.stop)
        os.environ.pop(header_tree.HOST_TREE_ENV, None)

    def test_a_string_names_a_shared_tree(self):
        self.assertEqual(header_tree.resolve("deb-a", self.DATA)["id"], "deb-a")

    def test_an_unknown_tree_is_refused(self):
        with self.assertRaises(KeyError):
            header_tree.resolve("nope", self.DATA)

    def test_host_headers_are_the_default(self):
        spec = header_tree.spec_for("hosty")
        self.assertEqual(spec["id"], header_tree.HOST)
        self.assertEqual(header_tree.check(spec)["status"], header_tree.OK)
        includes = ["-I", "/usr/include", "-I", "/usr/include/libnl3"]
        self.assertEqual(header_tree.substitute_includes(spec, includes), includes)
        self.assertEqual(header_tree.provenance(spec),
                         {"id": "host", "host": True, "replaces": "/usr/include"})
        self.assertEqual(header_tree.spec_for("hosty", header_tree.HOST), spec)

    def test_a_named_tree_replacing_the_same_prefix_is_opted_into(self):
        self.assertEqual(header_tree.spec_for("hosty", "deb-a")["id"], "deb-a")
        os.environ[header_tree.HOST_TREE_ENV] = "deb-a"
        self.assertEqual(header_tree.spec_for("hosty")["id"], "deb-a")

    def test_a_tree_for_another_prefix_is_refused(self):
        with self.assertRaises(ValueError):
            header_tree.spec_for("hosty", "other")

    def test_a_declared_tree_is_never_overridden(self):
        self.assertEqual(header_tree.spec_for("win", "deb-a")["id"], "win-tree")

    def test_a_corpus_without_system_headers_has_no_tree(self):
        self.assertIsNone(header_tree.spec_for("plain", "deb-a"))

    def test_the_cli_names_trees_not_host_header_corpora(self):
        self.assertEqual(header_tree._spec_arg("deb-a")["id"], "deb-a")
        self.assertEqual(header_tree._spec_arg("win")["id"], "win-tree")
        self.assertIsNone(header_tree._spec_arg("hosty"))
        self.assertEqual(header_tree.main(["verify", "hosty"]), 2)


class TestSubstituteIncludes(unittest.TestCase):
    SPEC = {"id": "deb", "replaces": "/usr/include",
            "include_dirs": ["usr/include/x86_64-linux-gnu"]}

    def test_rewrites_under_the_tree_with_multiarch_first(self):
        root = Path("/b/header-trees/deb")
        out = header_tree.substitute_includes(
            self.SPEC, ["-I", "/cb/lib", "-I", "/usr/include", "-I", "/usr/include/libnl3"],
            Path("/b"))
        self.assertEqual(out, ["-I", "/cb/lib",
                               "-I", str(root / "usr/include/x86_64-linux-gnu"),
                               "-I", str(root / "usr/include"),
                               "-I", str(root / "usr/include/libnl3")])

    def test_a_path_that_only_shares_the_prefix_text_is_left_alone(self):
        includes = ["-I", "/usr/includes", "-I", "/usr/include-old"]
        self.assertEqual(header_tree.substitute_includes(self.SPEC, includes, Path("/b")),
                         includes)

    def test_build_sqc_cmd_substitutes_for_a_replacing_tree(self):
        cfg = {"path": Path("/cb"), "sqc": {"manifest": rr.CODEBASES["lua"]["sqc"]["manifest"],
                                            "includes": ["-I", "/usr/include"]}}
        with mock.patch.object(header_tree, "BENCH_ROOT", Path("/b")):
            cmd = rr._build_sqc_cmd(cfg, Path("/out"), "rid", header_spec=self.SPEC)
        self.assertNotIn("/usr/include", cmd)
        self.assertIn(str(Path("/b/header-trees/deb/usr/include")), cmd)


class TestHostHeaderDeclaration(unittest.TestCase):
    """Every corpus that scans with -I /usr/include says so ('host_headers'),
    so --header-tree can stand a tree in for it, and every 'debs' tree pins
    each package by version, file, snapshot URL and sha256."""

    def test_corpora_reading_host_headers_declare_the_prefix(self):
        entries = {e["name"]: e for e in header_tree._repos()["repos"]}
        for name, cfg in rr.CODEBASES.items():
            incs = cfg["sqc"].get("includes", [])
            reads = any(v == "/usr/include" or str(v).startswith("/usr/include/")
                        for v in incs)
            with self.subTest(corpus=name):
                self.assertEqual(entries[name].get("host_headers"),
                                 "/usr/include" if reads else None)

    def test_host_header_corpora_scan_the_host_by_default(self):
        with mock.patch.dict("os.environ"):
            os.environ.pop(header_tree.HOST_TREE_ENV, None)
            for e in header_tree._repos()["repos"]:
                if e.get("host_headers"):
                    with self.subTest(corpus=e["name"]):
                        self.assertTrue(header_tree.spec_for(e["name"])["host"])

    def test_debs_trees_pin_every_package(self):
        trees = header_tree._repos().get("header_trees", {})
        self.assertTrue(trees)
        for tid, spec in trees.items():
            self.assertEqual(spec["id"], tid)
            for d in spec["fetch"]["debs"]:
                with self.subTest(tree=tid, package=d["package"]):
                    self.assertTrue(d["url"].startswith(header_tree.SNAPSHOT + "/file/"))
                    self.assertRegex(d["sha256"], r"^[0-9a-f]{64}$")
                    self.assertIn(f"_{d['version'].split(':')[-1]}_", d["file"])
            for inc in spec["include_dirs"]:
                self.assertTrue(any(inc == h or inc.startswith(h + "/")
                                    for h in spec["hashed_dirs"]))


if __name__ == "__main__":
    unittest.main()
