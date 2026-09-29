"""scripts/assemble_pages_site.py and scripts/fetch_published_pages.sh: the
GitHub Pages site keeps each release's docs under /<tag>/ for good.

Papers cite a release's rendered docs pages, so the property that matters is
that no later deploy removes or changes a published release directory: a main
deploy copies every one forward, and a tag deploy refuses a tag already
published. These tests run the sequence of deploys the two workflows make,
on small hand-built trees standing in for Sphinx output (the bench suite
installs nothing, so Sphinx is not available here), and the fetch script
against a local bare repository standing in for origin.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import assemble_pages_site as site  # noqa: E402

CONF_PY = REPO_ROOT / "docs" / "conf.py"


def fake_build(root: Path, marker: str, pages=("index.html", "configuration.html")) -> Path:
    """A directory shaped like `sphinx-build -b html` output."""
    root.mkdir(parents=True)
    for page in pages:
        (root / page).write_text(f"<html><body>{marker} {page}: 311 rules</body></html>")
    (root / "_static").mkdir()
    (root / "_static" / "theme.css").write_text(marker)
    return root


class AssembleSiteTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.published = self.tmp / "published"
        self.published.mkdir()
        self.n = 0

    def tearDown(self):
        self._tmp.cleanup()

    def deploy(self, kind, marker, tag=None, pages=("index.html", "configuration.html")):
        """Run one deploy and make its output the published site."""
        self.n += 1
        build = fake_build(self.tmp / f"build{self.n}", marker, pages)
        out = self.tmp / f"out{self.n}"
        if kind == "main":
            site.assemble_main(build, self.published, out, CONF_PY)
        else:
            site.assemble_tag(tag, build, self.published, out, CONF_PY)
        self.published = out
        return out

    def test_release_directories_survive_later_main_deploys(self):
        self.deploy("main", "main-1")
        self.deploy("tag", "tag-v0.6.0", tag="v0.6.0")
        cited = (self.published / "v0.6.0" / "configuration.html").read_text()
        self.deploy("main", "main-2")
        self.deploy("main", "main-3")
        self.assertEqual((self.published / "v0.6.0" / "configuration.html").read_text(), cited)
        self.assertIn("main-3", (self.published / "index.html").read_text())

    def test_main_deploy_drops_pages_main_no_longer_builds(self):
        self.deploy("main", "main-1", pages=("index.html", "old-page.html"))
        self.deploy("main", "main-2", pages=("index.html",))
        self.assertFalse((self.published / "old-page.html").exists())

    def test_tag_deploy_leaves_root_and_other_releases_alone(self):
        self.deploy("main", "main-1")
        self.deploy("tag", "tag-v0.6.0", tag="v0.6.0")
        root = (self.published / "index.html").read_text()
        self.deploy("tag", "tag-v0.6.1", tag="v0.6.1")
        self.assertEqual((self.published / "index.html").read_text(), root)
        self.assertIn("tag-v0.6.0", (self.published / "v0.6.0" / "index.html").read_text())
        self.assertIn("tag-v0.6.1", (self.published / "v0.6.1" / "index.html").read_text())

    def test_a_published_tag_is_never_replaced(self):
        self.deploy("main", "main-1")
        self.deploy("tag", "tag-v0.6.0", tag="v0.6.0")
        with self.assertRaisesRegex(site.Refused, "already published"):
            self.deploy("tag", "rebuilt", tag="v0.6.0")

    def test_first_deploy_can_be_a_tag(self):
        self.deploy("tag", "tag-v0.6.0", tag="v0.6.0")
        self.assertTrue((self.published / "v0.6.0" / "index.html").is_file())
        self.assertTrue((self.published / "versions.html").is_file())

    def test_non_release_tag_is_refused(self):
        for tag in ("latest", "v0.6", "../v0.6.0", "v0.6.0/x", "v1.2.3.foo", "v1.0.0-", "v1.0.0-rc..1"):
            with self.assertRaisesRegex(site.Refused, "not a release tag"):
                self.deploy("tag", "x", tag=tag)

    def test_pre_release_tags_are_accepted(self):
        for tag in ("v1.0.0-rc1", "v1.0.0-rc.1", "v2.0.0-beta.2.x"):
            self.deploy("tag", tag, tag=tag)
            self.assertTrue((self.published / tag / "index.html").is_file())

    def test_main_build_may_not_shadow_a_release(self):
        self.deploy("tag", "tag-v0.6.0", tag="v0.6.0")
        build = fake_build(self.tmp / "clash", "main")
        (build / "v0.6.0").mkdir()
        with self.assertRaisesRegex(site.Refused, "release's path"):
            site.assemble_main(build, self.published, self.tmp / "out-clash", CONF_PY)

    def test_versions_page_lists_releases_newest_first(self):
        self.deploy("main", "main-1")
        for tag in ("v0.9.0", "v0.10.0", "v1.0.0-rc1", "v1.0.0"):
            self.deploy("tag", tag, tag=tag)
        self.deploy("main", "main-2")
        page = (self.published / "versions.html").read_text()
        order = [page.index(f'"{t}/index.html"') for t in ("v1.0.0", "v1.0.0-rc1", "v0.10.0", "v0.9.0")]
        self.assertEqual(order, sorted(order))

    def test_unresolved_substitution_is_refused(self):
        names = site.epilog_substitutions(CONF_PY)
        self.assertIn("rules_total", names)
        build = fake_build(self.tmp / "raw", "main")
        (build / "configuration.html").write_text("<p>|rules_enabled| of the rules</p>")
        with self.assertRaisesRegex(site.Refused, r"configuration.html: \|rules_enabled\|"):
            site.assemble_main(build, self.published, self.tmp / "out-raw", CONF_PY)

    def test_substitution_shown_as_code_is_allowed(self):
        build = fake_build(self.tmp / "literal", "main")
        (build / "configuration.html").write_text(
            '<p>Write <code class="docutils literal"><span class="pre">|rules_total|</span></code>'
            ' in a page.</p>\n<div class="highlight"><pre>see |rules_enabled|\n</pre></div>'
        )
        site.assemble_main(build, self.published, self.tmp / "out-literal", CONF_PY)
        (build / "configuration.html").write_text(
            "<pre>|rules_total|</pre><p><strong>|rules_enabled|</strong></p>"
        )
        with self.assertRaisesRegex(site.Refused, r"\|rules_enabled\|"):
            site.assemble_main(build, self.published, self.tmp / "out-prose", CONF_PY)

    def test_sphinx_build_state_is_not_published(self):
        build = fake_build(self.tmp / "state", "main")
        (build / ".buildinfo").write_text("config: abc")
        (build / ".doctrees").mkdir()
        (build / ".doctrees" / "index.doctree").write_text("x")
        out = self.tmp / "out-state"
        site.assemble_main(build, self.published, out, CONF_PY)
        site.assemble_tag("v0.6.0", build, out, self.tmp / "out-state-tag", CONF_PY)
        for root in (out, self.tmp / "out-state-tag" / "v0.6.0"):
            self.assertFalse((root / ".buildinfo").exists())
            self.assertFalse((root / ".doctrees").exists())
            self.assertTrue((root / "index.html").is_file())

    def test_missing_releases_are_named(self):
        self.deploy("tag", "tag-v0.6.0", tag="v0.6.0")
        tags = ["v0.6.0", "v0.6.1", "v0.7.0-rc1", "not-a-release"]
        self.assertEqual(site.missing_releases(self.published, tags), ["v0.6.1", "v0.7.0-rc1"])

    def test_output_directory_must_be_new(self):
        build = fake_build(self.tmp / "b", "main")
        out = self.tmp / "exists"
        out.mkdir()
        with self.assertRaises(FileExistsError):
            site.assemble_main(build, self.published, out, CONF_PY)


class FetchPublishedPagesTests(unittest.TestCase):
    """The fetch script against a bare repository standing in for origin."""

    SCRIPT = REPO_ROOT / "scripts" / "fetch_published_pages.sh"

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.env = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
        }
        for var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            self.env.pop(var, None)
        self.origin = self.tmp / "origin.git"
        self.git("init", "-q", "--bare", str(self.origin))
        self.clone = self.tmp / "clone"
        self.git("clone", "-q", str(self.origin), str(self.clone))

    def tearDown(self):
        self._tmp.cleanup()

    def git(self, *args, cwd=None):
        subprocess.run(["git", *args], cwd=cwd, env=self.env, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def fetch(self, dest):
        return subprocess.run(["bash", str(self.SCRIPT), str(dest)], cwd=self.clone,
                              env=self.env, capture_output=True, text=True)

    def test_no_gh_pages_branch_leaves_an_empty_directory(self):
        dest = self.tmp / "published"
        result = self.fetch(dest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(dest.iterdir()), [])

    def test_gh_pages_is_extracted(self):
        pages = self.tmp / "pages"
        self.git("init", "-q", "-b", "gh-pages", str(pages))
        (pages / "v0.6.0").mkdir()
        (pages / "v0.6.0" / "index.html").write_text("tagged")
        (pages / ".nojekyll").write_text("")
        self.git("add", "-A", cwd=pages)
        self.git("commit", "-q", "-m", "deploy", cwd=pages)
        self.git("push", "-q", str(self.origin), "gh-pages", cwd=pages)
        dest = self.tmp / "published"
        result = self.fetch(dest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((dest / "v0.6.0" / "index.html").read_text(), "tagged")
        self.assertTrue((dest / ".nojekyll").exists())

    def test_unreachable_origin_stops_the_deploy(self):
        self.git("remote", "set-url", "origin", str(self.tmp / "missing.git"), cwd=self.clone)
        result = self.fetch(self.tmp / "published")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
