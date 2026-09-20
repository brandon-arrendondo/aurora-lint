"""scripts/generate_changelog.py and scripts/check_changelog_safety.py: the
ADR-0007 gate between the task database and the public CHANGELOG.md.

Task titles are internal working notes and routinely locate a defect in a
real-world corpus ("confirmed OOB write at foo.c:579"); CHANGELOG.md ships in
every release tarball. Until task 1375 the generator published every done
task's title verbatim. These tests pin the three layers that now stand in
between, against a real SQLite task table with sensitive titles rather than a
hand-rolled fixture object, so a schema drift in `load_tasks` (a renamed
column, a lost `details` read) fails here instead of on a release:

1. only a task tagged `release-note` is published, and its `release-note:`
   body line replaces the title;
2. a tagged task is still dropped, by name, if it carries a disclosure-family
   tag or its published text matches a content deny pattern;
3. the content scan itself, which CI runs over the committed file.

The generator's git-reading helpers (`released_versions`, `current_version`)
are not exercised: `build` takes the release list as an argument.
"""

import contextlib
import io
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_changelog_safety as safety  # noqa: E402
import generate_changelog as gen  # noqa: E402

RELEASES = [("0.1.0", "v0.1.0", "2026-01-01T00:00:00+00:00")]


def seed_db(path, tasks):
    """Write the fleet task schema (the columns the generator reads) and `tasks`.

    Each task is (id, title, tags, details, project_name, status).
    """
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE tasks (
            uuid TEXT PRIMARY KEY, id INTEGER NOT NULL, title TEXT NOT NULL,
            details TEXT, status TEXT NOT NULL, completed_at TEXT,
            project_name TEXT
        );
        CREATE TABLE tags (task_uuid TEXT NOT NULL, tag TEXT NOT NULL);
        """
    )
    for task_id, title, tags, details, project, status in tasks:
        uuid = f"uuid-{task_id}"
        completed = f"2026-02-{task_id:02d}T00:00:00+00:00" if status == "done" else None
        con.execute(
            "INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
            (uuid, task_id, title, details, status, completed, project),
        )
        con.executemany("INSERT INTO tags VALUES (?, ?)", [(uuid, t) for t in tags])
    con.commit()
    con.close()


SENSITIVE_TITLE = "MEM31-C: possible double-free sites in curl url.c:329 / hostap wpa_supplicant.c:8215"

FIXTURE = [
    # (id, title, tags, details, project, status)
    (1, SENSITIVE_TITLE, {"rule-bug"}, "", "aurora_lint", "done"),
    (2, "hostap disclosure: act on maintainer response", {"disclosure"}, "", "aurora_lint", "done"),
    (3, "INT34-C: no value-range reasoning for shift amounts", {"release-note", "rule-bug"},
     "", "aurora_lint", "done"),
    (4, "a real, documented OOB-write TP at sqlite fts3view.c:579 -- recall regression",
     {"release-note", "recall"},
     "Body prose.\nrelease-note: VRA: a fix no longer suppresses a class of out-of-bounds writes\nmore prose",
     "aurora_lint", "done"),
    (5, "Valkey upstream report candidate: investigate valkey-benchmark.c:556",
     {"release-note", "adr-0007", "upstream-candidate"}, "", "aurora_lint", "done"),
    (6, "MEM30-C: sibling early-exit branches cross-flagged", {"release-note", "rule-bug"},
     "", "aurora_lint", "done"),
    (7, "ARR30-C: buffer mis-linking at p2p_supplicant.c:5132", {"release-note", "rule-bug"},
     "", "aurora_lint", "done"),
    (8, "EXP34-C: NORETURN calls terminate flow", {"release-note", "rule-bug"},
     "release-note: EXP34-C: fixed at conf.c:921 (real bug)", "aurora_lint", "done"),
    (9, "Adjudicate MSC10-C findings into ground_truth", {"release-note", "adjudication"},
     "", "aurora_lint", "done"),
    (10, "Paper figure regen", {"release-note"}, "", "sqc_paper", "done"),
    (11, "Pending: not done yet", {"release-note"}, "", "aurora_lint", "pending"),
    (12, "compile_commands: recover implicit system include dirs", {"release-note", "feature"},
     "", "aurora_lint", "done"),
]


class TestGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "tasks.db"
        seed_db(cls.db, FIXTURE)
        cls.tasks = gen.load_tasks(cls.db)
        cls.warnings = []
        cls.sections = gen.sections_for(cls.tasks, warn=cls.warnings.append)
        cls.bullets = [b for bullets in cls.sections.values() for b in bullets]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_only_done_aurora_lint_tasks_load(self):
        ids = sorted(t.id for t in self.tasks)
        self.assertNotIn(10, ids, "another project's task loaded")
        self.assertNotIn(11, ids, "a pending task loaded")
        self.assertIn(1, ids)

    def test_untagged_task_is_not_published_and_not_warned_about(self):
        self.assertFalse(any(SENSITIVE_TITLE in b for b in self.bullets))
        self.assertFalse(any("task 1:" in w for w in self.warnings))

    def test_tagged_safe_title_is_published_in_its_bucket(self):
        self.assertIn("INT34-C: no value-range reasoning for shift amounts", self.sections["Fixed"])
        self.assertIn("MEM30-C: sibling early-exit branches cross-flagged", self.sections["Fixed"])
        self.assertIn("compile_commands: recover implicit system include dirs", self.sections["Added"])

    def test_release_note_line_replaces_the_title(self):
        self.assertIn("VRA: a fix no longer suppresses a class of out-of-bounds writes",
                      self.sections["Fixed"])
        self.assertFalse(any("fts3view" in b for b in self.bullets))

    def test_disclosure_family_tag_blocks_even_with_allow_tag(self):
        self.assertFalse(any("valkey" in b.lower() for b in self.bullets))
        self.assertTrue(any("task 5:" in w and "adr-0007" in w for w in self.warnings), self.warnings)

    def test_sensitive_title_without_note_is_dropped_with_warning(self):
        self.assertFalse(any("p2p_supplicant" in b for b in self.bullets))
        self.assertTrue(any("task 7:" in w and "deny pattern" in w for w in self.warnings), self.warnings)

    def test_sensitive_release_note_line_is_dropped_too(self):
        self.assertFalse(any("conf.c" in b for b in self.bullets))
        self.assertTrue(any("task 8:" in w for w in self.warnings), self.warnings)

    def test_never_shipped_tag_contradicts_allow_tag(self):
        self.assertFalse(any("MSC10-C" in b for b in self.bullets))
        self.assertTrue(any("task 9:" in w and "adjudication" in w for w in self.warnings), self.warnings)

    def test_warnings_name_the_task_id_never_the_title(self):
        for w in self.warnings:
            self.assertNotIn(".c:", w, w)
            self.assertNotIn("valkey", w.lower(), w)

    def test_built_changelog_passes_the_content_scan(self):
        with contextlib.redirect_stderr(io.StringIO()):
            text = gen.build(self.tasks, RELEASES, "0.2.0")
        self.assertEqual(safety.find_sensitive(text), [])
        self.assertIn("## [Unreleased]", text)
        self.assertIn("- INT34-C: no value-range reasoning for shift amounts", text)


class TestNoDatabase(unittest.TestCase):
    """The release workflow has no task DB (CLAUDE.md: task tracking is not part
    of the repo) and must still produce valid, empty-of-bullets notes."""

    def test_missing_db_degrades_to_empty(self):
        with contextlib.redirect_stderr(io.StringIO()):
            tasks = gen.load_tasks(Path(tempfile.gettempdir()) / "does-not-exist.db")
        self.assertEqual(tasks, [])
        text = gen.build(tasks, RELEASES, "0.2.0")
        body = gen.extract_section(text, "0.1.0")
        self.assertIn("No release notes recorded", body)
        self.assertEqual(safety.find_sensitive(text), [])

    def test_wrong_schema_degrades_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "other.db"
            con = sqlite3.connect(path)
            con.execute("CREATE TABLE unrelated (x)")
            con.commit()
            con.close()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(gen.load_tasks(path), [])


class TestContentScan(unittest.TestCase):
    OFFENDING = [
        "- hostap ARR30-C: fix buffer mis-linking at p2p_supplicant.c:5132",
        "- MEM31-C double free -- pure-pw.c:902/1054/1261",
        "- EXP34-C: conf.c line 921 confirmed",
        "- Investigate upstream status: file disclosure if unfixed",
        "- Pending response from maintainer",
        "- Valkey upstream report candidate",
        "- Reported upstream, awaiting fix",
        "- CVE-2026-0001 mapping",
        "- 5 confirmed recall regressions -- real bugs the tool used to catch",
        "- a genuine double-free in the parser",
    ]
    CLEAN = [
        "- INT30-C/INT31-C: pointer arithmetic misclassified as integer arithmetic",
        "- DCL31-C: attribute macros between type specifier and declarator",
        "- compile_commands: recover the compiler's implicit include dirs (cc -E -Wp,-v -)",
        "- bench/realworld_runner.py: record the checkout SHA",
        "- src/analyze/vra.rs: widen the lattice",  # Rust path, not a corpus location
        "- MEM07-C: advisory rule now respects the manifest",  # CERT vocabulary
        "- 0/104 TP on sel4 (measurement, no location)",
    ]

    def test_every_offending_line_is_caught(self):
        for line in self.OFFENDING:
            self.assertTrue(safety.is_sensitive(line), line)

    def test_clean_lines_pass(self):
        for line in self.CLEAN:
            self.assertFalse(safety.is_sensitive(line), line)

    def test_find_sensitive_reports_line_numbers_and_pattern(self):
        text = "\n".join(self.CLEAN[:2] + self.OFFENDING[:1] + self.CLEAN[2:3])
        hits = safety.find_sensitive(text)
        self.assertEqual([(h[0], h[1]) for h in hits], [(3, "source location (file:line)")])

    def test_main_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.md"
            good = Path(d) / "good.md"
            bad.write_text("\n".join(self.CLEAN + self.OFFENDING[:2]) + "\n")
            good.write_text("\n".join(self.CLEAN) + "\n")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(safety.main([str(good)]), 0)
                self.assertEqual(safety.main([str(bad), str(good)]), 1)
                self.assertEqual(safety.main([]), 2)
            self.assertIn("bad.md:8:", err.getvalue())
            self.assertIn("2 line(s)", err.getvalue())

    def test_committed_changelog_header_is_clean(self):
        # The generator's own prose must not trip the scan it enforces.
        self.assertEqual(safety.find_sensitive(gen.HEADER), [])


if __name__ == "__main__":
    unittest.main()
