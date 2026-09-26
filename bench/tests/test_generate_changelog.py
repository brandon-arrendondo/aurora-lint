"""scripts/generate_changelog.py and scripts/check_changelog_safety.py: the
ADR-0007 / ADR-0009 gate between the task database and the public CHANGELOG.md.

Task titles are internal working notes and routinely locate a defect in a
real-world corpus ("confirmed OOB write at foo.c:579"); CHANGELOG.md ships in
every release tarball. The generator used to publish every done task's title
verbatim; ADR-0009 then narrowed the changelog to
Added / Fixed / Removed notes written for publication. These tests pin the
layers, against a real SQLite task table with sensitive titles rather than a
hand-rolled fixture object, so a schema drift in `load_tasks` (a renamed
column, a lost `details` read) fails here instead of on a release:

1. only a task tagged `release-note` with a `release-note:` line AND a
   `category:` line (added|fixed|removed) is published, under that heading;
2. a tagged task is still dropped, by id, if it carries a disclosure-family
   tag, its bullet matches a content deny pattern, or its category is
   missing or unknown;
3. the generator owns only the [Unreleased] block and the link footer: the
   curated release sections are spliced back byte-for-byte, and a stale
   [Unreleased] is renamed to the newest tag rather than lost;
4. the content scan itself, which CI runs over the committed file.

The generator's git-reading helper (`released_versions`) is not exercised:
every function takes the release list as an argument.
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

RELEASES = [
    ("0.1.0", "v0.1.0", "2026-01-01T00:00:00+00:00"),
    ("0.2.0", "v0.2.0", "2026-02-15T00:00:00+00:00"),
]


def seed_db(path, tasks):
    """Write the fleet task schema (the columns the generator reads) and `tasks`.

    Each task is (id, title, tags, details, project_name, status, completed_at).
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
    for task_id, title, tags, details, project, status, completed in tasks:
        uuid = f"uuid-{task_id}"
        con.execute(
            "INSERT INTO tasks VALUES (?, ?, ?, ?, ?, ?, ?)",
            (uuid, task_id, title, details, status, completed if status == "done" else None, project),
        )
        con.executemany("INSERT INTO tags VALUES (?, ?)", [(uuid, t) for t in tags])
    con.commit()
    con.close()


def note(text, category="fixed"):
    return f"Body prose.\nrelease-note: {text}\ncategory: {category}\nmore prose"


SENSITIVE_TITLE = "MEM31-C: possible double-free sites in curl url.c:329 / hostap wpa_supplicant.c:8215"
T = "2026-03-%02dT00:00:00+00:00"  # after the newest release -> [Unreleased]
OLD = "2026-02-%02dT00:00:00+00:00"  # inside 0.2.0's window

FIXTURE = [
    # (id, title, tags, details, project, status, completed_at)
    (1, SENSITIVE_TITLE, {"rule-bug"}, note("never published: untagged"), "aurora_lint", "done", T % 1),
    (2, "hostap disclosure: act on maintainer response", {"disclosure"}, "", "aurora_lint", "done", T % 2),
    (3, "INT34-C: no value-range reasoning for shift amounts", {"release-note", "rule-bug"},
     note("INT34-C bounds a shift amount by the operand's width."), "aurora_lint", "done", T % 3),
    (4, "a real, documented OOB-write TP at sqlite fts3view.c:579 -- recall regression",
     {"release-note", "recall"},
     note("VRA no longer suppresses a class of out-of-bounds writes."), "aurora_lint", "done", T % 4),
    (5, "Valkey upstream report candidate: investigate valkey-benchmark.c:556",
     {"release-note", "adr-0007", "upstream-candidate"}, note("anything"), "aurora_lint", "done", T % 5),
    (6, "MEM30-C: sibling early-exit branches cross-flagged", {"release-note", "rule-bug"},
     "release-note: title-only, no category line", "aurora_lint", "done", T % 6),
    (7, "ARR30-C: buffer mis-linking at p2p_supplicant.c:5132", {"release-note", "rule-bug"},
     "category: fixed", "aurora_lint", "done", T % 7),
    (8, "EXP34-C: NORETURN calls terminate flow", {"release-note", "rule-bug"},
     note("EXP34-C: fixed at conf.c:921 (real bug)"), "aurora_lint", "done", T % 8),
    (9, "Adjudicate MSC10-C findings into ground_truth", {"release-note", "adjudication"},
     note("labels"), "aurora_lint", "done", T % 9),
    (10, "Paper figure regen", {"release-note"}, note("paper"), "sqc_paper", "done", T % 10),
    (11, "Pending: not done yet", {"release-note"}, note("pending"), "aurora_lint", "pending", None),
    (12, "compile_commands: recover implicit system include dirs", {"release-note", "feature"},
     note("`--system-includes` searches the compiler's own header directories.", "added"),
     "aurora_lint", "done", T % 12),
    (13, "drop the --legacy flag", {"release-note"},
     note("The `--legacy` flag is gone.", "Removed"), "aurora_lint", "done", T % 13),
    (14, "Changed-category note", {"release-note"},
     note("The default preset treats a dominating assert as a guard.", "changed"),
     "aurora_lint", "done", T % 14),
    (97, "Deprecated-category note", {"release-note"},
     note("something", "deprecated"), "aurora_lint", "done", T % 20),
    (15, "old fix in 0.2.0's window", {"release-note"},
     note("DCL31-C sees macro-wrapped declarators."), "aurora_lint", "done", OLD % 10),
    (16, "API00-C: wrapped release note must not be truncated at the first line break",
     {"release-note", "rule-bug"},
     "Body prose.\nrelease-note: API00-C again reports a function that passes an unvalidated\n"
     "pointer parameter to a helper whose only use of it is taking a member's\n"
     "address (&p->field), a case missed since 0.5.2.\ncategory: fixed\n",
     "aurora_lint", "done", T % 16),
    (17, "macro-gaps: informal 'release note' prose must not shadow the real directive",
     {"release-note", "rule-bug"},
     "RELEASE NOTE: proposing one, since this is documented CLI output and\n"
     "the old kind no longer appears. Coordinator's call on tagging:\n"
     "  release-note: the real, tagged bullet text.\n"
     "  category: fixed\nmore prose",
     "aurora_lint", "done", T % 17),
]

CURATED = """# Changelog

Hand-written preamble that must not move.

## [Unreleased]

### Fixed

- stale unreleased bullet

## [0.1.0] - 2026-01-01

### Added

- Curated history line one.
- Curated history line two, with `code` and a trailing space

[Unreleased]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/brandon-arrendondo/aurora-lint/releases/tag/v0.1.0
"""


class TestGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "tasks.db"
        seed_db(cls.db, FIXTURE)
        cls.tasks = gen.load_tasks(cls.db)
        cls.warnings = []
        cls.sections = gen.sections_for(gen.tasks_in_window(cls.tasks, RELEASES[-1][2], None),
                                        warn=cls.warnings.append)
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
        self.assertFalse(any("untagged" in b for b in self.bullets))
        self.assertFalse(any("task 1:" in w for w in self.warnings))

    def test_note_is_published_under_its_category(self):
        self.assertEqual(list(self.sections), ["Added", "Changed", "Fixed", "Removed"])
        self.assertIn("The default preset treats a dominating assert as a guard.",
                      self.sections["Changed"])
        self.assertIn("`--system-includes` searches the compiler's own header directories.",
                      self.sections["Added"])
        self.assertIn("INT34-C bounds a shift amount by the operand's width.", self.sections["Fixed"])
        self.assertIn("The `--legacy` flag is gone.", self.sections["Removed"])

    def test_title_is_never_published(self):
        for b in self.bullets:
            for t in self.tasks:
                self.assertNotIn(t.title, b)
        self.assertIn("VRA no longer suppresses a class of out-of-bounds writes.", self.sections["Fixed"])

    def test_missing_category_is_refused_by_id(self):
        self.assertFalse(any("title-only" in b for b in self.bullets))
        self.assertTrue(any("task 6:" in w and "category" in w for w in self.warnings), self.warnings)

    def test_missing_note_line_is_refused_by_id(self):
        self.assertFalse(any("p2p_supplicant" in b for b in self.bullets))
        self.assertTrue(any("task 7:" in w and "release-note" in w for w in self.warnings), self.warnings)

    def test_unknown_category_is_refused(self):
        self.assertFalse(any(b == "something" for b in self.bullets))
        self.assertTrue(any("task 97:" in w and "deprecated" in w for w in self.warnings), self.warnings)

    def test_wrapped_release_note_is_joined_not_truncated(self):
        # Regression: RELEASE_NOTE_LINE used to anchor on end-of-line ($), so a
        # bullet wrapped across several lines (as the coordinator writes them)
        # published only its first line.
        self.assertIn(
            "API00-C again reports a function that passes an unvalidated "
            "pointer parameter to a helper whose only use of it is taking a "
            "member's address (&p->field), a case missed since 0.5.2.",
            self.sections["Fixed"],
        )

    def test_informal_release_note_mention_does_not_shadow_the_real_directive(self):
        # Regression: searching for the FIRST "release note" occurrence could
        # pick up an earlier informal mention in the task's own discussion
        # instead of the actual tagged `release-note:` line further down.
        self.assertIn("the real, tagged bullet text.", self.sections["Fixed"])
        self.assertFalse(any("proposing one" in b for b in self.bullets))

    def test_disclosure_family_tag_blocks_even_with_allow_tag(self):
        self.assertFalse(any(b == "anything" for b in self.bullets))
        self.assertTrue(any("task 5:" in w and "adr-0007" in w for w in self.warnings), self.warnings)

    def test_sensitive_note_is_dropped(self):
        self.assertFalse(any("conf.c" in b for b in self.bullets))
        self.assertTrue(any("task 8:" in w and "deny pattern" in w for w in self.warnings), self.warnings)

    def test_never_shipped_tag_contradicts_allow_tag(self):
        self.assertFalse(any(b == "labels" for b in self.bullets))
        self.assertTrue(any("task 9:" in w and "adjudication" in w for w in self.warnings), self.warnings)

    def test_warnings_name_the_task_id_never_the_title(self):
        for w in self.warnings:
            self.assertNotIn(".c:", w, w)
            self.assertNotIn("valkey", w.lower(), w)

    def test_window_excludes_tasks_completed_before_the_newest_tag(self):
        self.assertFalse(any("DCL31-C" in b for b in self.bullets))
        old = gen.sections_for(gen.tasks_in_window(self.tasks, RELEASES[0][2], RELEASES[1][2]))
        self.assertEqual(old["Fixed"], ["DCL31-C sees macro-wrapped declarators."])

    def test_unreleased_block_passes_the_content_scan(self):
        with contextlib.redirect_stderr(io.StringIO()):
            lines = gen.build_unreleased(self.tasks, RELEASES)
        self.assertEqual(lines[0], "## [Unreleased]")
        self.assertEqual(safety.find_sensitive("\n".join(lines)), [])


class TestSplice(unittest.TestCase):
    NEW_BLOCK = ["## [Unreleased]", "", "### Fixed", "", "- fresh bullet", ""]

    def test_curated_sections_survive_byte_for_byte(self):
        out = gen.splice_unreleased(CURATED, self.NEW_BLOCK, RELEASES[:1])
        self.assertIn("Hand-written preamble that must not move.", out)
        self.assertIn("- Curated history line two, with `code` and a trailing space\n", out)
        self.assertIn("- fresh bullet", out)
        self.assertNotIn("stale unreleased bullet", out)
        # exactly one Unreleased heading, above the curated release
        self.assertEqual(out.count("## [Unreleased]"), 1)
        self.assertLess(out.index("## [Unreleased]"), out.index("## [0.1.0]"))

    def test_footer_is_regenerated_from_the_tags(self):
        out = gen.splice_unreleased(CURATED, self.NEW_BLOCK, RELEASES)
        self.assertTrue(out.rstrip().endswith("[0.1.0]: https://github.com/brandon-arrendondo/aurora-lint/releases/tag/v0.1.0"))
        self.assertIn("[Unreleased]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.2.0...HEAD", out)
        self.assertIn("[0.2.0]: https://github.com/brandon-arrendondo/aurora-lint/compare/v0.1.0...v0.2.0", out)
        self.assertEqual(out.count("[0.1.0]: https"), 1)

    def test_stale_unreleased_becomes_the_newest_untagged_release(self):
        # 0.2.0 was tagged but has no section: the old [Unreleased] IS its notes.
        out = gen.splice_unreleased(CURATED, self.NEW_BLOCK, RELEASES)
        self.assertIn("## [0.2.0] - 2026-02-15\n\n### Fixed\n\n- stale unreleased bullet", out)
        self.assertIn("- fresh bullet", out)
        self.assertEqual(gen.extract_section(out, "0.2.0"), "### Fixed\n\n- stale unreleased bullet")

    def test_idempotent(self):
        once = gen.splice_unreleased(CURATED, self.NEW_BLOCK, RELEASES)
        twice = gen.splice_unreleased(once, self.NEW_BLOCK, RELEASES)
        self.assertEqual(once, twice)

    def test_empty_file_gets_a_document(self):
        out = gen.splice_unreleased("", self.NEW_BLOCK, RELEASES[:1])
        self.assertTrue(out.startswith("## [Unreleased]"), out[:40])
        self.assertIn("[0.1.0]: https", out)

    def test_release_notes_prefer_the_curated_section(self):
        self.assertEqual(gen.release_notes("0.1.0", [], RELEASES, CURATED),
                         "### Added\n\n- Curated history line one.\n- Curated history line two, with `code` and a trailing space")

    def test_release_notes_fall_back_to_the_db_window(self):
        with tempfile.TemporaryDirectory() as d:
            db = Path(d) / "t.db"
            seed_db(db, FIXTURE)
            tasks = gen.load_tasks(db)
        with contextlib.redirect_stderr(io.StringIO()):
            body = gen.release_notes("0.2.0", tasks, RELEASES, CURATED)
        self.assertEqual(body, "### Fixed\n\n- DCL31-C sees macro-wrapped declarators.")
        self.assertIsNone(gen.release_notes("9.9.9", tasks, RELEASES, CURATED))


class TestReleasedVersionsUseUtc(unittest.TestCase):
    """Regression for 92eae76c: `released_versions` used git's %cI, which carries
    the committer's local offset, and the generator compares dates as text
    against the task DB's UTC `...Z` timestamps. A release cut at
    09:04:52-04:00 (13:04:52Z) sorted *before* a task completed at 12:17:38Z
    and so lost that task to [Unreleased]. Tag times must come back in UTC."""

    LOCAL = "2026-09-20T09:04:52-04:00"          # what %cI printed on the cutting machine
    EPOCH = 1789909492                            # the same instant: 2026-09-20T13:04:52Z
    TASK_DONE = "2026-09-20T12:17:38Z"            # completed before the cut, in UTC

    def fake_git(self, *args):
        if args[:2] == ("tag", "--list"):
            return "v0.5.2\nnot-a-release\n"
        if args[:2] == ("log", "-1") and "--format=%ct" in args:
            return str(self.EPOCH)
        if args[:2] == ("log", "-1") and "--format=%cI" in args:
            return self.LOCAL
        raise AssertionError(f"unexpected git call {args}")

    def test_tag_date_is_utc_and_contains_the_task(self):
        real = gen.run_git
        gen.run_git = self.fake_git
        try:
            releases = gen.released_versions()
        finally:
            gen.run_git = real
        self.assertEqual(releases, [("0.5.2", "v0.5.2", "2026-09-20T13:04:52Z")])
        task = gen.Task(self.TASK_DONE, "t", {"release-note"}, "release-note: x\ncategory: fixed", 1)
        # the bug: text order of the local-offset form put the tag before the task
        self.assertLess(self.LOCAL, self.TASK_DONE)
        # the fix: in UTC the task is inside the release window, not [Unreleased]
        self.assertEqual(gen.tasks_in_window([task], None, releases[-1][2]), [task])
        self.assertEqual(gen.tasks_in_window([task], releases[-1][2], None), [])


class TestNoDatabase(unittest.TestCase):
    """The release workflow has no task DB (CLAUDE.md: task tracking is not part
    of the repo) and must still produce valid, empty-of-bullets notes."""

    def test_missing_db_degrades_to_empty(self):
        with contextlib.redirect_stderr(io.StringIO()):
            tasks = gen.load_tasks(Path(tempfile.gettempdir()) / "does-not-exist.db")
        self.assertEqual(tasks, [])
        body = gen.release_notes("0.2.0", tasks, RELEASES, "")
        self.assertIn("No release notes recorded", body)
        self.assertEqual(safety.find_sensitive(body), [])

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

    def test_committed_changelog_is_clean(self):
        # The curated file the tool ships must pass the scan it enforces.
        self.assertEqual(safety.find_sensitive((REPO_ROOT / "CHANGELOG.md").read_text()), [])


if __name__ == "__main__":
    unittest.main()
