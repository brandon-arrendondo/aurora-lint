"""corpus.py's path-aware glob semantics and the in_scope predicate.

`*`, `?` and `[...]` must stop at `/`; `**` is the only way to cross one.
Plain `fnmatch` has no concept of a path, so under it `*.c` also matched
`testes/libs/lib1.c`. That is harmless for precision and recall -- scope
filters findings and an unscanned file produces none -- but wrong for any
file-count denominator derived from these globs, and benchmarking_db's copy of
this predicate had a real denominator bug from exactly that inheritance.

The two copies MUST agree, or a local clone and the shared oracle disagree
about what is in scope, so these cases are about the semantics rather than
about any project's current declarations. The in_scope tests stub the scope
source for the same reason: they should not start failing because someone
legitimately edited data/benchmark_repos.json.
"""

import unittest
from unittest import mock

from bench import corpus


class TestGlobSemantics(unittest.TestCase):
    # (pattern, path, expected, what it pins)
    CASES = [
        ("*.c", "main.c", True, "* matches within one segment"),
        ("*.c", "src/main.c", False, "* does NOT cross a separator"),
        ("src/*.c", "src/main.c", True, "* inside a directory"),
        ("src/*.c", "src/deep/main.c", False, "* still does not cross"),
        ("src/**", "src/main.c", True, "** covers everything beneath"),
        ("src/**", "src/a/b/c.c", True, "** crosses many separators"),
        ("src/**", "src/", True, "** matches the bare directory prefix"),
        ("src/**/*.c", "src/a/main.c", True, "**/ at depth"),
        ("**/b.c", "b.c", True, "**/x matches x at the root too"),
        ("**/b.c", "a/b.c", True, "**/x matches at depth"),
        ("a/**/b", "a/b", True, "a/**/b includes b at depth 1"),
        ("?.c", "a.c", True, "? matches one character"),
        ("?.c", "ab.c", False, "? matches exactly one"),
        ("?.c", "a/c", False, "? does not cross a separator"),
        ("[ab].c", "a.c", True, "character class"),
        ("[ab].c", "c.c", False, "character class excludes"),
        ("tests/**", "src/main.c", False, "unrelated prefix"),
        # The literal fnmatch regression: a bare *.c must not sweep up a
        # nested test-harness file.
        ("*.c", "testes/libs/lib1.c", False, "the fnmatch regression case"),
    ]

    def test_match_semantics(self):
        for pat, path, want, why in self.CASES:
            with self.subTest(why=why, pattern=pat, path=path):
                self.assertEqual(corpus._match(path, pat), want)

    def test_match_is_anchored_at_both_ends(self):
        """A pattern must full-match, not merely match a prefix."""
        self.assertFalse(corpus._match("src/main.c.orig", "src/*.c"))
        self.assertFalse(corpus._match("presrc/main.c", "src/*.c"))


class TestInScope(unittest.TestCase):
    def _with_scope(self, include, exclude=None):
        entry = {"name": "proj"}
        if include is not None:
            entry["scope_include"] = include
        if exclude is not None:
            entry["scope_exclude"] = exclude
        return mock.patch.object(corpus, "load_repos", return_value=[entry])

    def test_no_declared_scope_is_unrestricted(self):
        """Whole-repo audits (libcrc, raylib) declare no scope_include."""
        with self._with_scope(None):
            self.assertTrue(corpus.in_scope("proj", "anything/at/all.c"))

    def test_unknown_project_is_unrestricted(self):
        with mock.patch.object(corpus, "load_repos", return_value=[]):
            self.assertTrue(corpus.in_scope("absent", "x.c"))

    def test_include_admits_and_rejects(self):
        with self._with_scope(["src/**"]):
            self.assertTrue(corpus.in_scope("proj", "src/a/b.c"))
            self.assertFalse(corpus.in_scope("proj", "tests/a.c"))

    def test_exclude_overrides_include(self):
        with self._with_scope(["src/**"], ["src/vendor/**"]):
            self.assertTrue(corpus.in_scope("proj", "src/core/a.c"))
            self.assertFalse(corpus.in_scope("proj", "src/vendor/dep.c"))

    def test_exclude_alone_does_not_admit(self):
        """An exclude list never widens scope: a path outside every include
        stays out whether or not it also matches an exclude."""
        with self._with_scope(["src/**"], ["tests/**"]):
            self.assertFalse(corpus.in_scope("proj", "docs/a.c"))

    def test_bare_basename_is_out_of_scope_under_a_directory_include(self):
        """The downstream symptom of the project_relpath defect (task 762):
        a path wrongly collapsed to its basename matches no directory glob,
        so the finding silently reads as out of scope."""
        with self._with_scope(["include/**"]):
            self.assertTrue(corpus.in_scope("proj", "include/mosquitto/libmosquitto.h"))
            self.assertFalse(corpus.in_scope("proj", "libmosquitto.h"))
