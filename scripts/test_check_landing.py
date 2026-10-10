"""landing_check.py: a change runs less than the full suite only when the
classifier can show it cannot affect what the skipped suites test.

Each test commits a base tree and a change to a scratch repository, then
asks for the change's class.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import landing_check as lc

RULE_TOML = '''[metadata]
id = "EXP34-C"
title = "Do not dereference null pointers"
description = """
Dereferencing a null pointer is undefined behavior.
"""
severity = "High"

[rules.cert_c.EXP34-C]
enabled = true

[references]
wiki = "https://example.org/EXP34-C"
cwe = ["CWE-476"]
'''

LIB_RS = '''/// Adds one.
pub fn add_one(x: i32) -> i32 {
    // a plain comment
    x + 1
}

pub const SLASHES: &str = "http://example.org"; // not a comment inside the string
pub const DOC: &str = "docs/options.rst";
'''


class Repo(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        # Scrub any git state inherited from a hook so the scratch repo is
        # the one every git call sees.
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                   GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.org",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.org")
        self._env = mock.patch.dict(os.environ, env, clear=True)
        self._env.start()
        self._root = mock.patch.object(lc, "ROOT", self.root)
        self._root.start()
        self._git("init", "-q")
        self.write({
            "README.md": "# Project\n",
            "docs/index.rst": "Index\n=====\n",
            "docs/options.rst": "Options\n=======\n",
            "src/lib.rs": LIB_RS,
            "src/rules/cert_c/EXP/EXP34-C/EXP34-C.toml": RULE_TOML,
            "src/rules/cert_c/EXP/EXP34-C/tests/fail/case.c": "int main(void) { return 0; }\n",
            "bench/report.py": "print('x')\n",
            "Cargo.toml": "[package]\nname = \"x\"\n",
        })
        self.base = self.commit()

    def tearDown(self):
        self._root.stop()
        self._env.stop()
        self._tmp.cleanup()

    def _git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def write(self, files):
        for rel, text in files.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def commit(self):
        self._git("add", "-A")
        self._git("commit", "-q", "--allow-empty", "-m", "c")
        return self._git("rev-parse", "HEAD")

    def edit(self, rel, old, new):
        path = self.root / rel
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1))

    def class_of_change(self):
        return lc.plan(self.base, self.commit())["class"]


class ClassifyTests(Repo):
    def test_prose_only_is_docs(self):
        self.edit("README.md", "# Project", "# The project")
        self.edit("docs/index.rst", "Index", "Contents")
        result = lc.plan(self.base, self.commit())
        self.assertEqual(result["class"], "docs")
        # docs/ changed, so Sphinx runs, and nothing else does.
        self.assertEqual([c[0] for c in result["commands"]], ["sphinx-build"])

    def test_a_doc_named_in_a_rust_string_is_full(self):
        self.edit("docs/options.rst", "Options", "All options")
        self.assertEqual(self.class_of_change(), "full")

    def test_a_comment_or_doc_comment_change_is_comments(self):
        self.edit("src/lib.rs", "/// Adds one.", "/// Adds one to `x`.")
        self.edit("src/lib.rs", "// a plain comment", "// another comment\n    // over two lines")
        self.assertEqual(self.class_of_change(), "comments")

    def test_a_code_change_is_full(self):
        self.edit("src/lib.rs", "x + 1", "x + 2")
        self.assertEqual(self.class_of_change(), "full")

    def test_a_change_inside_a_string_that_looks_like_a_comment_is_full(self):
        self.edit("src/lib.rs", "http://example.org", "http://example.com")
        self.assertEqual(self.class_of_change(), "full")

    def test_a_file_using_line_macro_is_full_even_for_a_comment(self):
        self.edit("src/lib.rs", "    x + 1", "    let _ = line!();\n    x + 1")
        self.base = self.commit()
        self.edit("src/lib.rs", "// a plain comment", "// changed")
        self.assertEqual(self.class_of_change(), "full")

    def test_rule_description_is_rule_metadata(self):
        rel = "src/rules/cert_c/EXP/EXP34-C/EXP34-C.toml"
        self.edit(rel, "is undefined behavior.", "is undefined behavior in C.")
        result = lc.plan(self.base, self.commit())
        self.assertEqual(result["class"], "rule-metadata")
        self.assertIn(lc.GENERATED_FIXTURE_TESTS, result["commands"][0])

    def test_rule_enabled_or_severity_is_full(self):
        rel = "src/rules/cert_c/EXP/EXP34-C/EXP34-C.toml"
        for old, new in (("enabled = true", "enabled = false"),
                         ('severity = "High"', 'severity = "Low"'),
                         ('cwe = ["CWE-476"]', 'cwe = ["CWE-476", "CWE-690"]')):
            with self.subTest(new=new):
                self.edit(rel, old, new)
                self.assertEqual(self.class_of_change(), "full")
                self.edit(rel, new, old)
                self.base = self.commit()

    def test_bench_python_is_python(self):
        self.edit("bench/report.py", "'x'", "'y'")
        self.assertEqual(self.class_of_change(), "python")

    def test_a_change_to_the_classifier_is_full(self):
        self.write({"scripts/landing_check.py": "X = 1\n"})
        self.base = self.commit()
        self.edit("scripts/landing_check.py", "X = 1", "X = 2")
        self.assertEqual(self.class_of_change(), "full")

    def test_a_scripts_change_also_builds_the_docs(self):
        # docs/conf.py imports from scripts/.
        self.write({"scripts/facts.py": "X = 1\n"})
        self.base = self.commit()
        self.edit("scripts/facts.py", "X = 1", "X = 2")
        result = lc.plan(self.base, self.commit())
        self.assertEqual(result["class"], "python")
        self.assertEqual(result["commands"][-1][0], "sphinx-build")

    def test_the_most_expensive_file_decides(self):
        self.edit("README.md", "# Project", "# The project")
        self.edit("bench/report.py", "'x'", "'y'")
        self.edit("src/lib.rs", "x + 1", "x + 2")
        result = lc.plan(self.base, self.commit())
        self.assertEqual(result["class"], "full")
        # ... and the Python change's tests still run alongside it.
        for cmd in lc.PYTHON_TESTS:
            self.assertIn(cmd, result["commands"])

    def test_fixtures_manifests_and_unknown_files_are_full(self):
        for rel, old, new in (
                ("src/rules/cert_c/EXP/EXP34-C/tests/fail/case.c", "return 0", "return 1"),
                ("Cargo.toml", 'name = "x"', 'name = "y"')):
            with self.subTest(rel=rel):
                self.edit(rel, old, new)
                self.assertEqual(self.class_of_change(), "full")
                self.base = self.commit()

    def test_prose_in_a_tests_directory_is_full(self):
        self.write({"src/rules/cert_c/EXP/EXP34-C/tests/fail/NOTES.md": "notes\n"})
        self.assertEqual(self.class_of_change(), "full")

    def test_an_added_or_removed_rust_file_is_full(self):
        self.write({"src/new.rs": "// only a comment\n"})
        self.assertEqual(self.class_of_change(), "full")

    def test_an_empty_diff_is_full(self):
        self.assertEqual(self.class_of_change(), "full")


class VerifiedStampTests(Repo):
    def test_the_stamp_names_the_tree_not_the_commit(self):
        tree = self._git("rev-parse", "HEAD^{tree}")
        stamp = lc.verified_stamp("full")
        self.assertIn(f"tree {tree} class full", stamp)
        self.assertNotIn("UNCOMMITTED", stamp)
        # A second commit with the same content has the same tree.
        self._git("commit", "-q", "--allow-empty", "-m", "same tree")
        self.assertIn(f"tree {tree} ", lc.verified_stamp("full"))

    def test_a_head_other_than_the_checkout_is_named(self):
        self.edit("src/lib.rs", "x + 1", "x + 2")
        other = self.commit()
        self._git("checkout", "-q", self.base)
        self.assertIn(f"differs from --head {other}", lc.verified_stamp("full", other))

    def test_an_untracked_file_is_said_to_be_unverified(self):
        # A new fixture changes the generated tests even before it is added.
        self.write({"src/rules/cert_c/EXP/EXP34-C/tests/fail/new.c": "int x;\n"})
        self.assertIn("UNCOMMITTED", lc.verified_stamp("full"))

    def test_a_gitignored_file_is_not(self):
        self.write({".gitignore": "/scratch.txt\n"})
        self.commit()
        self.write({"scratch.txt": "notes\n"})
        self.assertNotIn("UNCOMMITTED", lc.verified_stamp("full"))

    def test_a_dirty_working_tree_is_said_to_be_unverified(self):
        self.edit("src/lib.rs", "x + 1", "x + 2")
        self.assertIn("UNCOMMITTED", lc.verified_stamp("full"))


class RustCodeTests(unittest.TestCase):
    def same(self, a, b):
        return lc.rust_code(a) == lc.rust_code(b)

    def test_comments_and_layout_do_not_count(self):
        self.assertTrue(self.same("fn f() { 1 }", "fn f() {\n    // c\n    1 /* d /* nested */ */\n}"))
        self.assertTrue(self.same("/// doc\nfn f() {}", "/** other doc */\nfn f() {}"))

    def test_literals_count_whatever_they_hold(self):
        self.assertFalse(self.same('let s = "// a";', 'let s = "// b";'))
        self.assertFalse(self.same('let s = r#"/* a */"#;', 'let s = r#"/* b */"#;'))
        self.assertFalse(self.same("let c = '\"';", "let c = '\\'';"))

    def test_quotes_inside_literals_do_not_open_strings(self):
        # A char literal holding '"' must not start a string that swallows
        # the comment after it.
        self.assertTrue(self.same("let c = '\"'; // x\nlet d = 1;", "let c = '\"'; // y\nlet d = 1;"))
        self.assertFalse(self.same("let c = '\"'; let d = 1;", "let c = '\"'; let d = 2;"))

    def test_escaped_char_literals_close_where_they_end(self):
        # b'\\' and '\'' end at their own closing quote; the comment after
        # them is a comment.
        for lit in ("b'\\\\'", "'\\''", "'\\u{7f}'"):
            with self.subTest(lit=lit):
                self.assertTrue(self.same(f"let c = {lit}; // a\nlet s = \"x\";",
                                          f"let c = {lit}; // b\nlet s = \"x\";"))

    def test_lifetimes_are_not_char_literals(self):
        self.assertTrue(self.same("fn f<'a>(x: &'a str) {} // a", "fn f<'a>(x: &'a str) {} // b"))
        self.assertFalse(self.same("fn f<'a>(x: &'a u8) {}", "fn f<'a>(x: &'a u16) {}"))

    def test_raw_identifiers_are_code(self):
        self.assertFalse(self.same("let r#type = 1;", "let r#type = 2;"))

    def test_unterminated_input_raises(self):
        for bad in ('let s = "open;', "/* open", 'let s = r#"open"'):
            with self.subTest(bad=bad), self.assertRaises(lc.LexError):
                lc.rust_code(bad)


if __name__ == "__main__":
    unittest.main()
