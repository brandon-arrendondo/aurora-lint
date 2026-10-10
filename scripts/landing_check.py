#!/usr/bin/env python3
"""Choose which test suites a change needs, from what its diff touches.

Every landing and every CI run used to build and test the whole crate,
even for a change to prose. This script classifies a diff and prints (or,
with --run, runs) the suites that change actually needs. It never reduces
what a code change runs: anything it cannot positively classify is FULL.

    docs           only prose: *.md / *.rst outside any tests/ directory,
                   and anything under docs/. Nothing to build; Sphinx -W
                   when docs/ changed. A prose file whose name appears in a
                   Rust string literal is read by code or a test (for
                   example docs/options.rst), so it is FULL instead.
    python         only *.py under bench/ or scripts/: their unittest
                   suites, no Rust build (and Sphinx for scripts/, which
                   docs/conf.py imports from).
    comments       *.rs files whose code is unchanged once comments are
                   ignored: build, doctests and clippy (a doc comment can
                   hold a doctest, and clippy lints doc comments). A file
                   that uses line!() or column!() is FULL, since moving its
                   lines changes what those return.
    rule-metadata  a rule's own <RULE-ID>.toml changed only in the text
                   fields of ALLOWED_METADATA_KEYS: the whole suite except
                   the generated fixture tests, which test detection and
                   cannot see those fields. build.rs still validates every
                   manifest. Any other key (enabled, severity, cwe ...)
                   is FULL.
    full           everything else: the full suite.

A diff's class is the most expensive class among its files. The git hooks
(`pre-commit`) run on every commit regardless of class; this script
decides only the suites on top of them.

    scripts/landing_check.py                    # main...HEAD
    scripts/landing_check.py --base A --head B
    scripts/landing_check.py --print class      # one word, for CI
    scripts/landing_check.py --run              # run the chosen commands

After --run passes it prints a `verified:` line naming the git TREE it
tested (the content, whichever commit carries it), the class, the host and
the rustc version. Only a `class full` stamp vouches for a tree on its own:
a landing whose tree hash (`git rev-parse HEAD^{tree}`) equals a recorded
`class full` tree, under the same rustc, has already been tested and needs
only the hooks. A lesser class ran less than the full suite, so its stamp
holds only together with a passing run on the base it was classified
against.

A change to this script is FULL: a diff must not be graded by the
classifier it edits. CI also runs the base commit's copy of it.
"""

import argparse
import datetime
import socket
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent

ORDER = ["docs", "python", "comments", "rule-metadata", "full"]

# Text-only fields of a rule manifest: nothing in detection or in a
# finding's severity reads them.
ALLOWED_METADATA_KEYS = {
    "metadata.title",
    "metadata.description",
    "metadata.last_modified",
    "metadata.cert_version",
    "references.wiki",
}

GENERATED_FIXTURE_TESTS = "rules::cert_c::integration::generated_tests::"

CLIPPY = ["cargo", "clippy", "--all-targets", "--all-features", "--", "-D", "warnings"]
PYTHON_TESTS = [
    ["python3", "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", ".", "-t", "."],
    ["python3", "-W", "error::ResourceWarning", "-m", "unittest", "discover",
     "-s", "scripts", "-p", "test_check_*.py"],
]
COMMANDS = {
    "docs": [],
    "python": PYTHON_TESTS,
    "comments": [["cargo", "build", "--all-targets"], ["cargo", "test", "--doc"], CLIPPY],
    "rule-metadata": [
        ["cargo", "test", "--all-targets", "--", "--skip", GENERATED_FIXTURE_TESTS],
        CLIPPY,
    ],
    "full": [["cargo", "test", "--all-targets"], ["cargo", "test", "--doc"], CLIPPY],
}


class LexError(Exception):
    pass


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True,
                          text=True).stdout


def show(rev: str, path: str) -> str | None:
    """`path`'s content at `rev`, or None when it does not exist there."""
    r = subprocess.run(["git", "-C", str(ROOT), "show", f"{rev}:{path}"], capture_output=True,
                       text=True)
    return r.stdout if r.returncode == 0 else None


def changed_paths(base: str, head: str) -> list[str]:
    """Every path the diff touches; both sides of a rename."""
    out = git("diff", "--name-status", "-z", "--find-renames", base, head)
    fields = out.split("\0")
    paths, i = [], 0
    while i < len(fields) and fields[i]:
        status = fields[i]
        n = 2 if status[0] in "RC" else 1
        paths.extend(fields[i + 1:i + 1 + n])
        i += 1 + n
    return paths


def rust_code(src: str) -> str:
    """`src` with every comment and whitespace run replaced by one space,
    literals kept verbatim. Two files with the same result differ only in
    comments and layout. Anything the scanner cannot follow raises LexError."""
    out, i, n = [], 0, len(src)

    def space():
        if out and out[-1] != " ":
            out.append(" ")

    while i < n:
        c = src[i]
        if c.isspace():
            space()
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            space()
        elif src.startswith("/*", i):
            depth, i = 1, i + 2
            while depth:
                if i >= n:
                    raise LexError("unterminated block comment")
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            space()
        elif (m := re.compile(r'(?:br|cr|r)(#*)"').match(src, i)) and (
                i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            close = '"' + m.group(1)
            j = src.find(close, m.end())
            if j < 0:
                raise LexError("unterminated raw string")
            out.append(src[i:j + len(close)])
            i = j + len(close)
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            if j >= n:
                raise LexError("unterminated string")
            out.append(src[i:j + 1])
            i = j + 1
        elif c == "'":
            if i + 1 < n and src[i + 1] == "\\":
                j = i + 3  # past the backslash and the character it escapes
                while j < n and src[j] != "'":
                    j += 2 if src[j] == "\\" else 1
                if j >= n:
                    raise LexError("unterminated char literal")
                out.append(src[i:j + 1])
                i = j + 1
            elif i + 2 < n and src[i + 2] == "'":
                out.append(src[i:i + 3])
                i += 3
            else:
                out.append(c)  # a lifetime or label; its name follows
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out).strip()


def flat_keys(table: dict, prefix: str = "") -> dict:
    flat = {}
    for key, value in table.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flat_keys(value, name + "."))
        else:
            flat[name] = value
    return flat


def is_rule_manifest(path: str) -> bool:
    p = PurePosixPath(path)
    return (path.startswith("src/rules/") and p.suffix == ".toml"
            and p.stem == p.parent.name)


def under_tests(path: str) -> bool:
    return "tests" in PurePosixPath(path).parts


def classify(path: str, base: str, head: str, rust_literals: str) -> tuple[str, str]:
    """(class, reason) for one changed path."""
    p = PurePosixPath(path)
    old, new = show(base, path), show(head, path)

    if path == "scripts/landing_check.py":
        return "full", "the classifier itself"

    if p.suffix in (".md", ".rst") or path.startswith("docs/"):
        if under_tests(path):
            return "full", "prose inside a tests/ directory"
        if f'{p.name}"' in rust_literals or f"/{p.name}" in rust_literals:
            return "full", "named in a Rust string literal (read by code or a test)"
        return "docs", "prose"

    if p.suffix == ".py" and p.parts[0] in ("bench", "scripts"):
        return "python", "Python outside the crate"

    if p.suffix == ".rs":
        if old is None or new is None:
            return "full", "Rust file added or removed"
        if any(re.search(r"\b(line|column)!\s*\(", s) for s in (old, new)):
            return "full", "uses line!()/column!()"
        try:
            same = rust_code(old) == rust_code(new)
        except LexError as e:
            return "full", f"could not scan: {e}"
        return ("comments", "comments only") if same else ("full", "code changed")

    if is_rule_manifest(path):
        if old is None or new is None:
            return "full", "rule manifest added or removed"
        try:
            before, after = flat_keys(tomllib.loads(old)), flat_keys(tomllib.loads(new))
        except tomllib.TOMLDecodeError as e:
            return "full", f"TOML does not parse: {e}"
        differing = {k for k in before.keys() | after.keys() if before.get(k) != after.get(k)}
        if differing <= ALLOWED_METADATA_KEYS:
            return "rule-metadata", "text fields: " + ", ".join(sorted(differing))
        return "full", "behavioral keys: " + ", ".join(sorted(differing - ALLOWED_METADATA_KEYS))

    return "full", "not a recognised low-risk kind of file"


def rust_string_literals(head: str) -> str:
    """Every string literal in the tracked Rust sources at `head`, joined."""
    files = git("ls-tree", "-r", "--name-only", head).splitlines()
    chunks = []
    for f in files:
        if f.endswith(".rs"):
            text = show(head, f) or ""
            chunks.extend(re.findall(r'"(?:[^"\\\n]|\\.)*"', text))
    return "\n".join(chunks)


def plan(base: str, head: str) -> dict:
    paths = changed_paths(base, head)
    if not paths:
        return {"class": "full", "files": [], "commands": COMMANDS["full"],
                "note": "empty diff: nothing to classify, so full"}
    literals = rust_string_literals(head)
    files = [(path, *classify(path, base, head, literals)) for path in paths]
    worst = max((cls for _, cls, _ in files), key=ORDER.index)
    commands = list(COMMANDS[worst])
    # Every other class's commands are a subset of the costlier classes';
    # the Python suites are not, so they join whichever class won.
    if any(cls == "python" for _, cls, _ in files) and worst != "python":
        commands.extend(PYTHON_TESTS)
    # docs/conf.py imports scripts/check_project_facts.py, so a change
    # under scripts/ can break the docs build too.
    if any(p.startswith(("docs/", "scripts/")) for p in paths):
        tmp = tempfile.gettempdir()
        commands.append(["sphinx-build", "-W", "-q", "-b", "html",
                         "-d", f"{tmp}/landing-doctrees", "docs", f"{tmp}/landing-html"])
    return {"class": worst, "files": files, "commands": commands}


def is_dirty() -> bool:
    # Untracked files count: a new fixture .c changes the generated tests.
    # Gitignored files do not.
    return bool(git("status", "--porcelain", "--untracked-files=normal").strip())


def verified_stamp(cls: str, head: str = "HEAD", dirty_before: bool = False) -> str:
    """The line --run prints once every chosen command has passed. The
    commands ran on the checked-out tree, so that is the tree it names."""
    tree = git("rev-parse", "HEAD^{tree}").strip()
    notes = []
    if dirty_before or is_dirty():
        notes.append("WORKING TREE HAD UNCOMMITTED OR UNTRACKED CHANGES: not a verification of this tree")
    if git("rev-parse", f"{head}^{{tree}}").strip() != tree:
        notes.append(f"ran on HEAD, whose tree differs from --head {head}")
    rustc = subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.strip()
    when = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    note = "".join(f" ({n})" for n in notes)
    return (f"verified: tree {tree} class {cls} on {socket.gethostname()} "
            f"with {rustc or 'no rustc'} at {when}{note}")


def default_base() -> str:
    for ref in ("origin/main", "main"):
        r = subprocess.run(["git", "-C", str(ROOT), "merge-base", ref, "HEAD"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    sys.exit("landing_check: no main or origin/main to diff against; pass --base")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--base", help="the tree the change applies to (default: merge-base with main)")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--print", choices=["class"], dest="print_only",
                    help="print only the class, one word")
    ap.add_argument("--run", action="store_true", help="run the chosen commands, stop at a failure")
    args = ap.parse_args()

    if args.base == "":
        sys.exit("landing_check: --base is empty")  # a caller's failed lookup; never guess
    result = plan(args.base if args.base is not None else default_base(), args.head)
    if args.print_only == "class":
        print(result["class"])
        return 0

    print(f"class: {result['class']}")
    if result.get("note"):
        print(f"  {result['note']}")
    for path, cls, why in result["files"]:
        print(f"  {cls:<13} {path}  ({why})")
    print("commands:" if result["commands"] else "commands: none beyond the hooks")
    for cmd in result["commands"]:
        print("  " + " ".join(cmd))
    if not args.run:
        return 0
    dirty_before = is_dirty()
    for cmd in result["commands"]:
        print(f"\n$ {' '.join(cmd)}", flush=True)
        rc = subprocess.run(cmd, cwd=ROOT).returncode
        if rc:
            return rc
    print("\n" + verified_stamp(result["class"], args.head, dirty_before))
    return 0


if __name__ == "__main__":
    sys.exit(main())
