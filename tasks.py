"""
Invoke tasks for aurora-lint development.

Usage:
    invoke check          # Run pre-commit hooks on all files
    invoke build          # Build (add --release for release mode)
    invoke test           # Run all tests
    invoke bump-version   # Bump version across all files (reads Cargo.toml)
    invoke lint-docs      # Advisory Vale prose lint of README.md, docs/*.rst, man page

Install invoke: pip install invoke
"""

import datetime
import re
import shlex
import shutil
from pathlib import Path

from invoke import task

# A semver core like 0.4.69 (no pre-release / build metadata).
SEMVER = r"\d+\.\d+\.\d+"


def _read_cargo_version():
    cargo = Path("Cargo.toml").read_text()
    # Match the package version line (anchored at start of line) — not the
    # `version = "..."` fields inside dependency tables.
    match = re.search(r'^version = "([^"]+)"', cargo, re.MULTILINE)
    if not match:
        raise RuntimeError("Could not find version in Cargo.toml")
    return match.group(1)


# Files that embed THIS crate's own version, with the pattern that locates it
# and a replacement template ({new} = new version, {date} = today as
# "Month YYYY", matching the existing man-page date style).
#
# Patterns match any semver (not just the current one) so a bump heals any
# existing drift instead of silently skipping an out-of-sync file. Running
# `invoke bump-version --new-version <current Cargo version>` therefore also
# re-syncs a stale man page to the Cargo source of truth.
#
# NOT touched (intentionally):
#   - .pre-commit-config.yaml `rev: v1.8.2`  -> that pins knots, not this crate
#   - .github/workflows/release.yml          -> deb/rpm/appimage read the
#                                               version out of Cargo.toml at
#                                               build time (grep), so they
#                                               auto-track and need no edit
#   - bench/                                   -> read Cargo.toml at runtime
VERSION_FILES = [
    # (path, pattern, replacement-template)
    ("Cargo.toml", r'^(version = ")' + SEMVER + r'(")', r"\g<1>{new}\g<2>"),
    # Man page version field: .TH aurora-lint 1 "<date>" "aurora-lint X.Y.Z" "User Commands"
    (
        "docs/aurora-lint.1",
        r'("aurora-lint )' + SEMVER + r'(")',
        r"\g<1>{new}\g<2>",
    ),
    # Refresh the man page date stamp (the .TH date field) on every bump.
    (
        "docs/aurora-lint.1",
        r'(\.TH aurora-lint 1 ")[^"]*(")',
        r"\g<1>{date}\g<2>",
    ),
]


@task
def bump_version(c, new_version=None):
    """Bump this crate's version across every file that embeds it.

    Reads the current version from Cargo.toml. With no --new-version, prints
    the current version and the files that would change (dry run). Otherwise
    rewrites Cargo.toml, the man page version, and the man page date.

    To re-sync docs to the current Cargo version without a real bump, pass the
    version already in Cargo.toml.

    Args:
        new_version: Target version string, e.g. 0.4.70 (no leading 'v').
    """
    current = _read_cargo_version()

    if not new_version:
        print(f"Current version (Cargo.toml): {current}")
        print("\nFiles that would be updated:")
        for path, *_ in VERSION_FILES:
            print(f"  {path}")
        print("\nRun: invoke bump-version --new-version X.Y.Z")
        return

    if not re.fullmatch(SEMVER, new_version):
        raise SystemExit(f"--new-version must look like X.Y.Z, got '{new_version}'")

    today = datetime.date.today().strftime("%B %Y")
    changed = []

    for path, pattern, tmpl in VERSION_FILES:
        p = Path(path)
        if not p.exists():
            continue
        text = p.read_text()
        replacement = tmpl.format(new=new_version, date=today)
        updated = re.sub(pattern, replacement, text, flags=re.MULTILINE)
        if updated != text:
            p.write_text(updated)
            changed.append(path)

    if changed:
        print(f"Bumped -> {new_version} in:")
        for f in sorted(set(changed)):
            print(f"  {f}")
        print(
            "\nNext: review `git diff`, commit, then "
            f"`git tag v{new_version} && git push && git push origin v{new_version}`"
        )
    else:
        print("No version strings matched — nothing changed.")


@task
def check(c):
    """Run pre-commit hooks on all files."""
    c.run("pre-commit run --all-files", pty=True)


@task
def build(c, release=False):
    """Build the project.

    Args:
        release: Build in release mode (default: debug).
    """
    cmd = "cargo build"
    if release:
        cmd += " --release"
    c.run(cmd, pty=True)


@task
def test(c):
    """Run all tests."""
    c.run("cargo test", pty=True)


# Vale prose lint (see .vale.ini). The Aurora house style is a package in a
# sibling ../style_package checkout, which a clone without it simply lacks:
# the task then says so and stops. Advisory only -- findings never fail it.
STYLE_PACKAGE = Path("../style_package")
STYLE_ZIP = STYLE_PACKAGE / "dist" / "Aurora.zip"
VALE_SYNCED = Path("styles/.synced")
# The user-facing docs: README, the Sphinx guide and (below) the man page.
# docs/design/ and docs/adr/ are internal working docs, and
# docs/juliet-coverage.md is generated elsewhere; lint those with --path.
LINT_DOCS_DEFAULT = ["README.md", ":(glob)docs/*.rst"]
MAN_PAGE = Path("docs/aurora-lint.1")
# Vale cannot read troff; pandoc converts the man page to Markdown here, so
# its findings name this file (and its line numbers) rather than the .1 source.
MAN_LINT_DIR = Path("target/vale")


def _vale_sync(c):
    """Build the package zip if missing, then `vale sync` when stale."""
    if not STYLE_ZIP.exists():
        if not STYLE_PACKAGE.is_dir():
            print(f"{STYLE_PACKAGE} not found; the Aurora style is not available here.")
            return False
        with c.cd(str(STYLE_PACKAGE)):
            c.run("invoke build")
    inputs = [Path(".vale.ini"), STYLE_ZIP]
    if not VALE_SYNCED.exists() or any(
        p.stat().st_mtime > VALE_SYNCED.stat().st_mtime for p in inputs
    ):
        c.run("vale sync")
        VALE_SYNCED.touch()
    return True


@task
def lint_docs(c, path=None, level=None):
    """Advisory Vale prose lint of README.md, the docs/*.rst guide and the man page.

    Findings never fail the task. reStructuredText needs docutils' rst2html
    on PATH; without it .rst files are skipped with a message.

    Args:
        path: A file or directory (.md, .rst) to lint instead of the defaults,
            e.g. docs/design.
        level: Vale --minAlertLevel (default: the package's, warning).
    """
    if not shutil.which("vale"):
        print("vale not found on PATH; see https://vale.sh/docs/install")
        return
    if not _vale_sync(c):
        return

    exts = [".md", ".rst"]
    if not (shutil.which("rst2html") or shutil.which("rst2html.py")):
        print(
            "rst2html not found; skipping .rst files. Install docutils "
            "(pip install docutils, or activate the dev venv) to lint them."
        )
        exts = [".md"]

    # Tracked and not-yet-tracked files only, so generated, gitignored docs
    # (docs/test-summary.md) stay out of a directory run.
    roots = [path] if path else LINT_DOCS_DEFAULT
    listed = c.run(
        "git ls-files --cached --others --exclude-standard -- "
        + " ".join(shlex.quote(r) for r in roots),
        hide=True,
    ).stdout.split()
    files = sorted({f for f in listed if Path(f).suffix in exts})
    if path and Path(path).is_file() and Path(path).suffix in exts:
        files = [path]

    lint_man = path is None or Path(path) == MAN_PAGE
    if lint_man and not shutil.which("pandoc"):
        print("pandoc not found; skipping the man page.")
    elif lint_man:
        MAN_LINT_DIR.mkdir(parents=True, exist_ok=True)
        man_md = MAN_LINT_DIR / f"{MAN_PAGE.name}.md"
        md = c.run(f"pandoc -f man -t gfm {MAN_PAGE}", hide=True).stdout
        # troff sets options in bold, which pandoc keeps as **--flag**; make
        # them code spans so Vale skips them as it does in the other docs.
        md = re.sub(r"\*\*(-{1,2}[A-Za-z][\w-]*)\*\*", r"`\1`", md)
        man_md.write_text(md)
        files.append(str(man_md))

    if not files:
        print(f"No {'/'.join(exts)} files to lint under {' '.join(roots)}.")
        return
    cmd = "vale --no-exit"
    if level:
        cmd += f" --minAlertLevel={level}"
    c.run(f"{cmd} {' '.join(files)}", pty=True)
