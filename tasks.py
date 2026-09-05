"""
Invoke tasks for aurora-lint development.

Usage:
    invoke check          # Run pre-commit hooks on all files
    invoke build          # Build (add --release for release mode)
    invoke test           # Run all tests
    invoke bump-version   # Bump version across all files (reads Cargo.toml)

Install invoke: pip install invoke
"""

import datetime
import re
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
