#!/usr/bin/env python3
"""Generate CHANGELOG.md (Keep a Changelog format) from the task database.

The project does not hand-write release notes: every shipped change is already
a done task in the fleet task database, and every published release is an
annotated `v*` git tag. This script joins the two -- tasks completed between
two tags become that release's section -- so the changelog is a projection of
records that already exist rather than a second thing to keep current.

Version numbers here are *published releases*, not every version the crate
passed through. aurora-lint bumps the patch version on nearly every commit (`run_id`
discriminates benchmark runs by SHA, see CLAUDE.md), so most versions are
never tagged and never shipped; a release section therefore covers everything
completed since the previous tag.

**A task is published only if it is tagged `release-note`** (task 1375, see
docs/adr/0007). Task titles are internal working notes, and a large share of
them locate a defect in a real-world corpus ("confirmed OOB write at
foo.c:579", "hostap disclosure: act on maintainer response") -- exactly what
ADR-0007 keeps out of the public record until the fix has landed upstream. So
the default is exclusion: no tag, no bullet. Marking a task:

    tag it `release-note`, and optionally add one line to its body
        release-note: <the bullet, written to be published>
    which is published INSTEAD of the title. A task without that line
    publishes its title.

Even a tagged task is dropped (with a warning on stderr naming it) if it also
carries a disclosure-family tag (`disclosure`, `upstream`, `adr-0007`, ...) or
if the text that would be published matches one of the content deny patterns
in scripts/check_changelog_safety.py (a `file.c:123` location, disclosure /
maintainer / CVE vocabulary). The same check runs over the finished output
before anything is written, and independently over the committed file in
pre-commit, CI and the release workflow.

Task tracking is maintainer infrastructure, not part of this repo (see
CLAUDE.md's "Task tracking" section) -- the fleet task database lives outside
any clone and is never available to a fresh checkout or CI. Point this script
at it with AURORA_LINT_TASK_DB; without that (e.g. in CI), it degrades to an
empty task list rather than failing, so `--release` still emits a valid
(task-bullet-free) section and the release workflow doesn't hard-fail on
infrastructure it was never meant to have. The DB now holds every project's
tasks in one table (2026-09-09 consolidation) with a `project_name` column --
load_tasks() filters to this repo's own tasks only.

Usage:
    AURORA_LINT_TASK_DB=~/data/fleet-tasks.db python3 scripts/generate_changelog.py
    python3 scripts/generate_changelog.py --check          # exit 1 if stale
    python3 scripts/generate_changelog.py --release 0.4.315  # one section, to stdout
"""
import argparse
import os
import re
import sqlite3
import subprocess
import sys
from collections import OrderedDict, namedtuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_changelog_safety import find_sensitive, is_sensitive  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("AURORA_LINT_TASK_DB", REPO_ROOT / "todo-sqlite-cli.db")).expanduser()
CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"

# The one tag that makes a task publishable at all. Chosen over the topic tag
# `changelog` (already used on tasks ABOUT the changelog) so that consent to
# publish cannot be given by accident while filing.
ALLOW_TAG = "release-note"

# A `release-note:` line in the task body is the bullet to publish instead of
# the title. First such line wins; matched case-insensitively at line start.
RELEASE_NOTE_LINE = re.compile(r"^\s*release[- ]note:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)

# Tags that mark disclosure work. A task carrying any of these is never
# published, allow tag or not -- its title and body are the working record
# ADR-0007 keeps local until the upstream fix lands. Matched as substrings so
# the ad-hoc variants (`hostap-upstream`, `upstream-disclosures`,
# `upstream-candidate`) are covered without listing each one.
DENY_TAG_FRAGMENTS = ("disclos", "upstream", "adr-0007", "triage", "cve")

Task = namedtuple("Task", "completed_at title tags details id")

# Keep a Changelog buckets, in precedence order: a task is filed under the
# first bucket any of its tags matches. The `added`/`changed`/`fixed` tags were
# an explicit changelog convention that lapsed after 2026-04, so the modern
# tag vocabulary (rule-bug, fp-reduction, new-rule, ...) is mapped too --
# without that, every section after April 2026 comes back empty.
BUCKETS = OrderedDict([
    ("Added", {"added", "new-rule", "feature", "enhancement"}),
    ("Fixed", {
        "fixed", "bug", "rule-bug", "fp-reduction", "crash", "robustness",
        "parser-gotcha", "rule-hardening", "security", "coverage-gap",
        "fn-detection", "recall",
    }),
    ("Changed", {
        "changed", "refactor", "rule-improvement", "performance", "packaging",
        "infra", "infrastructure", "build", "tech-debt", "architecture",
        "tooling", "knots", "release", "parsing", "analysis", "vra",
        "macro-expansion",
    }),
    ("Documentation", {"documentation", "docs"}),
])

# Work that never ships in the binary: adjudicating findings into ground
# truth, corpus curation, paper drafting. These now belong to the
# `benchmarking_db` and `sqc_paper` backlogs (CLAUDE.md), but their completed
# history stayed in this DB. A task tagged `release-note` AND one of these is
# dropped with a warning naming it, since the two tags contradict each other.
NEVER_SHIPPED = {
    "ground-truth", "ground-truth-quality", "adjudication",
    "delta-adjudication", "evaluation", "paper", "benchmarking-db",
    "external-review",
}

HEADER = """# Changelog

All notable changes to aurora-lint are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**Versions here are published releases**, not every version the crate passed
through. aurora-lint bumps the patch version on nearly every commit, and only tagged
versions are built, signed and published; a section therefore covers every
change since the previous release, not since the previous version number.

This file is generated by `scripts/generate_changelog.py` from the project's
task database: a completed task appears here only once it has been tagged
`release-note`, and its bullet is the task's `release-note:` line where one
was written. Edit the task, not this file -- a hand edit is overwritten on
the next regeneration, and CI screens the committed text with
`scripts/check_changelog_safety.py` (see `docs/adr/0007`).
"""


def run_git(*args):
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def version_key(v):
    return tuple(int(p) for p in re.findall(r"\d+", v))


def released_versions():
    """Every published release, oldest first, as (version, tag, iso_date)."""
    out = []
    for tag in run_git("tag", "--list", "v*").splitlines():
        tag = tag.strip()
        if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
            continue
        date = run_git("log", "-1", "--format=%cI", tag)
        out.append((tag[1:], tag, date))
    out.sort(key=lambda r: version_key(r[0]))
    return out


def current_version():
    text = (REPO_ROOT / "Cargo.toml").read_text()
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        raise SystemExit("could not read version from Cargo.toml")
    return m.group(1)


def _empty_task_db_warning():
    print(
        f"generate_changelog.py: no usable task database at {DB_PATH} "
        "(maintainer infrastructure, not part of this repo -- see CLAUDE.md's "
        "\"Task tracking\" section). Proceeding with an empty task list; set "
        "AURORA_LINT_TASK_DB to point at the fleet database for real output.",
        file=sys.stderr,
    )


def load_tasks(db_path=DB_PATH):
    db_path = Path(db_path)
    if not db_path.is_file():
        _empty_task_db_warning()
        return []
    try:
        con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        rows = con.execute(
            "SELECT uuid, title, completed_at, details, id FROM tasks "
            "WHERE status = 'done' AND completed_at IS NOT NULL "
            "AND (project_name = 'aurora_lint' OR project_name IS NULL)"
        ).fetchall()
        tags = {}
        for uuid, tag in con.execute("SELECT task_uuid, tag FROM tags"):
            tags.setdefault(uuid, set()).add(tag)
        con.close()
    except sqlite3.OperationalError:
        # A file exists at DB_PATH but doesn't have the expected schema --
        # e.g. a stale/empty pre-consolidation artifact. Same degrade as a
        # missing file, not a hard failure.
        _empty_task_db_warning()
        return []
    tasks = []
    for uuid, title, completed_at, details, task_id in rows:
        tasks.append(Task(completed_at, title.strip(), tags.get(uuid, set()), details or "", task_id))
    tasks.sort(key=lambda t: (t.completed_at, t.title))
    return tasks


def release_note(task):
    """The text this task would publish: its `release-note:` line, else its title."""
    m = RELEASE_NOTE_LINE.search(task.details)
    return m.group(1) if m else task.title


def publishable(task):
    """(text, None) if the task may be published, else (None, why-not).

    The reason is only reported for a task that carries the allow tag: an
    untagged task being skipped is the default and not worth a line, but a
    maintainer who tagged a task and does not see its bullet needs to know
    which layer stopped it.
    """
    if ALLOW_TAG not in task.tags:
        return None, None
    denied = sorted(t for t in task.tags if any(f in t for f in DENY_TAG_FRAGMENTS))
    if denied:
        return None, f"carries disclosure-family tag(s) {', '.join(denied)}"
    never = sorted(task.tags & NEVER_SHIPPED)
    if never:
        return None, f"carries never-shipped tag(s) {', '.join(never)}"
    text = escape_bullet(release_note(task))
    if is_sensitive(text):
        return None, "published text matches a content deny pattern (see scripts/check_changelog_safety.py)"
    return text, None


def bucket_for(task_tags):
    for name, members in BUCKETS.items():
        if task_tags & members:
            return name
    # No bucket tag (e.g. only a bare rule id like `int32-c`): the maintainer
    # tagged it for release, so it shipped something; file it under Changed.
    # (The old INTERNAL_ONLY heuristic -- drop a task whose tags are all
    # measurement/process -- is gone: with an explicit allow tag, the tag is
    # the decision, and a heuristic silently overriding it is a trap.)
    return "Changed"


def sections_for(tasks, warn=None):
    """Bucket the publishable tasks' bullets; `warn(msg)` is called per tagged task dropped."""
    grouped = OrderedDict((name, []) for name in BUCKETS)
    for task in tasks:
        text, why_not = publishable(task)
        if text is None:
            if why_not and warn:
                # The task id, never the title: this goes to stderr, and in
                # the release workflow stderr is a public Actions log.
                warn(f"generate_changelog.py: not publishing task {task.id}: {why_not}")
            continue
        name = bucket_for(task.tags)
        if name is not None:
            grouped[name].append(text)
    return OrderedDict((k, v) for k, v in grouped.items() if v)


def render_release(version, date, tasks, *, unreleased=False):
    heading = "## [Unreleased]" if unreleased else f"## [{version}] - {date}"
    lines = [heading, ""]
    sections = sections_for(tasks, warn=_warn)
    if not sections:
        lines += ["_No release notes recorded for this release; see the commit log._", ""]
        return lines
    for name, titles in sections.items():
        lines.append(f"### {name}")
        lines.append("")
        for title in titles:
            lines.append(f"- {title}")
        lines.append("")
    return lines


def escape_bullet(title):
    # Task titles are prose, not markdown; keep them readable without letting a
    # stray backtick or underscore reflow the list.
    return title.replace("\n", " ").strip()


def _warn(msg):
    print(msg, file=sys.stderr)


def build(tasks, releases, unreleased_version):
    parts = [HEADER.rstrip(), ""]
    prev_date = None
    windows = []
    for version, _tag, date in releases:
        windows.append((version, date, prev_date, date))
        prev_date = date
    last_release_date = releases[-1][2] if releases else None

    pending = [t for t in tasks if last_release_date is None or t.completed_at > last_release_date]
    if pending:
        parts += render_release(unreleased_version, None, pending, unreleased=True)

    for version, date, lo, hi in reversed(windows):
        window = [t for t in tasks
                  if (lo is None or t.completed_at > lo) and t.completed_at <= hi]
        parts += render_release(version, date[:10], window)

    parts += compare_links(releases, unreleased_version, bool(pending))
    return "\n".join(parts).rstrip() + "\n"


def compare_links(releases, unreleased_version, has_pending):
    base = "https://github.com/brandon-arrendondo/aurora-lint"
    lines = []
    if has_pending and releases:
        lines.append(f"[Unreleased]: {base}/compare/{releases[-1][1]}...HEAD")
    for i, (version, tag, _date) in enumerate(reversed(releases)):
        older = releases[len(releases) - i - 2] if i + 2 <= len(releases) else None
        if older:
            lines.append(f"[{version}]: {base}/compare/{older[1]}...{tag}")
        else:
            lines.append(f"[{version}]: {base}/releases/tag/{tag}")
    return ([""] + lines) if lines else []


def extract_section(text, version):
    """Return just the `## [version]` section body, for release notes."""
    pattern = re.compile(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)",
        re.M | re.S,
    )
    m = pattern.search(text)
    return m.group(1).strip() if m else None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if CHANGELOG.md differs from what would be generated")
    ap.add_argument("--release", metavar="VERSION",
                    help="print only that release's section (release-notes body)")
    ap.add_argument("--output", type=Path, default=CHANGELOG_PATH)
    args = ap.parse_args()

    content = build(load_tasks(), released_versions(), current_version())

    # Belt and braces: `publishable` screens every bullet, but nothing is
    # written or printed unless the finished text also passes the same scan
    # CI runs over the committed file, so the two cannot drift apart silently.
    hits = find_sensitive(content)
    if hits:
        for lineno, name, line in hits:
            print(f"generated changelog line {lineno}: [{name}] {line.strip()}", file=sys.stderr)
        print("error: generated changelog matches an ADR-0007 deny pattern; nothing written",
              file=sys.stderr)
        return 2

    if args.release:
        # Built from the DB and the tags present right now rather than read out
        # of the committed file, so release notes cannot be stale even if
        # CHANGELOG.md was last regenerated some tasks ago.
        version = args.release.lstrip("v")
        body = extract_section(content, version)
        if body is None:
            print(
                f"error: no changelog section for {version}. Tag {version} must "
                "exist and have completed tasks behind it.",
                file=sys.stderr,
            )
            return 1
        print(body)
        return 0

    if args.check:
        existing = args.output.read_text() if args.output.exists() else ""
        if existing != content:
            print(
                f"{args.output.name} is out of date. "
                "Regenerate with: python3 scripts/generate_changelog.py",
                file=sys.stderr,
            )
            return 1
        return 0

    args.output.write_text(content)
    print(f"wrote {args.output} ({content.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
