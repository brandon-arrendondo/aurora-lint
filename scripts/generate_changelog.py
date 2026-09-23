#!/usr/bin/env python3
"""Maintain CHANGELOG.md's [Unreleased] section, and cut release notes, from
the task database -- under docs/adr/0009: the changelog is written for a user
of the tool, has only Added / Fixed / Removed headings, and the generator is
an aid to the author, not the author.

WHAT IS PUBLISHED. A task appears only if it is tagged `release-note` AND its
body carries two lines:

    release-note: <the bullet, written to be published>
    category: added | fixed | removed

The bullet goes under that heading. A tagged task missing either line, or
naming another category, is refused with a stderr warning naming the task id
only (never its title) -- ADR-0009 calls an uncategorised note a defect in
the note, not something to default into "Added". Task titles are never
published: they are internal working notes, and a large share of them locate
a defect in a real-world corpus, which docs/adr/0007 keeps out of the public
record until the fix has landed upstream. A tagged task is also
dropped, with a warning, if it carries a disclosure-family tag
(`disclosure`, `upstream`, `adr-0007`, ...) or a never-shipped tag
(adjudication, paper, ...), or if the bullet matches a content deny pattern
in scripts/check_changelog_safety.py (a `file.c:123` location, disclosure /
maintainer / CVE vocabulary). The same scan runs over the finished text
before anything is written, and independently over the committed file in
pre-commit, CI and the release workflow.

WHAT THE GENERATOR OWNS. Only the `## [Unreleased]` block and the compare-link
footer. Every dated release section is curated text (ADR-0009 consolidates
history by hand; the task DB has no notes for it) and is left byte-for-byte
alone. When the newest `v*` tag has no section in the file yet, the existing
[Unreleased] block is renamed to that release -- its notes are the release's
notes, and they must not vanish under a fresh, empty [Unreleased] -- and a
new [Unreleased] is generated above it from the tasks completed since the
tag. Tags are the release record: aurora-lint bumps the patch version on
nearly every commit (`run_id` discriminates benchmark runs by SHA), so only
tagged versions are releases.

`--release VERSION` prints that release's notes for the GitHub release body:
the file's section when the file has one, else the tasks completed in the
tag's window. Task tracking is maintainer infrastructure, not part of this
repo (CLAUDE.md), so without AURORA_LINT_TASK_DB (e.g. in CI) the task list
is empty rather than an error: `--release` still emits a valid section, and
the release workflow does not hard-fail on infrastructure it never had.

Usage:
    AURORA_LINT_TASK_DB=~/data/fleet-tasks.db python3 scripts/generate_changelog.py
    python3 scripts/generate_changelog.py --check            # exit 1 if [Unreleased] is stale
    python3 scripts/generate_changelog.py --release 0.5.2    # one release's notes, to stdout
"""
import argparse
import os
import re
import sqlite3
import subprocess
import sys
from collections import OrderedDict, namedtuple
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_changelog_safety import find_sensitive, is_sensitive  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("AURORA_LINT_TASK_DB", REPO_ROOT / "todo-sqlite-cli.db")).expanduser()
CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"
COMPARE_BASE = "https://github.com/brandon-arrendondo/aurora-lint"

# The one tag that makes a task publishable at all. Chosen over the topic tag
# `changelog` (already used on tasks ABOUT the changelog) so that consent to
# publish cannot be given by accident while filing.
ALLOW_TAG = "release-note"

# The two body lines a published task must carry. First match of each wins;
# matched case-insensitively at line start.
RELEASE_NOTE_LINE = re.compile(r"^\s*release[- ]note:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
CATEGORY_LINE = re.compile(r"^\s*category:\s*([A-Za-z]+)\s*$", re.IGNORECASE | re.MULTILINE)

# ADR-0009's headings, in the order they are emitted. Keep a Changelog's other
# headings (Changed, Deprecated, Security) are deliberately not accepted.
CATEGORIES = OrderedDict([("added", "Added"), ("fixed", "Fixed"), ("removed", "Removed")])

# Tags that mark disclosure work. A task carrying any of these is never
# published, allow tag or not -- its title and body are the working record
# ADR-0007 keeps local until the upstream fix lands. Matched as substrings so
# the ad-hoc variants (`hostap-upstream`, `upstream-disclosures`,
# `upstream-candidate`) are covered without listing each one.
DENY_TAG_FRAGMENTS = ("disclos", "upstream", "adr-0007", "triage", "cve")

# Work that never ships in the binary: adjudicating findings into ground
# truth, corpus curation, paper drafting. A task tagged `release-note` AND one
# of these is dropped with a warning naming it, since the two contradict.
NEVER_SHIPPED = {
    "ground-truth", "ground-truth-quality", "adjudication",
    "delta-adjudication", "evaluation", "paper", "benchmarking-db",
    "external-review",
}

Task = namedtuple("Task", "completed_at title tags details id")

UNRELEASED_HEADING = "## [Unreleased]"
EMPTY_SECTION = "_No release notes recorded for this release; see the commit log._"


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
        # UTC, in the task DB's own `...Z` form: `%cI` carries the committer's
        # local offset, and comparing that as text against a `Z` timestamp put a
        # release cut on a UTC-4 machine hours before the tasks it already contains.
        epoch = int(run_git("log", "-1", "--format=%ct", tag))
        date = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        out.append((tag[1:], tag, date))
    out.sort(key=lambda r: version_key(r[0]))
    return out


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


def publishable(task):
    """(category, text) if the task may be published, else (None, why-not).

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
    note = RELEASE_NOTE_LINE.search(task.details)
    if not note:
        return None, "has no `release-note: <bullet>` line; the title is never published"
    category = CATEGORY_LINE.search(task.details)
    if not category:
        return None, "has no `category: added|fixed|removed` line"
    key = category.group(1).lower()
    if key not in CATEGORIES:
        return None, f"category {category.group(1)!r} is not one of added|fixed|removed"
    text = escape_bullet(note.group(1))
    if is_sensitive(text):
        return None, "release note matches a content deny pattern (see scripts/check_changelog_safety.py)"
    return key, text


def sections_for(tasks, warn=None):
    """Bullets per heading, in ADR-0009 order; `warn(msg)` is called per tagged task dropped."""
    grouped = OrderedDict((name, []) for name in CATEGORIES.values())
    for task in tasks:
        key, text = publishable(task)
        if key is None:
            if text and warn:
                # The task id, never the title: this goes to stderr, and in
                # the release workflow stderr is a public Actions log.
                warn(f"generate_changelog.py: not publishing task {task.id}: {text}")
            continue
        grouped[CATEGORIES[key]].append(text)
    return OrderedDict((k, v) for k, v in grouped.items() if v)


def render_section(heading, tasks, warn=None):
    lines = [heading, ""]
    sections = sections_for(tasks, warn=warn)
    if not sections:
        return lines + [EMPTY_SECTION, ""]
    for name, bullets in sections.items():
        lines += [f"### {name}", ""]
        lines += [f"- {b}" for b in bullets]
        lines.append("")
    return lines


def escape_bullet(text):
    # Notes are prose, not markdown; keep them on one line.
    return text.replace("\n", " ").strip()


def _warn(msg):
    print(msg, file=sys.stderr)


def tasks_in_window(tasks, lo, hi):
    """Tasks completed after `lo` and up to `hi` (ISO timestamps; None = open)."""
    return [t for t in tasks
            if (lo is None or t.completed_at > lo) and (hi is None or t.completed_at <= hi)]


def compare_links(releases, has_unreleased):
    lines = []
    if has_unreleased and releases:
        lines.append(f"[Unreleased]: {COMPARE_BASE}/compare/{releases[-1][1]}...HEAD")
    for i, (version, tag, _date) in enumerate(reversed(releases)):
        older = releases[len(releases) - i - 2] if i + 2 <= len(releases) else None
        if older:
            lines.append(f"[{version}]: {COMPARE_BASE}/compare/{older[1]}...{tag}")
        else:
            lines.append(f"[{version}]: {COMPARE_BASE}/releases/tag/{tag}")
    return lines


# --- splicing into the curated file ------------------------------------------

SECTION_RE = re.compile(r"^## \[(?P<version>[^\]]+)\][^\n]*$", re.M)
LINK_RE = re.compile(r"^\[[^\]]+\]: https?://\S+[ \t]*\n?", re.M)


def split_document(text):
    """(preamble, [(heading_line, version, body)]) for every `## [..]` section, in order.

    Compare-link definitions are stripped from the last body: the footer is
    regenerated from the tags on every run.
    """
    heads = list(SECTION_RE.finditer(text))
    if not heads:
        return text, []
    preamble = text[:heads[0].start()]
    sections = []
    for i, m in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        sections.append((m.group(0), m.group("version"), text[m.end():end]))
    heading, version, body = sections[-1]
    sections[-1] = (heading, version, LINK_RE.sub("", body))
    return preamble, sections


def splice_unreleased(existing, unreleased_lines, releases):
    """Return `existing` with its [Unreleased] block replaced and the footer regenerated.

    If the newest release has no section, the old [Unreleased] block becomes
    that release's section (heading renamed, body kept) rather than being lost.
    """
    preamble, sections = split_document(existing)
    newest = releases[-1] if releases else None
    newest_has_section = bool(newest) and any(v == newest[0] for _, v, _ in sections)
    kept = []
    for heading, version, body in sections:
        if version == "Unreleased":
            if newest and not newest_has_section:
                kept.append((f"## [{newest[0]}] - {newest[2][:10]}", body))
            continue
        kept.append((heading, body))
    out = [preamble.rstrip("\n"), ""] if preamble.strip() else []
    out += unreleased_lines
    for heading, body in kept:
        # The body is kept byte-for-byte (it starts with the newline after
        # the heading); only the run of blank lines before the next section
        # is normalised to one.
        out += [heading + body.rstrip("\n"), ""]
    out += compare_links(releases, has_unreleased=True)
    return "\n".join(out).rstrip("\n") + "\n"


def build_unreleased(tasks, releases):
    last_release_date = releases[-1][2] if releases else None
    pending = tasks_in_window(tasks, last_release_date, None)
    return render_section(UNRELEASED_HEADING, pending, warn=_warn)


def extract_section(text, version):
    """Return just the `## [version]` section body (links stripped), or None."""
    for _heading, v, body in split_document(text)[1]:
        if v == version:
            return LINK_RE.sub("", body).strip()
    return None


def release_notes(version, tasks, releases, existing_text):
    """The notes for `version`: the curated file section if present, else the DB window."""
    from_file = extract_section(existing_text, version)
    if from_file:
        return from_file
    for i, (v, _tag, date) in enumerate(releases):
        if v == version:
            lo = releases[i - 1][2] if i > 0 else None
            lines = render_section(f"## [{version}]", tasks_in_window(tasks, lo, date), warn=_warn)
            return "\n".join(lines[2:]).strip()
    return None


def screen(text, what):
    """Refuse text the committed-file scan would refuse; returns True when clean."""
    hits = find_sensitive(text)
    for lineno, name, line in hits:
        print(f"{what} line {lineno}: [{name}] {line.strip()}", file=sys.stderr)
    if hits:
        print(f"error: {what} matches an ADR-0007 deny pattern; nothing written", file=sys.stderr)
    return not hits


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if CHANGELOG.md's [Unreleased] block differs from what would be generated")
    ap.add_argument("--release", metavar="VERSION",
                    help="print only that release's notes (release-notes body)")
    ap.add_argument("--output", type=Path, default=CHANGELOG_PATH)
    args = ap.parse_args()

    tasks = load_tasks()
    releases = released_versions()
    existing = args.output.read_text() if args.output.exists() else ""

    if args.release:
        version = args.release.lstrip("v")
        body = release_notes(version, tasks, releases, existing)
        if body is None:
            print(f"error: no changelog section and no tag for {version}.", file=sys.stderr)
            return 1
        if not screen(body, f"release notes for {version}"):
            return 2
        print(body)
        return 0

    content = splice_unreleased(existing, build_unreleased(tasks, releases), releases)
    # Belt and braces: `publishable` screens every bullet, but nothing is
    # written unless the finished text also passes the same scan CI runs over
    # the committed file, so the two cannot drift apart silently.
    if not screen(content, "generated changelog"):
        return 2

    if args.check:
        if existing != content:
            print(
                f"{args.output.name}'s [Unreleased] block is out of date. "
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
