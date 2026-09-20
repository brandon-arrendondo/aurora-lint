#!/usr/bin/env python3
"""Fail if a changelog or release-notes file locates an unlanded defect.

CHANGELOG.md ships in every release tarball and the release notes are posted
to a public GitHub release, so both are part of the published record that
docs/adr/0007 governs: nothing that locates a defect in a real-world corpus
(project, file, line, mechanism) may appear there until the upstream fix has
landed. scripts/generate_changelog.py builds both from task titles, which are
internal working notes -- "confirmed OOB write at foo.c:579", "hostap
disclosure: act on maintainer response" -- and until task 1375 it published
them verbatim.

The generator now publishes only tasks explicitly marked for release (see its
docstring); this check is the second, independent layer: a content scan over
the committed text, run by pre-commit, CI and the release workflow, so a
regeneration that slips past the allowlist -- or a hand edit -- cannot
silently publish a match. Patterns, not judgment: the cost of a false match is
rewording one bullet, the cost of a miss is a public roadmap to an unpatched
bug, so the patterns lean wide.

Usage:
    python3 scripts/check_changelog_safety.py CHANGELOG.md [RELEASE_NOTES.md ...]
    exit 1 and print every offending line if any file matches; 0 otherwise.
"""
import re
import sys
from pathlib import Path

# Each entry is (name, compiled pattern). A line matching ANY of them fails.
# Names appear in the failure output so the reader knows which rule fired.
DENY_PATTERNS = [
    # A source location in a C/C++ corpus: `url.c:329`, `wpa_supplicant.c:8215`,
    # `conf.c line 921`, `fts3view.c@579`. This is the shape that locates a
    # defect. Rust/Python paths are aurora-lint's own code and are not covered.
    ("source location (file:line)",
     re.compile(r"\b[\w.\-/]+\.(?:c|h|cc|cpp|cxx|hh|hpp)\b\s*(?::|@|,?\s*line\s+)\s*\d+",
                re.IGNORECASE)),
    # Disclosure vocabulary: disclosure/disclosed/undisclosed, maintainer(s),
    # "upstream report" / "reported upstream" / "report upstream".
    ("disclosure vocabulary",
     re.compile(r"disclos|\bmaintainers?\b|upstream[- ]report|report(?:ed|ing)?\s+upstream",
                re.IGNORECASE)),
    # A vulnerability identifier or write-up vocabulary.
    ("vulnerability vocabulary",
     re.compile(r"\bCVE(?:-\d+)?\b|security advisory|\bexploit|\bvulnerab|\bzero[- ]day\b",
                re.IGNORECASE)),
    # "real bug" / "real defect" / "genuine bug": the phrasing task titles use
    # for a confirmed TP in a corpus, i.e. a defect that may not be fixed yet.
    ("confirmed-defect vocabulary",
     re.compile(r"\b(?:real|genuine|confirmed)\s+(?:bug|defect|vuln|UAF|OOB|double[- ]free)",
                re.IGNORECASE)),
]


def find_sensitive(text):
    """Every (line_number, pattern_name, line) in `text` that a deny pattern matches.

    Line numbers are 1-based. One line can appear more than once if several
    patterns match it; callers that only need yes/no use `is_sensitive`.
    """
    hits = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, pattern in DENY_PATTERNS:
            if pattern.search(line):
                hits.append((lineno, name, line))
    return hits


def is_sensitive(text):
    return any(pattern.search(text) for _name, pattern in DENY_PATTERNS)


def check_file(path):
    """Print every offending line of `path`; return the number found."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    hits = find_sensitive(text)
    for lineno, name, line in hits:
        print(f"{path}:{lineno}: [{name}] {line.strip()}", file=sys.stderr)
    return len(hits)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print("check_changelog_safety: expected one or more files to check",
              file=sys.stderr)
        return 2
    total = sum(check_file(p) for p in argv)
    if total:
        print(
            f"check_changelog_safety: {total} line(s) match an ADR-0007 deny "
            "pattern. A changelog bullet must not locate a defect in a real-world "
            "corpus or describe a disclosure; give the task a `release-note:` line "
            "written for publication (see scripts/generate_changelog.py) and "
            "regenerate.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
