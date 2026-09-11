#!/usr/bin/env python3
"""Reject commit messages carrying a git trailer that credits Claude/Anthropic.

CLAUDE.md forbids per-commit AI attribution trailers in this repo. The reason
is placement, not prohibition: Claude's contribution is acknowledged
deliberately in README.md's "AI Assistance" section, and repeating it in every
one of thousands of commits crowds out the message while telling a reader
nothing the README has not already said once.

Originally this only pattern-matched `Co-Authored-By`, so it accumulated in
172 commits before anyone noticed -- which is why it is a hook now rather
than a line of prose. That same failure mode reopened for any OTHER trailer
name: `Claude-Session:` (a live per-commit attribution convention, not
hypothetical) passed silently until this was widened, because the hook
checked one specific trailer key instead of the general shape. This version
matches any git-trailer-shaped line (`Key: value`) that mentions Claude or
Anthropic anywhere on the line -- in the key or the value -- so a new trailer
name doesn't need its own hook update to be caught.

Note sqc_paper deliberately differs and KEEPS these trailers; this hook is
tools_sqc's and must not be copied there.
"""
import re
import sys

# A git-trailer-shaped line: `SomeKey: value`. Deliberately not restricted to
# a fixed list of trailer names -- see the module docstring for why.
TRAILER_LINE = re.compile(r"^\s*[A-Za-z][A-Za-z0-9-]*\s*:\s*.+$", re.MULTILINE)

# Matches a trailer line only when it actually names Claude or Anthropic
# (in the key or the value), so a human co-author named in the usual way
# still passes.
AI_ATTRIBUTION = re.compile(r"\b(?:Claude|Anthropic)\b", re.IGNORECASE)


def main() -> int:
    if len(sys.argv) < 2:
        print("check_commit_message: expected a commit message file", file=sys.stderr)
        return 1

    with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
        message = fh.read()

    # Ignore the comment block git appends; it is stripped before committing.
    body = "\n".join(
        line for line in message.splitlines() if not line.startswith("#")
    )

    offenders = [
        line.strip()
        for line in TRAILER_LINE.findall(body)
        if AI_ATTRIBUTION.search(line)
    ]
    if not offenders:
        return 0

    print("", file=sys.stderr)
    print("Commit rejected: trailer crediting Claude/Anthropic.", file=sys.stderr)
    for line in offenders:
        print(f"    {line}", file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "CLAUDE.md forbids per-commit AI attribution trailers in tools_sqc\n"
        "(Co-Authored-By, Claude-Session, or any other trailer naming Claude/\n"
        "Anthropic). The contribution is acknowledged once, deliberately, in\n"
        "README.md's \"AI Assistance\" section -- do not remove that section\n"
        "for consistency, and do not repeat it per commit.\n"
        "\n"
        "Remove the trailer and commit again. (sqc_paper deliberately keeps\n"
        "these trailers; this rule is this repo's.)",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
