#!/usr/bin/env python3
"""Reject commit messages that credit Claude as a co-author.

CLAUDE.md forbids the `Co-Authored-By: Claude` trailer in this repo. The
reason is placement, not prohibition: Claude's contribution is acknowledged
deliberately in README.md's "AI Assistance" section, and repeating it in every
one of thousands of commits crowds out the message while telling a reader
nothing the README has not already said once.

Nothing checked this, so the trailer accumulated in 172 commits before anyone
noticed -- which is why it is a hook now rather than a line of prose.

Note sqc_paper deliberately differs and KEEPS the trailer; this hook is
tools_sqc's and must not be copied there.
"""
import re
import sys

# Matches the trailer only when it actually names Claude, so a human
# co-author named in the usual way still passes.
TRAILER = re.compile(
    r"^\s*Co-Authored-By\s*:.*\bClaude\b",
    re.IGNORECASE | re.MULTILINE,
)


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

    offenders = [m.group(0).strip() for m in TRAILER.finditer(body)]
    if not offenders:
        return 0

    print("", file=sys.stderr)
    print("Commit rejected: Co-Authored-By trailer naming Claude.", file=sys.stderr)
    for line in offenders:
        print(f"    {line}", file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "CLAUDE.md forbids this trailer in tools_sqc. The contribution is\n"
        "acknowledged once, deliberately, in README.md's \"AI Assistance\"\n"
        "section -- do not remove that section for consistency, and do not\n"
        "repeat it per commit.\n"
        "\n"
        "Remove the trailer and commit again. (sqc_paper deliberately keeps\n"
        "it; this rule is this repo's.)",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
