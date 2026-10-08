#!/usr/bin/env python3
"""Reject parsed Git trailers naming an AI agent or vendor.

CONTRIBUTING.md's "Git Commit Rules" explains the placement policy: AI use
is acknowledged once in README.md, rather than repeated in commit trailers.
Use Git's trailer parser so ordinary subject/body mentions remain allowed.
Human co-authors pass unless the parsed trailer names a listed AI tool/vendor.
"""
import re
import subprocess
import sys

# Add future agents here; avoid bare employer names such as Google/Microsoft.
AI_TOOL_NAMES = [
    "Claude",
    "Anthropic",
    "Codex",
    "OpenAI",
    "ChatGPT",
    "Gemini",
    "Copilot",
]
AI_ATTRIBUTION = re.compile(
    r"\b(?:" + "|".join(re.escape(name) for name in AI_TOOL_NAMES) + r")\b",
    re.IGNORECASE,
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

    result = subprocess.run(
        ["git", "interpret-trailers", "--parse"],
        input=body,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("check_commit_message: git interpret-trailers failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        return 1

    offenders = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and AI_ATTRIBUTION.search(line)
    ]
    if not offenders:
        return 0

    print("", file=sys.stderr)
    print("Commit rejected: trailer crediting an AI agent or vendor.", file=sys.stderr)
    for line in offenders:
        print(f"    {line}", file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "CONTRIBUTING.md forbids per-commit AI attribution trailers in aurora-lint\n"
        "(Co-Authored-By or any other trailer naming a listed AI tool/vendor).\n"
        "AI use is acknowledged once in README.md's \"AI Assistance\" section;\n"
        "keep that section and remove the trailer before committing again.",
        file=sys.stderr,
    )
    print("", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
