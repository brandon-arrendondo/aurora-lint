#!/usr/bin/env python3
"""Publish the rules aurora-lint no longer ships, from their one source.

ADR-0013 Decision 6: every rule that isn't shipped, and why, appears in
README.md and in docs/. The list lives in rules_templates/removed-rules.toml
(the same table the manifest loader and `--list-rules` read), and this script
renders it into both places between markers:

    README.md               <!-- REMOVED-RULES:START --> ... <!-- REMOVED-RULES:END -->
    docs/configuration.rst  .. REMOVED-RULES:START ... .. REMOVED-RULES:END

Everything outside the markers is hand-written and left alone.

It also checks the other record of the decision: each removed rule's row in
docs/design/rule-disposition.md must carry the same not-shipped disposition,
so the table and the tool cannot disagree about why a rule is gone.

    python3 scripts/render_removed_rules.py          # rewrite the blocks
    python3 scripts/render_removed_rules.py --check  # pre-commit: fail on drift

Dependency-free (stdlib tomllib, Python 3.11+).
"""

import argparse
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TABLE = ROOT / "rules_templates" / "removed-rules.toml"
DISPOSITIONS = ROOT / "docs" / "design" / "rule-disposition.md"

# The labels src/manifest/removed.rs's Disposition::label prints.
LABELS = {
    "unenforceable": "unenforceable",
    "fails-criterion": "fails the criterion",
    "covered": "covered by another rule",
    "deprecated": "deprecated by CERT",
}

# How rule-disposition.md's disposition column begins for each: it names
# the covering rules ("covered by ERR33-C, EXP12-C") or the successor
# ("deprecated by CERT (successor INT02-C)") in place of the generic label.
ROW_PREFIX = {
    "unenforceable": "unenforceable",
    "fails-criterion": "fails the criterion",
    "covered": "covered by ",
    "deprecated": "deprecated by CERT",
}

NONE_YET = "No rule has been removed yet."


def load() -> list[dict]:
    with TABLE.open("rb") as f:
        return tomllib.load(f).get("removed", [])


def one_line(text: str) -> str:
    """`text` with its whitespace, newlines included, collapsed to single
    spaces: a reason is one sentence, and a line break would end the table
    row or the bullet."""
    return " ".join(text.split())


def covered_text(rule: dict) -> str:
    covers = rule.get("covered_by", [])
    if not covers:
        return ""
    verb = "replaced by" if rule["disposition"] == "deprecated" else "covered by"
    return f"{verb} {', '.join(covers)}"


def render_markdown(rules: list[dict]) -> str:
    if not rules:
        return NONE_YET
    lines = [
        "| Rule | Removed in | Why | Instead |",
        "|------|------------|-----|---------|",
    ]
    for r in rules:
        # A `|` would end the Markdown cell.
        reason = one_line(r["reason"]).replace("|", "\\|")
        why = f"{LABELS[r['disposition']]}: {reason}"
        lines.append(f"| {r['id']} | v{r['removed_in']} | {why} | {covered_text(r) or '-'} |")
    return "\n".join(lines)


def render_rst(rules: list[dict]) -> str:
    if not rules:
        return NONE_YET
    lines = []
    for r in rules:
        # A `|` would open an RST substitution reference.
        reason = one_line(r["reason"]).rstrip(".").replace("|", "\\|") + "."
        item = f"- **{r['id']}** (removed in v{r['removed_in']}, {LABELS[r['disposition']]}): {reason}"
        if covered_text(r):
            item += f" Now {covered_text(r)}."
        lines.append(item)
    return "\n".join(lines)


TARGETS = [
    (ROOT / "README.md", "<!-- REMOVED-RULES:START -->", "<!-- REMOVED-RULES:END -->", render_markdown),
    (ROOT / "docs" / "configuration.rst", ".. REMOVED-RULES:START", ".. REMOVED-RULES:END", render_rst),
]


def replace_block(text: str, start: str, end: str, body: str, path: Path) -> str:
    pattern = re.compile(re.escape(start) + r"\n.*?" + re.escape(end), re.S)
    if len(pattern.findall(text)) != 1:
        raise SystemExit(f"{path.relative_to(ROOT)}: expected exactly one {start} ... {end} block")
    return pattern.sub(lambda _: f"{start}\n\n{body}\n\n{end}", text)


def disposition_problems(rules: list[dict]) -> list[str]:
    rows = {}
    for line in DISPOSITIONS.read_text().splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) > 2 and re.fullmatch(r"[A-Z]{3}\d{2}-C", cells[0]):
            rows[cells[0]] = cells[2]
    where = DISPOSITIONS.relative_to(ROOT)
    problems = []
    for r in rules:
        got = rows.get(r["id"])
        if got is None:
            problems.append(f"{r['id']} is removed but has no row in {where}")
            continue
        if not got.startswith(ROW_PREFIX[r["disposition"]]):
            problems.append(
                f"{r['id']}: removed as '{LABELS[r['disposition']]}' but {where} says '{got}'"
            )
        missing = [c for c in r.get("covered_by", []) if not re.search(rf"\b{re.escape(c)}\b", got)]
        if missing:
            problems.append(
                f"{r['id']}: covered_by names {', '.join(missing)}, which {where}'s row '{got}' does not"
            )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="fail instead of rewriting")
    args = parser.parse_args()

    rules = load()
    problems = disposition_problems(rules)
    for path, start, end, render in TARGETS:
        text = path.read_text()
        updated = replace_block(text, start, end, render(rules), path)
        if updated == text:
            continue
        if args.check:
            problems.append(
                f"{path.relative_to(ROOT)}: the not-shipped list is out of date; "
                "run python3 scripts/render_removed_rules.py"
            )
        else:
            path.write_text(updated)
            print(f"updated {path.relative_to(ROOT)}")

    for p in problems:
        print(p, file=sys.stderr)
    print(f"{TABLE.relative_to(ROOT)}: {len(rules)} removed rule(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
