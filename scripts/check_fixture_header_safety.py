#!/usr/bin/env python3
"""Report ADR-0007-restricted vocabulary in rule test-fixture comments.

Standalone counts-only reporting script (bmdb 1414 step 4) -- deliberately
not a Rust test in a rule file (see CLAUDE.md: no #[cfg(test)] in rule
implementation files), and deliberately not wired into any CI gate here:
this repo owns the fixtures but not ADR-0007 or the disclosure-safety
policy (that's benchmark_adjudication's scripts/validate.py). This is a
one-off audit pass, run by hand.

Scope: `src/rules/cert_c/**/tests/**/*.c`, the actual per-rule fixture
files (`tests/fixtures/**` is CLI-runner plumbing with no descriptive
comments and isn't scanned).

Three allowlists specific to this corpus, none of which apply to
benchmark_adjudication's version of this check:
  - `Source: wiki` fixtures (filename prefix `wiki_`, or a header
    "* Source: wiki" line) quote or paraphrase CERT's own published
    SEI CERT C Coding Standard examples -- already-public standard
    documentation, not a claim about a specific real codebase we found
    something in. Reported separately, not counted as a hit.
  - The literal `[[reproducible]]` / `[[unsequenced]]` C attribute
    syntax (DCL42-C's own subject matter) is stripped before matching so
    the attribute name doesn't trip the reproducibility pattern.
  - A "* Rule: ARR30-C - Do not form or use out-of-bounds pointers or
    array subscripts" header line is the rule's own official CERT title
    (872 of 3993 fixtures carry one) -- also already-public standard
    text, not commentary of ours, and it dominates the raw oob/vulnerable
    counts (nearly all of it) with zero disclosure content. Stripped
    before matching.

Everything else uses the same vocabulary categories as
benchmark_adjudication's scripts/validate.py (ADR0007_PATTERNS), copied
rather than imported since the two repos don't share a dependency edge.
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_GLOB = "src/rules/cert_c/*/*/tests/**/*.c"

ATTRIBUTE_STRIP_RE = re.compile(r"\[\[\s*(?:reproducible|unsequenced)\s*\]\]")
RULE_TITLE_LINE_RE = re.compile(r"^\s*\*\s*Rule:\s*[A-Z]+[0-9]+-C\s*-.*$", re.M)

ADR0007_PATTERNS = {
    "crafted": re.compile(r"\bcrafted\b", re.I),
    "attacker": re.compile(r"\battacker\b", re.I),
    "exploit": re.compile(r"\bexploit(?:s|ed|able|ability)?\b", re.I),
    "reachable_threat": re.compile(
        r"\b(?:attacker|remote(?:ly)?|network|external(?:ly)?|untrusted|malicious)"
        r"[\w\s-]{0,25}reachab(?:le|ility)\b"
        r"|\breachab(?:le|ility)[\w\s-]{0,25}"
        r"(?:attacker|remote(?:ly)?|network|untrusted|malicious)\b",
        re.I,
    ),
    "oob": re.compile(r"\boob\b|\bout[- ]of[- ]bounds\b", re.I),
    "heap_buffer_overflow": re.compile(r"\bheap-buffer-overflow\b", re.I),
    "crash": re.compile(r"\bcrash(?:es|ed|ing)?\b", re.I),
    "dos": re.compile(r"\bDoS\b"),
    "poc": re.compile(r"\bPoC\b|\bpoc/", re.I),
    "sanitizer_tool": re.compile(r"\b(?:ASan|UBSan|valgrind|GDB|sanitizer)\b", re.I),
    "reproduced": re.compile(r"\breproduc(?:ed|ible|es)\b", re.I),
    "cve": re.compile(r"\bCVE-\d{4}-\d+\b|\bCVE\b", re.I),
    "segfault": re.compile(r"\bsegfault\b|\bSIGSEGV\b", re.I),
    "vulnerable": re.compile(r"\bvulnerab(?:le|ility)\b", re.I),
}

COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def comment_text(source: str) -> str:
    return " ".join(m.group(0) for m in COMMENT_RE.finditer(source))


def is_wiki_sourced(path: Path, source: str) -> bool:
    if path.name.startswith("wiki_"):
        return True
    return bool(re.search(r"^\s*\*\s*Source:\s*wiki\b", source, re.M))


def hit_categories(text: str) -> set[str]:
    text = ATTRIBUTE_STRIP_RE.sub(" ", text)
    text = RULE_TITLE_LINE_RE.sub(" ", text)
    hits = set()
    for name, pat in ADR0007_PATTERNS.items():
        if pat.search(text):
            hits.add(name)
    return hits


def main() -> None:
    counts: dict[tuple[str, str], int] = {}
    category_totals: dict[str, int] = {}
    wiki_skipped = 0
    total = 0
    hit_files: list[tuple[Path, set[str]]] = []

    for path in sorted(REPO_ROOT.glob(FIXTURE_GLOB)):
        total += 1
        source = path.read_text(errors="replace")
        if is_wiki_sourced(path, source):
            wiki_skipped += 1
            continue
        hits = hit_categories(comment_text(source))
        if not hits:
            continue
        rule_id = path.parents[2].name  # .../<RULE_ID>/tests/{pass,fail}/file.c
        key = (rule_id, "hit")
        counts[key] = counts.get(key, 0) + 1
        for name in hits:
            category_totals[name] = category_totals.get(name, 0) + 1
        hit_files.append((path.relative_to(REPO_ROOT), hits))

    print(f"{total} fixture file(s) scanned, {wiki_skipped} wiki-sourced (skipped)")
    print(f"{len(hit_files)} file(s) flagged\n")
    print("by rule:")
    for (rule_id, _), n in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {rule_id:12s} {n}")
    print("\nby category:")
    for name, n in sorted(category_totals.items(), key=lambda kv: -kv[1]):
        print(f"  {name:20s} {n}")
    if "--files" in sys.argv:
        print("\nflagged files:")
        for path, hits in hit_files:
            print(f"  {path}: {', '.join(sorted(hits))}")


if __name__ == "__main__":
    main()
