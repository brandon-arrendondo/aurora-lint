#!/usr/bin/env python3
"""Report the test-fixture corpus split by provenance (CERT wiki vs local).

Every fixture under `src/rules/*/*/*/tests/{fail,pass,expected_fail}/` carries
a `Source:` line in its header comment. That line is what separates two kinds
of evidence that otherwise look identical in a pass/fail count:

  wiki  -- derived from the CERT C wiki's own compliant / non-compliant code
           examples. Third-party: SEI wrote them against the rule text, with
           no knowledge of aurora-lint, so agreement is external conformance evidence.
  local -- written in this repo, nearly always to pin a specific bug found in
           real code or a regression. Regression evidence only: we chose both
           the input and the expected answer.

The split is what the header *declares*, an authoring convention rather than
an audit. `scripts/audit_wiki_fixture_staleness.py` is the independent check
on it: it re-fetches each rule's current wiki page and measures what fraction
of a wiki code block's lines still appear in the fixture claiming to derive
from it (`data/wiki_fixture_staleness.json`). `--containment` reports that
distribution, which is the evidence for how wiki-derived the wiki tier really
is; a fixture rewritten until it matched what the checker looks for would
show low containment.

Usage:
    python3 scripts/fixture_provenance.py [--containment] [--by-rule] [--json]
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_ROOT = REPO_ROOT / "src" / "rules"
STALENESS = REPO_ROOT / "data" / "wiki_fixture_staleness.json"
TIERS = ("fail", "pass", "expected_fail")

SOURCE_RE = re.compile(r"^\s*\*\s*Source:\s*(.+?)\s*$", re.M)


def classify(source):
    """Map a declared Source: value onto wiki / local / undeclared."""
    if source is None:
        return "undeclared"
    return "wiki" if source.strip().lower().startswith("wiki") else "local"


def read_source(path):
    # The header comment is the first few lines; do not scan whole fixtures,
    # some of which are thousands of lines of generated nesting.
    head = "".join(path.read_text(errors="replace").splitlines(keepends=True)[:12])
    m = SOURCE_RE.search(head)
    return m.group(1) if m else None


def collect():
    rows = []
    for tier in TIERS:
        for path in sorted(RULES_ROOT.glob(f"*/*/*/tests/{tier}/*.c")):
            rule = path.parents[2].name
            source = read_source(path)
            rows.append((rule, tier, classify(source), source, path))
    return rows


def containment_report():
    if not STALENESS.exists():
        print(f"no {STALENESS.relative_to(REPO_ROOT)}; run "
              "scripts/audit_wiki_fixture_staleness.py first", file=sys.stderr)
        return None
    data = json.loads(STALENESS.read_text())
    bands = [
        (0.999, "1.00      wiki block reproduced line-for-line"),
        (0.85, "0.85-0.99 lightly edited"),
        (0.55, "0.55-0.84 substantially edited"),
        (0.0001, "0.01-0.54 mostly rewritten"),
        (-1.0, "0.00      no line overlap with the current page"),
    ]
    counts = Counter()
    total = 0
    stale = 0
    for rule in data.values():
        for fixture in rule.get("fixtures", []):
            total += 1
            stale += bool(fixture.get("stale"))
            c = fixture.get("containment", 0.0)
            for threshold, label in bands:
                if c >= threshold:
                    counts[label] += 1
                    break
    return {"audited": total, "stale": stale,
            "bands": [(label, counts[label]) for _, label in bands],
            "rules_checked": sum(1 for r in data.values()
                                 if r.get("status") == "checked")}


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--containment", action="store_true",
                    help="also report wiki-fixture containment against the live wiki")
    ap.add_argument("--by-rule", action="store_true",
                    help="list rules with no wiki-derived fixture at all")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rows = collect()
    per_tier = defaultdict(Counter)
    per_rule = defaultdict(Counter)
    for rule, tier, kind, _source, _path in rows:
        per_tier[tier][kind] += 1
        per_rule[rule][kind] += 1

    if args.json:
        print(json.dumps({
            "tiers": {t: dict(c) for t, c in per_tier.items()},
            "rules": {r: dict(c) for r, c in per_rule.items()},
            "containment": containment_report() if args.containment else None,
        }, indent=2, sort_keys=True))
        return 0

    width = max(len(t) for t in TIERS)
    print(f"{'tier':<{width}}  {'wiki':>7} {'local':>7} {'undecl':>7} {'total':>7}")
    totals = Counter()
    for tier in TIERS:
        c = per_tier[tier]
        total = sum(c.values())
        totals.update(c)
        print(f"{tier:<{width}}  {c['wiki']:>7} {c['local']:>7} "
              f"{c['undeclared']:>7} {total:>7}")
    grand = sum(totals.values())
    print(f"{'ALL':<{width}}  {totals['wiki']:>7} {totals['local']:>7} "
          f"{totals['undeclared']:>7} {grand:>7}")
    print(f"\n{len(per_rule)} rules with fixtures; "
          f"{sum(1 for c in per_rule.values() if not c['wiki'])} have no "
          f"wiki-derived fixture.")

    if args.by_rule:
        missing = sorted(r for r, c in per_rule.items() if not c["wiki"])
        print("\nrules with no wiki-derived fixture (regression evidence only):")
        for rule in missing:
            print(f"  {rule}")

    if args.containment:
        rep = containment_report()
        if rep:
            print(f"\nwiki-fixture containment against the current CERT wiki "
                  f"({rep['rules_checked']} rules re-fetched, "
                  f"{rep['audited']} fixtures):")
            for label, count in rep["bands"]:
                print(f"  {count:>5}  {label}")
            print(f"  {rep['stale']} flagged stale by the auditor's own threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
