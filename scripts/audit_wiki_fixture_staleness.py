#!/usr/bin/env python3
"""
Task 328 triage: determine which of the pre-existing wiki_*.c fixtures are
actually stale relative to the CURRENT cmu-sei.github.io page content,
before attempting any resynthesis.

Task 328's premise is that some/all of 569 existing wiki_*.c fixtures may
no longer reflect current wiki content (post-Confluence migration, possible
rule revisions). But most existing fixtures are hand/AI-synthesized wrappers
around the wiki's example code, not literal extractions -- so a byte-diff
against the current scrape is useless. Instead, for each fixture this does
a line-containment check: what fraction of a current-page code block's
non-blank lines appear (as substrings) in the fixture. High containment
against *some* current block means the fixture is still faithful to current
content (just wrapped/renamed). No current block reaching the threshold
means the fixture is a candidate for staleness -- either the page changed
since the original scrape, or it never was a faithful extraction.

This produces a bounded worklist instead of speculatively resynthesizing
everything.

Usage: python3 scripts/audit_wiki_fixture_staleness.py [--delay SECONDS] [--limit N]
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scrape_cert_wiki import WikiScraper, extract_code_examples, CATEGORY_DIR_OVERRIDES

BASE_OUTPUT_DIR = Path("src/rules/cert_c")
MATCH_THRESHOLD = 0.55


def normalize_lines(code: str):
    lines = []
    for line in code.splitlines():
        s = re.sub(r"\s+", " ", line.strip())
        if s and not s.startswith("//") and not s.startswith("*") and s != "/*" and s != "*/":
            lines.append(s)
    return lines


def containment_fraction(block_lines, fixture_lines):
    if not block_lines:
        return 0.0
    hits = sum(1 for bl in block_lines if any(bl in fl or fl in bl for fl in fixture_lines))
    return hits / len(block_lines)


def find_rule_dirs():
    rule_dirs = {}
    for toml in BASE_OUTPUT_DIR.glob("*/*/*.toml"):
        item_id = toml.stem
        if re.match(r"^[A-Z]{3}\d{2}-C$", item_id):
            rule_dirs[item_id] = toml.parent
    return rule_dirs


def existing_fixtures(rule_dir: Path):
    out = []
    for sub in ("fail", "pass"):
        d = rule_dir / "tests" / sub
        if d.is_dir():
            out.extend(sorted(d.glob("wiki_*.c")))
    return out


def path_for_item(item_id: str):
    m = re.match(r"^([A-Z]{3})(\d{2})-C$", item_id)
    if not m:
        return None
    return f"/rules/{item_id.lower()}" if False else None  # unused; paths come from nav


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default="data/wiki_fixture_staleness.json")
    args = ap.parse_args()

    scraper = WikiScraper(delay=args.delay)
    items = scraper.discover_items()  # (item_id, title, item_type, category, path)
    path_by_id = {item_id: path for item_id, _, _, _, path in items}
    type_by_id = {item_id: item_type for item_id, _, item_type, _, _ in items}

    rule_dirs = find_rule_dirs()
    rules_with_fixtures = {
        rid: rdir for rid, rdir in rule_dirs.items() if existing_fixtures(rdir)
    }
    print(f"{len(rules_with_fixtures)} rules have existing wiki_*.c fixtures")

    results = {}
    processed = 0
    for item_id, rule_dir in sorted(rules_with_fixtures.items()):
        if args.limit and processed >= args.limit:
            break
        path = path_by_id.get(item_id)
        if not path:
            results[item_id] = {"status": "no_longer_on_site"}
            processed += 1
            continue

        parsed = scraper.parse_item_page(item_id, path, type_by_id.get(item_id, "rule"))
        processed += 1
        if not parsed:
            results[item_id] = {"status": "fetch_failed"}
            continue
        _, non_compliant, compliant = parsed
        current_blocks = [("fail", n, c) for n, c in non_compliant] + [
            ("pass", n, c) for n, c in compliant
        ]
        current_norm = [(bucket, name, normalize_lines(code)) for bucket, name, code in current_blocks]

        fixture_reports = []
        any_stale = False
        for fpath in existing_fixtures(rule_dir):
            bucket = fpath.parent.name  # fail|pass
            fixture_lines = normalize_lines(fpath.read_text(errors="replace"))
            best_frac = 0.0
            best_name = None
            for cbucket, cname, cblock_lines in current_norm:
                if cbucket != bucket or not cblock_lines:
                    continue
                frac = containment_fraction(cblock_lines, fixture_lines)
                if frac > best_frac:
                    best_frac = frac
                    best_name = cname
            stale = best_frac < MATCH_THRESHOLD
            any_stale = any_stale or stale
            fixture_reports.append(
                {
                    "file": str(fpath),
                    "best_match": best_name,
                    "containment": round(best_frac, 2),
                    "stale": stale,
                }
            )

        results[item_id] = {
            "status": "checked",
            "current_block_count": len(current_norm),
            "any_stale": any_stale,
            "fixtures": fixture_reports,
        }
        stale_count = sum(1 for f in fixture_reports if f["stale"])
        print(f"  {item_id}: {len(fixture_reports)} fixtures, {stale_count} flagged stale")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(results, indent=2))
    print(f"\nWrote {args.out}")

    stale_rules = [rid for rid, r in results.items() if r.get("any_stale")]
    print(f"\n{len(stale_rules)}/{len(results)} rules have >=1 fixture flagged stale")


if __name__ == "__main__":
    main()
