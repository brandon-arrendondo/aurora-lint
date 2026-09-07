#!/usr/bin/env python3
"""Assert every real-world manifest carries an explicit decision for every rule.

WHY THIS EXISTS

Each ``conf/realworld/<cb>-rules.toml`` is a *complete standalone* manifest --
``--manifest`` replaces the base outright, there is no ``extends`` -- and a scan
iterates ``RuleManifest::enabled_rules()``. So a rule with no entry at all never
runs, and nothing says so. An omitted entry is byte-indistinguishable from an
oversight, in either direction.

Both directions actually happened. libcrc's manifest was created as the base
manifest minus exactly MSC04-C and MSC07-C: a deliberate categorical exclusion
inherited from a sibling embedded-C policy, but expressed by deleting the
entries rather than by ``enabled = false`` with a comment. It left no trace in
the commit message, none in the codebase's audit README (which does enumerate
its categorical disables by name), and none in the task DB -- so reading the
tree, the decision was unrecoverable from a mistake, and an audit first "fixed"
it as drift. A later suite-wide backfill applied one global list to all seven
manifests then current, so it could not see a gap unique to one of them.

Same failure shape as a drifted corpus checkout (``bench corpus-check``): the
runner records what it finds rather than asserting what was expected, and the
gap falls out of the measurement with no error at all.

WHAT IT CHECKS

Against the rule ids in ``rules_templates/rules-all.toml``:

1. **Missing** -- a rule with no ``[rules.cert_c.<ID>]`` block in a real-world
   manifest. This is the defect above: adding a rule under ``src/rules/cert_c/``
   fails this check until all nine manifests carry a decision for it, which is
   also how a new rule stops being silently dark on the real-world suite.
2. **Stale** -- a block naming a rule that no longer exists in the base. It
   reads as a decision and decides nothing; a rename leaves one behind.
3. **Undocumented disable** -- ``enabled = false`` with no comment anywhere in
   its block or immediately above it. ``conf/realworld/README.md`` allows a
   whole-rule disable for exactly three reasons and requires the line to state
   which; a bare ``false`` is the same "decision or oversight?" ambiguity one
   step along.

Deliberately NOT a check on which rules are enabled. Every codebase is entitled
to its own categorical policy -- this asserts only that the policy was *written
down*, per rule, per codebase.
"""

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "rules_templates" / "rules-all.toml"
REALWORLD_DIR = ROOT / "conf" / "realworld"

BLOCK_RE = re.compile(r"^\[rules\.cert_c\.([A-Z]+[0-9]+-C)\]\s*$")
DISABLED_RE = re.compile(r"^\s*enabled\s*=\s*false")


def rule_ids(path: Path) -> set[str]:
    with path.open("rb") as fh:
        return set(tomllib.load(fh).get("rules", {}).get("cert_c", {}))


def undocumented_disables(path: Path) -> list[str]:
    """Rule ids disabled without a comment stating why.

    A comment counts if it is trailing on the `enabled = false` line, anywhere
    else inside the rule's own block, or in the run of comment lines directly
    above the block header -- all three are used in the existing manifests.
    """
    lines = path.read_text().splitlines()
    starts = [(i, m.group(1)) for i, ln in enumerate(lines)
              if (m := BLOCK_RE.match(ln))]

    bad = []
    for n, (start, rule_id) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        block = lines[start + 1:end]
        if not any(DISABLED_RE.match(ln) for ln in block):
            continue
        if any("#" in ln for ln in block):
            continue
        preamble_end = starts[n - 1][0] if n else -1
        preceding = lines[preamble_end + 1:start]
        if any(ln.strip().startswith("#") for ln in preceding):
            continue
        bad.append(rule_id)
    return bad


def main() -> int:
    if not BASE.is_file():
        print(f"{BASE} not found -- run `cargo build` to generate it",
              file=sys.stderr)
        return 1

    base_ids = rule_ids(BASE)
    if not base_ids:
        print(f"no [rules.cert_c.*] blocks in {BASE}", file=sys.stderr)
        return 1

    manifests = sorted(REALWORLD_DIR.glob("*-rules.toml"))
    if not manifests:
        print(f"no *-rules.toml found in {REALWORLD_DIR}", file=sys.stderr)
        return 1

    print(f"{BASE.relative_to(ROOT)}: {len(base_ids)} rules; "
          f"checking {len(manifests)} real-world manifest(s)")

    failures = 0
    for path in manifests:
        rel = path.relative_to(ROOT)
        ids = rule_ids(path)
        missing = sorted(base_ids - ids)
        stale = sorted(ids - base_ids)
        bare = undocumented_disables(path)

        if missing:
            failures += 1
            print(f"\n{rel}: MISSING {len(missing)} rule(s) -- these never run "
                  f"and nothing reports it:\n  {', '.join(missing)}",
                  file=sys.stderr)
        if stale:
            failures += 1
            print(f"\n{rel}: {len(stale)} entr(y/ies) for rule(s) not in the "
                  f"base manifest (renamed or removed?):\n  {', '.join(stale)}",
                  file=sys.stderr)
        if bare:
            failures += 1
            print(f"\n{rel}: {len(bare)} disable(s) with no comment naming a "
                  f"reason (see conf/realworld/README.md):\n  "
                  f"{', '.join(bare)}", file=sys.stderr)

    if failures:
        print(
            "\nEvery real-world manifest is standalone: a rule with no entry "
            "never runs on that codebase, so it cannot reach the ground-truth "
            "oracle. Add the block with an explicit `enabled = true`/`false`, "
            "and a comment on every `false`.",
            file=sys.stderr)
        return 1

    print(f"all {len(manifests)} manifest(s) carry a decision for every rule")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
