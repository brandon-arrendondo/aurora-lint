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

1. **Missing** -- a rule with no ``[rules.cert_c.<ID>]`` (or ``[rules.cwe.<ID>]``) block in a real-world
   manifest. This is the defect above: adding a rule under ``src/rules/cert_c/``
   fails this check until every manifest carries a decision for it, which is
   also how a new rule stops being silently dark on the real-world suite.
2. **Stale** -- a block naming a rule that no longer exists in the base. It
   reads as a decision and decides nothing; a rename leaves one behind.
3. **Undocumented disable** -- ``enabled = false`` with no comment anywhere in
   its block or immediately above it. ``conf/realworld/README.md`` allows a
   whole-rule disable for exactly three reasons and requires the line to state
   which; a bare ``false`` is the same "decision or oversight?" ambiguity one
   step along.

4. **No data model** -- a manifest with no ``[environment] data_model``. The
   tool's default is ``iso`` (only what ISO C guarantees), so a corpus whose
   manifest says nothing is scanned under it and its integer findings stop
   being comparable with every other corpus's. Each corpus declares the
   architecture it is built for, with the reason in
   ``docs/design/realworld-corpus-scope.md``; a new one must too.

5. **Invalid configuration** -- a manifest ``aurora-lint --check-config``
   refuses: an unknown key, a bad value, a width below its ISO minimum, a rank
   order that shrinks. The check runs the tool's own validation, the code a
   scan runs, so the manifest cannot be valid here and refused there. It needs
   a built binary (``target/release`` or ``target/debug``, or
   ``$AURORA_LINT``); without one it says so and skips only this check.

Deliberately NOT a check on which rules are enabled. Every codebase is entitled
to its own categorical policy -- this asserts only that the policy was *written
down*, per rule, per codebase.
"""

import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "rules_templates" / "rules-all.toml"
REALWORLD_DIR = ROOT / "conf" / "realworld"
REMOVED = ROOT / "rules_templates" / "removed-rules.toml"

# Every rule family the default manifest ships: CERT C and the CWE ruleset.
FAMILIES = ("cert_c", "cwe")
BLOCK_RE = re.compile(r"^\[rules\.(?:cert_c\.([A-Z]+[0-9]+-C)|cwe\.(CWE-[0-9]+))\]\s*$")
DISABLED_RE = re.compile(r"^\s*enabled\s*=\s*false")


def removed_rules() -> dict[str, dict]:
    """Rules the tool no longer ships (ADR-0013 Decision 4), by id."""
    if not REMOVED.is_file():
        return {}
    with REMOVED.open("rb") as fh:
        return {r["id"]: r for r in tomllib.load(fh).get("removed", [])}


def rule_ids(path: Path) -> set[str]:
    with path.open("rb") as fh:
        rules = tomllib.load(fh).get("rules", {})
    return {rule_id for family in FAMILIES for rule_id in rules.get(family, {})}


DATA_MODELS = {"iso", "ilp32", "lp64", "llp64"}


def declared_data_model(path: Path) -> str | None:
    """The manifest's ``[environment] data_model``, or None when it has none
    (or a value the tool does not accept)."""
    with path.open("rb") as fh:
        value = tomllib.load(fh).get("environment", {}).get("data_model")
    return value if value in DATA_MODELS else None


def undocumented_disables(path: Path) -> list[str]:
    """Rule ids disabled without a comment stating why.

    A comment counts if it is trailing on the `enabled = false` line, anywhere
    else inside the rule's own block, or in the run of comment lines directly
    above the block header -- all three are used in the existing manifests.
    """
    lines = path.read_text().splitlines()
    starts = [(i, m.group(1) or m.group(2)) for i, ln in enumerate(lines)
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


def built_binary() -> Path | None:
    """The aurora-lint binary to validate manifests with, if one is built."""
    env = os.environ.get("AURORA_LINT")
    candidates = [Path(env)] if env else []
    candidates += [ROOT / "target" / "release" / "aurora-lint",
                   ROOT / "target" / "debug" / "aurora-lint"]
    # The newest build: an older one in the other profile may predate a flag.
    built = [c for c in candidates if c.is_file()]
    return max(built, key=lambda c: c.stat().st_mtime, default=None)


def knows_check_config(binary: Path) -> bool:
    """Whether `binary` has --check-config, so a stale build is skipped
    instead of being read as every manifest being invalid."""
    result = subprocess.run([str(binary), "--help"], capture_output=True, text=True)
    return "--check-config" in result.stdout


def check_config(binary: Path, path: Path) -> list[str]:
    """The problems ``aurora-lint --check-config`` finds in `path`: its
    stderr, one ``error:`` line per problem, empty when it is valid."""
    result = subprocess.run([str(binary), "--check-config", "-m", str(path)],
                            capture_output=True, text=True)
    if result.returncode == 0:
        return []
    return [ln for ln in result.stderr.splitlines() if ln.strip()] or [
        f"exit {result.returncode}"]


def main() -> int:
    if not BASE.is_file():
        print(f"{BASE} not found -- run `cargo build` to generate it",
              file=sys.stderr)
        return 1

    base_ids = rule_ids(BASE)
    removed = removed_rules()
    if not base_ids:
        print(f"no [rules.cert_c.*] or [rules.cwe.*] blocks in {BASE}", file=sys.stderr)
        return 1

    manifests = sorted(REALWORLD_DIR.glob("*-rules.toml"))
    if not manifests:
        print(f"no *-rules.toml found in {REALWORLD_DIR}", file=sys.stderr)
        return 1

    print(f"{BASE.relative_to(ROOT)}: {len(base_ids)} rules; "
          f"checking {len(manifests)} real-world manifest(s)")

    binary = built_binary()
    if binary is None:
        print("note: no built aurora-lint binary (target/release or target/debug): "
              "manifests were not validated with --check-config")
    elif not knows_check_config(binary):
        print(f"note: {binary.relative_to(ROOT)} predates --check-config (rebuild it): "
              "manifests were not validated with it")
        binary = None

    failures = 0
    for path in manifests:
        rel = path.relative_to(ROOT)
        ids = rule_ids(path)
        missing = sorted(base_ids - ids)
        named_removed = sorted((ids - base_ids) & removed.keys())
        stale = sorted(ids - base_ids - removed.keys())
        bare = undocumented_disables(path)
        no_model = declared_data_model(path) is None

        if missing:
            failures += 1
            print(f"\n{rel}: MISSING {len(missing)} rule(s) -- these never run "
                  f"and nothing reports it:\n  {', '.join(missing)}",
                  file=sys.stderr)
        if named_removed:
            failures += 1
            print(f"\n{rel}: {len(named_removed)} block(s) for rule(s) the tool "
                  f"no longer ships -- delete them (a scan ignores them with a "
                  f"warning):\n  " + "\n  ".join(
                      f"{r} (removed in v{removed[r]['removed_in']}: "
                      f"{removed[r]['reason']})" for r in named_removed),
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

        invalid = check_config(binary, path) if binary else []
        if invalid:
            failures += 1
            print(f"\n{rel}: refused by --check-config:\n  " + "\n  ".join(invalid),
                  file=sys.stderr)
        if no_model:
            failures += 1
            print(f"\n{rel}: no `[environment] data_model` (one of "
                  f"{', '.join(sorted(DATA_MODELS))}) -- the scan would run "
                  f"under the default, iso, unlike every other corpus; "
                  f"declare the architecture it is built for and say why in "
                  f"docs/design/realworld-corpus-scope.md", file=sys.stderr)

    if failures:
        print(
            "\nEvery real-world manifest is standalone: a rule with no entry "
            "never runs on that codebase, so it cannot reach the ground-truth "
            "oracle. Add the block with an explicit `enabled = true`/`false`, "
            "and a comment on every `false`.",
            file=sys.stderr)
        return 1

    print(f"all {len(manifests)} manifest(s) carry a decision for every rule, "
          f"declare a data model" + (" and pass --check-config" if binary else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
