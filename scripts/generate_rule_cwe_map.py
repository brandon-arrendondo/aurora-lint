#!/usr/bin/env python3
"""
Generate a mapping between CERT C rule IDs and CWE IDs from TOML metadata.

Walks src/rules/cert_c/**/*.toml, extracts [metadata].id and its two CWE
lists, and produces data/rule_cwe_map.json with forward and reverse mappings.

- [references].cwe: CWEs whose Juliet test cases exercise what the rule checks
  (ADR-0013 Decision 3). Only these drive Juliet CWE-matched scoring and the
  per-CWE fast-mode manifests.
- [references].related_cwe: CWEs the guideline's CERT page or cwe.mitre.org
  relates to the rule, not verified against Juliet. Informational only.

A CWE may appear in one list or the other, never both.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # Python < 3.11


def _normalize(cwes: list[str]) -> list[str]:
    """Normalize CWE IDs to "CWE-NNN" ("CWE190" becomes "CWE-190")."""
    normalized = []
    for cwe in cwes:
        cwe = cwe.strip()
        if cwe.startswith("CWE-"):
            normalized.append(cwe)
        elif cwe.startswith("CWE"):
            normalized.append("CWE-" + cwe[3:])
        else:
            normalized.append(cwe)
    return normalized


def generate_map(project_dir: Path) -> dict:
    toml_dir = project_dir / "src" / "rules" / "cert_c"
    rule_to_cwes: dict[str, list[str]] = {}
    cwe_to_rules: dict[str, list[str]] = defaultdict(list)
    rule_to_related: dict[str, list[str]] = {}

    toml_count = 0
    rules_with_cwe = 0

    for toml_path in sorted(toml_dir.rglob("*.toml")):
        toml_count += 1
        try:
            with open(toml_path, "rb") as f:
                data = tomllib.load(f)
        except Exception as e:
            print(f"WARNING: Could not parse {toml_path}: {e}", file=sys.stderr)
            continue

        rule_id = data.get("metadata", {}).get("id")
        if not rule_id:
            continue

        refs = data.get("references", {})
        related = _normalize(refs.get("related_cwe", []))
        normalized = _normalize(refs.get("cwe", []))
        both = sorted(set(normalized) & set(related))
        if both:
            raise SystemExit(
                f"{toml_path}: {', '.join(both)} in both cwe and related_cwe")
        if related:
            rule_to_related[rule_id] = related
        if not normalized:
            continue

        rule_to_cwes[rule_id] = normalized
        rules_with_cwe += 1
        for cwe in normalized:
            cwe_to_rules[cwe].append(rule_id)

    # Sort reverse map values for deterministic output
    for cwe in cwe_to_rules:
        cwe_to_rules[cwe] = sorted(set(cwe_to_rules[cwe]))

    return {
        "rule_to_cwes": dict(sorted(rule_to_cwes.items())),
        "cwe_to_rules": dict(sorted(cwe_to_rules.items())),
        "rule_to_related_cwes": dict(sorted(rule_to_related.items())),
        "stats": {
            "toml_count": toml_count,
            "rules_with_cwe": rules_with_cwe,
            "unique_cwes": len(cwe_to_rules),
            "rules_with_related_cwe": len(rule_to_related),
        },
    }


def generate_cwe_manifests(project_dir: Path, cwe_to_rules: dict[str, list[str]]) -> int:
    """Generate per-CWE TOML manifests with only CWE-matched rules enabled.

    Each manifest lives at rules_templates/cwe/CWE-NNN.toml and contains only
    the rules that map to that CWE, so aurora-lint runs faster and produces less noise.
    """
    manifest_dir = project_dir / "rules_templates" / "cwe"
    manifest_dir.mkdir(parents=True, exist_ok=True)

    # A CWE with no mapped rule left must lose its manifest, or fast mode keeps
    # running the rules it used to map.
    for stale in manifest_dir.glob("CWE-*.toml"):
        if stale.stem not in cwe_to_rules and \
                "CWE-focused manifest for" in stale.read_text():
            stale.unlink()

    count = 0
    for cwe_id, rules in sorted(cwe_to_rules.items()):
        lines = [
            f'[metadata]',
            f'name = "CWE-focused manifest for {cwe_id}"',
            f'version = "1.0.0"',
            f'cert_version = "2016"',
            f'',
        ]
        for rule in sorted(rules):
            lines.append(f'[rules.cert_c."{rule}"]')
            lines.append(f'enabled = true')
            lines.append(f'')

        manifest_path = manifest_dir / f"{cwe_id}.toml"
        manifest_path.write_text("\n".join(lines))
        count += 1

    return count


def main():
    project_dir = Path(__file__).resolve().parent.parent
    output_path = project_dir / "data" / "rule_cwe_map.json"

    mapping = generate_map(project_dir)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(mapping, f, indent=2)

    stats = mapping["stats"]
    print(
        f"Generated {output_path}: "
        f"{stats['toml_count']} TOMLs, "
        f"{stats['rules_with_cwe']} rules with CWE mappings, "
        f"{stats['unique_cwes']} unique CWEs"
    )

    # Generate per-CWE manifests for fast benchmark mode
    manifest_count = generate_cwe_manifests(
        project_dir, mapping["cwe_to_rules"]
    )
    print(f"Generated {manifest_count} per-CWE manifests in rules_templates/cwe/")


if __name__ == "__main__":
    main()
