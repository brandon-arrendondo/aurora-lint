"""The rule <-> CWE map that decides Juliet CWE-matched scoring.

A rule TOML carries two CWE lists (ADR-0013 Decision 3):
- `cwe`: CWEs whose Juliet test cases exercise what the rule checks. Only
  these count a rule's Juliet findings as CWE-matched, and only these pick
  the rules a fast-mode per-CWE manifest runs.
- `related_cwe`: what the guideline's CERT page or cwe.mitre.org relates to
  it, unverified. Informational.
"""

import importlib.util
import json
import os
import tempfile
import tomllib
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
JULIET = Path(os.path.expanduser("~/toolchain/benchmarks/juliet-test-suite-c/testcases"))


def _load(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _load("generate_rule_cwe_map")


def _rule_toml(rule_id, cwe=(), related=()):
    lines = ["[metadata]", f'id = "{rule_id}"', "",
             f"[rules.cert_c.{rule_id}]", "enabled = true", "", "[references]",
             "cwe = [" + ", ".join(f'"{c}"' for c in cwe) + "]"]
    if related:
        lines.append("related_cwe = [" + ", ".join(f'"{c}"' for c in related) + "]")
    return "\n".join(lines) + "\n"


class TestGenerateMap(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.rules = self.root / "src" / "rules" / "cert_c" / "STR"
        self.rules.mkdir(parents=True)

    def _write(self, rule_id, **kw):
        d = self.rules / rule_id
        d.mkdir()
        (d / f"{rule_id}.toml").write_text(_rule_toml(rule_id, **kw))

    def test_only_cwe_drives_scoring(self):
        self._write("STR31-C", cwe=["CWE-121"], related=["CWE-119"])
        m = gen.generate_map(self.root)
        self.assertEqual(m["rule_to_cwes"], {"STR31-C": ["CWE-121"]})
        self.assertEqual(m["cwe_to_rules"], {"CWE-121": ["STR31-C"]})
        self.assertEqual(m["rule_to_related_cwes"], {"STR31-C": ["CWE-119"]})

    def test_a_cwe_in_both_lists_is_refused(self):
        self._write("STR31-C", cwe=["CWE-121"], related=["CWE-121"])
        with self.assertRaises(SystemExit):
            gen.generate_map(self.root)

    def test_a_cwe_that_loses_its_rules_loses_its_manifest(self):
        manifests = self.root / "rules_templates" / "cwe"
        gen.generate_cwe_manifests(self.root, {"CWE-121": ["STR31-C"], "CWE-89": ["STR02-C"]})
        gen.generate_cwe_manifests(self.root, {"CWE-121": ["STR31-C"]})
        self.assertEqual(sorted(p.name for p in manifests.glob("*.toml")), ["CWE-121.toml"])


class TestScrapeNeverWritesCwe(unittest.TestCase):
    """A CERT page's CWE list is not Juliet evidence, so a re-scrape must put
    it in related_cwe and leave the verified list alone."""

    def test_page_cwes_go_to_related(self):
        scrape = _load("scrape_cert_wiki")
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "STR31-C.toml"
            out.write_text(_rule_toml("STR31-C", cwe=["CWE-121"], related=["CWE-119"]))
            item = scrape.ItemMetadata(
                id="STR31-C", item_type="rule", category="STR", number=31,
                title="t", cwe=["CWE-119", "CWE-121", "CWE-120"])
            scrape.generate_toml_metadata(item, out, force=True)
            refs = tomllib.loads(out.read_text())["references"]
        self.assertEqual(refs["cwe"], ["CWE-121"])
        self.assertEqual(refs["related_cwe"], ["CWE-119", "CWE-120"])


@unittest.skipUnless(JULIET.is_dir(), "Juliet test suite not checked out")
class TestCweEntriesAreJulietCwes(unittest.TestCase):
    """`cwe` means verified against Juliet's C test cases, so every entry must
    name a Juliet CWE directory that has C files."""

    def test_every_cwe_entry_has_c_test_cases(self):
        with_c = set()
        for d in JULIET.iterdir():
            if d.is_dir() and any(d.rglob("*.c")):
                with_c.add("CWE-" + d.name.split("_")[0][3:])
        bad = []
        for toml_path in sorted((REPO / "src" / "rules" / "cert_c").rglob("*-C.toml")):
            refs = tomllib.loads(toml_path.read_text()).get("references", {})
            bad += [f"{toml_path.stem}: {c}" for c in refs.get("cwe", []) if c not in with_c]
        self.assertEqual(bad, [])

    def test_generated_map_is_current(self):
        stored = json.loads((REPO / "data" / "rule_cwe_map.json").read_text())
        self.assertEqual(stored, json.loads(json.dumps(gen.generate_map(REPO))))


if __name__ == "__main__":
    unittest.main()
