"""aurora-lint's SARIF export validates against the SARIF 2.1.0 schema.

The schema is the OASIS one, vendored unmodified under tests/schemas/ (see
the README there). Validating needs the third-party `jsonschema` package and
a built aurora-lint, so without either the test skips and says which. CI
sets AURORA_LINT_REQUIRE_SCHEMA_CHECK=1 after `cargo test`, which turns a
skip into a failure there, so the check cannot silently stop running.

    AURORA_LINT_BIN=target/debug/aurora-lint \\
        python3 -m unittest scripts/test_sarif_schema.py -v
"""

import collections
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "tests" / "schemas" / "sarif-schema-2.1.0.json"
REQUIRED = os.environ.get("AURORA_LINT_REQUIRE_SCHEMA_CHECK") == "1"

# Each scan is (what it covers, the arguments before -e). Together they give
# results with suggestions, rules that report no column, suppressed findings,
# and the rules a configuration disables and a policy declines.
SCANS = [
    ("suggestions", ["src/rules/cert_c/MSC/MSC04-C/tests"]),
    ("no column (DCL05-C)", ["src/rules/cert_c/DCL/DCL05-C/tests"]),
    ("no column (CON43-C)", ["src/rules/cert_c/CONC/CON03-C/tests"]),
    ("no column (CON32-C)", ["src/rules/cert_c/CONC/CON32-C/tests"]),
    ("no column (FIO13-C)", ["src/rules/cert_c/FIO/FIO13-C/tests"]),
    ("suppressions", ["tests/fixtures/cli/suppressed_inline.c"]),
    (
        "declined and disabled rules",
        [
            "tests/fixtures/cli/violation.c",
            "--profile", "pedantic", "--libc", "glibc", "--data-model", "lp64",
        ],
    ),
]


def _binary():
    """The aurora-lint to scan with: $AURORA_LINT_BIN, else a built one."""
    given = os.environ.get("AURORA_LINT_BIN")
    if given:
        return Path(given)
    for profile in ("release", "debug"):
        candidate = ROOT / "target" / profile / "aurora-lint"
        if candidate.exists():
            return candidate
    return None


class SarifSchemaTests(unittest.TestCase):
    def setUp(self):
        missing = None
        if jsonschema is None:
            missing = "jsonschema is not installed (pip install jsonschema)"
        elif _binary() is None or not _binary().exists():
            missing = "no aurora-lint binary: build one or set AURORA_LINT_BIN"
        if missing:
            if REQUIRED:
                self.fail(missing)
            self.skipTest(missing)
        with open(SCHEMA, encoding="utf-8") as f:
            self.validator = jsonschema.Draft4Validator(json.load(f))

    def test_every_scan_s_sarif_validates(self):
        with tempfile.TemporaryDirectory() as tmp:
            for what, args in SCANS:
                with self.subTest(what):
                    for path in args[:1]:
                        self.assertTrue((ROOT / path).exists(), path)
                    out = Path(tmp) / "out.sarif"
                    scan = subprocess.run(
                        [str(_binary()), *args, "-e", str(out)],
                        cwd=ROOT, capture_output=True, text=True)
                    self.assertTrue(out.exists(), scan.stderr)
                    with open(out, encoding="utf-8") as f:
                        log = json.load(f)
                    self.assertTrue(log["runs"][0]["results"], f"{what}: no results")
                    errors = collections.Counter(
                        "/".join(str(p) for p in e.absolute_path if not isinstance(p, int))
                        + ": " + e.message[:120]
                        for e in self.validator.iter_errors(log))
                    self.assertEqual(errors, collections.Counter(), what)


if __name__ == "__main__":
    unittest.main()
