#!/usr/bin/env python3
"""Synthesize a compile_commands.json for the Juliet test suite.

Juliet ships as a flat pile of independent .c files under testcases/CWE*/
(optionally split into s01/s02/... subdirs for large CWEs) plus a shared
testcasesupport/ directory of helper .c/.h files -- there is no per-CWE
Makefile in the tree aurora-lint's benchmark harness downloads (see
docs/benchmark-setup.rst, "Juliet Test Suite Setup"), so there is nothing to
`bear -- make` against. Each file is meant to be compiled on its own, so this
walks the corpus and emits one entry per .c file instead of driving a real
build.

Flags mirror exactly what bench/runner.py already passes to aurora-lint for every
Juliet scan (`-d <cwe_dir> -d testcasesupport`, no OMITGOOD/OMITBAD/
INCLUDEMAIN defines) so the synthesized compile DB doesn't imply a different
view of the source than aurora-lint's own invocation: just `-I testcasesupport`,
no macro predefinitions. The fidelity gain over aurora-lint's current directory-based
resolution is system header / target-ABI info a real `cc` invocation carries
(and any new aurora-lint feature that consumes compile_commands.json can use), not a
different set of active preprocessor branches.

Usage:
    python3 scripts/generate_juliet_compile_commands.py
    python3 scripts/generate_juliet_compile_commands.py --juliet-base /path/to/testcases

Writes <juliet-test-suite-c>/compile_commands.json (sibling of testcases/ and
testcasesupport/). Safe to re-run -- it only reads the corpus and overwrites
its own output file.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bench.config import JULIET_BASE  # noqa: E402


def build_entries(juliet_base: Path, testcasesupport: Path) -> list[dict]:
    entries = []
    compiler = "cc"

    for c_file in sorted(testcasesupport.glob("*.c")):
        entries.append({
            "directory": str(testcasesupport),
            "arguments": [compiler, "-c", f"-I{testcasesupport}", c_file.name],
            "file": str(c_file),
        })

    for cwe_dir in sorted(d for d in juliet_base.iterdir() if d.is_dir()):
        for c_file in sorted(cwe_dir.rglob("*.c")):
            entries.append({
                "directory": str(c_file.parent),
                "arguments": [
                    compiler, "-c", f"-I{testcasesupport}", c_file.name,
                ],
                "file": str(c_file),
            })

    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--juliet-base", type=Path, default=JULIET_BASE,
        help="Path to juliet-test-suite-c/testcases (default: bench/config.py's JULIET_BASE)",
    )
    args = parser.parse_args()

    juliet_base: Path = args.juliet_base
    testcasesupport = juliet_base.parent / "testcasesupport"

    if not juliet_base.is_dir():
        print(f"error: {juliet_base} not found -- is the Juliet suite downloaded? "
              f"See docs/benchmark-setup.rst.", file=sys.stderr)
        return 1
    if not testcasesupport.is_dir():
        print(f"error: {testcasesupport} not found", file=sys.stderr)
        return 1

    entries = build_entries(juliet_base, testcasesupport)
    out_path = juliet_base.parent / "compile_commands.json"
    out_path.write_text(json.dumps(entries, indent=2) + "\n")
    print(f"wrote {len(entries)} entries to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
