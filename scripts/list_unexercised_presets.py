#!/usr/bin/env python3
"""Rules whose presets read them differently but whose fixtures never say how.

build.rs prints only a count of these. A rule whose `[presets]` block differs
(default narrows or widens, or pedantic goes beyond strict) should have a
fixture whose `Expect:` header names the preset that differs; this lists the
rules that have fixtures and none with a header.
"""
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    missing = []
    for toml in sorted(ROOT.glob("src/rules/cert_c/*/*/*.toml")):
        block = tomllib.loads(toml.read_text()).get("presets")
        if not block or not block.get("differs") or block.get("code_lags"):
            continue
        fixtures = [f for kind in ("fail", "pass", "expected_fail")
                    for f in (toml.parent / "tests" / kind).glob("*.c")]
        if fixtures and not any(re.search(r"^\s*(?://|/?\*)\s*Expect:", f.read_text(), re.M)
                                for f in fixtures):
            missing.append(toml.stem)
    print("\n".join(missing))
    print(f"{len(missing)} rule(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
