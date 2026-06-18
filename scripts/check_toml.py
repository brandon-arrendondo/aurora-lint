#!/usr/bin/env python3
"""Validate TOML syntax for the files given on the command line.

Used as a local pre-commit hook (see .pre-commit-config.yaml). build.rs already
performs deep schema validation of the individual rule manifests under
src/rules/**, but that only runs when the crate is compiled and only covers
those files. This is a cheap, dependency-free syntax safety net for *every*
TOML in the repo — benchmark manifests (rules_templates/, rules_templates/cwe/),
real-world configs (conf/realworld/), Cargo.toml, about.toml, etc.

With no arguments it scans every tracked-looking *.toml (excluding target/),
which is handy for a manual sweep.

Requires Python 3.11+ (stdlib `tomllib`).
"""
import sys
import glob
import tomllib


def iter_default_files():
    for path in glob.glob("**/*.toml", recursive=True):
        if path.startswith("target/") or "/target/" in path:
            continue
        yield path


def main(argv: list[str]) -> int:
    files = argv[1:] or list(iter_default_files())
    failures = 0
    for path in files:
        try:
            with open(path, "rb") as fh:
                tomllib.load(fh)
        except FileNotFoundError:
            # A staged deletion can still be passed in; ignore missing files.
            continue
        except tomllib.TOMLDecodeError as exc:
            failures += 1
            print(f"{path}: invalid TOML: {exc}", file=sys.stderr)
    if failures:
        print(
            f"\n{failures} TOML file(s) failed to parse. Fix the syntax above.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
