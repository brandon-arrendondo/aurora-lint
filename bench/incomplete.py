"""Read an incomplete scan's failures out of aurora-lint's output.

aurora-lint exits 3 when a scan completed but some unit of work did not: a
rule crashed or ran out of its step or time budget on a file, a file's
analysis or prescan did, or a rule failed on enough files to be abandoned
(ADR-0017, docs/error-handling.rst). Each is one stderr line in a stable
format, which this module parses so a benchmark run can say what was
missing instead of a bare FAILED.

An incomplete scan is never scored: its precision and recall would treat a
rule that crashed as a rule that chose not to report.
"""

import re

EXIT_INCOMPLETE = 3

_FAILURE = re.compile(
    r"^Error: (?P<stage>rule|file|prescan) failure \((?P<cause>[^)]*)\): "
    r"(?:(?P<rule>[A-Z][A-Z0-9]*\d\d-[A-Z]+): )?(?P<file>.+?): (?P<message>.*?)"
    r"(?: \[at (?P<location>[^\]]+)\])?$"
)
_ABANDONED = re.compile(r"^Error: rule abandoned: (?P<rule>\S+):")
_SKIPPED = re.compile(r"^Error: input skipped \((?P<cause>[^)]*)\): (?P<file>.+?): (?P<message>.*)$")


def parse_failures(text: str) -> list[dict]:
    """Every failure and abandoned rule `text` (a scan's stderr or log)
    reports, in order: dicts with `stage` (rule/file/prescan/abandoned),
    `cause`, `rule`, `file`, `message`, `location`. Stage `input` is a file
    skipped before parsing (too large, or not source text)."""
    out = []
    for line in text.splitlines():
        m = _FAILURE.match(line)
        if m:
            d = m.groupdict()
            if d["stage"] != "rule":
                d["rule"] = None
            out.append(d)
            continue
        m = _SKIPPED.match(line)
        if m:
            out.append({"stage": "input", "cause": m["cause"], "rule": None,
                        "file": m["file"], "message": m["message"], "location": None})
            continue
        m = _ABANDONED.match(line)
        if m:
            out.append({"stage": "abandoned", "cause": None, "rule": m["rule"],
                        "file": None, "message": None, "location": None})
    return out


def summary(failures: list[dict]) -> str:
    """One line for a run log: `INCOMPLETE: 3 failure(s) (rules MEM35-C)`."""
    rules = sorted({f["rule"] for f in failures if f["rule"]})
    n = sum(1 for f in failures if f["stage"] != "abandoned")
    text = f"INCOMPLETE: {n} failure(s)"
    if rules:
        text += f" (rule{'s' if len(rules) > 1 else ''} {', '.join(rules)})"
    abandoned = [f["rule"] for f in failures if f["stage"] == "abandoned"]
    if abandoned:
        text += f", abandoned: {', '.join(abandoned)}"
    return text
