#!/usr/bin/env python3
"""One-off converter: the reviewed per-rule x per-preset table (a TSV) and the
public rulings into the `[presets]` block each rule's TOML carries (schema and
validation: build/presets.rs). Run once, review the diff, commit the blocks.

    python3 scripts/gen_preset_blocks.py PRESET_TABLE.tsv RULINGS_RULES_DIR [--check]

PRESET_TABLE.tsv is the reviewed table (private: its source column names task
and ledger ids, so it is never committed). RULINGS_RULES_DIR is `rules/` of
the public rulings (benchmark_adjudication, `rulings/rules/<RULE>.md`). The
public ruling wins where the two disagree: its "Differs by preset" line is the
block's `basis`, names the rulings (`ruling`), and fixes whether and where the
presets differ (PUBLIC_CELLS carries the cells read off it). The table
supplies the cells elsewhere and the rules no preset enforces. A block already
present is replaced, so re-running is safe.
"""
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CELLS = {
    "as written": "as_written",
    "narrowed": "narrowed",
    "widened": "widened",
    "stricter": "stricter",
    "not enforced": "not_enforced",
}
# Options a rule reads directly (tied to the code by a settings test).
OPTIONS_READ = {
    "EXP34-C": ["assert_is_guard", "first_site_only"],
    "ARR38-C": ["assert_is_guard"],
    "FLP36-C": ["assert_is_guard"],
}
# Where the public "Differs by preset" line says the presets differ and the
# reviewed table does not (or says it differently), the cells it implies, read
# off the line by hand: `narrowed` where default withholds or credits,
# `widened` where it adds, `stricter` for pedantic's closed readings beyond
# strict, `not_enforced` where a preset declines the rule. Strict is always
# the rule as written.
PUBLIC_CELLS = {
    "ENV32-C": ("narrowed", "stricter"),
    "ERR30-C": ("narrowed", "stricter"),
    "EXP15-C": ("narrowed", "as_written"),
    "EXP19-C": ("narrowed", "as_written"),
    "EXP20-C": ("narrowed", "as_written"),
    "EXP33-C": ("narrowed", "stricter"),
    "EXP42-C": ("narrowed", "stricter"),
    "FIO01-C": ("as_written", "stricter"),
    "FIO08-C": ("narrowed", "as_written"),
    "FIO14-C": ("narrowed", "as_written"),
    "FIO19-C": ("narrowed", "as_written"),
    "FIO20-C": ("narrowed", "as_written"),
    "FIO30-C": ("widened", "not_enforced"),
    "FIO34-C": ("narrowed", "as_written"),
    "FIO37-C": ("as_written", "stricter"),
    "FIO45-C": ("narrowed", "stricter"),
    "FLP32-C": ("narrowed", "stricter"),
    "INT04-C": ("narrowed", "stricter"),
    "INT07-C": ("narrowed", "as_written"),
    "INT18-C": ("narrowed", "as_written"),
    "MEM05-C": ("as_written", "stricter"),
    "MSC06-C": ("narrowed", "stricter"),
    "MSC17-C": ("narrowed", "stricter"),
    "MSC24-C": ("narrowed", "stricter"),
    "MSC32-C": ("as_written", "stricter"),
    "POS30-C": ("narrowed", "stricter"),
    "POS34-C": ("narrowed", "as_written"),
    "POS39-C": ("narrowed", "stricter"),
    "POS54-C": ("narrowed", "not_enforced"),
    "PRE01-C": ("narrowed", "as_written"),
    "PRE02-C": ("narrowed", "as_written"),
    "PRE09-C": ("widened", "stricter"),
    "PRE10-C": ("as_written", "stricter"),
    "SIG30-C": ("narrowed", "stricter"),
    "SIG31-C": ("narrowed", "as_written"),
    "STR32-C": ("narrowed", "stricter"),
    "WIN00-C": ("as_written", "stricter"),
    "WIN01-C": ("narrowed", "as_written"),
    "WIN02-C": ("narrowed", "stricter"),
    # Pending in the reviewed table, ruled since (2026-10-09).
    "INT32-C": ("narrowed", "stricter"),
    "POS36-C": ("as_written", "stricter"),
    "POS37-C": ("narrowed", "stricter"),
    # The public rulings read these as one form in every preset; the shipped
    # code still differs (a strippable assert guards under default only).
    "ARR38-C": ("as_written", "as_written"),
    "FLP36-C": ("as_written", "as_written"),
}
# Rules whose fixtures or code still implement a difference the public ruling
# removed: a `code_lags` note, until the rule is rewritten to the ruling.
CODE_LAGS = {
    "ARR38-C": "A strippable assert still guards under default only (assert_is_guard); the ruling reads one form in every preset.",
    "FLP36-C": "A strippable assert still guards under default only (assert_is_guard); the ruling reads one form in every preset.",
}
# Ruling and task references are private: the TOMLs ship.
PRIVATE = [
    re.compile(r"\s*\((?:aurora_lint |task )?\d{4}\)"),
    re.compile(r"\b(?:aurora_lint|task|tasks) #?\d{3,4}\b"),
    re.compile(r"\bP\d{2,3}\b"),
    re.compile(r"\bQ\d{1,2}\b"),
]
RULING_ID = re.compile(r"\b[A-Z]{3}\d{2}-C/\d{4}-\d{2}-\d{2}/[A-Za-z0-9_-]+|\bP/[a-z][a-z0-9-]*")
DIFFERS = re.compile(r"\*\*Differs by preset:\*\*\s*(.*?)(?:\n- \*\*|\n\n)", re.S)


def scrub(text: str) -> str:
    for rx in PRIVATE:
        text = rx.sub("", text)
    text = re.sub(r"\s+([,;.)])", r"\1", text)
    text = re.sub(r"\(\s*\)", "", text)
    return re.sub(r"\s{2,}", " ", text).strip(" ;,")


def option_names() -> list[str]:
    src = (ROOT / "src/settings/mod.rs").read_text()
    start = src.index("pub static OPTIONS")
    end = src.index("pub static DECLINED_RULES")
    return re.findall(r'^\s+name: "([a-z0-9_]+)",', src[start:end], re.M)


def q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    check = "--check" in sys.argv
    if len(args) != 2:
        print(__doc__)
        return 2
    options = option_names()
    rows = {}
    with open(args[0], newline="") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            rows[r["rule"]] = r
    rulings = Path(args[1])
    changed = 0
    for path in sorted(ROOT.glob("src/rules/cert_c/*/*/*.toml")):
        rule = path.stem
        row = rows.get(rule)
        if row is None:
            print(f"no table row for {rule}", file=sys.stderr)
            return 1
        m = DIFFERS.search((rulings / f"{rule}.md").read_text())
        if m is None:
            print(f"no 'Differs by preset' line in the public ruling for {rule}", file=sys.stderr)
            return 1
        public = " ".join(m.group(1).split())

        table = {}
        for p in ("default", "strict", "pedantic"):
            v = row[p].strip()
            table[p] = None if v == "pending" else CELLS[row["strict"].strip() if v == "OPEN" else v]
        if None in table.values() and rule not in PUBLIC_CELLS:
            print(f"{rule} is pending in the table and has no public cells", file=sys.stderr)
            return 1
        all_off = table["strict"] == "not_enforced" and set(table.values()) == {"not_enforced"}
        if all_off:
            cells = table
        elif rule in PUBLIC_CELLS:
            d, ped = PUBLIC_CELLS[rule]
            cells = {"default": d, "strict": "as_written", "pedantic": ped}
        else:
            cells = dict(table)
            if cells["strict"] == "stricter":
                cells["strict"] = "as_written"
            if public.lower().startswith("no") and len(set(cells.values())) > 1:
                print(f"{rule}: the public ruling reads one form, the table says {cells}", file=sys.stderr)
                return 1

        used = [o for o in options if re.search(rf"\b{o}\b", public) or re.search(rf"\b{o}\b", row["basis"])]
        used += [o for o in OPTIONS_READ.get(rule, []) if o not in used]
        ids = list(dict.fromkeys(RULING_ID.findall(public)))
        lines = ["[presets]"]
        for p in ("default", "strict", "pedantic"):
            lines.append(f"{p} = {q(cells[p])}")
        lines.append(f"differs = {str(len(set(cells.values())) > 1).lower()}")
        if row["overlap_owner"].strip():
            lines.append(f"overlap = {q(scrub(row['overlap_owner']))}")
        if used:
            lines.append("options = [" + ", ".join(q(o) for o in used) + "]")
        lines.append(f"basis = {q(public)}")
        if ids:
            lines.append("ruling = " + q(", ".join(ids)))
        if rule in CODE_LAGS:
            lines.append(f"code_lags = {q(CODE_LAGS[rule])}")
        block = "\n".join(lines) + "\n"
        text = path.read_text()
        head = re.split(r"\n\[presets\]\n", text)[0].rstrip("\n") + "\n"
        new = head + "\n" + block
        if new != text:
            changed += 1
            if not check:
                path.write_text(new)
    print(f"{changed} rule file(s) {'would change' if check else 'rewritten'}")
    return 1 if check and changed else 0


if __name__ == "__main__":
    sys.exit(main())
