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
    # Pedantic's loud declines alone are not "stricter": it flags nothing more.
    "WIN02-C": ("narrowed", "as_written"),
    "ERR33-C": ("narrowed", "not_enforced"),
    "MEM35-C": ("narrowed", "as_written"),
    "MSC20-C": ("narrowed", "as_written"),
    "MSC41-C": ("as_written", "stricter"),
    "POS01-C": ("narrowed", "stricter"),
    # The 2026-10-08 POSIX pattern: default assumes POSIX and applies the
    # exception; strict and pedantic apply it only under declared POSIX.
    "CON37-C": ("narrowed", "as_written"),
    "FIO24-C": ("narrowed", "as_written"),
    "MSC05-C": ("narrowed", "as_written"),
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
# Open families (a list in the rule's text that default infers beyond): the
# set default infers, documented.
OPEN_FAMILY = {
    "FIO30-C": "Strict's members plus format-attributed declarations, variadic or va_list forwarders, wrapper macros, and platform members on a declared platform or library (vsyslog, the <err.h> family, GNU error, the Windows _snprintf family, the Curses printw family), resolved by declaration.",
    "ERR33-C": "CERT's table plus fgetws and the C23 functions the declared c_standard has.",
    "POS39-C": "Byte swaps under a host-order test, target variants (ntohll/htonll, pre-Issue-8 be32toh) and declared project helpers, beyond the enumerated ntohl, ntohs, htonl, htons and the <endian.h> functions under a declared Issue 8.",
}
# Rulings a block cites beyond those its "Differs by preset" line names.
EXTRA_RULINGS = {
    "FLP36-C": ["FLP36-C/2026-10-07/presets"],
}
# Ruling and task references are private: the TOMLs ship.
PRIVATE = [
    re.compile(r"\s*\(ledger[^)]*\)"),
    re.compile(r"\s*\((?:aurora_lint |task )?\d{4}\)"),
    re.compile(r"\b(?:aurora_lint|task|tasks) #?\d{3,4}\b"),
    re.compile(r"\bP\d{2,3}\b"),
    re.compile(r"\bQ\d{1,2}\b"),
]
RULING_TOKEN = re.compile(
    r"\b(?P<rule>[A-Z]{3}\d{2}-C)/(?P<date>\d{4}-\d{2}-\d{2})/(?P<item>[A-Za-z0-9_-]+)"
    r"|\bP/(?P<principle>[a-z][a-z0-9-]*)"
    r"|(?<![A-Za-z0-9_.-])/(?P<short>\d+(?:-\d+)?|presets|options|library|disposition|ex\d)\b"
)


def ruling_ids(text: str) -> list[str]:
    """Every public ruling id the text names, a short form (`/6`) taking the
    rule and date of the full id before it."""
    out, base = [], None
    for m in RULING_TOKEN.finditer(text):
        if m["rule"]:
            base = f"{m['rule']}/{m['date']}"
            out.append(f"{base}/{m['item']}")
        elif m["principle"]:
            out.append(f"P/{m['principle']}")
        elif base:
            out.append(f"{base}/{m['short']}")
    return list(dict.fromkeys(out))
DIFFERS = re.compile(r"\*\*Differs by preset:\*\*\s*(.*?)(?:\n- \*\*|\n\n)", re.S)


def shape_problems(cells: dict, public: str) -> list[str]:
    """Where the cells disagree with the shape of the public line: "at default
    only", "at pedantic only", "Pedantic equals strict", "Default equals
    strict", "pedantic declines the rule", "in all three"."""
    low = public.lower()
    d, s_, p = cells["default"], cells["strict"], cells["pedantic"]
    out = []

    def need(ok: bool, what: str) -> None:
        if not ok:
            out.append(what)

    if re.search(r"pedantic declines the rule", low):
        need(p == "not_enforced", "pedantic declines the rule, but the cell is not not_enforced")
    if re.search(r"yes, at default", low) or low.startswith("only through the named options"):
        need(d != s_, "differs at default, but default equals strict")
        need(p == s_, "differs at default only, but pedantic differs from strict")
    if re.search(r"yes, at pedantic", low):
        need(p != s_, "differs at pedantic, but pedantic equals strict")
        need(d == s_, "differs at pedantic only, but default differs from strict")
    if re.search(r"pedantic equals strict(?! (apart|except))|strict and pedantic coincide|pedantic reports what strict reports", low):
        need(p == s_, "pedantic equals strict, but the cells differ")
    if re.search(r"default equals strict|default and strict coincide", low):
        need(d == s_, "default equals strict, but the cells differ")
    if re.search(r"yes, in all three|yes, in every column", low):
        need(d != s_ and p != s_, "differs in all three, but a preset equals strict")
    return out


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
    shape_failures = 0
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

        if not all_off:
            for problem in shape_problems(cells, public):
                print(f"{rule}: {problem}  [{cells['default']}/{cells['strict']}/{cells['pedantic']}]", file=sys.stderr)
                shape_failures += 1
        used = [o for o in options if re.search(rf"\b{o}\b", public) or re.search(rf"\b{o}\b", row["basis"])]
        used += [o for o in OPTIONS_READ.get(rule, []) if o not in used]
        ids = ruling_ids(public)
        if all_off:
            # A decided cut cites its disposition (and removal) ruling.
            body = (rulings / f"{rule}.md").read_text()
            ids += [i for i in re.findall(rf"\b{rule}/\d{{4}}-\d{{2}}-\d{{2}}/(?:disposition|removal)\b", body)
                    if i not in ids]
        ids += [i for i in EXTRA_RULINGS.get(rule, []) if i not in ids]
        lines = ["[presets]"]
        for p in ("default", "strict", "pedantic"):
            lines.append(f"{p} = {q(cells[p])}")
        lines.append(f"differs = {str(len(set(cells.values())) > 1).lower()}")
        if row["overlap_owner"].strip():
            lines.append(f"overlap = {q(scrub(row['overlap_owner']))}")
        if used:
            lines.append("options = [" + ", ".join(q(o) for o in used) + "]")
        if rule in OPEN_FAMILY:
            lines.append("open_family = true")
            lines.append(f"inferred = {q(OPEN_FAMILY[rule])}")
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
    if shape_failures:
        print(f"{shape_failures} disagreement(s) between the cells and the public lines", file=sys.stderr)
        return 1
    print(f"{changed} rule file(s) {'would change' if check else 'rewritten'}")
    return 1 if check and changed else 0


if __name__ == "__main__":
    sys.exit(main())
