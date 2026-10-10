//! The per-rule x per-preset table: the `[presets]` block each rule's TOML
//! carries (ADR-0015, 2026-10-07 amendment and the rulings after it).
//!
//! This file is compiled twice: by `build.rs`, which validates every block
//! and generates `rules_templates/rule-presets.json` from them, and, under
//! `cfg(test)`, into the library (`src/lib.rs`) so the validation has unit
//! tests. It therefore uses only `serde`, `toml` and `anyhow`.
//!
//! ```toml
//! [presets]
//! default  = "narrowed"      # as_written | narrowed | widened | stricter | not_enforced
//! strict   = "as_written"
//! pedantic = "as_written"
//! differs  = true            # derived; checked, never trusted
//! overlap  = "prose"         # who owns which construct, and what co-fires
//! options  = ["assert_is_guard"]   # settings::OPTIONS names behind a departure
//! basis    = "one or two sentences naming the reading"
//! ```
//!
//! Optional: `owner`, `cofires` (rule ids), `open_family` + `inferred` (the
//! set a preset infers where the rule's text is an open family),
//! `complete_coverage`, `cert_page_version`, `ruling`.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

/// What one preset does with a rule, relative to the rule's text.
///
/// - `as_written`: the rule as CERT writes it. Strict is always this (or
///   `not_enforced`).
/// - `narrowed`: default reports less than strict, for a clear and common
///   idiom (a named option, an exemption).
/// - `widened`: default reports more than strict (a reading by the rule's
///   spirit, or an open family inferred wider; `inferred` says what).
/// - `stricter`: pedantic's closed reading beyond strict.
/// - `not_enforced`: the preset declines the rule, loudly, rather than guess;
///   the block's `basis` gives the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cell {
    /// The rule as CERT writes it.
    AsWritten,
    /// Fewer findings than the text gives, for a clear and common idiom.
    Narrowed,
    /// More findings than the text gives, for a clear and common idiom.
    Widened,
    /// A closed reading beyond the text.
    Stricter,
    /// The preset declines the rule: it abstains, loudly, rather than guess.
    NotEnforced,
}

impl Cell {
    /// The spelling in a rule's TOML and in the generated JSON.
    pub fn key(self) -> &'static str {
        match self {
            Cell::AsWritten => "as_written",
            Cell::Narrowed => "narrowed",
            Cell::Widened => "widened",
            Cell::Stricter => "stricter",
            Cell::NotEnforced => "not_enforced",
        }
    }

    /// Whether the cell departs from the text, and so must say how.
    fn departs(self) -> bool {
        matches!(self, Cell::Narrowed | Cell::Widened | Cell::Stricter)
    }
}

/// A rule's `[presets]` block.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub default: Cell,
    pub strict: Cell,
    pub pedantic: Cell,
    /// Derived: whether the three cells are not all equal.
    pub differs: Option<bool>,
    /// The rule that owns the construct this rule shares, if one does.
    pub owner: Option<String>,
    /// Rules allowed to fire on the same construct.
    #[serde(default)]
    pub cofires: Vec<String>,
    /// Free text on who owns what; co-firing is normal.
    pub overlap: Option<String>,
    /// Names from `settings::OPTIONS` behind each departure.
    #[serde(default)]
    pub options: Vec<String>,
    /// The text is an open family (an enumerated list its preset extends).
    #[serde(default)]
    pub open_family: bool,
    /// For an open family: the set `default` infers, documented.
    pub inferred: Option<String>,
    /// Another rule owns the construct *and* covers it completely in every
    /// preset and environment, which is what allows this rule to decline it.
    #[serde(default)]
    pub complete_coverage: bool,
    /// The CERT page version this table's reading was reviewed against.
    /// Reserved for the rule-text pin (ADR-0018); nothing reads it yet.
    #[allow(dead_code)]
    pub cert_page_version: Option<String>,
    pub basis: Option<String>,
    /// Public ruling ids, `<RULE>/<YYYY-MM-DD>/<item>` or `P/<name>`.
    pub ruling: Option<String>,
    /// The shipped code (or its fixtures) still implements a reading the
    /// ruling has since changed, until the rule is rewritten to it; the
    /// fixture checks skip the rule.
    pub code_lags: Option<String>,
}

impl Block {
    /// The three cells, in preset order.
    pub fn cells(&self) -> [Cell; 3] {
        [self.default, self.strict, self.pedantic]
    }

    /// Whether the presets do not all read the rule the same way.
    pub fn derived_differs(&self) -> bool {
        let [d, s, p] = self.cells();
        d != s || s != p
    }
}

/// Rules whose row is still pending a ruling: they carry no block yet.
pub const PENDING: &[&str] = &[];

/// Rules the table declines under every preset that the tree still ships
/// (`enabled = true`): decided cuts whose removal has not been made. Removing
/// a rule (ADR-0013 Decision 4) takes it out of this list in the same change;
/// a rule that is neither removed nor listed here may not decline everywhere,
/// and an entry here whose rule is no longer enabled and declined everywhere
/// is stale.
pub const DECLINED_BUT_STILL_SHIPPED: &[&str] = &[
    "API03-C", "API04-C", "API07-C", "API09-C", "API10-C", "ARR00-C", "CON03-C", "CON06-C",
    "CON09-C", "CON50-C", "DCL08-C", "DCL10-C", "DCL11-C", "DCL17-C", "DCL21-C", "DCL22-C",
    "ENV01-C", "ERR00-C", "ERR06-C", "EXP03-C", "EXP07-C", "EXP08-C", "EXP10-C", "EXP14-C",
    "FIO03-C", "FIO10-C", "FIO15-C", "FIO17-C", "FIO18-C", "FLP01-C", "FLP02-C", "FLP05-C",
    "INT00-C", "INT05-C", "INT08-C", "INT14-C", "INT16-C", "MEM00-C", "MEM07-C", "MEM10-C",
    "MEM11-C", "MEM12-C", "MSC07-C", "MSC14-C", "MSC15-C", "MSC23-C", "POS02-C", "PRE12-C",
    "PRE13-C", "STR00-C", "STR01-C", "STR03-C",
];

/// What validation needs to know about the rest of the tree.
pub struct Context<'a> {
    /// Every rule id that has a TOML.
    pub rules: &'a BTreeSet<String>,
    /// Every name in `settings::OPTIONS`.
    pub options: &'a BTreeSet<String>,
    /// Whether each rule is implemented (`enabled = true`).
    pub enabled: &'a BTreeMap<String, bool>,
}

/// The `[presets]` block of a rule's TOML, if it has one.
pub fn parse(content: &str) -> anyhow::Result<Option<Block>> {
    let value: toml::Value = toml::from_str(content)?;
    match value.get("presets") {
        None => Ok(None),
        Some(table) => Ok(Some(table.clone().try_into()?)),
    }
}

trait MapKeys {
    fn map_keys(&self) -> String;
}

impl MapKeys for [Cell] {
    fn map_keys(&self) -> String {
        self.iter().map(|c| c.key()).collect::<Vec<_>>().join(", ")
    }
}

/// Whether `id` is a public ruling id: `<RULE>/<YYYY-MM-DD>/<item>` or
/// `P/<name>` (benchmark_adjudication, rulings/README.md).
fn ruling_id(id: &str) -> bool {
    let item = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    };
    let parts: Vec<&str> = id.split('/').collect();
    match parts.as_slice() {
        ["P", name] => item(name),
        [rule, date, it] => {
            let d: Vec<&str> = date.split('-').collect();
            rule.ends_with("-C")
                && d.len() == 3
                && d[0].len() == 4
                && d[1].len() == 2
                && d[2].len() == 2
                && d.iter().all(|x| x.chars().all(|c| c.is_ascii_digit()))
                && item(it)
        }
        _ => false,
    }
}

/// Text that names a private task, ruling or ledger id. The TOMLs ship, so
/// none may carry one.
fn private_reference(text: &str) -> Option<String> {
    // A bare number in parentheses or after `#` is a task id by its shape:
    // `(2267)`, `#2267`.
    let bytes = text.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        let digits = |from: usize| {
            bytes[from..]
                .iter()
                .take_while(|c| c.is_ascii_digit())
                .count()
        };
        if *b == b'#' && (3..=5).contains(&digits(i + 1)) {
            return Some(text[i..i + 1 + digits(i + 1)].to_string());
        }
        if *b == b'(' {
            let n = digits(i + 1);
            if (3..=5).contains(&n) && bytes.get(i + 1 + n) == Some(&b')') {
                return Some(text[i..i + 2 + n].to_string());
            }
        }
    }
    let words: Vec<&str> = text
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .filter(|w| !w.is_empty())
        .collect();
    for (i, w) in words.iter().enumerate() {
        let digits = |s: &str| s.len() >= 3 && s.chars().all(|c| c.is_ascii_digit());
        let ledger =
            w.len() >= 2 && w.starts_with(['P', 'Q']) && w[1..].chars().all(|c| c.is_ascii_digit());
        let tasked = matches!(*w, "task" | "tasks" | "aurora_lint" | "bmdb")
            && words.get(i + 1).is_some_and(|n| digits(n));
        if ledger || tasked {
            return Some((*w).to_string());
        }
    }
    None
}

/// Everything wrong with `rule`'s block, one line each. Empty when sound.
pub fn problems(rule: &str, block: Option<&Block>, ctx: &Context) -> Vec<String> {
    let mut out = Vec::new();
    let Some(b) = block else {
        if !PENDING.contains(&rule) {
            out.push(format!("{rule}: no [presets] block"));
        }
        return out;
    };
    if PENDING.contains(&rule) {
        out.push(format!(
            "{rule}: has a [presets] block but is listed as pending a ruling (build/presets.rs PENDING)"
        ));
    }
    if let Some(declared) = b.differs {
        if declared != b.derived_differs() {
            out.push(format!(
                "{rule}: differs = {declared}, but the cells {} say {}",
                b.cells().map(Cell::key).join("/"),
                b.derived_differs()
            ));
        }
    }
    // Which cells a preset can hold: strict is the rule as written, default
    // may narrow or widen it, pedantic goes beyond it.
    let allowed = |cell: Cell, ok: &[Cell], preset: &str| {
        (!ok.contains(&cell)).then(|| {
            format!(
                "{rule}: {preset} cannot be {} (it may be {})",
                cell.key(),
                ok.map_keys()
            )
        })
    };
    use Cell::*;
    out.extend(allowed(
        b.default,
        &[AsWritten, Narrowed, Widened, NotEnforced],
        "default",
    ));
    out.extend(allowed(b.strict, &[AsWritten, NotEnforced], "strict"));
    out.extend(allowed(
        b.pedantic,
        &[AsWritten, Stricter, NotEnforced],
        "pedantic",
    ));
    if b.cells().contains(&NotEnforced) && b.basis.as_deref().is_none_or(|t| t.trim().is_empty()) {
        out.push(format!(
            "{rule}: a preset declines the rule, so `basis` must give the reason"
        ));
    }
    for id in b.ruling.iter().flat_map(|r| r.split(',')).map(str::trim) {
        if !ruling_id(id) {
            out.push(format!(
                "{rule}: ruling '{id}' is not a public id (<RULE>/<YYYY-MM-DD>/<item> or P/<name>)"
            ));
        }
    }
    let says = b.basis.as_deref().is_some_and(|t| !t.trim().is_empty()) || !b.options.is_empty();
    if b.cells().iter().any(|c| c.departs()) && !says {
        out.push(format!(
            "{rule}: a cell departs from the text but neither `basis` nor `options` names the reading"
        ));
    }
    if b.pedantic != b.strict && !says {
        out.push(format!(
            "{rule}: pedantic differs from strict without a named reading"
        ));
    }
    for name in &b.options {
        if !ctx.options.contains(name) {
            out.push(format!(
                "{rule}: option '{name}' is not in settings::OPTIONS"
            ));
        }
    }
    for id in b.owner.iter().chain(&b.cofires) {
        if !ctx.rules.contains(id) {
            out.push(format!("{rule}: '{id}' is not a rule"));
        }
    }
    if b.owner.as_deref() == Some(rule) {
        out.push(format!("{rule}: names itself as owner"));
    }
    // Co-firing is normal: an owner records who reports a construct, never a
    // cut. Declining a construct another rule owns needs that rule's complete
    // coverage in every preset and environment (cross-rule-overlap bar 2).
    if b.owner.is_some()
        && b.cells().contains(&Cell::NotEnforced)
        && b.cells() != [Cell::NotEnforced; 3]
        && !b.complete_coverage
    {
        out.push(format!(
            "{rule}: declines under some preset while another rule owns the construct, without complete_coverage = true"
        ));
    }
    if b.open_family
        && b.default != b.strict
        && b.inferred.as_deref().is_none_or(|t| t.trim().is_empty())
    {
        out.push(format!(
            "{rule}: an open family whose default reads differently must document `inferred`"
        ));
    }
    if b.inferred.is_some() && !b.open_family {
        out.push(format!("{rule}: `inferred` without `open_family = true`"));
    }
    // A rule every preset declines is not implemented; an implemented rule
    // is enforced by at least one preset.
    let all_off = b.cells() == [Cell::NotEnforced; 3];
    let shipped = ctx.enabled.get(rule) == Some(&true);
    let listed = DECLINED_BUT_STILL_SHIPPED.contains(&rule);
    if all_off && shipped && !listed {
        out.push(format!(
            "{rule}: enabled, but every preset declines it; remove the rule, or list it in DECLINED_BUT_STILL_SHIPPED until it is removed"
        ));
    }
    if listed && !(all_off && shipped) {
        out.push(format!(
            "{rule}: listed in DECLINED_BUT_STILL_SHIPPED but it is not enabled and declined by every preset; drop the entry"
        ));
    }
    for (what, text) in [
        ("basis", b.basis.as_deref()),
        ("overlap", b.overlap.as_deref()),
        ("ruling", b.ruling.as_deref()),
        ("inferred", b.inferred.as_deref()),
    ] {
        if let Some(word) = text.and_then(private_reference) {
            out.push(format!(
                "{rule}: `{what}` names a private task or ruling id ('{word}'); the TOMLs ship"
            ));
        }
    }
    out
}

/// `rules_templates/rule-presets.json`: every rule's cells, sorted, with a
/// stable layout so the committed file diffs cleanly.
pub fn to_json(table: &BTreeMap<String, Block>) -> String {
    let mut out = String::from("{\n  \"presets\": [\"default\", \"strict\", \"pedantic\"],\n");
    out.push_str("  \"cells\": [\"as_written\", \"narrowed\", \"widened\", \"stricter\", \"not_enforced\"],\n");
    out.push_str("  \"rules\": {\n");
    let last = table.len().saturating_sub(1);
    for (i, (rule, b)) in table.iter().enumerate() {
        out.push_str(&format!(
            "    \"{rule}\": {{\"default\": \"{}\", \"strict\": \"{}\", \"pedantic\": \"{}\", \"differs\": {}}}{}\n",
            b.default.key(),
            b.strict.key(),
            b.pedantic.key(),
            b.derived_differs(),
            if i == last { "" } else { "," }
        ));
    }
    out.push_str("  }\n}\n");
    out
}

/// `docs/rule-presets.rst`: the same table as a page, so the docs cannot
/// disagree with the metadata (ADR-0015 requires docs generated from the
/// option table; this is the per-rule half).
pub fn to_rst(table: &BTreeMap<String, Block>) -> String {
    let mut out = String::from(
        "..\n   Generated by build.rs from the [presets] block of each rule's TOML. Do not edit by\n   \
         hand: change the rule's TOML and rebuild.\n\n\
         Rule readings by preset\n=======================\n\n\
         How each preset reads each rule, relative to the rule's text. See\n\
         :doc:`configuration` for the presets and :doc:`options` for the named options\n\
         behind a departure.\n\n\
         - ``as_written``: the rule as CERT writes it. Strict is always this.\n\
         - ``narrowed``: default reports less than strict, for a clear and common idiom.\n\
         - ``widened``: default reports more than strict (a reading by the rule's spirit,\n  \
         or an open family inferred wider).\n\
         - ``stricter``: pedantic's closed reading beyond strict.\n\
         - ``not_enforced``: the preset declines the rule, loudly, rather than guess.\n\n\
         .. list-table::\n   :header-rows: 1\n   :widths: 10 12 12 12 24 30\n\n\
         \x20  * - Rule\n     - default\n     - strict\n     - pedantic\n     - Options\n     - Rulings\n",
    );
    for (rule, b) in table {
        let options = if b.options.is_empty() {
            String::new()
        } else {
            b.options
                .iter()
                .map(|o| format!("``{o}``"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!(
            "   * - {rule}\n     - {}\n     - {}\n     - {}\n     - {options}\n     - {}\n",
            b.default.key(),
            b.strict.key(),
            b.pedantic.key(),
            b.ruling.as_deref().unwrap_or("")
        ));
    }
    let lagging: Vec<(&String, &str)> = table
        .iter()
        .filter_map(|(r, b)| b.code_lags.as_deref().map(|l| (r, l)))
        .collect();
    if !lagging.is_empty() {
        out.push_str(
            "\nThe shipped code of these rules still differs from the ruling above, until the\n\
             rule is rewritten to it:\n\n",
        );
        for (rule, why) in lagging {
            out.push_str(&format!("- {rule}: {why}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(text: &str) -> Block {
        parse(text).unwrap().unwrap()
    }

    fn check(rule: &str, text: &str) -> Vec<String> {
        let rules: BTreeSet<String> = ["A-C", "B-C", "C-C"].map(String::from).into();
        let options: BTreeSet<String> = ["assert_is_guard"].map(String::from).into();
        let enabled: BTreeMap<String, bool> =
            [("A-C".to_string(), true), ("B-C".to_string(), false)].into();
        let ctx = Context {
            rules: &rules,
            options: &options,
            enabled: &enabled,
        };
        problems(rule, Some(&block(text)), &ctx)
    }

    #[test]
    fn a_sound_block_has_no_problems() {
        let text = "[presets]\ndefault = \"narrowed\"\nstrict = \"as_written\"\n\
                    pedantic = \"as_written\"\ndiffers = true\noptions = [\"assert_is_guard\"]\n";
        assert_eq!(check("A-C", text), Vec::<String>::new());
    }

    #[test]
    fn presets_may_all_coincide() {
        let text = "[presets]\ndefault = \"as_written\"\nstrict = \"as_written\"\n\
                    pedantic = \"as_written\"\ndiffers = false\n";
        assert!(check("A-C", text).is_empty());
        assert!(!block(text).derived_differs());
    }

    #[test]
    fn a_wrong_differs_is_caught() {
        let text = "[presets]\ndefault = \"widened\"\nstrict = \"as_written\"\n\
                    pedantic = \"as_written\"\ndiffers = false\nbasis = \"x\"\n";
        let p = check("A-C", text);
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].contains("differs = false"));
    }

    #[test]
    fn a_departure_must_name_its_reading() {
        let text = "[presets]\ndefault = \"as_written\"\nstrict = \"as_written\"\npedantic = \"stricter\"\n";
        let p = check("A-C", text);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(check("A-C", &format!("{text}basis = \"closed reading\"\n")).is_empty());
    }

    #[test]
    fn an_unknown_option_rule_or_field_is_refused() {
        let base = "[presets]\ndefault = \"as_written\"\nstrict = \"as_written\"\npedantic = \"as_written\"\n";
        assert!(check("A-C", &format!("{base}options = [\"nope\"]\n"))[0]
            .contains("not in settings::OPTIONS"));
        assert!(check("A-C", &format!("{base}owner = \"Z-C\"\n"))[0].contains("not a rule"));
        assert!(check("A-C", &format!("{base}owner = \"A-C\"\n"))[0].contains("itself"));
        assert!(parse(&format!("{base}typo = 1\n")).is_err());
        assert!(parse(
            "[presets]\ndefault = \"loose\"\nstrict = \"as_written\"\npedantic = \"as_written\"\n"
        )
        .is_err());
    }

    #[test]
    fn declining_what_another_rule_owns_needs_complete_coverage() {
        let text = "[presets]\ndefault = \"as_written\"\nstrict = \"as_written\"\n\
                    pedantic = \"not_enforced\"\nowner = \"B-C\"\nbasis = \"b owns it\"\n";
        let p = check("A-C", text);
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(p[0].contains("complete_coverage"));
        assert!(check("A-C", &format!("{text}complete_coverage = true\n")).is_empty());
        // Co-firing is a record, not a cut.
        let fires = "[presets]\ndefault = \"as_written\"\nstrict = \"as_written\"\n\
                     pedantic = \"as_written\"\nowner = \"B-C\"\ncofires = [\"C-C\"]\n";
        assert!(check("A-C", fires).is_empty());
    }

    #[test]
    fn an_open_family_documents_what_default_infers() {
        let text = "[presets]\ndefault = \"widened\"\nstrict = \"as_written\"\n\
                    pedantic = \"not_enforced\"\nopen_family = true\nbasis = \"x\"\n";
        let p = check("A-C", text);
        assert!(p.iter().any(|m| m.contains("inferred")), "{p:?}");
        let ok = format!("{text}inferred = \"macros that wrap free\"\n");
        assert!(check("A-C", &ok).is_empty());
        assert!(check("A-C", "[presets]\ndefault = \"as_written\"\nstrict = \"as_written\"\npedantic = \"as_written\"\ninferred = \"x\"\n")[0].contains("open_family"));
    }

    #[test]
    fn an_enabled_rule_is_enforced_by_some_preset() {
        let off = "[presets]\ndefault = \"not_enforced\"\nstrict = \"not_enforced\"\npedantic = \"not_enforced\"\nbasis = \"cut\"\n";
        assert!(check("A-C", off)[0].contains("every preset declines"));
        // A decline gives its reason.
        let bare = off.replace("basis = \"cut\"\n", "");
        assert!(check("B-C", &bare)[0].contains("must give the reason"));
        assert!(check("B-C", off).is_empty());
        // The decided cuts that still ship are listed, and each entry is live.
        assert_eq!(DECLINED_BUT_STILL_SHIPPED.len(), 52);
        let rules: BTreeSet<String> = ["API03-C", "ARR00-C"].map(String::from).into();
        let options = BTreeSet::new();
        let enabled: BTreeMap<String, bool> = [
            ("API03-C".to_string(), true),
            ("ARR00-C".to_string(), false),
        ]
        .into();
        let ctx = Context {
            rules: &rules,
            options: &options,
            enabled: &enabled,
        };
        let blk = block(off);
        assert!(problems("API03-C", Some(&blk), &ctx).is_empty());
        let stale = problems("ARR00-C", Some(&blk), &ctx);
        assert!(stale[0].contains("drop the entry"), "{stale:?}");
        let on = block("[presets]\ndefault = \"as_written\"\nstrict = \"as_written\"\npedantic = \"as_written\"\n");
        assert!(problems("API03-C", Some(&on), &ctx)[0].contains("drop the entry"));
    }

    #[test]
    fn private_ids_are_refused_wherever_prose_goes() {
        let base = "[presets]\ndefault = \"as_written\"\nstrict = \"as_written\"\npedantic = \"as_written\"\n";
        for bad in [
            "basis = \"see P99\"",
            "basis = \"task 9999\"",
            "overlap = \"aurora_lint 9999\"",
            "ruling = \"Q8\"",
        ] {
            let p = check("A-C", &format!("{base}{bad}\n"));
            assert!(p.iter().any(|m| m.contains("private")), "{bad}: {p:?}");
        }
        // Rule ids and numbers in prose are fine.
        assert!(check(
            "A-C",
            &format!("{base}basis = \"C11 7.22.3.5p3, MEM30-C, 2016 edition\"\n")
        )
        .is_empty());
    }

    #[test]
    fn a_missing_block_is_a_problem() {
        let rules = BTreeSet::new();
        let options = BTreeSet::new();
        let enabled = BTreeMap::new();
        let ctx = Context {
            rules: &rules,
            options: &options,
            enabled: &enabled,
        };
        assert_eq!(problems("X-C", None, &ctx).len(), 1);
    }

    #[test]
    fn the_page_lists_every_rule_with_its_cells() {
        let a = block("[presets]\ndefault = \"narrowed\"\nstrict = \"as_written\"\npedantic = \"stricter\"\noptions = [\"assert_is_guard\"]\nruling = \"A-C/2026-10-09/1\"\n");
        let table: BTreeMap<String, Block> = [("A-C".to_string(), a)].into();
        let rst = to_rst(&table);
        assert!(rst.contains("   * - A-C\n     - narrowed\n     - as_written\n     - stricter\n     - ``assert_is_guard``\n     - A-C/2026-10-09/1\n"), "{rst}");
        assert!(rst.starts_with(".."));
    }

    #[test]
    fn the_json_is_sorted_and_derives_differs() {
        let a = block("[presets]\ndefault = \"narrowed\"\nstrict = \"as_written\"\npedantic = \"as_written\"\nbasis = \"x\"\n");
        let b = block("[presets]\ndefault = \"as_written\"\nstrict = \"as_written\"\npedantic = \"as_written\"\n");
        let table: BTreeMap<String, Block> =
            [("B-C".to_string(), b), ("A-C".to_string(), a)].into();
        let json = to_json(&table);
        assert!(json.find("\"A-C\"").unwrap() < json.find("\"B-C\"").unwrap());
        assert!(json.contains("\"A-C\": {\"default\": \"narrowed\", \"strict\": \"as_written\", \"pedantic\": \"as_written\", \"differs\": true}"));
        assert!(json.contains("\"B-C\": {\"default\": \"as_written\", \"strict\": \"as_written\", \"pedantic\": \"as_written\", \"differs\": false}"));
    }
}
