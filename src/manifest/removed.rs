// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Rules aurora-lint no longer ships (ADR-0013 Decision 4), read from
//! `rules_templates/removed-rules.toml`.
//!
//! A removed rule is deleted from the tool, not disabled, but its name stays
//! in the inventory with its reason: a configuration that still names it
//! loads with a warning, and `--list-rules` shows it (Decision 6).

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Why a rule is not shipped: the not-shipped dispositions of ADR-0013
/// Decision 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    /// CERT says it can't be checked automatically, or no sound detector is
    /// possible.
    Unenforceable,
    /// Any checkable form only approximates an intent or design judgment.
    FailsCriterion,
    /// Its only checkable form is what another shipped rule reports.
    Covered,
    /// CERT deprecated or merged the guideline.
    Deprecated,
}

impl Disposition {
    /// The disposition as ADR-0013 names it.
    pub fn label(&self) -> &'static str {
        match self {
            Disposition::Unenforceable => "unenforceable",
            Disposition::FailsCriterion => "fails the criterion",
            Disposition::Covered => "covered by another rule",
            Disposition::Deprecated => "deprecated by CERT",
        }
    }
}

/// One rule the tool no longer ships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedRule {
    /// The rule id, e.g. `ERR00-C`.
    pub id: String,
    /// The release the removal ships in, without a leading `v`.
    pub removed_in: String,
    /// Which not-shipped disposition the rule has.
    pub disposition: Disposition,
    /// One sentence, written for users.
    pub reason: String,
    /// The rules that report the construct instead: required when the
    /// disposition is `covered`, the successor (if any) when `deprecated`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_by: Vec<String>,
}

impl RemovedRule {
    /// "(disposition): reason; covered by A, B", shared by the warning and
    /// the listing.
    fn why(&self) -> String {
        let mut text = format!(
            "({}): {}",
            self.disposition.label(),
            self.reason.trim_end_matches('.')
        );
        if !self.covered_by.is_empty() {
            let verb = match self.disposition {
                Disposition::Deprecated => "replaced by",
                _ => "covered by",
            };
            text.push_str(&format!("; {verb} {}", self.covered_by.join(", ")));
        }
        text
    }

    /// What the tool says when a configuration names this rule.
    pub fn warning(&self) -> String {
        format!(
            "{} was removed in v{} {}. Its configuration block is ignored.",
            self.id,
            self.removed_in,
            self.why()
        )
    }

    /// What the tool says when something other than a configuration block
    /// names this rule: `place` is what named it (`--rules`, "A
    /// suppression").
    pub fn reference_warning(&self, place: &str) -> String {
        format!(
            "{place} names {}, which was removed in v{} {}. It matches nothing.",
            self.id,
            self.removed_in,
            self.why()
        )
    }

    /// This rule's line in `--list-rules`.
    pub fn warning_line(&self) -> String {
        format!(
            "{:<10} removed in v{} {}",
            self.id,
            self.removed_in,
            self.why()
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovedTable {
    #[serde(default)]
    removed: Vec<RemovedRule>,
}

/// Parse and check a removed-rules table: every field set, ids unique and
/// sorted, and a `covered` entry naming what covers it. Sorted, so that
/// removals on parallel branches each add their entry in its own place
/// instead of all at the end of the file.
pub fn parse_removed_rules(content: &str) -> Result<Vec<RemovedRule>, String> {
    let table: RemovedTable = toml::from_str(content).map_err(|e| e.to_string())?;
    for pair in table.removed.windows(2) {
        if pair[0].id == pair[1].id {
            return Err(format!("removed rule {} is listed twice", pair[0].id));
        }
        if pair[0].id > pair[1].id {
            return Err(format!(
                "removed rules are kept sorted by id: {} comes before {}",
                pair[1].id, pair[0].id
            ));
        }
    }
    for rule in &table.removed {
        if rule.id.is_empty() || rule.removed_in.is_empty() || rule.reason.trim().is_empty() {
            return Err(format!(
                "removed rule '{}' needs an id, removed_in and reason",
                rule.id
            ));
        }
        if rule.removed_in.starts_with('v') {
            return Err(format!(
                "removed rule {}: write removed_in without the leading 'v'",
                rule.id
            ));
        }
        if rule.disposition == Disposition::Covered && rule.covered_by.is_empty() {
            return Err(format!(
                "removed rule {} is 'covered' but names no covering rule",
                rule.id
            ));
        }
    }
    Ok(table.removed)
}

const REMOVED_RULES_TOML: &str = include_str!("../../rules_templates/removed-rules.toml");

/// Every rule the tool no longer ships, from `rules_templates/removed-rules.toml`.
pub fn removed_rules() -> &'static [RemovedRule] {
    static TABLE: OnceLock<Vec<RemovedRule>> = OnceLock::new();
    TABLE.get_or_init(|| {
        parse_removed_rules(REMOVED_RULES_TOML)
            .unwrap_or_else(|e| panic!("rules_templates/removed-rules.toml: {e}"))
    })
}

/// The removed rule with this id, if any.
pub fn find_removed(id: &str) -> Option<&'static RemovedRule> {
    removed_rules().iter().find(|r| r.id == id)
}

/// Check `removed` against the rules the tool ships: a removed rule is not
/// also shipped, and every rule a `covered_by` names is shipped, so a typo
/// or a rule removed in its turn is caught rather than published as the
/// replacement.
pub fn check_against_shipped(
    removed: &[RemovedRule],
    shipped: &std::collections::HashSet<&str>,
) -> Result<(), String> {
    for rule in removed {
        if shipped.contains(rule.id.as_str()) {
            return Err(format!(
                "{} is listed as removed but the tool still ships it",
                rule.id
            ));
        }
        for cover in &rule.covered_by {
            if !shipped.contains(cover.as_str()) {
                let what = if removed.iter().any(|r| &r.id == cover) {
                    "was removed too"
                } else {
                    "is not a rule the tool ships"
                };
                return Err(format!(
                    "removed rule {} is covered by {cover}, which {what}",
                    rule.id
                ));
            }
        }
    }
    Ok(())
}

/// Print `warning` on stderr unless this process already has: a run that
/// loads the same configuration twice, or meets the same removed id in many
/// suppressions, still says it once.
pub fn warn_once(warning: &str) {
    static SEEN: OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    let seen = SEEN.get_or_init(Default::default);
    if seen
        .lock()
        .map(|mut s| s.insert(warning.to_string()))
        .unwrap_or(true)
    {
        eprintln!("Warning: {warning}");
    }
}

/// Warn once when `id`, named by `place`, is a removed rule.
pub fn warn_if_removed(id: &str, place: &str) {
    if let Some(rule) = find_removed(id) {
        warn_once(&rule.reference_warning(place));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, disposition: &str, covered_by: &[&str]) -> String {
        format!(
            "[[removed]]\nid = \"{id}\"\nremoved_in = \"0.7.0\"\ndisposition = \"{disposition}\"\n\
             reason = \"r\"\ncovered_by = {covered_by:?}\n"
        )
    }

    #[test]
    fn the_shipped_table_parses_and_names_only_shipped_covering_rules() {
        let registry = crate::rules::RuleRegistry::new();
        let shipped: std::collections::HashSet<&str> =
            registry.all_rules().iter().map(|r| r.rule_id()).collect();
        check_against_shipped(removed_rules(), &shipped).unwrap();
    }

    #[test]
    fn a_reference_outside_the_configuration_says_what_replaced_the_rule() {
        let removed = parse_removed_rules(&rule("ERR00-C", "covered", &["ERR33-C"])).unwrap();
        assert_eq!(
            removed[0].reference_warning("--rules"),
            "--rules names ERR00-C, which was removed in v0.7.0 (covered by another rule): r; \
             covered by ERR33-C. It matches nothing."
        );
    }

    #[test]
    fn entries_out_of_order_are_refused() {
        let toml = rule("MSC00-C", "unenforceable", &[]) + &rule("ERR00-C", "unenforceable", &[]);
        let err = parse_removed_rules(&toml).unwrap_err();
        assert!(err.contains("sorted"), "{err}");
    }

    #[test]
    fn a_covering_rule_that_is_not_shipped_is_refused() {
        let shipped: std::collections::HashSet<&str> = ["ERR33-C"].into_iter().collect();
        let typo = parse_removed_rules(&rule("ERR00-C", "covered", &["ERR33C"])).unwrap();
        let err = check_against_shipped(&typo, &shipped).unwrap_err();
        assert!(err.contains("not a rule the tool ships"), "{err}");
        let chain = parse_removed_rules(
            &(rule("ERR00-C", "covered", &["MSC00-C"]) + &rule("MSC00-C", "unenforceable", &[])),
        )
        .unwrap();
        let err = check_against_shipped(&chain, &shipped).unwrap_err();
        assert!(err.contains("was removed too"), "{err}");
        let fine = parse_removed_rules(&rule("ERR00-C", "covered", &["ERR33-C"])).unwrap();
        check_against_shipped(&fine, &shipped).unwrap();
    }
}
