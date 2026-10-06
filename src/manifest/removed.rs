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

/// Parse and check a removed-rules table: every field set, ids unique, and
/// a `covered` entry naming what covers it.
pub fn parse_removed_rules(content: &str) -> Result<Vec<RemovedRule>, String> {
    let table: RemovedTable = toml::from_str(content).map_err(|e| e.to_string())?;
    let mut seen = std::collections::HashSet::new();
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
        if !seen.insert(rule.id.as_str()) {
            return Err(format!("removed rule {} is listed twice", rule.id));
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
