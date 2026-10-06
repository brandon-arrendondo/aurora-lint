// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! `--list-rules`: every rule the tool ships, whether the loaded
//! configuration enables it, and then every rule it no longer ships with the
//! reason (ADR-0013 Decision 6).

use super::RuleRegistry;
use crate::manifest::removed::RemovedRule;
use crate::manifest::RuleManifest;
use serde_json::{json, Value};

/// Whether `manifest` runs `id`: `Some(true|false)` from its block, `None`
/// when it has no block for the rule (so the rule does not run).
fn enabled_in(manifest: &RuleManifest, id: &str) -> Option<bool> {
    manifest.get_rule(id).map(|c| c.enabled)
}

/// The listing as plain text: one line per shipped rule, then the removed
/// rules.
pub fn render_text(
    registry: &RuleRegistry,
    manifest: &RuleManifest,
    removed: &[RemovedRule],
) -> String {
    let mut rules: Vec<_> = registry.all_rules().iter().collect();
    rules.sort_by_key(|r| r.rule_id());
    let enabled = rules
        .iter()
        .filter(|r| enabled_in(manifest, r.rule_id()) == Some(true))
        .count();
    let mut out = format!(
        "Rules ({} shipped, {} enabled by this configuration):\n",
        rules.len(),
        enabled
    );
    for rule in &rules {
        let state = match enabled_in(manifest, rule.rule_id()) {
            Some(true) => "on ",
            Some(false) => "off",
            None => "-- ",
        };
        out.push_str(&format!(
            "  {:<10} {} {:<6} {}\n",
            rule.rule_id(),
            state,
            rule.severity().to_string(),
            rule.description()
        ));
    }
    out.push_str("  (on/off: this configuration's setting; --: not in this configuration)\n");
    if removed.is_empty() {
        out.push_str("\nRemoved rules: none.\n");
    } else {
        out.push_str(&format!(
            "\nRemoved rules ({}), no longer shipped:\n",
            removed.len()
        ));
        for rule in removed {
            out.push_str(&format!("  {}\n", rule.warning_line()));
        }
    }
    out
}

/// The listing as JSON: `{"rules": [...], "removed": [...]}`.
pub fn render_json(
    registry: &RuleRegistry,
    manifest: &RuleManifest,
    removed: &[RemovedRule],
) -> Value {
    let mut rules: Vec<_> = registry.all_rules().iter().collect();
    rules.sort_by_key(|r| r.rule_id());
    json!({
        "rules": rules.iter().map(|r| json!({
            "id": r.rule_id(),
            "enabled": enabled_in(manifest, r.rule_id()),
            "severity": r.severity().to_string(),
            "description": r.description(),
        })).collect::<Vec<_>>(),
        "removed": removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::removed::parse_removed_rules;

    fn manifest() -> RuleManifest {
        RuleManifest::from_toml_str(include_str!("../../rules_templates/rules-all.toml")).unwrap()
    }

    #[test]
    fn text_lists_every_shipped_rule_and_says_when_none_are_removed() {
        let registry = RuleRegistry::new();
        let text = render_text(&registry, &manifest(), &[]);
        assert!(text.contains("  ARR30-C    on "), "{text}");
        assert!(text.ends_with("\nRemoved rules: none.\n"), "{text}");
        for rule in registry.all_rules() {
            assert!(
                text.contains(&format!("  {:<10} ", rule.rule_id())),
                "{}",
                rule.rule_id()
            );
        }
    }

    #[test]
    fn removed_rules_are_listed_separately_with_their_reason() {
        let removed = parse_removed_rules(
            "[[removed]]\nid = \"ERR00-C\"\nremoved_in = \"9.9.9\"\n\
             disposition = \"covered\"\nreason = \"Test-only entry.\"\n\
             covered_by = [\"ERR33-C\", \"EXP12-C\"]\n",
        )
        .unwrap();
        let registry = RuleRegistry::new();
        let text = render_text(&registry, &manifest(), &removed);
        let tail = text
            .split("\nRemoved rules (1), no longer shipped:\n")
            .nth(1)
            .unwrap();
        assert_eq!(
            tail,
            "  ERR00-C    removed in v9.9.9 (covered by another rule): Test-only entry; \
             covered by ERR33-C, EXP12-C\n"
        );
        let json = render_json(&registry, &manifest(), &removed);
        assert_eq!(json["removed"][0]["id"], "ERR00-C");
        assert_eq!(json["removed"][0]["covered_by"][1], "EXP12-C");
    }
}
