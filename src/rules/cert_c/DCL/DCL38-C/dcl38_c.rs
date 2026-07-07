// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Dcl38C;

impl CertRule for Dcl38C {
    fn rule_id(&self) -> &'static str {
        "DCL38-C"
    }
    fn description(&self) -> &'static str {
        "Use the correct syntax when declaring a flexible array member"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "DCL38-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Dcl38C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "field_declaration") {
            let text = get_node_text(&n, source);

            if text.contains("[1]") {
                if let Some(parent) = n.parent() {
                    if parent.kind() == "field_declaration_list" {
                        let mut cursor = parent.walk();
                        let fields: Vec<_> = parent
                            .children(&mut cursor)
                            .filter(|c| c.kind() == "field_declaration")
                            .collect();

                        if let Some(last) = fields.last() {
                            if last.id() == n.id() {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    line: n.start_position().row + 1,
                                    column: n.start_position().column + 1,
                                    file_path: String::new(),
                                    message: "Flexible array member should use [] not [1]"
                                        .to_string(),
                                    suggestion: Some("Use int data[]; syntax".to_string()),
                                    requires_manual_review: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
}
