// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
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

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Dcl38C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "field_declaration" {
            let text = get_node_text(node, source);

            if text.contains("[1]") {
                if let Some(parent) = node.parent() {
                    if parent.kind() == "field_declaration_list" {
                        let mut cursor = parent.walk();
                        let fields: Vec<_> = parent
                            .children(&mut cursor)
                            .filter(|n| n.kind() == "field_declaration")
                            .collect();

                        if let Some(last) = fields.last() {
                            if last.id() == node.id() {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
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

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, violations);
        }
    }
}
