// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Err02C;

impl CertRule for Err02C {
    fn rule_id(&self) -> &'static str {
        "ERR02-C"
    }
    fn description(&self) -> &'static str {
        "Avoid in-band error indicators"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "ERR02-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Err02C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            // Check for function declarations using ssize_t (in-band error indicator)
            if n.kind() == "declaration" {
                let text = n.utf8_text(source.as_bytes()).unwrap_or("");

                // ssize_t is problematic - uses negative for errors, positive for data
                if text.contains("ssize_t") && text.contains("(") {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
                        file_path: String::new(),
                        message: "Using ssize_t mixes error indicators with data; use separate error parameter".to_string(),
                        suggestion: Some("Use size_t with separate errno_t error parameter".to_string()),
                        requires_manual_review: None,
                    });
                }
            }

            // Look for sprintf/snprintf calls where return value is used for accumulation
            // Pattern: count += sprintf(...) without error checking
            if n.kind() == "assignment_expression" {
                let text = n.utf8_text(source.as_bytes()).unwrap_or("");

                // Check for += with sprintf
                if text.contains("+=") && (text.contains("sprintf") || text.contains("snprintf")) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
                        file_path: String::new(),
                        message: "Using sprintf return value without error checking; use sprintf_m or check for negative return".to_string(),
                        suggestion: Some("Check return value for errors before using it".to_string()),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }
}
