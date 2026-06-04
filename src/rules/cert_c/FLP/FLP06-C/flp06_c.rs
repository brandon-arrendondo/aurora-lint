// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use tree_sitter::Node;

pub struct Flp06C;

impl CertRule for Flp06C {
    fn rule_id(&self) -> &'static str {
        "FLP06-C"
    }
    fn description(&self) -> &'static str {
        "TODO"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "FLP06-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Flp06C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for declarations: float/double var = expression;
        if node.kind() == "declaration" {
            let decl_text = node.utf8_text(source.as_bytes()).unwrap_or("");

            // Must be float or double declaration
            if (decl_text.contains("float") || decl_text.contains("double"))
                && decl_text.contains(" = ")
            {
                // Extract expression after =, before ; or comment
                let after_equals = decl_text.split(" = ").nth(1).unwrap_or("");
                let expr = after_equals
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .split("/*")
                    .next()
                    .unwrap_or("")
                    .split("//")
                    .next()
                    .unwrap_or("")
                    .trim();

                // Check if it has arithmetic operation
                let has_arithmetic = expr.contains('/')
                    || expr.contains('*')
                    || expr.contains('+')
                    || expr.contains('-');

                if has_arithmetic {
                    // Check for floating-point indicators
                    let has_float_literal =
                        expr.contains('.') || expr.contains('f') || expr.contains('F');
                    let has_cast = expr.contains("(float)") || expr.contains("(double)");

                    // Violation: arithmetic without floating-point conversion
                    if !has_float_literal && !has_cast {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            file_path: String::new(),
                            message: "Floating point variable initialized with integer arithmetic; use floating-point literals or explicit conversion".to_string(),
                            suggestion: Some("Use floating-point literals (e.g., 7.0) or explicit casts (e.g., (double)x)".to_string()),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }

        // Recursively check children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, violations);
        }
    }
}
