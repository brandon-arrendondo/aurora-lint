// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use tree_sitter::Node;

pub struct Exp37C;

impl CertRule for Exp37C {
    fn rule_id(&self) -> &'static str {
        "EXP37-C"
    }
    fn description(&self) -> &'static str {
        "Call functions with correct arguments"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "EXP37-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Exp37C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for log2() with complex numbers (not creal)
        if node.kind() == "call_expression" {
            let text = node.utf8_text(source.as_bytes()).unwrap_or("");

            // log2() doesn't support complex numbers directly
            if text.starts_with("log2(") && !text.contains("creal(") {
                // Check if context has complex number declarations
                let lines_before = source
                    .lines()
                    .take(node.start_position().row + 1)
                    .collect::<Vec<_>>()
                    .join("\n");
                if lines_before.contains("complex") && lines_before.contains("=") {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        message: "log2() does not support complex numbers; use log(x)/log(2) or log2(creal(x))".to_string(),
                        suggestion: Some("Replace log2(complex) with log(complex)/log(2) or log2(creal(complex))".to_string()),
                        requires_manual_review: None,
                    });
                }
            }

            // Check for open() without mode parameter when O_CREAT is used
            if text.starts_with("open(") && text.contains("O_CREAT") {
                // Count commas to check argument count
                let comma_count = text.matches(',').count();
                if comma_count < 2 {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        message: "open() with O_CREAT requires mode parameter".to_string(),
                        suggestion: Some("Add mode_t parameter to open() call".to_string()),
                        requires_manual_review: None,
                    });
                }
            }
        }

        // Check for old-style function declarations without parameter types
        if node.kind() == "declaration" {
            let text = node.utf8_text(source.as_bytes()).unwrap_or("");

            // Skip variable declarations with initialization (e.g. uint32_t x = MACRO();)
            let has_init = (0..node.child_count())
                .any(|i| node.child(i).is_some_and(|c| c.kind() == "init_declarator"));

            // Pattern: function_name(); with empty parens (K&R style)
            if !has_init && text.contains("()") && !text.contains("void") {
                // Exclude function pointers and actual function definitions
                if !text.contains("(*") && !text.contains("{") {
                    // Check if it looks like a function declaration
                    if text.trim().ends_with(");") {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            file_path: String::new(),
                            message: "Old-style function declaration without parameter types"
                                .to_string(),
                            suggestion: Some(
                                "Specify parameter types in function declaration".to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }

            // Check for variadic function declarations without proper header
            if text.contains("...") && !text.contains("#include") {
                // Check if it's a declaration (not definition)
                if text.trim().ends_with(";") && !text.contains("{") {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        message: "Variadic function declaration should use proper header"
                            .to_string(),
                        suggestion: Some(
                            "Include proper header instead of declaring variadic function"
                                .to_string(),
                        ),
                        requires_manual_review: None,
                    });
                }
            }

            // Check for function pointer with wrong signature
            if text.contains("(*fp)()") || (text.contains("(*fp)") && text.contains("()")) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    file_path: String::new(),
                    message: "Function pointer declared without parameter types".to_string(),
                    suggestion: Some(
                        "Declare function pointer with explicit parameter types".to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }

        // Recursively check children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, violations);
        }
    }
}
