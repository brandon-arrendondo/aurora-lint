// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Int02C;

impl CertRule for Int02C {
    fn rule_id(&self) -> &'static str {
        "INT02-C"
    }
    fn description(&self) -> &'static str {
        "Understand integer conversion rules"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "INT02-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Int02C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            // Look for binary comparisons between signed and unsigned integers
            if n.kind() == "binary_expression" {
                let text = n.utf8_text(source.as_bytes()).unwrap_or("");

                // Check for comparison operators
                if text.contains("<")
                    || text.contains(">")
                    || text.contains("<=")
                    || text.contains(">=")
                    || text.contains("==")
                    || text.contains("!=")
                {
                    // Look for patterns where one operand might be signed and other unsigned
                    let has_signed_pattern = text.contains("si ") || text.contains(" si");
                    let has_unsigned_pattern = text.contains("ui ") || text.contains(" ui");

                    let has_cast = text.contains("(int)") || text.contains("(unsigned");

                    if has_signed_pattern && has_unsigned_pattern && !has_cast {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            file_path: String::new(),
                            message: "Comparison between signed and unsigned integers without cast"
                                .to_string(),
                            suggestion: Some("Cast one operand to match signedness".to_string()),
                            requires_manual_review: None,
                        });
                    }
                }
            }

            // Check declarations with bitwise NOT on small types
            if n.kind() == "declaration" {
                let text = n.utf8_text(source.as_bytes()).unwrap_or("");

                // Pattern: uint8_t result = ( ~value ) >> shift WITHOUT explicit cast
                if (text.contains("uint8_t") || text.contains("int8_t")) && text.contains("~") {
                    // Check if there's NO explicit cast to uint8_t/int8_t after the ~
                    if !text.contains("(uint8_t)") && !text.contains("(int8_t)") {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            file_path: String::new(),
                            message:
                                "Bitwise operation on small integer type subject to integer promotion"
                                    .to_string(),
                            suggestion: Some("Cast result explicitly to intended type".to_string()),
                            requires_manual_review: None,
                        });
                    }
                }

                // Check for unsigned short multiplication
                if text.contains("unsigned short")
                    && text.contains("*")
                    && !text.contains("(unsigned int)")
                {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
                        file_path: String::new(),
                        message: "Multiplication of unsigned short undergoes integer promotion; result may overflow".to_string(),
                        suggestion: Some("Cast operands to unsigned int before multiplication".to_string()),
                        requires_manual_review: None,
                    });
                }
            }

            // Check for loops comparing char with unsigned char
            if n.kind() == "for_statement" {
                let text = n.utf8_text(source.as_bytes()).unwrap_or("");

                // Get lines before the loop to check declarations
                let lines_before = source
                    .lines()
                    .take(n.start_position().row)
                    .collect::<Vec<_>>()
                    .join("\n");

                // Pattern: char i (signed) compared with unsigned char max (unsigned)
                // NOT: unsigned char i with unsigned char max (both unsigned - OK)
                if text.contains("char i")
                    && !text.contains("unsigned char i")
                    && lines_before.contains("unsigned char max")
                    && text.contains("<")
                {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
                        file_path: String::new(),
                        message:
                            "Loop compares signed char with unsigned char; signedness mismatch"
                                .to_string(),
                        suggestion: Some(
                            "Use consistent signedness for loop variable and limit".to_string(),
                        ),
                        requires_manual_review: None,
                    });
                }
            }

            // Check for assignments with unsigned short multiplication
            if n.kind() == "assignment_expression" || n.kind() == "init_declarator" {
                let text = n.utf8_text(source.as_bytes()).unwrap_or("");

                // Pattern: unsigned int z = x * y where x, y are unsigned short WITHOUT cast
                let lines_before = source
                    .lines()
                    .take(n.start_position().row)
                    .collect::<Vec<_>>()
                    .join("\n");

                if text.contains("*")
                    && lines_before.contains("unsigned short")
                    && !text.contains("(unsigned int)")
                    && !text.contains("(unsigned long)")
                {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
                        file_path: String::new(),
                        message: "Multiplication of unsigned short values; result may overflow due to integer promotion".to_string(),
                        suggestion: Some("Cast operands to unsigned int before multiplication".to_string()),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }
}
