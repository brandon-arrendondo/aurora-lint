// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use lang_parsing_substrate::query;
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
    fn cert_id(&self) -> &'static str {
        "EXP37-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Exp37C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Every form is reported at the call. Old-style declarations are
        // DCL20-C's construct, and a variadic prototype violates nothing.
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            // Check for log2() with complex numbers (not creal)
            let text = n.utf8_text(source.as_bytes()).unwrap_or("");

            // log2() doesn't support complex numbers directly
            if text.starts_with("log2(") && !text.contains("creal(") {
                // Check if context has complex number declarations
                let lines_before = source
                    .lines()
                    .take(n.start_position().row + 1)
                    .collect::<Vec<_>>()
                    .join("\n");
                if lines_before.contains("complex") && lines_before.contains("=") {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
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
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
                        file_path: String::new(),
                        message: "open() with O_CREAT requires mode parameter".to_string(),
                        suggestion: Some("Add mode_t parameter to open() call".to_string()),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }
}
