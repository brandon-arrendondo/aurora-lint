// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

//! STR01-C: Adopt and implement a consistent plan for managing strings
//!
//! Detects potential inconsistencies in string management approaches within a file.
//! Flags when both static string arrays and dynamic string allocation are used together,
//! which may indicate lack of a consistent string management strategy.
//!
//! Note: This is a recommendation-level rule. Full project-wide consistency checking
//! would require cross-file analysis.

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;

pub struct Str01C {
    pub has_static_char_array: bool,
    pub has_dynamic_string_alloc: bool,
    pub static_array_line: usize,
    pub dynamic_alloc_line: usize,
}

impl CertRule for Str01C {
    fn rule_id(&self) -> &'static str {
        "STR01-C"
    }

    fn description(&self) -> &'static str {
        "Adopt and implement a consistent plan for managing strings"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "STR01-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut checker = Str01C {
            has_static_char_array: false,
            has_dynamic_string_alloc: false,
            static_array_line: 0,
            dynamic_alloc_line: 0,
        };

        let mut violations = Vec::new();
        checker.check_node(node, source, &mut violations);

        // If we found both patterns, report a violation
        if checker.has_static_char_array && checker.has_dynamic_string_alloc {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                line: checker.dynamic_alloc_line,
                column: 1,
                file_path: String::new(),
                message: format!(
                    "Mixed string management approaches detected. Static char array at line {} \
                    and dynamic allocation at line {}. Consider adopting a consistent approach.",
                    checker.static_array_line, checker.dynamic_alloc_line
                ),
                suggestion: Some(
                    "Adopt either static string arrays OR dynamic allocation consistently \
                    throughout the codebase. Document the chosen approach in coding standards."
                        .to_string(),
                ),
                requires_manual_review: Some(true),
            });
        }

        violations
    }
}

impl Str01C {
    fn check_node(&mut self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for static char arrays: char str[SIZE]
        if node.kind() == "declaration" {
            self.check_static_string_declaration(node, source);
        }

        // Check for dynamic string allocation: malloc, calloc, realloc, strdup
        if node.kind() == "call_expression" {
            self.check_dynamic_string_allocation(node, source);
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, violations);
        }
    }

    fn check_static_string_declaration(&mut self, node: &Node, source: &str) {
        let decl_text = get_node_text(node, source);

        // Look for char array declarations: char name[SIZE]
        if decl_text.contains("char") && decl_text.contains('[') && decl_text.contains(']') {
            // Check if it's a string (has size or initialized with string)
            if decl_text.contains('"') || decl_text.matches('[').count() == 1 {
                if !self.has_static_char_array {
                    self.has_static_char_array = true;
                    self.static_array_line = node.start_position().row + 1;
                }
            }
        }
    }

    fn check_dynamic_string_allocation(&mut self, node: &Node, source: &str) {
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source).trim();

            // Check for string-related dynamic allocation functions
            if matches!(
                func_name,
                "malloc" | "calloc" | "realloc" | "strdup" | "strndup"
            ) {
                if !self.has_dynamic_string_alloc {
                    self.has_dynamic_string_alloc = true;
                    self.dynamic_alloc_line = node.start_position().row + 1;
                }
            }
        }
    }
}
