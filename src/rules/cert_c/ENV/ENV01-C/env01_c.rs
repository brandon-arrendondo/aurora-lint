// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! ENV01-C: Do not make assumptions about the size of an environment variable
//!
//! This rule detects violations where getenv() results are used without proper
//! size checking or NULL checking, or when fixed-size buffers are used.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/ENV01-C.+Do+not+make+assumptions+about+the+size+of+an+environment+variable

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Env01C;

impl Env01C {
    pub fn new() -> Self {
        Env01C
    }

    /// Check if a call expression is to getenv
    fn is_getenv_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                return func_name == "getenv";
            }
        }
        false
    }

    /// Check if getenv result is used directly in strcpy or similar
    fn check_unsafe_usage(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // Check for strcpy, strcat, etc. with getenv as source
                if func_name == "strcpy" || func_name == "strcat" {
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        let mut cursor = arguments.walk();
                        for child in arguments.children(&mut cursor) {
                            if self.is_getenv_call(&child, source) {
                                violations.push(RuleViolation {
                                    rule_id: "ENV01-C".to_string(),
                                    severity: Severity::High,
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    message: format!(
                                        "getenv() result used directly in {} without size or NULL check",
                                        func_name
                                    ),
                                    file_path: String::new(),
                                    suggestion: Some("Check getenv() return for NULL and use strlen() to allocate appropriate buffer size".to_string()),
                                    requires_manual_review: Some(false),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check for fixed-size buffer usage with getenv
    fn check_fixed_buffer(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for array declarations with PATH_MAX or other constants
        if node.kind() == "declaration" {
            let mut has_fixed_size_array = false;
            let mut cursor = node.walk();

            for child in node.children(&mut cursor) {
                if child.kind() == "array_declarator" {
                    if let Some(size) = child.child_by_field_name("size") {
                        let size_text = get_node_text(&size, source);
                        if size_text.contains("PATH_MAX") || size_text.contains("MAX") {
                            has_fixed_size_array = true;
                        }
                    }
                }
            }

            if has_fixed_size_array {
                // Check if this is followed by getenv usage in the same scope
                // This is a simplified check - a more thorough check would track data flow
                violations.push(RuleViolation {
                    rule_id: "ENV01-C".to_string(),
                    severity: Severity::Medium,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: "Fixed-size buffer may be used with environment variable".to_string(),
                    file_path: String::new(),
                    suggestion: Some(
                        "Use dynamic allocation based on strlen() of getenv() result".to_string(),
                    ),
                    requires_manual_review: Some(true),
                });
            }
        }
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            self.check_unsafe_usage(&n, source, violations);
            self.check_fixed_buffer(&n, source, violations);
        }
    }
}

impl Default for Env01C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Env01C {
    fn rule_id(&self) -> &'static str {
        "ENV01-C"
    }

    fn description(&self) -> &'static str {
        "Do not make assumptions about the size of an environment variable"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ENV01-C"
    }

    fn scan(&self, root_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(root_node, source, violations);
    }
}
