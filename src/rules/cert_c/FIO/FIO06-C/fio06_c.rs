// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! FIO06-C: Create files with appropriate access permissions
//!
//! This rule detects file creation without explicitly specified permissions.
//! Common violations include:
//! - Using fopen() which cannot specify permissions (uses implementation-defined defaults)
//! - Using open() with O_CREAT but omitting the mode argument
//!
//! The recommended approach is to use open() with three arguments including
//! explicit file permissions.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/FIO06-C.+Create+files+with+appropriate+access+permissions

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Fio06C;

impl Fio06C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Fio06C
    }

    /// Check if an fopen() call uses modes that create files
    fn is_file_creating_mode(&self, mode: &str) -> bool {
        // Modes that create or write files
        mode.contains('w') || mode.contains('a') || mode.contains('+')
    }

    /// Check for fopen() calls that may create files
    fn check_fopen_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "call_expression" {
            return;
        }

        // Check if this is an fopen call
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source);
            if func_name != "fopen" {
                return;
            }
        } else {
            return;
        }

        // Get the arguments
        if let Some(arguments) = node.child_by_field_name("arguments") {
            let mut cursor = arguments.walk();
            let mut mode_arg = None;

            for child in arguments.children(&mut cursor) {
                if child.kind() == "string_literal" || child.kind() == "identifier" {
                    // Second string argument is the mode
                    if mode_arg.is_none() {
                        mode_arg = Some(child);
                    } else {
                        // This is the mode argument
                        let mode_text = get_node_text(&child, source);

                        // Check if mode creates or writes files
                        if self.is_file_creating_mode(mode_text) {
                            violations.push(RuleViolation {
                                rule_id: "FIO06-C".to_string(),
                                severity: Severity::Medium,
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                message: "fopen() cannot explicitly specify file permissions; use open() for security-sensitive files".to_string(),
                                file_path: String::new(),
                                suggestion: Some(
                                    "Use open(filename, O_CREAT | O_WRONLY, mode) to explicitly specify file permissions".to_string(),
                                ),
                                requires_manual_review: Some(false),
                            });
                        }
                        break;
                    }
                }
            }
        }
    }

    /// Check if open() call includes O_CREAT flag
    fn has_o_creat_flag(&self, flags_node: &Node, source: &str) -> bool {
        let flags_text = get_node_text(flags_node, source);

        // Check for O_CREAT in the flags
        flags_text.contains("O_CREAT")
    }

    /// Count the number of arguments in an open() call
    fn count_open_arguments(&self, arguments: &Node) -> usize {
        let mut count = 0;
        let mut cursor = arguments.walk();

        for child in arguments.children(&mut cursor) {
            // Skip parentheses and commas
            if child.kind() == "(" || child.kind() == ")" || child.kind() == "," {
                continue;
            }
            count += 1;
        }

        count
    }

    /// Check for open() calls missing mode parameter
    fn check_open_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "call_expression" {
            return;
        }

        // Check if this is an open call
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source);
            if func_name != "open" {
                return;
            }
        } else {
            return;
        }

        // Get the arguments
        if let Some(arguments) = node.child_by_field_name("arguments") {
            let arg_count = self.count_open_arguments(&arguments);

            // If only 2 arguments, need to check if O_CREAT is used
            if arg_count == 2 {
                // Get the second argument (flags)
                let mut cursor = arguments.walk();
                let mut args_found = 0;

                for child in arguments.children(&mut cursor) {
                    if child.kind() == "(" || child.kind() == ")" || child.kind() == "," {
                        continue;
                    }

                    args_found += 1;

                    // Second argument is flags
                    if args_found == 2 {
                        if self.has_o_creat_flag(&child, source) {
                            violations.push(RuleViolation {
                                rule_id: "FIO06-C".to_string(),
                                severity: Severity::High,
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                message: "open() called with O_CREAT but missing mode argument".to_string(),
                                file_path: String::new(),
                                suggestion: Some(
                                    "Add a third argument to specify file permissions, e.g., open(filename, O_CREAT | flags, 0600)".to_string(),
                                ),
                                requires_manual_review: Some(false),
                            });
                        }
                        break;
                    }
                }
            }
        }
    }

    /// Recursively traverse AST
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for fopen and open calls
        if node.kind() == "call_expression" {
            self.check_fopen_call(node, source, violations);
            self.check_open_call(node, source, violations);
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.traverse(&child, source, violations);
        }
    }
}

impl CertRule for Fio06C {
    fn rule_id(&self) -> &'static str {
        "FIO06-C"
    }

    fn description(&self) -> &'static str {
        "Create files with appropriate access permissions"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "FIO06-C"
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.traverse(root, source, &mut violations);
        violations
    }
}
