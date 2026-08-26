// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! ERR01-C: Use ferror() rather than errno to check for FILE stream errors
//!
//! This rule detects when errno is checked after FILE stream operations.
//! The correct approach is to use ferror() to check for errors on FILE streams,
//! as errno may retain values from earlier operations even if subsequent calls succeed.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/ERR01-C.+Use+ferror()+rather+than+errno+to+check+for+FILE+stream+errors

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Err01C {
    // Track FILE stream function calls
    file_stream_functions_seen: RefCell<bool>,
}

impl Err01C {
    pub fn new() -> Self {
        Err01C {
            file_stream_functions_seen: RefCell::new(false),
        }
    }

    /// Check if a function is a FILE stream operation
    fn is_file_stream_function(&self, name: &str) -> bool {
        matches!(
            name,
            "printf"
                | "fprintf"
                | "sprintf"
                | "snprintf"
                | "vprintf"
                | "vfprintf"
                | "vsprintf"
                | "vsnprintf"
                | "scanf"
                | "fscanf"
                | "sscanf"
                | "vscanf"
                | "vfscanf"
                | "vsscanf"
                | "fgetc"
                | "fgets"
                | "getc"
                | "getchar"
                | "gets"
                | "fputc"
                | "fputs"
                | "putc"
                | "putchar"
                | "puts"
                | "ungetc"
                | "fread"
                | "fwrite"
                | "fseek"
                | "ftell"
                | "rewind"
                | "fgetpos"
                | "fsetpos"
                | "fflush"
                | "fclose"
                | "fopen"
                | "freopen"
                | "setbuf"
                | "setvbuf"
        )
    }

    /// Check if an identifier is errno
    fn is_errno(&self, node: &Node, source: &str) -> bool {
        node.kind() == "identifier" && get_node_text(node, source) == "errno"
    }

    /// Check for errno in an expression
    fn contains_errno(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| self.is_errno(&n, source)).is_some()
    }

    /// Check if a statement is checking errno
    fn is_errno_check(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "if_statement" | "while_statement" | "do_statement" | "for_statement" => {
                if let Some(condition) = node.child_by_field_name("condition") {
                    return self.contains_errno(&condition, source);
                }
            }
            "binary_expression" | "unary_expression" | "parenthesized_expression" => {
                return self.contains_errno(node, source);
            }
            _ => {}
        }

        false
    }

    /// Process a call expression
    fn check_call_expression(&self, node: &Node, source: &str) {
        if node.kind() != "call_expression" {
            return;
        }

        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source);

            if self.is_file_stream_function(func_name) {
                *self.file_stream_functions_seen.borrow_mut() = true;
            }
        }
    }

    /// Check for errno usage after FILE stream operations
    fn check_errno_usage(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check if this statement checks errno
        if self.is_errno_check(node, source) && *self.file_stream_functions_seen.borrow() {
            violations.push(RuleViolation {
                rule_id: "ERR01-C".to_string(),
                severity: Severity::Low,
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                message: "errno is checked after FILE stream operations; use ferror() instead"
                    .to_string(),
                file_path: String::new(),
                suggestion: Some(
                    "Use ferror() to check for errors on FILE streams instead of checking errno"
                        .to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }

    /// Process a function definition (reset state for each function)
    fn process_function(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "function_definition" {
            return;
        }

        // Reset state for this function
        *self.file_stream_functions_seen.borrow_mut() = false;

        // Traverse the function body for FILE stream errno checks
        if let Some(body) = node.child_by_field_name("body") {
            self.traverse_block(&body, source, violations);
        }
    }

    /// Traverse a block of code
    fn traverse_block(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // Check for FILE stream function calls
            self.check_call_expression(&child, source);

            // Check for errno usage
            self.check_errno_usage(&child, source, violations);

            // Recurse into nested blocks
            if child.kind() == "compound_statement" {
                self.traverse_block(&child, source, violations);
            } else {
                // Recurse into child nodes
                let mut child_cursor = child.walk();
                for grandchild in child.children(&mut child_cursor) {
                    if grandchild.kind() == "call_expression" {
                        self.check_call_expression(&grandchild, source);
                    }
                }
            }
        }
    }

    /// Recursively traverse AST
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            // Handle function definitions
            if n.kind() == "function_definition" {
                self.process_function(&n, source, violations);
            } else if n.kind() == "translation_unit" {
                // Handle top-level statements (for code snippets without function wrappers)
                *self.file_stream_functions_seen.borrow_mut() = false;
                self.traverse_top_level(&n, source, violations);
            }
        }
    }

    /// Traverse top-level statements in a translation unit
    fn traverse_top_level(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // Skip function definitions (handled separately)
            if child.kind() == "function_definition" {
                continue;
            }

            // Check expression statements at top level
            if child.kind() == "expression_statement" {
                self.check_expression_statement(&child, source, violations);
            }

            // Check if statements at top level
            if child.kind() == "if_statement" {
                self.check_errno_usage(&child, source, violations);
            }
        }
    }

    /// Check an expression statement for FILE stream calls
    fn check_expression_statement(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "call_expression" {
                self.check_call_expression(&child, source);
            }
            // Also check for errno checks in expression statements
            self.check_errno_usage(&child, source, violations);

            // Recurse to find nested call expressions
            self.find_calls_recursive(&child, source);
        }
    }

    /// Recursively find call expressions in a node
    fn find_calls_recursive(&self, node: &Node, source: &str) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_call_expression(&n, source);
        }
    }
}

impl CertRule for Err01C {
    fn rule_id(&self) -> &'static str {
        "ERR01-C"
    }

    fn description(&self) -> &'static str {
        "Use ferror() rather than errno to check for FILE stream errors"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "ERR01-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
