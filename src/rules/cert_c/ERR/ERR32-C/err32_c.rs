// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! ERR32-C: Do not rely on indeterminate values of errno
//!
//! This rule detects violations where errno is checked without first calling
//! a function that sets it, or where errno is used in signal handlers.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/ERR32-C.+Do+not+rely+on+indeterminate+values+of+errno

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Err32C;

impl Err32C {
    pub fn new() -> Self {
        Err32C
    }

    /// First pass: collect function names registered as signal handlers
    fn collect_signal_handlers(&self, node: &Node, source: &str, handlers: &mut HashSet<String>) {
        for n in query::find_descendants(*node, |_| true) {
            // Check for signal(SIG..., handler) pattern
            if n.kind() == "call_expression" {
                if let Some(function) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);
                    if func_name == "signal" {
                        if let Some(args) = n.child_by_field_name("arguments") {
                            // Second argument is the handler
                            let mut arg_idx = 0;
                            let mut cursor = args.walk();
                            for child in args.children(&mut cursor) {
                                if child.kind() != "," && child.kind() != "(" && child.kind() != ")"
                                {
                                    arg_idx += 1;
                                    if arg_idx == 2 {
                                        let handler_name =
                                            get_node_text(&child, source).trim().to_string();
                                        if !handler_name.starts_with("SIG_") {
                                            handlers.insert(handler_name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check for sigaction: .sa_handler = func_name or act.sa_handler = func_name
            if n.kind() == "assignment_expression" {
                if let Some(left) = n.child_by_field_name("left") {
                    let left_text = get_node_text(&left, source);
                    if left_text.contains("sa_handler") || left_text.contains("sa_sigaction") {
                        if let Some(right) = n.child_by_field_name("right") {
                            let handler_name = get_node_text(&right, source).trim().to_string();
                            if !handler_name.is_empty() && !handler_name.starts_with("SIG_") {
                                handlers.insert(handler_name);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Extract just the function name from a declarator node
    fn get_function_name(&self, declarator: &Node, source: &str) -> String {
        // For function_declarator nodes, get the nested declarator (function name)
        if declarator.kind() == "function_declarator" {
            if let Some(name_node) = declarator.child_by_field_name("declarator") {
                return get_node_text(&name_node, source).trim().to_string();
            }
        }
        // Fallback: extract function name by splitting on '(' to remove parameters
        let declarator_text = get_node_text(declarator, source);
        declarator_text
            .split('(')
            .next()
            .unwrap_or(&declarator_text)
            .trim()
            .to_string()
    }

    /// Check if a function definition saves and restores errno (compliance pattern)
    fn has_errno_save_restore(&self, func_node: &Node, source: &str) -> bool {
        let func_text = get_node_text(func_node, source);
        // Pattern: saves errno at start and restores it at end
        // Look for: save_var = errno; ... errno = save_var;
        // Common patterns: save_errno, saved_errno, errno_save, old_errno
        let save_patterns = [
            "save_errno",
            "saved_errno",
            "errno_save",
            "old_errno",
            "errno_saved",
        ];

        for pattern in &save_patterns {
            // Check for save: pattern = errno
            let has_save = func_text.contains(&format!("{} = errno", pattern))
                || func_text.contains(&format!("{}=errno", pattern));
            // Check for restore: errno = pattern
            let has_restore = func_text.contains(&format!("errno = {}", pattern))
                || func_text.contains(&format!("errno={}", pattern));

            if has_save && has_restore {
                return true;
            }
        }
        false
    }

    /// Check if we're in a signal handler function
    fn is_in_signal_handler(
        &self,
        node: &Node,
        source: &str,
        registered_handlers: &HashSet<String>,
    ) -> bool {
        let mut current = Some(*node);

        while let Some(n) = current {
            if n.kind() == "function_definition" {
                if let Some(declarator) = n.child_by_field_name("declarator") {
                    let func_name = self.get_function_name(&declarator, source);

                    // Check if registered as signal handler
                    if registered_handlers.contains(&func_name) {
                        return true;
                    }

                    // Also use heuristic: name contains "handler" or starts with "sig"
                    let lower_name = func_name.to_lowercase();
                    if lower_name.contains("handler") || lower_name.starts_with("sig") {
                        return true;
                    }
                }
                break;
            }
            current = n.parent();
        }
        false
    }

    /// Get the containing function definition for a node
    fn get_containing_function<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = Some(*node);
        while let Some(n) = current {
            if n.kind() == "function_definition" {
                return Some(n);
            }
            current = n.parent();
        }
        None
    }

    /// Check for errno usage in signal handlers
    fn check_errno_in_handler(
        &self,
        node: &Node,
        source: &str,
        registered_handlers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "identifier" {
            let name = get_node_text(node, source);
            if name == "errno" && self.is_in_signal_handler(node, source, registered_handlers) {
                // Check if the containing function has errno save/restore pattern
                if let Some(func_node) = self.get_containing_function(node) {
                    if self.has_errno_save_restore(&func_node, source) {
                        return; // Compliant: errno is saved and restored
                    }
                }

                violations.push(RuleViolation {
                    rule_id: "ERR32-C".to_string(),
                    severity: Severity::High,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: "errno should not be used in signal handlers".to_string(),
                    file_path: String::new(),
                    suggestion: Some(
                        "Save and restore errno in signal handler if needed".to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    /// Check for perror/strerror in signal handlers (they use errno)
    fn check_error_functions_in_handler(
        &self,
        node: &Node,
        source: &str,
        registered_handlers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if (func_name == "perror" || func_name == "strerror")
                    && self.is_in_signal_handler(node, source, registered_handlers)
                {
                    violations.push(RuleViolation {
                        rule_id: "ERR32-C".to_string(),
                        severity: Severity::High,
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        message: format!(
                            "{}() should not be called in signal handlers (uses errno)",
                            func_name
                        ),
                        file_path: String::new(),
                        suggestion: Some(
                            "Avoid error reporting functions in signal handlers".to_string(),
                        ),
                        requires_manual_review: Some(false),
                    });
                }
            }
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        registered_handlers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            self.check_errno_in_handler(&n, source, registered_handlers, violations);
            self.check_error_functions_in_handler(&n, source, registered_handlers, violations);
        }
    }
}

impl Default for Err32C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Err32C {
    fn rule_id(&self) -> &'static str {
        "ERR32-C"
    }

    fn description(&self) -> &'static str {
        "Do not rely on indeterminate values of errno"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ERR32-C"
    }

    fn check(&self, root_node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect signal handler function names
        let mut registered_handlers = HashSet::new();
        self.collect_signal_handlers(root_node, source, &mut registered_handlers);

        // Second pass: check errno/perror/strerror usage in handlers
        self.check_node(root_node, source, &registered_handlers, &mut violations);

        violations
    }
}
