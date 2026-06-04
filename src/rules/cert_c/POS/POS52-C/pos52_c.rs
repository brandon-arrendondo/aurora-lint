// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

//! POS52-C: Do not perform operations that can block while holding a POSIX lock
//!
//! Blocking operations (I/O, network calls) should not be performed while holding a mutex.

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;

pub struct Pos52C;

impl CertRule for Pos52C {
    fn rule_id(&self) -> &'static str {
        "POS52-C"
    }

    fn description(&self) -> &'static str {
        "Do not perform operations that can block while holding a POSIX lock"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS52-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Pos52C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for function bodies that contain mutex locks
        if node.kind() == "compound_statement" {
            self.check_for_lock_and_blocking(&node, source, violations);
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, violations);
        }
    }

    /// Check if a block contains pthread_mutex_lock followed by blocking operations
    fn check_for_lock_and_blocking(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let statements = self.get_statements(node);
        let mut locked = false;
        let mut lock_line = 0;

        for stmt in statements {
            if let Some(call) = self.find_call_expression(&stmt, source) {
                let func_name = self.get_function_name(&call, source);

                if func_name == "pthread_mutex_lock" {
                    locked = true;
                    lock_line = call.start_position().row + 1;
                } else if func_name == "pthread_mutex_unlock" {
                    locked = false;
                } else if locked && self.is_blocking_function(&func_name) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        file_path: String::new(),
                        message: format!(
                            "Blocking function '{}' called while holding mutex (locked at line {}). \
                            This can cause deadlocks and poor performance.",
                            func_name, lock_line
                        ),
                        suggestion: Some(
                            "Perform blocking operations before acquiring or after releasing the mutex.".to_string()
                        ),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    /// Get all statements in a compound statement
    fn get_statements<'a>(&self, node: &Node<'a>) -> Vec<Node<'a>> {
        let mut statements = Vec::new();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() != "{" && child.kind() != "}" {
                statements.push(child);
            }
        }
        statements
    }

    /// Find a call expression in a statement (handles if statements, etc.)
    fn find_call_expression<'a>(&self, node: &Node<'a>, source: &str) -> Option<Node<'a>> {
        if node.kind() == "call_expression" {
            return Some(*node);
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(call) = self.find_call_expression(&child, source) {
                return Some(call);
            }
        }

        None
    }

    /// Get function name from a call expression
    fn get_function_name(&self, node: &Node, source: &str) -> String {
        if let Some(func) = node.child_by_field_name("function") {
            return get_node_text(&func, source).trim().to_string();
        }
        String::new()
    }

    /// Check if a function is a blocking operation
    fn is_blocking_function(&self, func_name: &str) -> bool {
        matches!(
            func_name,
            // Network I/O
            "recv" | "recvfrom" | "recvmsg" | "send" | "sendto" | "sendmsg" |
            "accept" | "connect" |
            // File I/O
            "read" | "write" | "fread" | "fwrite" |
            "fgets" | "fputs" | "fgetc" | "fputc" |
            // Other blocking operations
            "sleep" | "usleep" | "nanosleep" |
            "wait" | "waitpid" | "pause" |
            "select" | "poll" | "epoll_wait"
        )
    }
}
