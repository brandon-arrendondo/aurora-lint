// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Ryan Bissell

//! CON43-C: Do not allow data races in multithreaded code
//!
//! This rule detects potential data races in multithreaded code, including:
//! - Static volatile variables accessed by multiple functions without proper synchronization
//! - Multiple dereferences of pointer parameters (double-fetch vulnerability)
//!
//! References:
//! - https://wiki.sei.cmu.edu/confluence/display/c/CON43-C.+Do+not+allow+data+races+in+multithreaded+code

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

pub struct Con43C;

impl CertRule for Con43C {
    fn rule_id(&self) -> &'static str {
        "CON43-C"
    }

    fn description(&self) -> &'static str {
        "Do not allow data races in multithreaded code"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON43-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for static volatile variables (data race risk)
        check_static_volatile(node, source, &mut violations);

        // Check for double-fetch vulnerabilities
        check_double_fetch(node, source, &mut violations);

        violations
    }
}

/// Check for static volatile variables that may be accessed without synchronization
fn check_static_volatile(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    if node.kind() == "declaration" {
        let text = get_node_text(node, source);

        // Check if this is a static volatile variable
        if text.contains("static") && text.contains("volatile") {
            // Extract variable name
            if let Some(var_name) = extract_var_name(node, source) {
                violations.push(RuleViolation {
                    rule_id: "CON43-C".to_string(),
                    file_path: "".to_string(),
                    message: format!(
                        "Static volatile variable '{}' may be accessed by multiple threads without synchronization",
                        var_name
                    ),
                    line: node.start_position().row + 1,
                    column: node.start_position().column,
                    severity: Severity::High,
                    suggestion: Some("Use atomic operations, mutex locks, or other synchronization primitives to protect shared data".to_string()),
                    requires_manual_review: Some(true),
                });
            }
        }
    }

    // Recurse through children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_static_volatile(&child, source, violations);
    }
}

/// Check for double-fetch vulnerabilities (multiple pointer dereferences in control flow)
fn check_double_fetch(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    // Look for switch statements with pointer dereferences
    if node.kind() == "switch_statement" {
        if let Some(condition) = get_switch_condition(node) {
            // Check if the condition contains a pointer dereference
            if contains_pointer_deref(&condition, source) {
                // Check if the parent function has synchronization
                if !has_synchronization_nearby(node, source) {
                    violations.push(RuleViolation {
                        rule_id: "CON43-C".to_string(),
                        file_path: "".to_string(),
                        message: "Dereferencing pointer in switch statement may create double-fetch vulnerability".to_string(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column,
                        severity: Severity::High,
                        suggestion: Some("Store dereferenced value in a local variable or use atomic operations".to_string()),
                        requires_manual_review: Some(true),
                    });
                }
            }
        }
    }

    // Recurse through children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_double_fetch(&child, source, violations);
    }
}

/// Check if there is synchronization (mutex, atomic) nearby
fn has_synchronization_nearby(node: &Node, source: &str) -> bool {
    // Look for parent function
    let mut current = *node;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_definition" {
            // Check if function uses synchronization primitives
            let text = get_node_text(&parent, source);
            if text.contains("mtx_lock")
                || text.contains("atomic_")
                || text.contains("pthread_mutex")
            {
                return true;
            }
            break;
        }
        current = parent;
    }
    false
}

/// Check if a node contains a pointer dereference
#[allow(clippy::only_used_in_recursion)]
fn contains_pointer_deref(node: &Node, source: &str) -> bool {
    if node.kind() == "pointer_expression" {
        return true;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if contains_pointer_deref(&child, source) {
            return true;
        }
    }
    false
}

/// Extract variable name from a declaration
fn extract_var_name(node: &Node, source: &str) -> Option<String> {
    find_identifier(node, source)
}

/// Recursively find an identifier node
fn find_identifier(node: &Node, source: &str) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(get_node_text(node, source).to_string());
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(id) = find_identifier(&child, source) {
            return Some(id);
        }
    }
    None
}

/// Get the condition node from a switch statement
fn get_switch_condition<'a>(node: &'a Node) -> Option<Node<'a>> {
    let mut cursor = node.walk();
    let result = node
        .children(&mut cursor)
        .find(|child| child.kind() == "parenthesized_expression");
    result
}
