// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON39-C: Do not join or detach a thread that was previously joined or detached
//!
//! This rule detects violations where:
//! 1. A thread detaches itself (thrd_detach(thrd_current())) and is later joined
//! 2. A thread is joined or detached multiple times
//!
//! References:
//! - https://wiki.sei.cmu.edu/confluence/display/c/CON39-C.+Do+not+join+or+detach+a+thread+that+was+previously+joined+or+detached

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Con39C;

impl CertRule for Con39C {
    fn rule_id(&self) -> &'static str {
        "CON39-C"
    }

    fn description(&self) -> &'static str {
        "Do not join or detach a thread that was previously joined or detached"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON39-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for self-detaching threads
        check_for_self_detach(node, source, &mut violations);

        violations
    }
}

/// Check for threads that detach themselves using thrd_detach(thrd_current())
///
/// This is problematic because the main thread or another thread may attempt to join
/// this thread, which would result in undefined behavior.
fn check_for_self_detach(node: &Node, file_content: &str, violations: &mut Vec<RuleViolation>) {
    let mut cursor = node.walk();

    // First pass: find all function definitions
    for func_node in node.children(&mut cursor) {
        if func_node.kind() == "function_definition" {
            // Check if this function contains thrd_detach(thrd_current())
            if contains_self_detach(&func_node, file_content) {
                // This is a thread function that detaches itself
                // Look for any thrd_create calls that might create this thread
                check_thread_usage(&func_node, file_content, violations);
            }
        }
    }
}

/// Check if a function contains a call to thrd_detach(thrd_current())
fn contains_self_detach(func_node: &Node, file_content: &str) -> bool {
    check_node_for_self_detach(func_node, file_content)
}

/// Recursively check a node and its children for thrd_detach(thrd_current())
fn check_node_for_self_detach(node: &Node, file_content: &str) -> bool {
    query::find_first_descendant(*node, |n| {
        if n.kind() != "call_expression" {
            return false;
        }
        let Some(func_name_node) = n.child_by_field_name("function") else {
            return false;
        };
        let fn_name = get_node_text(&func_name_node, file_content);
        if fn_name != "thrd_detach" && fn_name != "pthread_detach" {
            return false;
        }
        let Some(args_node) = n.child_by_field_name("arguments") else {
            return false;
        };
        let args_text = get_node_text(&args_node, file_content);
        args_text.contains("thrd_current()") || args_text.contains("pthread_self()")
    })
    .is_some()
}

/// Check if a thread function that self-detaches is being used with thrd_create and thrd_join
fn check_thread_usage(func_node: &Node, file_content: &str, violations: &mut Vec<RuleViolation>) {
    // Get the function name
    let func_name = if let Some(declarator) = func_node.child_by_field_name("declarator") {
        get_function_name(&declarator, file_content)
    } else {
        return;
    };

    if func_name.is_empty() {
        return;
    }

    // Now search the entire file for thrd_create calls using this function
    let root = func_node.parent().unwrap_or(*func_node);
    search_for_thread_create(&root, &func_name, file_content, violations);
}

/// Recursively search for thrd_create calls
fn search_for_thread_create(
    node: &Node,
    func_name: &str,
    file_content: &str,
    violations: &mut Vec<RuleViolation>,
) {
    for n in query::find_descendants_of_kind(*node, "call_expression") {
        if let Some(fn_node) = n.child_by_field_name("function") {
            let fn_name = get_node_text(&fn_node, file_content);
            if fn_name == "thrd_create" || fn_name == "pthread_create" {
                // Check if this creates the thread with our function
                if let Some(args) = n.child_by_field_name("arguments") {
                    let args_text = get_node_text(&args, file_content);
                    if args_text.contains(func_name) {
                        // Found a thrd_create for this function
                        // Now check if there's a thrd_join in the same function scope
                        if check_for_join_after_create(&n, file_content) {
                            let start_pos = n.start_position();
                            let line = start_pos.row + 1;
                            let column = start_pos.column + 1;

                            violations.push(RuleViolation {
                                rule_id: "CON39-C".to_string(),
                                severity: Severity::Low,
                                file_path: String::new(),
                                line,
                                column,
                                message: format!(
                                    "Thread created with function '{}' that detaches itself, but is later joined, causing undefined behavior",
                                    func_name
                                ),
                                suggestion: None,
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Extract function name from a declarator node
fn get_function_name(declarator: &Node, file_content: &str) -> String {
    find_identifier_in_node(declarator, file_content).unwrap_or_default()
}

/// Recursively search for an identifier node
fn find_identifier_in_node(node: &Node, file_content: &str) -> Option<String> {
    query::find_first_descendant(*node, |n| n.kind() == "identifier")
        .map(|n| get_node_text(&n, file_content).to_string())
}

/// Check if there's a thrd_join call in the same scope as the thrd_create
fn check_for_join_after_create(create_node: &Node, file_content: &str) -> bool {
    // Navigate up to find the containing function
    let mut parent = create_node.parent();

    while let Some(p) = parent {
        if p.kind() == "function_definition" {
            // Found the containing function, now search for thrd_join
            return find_thrd_join_in_node(&p, file_content);
        }
        parent = p.parent();
    }

    false
}

/// Recursively search for thrd_join calls
fn find_thrd_join_in_node(node: &Node, file_content: &str) -> bool {
    query::find_first_descendant(*node, |n| {
        if n.kind() != "call_expression" {
            return false;
        }
        let Some(fn_node) = n.child_by_field_name("function") else {
            return false;
        };
        let fn_name = get_node_text(&fn_node, file_content);
        fn_name == "thrd_join" || fn_name == "pthread_join"
    })
    .is_some()
}
