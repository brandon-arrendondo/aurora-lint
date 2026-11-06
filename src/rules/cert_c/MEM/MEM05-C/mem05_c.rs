// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use std::cell::RefCell;

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::constant_expression::{
    in_block_scope, ConstantExpressions, Constness, ProjectTables,
};
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Default)]
pub struct Mem05C {
    /// The project's macro and typedef tables: an array size macro is
    /// usually defined in a header.
    project: RefCell<ProjectTables>,
}

impl CertRule for Mem05C {
    fn rule_id(&self) -> &'static str {
        "MEM05-C"
    }
    fn description(&self) -> &'static str {
        "Avoid large stack allocations"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cert_id(&self) -> &'static str {
        "MEM05-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = ProjectTables::from_context(context);
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Mem05C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let project = self.project.borrow();
        let constants = ConstantExpressions::new(*node, source, &project);
        for n in query::find_descendants(*node, |_| true) {
            // Look for array declarations with variable size (VLA)
            if n.kind() == "declaration" {
                // Use AST-based detection: look for array_declarator in the declaration.
                // This avoids false positives from array subscripts in initializers
                // (e.g., `uint8_t x = arr[i]` is NOT a VLA, but `uint8_t arr[n]` IS).
                if let Some((size_expr, size_node)) = Self::find_array_declarator_size(&n, source) {
                    // A size that is not an integer constant expression
                    // declares a VLA, whatever its names are spelled like. A
                    // name nothing in reach declares or defines is not taken
                    // for one: a VLA's size is read from an object with block
                    // scope (C11 6.7.6.2p2), which this file would declare.
                    if !size_expr.trim().is_empty()
                        && in_block_scope(&n)
                        && size_node.is_some_and(|size| {
                            constants.integer_constant_expression(&size) == Constness::NotConstant
                        })
                    {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            file_path: String::new(),
                            message: "Variable-length array with runtime-sized allocation; \
                                         use malloc instead"
                                .to_string(),
                            suggestion: Some(
                                "Use malloc/calloc for dynamic allocation".to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }

            // Check for recursive functions (potential stack overflow)
            if n.kind() == "function_definition" {
                if let Some(func_name) = self.extract_function_name(&n, source) {
                    if let Some(body) = n.child_by_field_name("body") {
                        if Self::body_calls_function(&body, source, &func_name) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                line: n.start_position().row + 1,
                                column: n.start_position().column + 1,
                                file_path: String::new(),
                                message: "Recursive function can cause excessive stack allocation"
                                    .to_string(),
                                suggestion: Some(
                                    "Consider iterative approach or limit recursion depth"
                                        .to_string(),
                                ),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Returns true if `body` (a compound_statement) contains a direct call to `func_name`.
    /// Uses AST traversal of call_expression nodes to avoid matching occurrences in
    /// string literals, comments, or the function's own declaration.
    fn body_calls_function(node: &Node, source: &str, func_name: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function) = n.child_by_field_name("function") else {
                return false;
            };
            function.utf8_text(source.as_bytes()).unwrap_or("") == func_name
        })
        .is_some()
    }

    /// Walk a declaration's AST to find an array_declarator and return its size expression,
    /// with the size's node when the parse has one.
    /// Returns None if the declaration doesn't contain an array_declarator (e.g., it's a
    /// scalar declaration like `uint8_t x = arr[i]` where `[i]` is a subscript, not a size).
    fn find_array_declarator_size<'a>(
        decl_node: &Node<'a>,
        source: &str,
    ) -> Option<(String, Option<Node<'a>>)> {
        Self::find_array_size_recursive(decl_node, source)
    }

    fn find_array_size_recursive<'a>(
        node: &Node<'a>,
        source: &str,
    ) -> Option<(String, Option<Node<'a>>)> {
        if node.kind() == "array_declarator" {
            // The array size is the child in brackets, typically the `size` field
            // or the last child before `]`
            if let Some(size_node) = node.child_by_field_name("size") {
                let size_text = size_node
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_string();
                return Some((size_text, Some(size_node)));
            }
            // Fallback: extract text between [ and ]
            let text = node.utf8_text(source.as_bytes()).unwrap_or("");
            if let Some(start) = text.find('[') {
                // Search for the `]` after the `[`: a `]` earlier in the text
                // (in a comment, say) must not reverse the range.
                if let Some(end) = text[start + 1..].find(']') {
                    let size = text[start + 1..start + 1 + end].trim().to_string();
                    if !size.is_empty() {
                        return Some((size, None));
                    }
                }
            }
            return None;
        }
        // Recurse into children but skip init_declarator's value (the initializer)
        // to avoid matching subscript expressions on the RHS of assignments
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                // Skip the value/initializer — subscripts there are NOT array declarations
                if node.kind() == "init_declarator"
                    && node.child_by_field_name("value").map(|v| v.id()) == Some(child.id())
                {
                    continue;
                }
                if let Some(size) = Self::find_array_size_recursive(&child, source) {
                    return Some(size);
                }
            }
        }
        None
    }

    fn extract_function_name(&self, node: &Node, source: &str) -> Option<String> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "function_declarator" {
                let mut inner_cursor = child.walk();
                for inner_child in child.children(&mut inner_cursor) {
                    if inner_child.kind() == "identifier" {
                        return Some(
                            inner_child
                                .utf8_text(source.as_bytes())
                                .unwrap_or("")
                                .to_string(),
                        );
                    }
                }
            }
        }
        None
    }
}
