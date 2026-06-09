// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use tree_sitter::Node;

pub struct Mem05C;

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
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "MEM05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Mem05C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for array declarations with variable size (VLA)
        if node.kind() == "declaration" {
            // Use AST-based detection: look for array_declarator in the declaration.
            // This avoids false positives from array subscripts in initializers
            // (e.g., `uint8_t x = arr[i]` is NOT a VLA, but `uint8_t arr[n]` IS).
            if let Some(size_expr) = Self::find_array_declarator_size(node, source) {
                let size_expr = size_expr.trim();
                // If size is not a numeric constant, it might be a VLA.
                // ALL_CAPS identifiers are likely preprocessor constants.
                if !size_expr.is_empty()
                    && !size_expr.chars().all(|c| c.is_numeric())
                    && !Self::is_likely_macro_constant(size_expr)
                {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        message: "Variable-length array with runtime-sized allocation; \
                                     use malloc instead"
                            .to_string(),
                        suggestion: Some("Use malloc/calloc for dynamic allocation".to_string()),
                        requires_manual_review: None,
                    });
                }
            }
        }

        // Check for recursive functions (potential stack overflow)
        if node.kind() == "function_definition" {
            if let Some(func_name) = self.extract_function_name(node, source) {
                if let Some(body) = node.child_by_field_name("body") {
                    if Self::body_calls_function(&body, source, &func_name) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            file_path: String::new(),
                            message: "Recursive function can cause excessive stack allocation"
                                .to_string(),
                            suggestion: Some(
                                "Consider iterative approach or limit recursion depth".to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }

        // Recursively check children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, violations);
        }
    }

    /// Returns true if `body` (a compound_statement) contains a direct call to `func_name`.
    /// Uses AST traversal of call_expression nodes to avoid matching occurrences in
    /// string literals, comments, or the function's own declaration.
    fn body_calls_function(node: &Node, source: &str, func_name: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let callee = function.utf8_text(source.as_bytes()).unwrap_or("");
                if callee == func_name {
                    return true;
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if Self::body_calls_function(&child, source, func_name) {
                return true;
            }
        }
        false
    }

    /// Check if a size expression is likely a preprocessor macro constant.
    /// ALL_CAPS identifiers with optional underscores are conventionally macros.
    /// Walk a declaration's AST to find an array_declarator and return its size expression.
    /// Returns None if the declaration doesn't contain an array_declarator (e.g., it's a
    /// scalar declaration like `uint8_t x = arr[i]` where `[i]` is a subscript, not a size).
    fn find_array_declarator_size(decl_node: &Node, source: &str) -> Option<String> {
        Self::find_array_size_recursive(decl_node, source)
    }

    fn find_array_size_recursive(node: &Node, source: &str) -> Option<String> {
        if node.kind() == "array_declarator" {
            // The array size is the child in brackets, typically the `size` field
            // or the last child before `]`
            if let Some(size_node) = node.child_by_field_name("size") {
                let size_text = size_node
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_string();
                return Some(size_text);
            }
            // Fallback: extract text between [ and ]
            let text = node.utf8_text(source.as_bytes()).unwrap_or("");
            if let (Some(start), Some(end)) = (text.find('['), text.find(']')) {
                let size = text[start + 1..end].trim().to_string();
                if !size.is_empty() {
                    return Some(size);
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

    fn is_likely_macro_constant(expr: &str) -> bool {
        !expr.is_empty()
            && expr
                .chars()
                .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
            && expr
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
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
