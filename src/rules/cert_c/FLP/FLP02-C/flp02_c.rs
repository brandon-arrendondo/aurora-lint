// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! FLP02-C: Avoid using floating-point numbers when precise computation is needed
//!
//! This rule detects misuse of floating-point arithmetic when exact computational
//! results are required. Binary floating-point cannot precisely represent many
//! decimal values (e.g., 1/3, 1/5), leading to cumulative rounding errors.
//!
//! ## Key Violations:
//! - Floating-point equality/inequality comparisons
//! - Using float/double for financial or other precision-critical calculations
//! - Accumulating floating-point values where exact results matter
//!
//! ## Noncompliant Code Example (Equality Comparison):
//! ```c
//! float x = 10.1;
//! float y = 10.1;
//! if (x == y) {  // VIOLATION: Floating-point equality comparison
//!     // May fail due to representation error
//! }
//! ```
//!
//! ## Noncompliant Code Example (Accumulation):
//! ```c
//! float sum = 0.0f;
//! for (int i = 0; i < 10; i++) {
//!     sum += 0.1f;  // Cumulative error: sum != 1.0
//! }
//! if (sum == 1.0f) {  // VIOLATION: Will likely fail
//!     // ...
//! }
//! ```
//!
//! ## Compliant Solutions:
//!
//! **Use epsilon comparison:**
//! ```c
//! #define EPSILON 0.0001
//! if (fabs(x - y) < EPSILON) {  // Compliant
//!     // ...
//! }
//! ```
//!
//! **Use integer arithmetic:**
//! ```c
//! int cents = 1010;  // Represent 10.10 as integer
//! // Perform arithmetic on cents
//! float dollars = cents / 100.0f;  // Convert only for display
//! ```
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/FLP02-C.+Avoid+using+floating-point+numbers+when+precise+computation+is+needed

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::float_typing;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Flp02C;

impl Flp02C {
    pub fn new() -> Self {
        Flp02C
    }

    /// Check if type is a floating-point type
    fn is_float_type(&self, type_text: &str) -> bool {
        float_typing::is_float_type(type_text)
    }

    /// Check if operator is equality or inequality
    fn is_equality_operator(&self, op: &str) -> bool {
        op == "==" || op == "!="
    }

    /// Check if a literal is an exact-zero float (0.0, 0.0f, 0.0F, -0.0, etc.)
    fn is_zero_float_literal(text: &str) -> bool {
        let t = text
            .trim()
            .trim_start_matches('-')
            .trim_end_matches(['f', 'F', 'l', 'L']);
        matches!(t, "0.0" | "0." | ".0" | "0")
    }

    /// Get the type of an expression (simplified heuristic)
    /// Checks if expression or any of its descendants contain floating-point characteristics
    #[allow(dead_code)]
    fn appears_to_be_float_expression(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| self.has_float_characteristics(&n, source))
            .is_some()
    }

    /// Check if a node itself has floating-point characteristics
    /// Only checks via AST node kinds to avoid false positives from text matching
    fn has_float_characteristics(&self, node: &Node, source: &str) -> bool {
        let kind = node.kind();

        // Only check number_literal nodes for float literal patterns
        if kind == "number_literal" {
            let text = get_node_text(node, source);
            // Decimal point (but not -> or ...)
            if text.contains('.') && !text.contains("->") && !text.contains("...") {
                return true;
            }
            // 'f'/'F' suffix on number literal
            if text.ends_with('f') || text.ends_with('F') {
                return true;
            }
            // Scientific notation on number literal
            if text.contains('e') || text.contains('E') {
                return true;
            }
        }

        // Only check cast_expression nodes for float casts
        if kind == "cast_expression" {
            if let Some(type_node) = node.child_by_field_name("type") {
                let type_text = get_node_text(&type_node, source);
                if type_text.contains("float") || type_text.contains("double") {
                    return true;
                }
            }
        }

        // Only check call_expression nodes for float function calls
        if kind == "call_expression" {
            if let Some(func_node) = node.child_by_field_name("function") {
                if func_node.kind() == "identifier" {
                    let func_name = get_node_text(&func_node, source);
                    let float_funcs = [
                        "sqrtf", "sqrt", "powf", "pow", "sinf", "sin", "cosf", "cos", "tanf",
                        "tan", "logf", "log", "expf", "exp", "fabsf", "fabs",
                    ];
                    if float_funcs.contains(&func_name) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Collect float/double variable names from declarations
    fn collect_float_variables(&self, node: &Node, source: &str, float_vars: &mut HashSet<String>) {
        for n in query::find_descendants_of_kinds(*node, &["declaration", "parameter_declaration"])
        {
            let decl_text = get_node_text(&n, source);
            if self.is_float_type(&decl_text) {
                // Extract identifier names from this declaration
                self.extract_identifiers(&n, source, float_vars);
            }
        }
    }

    /// Extract identifier names from a declaration node
    fn extract_identifiers(&self, node: &Node, source: &str, identifiers: &mut HashSet<String>) {
        for n in query::find_descendants_of_kind(*node, "identifier") {
            identifiers.insert(get_node_text(&n, source).to_string());
        }
    }

    /// Check if an expression involves a float variable
    fn involves_float_variable(
        &self,
        node: &Node,
        source: &str,
        float_vars: &HashSet<String>,
    ) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() == "identifier" && float_vars.contains(get_node_text(&n, source)) {
                return true;
            }
            self.has_float_characteristics(&n, source)
        })
        .is_some()
    }

    /// Check if a binary expression is a floating-point equality comparison
    fn check_float_equality(
        &self,
        node: &Node,
        source: &str,
        float_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "binary_expression" {
            return;
        }

        // Get the operator
        if let Some(operator_node) = node.child_by_field_name("operator") {
            let operator = get_node_text(&operator_node, source);

            if !self.is_equality_operator(operator) {
                return;
            }

            // Check if either operand involves floating-point
            let left_is_float = if let Some(left) = node.child_by_field_name("left") {
                self.involves_float_variable(&left, source, float_vars)
            } else {
                false
            };

            let right_is_float = if let Some(right) = node.child_by_field_name("right") {
                self.involves_float_variable(&right, source, float_vars)
            } else {
                false
            };

            // Skip comparisons against exact zero (0.0, 0.0f, -0.0, etc.)
            // Zero is exactly representable in IEEE 754 — comparing to zero is
            // a standard divide-by-zero guard pattern, not an epsilon issue.
            let left_text = node
                .child_by_field_name("left")
                .map(|n| get_node_text(&n, source).to_string())
                .unwrap_or_default();
            let right_text = node
                .child_by_field_name("right")
                .map(|n| get_node_text(&n, source).to_string())
                .unwrap_or_default();
            if Self::is_zero_float_literal(&left_text) || Self::is_zero_float_literal(&right_text) {
                return;
            }

            // Only flag if BOTH operands involve floating-point
            // This avoids false positives when comparing float to integer literals
            if left_is_float && right_is_float {
                violations.push(RuleViolation {
                    rule_id: "FLP02-C".to_string(),
                    severity: Severity::Low,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: format!(
                        "Floating-point {} comparison may produce unexpected results due to representation error",
                        if operator == "==" { "equality" } else { "inequality" }
                    ),
                    file_path: String::new(),
                    suggestion: Some(
                        "Use epsilon-based comparison (e.g., fabs(x - y) < EPSILON) or consider using integer arithmetic for precise computation".to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    /// Recursively traverse AST
    fn traverse(
        &self,
        node: &Node,
        source: &str,
        float_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for floating-point equality comparisons
        for n in query::find_descendants_of_kind(*node, "binary_expression") {
            self.check_float_equality(&n, source, float_vars, violations);
        }
    }
}

impl CertRule for Flp02C {
    fn rule_id(&self) -> &'static str {
        "FLP02-C"
    }

    fn description(&self) -> &'static str {
        "Avoid using floating-point numbers when precise computation is needed"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "FLP02-C"
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        // First pass: collect all float/double variable names
        let mut float_vars = HashSet::new();
        self.collect_float_variables(root, source, &mut float_vars);

        // Second pass: check for floating-point equality comparisons
        let mut violations = Vec::new();
        self.traverse(root, source, &float_vars, &mut violations);
        violations
    }
}
