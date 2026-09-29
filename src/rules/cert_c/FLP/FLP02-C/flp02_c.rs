// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

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
//! <https://wiki.sei.cmu.edu/confluence/display/c/FLP02-C.+Avoid+using+floating-point+numbers+when+precise+computation+is+needed>

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::VisibleTypes;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::expr_type::{self, TypeEnv};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct Flp02C {
    /// The typedefs and struct fields this file sees, so an operand declared
    /// `real` (a typedef of double) or `p->ratio` is typed by its declaration.
    visible: RefCell<VisibleTypes>,
}

impl Flp02C {
    pub fn new() -> Self {
        Self::default()
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

    /// Whether the operand's value is of a floating type: its type by
    /// declaration (`expr_type`), or a `<math.h>` call's standard type. An
    /// operand whose type is not in reach is not floating-point: this check
    /// accuses, so an unknown type must not raise a finding.
    fn is_float_operand(&self, node: &Node, source: &str, env: &TypeEnv) -> bool {
        expr_type::expr_type(node, source, env)
            .or_else(|| expr_type::math_call_type(node, source))
            .is_some_and(|t| t.is_float())
    }

    /// Check if a binary expression is a floating-point equality comparison
    fn check_float_equality(
        &self,
        node: &Node,
        source: &str,
        env: &TypeEnv,
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

            let left_is_float = node
                .child_by_field_name("left")
                .is_some_and(|l| self.is_float_operand(&l, source, env));
            let right_is_float = node
                .child_by_field_name("right")
                .is_some_and(|r| self.is_float_operand(&r, source, env));

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

            // Only flag if BOTH operands are floating-point
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
}

impl CertRule for Flp02C {
    fn rule_id(&self) -> &'static str {
        "FLP02-C"
    }

    fn description(&self) -> &'static str {
        "Avoid using floating-point numbers when precise computation is needed"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "FLP02-C"
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible);
        let mut violations = Vec::new();
        for n in query::find_descendants_of_kind(*root, "binary_expression") {
            self.check_float_equality(&n, source, &env, &mut violations);
        }
        violations
    }
}
