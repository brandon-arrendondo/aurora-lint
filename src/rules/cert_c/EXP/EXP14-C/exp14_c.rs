//! EXP14-C: Beware of integer promotion when performing bitwise operations on integer types smaller than int
//!
//! When performing bitwise operations on types smaller than int (e.g., char, uint8_t, int8_t),
//! the C standard automatically promotes these values to int. This can cause unexpected results
//! because the bitwise operation is performed on the promoted (wider) value.
//!
//! ## Examples:
//!
//! **Non-compliant (missing explicit cast):**
//! ```c
//! uint8_t port = 0x5a;
//! uint8_t result_8 = (~port) >> 4;  // Violates EXP14-C - implicit promotion
//! ```
//!
//! **Compliant (explicit cast):**
//! ```c
//! uint8_t port = 0x5a;
//! uint8_t result_8 = (uint8_t)(~port) >> 4;  // Explicit cast prevents issues
//! ```
//!
//! ## Detection Strategy:
//! - Identify assignment expressions where small integer types are assigned
//! - Check if the RHS contains bitwise operations on small types
//! - Verify if there's an explicit cast to the target type
//! - Flag violations where no explicit cast wraps the bitwise operation

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp14C;

impl CertRule for Exp14C {
    fn rule_id(&self) -> &'static str {
        "EXP14-C"
    }

    fn description(&self) -> &'static str {
        "Beware of integer promotion when performing bitwise operations on integer types smaller than int"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP14-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        check_node(node, source, &mut violations);
        violations
    }
}

/// Recursively checks nodes for bitwise operations on small integer types without explicit casts
fn check_node(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    for n in query::find_descendants(*node, |_| true) {
        match n.kind() {
            "assignment_expression" => check_assignment(&n, source, violations),
            "init_declarator" => check_init_declarator(&n, source, violations),
            _ => {}
        }
    }
}

/// Checks an assignment expression for bitwise operations on small types
fn check_assignment(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    // Get left side (variable being assigned to)
    if let Some(left) = node.child_by_field_name("left") {
        let _left_text = ast_utils::get_node_text(&left, source);

        // Check if left side appears to be a small integer type variable
        // We'll check the right side for bitwise operations
        if let Some(right) = node.child_by_field_name("right") {
            check_bitwise_expression(&right, source, violations);
        }
    }
}

/// Checks an init declarator (variable declaration with initialization)
fn check_init_declarator(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    // Get declarator and value
    if let Some(value) = node.child_by_field_name("value") {
        check_bitwise_expression(&value, source, violations);
    }
}

/// Checks if an expression contains bitwise operations on small types without explicit casts
fn check_bitwise_expression(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    // If this node is a cast_expression, don't check inside it - the cast handles promotion
    if node.kind() == "cast_expression" {
        return;
    }

    match node.kind() {
        "unary_expression" => {
            // Check for bitwise NOT (~)
            if let Some(operator) = node.child_by_field_name("operator") {
                let op_text = ast_utils::get_node_text(&operator, source);
                if op_text == "~" {
                    // Check if the result is used in a context that suggests small integer type
                    // and there's no explicit cast
                    if !is_wrapped_in_cast(node) {
                        violations.push(RuleViolation {
                            rule_id: "EXP14-C".to_string(),
                            severity: Severity::Medium,
                            message: "Bitwise operation on type smaller than int may cause unexpected integer promotion. Use explicit cast to control promotion behavior.".to_string(),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Wrap the bitwise operation with an explicit cast: (uint8_t)(~value)".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        "binary_expression" => {
            // Check for bitwise operators that are genuinely risky after promotion.
            // &, |, ^, >> are safe: promotion widens but the result, when truncated
            // back to the small type, is identical to the non-promoted result.
            // Only ~ (unary, handled above) and << are risky: ~ sign-extends the
            // upper bits, and << can produce a value wider than the original type.
            if let Some(operator) = node.child_by_field_name("operator") {
                let op_text = ast_utils::get_node_text(&operator, source);
                if matches!(op_text, "<<") {
                    // Check if left operand has an explicit cast
                    let left_has_cast = if let Some(left) = node.child_by_field_name("left") {
                        left.kind() == "cast_expression"
                    } else {
                        false
                    };

                    if !left_has_cast && !is_wrapped_in_cast(node) {
                        violations.push(RuleViolation {
                            rule_id: "EXP14-C".to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Bitwise operation '{}' on type smaller than int may cause unexpected integer promotion. Use explicit cast to control promotion behavior.",
                                op_text
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Wrap the bitwise operation with an explicit cast: (uint8_t)(value & mask)".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
        _ => {}
    }

    // Recursively check children
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        check_bitwise_expression(&child, source, violations);
    }
}

/// Checks if a node is wrapped in a cast expression
fn is_wrapped_in_cast(node: &Node) -> bool {
    if let Some(parent) = node.parent() {
        // Check if parent is a cast_expression
        if parent.kind() == "cast_expression" {
            // Verify this node is the value being cast
            if let Some(value) = parent.child_by_field_name("value") {
                if value.id() == node.id() {
                    return true;
                }
            }
        }

        // Check if parent is a parenthesized expression that's inside a cast
        if parent.kind() == "parenthesized_expression" {
            return is_wrapped_in_cast(&parent);
        }
    }
    false
}
