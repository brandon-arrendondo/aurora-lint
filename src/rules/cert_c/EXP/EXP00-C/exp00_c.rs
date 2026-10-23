// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp00C;

impl CertRule for Exp00C {
    fn rule_id(&self) -> &'static str {
        "EXP00-C"
    }

    fn description(&self) -> &'static str {
        "Use parentheses for precedence of operation"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "EXP00-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for binary expressions with precedence issues
        for bin_node in query::find_descendants_of_kind(*node, "binary_expression") {
            if let Some(operator_node) = bin_node.child_by_field_name("operator") {
                let operator = get_node_text(&operator_node, source);

                // Check if this is a comparison operator
                if is_comparison_operator(operator) {
                    // Check left operand for bitwise operators
                    if let Some(left) = bin_node.child_by_field_name("left") {
                        if has_unparenthesized_bitwise_operator(&left, source) {
                            report_violation(&left, source, &mut violations);
                        }
                    }

                    // Check right operand for bitwise operators
                    if let Some(right) = bin_node.child_by_field_name("right") {
                        if has_unparenthesized_bitwise_operator(&right, source) {
                            report_violation(&right, source, &mut violations);
                        }
                    }
                }
                // A bitwise operator with a comparison as a direct operand:
                // `a & b == c` reads as `a & (b == c)`. A comparison inside
                // parentheses or a call's arguments is already grouped, and
                // a node with two such operands is one finding, not two.
                else if is_bitwise_operator(operator) {
                    let direct_comparison = |field| {
                        bin_node
                            .child_by_field_name(field)
                            .is_some_and(|operand| is_comparison(&operand, source))
                    };
                    if direct_comparison("left") || direct_comparison("right") {
                        report_violation(&bin_node, source, &mut violations);
                    }
                }
            }
        }

        violations
    }
}

/// Check if the operator is a comparison operator
fn is_comparison_operator(op: &str) -> bool {
    matches!(op, "==" | "!=" | "<" | ">" | "<=" | ">=")
}

/// Check if the operator is a low-precedence bitwise operator
fn is_bitwise_operator(op: &str) -> bool {
    matches!(op, "&" | "|" | "^" | "<<" | ">>")
}

/// Check if a node contains an unparenthesized bitwise operator
fn has_unparenthesized_bitwise_operator(node: &Node, source: &str) -> bool {
    match node.kind() {
        "binary_expression" => {
            if let Some(operator_node) = node.child_by_field_name("operator") {
                let operator = get_node_text(&operator_node, source);
                is_bitwise_operator(operator)
            } else {
                false
            }
        }
        "parenthesized_expression" => {
            // If it's already parenthesized, it's safe
            false
        }
        _ => false,
    }
}

/// Whether `node` is itself a comparison, not one nested anywhere under it.
fn is_comparison(node: &Node, source: &str) -> bool {
    node.kind() == "binary_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|op| is_comparison_operator(get_node_text(&op, source)))
}

/// Report a violation for operator precedence issues
fn report_violation(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    let start_point = node.start_position();
    let node_text = get_node_text(node, source);

    violations.push(RuleViolation {
        rule_id: "EXP00-C".to_string(),
        severity: Severity::Low,
        message: format!(
            "Use parentheses to clarify operator precedence: '{}'",
            node_text
        ),
        file_path: String::new(),
        line: start_point.row + 1,
        column: start_point.column + 1,
        suggestion: Some("Add parentheses to enforce the intended order of operations".to_string()),
        ..Default::default()
    });
}
