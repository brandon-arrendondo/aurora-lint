use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp13C;

impl CertRule for Exp13C {
    fn rule_id(&self) -> &'static str {
        "EXP13-C"
    }

    fn description(&self) -> &'static str {
        "Treat relational and equality operators as if they were nonassociative"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "EXP13-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for binary expressions with relational or equality operators
        for bin_node in query::find_descendants_of_kind(*node, "binary_expression") {
            if let Some(operator_node) = bin_node.child_by_field_name("operator") {
                let operator = get_node_text(&operator_node, source);

                // Check if this is a relational or equality operator
                if is_relational_or_equality_operator(operator) {
                    // Check if either operand contains another relational/equality operator
                    // This would indicate chaining like a < b < c
                    if let Some(left) = bin_node.child_by_field_name("left") {
                        if contains_relational_or_equality(&left, source) {
                            report_violation(&bin_node, source, &mut violations);
                        }
                    }
                    if let Some(right) = bin_node.child_by_field_name("right") {
                        if contains_relational_or_equality(&right, source) {
                            report_violation(&bin_node, source, &mut violations);
                        }
                    }
                }
            }
        }

        violations
    }
}

/// Check if an operator is a relational or equality operator
fn is_relational_or_equality_operator(op: &str) -> bool {
    matches!(op, "<" | ">" | "<=" | ">=" | "==" | "!=")
}

/// Check if a node or its children contain relational or equality operators
/// without parentheses (indicating direct chaining)
fn contains_relational_or_equality(node: &Node, source: &str) -> bool {
    match node.kind() {
        "binary_expression" => {
            // Check if this binary expression uses a relational/equality operator
            if let Some(operator_node) = node.child_by_field_name("operator") {
                let operator = get_node_text(&operator_node, source);
                // If this is a relational/equality operator, we found chaining
                is_relational_or_equality_operator(operator)
            } else {
                false
            }
        }
        "parenthesized_expression" => {
            // Parentheses break the chaining, so this is safe
            false
        }
        _ => false,
    }
}

/// Report a violation for chained relational/equality operators
fn report_violation(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    let start_point = node.start_position();
    let node_text = get_node_text(node, source);

    violations.push(RuleViolation {
        rule_id: "EXP13-C".to_string(),
        severity: Severity::Low,
        message: format!(
            "Chained relational or equality operators should use explicit logical operators: '{}'",
            node_text
        ),
        file_path: String::new(),
        line: start_point.row + 1,
        column: start_point.column + 1,
        suggestion: Some(
            "Use explicit logical operators (&&, ||) to clarify intent: e.g., (a < b) && (b < c)"
                .to_string(),
        ),
        ..Default::default()
    });
}
