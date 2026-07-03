use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp07C;

impl CertRule for Exp07C {
    fn rule_id(&self) -> &'static str {
        "EXP07-C"
    }

    fn description(&self) -> &'static str {
        "Do not diminish the benefits of constants by assuming their values in expressions"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "EXP07-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for binary expressions with shift operators that use magic numbers
        for bin_node in query::find_descendants_of_kind(*node, "binary_expression") {
            if let Some(operator_node) = bin_node.child_by_field_name("operator") {
                let operator = get_node_text(&operator_node, source);

                // Check for shift operators
                if operator == "<<" || operator == ">>" {
                    if let Some(right) = bin_node.child_by_field_name("right") {
                        if is_numeric_literal(&right, source) {
                            let shift_text = get_node_text(&right, source).trim();
                            let shift_text = shift_text.trim_end_matches(['u', 'U', 'l', 'L']);
                            if let Ok(shift_val) = shift_text.parse::<u32>() {
                                // Skip standard bit manipulation idioms:
                                // - Shifts 0-7: bit-position operations within a byte
                                // - Byte-boundary shifts (8, 16, 24, 32): serialization/packing
                                let is_bit_position = shift_val <= 7;
                                let is_byte_boundary = shift_val > 0 && shift_val % 8 == 0;
                                if !is_bit_position && !is_byte_boundary {
                                    report_violation(&bin_node, source, &mut violations);
                                }
                            } else {
                                report_violation(&bin_node, source, &mut violations);
                            }
                        }
                    }
                }
            }
        }

        violations
    }
}

/// Check if a node is a numeric literal
fn is_numeric_literal(node: &Node, source: &str) -> bool {
    match node.kind() {
        "number_literal" => true,
        _ => {
            // Also check if it's an expression that evaluates to a number
            let text = get_node_text(node, source).trim();
            text.chars().all(|c| c.is_ascii_digit())
        }
    }
}

/// Report a violation for assuming constant values in expressions
fn report_violation(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
    let start_point = node.start_position();
    let node_text = get_node_text(node, source);

    violations.push(RuleViolation {
        rule_id: "EXP07-C".to_string(),
        severity: Severity::Low,
        message: format!(
            "Do not assume constant values in expressions: '{}'",
            node_text
        ),
        file_path: String::new(),
        line: start_point.row + 1,
        column: start_point.column + 1,
        suggestion: Some(
            "Use the constant identifier directly instead of assuming its numeric value"
                .to_string(),
        ),
        ..Default::default()
    });
}
