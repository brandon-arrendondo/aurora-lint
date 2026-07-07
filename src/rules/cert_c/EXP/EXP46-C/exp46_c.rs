//! EXP46-C: Do not use a bitwise operator with a Boolean-like operand
//!
//! This rule detects the incorrect use of bitwise operators (&, |, ^) with Boolean-like
//! operands. Boolean-like operands include results from relational and equality expressions,
//! as well as _Bool types. This is typically a logic error where the developer intended
//! to use logical operators (&&, ||) instead.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! if (getuid() == 0 & getgid() == 0) {  // Should use && not &
//!   /* ... */
//! }
//! ```
//!
//! **Non-compliant:**
//! ```c
//! if (a > b | c < d) {  // Should use || not |
//!   /* ... */
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! if (getuid() == 0 && getgid() == 0) {
//!   /* Correct: uses logical AND */
//! }
//! ```
//!
//! **Compliant (intentional bitwise operation):**
//! ```c
//! unsigned int a = SOME_VALUE;
//! unsigned int b = SOME_VALUE;
//! if ((a & b) == SOME_VALUE) {  // Acceptable: bitwise on non-Boolean
//!   /* ... */
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find binary_expression nodes with bitwise operators (&, |, ^)
//! - Check if either operand is a Boolean-like expression:
//!   - Relational operators (<, >, <=, >=)
//!   - Equality operators (==, !=)
//!   - _Bool type (if detectable)
//! - Flag violations when bitwise operator is used with these operands

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp46C;

impl CertRule for Exp46C {
    fn rule_id(&self) -> &'static str {
        "EXP46-C"
    }

    fn description(&self) -> &'static str {
        "Do not use a bitwise operator with a Boolean-like operand"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP46-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Exp46C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for binary_expression nodes
        for n in query::find_descendants_of_kind(*node, "binary_expression") {
            if let Some(operator_node) = n.child_by_field_name("operator") {
                let operator = get_node_text(&operator_node, source).trim();

                // Check if this is a bitwise operator we care about
                if self.is_bitwise_operator(operator) {
                    // Check left operand
                    if let Some(left) = n.child_by_field_name("left") {
                        if self.is_boolean_like_expression(&left, source) {
                            self.report_violation(&n, source, operator, "left", &left, violations);
                        }
                    }

                    // Check right operand
                    if let Some(right) = n.child_by_field_name("right") {
                        if self.is_boolean_like_expression(&right, source) {
                            self.report_violation(
                                &n, source, operator, "right", &right, violations,
                            );
                        }
                    }
                }
            }
        }
    }

    fn is_bitwise_operator(&self, op: &str) -> bool {
        matches!(op, "&" | "|" | "^")
    }

    fn is_boolean_like_expression(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "binary_expression" => {
                // Check if this binary expression uses a relational or equality operator
                if let Some(operator_node) = node.child_by_field_name("operator") {
                    let operator = get_node_text(&operator_node, source).trim();
                    self.is_relational_or_equality_operator(operator)
                } else {
                    false
                }
            }
            "parenthesized_expression" => {
                // Look inside parentheses
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "(" && child.kind() != ")" {
                            if self.is_boolean_like_expression(&child, source) {
                                return true;
                            }
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn is_relational_or_equality_operator(&self, op: &str) -> bool {
        matches!(op, "==" | "!=" | "<" | ">" | "<=" | ">=")
    }

    fn report_violation(
        &self,
        node: &Node,
        source: &str,
        operator: &str,
        operand_side: &str,
        operand_node: &Node,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let expr_text = get_node_text(node, source).trim().to_string();
        let operand_text = get_node_text(operand_node, source).trim().to_string();

        let suggested_operator = match operator {
            "&" => "&&",
            "|" => "||",
            "^" => "!= (for XOR logic)",
            _ => "logical operator",
        };

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Low,
            message: format!(
                "Do not use bitwise operator '{}' with Boolean-like {} operand '{}'. Did you mean '{}'?",
                operator,
                operand_side,
                if operand_text.len() > 40 {
                    format!("{}...", &operand_text[..40])
                } else {
                    operand_text
                },
                suggested_operator
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Replace bitwise operator '{}' with logical operator '{}' when working with Boolean values. Expression: {}",
                operator,
                suggested_operator,
                if expr_text.len() > 60 {
                    format!("{}...", &expr_text[..60])
                } else {
                    expr_text
                }
            )),
            ..Default::default()
        });
    }
}
