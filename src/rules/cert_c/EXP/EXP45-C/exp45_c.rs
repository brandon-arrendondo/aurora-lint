//! EXP45-C: Do not perform assignments in selection statements
//!
//! Performing assignments in selection statements can lead to confusion between
//! the assignment operator (=) and the equality operator (==), potentially causing
//! logic errors.
//!
//! ## Rationale:
//! - Assignments in conditions are often mistakes (= instead of ==)
//! - Reduces code readability
//! - Can lead to unintended behavior
//!
//! ## Examples:
//!
//! **Non-compliant (assignment in if condition):**
//! ```c
//! if (x = 5) {  // Likely meant ==, always true
//!     // ...
//! }
//! ```
//!
//! **Compliant (comparison):**
//! ```c
//! if (x == 5) {
//!     // ...
//! }
//! ```
//!
//! **Exception EX1 (assignment used in comparison - compliant):**
//! ```c
//! if ((x = foo()) != NULL) {  // Assignment result compared
//!     // ...
//! }
//! ```

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;

pub struct Exp45C;

impl CertRule for Exp45C {
    fn rule_id(&self) -> &'static str {
        "EXP45-C"
    }

    fn description(&self) -> &'static str {
        "Do not perform assignments in selection statements"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP45-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Exp45C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            match n.kind() {
                "if_statement" => {
                    if let Some(condition) = n.child_by_field_name("condition") {
                        self.check_condition_for_assignment(&condition, source, "if", violations);
                    }
                }
                "switch_statement" => {
                    if let Some(condition) = n.child_by_field_name("condition") {
                        self.check_condition_for_assignment(
                            &condition, source, "switch", violations,
                        );
                    }
                }
                "while_statement" => {
                    if let Some(condition) = n.child_by_field_name("condition") {
                        self.check_condition_for_assignment(
                            &condition, source, "while", violations,
                        );
                    }
                }
                "do_statement" => {
                    if let Some(condition) = n.child_by_field_name("condition") {
                        self.check_condition_for_assignment(
                            &condition, source, "do-while", violations,
                        );
                    }
                }
                "for_statement" => {
                    // Check condition (second expression) - assignments NOT allowed here
                    if let Some(condition) = n.child_by_field_name("condition") {
                        self.check_condition_for_assignment(&condition, source, "for", violations);
                    }
                    // Note: Assignments in initializer and update expressions are allowed
                }
                _ => {}
            }
        }
    }

    fn check_condition_for_assignment(
        &self,
        condition: &Node,
        source: &str,
        statement_type: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        self.find_assignments_in_condition(condition, source, statement_type, violations);
    }

    fn find_assignments_in_condition(
        &self,
        node: &Node,
        source: &str,
        statement_type: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "assignment_expression") {
            // Check if this assignment is part of a comparison (EX1 exception)
            // or in the first operand of a comma expression (allowed)
            if !self.is_assignment_in_comparison(&n) && !self.is_in_first_comma_operand(&n) {
                let line = n.start_position().row + 1;
                let column = n.start_position().column + 1;
                let assignment_text = get_node_text(&n, source);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Assignment in {} statement condition: '{}'",
                        statement_type,
                        assignment_text
                            .split('\n')
                            .next()
                            .unwrap_or(&assignment_text)
                    ),
                    file_path: String::new(),
                    line,
                    column,
                    suggestion: Some(format!(
                        "Use == for comparison, or move assignment outside {} condition",
                        statement_type
                    )),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Check if assignment is used as operand to a comparison (EX1 exception)
    /// Examples: if ((x = foo()) != NULL) is allowed
    fn is_assignment_in_comparison(&self, assignment_node: &Node) -> bool {
        // Walk up to find parent
        if let Some(parent) = assignment_node.parent() {
            // Check if parent is a comparison or relational expression
            match parent.kind() {
                "binary_expression" => {
                    // Check if it's a comparison operator
                    let mut cursor = parent.walk();
                    for child in parent.children(&mut cursor) {
                        if matches!(child.kind(), "!=" | "==" | "<" | ">" | "<=" | ">=") {
                            return true;
                        }
                    }
                }
                "parenthesized_expression" => {
                    // Assignment in parentheses, check if the parentheses are part of a comparison
                    return self.is_assignment_in_comparison(&parent);
                }
                _ => {}
            }
        }
        false
    }

    /// Check if assignment is in the first operand of a comma expression
    /// This is allowed per the rule (only second operand is restricted)
    fn is_in_first_comma_operand(&self, assignment_node: &Node) -> bool {
        if let Some(parent) = assignment_node.parent() {
            if parent.kind() == "comma_expression" {
                // Check if this assignment is the left/first operand
                if let Some(left) = parent.child_by_field_name("left") {
                    // The assignment or its parent is the left operand
                    if left.id() == assignment_node.id() {
                        return true;
                    }
                    // Check if assignment is within the left operand
                    return self.is_ancestor_of(&left, assignment_node);
                }
            }
            // Recursively check if we're nested in a comma expression's first operand
            return self.is_in_first_comma_operand(&parent);
        }
        false
    }

    /// Check if ancestor_node contains target_node
    fn is_ancestor_of(&self, ancestor: &Node, target: &Node) -> bool {
        let target_id = target.id();
        query::find_first_descendant(*ancestor, |n| n.id() == target_id).is_some()
    }
}
