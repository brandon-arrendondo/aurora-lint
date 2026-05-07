//! EXP02-C: Be aware of the short-circuit behavior of the logical AND and OR operators
//!
//! This rule detects side effects (function calls, assignments, increments/decrements) in the
//! second operand of logical AND (&&) and OR (||) operators, which may not execute due to
//! short-circuit evaluation.
//!
//! ## Key Issues:
//! - The second operand of `&&` is only evaluated if the first operand is true
//! - The second operand of `||` is only evaluated if the first operand is false
//! - Side effects in the second operand may not occur, leading to logic errors
//!
//! ## Detected Violations:
//! - Function calls in the right operand of `&&` or `||`
//! - Assignment expressions in the right operand
//! - Increment/decrement operators (++, --) in the right operand
//! - Compound assignments (+=, -=, etc.) in the right operand
//!
//! ## Compliant Patterns:
//! - Side effects only in the first operand
//! - Pure boolean expressions without side effects
//! - Refactored to use separate statements for side effects

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

pub struct Exp02C;

impl CertRule for Exp02C {
    fn rule_id(&self) -> &'static str {
        "EXP02-C"
    }

    fn description(&self) -> &'static str {
        "Be aware of the short-circuit behavior of the logical AND and OR operators"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP02-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Exp02C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for binary expressions that are logical AND or OR
        if node.kind() == "binary_expression" {
            if let Some(operator) = node.child_by_field_name("operator") {
                let op_text = get_node_text(&operator, source);

                // Only check logical AND (&&) and OR (||) operators
                if matches!(op_text, "&&" | "||") {
                    if let Some(right) = node.child_by_field_name("right") {
                        // Exempt guarded short-circuit idioms for both && and ||.
                        // A guard is any comparison (==, !=, <, >, <=, >=), a
                        // truthiness check, or an &&/|| chain of guards.
                        // Exempt only when the RHS carries no assignment, compound
                        // assignment, or increment/decrement — pure function calls
                        // are the expected payload.
                        //   `ptr != NULL && func(ptr)`
                        //   `ptr == NULL || fallback(ptr)`
                        //   `file_size > 0 && buflen >= file_size && fseek(...)`
                        //   `len == capacity && !grow(self)`
                        if let Some(left) = node.child_by_field_name("left") {
                            if self.is_guard_pattern(&left, source)
                                && !self.has_mutation_side_effects(&right, source)
                            {
                                return;
                            }
                            // Also exempt: guard && (--countdown) — intentional hardware
                            // busy-wait countdown pattern, e.g. (reg & mask) && (--timeout)
                            if self.is_guard_pattern(&left, source)
                                && Self::is_simple_decrement(&right)
                            {
                                return;
                            }
                        }

                        // Check if the right operand has side effects
                        if self.has_side_effects(&right, source) {
                            let start_point = right.start_position();
                            let right_text = get_node_text(&right, source);

                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Low,
                                message: format!(
                                    "Side effect in right operand of '{}' operator may not execute due to short-circuit evaluation: '{}'",
                                    op_text, right_text
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some(
                                    "Move side effects to separate statements before the logical expression".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }

        // Recursively check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, violations);
            }
        }
    }

    /// Check if the left operand of && or || is a guard pattern — a predicate
    /// whose truth value controls whether the RHS runs. Recognized shapes:
    ///   * comparison:    a == b, a != b, a < b, a > b, a <= b, a >= b
    ///   * truthiness:    ident, !ident, ptr->field, obj.field
    ///   * compound:      (guard) && (guard), (guard) || (guard)
    ///   * parenthesized: any of the above wrapped in parens
    fn is_guard_pattern(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "binary_expression" => {
                if let Some(op) = node.child_by_field_name("operator") {
                    let op_text = get_node_text(&op, source);
                    if matches!(op_text, "==" | "!=" | "<" | ">" | "<=" | ">=") {
                        return true;
                    }
                    // Bitwise AND/OR/XOR: (reg & mask) is a flag/condition test
                    if matches!(op_text, "&" | "|" | "^") {
                        return true;
                    }
                    if matches!(op_text, "&&" | "||") {
                        let left_guard = node
                            .child_by_field_name("left")
                            .map(|l| self.is_guard_pattern(&l, source))
                            .unwrap_or(false);
                        let right_guard = node
                            .child_by_field_name("right")
                            .map(|r| self.is_guard_pattern(&r, source))
                            .unwrap_or(false);
                        return left_guard && right_guard;
                    }
                }
                false
            }
            "identifier"
            | "unary_expression"
            | "field_expression"
            | "pointer_expression"
            | "subscript_expression" => true,
            "parenthesized_expression" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if matches!(child.kind(), "(" | ")") {
                            continue;
                        }
                        return self.is_guard_pattern(&child, source);
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Check if a node contains mutation side effects: assignment (=), compound
    /// assignment (+=, etc.), increment (++), or decrement (--).
    /// Pure function calls are NOT considered mutations — they're common in
    /// intentional guard patterns like `ptr == NULL || fallback()`.
    fn has_mutation_side_effects(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "assignment_expression" | "update_expression" => return true,
            _ => {}
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.has_mutation_side_effects(&child, source) {
                    return true;
                }
            }
        }
        false
    }

    /// Returns true if `node` is a simple pre/post decrement of a single identifier:
    /// `--var`, `var--`, or parenthesized forms. Used to detect countdown patterns like
    /// `(hardware_flag) && (--timeout)` which are intentional and not EXP02-C violations.
    fn is_simple_decrement(node: &Node) -> bool {
        match node.kind() {
            "update_expression" => {
                // Tree-sitter-c: update_expression has an "argument" field (the operand)
                // and a fixed-position operator child (++ or --)
                if let Some(arg) = node.child_by_field_name("argument") {
                    // Check operator is --
                    let is_decrement = (0..node.child_count())
                        .any(|i| node.child(i).map(|c| c.kind() == "--").unwrap_or(false));
                    return is_decrement && arg.kind() == "identifier";
                }
                false
            }
            "parenthesized_expression" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if !matches!(child.kind(), "(" | ")") {
                            return Self::is_simple_decrement(&child);
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Check if a call_expression is used as a getter in a field access pattern:
    /// `func()->field` or `func().field`. The call just returns a struct/pointer
    /// and the result is read — no observable side effect.
    fn is_getter_in_field_access(&self, call_node: &Node) -> bool {
        if let Some(parent) = call_node.parent() {
            if parent.kind() == "field_expression" {
                if let Some(arg) = parent.child_by_field_name("argument") {
                    return arg.id() == call_node.id();
                }
            }
        }
        false
    }

    /// Check if a node contains side effects (function calls, assignments, increments)
    fn has_side_effects(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            // Function calls have side effects — unless they're getter patterns
            "call_expression" => {
                // Exception: func()->field is a getter pattern (returns struct pointer,
                // field is read). The function call is just to obtain a reference.
                if self.is_getter_in_field_access(node) {
                    return false;
                }
                true
            }
            // Assignment operators have side effects
            "assignment_expression" => true,
            // Increment and decrement operators have side effects
            "update_expression" => {
                // Check if it's ++ or --
                if let Some(operator) = node.child_by_field_name("operator") {
                    let op = get_node_text(&operator, source);
                    matches!(op, "++" | "--")
                } else {
                    false
                }
            }
            // Compound assignment operators (+=, -=, etc.) have side effects
            "compound_assignment_expr" => true,
            // Recursively check child nodes for side effects
            _ => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if self.has_side_effects(&child, source) {
                            return true;
                        }
                    }
                }
                false
            }
        }
    }
}
