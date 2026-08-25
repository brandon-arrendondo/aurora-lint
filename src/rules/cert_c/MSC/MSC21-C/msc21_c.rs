// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! MSC21-C: Use robust loop termination conditions
//!
//! Two statically checkable ways a `for` loop's termination condition can
//! fail to actually terminate the loop:
//!
//!   - using `!=`/`==` against a target value when the loop counter's step
//!     isn't exactly +-1 -- a larger or variable step can skip over the
//!     target value entirely, running forever (or until wraparound). A step
//!     of exactly 1 (`++i`, `i++`, `--i`, `i--`, `i += 1`, `i -= 1`) can
//!     never skip past its target and is not flagged.
//!   - comparing the loop counter to the type's maximum value with `<=` (or
//!     minimum with `>=`) -- once the counter reaches that value, adding the
//!     step wraps it around rather than exceeding the bound, so the
//!     condition never becomes false.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC21-C.+Use+robust+loop+termination+conditions

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

const MAX_VALUE_CONSTANTS: &[&str] = &[
    "SIZE_MAX",
    "UINT_MAX",
    "UINT8_MAX",
    "UINT16_MAX",
    "UINT32_MAX",
    "UINT64_MAX",
    "ULONG_MAX",
    "ULLONG_MAX",
    "INT_MAX",
    "LONG_MAX",
    "LLONG_MAX",
];

/// A numeric step recognized on the loop counter: exactly ±1, or a
/// constant literal other than ±1.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Unit,
    NonUnit,
}

#[derive(Debug)]
pub struct Msc21C;

impl Msc21C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc21C
    }

    /// A `var +/- literal` (or `literal +/- var`) binary expression's step,
    /// if it's an addition/subtraction with `var_name` on one side and a
    /// numeric literal on the other.
    fn literal_binary_step(&self, expr: &Node, var_name: &str, source: &str) -> Option<Step> {
        if expr.kind() != "binary_expression" {
            return None;
        }
        let op = ast_utils::get_node_text(&expr.child(1)?, source);
        if op != "+" && op != "-" {
            return None;
        }
        let left = expr.child_by_field_name("left")?;
        let right = expr.child_by_field_name("right")?;
        let literal_side =
            if left.kind() == "identifier" && ast_utils::get_node_text(&left, source) == var_name {
                right
            } else if right.kind() == "identifier"
                && ast_utils::get_node_text(&right, source) == var_name
            {
                left
            } else {
                return None;
            };
        if literal_side.kind() != "number_literal" {
            return None;
        }
        if ast_utils::get_node_text(&literal_side, source) == "1" {
            Some(Step::Unit)
        } else {
            Some(Step::NonUnit)
        }
    }

    /// Classifies the numeric step the `update` clause of a for-loop applies
    /// to `var_name`, or `None` when `update` doesn't provably step
    /// `var_name` by a constant amount at all.
    ///
    /// `None` covers pointer-chasing traversal (`p = p->next`),
    /// function-return-driven conditions (`rc = f()`), a non-literal step
    /// that can't be proven non-unit by this AST-only checker, and an
    /// `update` that touches a variable other than the one actually
    /// compared in the loop condition (the two can differ, e.g. `for
    /// (...; eOp != f(op); op++)` — a real +1 step on `op`, but not on the
    /// compared `eOp`). Any of these means the loop isn't the arithmetic
    /// "counter can skip its target" shape this rule checks, so it must not
    /// be flagged regardless of comparison operator.
    fn classify_step(&self, update: &Node, var_name: &str, source: &str) -> Option<Step> {
        match update.kind() {
            "update_expression" => query::find_descendants_of_kind(*update, "identifier")
                .iter()
                .any(|n| ast_utils::get_node_text(n, source) == var_name)
                .then_some(Step::Unit),
            "assignment_expression" => {
                let left = update.child_by_field_name("left")?;
                if left.kind() != "identifier"
                    || ast_utils::get_node_text(&left, source) != var_name
                {
                    return None;
                }
                let op = ast_utils::get_node_text(&update.child(1)?, source);
                let right = update.child_by_field_name("right")?;
                match op {
                    "+=" | "-=" => {
                        if right.kind() != "number_literal" {
                            // Non-literal step: could be provably ±1 by
                            // dataflow this AST-only check can't see —
                            // never positively confirmed non-unit either.
                            return None;
                        }
                        if ast_utils::get_node_text(&right, source) == "1" {
                            Some(Step::Unit)
                        } else {
                            Some(Step::NonUnit)
                        }
                    }
                    "=" => self.literal_binary_step(&right, var_name, source),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn check_for_loop(&self, for_stmt: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let Some(cond) = for_stmt.child_by_field_name("condition") else {
            return;
        };
        if cond.kind() != "binary_expression" {
            return;
        }
        let Some(op) = cond.child(1) else { return };
        let op_text = ast_utils::get_node_text(&op, source);
        let Some(left) = cond.child_by_field_name("left") else {
            return;
        };
        let Some(right) = cond.child_by_field_name("right") else {
            return;
        };
        if left.kind() != "identifier" {
            return;
        }
        let var_name = ast_utils::get_node_text(&left, source);

        let step = for_stmt
            .child_by_field_name("update")
            .and_then(|u| self.classify_step(&u, var_name, source));

        if (op_text == "!=" || op_text == "==") && step == Some(Step::NonUnit) {
            let pos = cond.start_position();
            violations.push(RuleViolation {
                rule_id: "MSC21-C".to_string(),
                severity: Severity::Low,
                line: pos.row + 1,
                column: pos.column + 1,
                message: format!(
                    "loop termination uses '{}' with a step other than +-1 -- the counter can skip over the target value and never terminate",
                    op_text
                ),
                file_path: String::new(),
                suggestion: Some(
                    "Use a relational operator (<, <=, >, >=) to terminate the loop instead of an equality operator, unless the step is exactly 1"
                        .to_string(),
                ),
                requires_manual_review: Some(false),
            });
            return;
        }

        if op_text == "<=" || op_text == ">=" {
            if right.kind() == "identifier"
                && MAX_VALUE_CONSTANTS.contains(&ast_utils::get_node_text(&right, source))
            {
                let pos = cond.start_position();
                violations.push(RuleViolation {
                    rule_id: "MSC21-C".to_string(),
                    severity: Severity::Low,
                    line: pos.row + 1,
                    column: pos.column + 1,
                    message: format!(
                        "loop condition compares against {} with '{}' -- once the counter reaches the type's boundary value, advancing it wraps around instead of exceeding the bound",
                        ast_utils::get_node_text(&right, source), op_text
                    ),
                    file_path: String::new(),
                    suggestion: Some(
                        "Reduce the boundary by the loop's step (e.g. `i <= SIZE_MAX - step`) so the comparison can't be skipped by wraparound"
                            .to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for for_stmt in query::find_descendants_of_kind(*root, "for_statement") {
            self.check_for_loop(&for_stmt, source, violations);
        }
    }
}

impl CertRule for Msc21C {
    fn rule_id(&self) -> &'static str {
        "MSC21-C"
    }

    fn description(&self) -> &'static str {
        "Use robust loop termination conditions"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "MSC21-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
