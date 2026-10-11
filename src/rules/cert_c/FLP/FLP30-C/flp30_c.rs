// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! FLP30-C: Do not use floating-point variables as loop counters
//!
//! Floating-point numbers cannot represent all decimal values exactly.
//! Using them as loop counters can cause loops to iterate an unexpected
//! number of times or create infinite loops.
//!
//! ## What is reported
//!
//! CERT's own definition of a loop counter: an operand of the controlling
//! comparison of a `for`, `while` or `do` loop that the loop changes by a
//! fixed amount (`++`, `--`, `+=`/`-=` of a loop-invariant value, or
//! `x = x + k`) in its body or, for a `for`, its update clause. The counter is
//! reported when its declared type, typedefs resolved, is a floating type.
//!
//! A floating variable that a `for` initializer declares but the condition
//! does not test (`for (double acc = 0.0; n > 0; n--)`) is an accumulator,
//! not a counter, and is not reported.
//!
//! **Decimal floating types are in scope.** C23 makes `_Decimal32`,
//! `_Decimal64` and `_Decimal128` floating types, and the guideline is
//! written about floating-point variables. A decimal step of `0.1` is exact,
//! so CERT's first example would run its ten iterations, but the fixed
//! precision that defeats the second example (a step lost against a large
//! value) applies to decimal types too.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! for (float x = 0.1f; x <= 1.0f; x += 0.1f) {
//!     // May iterate 9 or 10 times
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! for (size_t count = 1; count <= 10; ++count) {
//!     float x = count / 10.0f;
//!     // Iterates exactly 10 times
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::VisibleTypes;
use crate::manifest::Severity;
use crate::settings::{AnalysisSettings, IntFacts};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::expr_type::{self, TypeEnv};
use crate::utility::cert_c::result_checks::same_lvalue;
use lang_parsing_substrate::query;
use std::cell::{Cell, RefCell};
use tree_sitter::Node;

#[derive(Debug, Default)]
pub struct Flp30C {
    /// The typedefs and struct fields this file sees, so a counter declared
    /// `real_t` (a typedef of double) is typed by its declaration.
    visible: RefCell<VisibleTypes>,
    /// The integer data model the settings credit, for typing.
    data_model: Cell<IntFacts>,
}

impl CertRule for Flp30C {
    fn rule_id(&self) -> &'static str {
        "FLP30-C"
    }

    fn description(&self) -> &'static str {
        "Do not use floating-point variables as loop counters"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "FLP30-C"
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn set_analysis_settings(&self, settings: &std::sync::Arc<AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible, self.data_model.get()).in_tree(*root);
        let mut violations = Vec::new();
        let loops = query::find_descendants(*root, |n| {
            matches!(
                n.kind(),
                "for_statement" | "while_statement" | "do_statement"
            )
        });
        for lp in loops {
            if let Some(counter) = self.floating_counter(&lp, source, &env) {
                violations.push(self.violation(&lp, &counter, source));
            }
        }
        violations
    }
}

impl Flp30C {
    pub fn new() -> Self {
        Self::default()
    }

    /// The first operand of the loop's controlling comparison that the loop
    /// changes by a fixed amount and whose declared type is floating.
    fn floating_counter<'a>(&self, lp: &Node<'a>, source: &str, env: &TypeEnv) -> Option<Node<'a>> {
        let condition = lp.child_by_field_name("condition")?;
        let mut operands = Vec::new();
        Self::comparison_operands(condition, &mut operands);
        operands.into_iter().find(|op| {
            matches!(op.kind(), "identifier" | "field_expression")
                && expr_type::expr_type(op, source, env).is_some_and(|t| t.is_float())
                && Self::changed_by_fixed_amount(lp, op, source)
        })
    }

    /// The operands of every comparison the controlling expression is made
    /// of: through parentheses, `!`, `&&`, `||` and the comma operator's
    /// last operand, down to a relational or equality operator.
    fn comparison_operands<'a>(node: Node<'a>, out: &mut Vec<Node<'a>>) {
        match node.kind() {
            "parenthesized_expression" => {
                if let Some(inner) = node.named_child(0) {
                    Self::comparison_operands(inner, out);
                }
            }
            "unary_expression" if node.child(0).is_some_and(|op| op.kind() == "!") => {
                if let Some(arg) = node.child_by_field_name("argument") {
                    Self::comparison_operands(arg, out);
                }
            }
            "comma_expression" => {
                if let Some(right) = node.child_by_field_name("right") {
                    Self::comparison_operands(right, out);
                }
            }
            "binary_expression" => {
                let Some(op) = node.child_by_field_name("operator") else {
                    return;
                };
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return;
                };
                match op.kind() {
                    "&&" | "||" => {
                        Self::comparison_operands(left, out);
                        Self::comparison_operands(right, out);
                    }
                    "<" | "<=" | ">" | ">=" | "==" | "!=" => {
                        out.push(strip_parens(left));
                        out.push(strip_parens(right));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    /// Whether the loop changes `var` by a fixed amount in its body or, for
    /// a `for`, its update clause: `++`/`--`, `+=`/`-=` of a value the loop
    /// does not change, or `var = var + k` / `var = k + var` / `var = var - k`.
    fn changed_by_fixed_amount(lp: &Node, var: &Node, source: &str) -> bool {
        let regions: Vec<Node> = ["body", "update"]
            .iter()
            .filter_map(|f| lp.child_by_field_name(f))
            .collect();
        regions.iter().any(|region| {
            query::find_descendants(*region, |n| {
                matches!(n.kind(), "update_expression" | "assignment_expression")
            })
            .into_iter()
            .any(|n| Self::is_fixed_step_of(&n, var, &regions, source))
        })
    }

    fn is_fixed_step_of(n: &Node, var: &Node, regions: &[Node], source: &str) -> bool {
        if n.kind() == "update_expression" {
            return n
                .child_by_field_name("argument")
                .is_some_and(|a| same_lvalue(&a, var, source));
        }
        let (Some(left), Some(op), Some(right)) = (
            n.child_by_field_name("left"),
            n.child_by_field_name("operator"),
            n.child_by_field_name("right"),
        ) else {
            return false;
        };
        if !same_lvalue(&left, var, source) {
            return false;
        }
        match op.kind() {
            "+=" | "-=" => Self::loop_invariant(&right, regions, source),
            "=" => {
                let right = strip_parens(right);
                if right.kind() != "binary_expression" {
                    return false;
                }
                let (Some(a), Some(bop), Some(b)) = (
                    right.child_by_field_name("left"),
                    right.child_by_field_name("operator"),
                    right.child_by_field_name("right"),
                ) else {
                    return false;
                };
                match bop.kind() {
                    "+" => {
                        (same_lvalue(&a, var, source) && Self::loop_invariant(&b, regions, source))
                            || (same_lvalue(&b, var, source)
                                && Self::loop_invariant(&a, regions, source))
                    }
                    "-" => {
                        same_lvalue(&a, var, source) && Self::loop_invariant(&b, regions, source)
                    }
                    _ => false,
                }
            }
            _ => false,
        }
    }

    /// The step is the same on every iteration: it calls nothing and names
    /// nothing the loop writes.
    fn loop_invariant(step: &Node, regions: &[Node], source: &str) -> bool {
        if query::find_first_descendant(*step, |n| n.kind() == "call_expression").is_some()
            || step.kind() == "call_expression"
        {
            return false;
        }
        let mut names = query::find_descendants(*step, |n| {
            matches!(n.kind(), "identifier" | "field_expression")
        });
        if matches!(step.kind(), "identifier" | "field_expression") {
            names.push(*step);
        }
        !names.iter().any(|name| {
            regions.iter().any(|region| {
                query::find_descendants(*region, |n| {
                    matches!(n.kind(), "update_expression" | "assignment_expression")
                })
                .into_iter()
                .any(|w| {
                    let target = if w.kind() == "update_expression" {
                        w.child_by_field_name("argument")
                    } else {
                        w.child_by_field_name("left")
                    };
                    target.is_some_and(|t| same_lvalue(&t, name, source))
                })
            })
        })
    }

    fn violation(&self, lp: &Node, counter: &Node, source: &str) -> RuleViolation {
        RuleViolation {
            rule_id: self.rule_id().to_string(),
            message: format!(
                "Floating-point variable '{}' used as loop counter. \
                 Floating-point arithmetic may cause unexpected iteration counts.",
                get_node_text(counter, source)
            ),
            severity: self.severity(),
            line: lp.start_position().row + 1,
            column: lp.start_position().column + 1,
            file_path: String::new(),
            suggestion: Some(
                "Use an integer counter and derive floating-point values inside the loop"
                    .to_string(),
            ),
            requires_manual_review: None,
        }
    }
}

fn strip_parens(mut n: Node) -> Node {
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => break,
        }
    }
    n
}
