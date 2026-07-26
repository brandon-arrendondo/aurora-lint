// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! MSC15-C: Do not depend on undefined behavior
//!
//! This rule targets the concrete, statically checkable case from the
//! wiki's own example: a signed-overflow check of the form `x + c > x` (or
//! `x - c < x`). Evaluating `x + c` when it overflows a *signed* integer is
//! itself undefined behavior, so a check that depends on observing the
//! wrapped-around result is depending on UB not happening in order to work
//! -- the compiler is free to assume signed overflow never occurs and
//! optimize the check away entirely. The same shape on an *unsigned*
//! operand is the correct, well-defined idiom (unsigned wraparound is
//! defined by the Standard) and is not flagged.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC15-C.+Do+not+depend+on+undefined+behavior

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Msc15C;

impl Msc15C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc15C
    }

    fn declared_type_is_unsigned(&self, root: &Node, var_name: &str, source: &str) -> bool {
        for decl in
            query::find_descendants_of_kinds(*root, &["declaration", "parameter_declaration"])
        {
            let has_name = query::find_descendants_of_kind(decl, "identifier")
                .iter()
                .any(|n| ast_utils::get_node_text(n, source) == var_name);
            if !has_name {
                continue;
            }
            let type_text: String = (0..decl.child_count())
                .filter_map(|i| decl.child(i))
                .take_while(|c| c.kind() != "identifier" && c.kind() != "init_declarator")
                .map(|c| ast_utils::get_node_text(&c, source))
                .collect::<Vec<_>>()
                .join(" ");
            if type_text.contains("unsigned") {
                return true;
            }
        }
        false
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for outer in query::find_descendants_of_kind(*root, "binary_expression") {
            let Some(op) = outer.child(1) else { continue };
            let op_text = ast_utils::get_node_text(&op, source);
            if !matches!(op_text, ">" | "<" | ">=" | "<=") {
                continue;
            }
            let Some(left) = outer.child_by_field_name("left") else {
                continue;
            };
            let Some(right) = outer.child_by_field_name("right") else {
                continue;
            };
            if left.kind() != "binary_expression" || right.kind() != "identifier" {
                continue;
            }
            let Some(inner_op) = left.child(1) else {
                continue;
            };
            let inner_op_text = ast_utils::get_node_text(&inner_op, source);
            if inner_op_text != "+" && inner_op_text != "-" {
                continue;
            }
            let Some(inner_left) = left.child_by_field_name("left") else {
                continue;
            };
            if inner_left.kind() != "identifier" {
                continue;
            }
            let right_name = ast_utils::get_node_text(&right, source);
            let inner_left_name = ast_utils::get_node_text(&inner_left, source);
            if right_name != inner_left_name {
                continue;
            }
            if self.declared_type_is_unsigned(root, right_name, source) {
                continue;
            }

            let pos = outer.start_position();
            violations.push(RuleViolation {
                rule_id: "MSC15-C".to_string(),
                severity: Severity::High,
                line: pos.row + 1,
                column: pos.column + 1,
                message: format!(
                    "overflow check '{} {} ... {} {}' depends on undefined behavior -- evaluating the overflowing signed addition/subtraction is itself UB",
                    inner_left_name, inner_op_text, op_text, right_name
                ),
                file_path: String::new(),
                suggestion: Some(
                    "Check for overflow before performing the arithmetic (e.g. `a < INT_MAX - c`), rather than comparing the result of the operation to its operand"
                        .to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }
}

impl CertRule for Msc15C {
    fn rule_id(&self) -> &'static str {
        "MSC15-C"
    }

    fn description(&self) -> &'static str {
        "Do not depend on undefined behavior"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "MSC15-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
