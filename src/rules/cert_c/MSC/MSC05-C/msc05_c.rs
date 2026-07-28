// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! MSC05-C: Do not manipulate time_t typed values directly
//!
//! The encoding `time()` uses within a `time_t` is unspecified by the C
//! Standard, so performing arithmetic directly on `time_t` values is not
//! portable. This rule flags arithmetic operators (`+ - * / %` and their
//! compound-assignment forms) applied to an operand declared `time_t`.
//! Equality/relational comparisons are not flagged -- comparing against the
//! `(time_t)(-1)` error sentinel is the standard idiom for checking `time()`'s
//! return value and is explicitly compliant.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC05-C.+Do+not+manipulate+time_t+typed+values+directly

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

const ARITHMETIC_OPS: &[&str] = &["+", "-", "*", "/", "%", "+=", "-=", "*=", "/=", "%="];

#[derive(Debug)]
pub struct Msc05C;

impl Msc05C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc05C
    }

    /// Extract the type text (tokens before the declarator) of a `declaration`
    /// node, e.g. `time_t x;` -> `"time_t"`.
    fn type_text_for_decl(decl: &Node, source: &str) -> String {
        (0..decl.child_count())
            .filter_map(|i| decl.child(i))
            .take_while(|c| {
                !matches!(
                    c.kind(),
                    "identifier" | "init_declarator" | "pointer_declarator" | "array_declarator"
                )
            })
            .map(|c| ast_utils::get_node_text(&c, source))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Fallback for file-scope (global) `time_t` declarations, which
    /// `find_enclosing_declaration_for_identifier` intentionally does not
    /// resolve to (it only walks enclosing `compound_statement` blocks).
    /// Mirrors the original whole-file scan, but restricted to direct
    /// children of the translation unit so it can't cross into unrelated
    /// function bodies.
    fn global_time_t_decl(&self, ident_node: &Node, name: &str, source: &str) -> bool {
        let mut top = *ident_node;
        while let Some(p) = top.parent() {
            top = p;
        }
        for i in 0..top.child_count() {
            let Some(decl) = top.child(i) else { continue };
            if decl.kind() != "declaration" {
                continue;
            }
            let Some(type_node) = decl.child(0) else {
                continue;
            };
            if type_node.kind() != "type_identifier"
                || ast_utils::get_node_text(&type_node, source) != "time_t"
            {
                continue;
            }
            for name_node in query::find_descendants_of_kind(decl, "identifier") {
                let is_declared_name = match name_node.parent() {
                    Some(p) if p.kind() == "declaration" => true,
                    Some(p) if p.kind() == "init_declarator" => p.child(0) == Some(name_node),
                    _ => false,
                };
                if is_declared_name && ast_utils::get_node_text(&name_node, source) == name {
                    return true;
                }
            }
        }
        false
    }

    /// Resolve whether the identifier at this specific use site is declared
    /// (locally, as a parameter, or at file scope) with type `time_t`.
    /// Scope- and shadowing-aware: two different functions (or blocks)
    /// declaring a same-named variable of a different type are not conflated.
    fn is_time_t_typed(&self, ident: &Node, source: &str) -> bool {
        let name = ast_utils::get_node_text(ident, source);
        if let Some(decl) =
            ast_utils::find_enclosing_declaration_for_identifier(ident, name, source)
        {
            return Self::type_text_for_decl(&decl, source).contains("time_t");
        }
        if let Some(func) = ast_utils::find_containing_function(ident) {
            if let Some(params) = ast_utils::get_function_parameters(&func, source) {
                if let Some((_, ptype)) = params.iter().find(|(n, _)| n == name) {
                    return ptype.contains("time_t");
                }
            }
        }
        self.global_time_t_decl(ident, name, source)
    }

    fn flag(&self, node: &Node, op: &str, name: &str, violations: &mut Vec<RuleViolation>) {
        let pos = node.start_position();
        violations.push(RuleViolation {
            rule_id: "MSC05-C".to_string(),
            severity: Severity::Low,
            line: pos.row + 1,
            column: pos.column + 1,
            message: format!(
                "arithmetic operator '{}' applied directly to time_t-typed '{}' -- the encoding of time_t is unspecified",
                op, name
            ),
            file_path: String::new(),
            suggestion: Some(
                "Use difftime() to compute a duration between two time_t values instead of subtracting/adding them directly"
                    .to_string(),
            ),
            requires_manual_review: Some(false),
        });
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for bin in query::find_descendants_of_kind(*root, "binary_expression") {
            let Some(op) = bin.child(1) else { continue };
            let op_text = ast_utils::get_node_text(&op, source);
            if !ARITHMETIC_OPS.contains(&op_text) {
                continue;
            }
            for side in ["left", "right"] {
                if let Some(operand) = bin.child_by_field_name(side) {
                    if operand.kind() == "identifier" && self.is_time_t_typed(&operand, source) {
                        let name = ast_utils::get_node_text(&operand, source);
                        self.flag(&bin, op_text, name, violations);
                        break;
                    }
                }
            }
        }

        for assign in query::find_descendants_of_kind(*root, "assignment_expression") {
            let Some(op) = assign.child(1) else { continue };
            let op_text = ast_utils::get_node_text(&op, source);
            if !ARITHMETIC_OPS.contains(&op_text) {
                continue;
            }
            if let Some(left) = assign.child_by_field_name("left") {
                if left.kind() == "identifier" && self.is_time_t_typed(&left, source) {
                    let name = ast_utils::get_node_text(&left, source);
                    self.flag(&assign, op_text, name, violations);
                }
            }
        }
    }
}

impl CertRule for Msc05C {
    fn rule_id(&self) -> &'static str {
        "MSC05-C"
    }

    fn description(&self) -> &'static str {
        "Do not manipulate time_t typed values directly"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "MSC05-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
