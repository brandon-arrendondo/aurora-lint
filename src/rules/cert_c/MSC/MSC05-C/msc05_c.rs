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
use std::collections::HashSet;
use tree_sitter::Node;

const ARITHMETIC_OPS: &[&str] = &["+", "-", "*", "/", "%", "+=", "-=", "*=", "/=", "%="];

#[derive(Debug)]
pub struct Msc05C;

impl Msc05C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc05C
    }

    /// Collect the names of every variable declared with type `time_t`
    /// anywhere in the file (function parameters and local/global declarations).
    fn collect_time_t_names(&self, root: &Node, source: &str, out: &mut HashSet<String>) {
        for decl in
            query::find_descendants_of_kinds(*root, &["declaration", "parameter_declaration"])
        {
            let Some(type_node) = decl.child(0) else {
                continue;
            };
            if type_node.kind() != "type_identifier"
                || ast_utils::get_node_text(&type_node, source) != "time_t"
            {
                continue;
            }
            for name in query::find_descendants_of_kind(decl, "identifier") {
                let is_declared_name = match name.parent() {
                    Some(p) if p.kind() == "declaration" || p.kind() == "parameter_declaration" => {
                        true
                    }
                    Some(p) if p.kind() == "init_declarator" => p.child(0) == Some(name),
                    _ => false,
                };
                if is_declared_name {
                    out.insert(ast_utils::get_node_text(&name, source).to_string());
                }
            }
        }
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
        let mut time_t_names = HashSet::new();
        self.collect_time_t_names(root, source, &mut time_t_names);
        if time_t_names.is_empty() {
            return;
        }

        for bin in query::find_descendants_of_kind(*root, "binary_expression") {
            let Some(op) = bin.child(1) else { continue };
            let op_text = ast_utils::get_node_text(&op, source);
            if !ARITHMETIC_OPS.contains(&op_text) {
                continue;
            }
            for side in ["left", "right"] {
                if let Some(operand) = bin.child_by_field_name(side) {
                    if operand.kind() == "identifier" {
                        let name = ast_utils::get_node_text(&operand, source);
                        if time_t_names.contains(name) {
                            self.flag(&bin, op_text, name, violations);
                            break;
                        }
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
                if left.kind() == "identifier" {
                    let name = ast_utils::get_node_text(&left, source);
                    if time_t_names.contains(name) {
                        self.flag(&assign, op_text, name, violations);
                    }
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
