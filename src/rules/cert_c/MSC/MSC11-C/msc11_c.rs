// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! MSC11-C: Incorporate diagnostic tests using assertions
//!
//! `assert()` is a diagnostic tool for catching programmer errors during
//! development/debug builds -- when `NDEBUG` is defined for a release build,
//! `assert()` expands to nothing, and the check silently disappears. Using it
//! to validate a condition that can legitimately occur at runtime due to
//! external factors (rather than a programming logic error) removes the
//! error handling in release builds. This rule flags the specific,
//! statically checkable case from the wiki's own example: `assert()` used as
//! the NULL check on a memory-allocation function's result, where a real
//! runtime out-of-memory condition (not a bug) needs real error handling
//! that survives NDEBUG.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC11-C.+Incorporate+diagnostic+tests+using+assertions

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

const ALLOC_FUNCS: &[&str] = &["malloc", "calloc", "realloc", "strdup"];

#[derive(Debug)]
pub struct Msc11C;

impl Msc11C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc11C
    }

    /// Collect names of variables assigned (anywhere) from a call to a
    /// memory-allocation function.
    fn collect_alloc_vars(&self, root: &Node, source: &str, out: &mut HashSet<String>) {
        for assign in query::find_descendants_of_kind(*root, "assignment_expression") {
            let Some(left) = assign.child_by_field_name("left") else {
                continue;
            };
            if left.kind() != "identifier" {
                continue;
            }
            let Some(right) = assign.child_by_field_name("right") else {
                continue;
            };
            if self.is_alloc_call(&right, source) {
                out.insert(ast_utils::get_node_text(&left, source).to_string());
            }
        }
        for init_decl in query::find_descendants_of_kind(*root, "init_declarator") {
            let Some(name) = init_decl.child(0) else {
                continue;
            };
            if name.kind() != "identifier" {
                continue;
            }
            if let Some(value) = init_decl.child_by_field_name("value") {
                if self.is_alloc_call(&value, source) {
                    out.insert(ast_utils::get_node_text(&name, source).to_string());
                }
            }
        }
    }

    /// Whether `expr` is (possibly through a cast) a call to an allocation
    /// function.
    fn is_alloc_call(&self, expr: &Node, source: &str) -> bool {
        let mut node = *expr;
        if node.kind() == "cast_expression" {
            if let Some(inner) = node.child_by_field_name("value") {
                node = inner;
            }
        }
        if node.kind() != "call_expression" {
            return false;
        }
        let Some(func) = node.child_by_field_name("function") else {
            return false;
        };
        func.kind() == "identifier"
            && ALLOC_FUNCS.contains(&ast_utils::get_node_text(&func, source))
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut alloc_vars = HashSet::new();
        self.collect_alloc_vars(root, source, &mut alloc_vars);
        if alloc_vars.is_empty() {
            return;
        }

        for call in query::find_descendants_of_kind(*root, "call_expression") {
            let Some(func) = call.child_by_field_name("function") else {
                continue;
            };
            if func.kind() != "identifier" || ast_utils::get_node_text(&func, source) != "assert" {
                continue;
            }
            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };
            let Some(cond) = args.named_child(0) else {
                continue;
            };
            if cond.kind() != "binary_expression" {
                continue;
            }
            let Some(op) = cond.child(1) else { continue };
            let op_text = ast_utils::get_node_text(&op, source);
            if op_text != "==" && op_text != "!=" {
                continue;
            }
            let checks_alloc_var = ["left", "right"].into_iter().any(|side| {
                cond.child_by_field_name(side)
                    .map(|n| {
                        n.kind() == "identifier"
                            && alloc_vars.contains(ast_utils::get_node_text(&n, source))
                    })
                    .unwrap_or(false)
            });
            let compares_null = ["left", "right"].into_iter().any(|side| {
                cond.child_by_field_name(side)
                    .map(|n| n.kind() == "null" || ast_utils::get_node_text(&n, source) == "0")
                    .unwrap_or(false)
            });
            if !checks_alloc_var || !compares_null {
                continue;
            }

            let pos = call.start_position();
            violations.push(RuleViolation {
                rule_id: "MSC11-C".to_string(),
                severity: Severity::Low,
                line: pos.row + 1,
                column: pos.column + 1,
                message: "assert() used to check a memory-allocation result -- assert() is compiled out when NDEBUG is defined, silently removing this error handling in release builds".to_string(),
                file_path: String::new(),
                suggestion: Some(
                    "Replace assert() with a real if-check and error handling; allocation failure is a legitimate runtime condition, not a programming logic error"
                        .to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }
}

impl CertRule for Msc11C {
    fn rule_id(&self) -> &'static str {
        "MSC11-C"
    }

    fn description(&self) -> &'static str {
        "Incorporate diagnostic tests using assertions"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "MSC11-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
