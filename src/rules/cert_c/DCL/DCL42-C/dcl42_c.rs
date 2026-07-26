// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! DCL42-C: Only call functions with the unsequenced or reproducible attributes
//! if they actually have the asserted property
//!
//! `[[reproducible]]` asserts a function is effectless (no visible side effects
//! outside objects reachable via its own arguments) and idempotent (calling it
//! twice with the same arguments has the same effect as calling it once).
//! `[[unsequenced]]` asserts everything `[[reproducible]]` does, plus independence
//! (the result cannot depend on any external mutable state, e.g. globals).
//!
//! This rule flags functions carrying either attribute whose body visibly
//! violates the asserted property:
//!   - a compound assignment using a non-idempotent operator (+=, -=, *=, /=,
//!     %=, ^=, <<=, >>=) applied to any lvalue -- applying such an operator
//!     twice does not generally produce the same result as applying it once
//!   - a direct write to a file-scope (global) variable -- a side effect not
//!     reachable via the function's own arguments
//!   - for `[[unsequenced]]` only: reading a file-scope (global) variable --
//!     the result then depends on external state, violating independence
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/DCL42-C.+Only+call+functions+with+the+unsequenced+or+reproducible+attributes+if+they+actually+have+the+asserted+property

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

/// Compound-assignment operators that are not idempotent in general: applying
/// them twice with the same right-hand side does not reproduce the effect of
/// applying them once (e.g. `x -= 3` twice subtracts 6, not 3).
const NON_IDEMPOTENT_OPS: &[&str] = &["+=", "-=", "*=", "/=", "%=", "^=", "<<=", ">>="];

#[derive(Debug)]
pub struct Dcl42C;

impl Dcl42C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Dcl42C
    }

    /// Collect the attribute names (e.g. "reproducible", "unsequenced") attached
    /// to a function definition, without descending into the function body.
    fn collect_attributes(&self, func_def: &Node, source: &str, out: &mut HashSet<String>) {
        for i in 0..func_def.child_count() {
            if let Some(child) = func_def.child(i) {
                if child.kind() == "compound_statement" {
                    continue;
                }
                self.collect_attributes_recursive(&child, source, out);
            }
        }
    }

    fn collect_attributes_recursive(&self, node: &Node, source: &str, out: &mut HashSet<String>) {
        if node.kind() == "attribute" {
            if let Some(name_node) = node.named_child(0) {
                out.insert(ast_utils::get_node_text(&name_node, source).to_string());
            }
            return;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_attributes_recursive(&child, source, out);
            }
        }
    }

    /// Collect the names of variables declared at file (global) scope, looking
    /// through preprocessor conditional blocks and skipping function prototypes.
    fn collect_global_names(&self, root: &Node, source: &str, out: &mut HashSet<String>) {
        for i in 0..root.child_count() {
            if let Some(child) = root.child(i) {
                match child.kind() {
                    "declaration" => {
                        if query::find_first_descendant(child, |n| {
                            n.kind() == "function_declarator"
                        })
                        .is_some()
                        {
                            continue;
                        }
                        self.collect_declarator_names(&child, source, out);
                    }
                    k if k.starts_with("preproc_") => {
                        self.collect_global_names(&child, source, out);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Within a top-level declaration, find the declared identifier(s) -- the
    /// last identifier in each declarator chain (skips type names/qualifiers).
    fn collect_declarator_names(&self, decl: &Node, source: &str, out: &mut HashSet<String>) {
        for name in query::find_descendants(*decl, |n| {
            n.kind() == "identifier" || n.kind() == "array_declarator"
        }) {
            if name.kind() == "identifier" {
                out.insert(ast_utils::get_node_text(&name, source).to_string());
            }
        }
    }

    /// Check whether the function body writes to (or, if `check_reads` is set,
    /// also reads) any of the given global variable names, or applies a
    /// non-idempotent compound assignment to any lvalue.
    fn check_body(
        &self,
        body: &Node,
        globals: &HashSet<String>,
        check_reads: bool,
        source: &str,
    ) -> Option<(usize, usize, String)> {
        for assign in query::find_descendants_of_kind(*body, "assignment_expression") {
            let Some(op) = assign.child(1) else { continue };
            let op_text = ast_utils::get_node_text(&op, source);
            if NON_IDEMPOTENT_OPS.contains(&op_text) {
                let pos = assign.start_position();
                return Some((
                    pos.row + 1,
                    pos.column + 1,
                    format!(
                        "non-idempotent compound assignment ('{}') is not safe in a function marked reproducible/unsequenced",
                        op_text
                    ),
                ));
            }
            if let Some(left) = assign.child_by_field_name("left") {
                if left.kind() == "identifier" {
                    let name = ast_utils::get_node_text(&left, source);
                    if globals.contains(name) {
                        let pos = assign.start_position();
                        return Some((
                            pos.row + 1,
                            pos.column + 1,
                            format!(
                                "write to file-scope variable '{}' is a side effect not reachable via the function's arguments",
                                name
                            ),
                        ));
                    }
                }
            }
        }

        if check_reads {
            for ident in query::find_descendants_of_kind(*body, "identifier") {
                let name = ast_utils::get_node_text(&ident, source);
                if globals.contains(name) {
                    let pos = ident.start_position();
                    return Some((
                        pos.row + 1,
                        pos.column + 1,
                        format!(
                            "read of file-scope variable '{}' makes the result depend on external state",
                            name
                        ),
                    ));
                }
            }
        }

        None
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut globals = HashSet::new();
        self.collect_global_names(root, source, &mut globals);

        for func_def in query::find_descendants_of_kind(*root, "function_definition") {
            let mut attrs = HashSet::new();
            self.collect_attributes(&func_def, source, &mut attrs);

            let unsequenced = attrs.contains("unsequenced");
            let reproducible = attrs.contains("reproducible");
            if !unsequenced && !reproducible {
                continue;
            }

            let Some(body) = func_def.child_by_field_name("body") else {
                continue;
            };

            if let Some((line, column, reason)) =
                self.check_body(&body, &globals, unsequenced, source)
            {
                let attr_name = if unsequenced {
                    "unsequenced"
                } else {
                    "reproducible"
                };
                violations.push(RuleViolation {
                    rule_id: "DCL42-C".to_string(),
                    severity: Severity::Medium,
                    line,
                    column,
                    message: format!(
                        "function marked [[{}]] does not actually have the asserted property: {}",
                        attr_name, reason
                    ),
                    file_path: String::new(),
                    suggestion: Some(
                        "Remove the attribute, or change the function so it no longer has visible side effects outside its arguments and is idempotent"
                            .to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
        }
    }
}

impl CertRule for Dcl42C {
    fn rule_id(&self) -> &'static str {
        "DCL42-C"
    }

    fn description(&self) -> &'static str {
        "Only call functions with the unsequenced or reproducible attributes if they actually have the asserted property"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "DCL42-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
