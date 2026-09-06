// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! DCL41-C: Do not declare variables inside a switch statement before the first case label
//!
//! This rule detects variable declarations and executable statements that appear
//! before the first case or default label in a switch statement. Such declarations
//! create variables with switch-block scope but which may remain uninitialized when
//! control flow jumps directly to a case label, leading to undefined behavior.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/DCL41-C.+Do+not+declare+variables+inside+a+switch+statement+before+the+first+case+label

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{macro_expands_to_case_label, FunctionMacro};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Default)]
pub struct Dcl41C {
    /// Cross-file function-like macro definitions (from the prescan / macro
    /// engine). Used to recognize macros like sqlite's `CASE(i,str)` that
    /// expand to a real `case i:` label aurora-lint's tree-sitter-based parse can't
    /// see directly — the invocation parses as an ordinary call expression.
    function_macros: RefCell<HashMap<String, FunctionMacro>>,
}

impl Dcl41C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a node is a case or default label
    fn is_case_label(&self, node: &Node) -> bool {
        matches!(node.kind(), "case_statement" | "default")
    }

    /// True if `node` is an `expression_statement` invoking a function-like
    /// macro whose replacement list begins with a `case` label (e.g. sqlite's
    /// `CASE(i,str)` → `case i: assert(...);`). Such an invocation *is* the
    /// first case label, even though tree-sitter sees only an ordinary call.
    fn is_case_label_macro_invocation(&self, node: &Node, source: &str) -> bool {
        if node.kind() != "expression_statement" {
            return false;
        }
        let call = match node.child(0) {
            Some(c) if c.kind() == "call_expression" => c,
            _ => return false,
        };
        let func = match call.child_by_field_name("function") {
            Some(f) if f.kind() == "identifier" => f,
            _ => return false,
        };
        let name = match func.utf8_text(source.as_bytes()) {
            Ok(n) => n,
            Err(_) => return false,
        };
        let macros = self.function_macros.borrow();
        macro_expands_to_case_label(&macros, name)
    }

    /// Check if a node is a declaration or executable statement
    fn is_statement_or_declaration(&self, node: &Node) -> bool {
        matches!(
            node.kind(),
            "declaration"
                | "expression_statement"
                | "if_statement"
                | "while_statement"
                | "do_statement"
                | "for_statement"
                | "return_statement"
                | "break_statement"
                | "continue_statement"
                | "goto_statement"
                | "switch_statement"
                | "function_definition"
                | "labeled_statement"
        )
    }

    /// Check a switch statement for violations
    fn check_switch_statement(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "switch_statement" {
            return;
        }

        // Get the compound statement (body) of the switch
        if let Some(body) = node.child_by_field_name("body") {
            if body.kind() != "compound_statement" {
                return;
            }

            // Track if we've seen a case/default label yet
            let mut found_first_label = false;

            // Iterate through direct children of the compound statement
            let mut cursor = body.walk();
            for child in body.children(&mut cursor) {
                // Skip opening/closing braces
                if child.kind() == "{" || child.kind() == "}" {
                    continue;
                }

                // Check if this is a case/default label
                if self.is_case_label(&child) {
                    found_first_label = true;
                    continue;
                }

                // Check if this is a macro invocation that expands to a case
                // label (e.g. sqlite's `CASE(i,str)`) — hidden from the plain
                // AST, so treat it the same as a real case label.
                if self.is_case_label_macro_invocation(&child, source) {
                    found_first_label = true;
                    continue;
                }

                // If we haven't found the first label yet and this is a statement/declaration
                if !found_first_label && self.is_statement_or_declaration(&child) {
                    let kind_desc = match child.kind() {
                        "declaration" => "Variable declaration",
                        "expression_statement" => "Expression statement",
                        _ => "Statement",
                    };

                    violations.push(RuleViolation {
                        rule_id: "DCL41-C".to_string(),
                        severity: Severity::Medium,
                        line: child.start_position().row + 1,
                        column: child.start_position().column + 1,
                        message: format!(
                            "{} appears before the first case label in switch statement",
                            kind_desc
                        ),
                        file_path: String::new(),
                        suggestion: Some(
                            "Move declarations and statements outside the switch statement or after the first case label"
                                .to_string(),
                        ),
                        requires_manual_review: Some(false),
                    });
                }
            }
        }
    }

    /// Recursively traverse AST
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "switch_statement") {
            self.check_switch_statement(&n, source, violations);
        }
    }
}

impl CertRule for Dcl41C {
    fn rule_id(&self) -> &'static str {
        "DCL41-C"
    }

    fn description(&self) -> &'static str {
        "Do not declare variables inside a switch statement before the first case label"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "DCL41-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_macros.borrow_mut() = context.function_macros.clone();
    }
}
