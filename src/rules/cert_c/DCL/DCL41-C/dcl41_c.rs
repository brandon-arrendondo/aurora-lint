// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

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
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Dcl41C;

impl Dcl41C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Dcl41C
    }

    /// Check if a node is a case or default label
    fn is_case_label(&self, node: &Node) -> bool {
        matches!(node.kind(), "case_statement" | "default")
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
        _source: &str,
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
}
