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
//! <https://wiki.sei.cmu.edu/confluence/display/c/DCL41-C.+Do+not+declare+variables+inside+a+switch+statement+before+the+first+case+label>

use super::super::{CertRule, RuleViolation};
use crate::analyze::check_macros::{collect_macro_definitions, MacroDefinition};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{macro_expands_to_case_label, FunctionMacro};
use crate::manifest::Severity;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;
use tree_sitter::Node;

#[derive(Default)]
pub struct Dcl41C {
    /// Cross-file function-like macro definitions (from the prescan / macro
    /// engine). Used to recognize macros like sqlite's `CASE(i,str)` that
    /// expand to a real `case i:` label aurora-lint's tree-sitter-based parse can't
    /// see directly — the invocation parses as an ordinary call expression.
    function_macros: RefCell<Arc<HashMap<String, FunctionMacro>>>,
    /// Every definition of every macro name across the scanned files, so a
    /// label-generating macro is recognized whichever arm defines it.
    macro_definitions: RefCell<Arc<HashMap<String, Vec<MacroDefinition>>>>,
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

    /// True if `node` begins with a macro every definition of which begins
    /// with a `case` or `default` label: `#define CASE_AB case 'a': case 'b':`
    /// used as `CASE_AB f(1);`, or `#define DEFAULT_ARM default:`. Written
    /// with no `;` and no argument list, such an invocation glues itself to
    /// the statement after it, so tree-sitter reads the pair as one
    /// `declaration` whose type is the macro's name. The label is in the
    /// expansion, which every configuration shares; a name some definition
    /// expands to anything else stays a statement.
    fn begins_with_label_macro(
        &self,
        node: &Node,
        source: &str,
        file_defs: &HashMap<String, Vec<MacroDefinition>>,
    ) -> bool {
        let mut first = *node;
        while let Some(child) = first.child(0) {
            first = child;
        }
        if !matches!(first.kind(), "identifier" | "type_identifier") {
            return false;
        }
        let Ok(name) = first.utf8_text(source.as_bytes()) else {
            return false;
        };
        let project = self.macro_definitions.borrow();
        let defs: Vec<&MacroDefinition> = [project.get(name), file_defs.get(name)]
            .into_iter()
            .flatten()
            .flatten()
            .collect();
        !defs.is_empty()
            && defs.iter().all(|def| match def {
                MacroDefinition::Object { body } | MacroDefinition::Function { body, .. } => {
                    let body = body.trim_start();
                    ["case", "default"].iter().any(|label| {
                        body.strip_prefix(label).is_some_and(|rest| {
                            !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_')
                        })
                    })
                }
                MacroDefinition::Opaque => false,
            })
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
        file_defs: &HashMap<String, Vec<MacroDefinition>>,
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
                if self.is_case_label_macro_invocation(&child, source)
                    || self.begins_with_label_macro(&child, source, file_defs)
                {
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
        let switches = query::find_descendants_of_kind(*node, "switch_statement");
        if switches.is_empty() {
            return;
        }
        let file_defs = collect_macro_definitions(source);
        for n in switches {
            self.check_switch_statement(&n, source, &file_defs, violations);
        }
    }
}

impl CertRule for Dcl41C {
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn rule_id(&self) -> &'static str {
        "DCL41-C"
    }

    fn description(&self) -> &'static str {
        "Do not declare variables inside a switch statement before the first case label"
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
        *self.macro_definitions.borrow_mut() = context.macro_definitions.clone();
    }
}
