// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! EXP44-C: Do not rely on side effects in operands to sizeof, _Alignof, or _Generic
//!
//! This rule detects when expressions with side effects are used in operands to
//! sizeof, _Alignof, or _Generic. These operators do not evaluate their operands
//! (or evaluation is unspecified for sizeof with VLAs), so any side effects won't
//! actually occur, leading to logic errors.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/EXP44-C.+Do+not+rely+on+side+effects+in+operands+to+sizeof,+_Alignof,+or+_Generic

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Exp44C {
    // Track macros that contain _Generic
    generic_macros: HashSet<String>,
}

impl Exp44C {
    pub fn new() -> Self {
        Exp44C {
            generic_macros: HashSet::new(),
        }
    }

    /// Check if a node represents a side effect
    fn has_side_effect(&self, node: &Node) -> bool {
        match node.kind() {
            // Update expressions: ++, --
            "update_expression" => true,

            // Assignment operators: =, +=, -=, etc.
            "assignment_expression" => true,

            // Function calls (potential side effects)
            "call_expression" => true,

            // Compound assignments
            "compound_assignment_expression" => true,

            _ => {
                // Recursively check children for side effects
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if self.has_side_effect(&child) {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Check sizeof expression for side effects
    fn check_sizeof_expression(&self, node: &Node, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "sizeof_expression" {
            return;
        }

        // Check the value/type argument
        if let Some(value) = node.child_by_field_name("value") {
            if self.has_side_effect(&value) {
                violations.push(RuleViolation {
                    rule_id: "EXP44-C".to_string(),
                    severity: Severity::Low,
                    line: value.start_position().row + 1,
                    column: value.start_position().column + 1,
                    message: "Side effect in sizeof operand will not be evaluated".to_string(),
                    file_path: String::new(),
                    suggestion: Some("Move side effects outside of sizeof operator".to_string()),
                    requires_manual_review: Some(false),
                });
            }
        }

        if let Some(type_node) = node.child_by_field_name("type") {
            if self.has_side_effect(&type_node) {
                violations.push(RuleViolation {
                    rule_id: "EXP44-C".to_string(),
                    severity: Severity::Low,
                    line: type_node.start_position().row + 1,
                    column: type_node.start_position().column + 1,
                    message: "Side effect in sizeof operand will not be evaluated".to_string(),
                    file_path: String::new(),
                    suggestion: Some("Move side effects outside of sizeof operator".to_string()),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    /// Check _Alignof expression for side effects
    fn check_alignof_expression(&self, node: &Node, violations: &mut Vec<RuleViolation>) {
        // tree-sitter might use "alignof_expression" or similar
        if !node.kind().contains("alignof") && !node.kind().contains("Alignof") {
            return;
        }

        // Check all children for side effects
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if self.has_side_effect(&child) {
                violations.push(RuleViolation {
                    rule_id: "EXP44-C".to_string(),
                    severity: Severity::Low,
                    line: child.start_position().row + 1,
                    column: child.start_position().column + 1,
                    message: "_Alignof operand is never evaluated; side effects will not occur"
                        .to_string(),
                    file_path: String::new(),
                    suggestion: Some("Move side effects outside of _Alignof operator".to_string()),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    /// Check _Generic expression for side effects
    fn check_generic_expression(&self, node: &Node, violations: &mut Vec<RuleViolation>) {
        // tree-sitter might use "generic_expression" or similar
        if !node.kind().contains("generic") && !node.kind().contains("Generic") {
            return;
        }

        // The controlling expression in _Generic is not evaluated
        // Check the first argument (controlling expression)
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            // Skip the _Generic keyword itself
            if child.kind() == "identifier" || child.kind() == "(" {
                continue;
            }

            // Check only the controlling expression (first argument)
            if self.has_side_effect(&child) {
                violations.push(RuleViolation {
                    rule_id: "EXP44-C".to_string(),
                    severity: Severity::Low,
                    line: child.start_position().row + 1,
                    column: child.start_position().column + 1,
                    message: "_Generic controlling expression is never evaluated; side effects will not occur".to_string(),
                    file_path: String::new(),
                    suggestion: Some(
                        "Move side effects outside of _Generic operator".to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
            }
            break; // Only check the first argument
        }
    }

    /// Track macro definitions that contain _Generic
    fn collect_generic_macros(&self, node: &Node, source: &str, macros: &mut HashSet<String>) {
        // Look for #define directives
        for n in query::find_descendants_of_kinds(*node, &["preproc_function_def", "preproc_def"]) {
            let text = get_node_text(&n, source);
            // Check if the macro body contains _Generic
            if text.contains("_Generic") {
                // Extract macro name
                if let Some(name_node) = n.child_by_field_name("name") {
                    let name = get_node_text(&name_node, source).trim().to_string();
                    macros.insert(name);
                }
            }
        }
    }

    /// Check if a call expression is to a _Generic-containing macro with side effects
    fn check_generic_macro_call(
        &self,
        node: &Node,
        source: &str,
        generic_macros: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "call_expression" {
            return;
        }

        // Get function name
        if let Some(func_node) = node.child_by_field_name("function") {
            let func_name = get_node_text(&func_node, source).trim().to_string();

            // Check if this is a call to a _Generic-containing macro
            if generic_macros.contains(&func_name) {
                // Check arguments for side effects
                if let Some(args_node) = node.child_by_field_name("arguments") {
                    let mut cursor = args_node.walk();
                    for child in args_node.children(&mut cursor) {
                        if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                            if self.has_side_effect(&child) {
                                violations.push(RuleViolation {
                                    rule_id: "EXP44-C".to_string(),
                                    severity: Severity::Low,
                                    line: child.start_position().row + 1,
                                    column: child.start_position().column + 1,
                                    message: format!(
                                        "Side effect in macro '{}' argument that uses _Generic; expression may not be evaluated",
                                        func_name
                                    ),
                                    file_path: String::new(),
                                    suggestion: Some(
                                        "Move side effects outside of _Generic-containing macro call".to_string(),
                                    ),
                                    requires_manual_review: Some(false),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Recursively traverse AST
    fn traverse(
        &self,
        node: &Node,
        source: &str,
        generic_macros: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            self.check_sizeof_expression(&n, violations);
            self.check_alignof_expression(&n, violations);
            self.check_generic_expression(&n, violations);
            self.check_generic_macro_call(&n, source, generic_macros, violations);
        }
    }
}

impl CertRule for Exp44C {
    fn rule_id(&self) -> &'static str {
        "EXP44-C"
    }

    fn description(&self) -> &'static str {
        "Do not rely on side effects in operands to sizeof, _Alignof, or _Generic"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "EXP44-C"
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect macros that contain _Generic
        let mut generic_macros = HashSet::new();
        self.collect_generic_macros(root, source, &mut generic_macros);

        // Second pass: check for violations
        self.traverse(root, source, &generic_macros, &mut violations);
        violations
    }
}
