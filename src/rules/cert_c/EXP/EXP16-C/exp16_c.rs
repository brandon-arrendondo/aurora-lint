// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! EXP16-C: Do not compare function pointers to constant values
//!
//! This rule detects comparisons of function pointers to constant values
//! (other than null pointers). This typically indicates programmer error
//! where the function was intended to be called but the parentheses were omitted.
//!
//! VIOLATIONS:
//! - if (getuid == 0)      // Function identifier compared to constant
//! - if (geteuid != 0)     // Function identifier compared to constant
//! - if (do_xyz)           // Function identifier used as boolean (implicit != 0)
//!
//! COMPLIANT:
//! - if (getuid() == 0)    // Function is called, result compared
//! - if (geteuid() != 0)   // Function is called, result compared
//! - if (do_xyz())         // Function is called, result used as boolean

use std::collections::HashSet;

use super::super::{CertRule, RuleViolation};
use crate::analyze::side_effects::designates_object_in;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::ScopeDeclarations;
use crate::utility::cert_c::node_children::NodeChildren;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp16C;

impl CertRule for Exp16C {
    fn rule_id(&self) -> &'static str {
        "EXP16-C"
    }

    fn description(&self) -> &'static str {
        "Do not compare function pointers to constant values"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "EXP16-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let names = FunctionNames {
            names: self.collect_function_names(node, source),
            root: *node,
            declarations: ScopeDeclarations::indexed(*node),
        };
        self.check_node(node, source, &names, &mut violations);
        violations
    }
}

/// The names this file declares as functions, and what resolves an
/// occurrence of one to the declaration that binds it there: a local or a
/// parameter spelled like a function is an object (ADR-0006).
struct FunctionNames<'a> {
    names: HashSet<String>,
    root: Node<'a>,
    declarations: ScopeDeclarations<'a>,
}

impl Exp16C {
    /// Collect all function names defined or declared in this translation unit.
    fn collect_function_names(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        self.collect_function_names_recursive(node, source, &mut names);
        names
    }

    fn collect_function_names_recursive(
        &self,
        node: &Node,
        source: &str,
        names: &mut HashSet<String>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["function_definition", "declaration"]) {
            match n.kind() {
                "function_definition" => {
                    if let Some(name) = self.extract_function_name(&n, source) {
                        names.insert(name);
                    }
                }
                "declaration" => {
                    // Forward declarations: check if declarator contains a function_declarator
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        if self.has_function_declarator(&declarator) {
                            if let Some(name) = self.extract_declarator_name(&declarator, source) {
                                names.insert(name);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn extract_function_name(&self, func_def: &Node, source: &str) -> Option<String> {
        let declarator = func_def.child_by_field_name("declarator")?;
        self.extract_declarator_name(&declarator, source)
    }

    fn extract_declarator_name(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(node.utf8_text(source.as_bytes()).ok()?.to_string()),
            "function_declarator" | "pointer_declarator" | "parenthesized_declarator" => {
                let child = node.child_by_field_name("declarator")?;
                self.extract_declarator_name(&child, source)
            }
            _ => {
                // Walk children looking for an identifier
                for child in node.child_nodes() {
                    if let Some(name) = self.extract_declarator_name(&child, source) {
                        return Some(name);
                    }
                }
                None
            }
        }
    }

    fn has_function_declarator(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "function_declarator").is_some()
    }

    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        function_names: &FunctionNames<'a>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let kinds = [
            "binary_expression",
            "if_statement",
            "while_statement",
            "parenthesized_expression",
        ];
        let found = query::find_descendants_of_kinds(*node, &kinds);
        // The parenthesized expressions directly under an `if` or `while`,
        // read from the statements down rather than from each expression up:
        // `Node::parent` costs the node's depth.
        let conditions: HashSet<usize> = found
            .iter()
            .filter(|n| matches!(n.kind(), "if_statement" | "while_statement"))
            .flat_map(|n| n.child_nodes())
            .filter(|c| c.kind() == "parenthesized_expression")
            .map(|c| c.id())
            .collect();
        for n in found {
            match n.kind() {
                // Check binary expressions for comparisons
                "binary_expression" => {
                    self.check_binary_expression(&n, source, function_names, violations);
                }
                // An if/while condition that is a bare identifier, tested
                // against 0. Read once, here: the statement itself has no
                // check of its own.
                "parenthesized_expression" if conditions.contains(&n.id()) => {
                    // Check the inner expression
                    for child in n.child_nodes() {
                        if child.kind() == "identifier" {
                            self.check_identifier_as_condition(
                                &child,
                                source,
                                function_names,
                                violations,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn check_binary_expression<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        function_names: &FunctionNames<'a>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the operator
        let mut operator = None;
        let mut left = None;
        let mut right = None;

        for child in node.child_nodes() {
            match child.kind() {
                "==" | "!=" | "<" | ">" | "<=" | ">=" => {
                    operator = Some(child.kind());
                }
                _ => {
                    if left.is_none() {
                        left = Some(child);
                    } else if right.is_none() {
                        right = Some(child);
                    }
                }
            }
        }

        // Only check comparison operators
        if let (Some(op), Some(left_node), Some(right_node)) = (operator, left, right) {
            if op == "==" || op == "!=" || op == "<" || op == ">" || op == "<=" || op == ">=" {
                // Check if left side is a function identifier and right is a constant
                if self.is_function_identifier(&left_node, source, function_names)
                    && self.is_constant(&right_node, source)
                {
                    let func_name = left_node.utf8_text(source.as_bytes()).unwrap_or("unknown");
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        message: format!(
                            "Function pointer '{}' compared to constant value; did you mean to call the function?",
                            func_name
                        ),
                        suggestion: Some(format!(
                            "Use '{}()' to call the function instead of comparing its address",
                            func_name
                        )),
                        requires_manual_review: None,
                    });
                }

                // Check if right side is a function identifier and left is a constant
                if self.is_function_identifier(&right_node, source, function_names)
                    && self.is_constant(&left_node, source)
                {
                    let func_name = right_node.utf8_text(source.as_bytes()).unwrap_or("unknown");
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        message: format!(
                            "Function pointer '{}' compared to constant value; did you mean to call the function?",
                            func_name
                        ),
                        suggestion: Some(format!(
                            "Use '{}()' to call the function instead of comparing its address",
                            func_name
                        )),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    fn check_identifier_as_condition<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        function_names: &FunctionNames<'a>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // An identifier used directly in a condition is implicitly compared to 0
        if self.is_function_identifier(node, source, function_names) {
            let func_name = node.utf8_text(source.as_bytes()).unwrap_or("unknown");
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                file_path: String::new(),
                message: format!(
                    "Function pointer '{}' used in boolean context; did you mean to call the function?",
                    func_name
                ),
                suggestion: Some(format!(
                    "Use '{}()' to call the function instead of testing its address",
                    func_name
                )),
                requires_manual_review: None,
            });
        }
    }

    fn is_function_identifier<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        function_names: &FunctionNames<'a>,
    ) -> bool {
        if node.kind() != "identifier" {
            return false;
        }

        let name = node.utf8_text(source.as_bytes()).unwrap_or("");

        // Check against function names collected from the AST, with a
        // fallback to well-known standard library functions. Asked first:
        // the parent test below costs the identifier's depth.
        const KNOWN_FUNCTIONS: &[&str] = &[
            "getuid", "geteuid", "getgid", "getegid", "getpid", "getppid", "fork", "exit", "main",
            "printf", "scanf", "malloc", "free", "strlen", "strcpy", "strcat", "strcmp", "memcpy",
            "memset", "fopen", "fclose", "fread", "fwrite", "rand", "srand",
        ];
        if !function_names.names.contains(name) && !KNOWN_FUNCTIONS.contains(&name) {
            return false;
        }
        // A parameter, a local or a function pointer of that name is an
        // object, and testing or comparing an object is not this rule's.
        if designates_object_in(
            &function_names.root,
            node,
            source,
            &function_names.declarations,
        ) {
            return false;
        }

        // If this identifier is being called (parent is call_expression), it's fine
        if let Some(parent) = node.parent() {
            if parent.kind() == "call_expression" {
                if let Some(func) = parent.child_by_field_name("function") {
                    if func.id() == node.id() {
                        return false;
                    }
                }
            }
        }
        true
    }

    fn is_constant(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "number_literal" | "char_literal" | "true" | "false" | "null" => true,
            "identifier" => {
                let text = node.utf8_text(source.as_bytes()).unwrap_or("");
                text == "NULL" || text == "nullptr"
            }
            _ => false,
        }
    }
}
