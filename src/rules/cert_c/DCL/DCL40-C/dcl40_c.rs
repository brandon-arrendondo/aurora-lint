// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! DCL40-C: Do not create incompatible declarations of the same function or object
//!
//! This rule detects violations where a function or object is declared multiple
//! times with incompatible types. This causes undefined behavior.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/DCL40-C.+Do+not+create+incompatible+declarations+of+the+same+function+or+object

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Dcl40C {
    // Track function declarations: name -> (return_type, param_types)
    function_decls: RefCell<HashMap<String, (String, Vec<String>)>>,
    // Track object declarations: name -> type
    object_decls: RefCell<HashMap<String, String>>,
}

impl Dcl40C {
    pub fn new() -> Self {
        Dcl40C {
            function_decls: RefCell::new(HashMap::new()),
            object_decls: RefCell::new(HashMap::new()),
        }
    }

    /// Get function name from declarator
    fn get_function_name(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(get_node_text(node, source).to_string()),
            "function_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.get_function_name(&declarator, source)
                } else {
                    None
                }
            }
            "pointer_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.get_function_name(&declarator, source)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Get return type from declaration
    fn get_return_type(&self, node: &Node, source: &str) -> String {
        if let Some(type_node) = node.child_by_field_name("type") {
            get_node_text(&type_node, source).to_string()
        } else {
            "int".to_string() // Default in old C
        }
    }

    /// Check if a declarator is a function declarator
    fn is_function_declarator(&self, node: &Node) -> bool {
        match node.kind() {
            "function_declarator" => true,
            "pointer_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.is_function_declarator(&declarator)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Get parameter types from function declarator
    fn get_param_types(&self, node: &Node, source: &str) -> Vec<String> {
        let mut params = Vec::new();

        if node.kind() == "function_declarator" {
            if let Some(parameters) = node.child_by_field_name("parameters") {
                let mut cursor = parameters.walk();
                for child in parameters.children(&mut cursor) {
                    if child.kind() == "parameter_declaration" {
                        if let Some(type_node) = child.child_by_field_name("type") {
                            params.push(get_node_text(&type_node, source).to_string());
                        }
                    } else if child.kind() == "variadic_parameter" {
                        params.push("...".to_string());
                    }
                }
            }
        } else if node.kind() == "pointer_declarator" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                return self.get_param_types(&declarator, source);
            }
        }

        params
    }

    /// Check function declarations for incompatibilities
    fn check_function_declaration(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            if self.is_function_declarator(&declarator) {
                if let Some(name) = self.get_function_name(&declarator, source) {
                    let return_type = self.get_return_type(node, source);
                    let param_types = self.get_param_types(&declarator, source);

                    let mut function_decls = self.function_decls.borrow_mut();

                    if let Some((prev_return_type, prev_param_types)) = function_decls.get(&name) {
                        // Check for incompatible return types
                        if *prev_return_type != return_type {
                            violations.push(RuleViolation {
                                rule_id: "DCL40-C".to_string(),
                                severity: Severity::High,
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                message: format!(
                                    "Incompatible declarations of function '{}': return types '{}' and '{}'",
                                    name, prev_return_type, return_type
                                ),
                                file_path: String::new(),
                                suggestion: Some("Ensure all declarations of the same function have identical signatures".to_string()),
                                requires_manual_review: Some(false),
                            });
                        }
                        // Check for incompatible parameter types
                        else if prev_param_types.len() != param_types.len()
                            || prev_param_types
                                .iter()
                                .zip(&param_types)
                                .any(|(a, b)| a != b)
                        {
                            violations.push(RuleViolation {
                                rule_id: "DCL40-C".to_string(),
                                severity: Severity::High,
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                message: format!(
                                    "Incompatible declarations of function '{}': parameter types differ",
                                    name
                                ),
                                file_path: String::new(),
                                suggestion: Some("Ensure all declarations of the same function have identical signatures".to_string()),
                                requires_manual_review: Some(false),
                            });
                        }
                    } else {
                        // First declaration - store it
                        function_decls.insert(name, (return_type, param_types));
                    }
                }
            }
        }
    }

    /// Check object declarations for incompatibilities
    fn check_object_declaration(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            // Skip function declarators - handled separately
            if self.is_function_declarator(&declarator) {
                return;
            }

            // Get variable name
            if let Some(name) = self.get_variable_name(&declarator, source) {
                // Get type information
                let type_info = self.get_object_type(node, &declarator, source);

                let mut object_decls = self.object_decls.borrow_mut();
                if let Some(prev_type) = object_decls.get(&name) {
                    // Check for incompatible types
                    if prev_type != &type_info {
                        violations.push(RuleViolation {
                            rule_id: "DCL40-C".to_string(),
                            severity: Severity::High,
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            message: format!(
                                "Incompatible declarations of object '{}': types '{}' and '{}'",
                                name, prev_type, type_info
                            ),
                            file_path: String::new(),
                            suggestion: Some(
                                "Ensure all declarations of the same object have identical types"
                                    .to_string(),
                            ),
                            requires_manual_review: Some(false),
                        });
                    }
                } else {
                    // First declaration - store it
                    object_decls.insert(name, type_info);
                }
            }
        }
    }

    /// Get variable name from declarator
    fn get_variable_name(&self, declarator: &Node, source: &str) -> Option<String> {
        match declarator.kind() {
            "identifier" => Some(get_node_text(declarator, source).to_string()),
            "pointer_declarator" | "array_declarator" | "init_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.get_variable_name(&inner, source)
                } else {
                    // Try to find identifier child
                    for i in 0..declarator.child_count() {
                        if let Some(child) = declarator.child(i) {
                            if child.kind() == "identifier" {
                                return Some(get_node_text(&child, source).to_string());
                            }
                            if let Some(name) = self.get_variable_name(&child, source) {
                                return Some(name);
                            }
                        }
                    }
                    None
                }
            }
            _ => {
                // Search for identifier in children
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            return Some(get_node_text(&child, source).to_string());
                        }
                    }
                }
                None
            }
        }
    }

    /// Get object type as a normalized string
    fn get_object_type(&self, decl_node: &Node, declarator: &Node, source: &str) -> String {
        let base_type = self.get_return_type(decl_node, source);
        let declarator_type = self.get_declarator_type(declarator, source);

        // Normalize: treat int[] and int* as incompatible for extern declarations
        format!("{}{}", base_type, declarator_type)
    }

    /// Get type modifier from declarator (*, [], etc.)
    fn get_declarator_type(&self, declarator: &Node, source: &str) -> String {
        match declarator.kind() {
            "pointer_declarator" => {
                let inner = if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.get_declarator_type(&inner, source)
                } else {
                    String::new()
                };
                format!("*{}", inner)
            }
            "array_declarator" => {
                let inner = if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.get_declarator_type(&inner, source)
                } else {
                    String::new()
                };
                format!("{}[]", inner)
            }
            "init_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.get_declarator_type(&inner, source)
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        }
    }

    /// Check declarations — only at file scope (direct children of translation_unit
    /// or preproc_* blocks). Declarations inside function bodies are local variables
    /// and cannot conflict with file-scope declarations in the DCL40-C sense.
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        match node.kind() {
            "translation_unit" => {
                // Only process direct children at file scope
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    match child.kind() {
                        "declaration" => {
                            self.check_function_declaration(&child, source, violations);
                            self.check_object_declaration(&child, source, violations);
                        }
                        "function_definition" => {
                            self.check_function_declaration(&child, source, violations);
                        }
                        kind if kind.starts_with("preproc_") => {
                            // Recurse into preprocessor blocks at file scope
                            self.check_node(&child, source, violations);
                        }
                        _ => {}
                    }
                }
            }
            kind if kind.starts_with("preproc_") => {
                // Process direct children of preprocessor blocks
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    match child.kind() {
                        "declaration" => {
                            self.check_function_declaration(&child, source, violations);
                            self.check_object_declaration(&child, source, violations);
                        }
                        "function_definition" => {
                            self.check_function_declaration(&child, source, violations);
                        }
                        kind if kind.starts_with("preproc_") => {
                            self.check_node(&child, source, violations);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

impl Default for Dcl40C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Dcl40C {
    fn rule_id(&self) -> &'static str {
        "DCL40-C"
    }

    fn description(&self) -> &'static str {
        "Do not create incompatible declarations of the same function or object"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL40-C"
    }

    fn check(&self, root_node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        // Clear previous state
        self.function_decls.borrow_mut().clear();
        self.object_decls.borrow_mut().clear();
        // Check the tree
        self.check_node(root_node, source, &mut violations);
        violations
    }
}
