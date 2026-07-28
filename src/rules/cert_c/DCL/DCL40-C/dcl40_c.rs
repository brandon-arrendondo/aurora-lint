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
use crate::utility::cert_c::ast_utils::{get_identifier_from_declarator, get_node_text};
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

// C99/C11 minimum guaranteed significant initial characters for an
// external identifier (6.4.2.1p2 / footnote): implementations are only
// required to distinguish identifiers by their first 31 characters.
const MIN_SIGNIFICANT_EXTERNAL_CHARS: usize = 31;

#[derive(Debug)]
pub struct Dcl40C {
    // Track function declarations: name -> (return_type, param_types)
    function_decls: RefCell<HashMap<String, (String, Vec<String>)>>,
    // Track object declarations: name -> type
    object_decls: RefCell<HashMap<String, String>>,
    // Track external-linkage identifiers by their first 31 significant
    // characters, to catch DCL40-C's "excessively long identifiers"
    // case: two distinct external identifiers that agree in their first
    // 31 characters may collide on conforming implementations, which is
    // undefined behavior even though the full names differ.
    truncated_external_decls: RefCell<HashMap<String, String>>,
}

impl Dcl40C {
    pub fn new() -> Self {
        Dcl40C {
            function_decls: RefCell::new(HashMap::new()),
            object_decls: RefCell::new(HashMap::new()),
            truncated_external_decls: RefCell::new(HashMap::new()),
        }
    }

    /// True if this file-scope declaration has internal linkage (`static`)
    /// and is therefore not subject to the external-identifier
    /// significant-character limit.
    fn is_static_declaration(&self, node: &Node, source: &str) -> bool {
        let mut cursor = node.walk();
        let result = node.children(&mut cursor).any(|child| {
            child.kind() == "storage_class_specifier" && get_node_text(&child, source) == "static"
        });
        result
    }

    /// DCL40-C: two external identifiers that agree in their first 31
    /// significant characters but differ afterward may collide on a
    /// conforming implementation (undefined behavior 30), independent of
    /// whether their full spellings or types match.
    fn check_truncated_collision(
        &self,
        node: &Node,
        name: &str,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if self.is_static_declaration(node, source) {
            return;
        }
        // Truncate to the guaranteed-significant prefix so that a short
        // identifier can still be found to collide with an earlier
        // excessively long one (and vice versa); identifiers at or under
        // the limit truncate to themselves, so two distinct short names
        // never spuriously collide here.
        let truncated: String = name.chars().take(MIN_SIGNIFICANT_EXTERNAL_CHARS).collect();
        let mut truncated_decls = self.truncated_external_decls.borrow_mut();
        match truncated_decls.get(&truncated) {
            Some(prev_name) if prev_name != name => {
                violations.push(RuleViolation {
                    rule_id: "DCL40-C".to_string(),
                    severity: Severity::High,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: format!(
                        "Identifier '{}' agrees with '{}' in its first {} significant characters; they may collide as the same external identifier on a conforming implementation",
                        name, prev_name, MIN_SIGNIFICANT_EXTERNAL_CHARS
                    ),
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Shorten one of the identifiers so they differ within the first {} characters",
                        MIN_SIGNIFICANT_EXTERNAL_CHARS
                    )),
                    requires_manual_review: Some(false),
                });
            }
            Some(_) => {}
            None => {
                truncated_decls.insert(truncated, name.to_string());
            }
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

                    self.check_truncated_collision(node, &name, source, violations);

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

                self.check_truncated_collision(node, &name, source, violations);

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
        let target = if declarator.kind() == "init_declarator" {
            declarator
                .child_by_field_name("declarator")
                .unwrap_or(*declarator)
        } else {
            *declarator
        };
        let name = get_identifier_from_declarator(&target, source);
        if name.is_empty() {
            None
        } else {
            Some(name)
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
        self.truncated_external_decls.borrow_mut().clear();
        // Check the tree
        self.check_node(root_node, source, &mut violations);
        violations
    }
}
