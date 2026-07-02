// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! DCL36-C: Do not declare an identifier with conflicting linkage classifications
//!
//! This rule detects when an identifier is declared with conflicting linkage
//! classifications within a single translation unit. Declaring an identifier
//! with both internal linkage (static) and external linkage (non-static) creates
//! undefined behavior.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/DCL36-C.+Do+not+declare+an+identifier+with+conflicting+linkage+classifications

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Linkage {
    Internal, // static
    External, // non-static
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct IdentifierInfo {
    name: String,
    linkage: Linkage,
    line: usize,
    column: usize,
}

#[derive(Debug)]
pub struct Dcl36C {
    // Track all identifier declarations with their linkage
    declarations: RefCell<HashMap<String, Vec<IdentifierInfo>>>,
}

impl Dcl36C {
    pub fn new() -> Self {
        Dcl36C {
            declarations: RefCell::new(HashMap::new()),
        }
    }

    /// Determine the linkage of a declaration
    fn get_linkage(&self, node: &Node) -> Option<Linkage> {
        // Check if declaration has 'static' storage class specifier
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "storage_class_specifier" {
                // This is a static declaration (internal linkage)
                return Some(Linkage::Internal);
            }
        }

        // No static specifier means external linkage (for file-scope identifiers)
        Some(Linkage::External)
    }

    /// Extract identifier name from a declarator
    fn extract_identifier(&self, declarator: &Node, source: &str) -> Option<String> {
        match declarator.kind() {
            "identifier" => Some(get_node_text(declarator, source).to_string()),
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    return self.extract_identifier(&inner, source);
                }
                None
            }
            "init_declarator" => {
                if let Some(decl) = declarator.child_by_field_name("declarator") {
                    return self.extract_identifier(&decl, source);
                }
                None
            }
            _ => {
                // Try to find identifier child
                let mut cursor = declarator.walk();
                for child in declarator.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        return Some(get_node_text(&child, source).to_string());
                    }
                    if let Some(name) = self.extract_identifier(&child, source) {
                        return Some(name);
                    }
                }
                None
            }
        }
    }

    /// Check if this is a file-scope declaration (not inside a function)
    fn is_file_scope(&self, node: &Node) -> bool {
        let mut current = node.parent();
        while let Some(parent) = current {
            // If we hit a function definition, this is not file scope
            if parent.kind() == "function_definition" {
                return false;
            }
            // If we hit a compound statement (block), check if it's inside a function
            if parent.kind() == "compound_statement" {
                if let Some(grandparent) = parent.parent() {
                    if grandparent.kind() == "function_definition" {
                        return false;
                    }
                }
            }
            current = parent.parent();
        }
        true
    }

    /// Process a declaration node
    fn process_declaration(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "declaration" {
            return;
        }

        // Only check file-scope declarations
        if !self.is_file_scope(node) {
            return;
        }

        // Get linkage for this declaration
        let linkage = match self.get_linkage(node) {
            Some(l) => l,
            None => return,
        };

        // Extract all identifiers from this declaration
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "init_declarator" {
                if let Some(declarator) = child.child_by_field_name("declarator") {
                    if let Some(name) = self.extract_identifier(&declarator, source) {
                        self.record_identifier(name, linkage, node, violations);
                    }
                }
            } else if let Some(name) = self.extract_identifier(&child, source) {
                self.record_identifier(name, linkage, node, violations);
            }
        }
    }

    /// Record an identifier and check for linkage conflicts
    fn record_identifier(
        &self,
        name: String,
        linkage: Linkage,
        node: &Node,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut decls = self.declarations.borrow_mut();
        let entry = decls.entry(name.clone()).or_default();

        // Check if this identifier already has a declaration with different linkage
        for prev in entry.iter() {
            if prev.linkage != linkage {
                violations.push(RuleViolation {
                    rule_id: "DCL36-C".to_string(),
                    severity: Severity::Medium,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: format!(
                        "Identifier '{}' has conflicting linkage: previously declared as {} at line {}, now declared as {}",
                        name,
                        if prev.linkage == Linkage::Internal { "static (internal)" } else { "non-static (external)" },
                        prev.line,
                        if linkage == Linkage::Internal { "static (internal)" } else { "non-static (external)" }
                    ),
                    file_path: String::new(),
                    suggestion: Some(
                        "Use consistent storage-class specifiers for all declarations of the same identifier"
                            .to_string(),
                    ),
                    requires_manual_review: Some(false),
                });
                return;
            }
        }

        // Record this declaration
        entry.push(IdentifierInfo {
            name,
            linkage,
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
        });
    }

    /// Recursively traverse AST
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            self.process_declaration(&n, source, violations);
        }
    }
}

impl CertRule for Dcl36C {
    fn rule_id(&self) -> &'static str {
        "DCL36-C"
    }

    fn description(&self) -> &'static str {
        "Do not declare an identifier with conflicting linkage classifications"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "DCL36-C"
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.declarations.borrow_mut().clear();
        self.traverse(root, source, &mut violations);
        violations
    }
}
