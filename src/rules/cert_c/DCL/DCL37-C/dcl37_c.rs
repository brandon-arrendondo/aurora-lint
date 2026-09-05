// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! DCL37-C: Do not declare or define a reserved identifier
//!
//! This rule detects violations where code declares or defines identifiers
//! that are reserved by the C standard, including:
//! - Names starting with underscore followed by uppercase letter (_M, _A, etc.)
//! - Names starting with double underscore (__, ___foo, etc.)
//! - Reserved standard library names (errno, SIZE_MAX, etc.)
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/DCL37-C.+Do+not+declare+or+define+a+reserved+identifier

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

const RESERVED_NAMES: &[&str] = &[
    "errno",
    "SIZE_MAX",
    "INT_MAX",
    "INT_MIN",
    "UINT_MAX",
    "LONG_MAX",
    "LONG_MIN",
    "ULONG_MAX",
    "CHAR_MAX",
    "CHAR_MIN",
    "SHRT_MAX",
    "SHRT_MIN",
    "USHRT_MAX",
    "LLONG_MAX",
    "LLONG_MIN",
    "ULLONG_MAX",
    "NULL",
    "true",
    "false",
    "bool",
    "stdin",
    "stdout",
    "stderr",
    "FILE",
    "EOF",
];

// Standard library function names with external linkage
const RESERVED_FUNCTIONS: &[&str] = &[
    "malloc", "calloc", "realloc", "free", "printf", "scanf", "fprintf", "sprintf", "fopen",
    "fclose", "fread", "fwrite", "memcpy", "memset", "strlen", "strcpy", "strcat", "strcmp",
    "exit", "abort",
];

#[derive(Debug)]
pub struct Dcl37C;

impl Dcl37C {
    pub fn new() -> Self {
        Dcl37C
    }

    /// Check if an identifier is a reserved identifier per C standard
    fn is_reserved_identifier(&self, name: &str) -> bool {
        // Check for leading underscore patterns
        if name.starts_with("__") {
            // Double underscore is reserved
            return true;
        }

        if name.starts_with('_') && name.len() > 1 {
            // Single underscore followed by uppercase letter is reserved
            if let Some(second_char) = name.chars().nth(1) {
                if second_char.is_uppercase() {
                    return true;
                }
            }
        }

        // Check for reserved standard library names
        RESERVED_NAMES.contains(&name)
    }

    /// Check if a name is a reserved function name
    fn is_reserved_function(&self, name: &str) -> bool {
        RESERVED_FUNCTIONS.contains(&name)
    }

    /// Check if identifier starts with underscore (reserved at file scope)
    fn has_file_scope_reserved_prefix(&self, name: &str) -> bool {
        name.starts_with('_')
    }

    /// Check declarations for reserved identifiers
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            match n.kind() {
                "declaration" => {
                    // Check all init_declarators in this declaration
                    let mut cursor = n.walk();
                    for child in n.children(&mut cursor) {
                        if child.kind() == "init_declarator" {
                            if let Some(declarator) = child.child_by_field_name("declarator") {
                                self.check_file_scope_declarator(&declarator, source, violations);
                            }
                        }
                    }
                    // Also check direct declarator field if present
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        self.check_file_scope_declarator(&declarator, source, violations);
                    }
                }
                "preproc_def" | "preproc_function_def" => {
                    self.check_preproc_def(&n, source, violations);
                }
                "function_definition" => {
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        // Function definitions: check against reserved function names and patterns
                        self.check_function_declarator(&declarator, source, violations);
                    }
                }
                "parameter_declaration" => {
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        self.check_declarator(&declarator, source, violations);
                    }
                }
                _ => {}
            }
        }
    }

    /// Check declarations for reserved identifiers
    #[allow(dead_code)]
    fn check_declaration(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            self.check_declarator(&declarator, source, violations);
        }
    }

    /// Check function declarators for reserved function names
    fn check_function_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, source);
                // Check against reserved function names
                if self.is_reserved_function(&name) {
                    violations.push(RuleViolation {
                        rule_id: "DCL37-C".to_string(),
                        severity: Severity::Medium,
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        message: format!(
                            "Reserved function name '{}' should not be redefined",
                            name
                        ),
                        file_path: String::new(),
                        suggestion: Some("Use a different function name".to_string()),
                        requires_manual_review: Some(false),
                    });
                }
                // Also check general reserved identifier patterns
                if self.is_reserved_identifier(&name) {
                    violations.push(RuleViolation {
                        rule_id: "DCL37-C".to_string(),
                        severity: Severity::Medium,
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        message: format!(
                            "Reserved identifier '{}' should not be used as function name",
                            name
                        ),
                        file_path: String::new(),
                        suggestion: Some("Use a non-reserved function name".to_string()),
                        requires_manual_review: Some(false),
                    });
                }
            }
            "function_declarator" => {
                // For function declarators, check the declarator field
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.check_function_declarator(&declarator, source, violations);
                }
            }
            "pointer_declarator" => {
                // Recurse into pointer declarators
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.check_function_declarator(&declarator, source, violations);
                }
            }
            _ => {}
        }
    }

    /// Check file-scope declarators for underscore-prefixed identifiers
    fn check_file_scope_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, source);
                // At file scope, any identifier starting with underscore is reserved
                if self.has_file_scope_reserved_prefix(&name) {
                    violations.push(RuleViolation {
                        rule_id: "DCL37-C".to_string(),
                        severity: Severity::Medium,
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        message: format!(
                            "File-scope identifier '{}' should not start with underscore",
                            name
                        ),
                        file_path: String::new(),
                        suggestion: Some(
                            "Remove the leading underscore or rename the identifier".to_string(),
                        ),
                        requires_manual_review: Some(false),
                    });
                }
                // Also check general reserved patterns
                if self.is_reserved_identifier(&name) {
                    violations.push(RuleViolation {
                        rule_id: "DCL37-C".to_string(),
                        severity: Severity::Medium,
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        message: format!("Reserved identifier '{}' should not be used", name),
                        file_path: String::new(),
                        suggestion: Some("Use a non-reserved identifier".to_string()),
                        requires_manual_review: Some(false),
                    });
                }
            }
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                // Recurse into nested declarators
                for child in node.named_children(&mut node.walk()) {
                    self.check_file_scope_declarator(&child, source, violations);
                }
            }
            _ => {}
        }
    }

    /// Recursively check declarator nodes for identifiers
    fn check_declarator(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, source);
                if self.is_reserved_identifier(&name) {
                    violations.push(RuleViolation {
                        rule_id: "DCL37-C".to_string(),
                        severity: Severity::Medium,
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        message: format!("Reserved identifier '{}' should not be used", name),
                        file_path: String::new(),
                        suggestion: Some("Use a non-reserved identifier".to_string()),
                        requires_manual_review: Some(false),
                    });
                }
            }
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                // Recurse into nested declarators
                for child in node.named_children(&mut node.walk()) {
                    self.check_declarator(&child, source, violations);
                }
            }
            _ => {}
        }
    }

    /// Check macro definitions for reserved identifiers
    fn check_preproc_def(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = get_node_text(&name_node, source);
            if self.is_reserved_identifier(&name) {
                violations.push(RuleViolation {
                    rule_id: "DCL37-C".to_string(),
                    severity: Severity::Medium,
                    line: name_node.start_position().row + 1,
                    column: name_node.start_position().column + 1,
                    message: format!(
                        "Reserved identifier '{}' should not be used as a macro name",
                        name
                    ),
                    file_path: String::new(),
                    suggestion: Some("Use a non-reserved macro name".to_string()),
                    requires_manual_review: Some(false),
                });
            }
        }
    }
}

impl Default for Dcl37C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Dcl37C {
    fn rule_id(&self) -> &'static str {
        "DCL37-C"
    }

    fn description(&self) -> &'static str {
        "Do not declare or define a reserved identifier"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL37-C"
    }

    fn scan(&self, root_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(root_node, source, violations);
    }
}
