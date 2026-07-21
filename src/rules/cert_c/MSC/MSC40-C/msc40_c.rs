//! MSC40-C: Do not violate constraints
//!
//! This rule enforces C Standard constraints related to inline function definitions.
//! Specifically, it detects when inline functions violate constraints by:
//! - Referencing identifiers with internal linkage (static identifiers)
//! - Referencing modifiable objects with static or thread storage duration
//! - Containing modifiable static variables
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! static int I = 12;  // Internal linkage
//! extern inline void func(int a) {
//!   int b = a * I;  // References static identifier - violates constraint
//! }
//! ```
//!
//! **Non-compliant:**
//! ```c
//! extern inline void func(void) {
//!   static int I = 12;  // Modifiable static in inline function - violates constraint
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! int I = 12;  // External linkage - OK
//! extern inline void func(int a) {
//!   int b = a * I;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Detect non-static inline functions
//! - Check if they reference static (internally-linked) identifiers
//! - Check if they contain static variable declarations

use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::{get_node_text, get_sanitized_node_text};
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Msc40C;

impl CertRule for Msc40C {
    fn rule_id(&self) -> &'static str {
        "MSC40-C"
    }

    fn cert_id(&self) -> &'static str {
        "MSC40"
    }

    fn description(&self) -> &'static str {
        "Do not violate constraints"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect static (internal linkage) identifiers at file scope
        let mut static_identifiers = HashSet::new();
        self.collect_static_identifiers(node, source, &mut static_identifiers);

        // Second pass: check for violations
        self.check_node_with_statics(node, source, &static_identifiers, &mut violations);
        violations
    }
}

impl Msc40C {
    /// Collect static identifiers declared at file scope
    fn collect_static_identifiers(&self, node: &Node, source: &str, statics: &mut HashSet<String>) {
        // Only look at translation_unit level for file-scope statics
        if node.kind() == "declaration" {
            let decl_text = get_node_text(node, source);
            if decl_text.trim_start().starts_with("static") {
                // Extract variable name from declaration
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    let name = self.extract_identifier_name(&declarator, source);
                    if !name.is_empty() {
                        statics.insert(name);
                    }
                }
            }
        }

        // Only recurse into top-level nodes (not into function bodies)
        if node.kind() == "translation_unit" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                // Skip function definitions when collecting file-scope statics
                if child.kind() != "function_definition" {
                    self.collect_static_identifiers(&child, source, statics);
                }
            }
        }
    }

    fn extract_identifier_name(&self, node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => get_node_text(node, source).trim().to_string(),
            "init_declarator" | "pointer_declarator" | "array_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    return self.extract_identifier_name(&declarator, source);
                }
                // Fallback: try first child
                if let Some(child) = node.child(0) {
                    return self.extract_identifier_name(&child, source);
                }
                String::new()
            }
            _ => {
                // Try to find an identifier child
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        return get_node_text(&child, source).trim().to_string();
                    }
                }
                String::new()
            }
        }
    }

    fn check_node_with_statics(
        &self,
        node: &Node,
        source: &str,
        static_identifiers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for inline function definitions
        for n in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_inline_function_with_statics(&n, source, static_identifiers, violations);
        }
    }

    fn check_inline_function_with_statics(
        &self,
        node: &Node,
        source: &str,
        static_identifiers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this is an inline function (extern inline or just inline, but not static inline)
        if !self.is_non_static_inline_function(node, source) {
            return;
        }

        // Check for static variable declarations inside the function
        self.check_for_internal_static_declarations(node, source, violations);

        // Check for references to static (internally-linked) identifiers
        self.check_for_static_references_with_set(node, source, static_identifiers, violations);
    }

    #[allow(dead_code)]
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for inline function definitions
        for n in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_inline_function(&n, source, violations);
        }
    }

    #[allow(dead_code)]
    fn check_inline_function(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this is an inline function (extern inline or just inline, but not static inline)
        if !self.is_non_static_inline_function(node, source) {
            return;
        }

        // Check for static variable declarations inside the function
        self.check_for_internal_static_declarations(node, source, violations);

        // Check for references to static (internally-linked) identifiers
        self.check_for_static_references(node, source, violations);
    }

    fn is_non_static_inline_function(&self, node: &Node, source: &str) -> bool {
        // Check for inline specifier and ensure it's not static inline.
        // Scan only the signature (up to the body), not the whole function —
        // this both narrows the scope structurally (a comment/string literal
        // in the BODY can no longer be misread as an "inline"/"extern"/
        // "static" specifier) and, as a further guard, sanitizes that
        // signature slice so an inline comment can't spoof it either.
        let signature_end = node
            .child_by_field_name("body")
            .map(|b| b.start_byte())
            .unwrap_or_else(|| node.end_byte());
        let sanitized_func_text = get_sanitized_node_text(node, source);
        let rel_end = (signature_end - node.start_byte()).min(sanitized_func_text.len());
        let func_text = &sanitized_func_text[..rel_end];

        // Check for "extern inline" or just "inline" (not "static inline")
        let has_inline = func_text.contains("inline");
        let has_extern = func_text.contains("extern");

        // If it has inline keyword
        if has_inline {
            // But not static inline (static inline is allowed)
            // Check if "static" appears before "inline" in the declaration
            if let Some(inline_pos) = func_text.find("inline") {
                let before_inline = &func_text[..inline_pos];
                if before_inline.contains("static") {
                    return false; // static inline is compliant
                }
            }
            return true;
        }

        // extern function definitions (without static) that have static variables
        // are also problematic - they provide external linkage with internal state
        if has_extern {
            // Check if "static" appears at the beginning (static extern is unusual but check)
            if !func_text.trim_start().starts_with("static") {
                return true; // extern function without static qualifier
            }
        }

        false
    }

    fn check_for_internal_static_declarations(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for static variable declarations inside the function body
        if let Some(body) = node.child_by_field_name("body") {
            self.find_static_declarations(&body, source, violations);
        }
    }

    fn find_static_declarations(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "declaration") {
            let decl_text = get_node_text(&n, source);
            if decl_text.trim_start().starts_with("static") {
                let start_point = n.start_position();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Low,
                    message: "Non-static inline function contains static variable declaration, violating C Standard constraint. Use external linkage or make the function 'static inline'.".to_string(),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Either remove 'static' from the variable declaration, make the function 'static inline', or remove 'inline' from the function.".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn check_for_static_references_with_set(
        &self,
        node: &Node,
        source: &str,
        static_identifiers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for identifier references in the function body that match static identifiers
        if let Some(body) = node.child_by_field_name("body") {
            self.find_static_references(&body, source, static_identifiers, violations);
        }
    }

    fn find_static_references(
        &self,
        node: &Node,
        source: &str,
        static_identifiers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this is an identifier that matches a static
        for n in query::find_descendants_of_kind(*node, "identifier") {
            let name = get_node_text(&n, source).trim().to_string();
            if static_identifiers.contains(&name) {
                // Check if this is not a declaration (we only want references)
                if let Some(parent) = n.parent() {
                    // Skip if this is the declarator in a declaration
                    if parent.kind() != "init_declarator" && !parent.kind().contains("declarator") {
                        let start_point = n.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Low,
                            message: format!(
                                "Non-static inline function references static identifier '{}' which has internal linkage. This violates C Standard constraint.",
                                name
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Either remove 'static' from the referenced identifier, make the function 'static inline', or remove 'inline' from the function.".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    fn check_for_static_references(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Legacy stub - kept for compatibility
        let _ = (node, source, violations);
    }
}
