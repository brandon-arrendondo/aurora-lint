//! STR05-C: Use pointers to const when referring to string literals
//!
//! String literals are immutable but lack const qualification when assigned to
//! non-const pointers. This allows code to compile while modifications produce
//! undefined behavior.
//!
//! ## Non-compliant example:
//!
//! ```c
//! char *c = "Hello";         // Should be const char *
//! wchar_t *w = L"Hello";     // Should be const wchar_t *
//!
//! // Attempting modification causes undefined behavior
//! c[0] = 'h';  // Undefined behavior!
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! const char *c = "Hello";      // Pointer to const data
//! char c_copy[] = "Hello";      // Mutable array copy
//! const wchar_t *w = L"Hello";  // Const-qualified wide string
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Str05C;

impl Str05C {
    pub fn new() -> Self {
        Self
    }

    /// Check declarations for non-const pointers to string literals
    fn check_declaration(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "declaration" {
            return;
        }

        // Look for pointer declarator with string literal initializer
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "init_declarator" {
                    self.check_init_declarator(&child, node, source, violations);
                }
            }
        }
    }

    /// Check an init_declarator for string literal assignment to non-const pointer
    fn check_init_declarator(
        &self,
        init_decl_node: &Node,
        decl_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get declarator and value
        let declarator = match init_decl_node.child_by_field_name("declarator") {
            Some(d) => d,
            None => return,
        };

        let value = match init_decl_node.child_by_field_name("value") {
            Some(v) => v,
            None => return,
        };

        // Check if value is a string literal
        if !self.is_string_literal(&value) {
            return;
        }

        // Check if this is a pointer declarator (not array)
        if !self.is_pointer_declarator(&declarator) {
            return;
        }

        // Check if the pointee type is const-qualified
        if self.is_const_qualified_pointee(decl_node, source) {
            return;
        }

        // Violation: non-const pointer to string literal
        let var_name = self.get_declarator_identifier(&declarator, source);
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "Pointer variable '{}' is assigned a string literal without const qualification. String literals are immutable and should be declared as 'const char *' or 'const wchar_t *'.",
                var_name
            ),
            file_path: String::new(),
            line: init_decl_node.start_position().row + 1,
            column: init_decl_node.start_position().column + 1,
            suggestion: Some(
                "Add 'const' qualifier to the pointee type (e.g., change 'char *' to 'const char *')."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    /// Check if a node is a string literal (narrow or wide)
    fn is_string_literal(&self, node: &Node) -> bool {
        matches!(
            node.kind(),
            "string_literal" | "concatenated_string" | "L\"...\""
        )
    }

    /// Check if declarator is a pointer (has * in its structure)
    fn is_pointer_declarator(&self, declarator: &Node) -> bool {
        if declarator.kind() == "pointer_declarator" {
            return true;
        }

        // Recursively check children
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if self.is_pointer_declarator(&child) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if the pointee type in a declaration has const qualification
    fn is_const_qualified_pointee(&self, decl_node: &Node, source: &str) -> bool {
        // Look for type_qualifier node with "const" before the pointer
        for i in 0..decl_node.child_count() {
            if let Some(child) = decl_node.child(i) {
                if child.kind() == "type_qualifier" {
                    let text = get_node_text(&child, source);
                    if text.contains("const") {
                        return true;
                    }
                }

                // Also check inside primitive_type or type_identifier
                if child.kind() == "primitive_type" || child.kind() == "type_identifier" {
                    let text = get_node_text(&child, source);
                    if text.contains("const") {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Extract identifier name from declarator
    fn get_declarator_identifier(&self, declarator: &Node, source: &str) -> String {
        // Look for identifier in declarator tree
        if declarator.kind() == "identifier" {
            return get_node_text(declarator, source).to_string();
        }

        // Recursively search children
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                let result = self.get_declarator_identifier(&child, source);
                if !result.is_empty() {
                    return result;
                }
            }
        }

        String::from("(unknown)")
    }
}

impl CertRule for Str05C {
    fn rule_id(&self) -> &'static str {
        "STR05-C"
    }

    fn description(&self) -> &'static str {
        "Use pointers to const when referring to string literals"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "STR05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Str05C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "declaration") {
            self.check_declaration(&n, source, violations);
        }
    }
}
