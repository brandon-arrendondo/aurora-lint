//! INT12-C: Do not make assumptions about the type of a plain int bit-field when used in an expression
//!
//! Plain `int` bit-fields have implementation-defined signedness, creating portability issues.
//! Always use explicit `signed int` or `unsigned int` for bit-fields.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! struct {
//!     int a: 8;  // Plain int - implementation-defined signedness
//! } bits = {255};
//! ```
//!
//! **Compliant:**
//! ```c
//! struct {
//!     unsigned int a: 8;  // Explicit signedness
//! } bits = {255};
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Int12C;

impl CertRule for Int12C {
    fn rule_id(&self) -> &'static str {
        "INT12-C"
    }

    fn description(&self) -> &'static str {
        "Do not make assumptions about the type of a plain int bit-field when used in an expression"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT12-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Recursively traverse the tree
        self.traverse(node, source, &mut violations);

        violations
    }
}

impl Int12C {
    /// Traverse the AST looking for bit-field declarations
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for field in query::find_descendants_of_kind(*node, "field_declaration") {
            self.check_field_declaration(&field, source, violations);
        }
    }

    /// Check a single field declaration for plain int bit-field
    fn check_field_declaration(
        &self,
        field: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let field_text = get_node_text(field, source);

        // Check if this is a bit-field (contains ':')
        if !field_text.contains(':') {
            return;
        }

        // Check if it uses plain int (not signed/unsigned)
        if !field_text.contains("int") {
            return;
        }

        if field_text.contains("signed") || field_text.contains("unsigned") {
            return;
        }

        // Exclude typedefs like int8_t, uint32_t
        if field_text.contains("_t") {
            return;
        }

        // This is a plain int bit-field - report violation
        let (field_name, line, column) = self.get_field_info(field, source).unwrap_or_else(|| {
            (
                "unknown".to_string(),
                field.start_position().row + 1,
                field.start_position().column + 1,
            )
        });

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            message: format!(
                "Bit-field '{}' uses plain 'int' with implementation-defined signedness. \
                 Use explicit 'signed int' or 'unsigned int' instead.",
                field_name
            ),
            severity: self.severity(),
            line,
            column,
            file_path: String::new(),
            suggestion: Some(format!(
                "Change 'int {}' to 'signed int {}' or 'unsigned int {}'",
                field_name, field_name, field_name
            )),
            requires_manual_review: None,
        });
    }

    /// Get field name and location information
    fn get_field_info(&self, field: &Node, source: &str) -> Option<(String, usize, usize)> {
        // Find the field_declarator
        for i in 0..field.child_count() {
            if let Some(child) = field.child(i) {
                if child.kind() == "field_declarator" {
                    // Find the identifier within the declarator
                    if let Some(identifier) = self.find_identifier(&child, source) {
                        return Some((
                            identifier,
                            field.start_position().row + 1,
                            field.start_position().column + 1,
                        ));
                    }
                }
            }
        }
        None
    }

    /// Find identifier node within a tree
    fn find_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "field_identifier" || node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(id) = self.find_identifier(&child, source) {
                    return Some(id);
                }
            }
        }

        None
    }
}
