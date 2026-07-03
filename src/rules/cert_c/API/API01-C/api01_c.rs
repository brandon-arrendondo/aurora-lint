//! API01-C: Avoid laying out strings in memory directly before sensitive data
//!
//! This rule detects structs where string buffers (char arrays) are placed before
//! pointer fields. Buffer overflows on strings can corrupt subsequent pointers,
//! enabling arbitrary memory access or code execution.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! struct node_s {
//!     char name[20];        // String buffer before pointer - VIOLATION
//!     struct node_s* next;  // Pointer (sensitive data)
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! struct node_s {
//!     struct node_s* next;  // Pointer first
//!     char name[20];        // String after - OK
//! }
//! ```
//!
//! **Also Compliant:**
//! ```c
//! struct node_s {
//!     struct node_s* next;
//!     char* name;           // Pointer to string (not array) - OK
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find struct_specifier nodes
//! - Extract field declarations in order
//! - Check if any char array field comes before any pointer field
//! - Report violation if pattern detected

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::declarator_utils::{is_array_declarator, is_pointer_declarator};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Api01C;

impl CertRule for Api01C {
    fn rule_id(&self) -> &'static str {
        "API01-C"
    }

    fn description(&self) -> &'static str {
        "Avoid laying out strings in memory directly before sensitive data"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "API01-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for struct_node in query::find_descendants_of_kind(*node, "struct_specifier") {
            self.check_struct_layout(&struct_node, source, &mut violations);
        }
        violations
    }
}

impl Api01C {
    fn check_struct_layout(
        &self,
        struct_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the field_declaration_list
        let field_list = match struct_node.child_by_field_name("body") {
            Some(body) => body,
            None => return, // No body (forward declaration)
        };

        // Collect all field declarations
        let mut fields = Vec::new();
        for i in 0..field_list.child_count() {
            if let Some(child) = field_list.child(i) {
                if child.kind() == "field_declaration" {
                    fields.push(child);
                }
            }
        }

        // Check for char arrays followed by pointer fields
        for i in 0..fields.len() {
            if self.is_char_array_field(&fields[i], source) {
                // Check if any subsequent field is a pointer
                for j in (i + 1)..fields.len() {
                    if self.is_pointer_field(&fields[j], source) {
                        self.report_violation(
                            &fields[i],
                            &fields[j],
                            struct_node,
                            source,
                            violations,
                        );
                        break; // Only report once per char array
                    }
                }
            }
        }
    }

    /// Check if a field is a char array (e.g., char name[20])
    fn is_char_array_field(&self, field_node: &Node, source: &str) -> bool {
        // Get the type
        let type_node = match field_node.child_by_field_name("type") {
            Some(t) => t,
            None => return false,
        };

        // Check if type is "char" or "primitive_type" containing "char"
        let type_text = get_node_text(&type_node, source);
        if !type_text.contains("char") {
            return false;
        }

        // Check if declarator is an array
        if let Some(declarator) = field_node.child_by_field_name("declarator") {
            return is_array_declarator(&declarator);
        }

        false
    }

    /// Check if a field is a pointer type
    fn is_pointer_field(&self, field_node: &Node, source: &str) -> bool {
        // Get the type
        let type_node = match field_node.child_by_field_name("type") {
            Some(t) => t,
            None => return false,
        };

        // Check if type contains "*" (pointer)
        let type_text = get_node_text(&type_node, source);
        if type_text.contains('*') {
            return true;
        }

        // Check declarator for pointer
        if let Some(declarator) = field_node.child_by_field_name("declarator") {
            return is_pointer_declarator(&declarator);
        }

        false
    }

    fn report_violation(
        &self,
        char_array_field: &Node,
        pointer_field: &Node,
        struct_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let char_array_text = get_node_text(char_array_field, source);
        let pointer_text = get_node_text(pointer_field, source);

        // Get struct name if available
        let struct_name = if let Some(name_node) = struct_node.child_by_field_name("name") {
            get_node_text(&name_node, source)
        } else {
            "anonymous"
        };

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "String buffer placed before pointer in struct '{}': '{}' before '{}' - Buffer overflow could corrupt pointer",
                struct_name,
                char_array_text.lines().next().unwrap_or(char_array_text).trim(),
                pointer_text.lines().next().unwrap_or(pointer_text).trim()
            ),
            file_path: String::new(),
            line: char_array_field.start_position().row + 1,
            column: char_array_field.start_position().column + 1,
            suggestion: Some(format!(
                "Move the string buffer '{}' after the pointer field '{}', or use a char* pointer instead of a char array",
                char_array_text.split('[').next().unwrap_or("").trim(),
                pointer_text.split(':').next().unwrap_or(pointer_text).trim()
            )),
            ..Default::default()
        });
    }
}
