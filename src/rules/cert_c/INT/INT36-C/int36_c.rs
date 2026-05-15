//! INT36-C: Converting a pointer to integer or integer to pointer
//!
//! This rule addresses unsafe conversions between pointers and integers.
//! Pointer-to-integer and integer-to-pointer conversions are implementation-defined
//! and can result in information loss, misalignment, or invalid pointers.
//!
//! ## Non-compliant examples:
//!
//! **Pointer to narrow integer:**
//! ```c
//! void *ptr = /* ... */;
//! unsigned int number = (unsigned int)ptr;  // May lose high-order bits on 64-bit systems
//! ```
//!
//! **Integer constant to pointer:**
//! ```c
//! unsigned int *ptr = 0xdeadbeef;  // Unknown alignment/validity
//! ```
//!
//! **Pointer round-trip through narrow integer:**
//! ```c
//! unsigned int number = (unsigned int)ptr;
//! number = (number & 0x7fffff) | (flag << 23);
//! ptr = (char *)number;  // High-order bits lost
//! ```
//!
//! ## Compliant solutions:
//!
//! **Use uintptr_t/intptr_t:**
//! ```c
//! #include <stdint.h>
//! void *ptr = /* ... */;
//! uintptr_t number = (uintptr_t)ptr;  // Safe round-trip
//! ptr = (void *)number;
//! ```
//!
//! **NULL pointer exception:**
//! ```c
//! int *ptr = 0;  // Integer 0 safely converts to null pointer
//! int *ptr2 = NULL;  // Explicit null pointer
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

pub struct Int36C;

impl Int36C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }

    /// Check if a type is a pointer type
    /// Note: bare `void` (without `*`) is NOT a pointer type — it's a discard cast.
    /// `void *` matches via the `*` check.
    fn is_pointer_type(&self, type_text: &str) -> bool {
        type_text.contains('*')
    }

    /// Check if a type is an integer type suitable for pointer storage
    fn is_safe_pointer_integer_type(&self, type_text: &str) -> bool {
        type_text.contains("uintptr_t") || type_text.contains("intptr_t")
    }

    /// Check if a type is a generic integer type
    fn is_integer_type(&self, type_text: &str) -> bool {
        let integer_types = [
            "int",
            "unsigned",
            "long",
            "short",
            "char",
            "size_t",
            "ptrdiff_t",
        ];
        integer_types.iter().any(|&t| {
            type_text.contains(t)
                && !type_text.contains("uintptr_t")
                && !type_text.contains("intptr_t")
        })
    }

    /// Check if an expression is the integer constant 0 (NULL exception)
    fn is_zero_constant(&self, node: &Node, source: &str) -> bool {
        let text = get_node_text(node, source).trim();
        text == "0" || text == "NULL" || text == "nullptr"
    }

    /// Check for pointer-to-integer cast
    fn check_pointer_to_integer_cast(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(type_node), Some(value_node)) = (
            node.child_by_field_name("type"),
            node.child_by_field_name("value"),
        ) {
            let type_text = get_node_text(&type_node, source);

            // Try to infer if the value is a pointer
            // This is a heuristic - ideally we'd have full type analysis
            let value_text = get_node_text(&value_node, source);
            let cast_to_pointer = type_text.contains('*');
            // When the expression contains `->` or `[`, it's a struct field access
            // or array subscript — these dereference the pointer and yield the
            // member/element type, which is typically NOT a pointer itself.
            // Exception: when casting TO a pointer type, the field may itself be
            // a pointer (e.g., structCharVoid->voidSecond is void*).
            let is_dereferenced = value_text.contains("->") || value_text.contains('[');

            // Distinguish address-of (&var) from bitwise AND (expr & mask).
            // Address-of: the value node is a pointer_expression with "&" operator,
            // OR the text starts with "&" (unary).
            // Bitwise AND: appears as " & " with spaces, typically in binary expressions.
            let has_address_of = value_text.starts_with('&')
                || (value_node.kind() == "pointer_expression" && value_text.starts_with('&'));

            // pointer_expression (*ptr) is a dereference — the result is the
            // pointed-to VALUE, not a pointer.  Only treat it as pointer-like if
            // the outer node is a pointer_expression with "&" (address-of).
            let appears_to_be_pointer = has_address_of
                || value_text == "NULL"
                || (!is_dereferenced && value_text.contains("ptr"))
                || (cast_to_pointer && is_dereferenced);

            // Check if casting to an integer type that's not uintptr_t/intptr_t.
            // Exclude pointer types — a cast like `(uint8_t *)&x` has a type_text containing
            // '*', meaning it's a pointer cast, not a pointer-to-integer cast.
            if self.is_integer_type(type_text)
                && !self.is_safe_pointer_integer_type(type_text)
                && !self.is_pointer_type(type_text)
            {
                if appears_to_be_pointer {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Unsafe pointer-to-integer conversion to '{}' (use uintptr_t or intptr_t for portable pointer storage)",
                            type_text.trim()
                        ),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(
                            "Use uintptr_t or intptr_t for safe pointer-to-integer conversions".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check for integer-to-pointer cast
    fn check_integer_to_pointer_cast(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(type_node), Some(value_node)) = (
            node.child_by_field_name("type"),
            node.child_by_field_name("value"),
        ) {
            let type_text = get_node_text(&type_node, source);

            // Check if casting to a pointer type
            if self.is_pointer_type(type_text) {
                // Exception: Integer constant 0 is allowed (NULL)
                if self.is_zero_constant(&value_node, source) {
                    return;
                }

                // Check if the value is an integer expression
                let value_text = get_node_text(&value_node, source);

                // If the value is not uintptr_t/intptr_t based, flag it
                if !self.is_safe_pointer_integer_type(&value_text) {
                    // Only flag numeric literals and integer arithmetic expressions.
                    // Deliberately exclude is_integer_type(&value_text) — that check
                    // matched expression TEXT (e.g. "ALLOCA(sizeof(char))") against type
                    // keywords like "char", causing every void*→T* cast to be flagged.
                    if value_node.kind() == "number_literal"
                        || value_node.kind() == "binary_expression"
                    {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "Unsafe integer-to-pointer conversion from '{}' (may result in misalignment or invalid pointer)",
                                value_text.trim()
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Use uintptr_t/intptr_t for integer values, or ensure value is obtained from a valid pointer".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check for pointer initialization with integer constants
    fn check_pointer_initialization(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for init_declarator with pointer type
        if node.kind() == "init_declarator" {
            if let (Some(declarator), Some(value)) = (
                node.child_by_field_name("declarator"),
                node.child_by_field_name("value"),
            ) {
                // Check if declarator is a pointer
                let declarator_text = get_node_text(&declarator, source);
                if declarator_text.contains('*') {
                    // Exception: 0 or NULL is allowed
                    if self.is_zero_constant(&value, source) {
                        return;
                    }

                    // Check if initialized with a numeric literal
                    if value.kind() == "number_literal" {
                        let value_text = get_node_text(&value, source);
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "Pointer '{}' initialized with integer constant '{}' (unknown alignment/validity)",
                                declarator_text.trim(),
                                value_text.trim()
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Use NULL for null pointers, or derive pointer from valid object/array".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
}

impl CertRule for Int36C {
    fn rule_id(&self) -> &'static str {
        "INT36-C"
    }

    fn description(&self) -> &'static str {
        "Converting a pointer to integer or integer to pointer"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT36-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Int36C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        match node.kind() {
            "cast_expression" => {
                self.check_pointer_to_integer_cast(node, source, violations);
                self.check_integer_to_pointer_cast(node, source, violations);
            }
            "init_declarator" => {
                self.check_pointer_initialization(node, source, violations);
            }
            _ => {}
        }

        // Recursively check child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, violations);
            }
        }
    }
}
