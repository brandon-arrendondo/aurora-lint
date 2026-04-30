//! INT10-C: Do not assume a positive remainder when using the % operator
//!
//! The C Standard states that if either operand of the modulo (%) operator is negative,
//! the sign of the result is implementation-defined. This means the result can be negative
//! even when you might expect a positive value. This is particularly dangerous when:
//! 1. The result is used as an array index (can cause out-of-bounds access)
//! 2. The result is expected to be positive for algorithm correctness
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int insert(int index, int *list, int size, int value) {
//!     if (size != 0) {
//!         index = (index + 1) % size;  // Can be negative!
//!         list[index] = value;         // Undefined behavior if negative
//!         return index;
//!     }
//!     return -1;
//! }
//! ```
//!
//! **Non-compliant (abs() is not a fix):**
//! ```c
//! index = abs((index + 1) % size);  // abs(INT_MIN) is undefined behavior
//! ```
//!
//! **Compliant (use unsigned types):**
//! ```c
//! size_t insert(size_t index, int *list, size_t size, int value) {
//!     if (size != 0 && size != SIZE_MAX) {
//!         index = (index + 1) % size;  // Always positive (unsigned)
//!         list[index] = value;
//!         return index;
//!     }
//!     return SIZE_MAX;  // Error indicator
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Int10C;

impl CertRule for Int10C {
    fn rule_id(&self) -> &'static str {
        "INT10-C"
    }

    fn description(&self) -> &'static str {
        "Do not assume a positive remainder when using the % operator"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT10-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let type_map = self.collect_variable_types(node, source);
        self.check_modulo_usage(node, source, &mut violations, &type_map);
        violations
    }
}

impl Int10C {
    /// Collect variable types from function parameters and local declarations
    fn collect_variable_types(&self, node: &Node, source: &str) -> HashMap<String, String> {
        let mut type_map = HashMap::new();
        self.collect_types_recursive(node, source, &mut type_map);
        type_map
    }

    fn collect_types_recursive(
        &self,
        node: &Node,
        source: &str,
        type_map: &mut HashMap<String, String>,
    ) {
        match node.kind() {
            "parameter_declaration" | "declaration" => {
                // Extract type text from the node
                let mut type_text = String::new();
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    match child.kind() {
                        "type_qualifier"
                        | "primitive_type"
                        | "sized_type_specifier"
                        | "type_identifier" => {
                            if !type_text.is_empty() {
                                type_text.push(' ');
                            }
                            type_text.push_str(get_node_text(&child, source));
                        }
                        _ => {}
                    }
                }
                if !type_text.is_empty() {
                    // Extract identifiers from declarators
                    let mut cursor2 = node.walk();
                    for child in node.children(&mut cursor2) {
                        self.extract_var_names(&child, source, &type_text, type_map);
                    }
                }
            }
            _ => {}
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_types_recursive(&child, source, type_map);
        }
    }

    fn extract_var_names(
        &self,
        node: &Node,
        source: &str,
        type_text: &str,
        type_map: &mut HashMap<String, String>,
    ) {
        if node.kind() == "identifier" {
            if let Some(parent) = node.parent() {
                let pk = parent.kind();
                if pk == "init_declarator"
                    || pk == "pointer_declarator"
                    || pk == "array_declarator"
                    || pk == "parameter_declaration"
                {
                    type_map.insert(
                        get_node_text(node, source).to_string(),
                        type_text.to_string(),
                    );
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.extract_var_names(&child, source, type_text, type_map);
        }
    }

    fn check_modulo_usage(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        type_map: &HashMap<String, String>,
    ) {
        if node.kind() == "binary_expression" {
            if let Some(operator) = node.child_by_field_name("operator") {
                let op_text = get_node_text(&operator, source);

                if op_text == "%" {
                    // Check if this is a signed modulo operation
                    if self.is_potentially_signed_modulo(node, source, type_map) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: "Modulo operator used with potentially signed operands. \
                                     The result of % with negative operands is implementation-defined \
                                     and can be negative. Use unsigned types (size_t, unsigned int) \
                                     or explicitly handle negative remainders."
                                .to_string(),
                            severity: self.severity(),
                            line: operator.start_position().row + 1,
                            column: operator.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Convert operands to unsigned types (size_t, unsigned int) \
                                 or add explicit checks for negative values"
                                    .to_string(),
                            ),
                            requires_manual_review: Some(true),
                        });
                    }
                }
            }
        }

        // Recurse through children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_modulo_usage(&child, source, violations, type_map);
            }
        }
    }

    /// Check if a modulo operation might involve signed operands
    fn is_potentially_signed_modulo(
        &self,
        modulo_node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        // Get left and right operands
        let left = modulo_node.child_by_field_name("left");
        let right = modulo_node.child_by_field_name("right");

        if left.is_none() || right.is_none() {
            return false;
        }

        let left_node = left.unwrap();
        let right_node = right.unwrap();

        // Check if either operand appears to be unsigned
        let left_text = get_node_text(&left_node, source);
        let right_text = get_node_text(&right_node, source);

        // If either operand is explicitly unsigned, it's likely safe
        let expr_is_unsigned = self.looks_unsigned(&left_text) || self.looks_unsigned(&right_text);

        if expr_is_unsigned {
            return false;
        }

        // Check type_map for identifiers within each operand
        if self.operand_has_unsigned_type(&left_node, source, type_map)
            || self.operand_has_unsigned_type(&right_node, source, type_map)
        {
            return false;
        }

        // Field expressions (e.g., self->field) — we can't resolve struct member
        // types without struct definitions, so don't assume signed
        if left_node.kind() == "field_expression" || right_node.kind() == "field_expression" {
            return false;
        }

        // Check if we're in a function with size_t parameters
        if self.is_in_function_with_unsigned_params(modulo_node, source) {
            return false;
        }

        true
    }

    /// Check if any identifier in the operand resolves to an unsigned type
    fn operand_has_unsigned_type(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> bool {
        if node.kind() == "identifier" {
            let name = get_node_text(node, source);
            if let Some(t) = type_map.get(name) {
                return t.contains("size_t")
                    || t.contains("unsigned")
                    || t.contains("uint")
                    || is_short_unsigned_typedef(t);
            }
        }
        // For field expressions like self->field, we can't resolve the type
        // but we know it's a struct access — check text heuristic
        if node.kind() == "field_expression" {
            let text = get_node_text(node, source);
            if self.looks_unsigned(&text) {
                return true;
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.operand_has_unsigned_type(&child, source, type_map) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if an expression appears to use unsigned types
    fn looks_unsigned(&self, text: &str) -> bool {
        // Common unsigned type patterns
        text.contains("size_t")
            || text.contains("unsigned")
            || text.contains("SIZE_MAX")
            || text.contains("UINT_MAX")
            // Unsigned literal suffix
            || text.ends_with('u')
            || text.ends_with('U')
            || text.ends_with("ul")
            || text.ends_with("UL")
            || text.ends_with("ull")
            || text.ends_with("ULL")
    }

    /// Check if node is within a function that has unsigned type parameters
    fn is_in_function_with_unsigned_params(&self, node: &Node, source: &str) -> bool {
        let mut current = node.parent();

        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                // Look for parameter list
                if let Some(declarator) = parent.child_by_field_name("declarator") {
                    let params_text = get_node_text(&declarator, source);
                    // Check if parameters contain unsigned types
                    if params_text.contains("size_t") || params_text.contains("unsigned") {
                        return true;
                    }
                }
                break;
            }
            current = parent.parent();
        }

        false
    }
}

/// Recognizes common short unsigned typedef names: u8, u16, u32, u64, u128.
fn is_short_unsigned_typedef(s: &str) -> bool {
    matches!(s, "u8" | "u16" | "u32" | "u64" | "u128")
}
