//! API09-C: Compatible values should have the same type
//!
//! Make sure compatible values have the same type. For example, when the return
//! value of one function is used as an argument to another function, make sure they
//! are the same type. Ensuring compatible values have the same type allows the return
//! value to be passed as an argument to the related function without conversion,
//! reducing the potential for conversion errors.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! // Function returns ssize_t (signed) when it should return size_t (unsigned)
//! ssize_t atomicio(ssize_t (*f)(int, void *, size_t),
//!                  int fd, void *_s, size_t n) {
//!   char *s = _s;
//!   ssize_t res, pos = 0;  // pos is signed but represents a size
//!
//!   while (n > pos) {  // Mixing unsigned n with signed pos
//!     res = (f)(fd, s + pos, n - pos);  // n - pos triggers implicit conversion
//!     // ... res used in switch without cast
//!     pos += res;  // Mixing signed values
//!   }
//!   return (pos);  // Returning signed value as size
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! // Function returns size_t (unsigned) for size values
//! size_t atomicio(ssize_t (*f)(int, void *, size_t),
//!                 int fd, void *_s, size_t n) {
//!   char *s = _s;
//!   size_t pos = 0;  // pos is now unsigned
//!   ssize_t res;     // res is signed (function return value)
//!
//!   while (n > pos) {  // Both unsigned
//!     res = (f)(fd, s + pos, n - pos);  // No implicit conversion needed
//!     // ... error checking ...
//!     pos += (size_t)res;  // Explicit cast for safety
//!   }
//!   return (pos);  // Returning unsigned value
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find functions that return signed types (ssize_t, int, long) when they accumulate or return sizes
//! - Check for local variables of signed types used to accumulate sizes
//! - Look for implicit conversions between signed/unsigned in arithmetic operations
//! - Check for assignments from signed to unsigned without explicit casts

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Api09C;

impl CertRule for Api09C {
    fn rule_id(&self) -> &'static str {
        "API09-C"
    }

    fn description(&self) -> &'static str {
        "Compatible values should have the same type"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "API09-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function_type_compatibility(&func, source, &mut violations);
        }
        violations
    }
}

impl Api09C {
    /// Check for signed return types when function accumulates/returns sizes
    fn check_function_type_compatibility(
        &self,
        function_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get function name and return type
        let (func_name, return_type) = match self.get_function_info(function_node, source) {
            Some((name, ret_type)) => (name, ret_type),
            None => return,
        };

        // Check if function returns signed type that accumulates sizes
        if self.is_signed_size_type(&return_type) {
            // Check if function body accumulates a size value
            if let Some(body) = function_node.child_by_field_name("body") {
                if self.accumulates_size_value(&body, source) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Low,
                        message: format!(
                            "Function '{}' returns signed type '{}' but accumulates size values. Consider using 'size_t' for return type.",
                            func_name, return_type.trim()
                        ),
                        file_path: String::new(),
                        line: function_node.start_position().row + 1,
                        column: function_node.start_position().column + 1,
                        suggestion: Some(format!(
                            "Change return type from '{}' to 'size_t' to avoid implicit conversions",
                            return_type.trim()
                        )),
                        ..Default::default()
                    });
                }
            }
        }

        // Check function body for signed variables used as size accumulators
        if let Some(body) = function_node.child_by_field_name("body") {
            self.check_signed_size_accumulators(&body, source, violations);
        }
    }

    /// Get function name and return type
    fn get_function_info(&self, function_node: &Node, source: &str) -> Option<(String, String)> {
        let mut return_type = String::new();
        let mut func_name = String::new();

        // Look for type specifier (return type) and declarator (name)
        for i in 0..function_node.child_count() {
            if let Some(child) = function_node.child(i) {
                match child.kind() {
                    "primitive_type" | "type_identifier" | "sized_type_specifier"
                        if return_type.is_empty() =>
                    {
                        return_type = get_node_text(&child, source).to_string();
                    }
                    "function_declarator" => {
                        // Extract function name
                        if let Some(name) = self.extract_function_name(&child, source) {
                            func_name = name;
                        }
                    }
                    "pointer_declarator" => {
                        // Handle functions returning pointers
                        if let Some(name) = self.find_identifier(&child, source) {
                            func_name = name;
                        }
                    }
                    _ => {}
                }
            }
        }

        if func_name.is_empty() {
            None
        } else {
            Some((func_name, return_type))
        }
    }

    fn extract_function_name(&self, declarator_node: &Node, source: &str) -> Option<String> {
        for i in 0..declarator_node.child_count() {
            if let Some(child) = declarator_node.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    fn find_identifier(&self, node: &Node, source: &str) -> Option<String> {
        query::find_first_descendant(*node, |n| n.kind() == "identifier")
            .map(|n| get_node_text(&n, source).to_string())
    }

    /// Check if a type is a signed size type (ssize_t, etc.)
    fn is_signed_size_type(&self, type_name: &str) -> bool {
        let normalized = type_name.trim();
        matches!(normalized, "ssize_t")
    }

    /// Check if function body accumulates a size value (typically in a variable named 'pos', 'count', 'total', etc.)
    fn accumulates_size_value(&self, body: &Node, source: &str) -> bool {
        self.find_size_accumulator_pattern(body, source)
    }

    /// Look for patterns like: pos += res; or count += len; in loops
    fn find_size_accumulator_pattern(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            // Look for while loops or for loops
            if matches!(n.kind(), "while_statement" | "for_statement") {
                // Check if loop body contains += operations with size-like variable names
                if let Some(body) = self.get_loop_body(&n) {
                    if self.contains_accumulator_assignment(&body, source) {
                        return true;
                    }
                }
            }

            // Check for return statements returning accumulated values
            if n.kind() == "return_statement" {
                if let Some(value) = n.child_by_field_name("") {
                    let text = get_node_text(&value, source);
                    if matches!(text, "pos" | "count" | "total" | "bytes" | "size") {
                        return true;
                    }
                }
                // Alternative: check return value directly
                for i in 0..n.child_count() {
                    if let Some(child) = n.child(i) {
                        if child.kind() == "identifier" {
                            let text = get_node_text(&child, source);
                            if matches!(text, "pos" | "count" | "total" | "bytes" | "size") {
                                return true;
                            }
                        }
                    }
                }
            }

            false
        })
        .is_some()
    }

    fn get_loop_body<'a>(&self, loop_node: &'a Node) -> Option<Node<'a>> {
        loop_node.child_by_field_name("body")
    }

    fn contains_accumulator_assignment(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "expression_statement" {
                return false;
            }
            for i in 0..n.child_count() {
                if let Some(child) = n.child(i) {
                    if child.kind() == "assignment_expression" {
                        if let Some(operator) = child.child_by_field_name("operator") {
                            let op_text = get_node_text(&operator, source);
                            if op_text == "+=" {
                                // Check if left side is size-like variable
                                if let Some(left) = child.child_by_field_name("left") {
                                    let var_name = get_node_text(&left, source);
                                    if matches!(
                                        var_name,
                                        "pos" | "count" | "total" | "bytes" | "size"
                                    ) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            false
        })
        .is_some()
    }

    /// Check for signed local variables used as size accumulators
    fn check_signed_size_accumulators(
        &self,
        body: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for node in query::find_descendants_of_kind(*body, "declaration") {
            // Get the type specifier
            let mut type_name = String::new();
            let mut declarators = Vec::new();

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        "primitive_type" | "type_identifier" | "sized_type_specifier" => {
                            type_name = get_node_text(&child, source).to_string();
                        }
                        "init_declarator" => {
                            if let Some(declarator) = child.child_by_field_name("declarator") {
                                if let Some(var_name) =
                                    self.get_declarator_name(&declarator, source)
                                {
                                    declarators.push((var_name, child.start_position().row + 1));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Check if this is a signed type used for size accumulation
            if self.is_signed_size_type(&type_name) {
                for (var_name, line) in declarators {
                    if matches!(
                        var_name.as_str(),
                        "pos" | "count" | "total" | "bytes" | "size"
                    ) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Low,
                            message: format!(
                                "Variable '{}' has signed type '{}' but is used to accumulate size values. Consider using 'size_t' instead.",
                                var_name, type_name.trim()
                            ),
                            file_path: String::new(),
                            line,
                            column: node.start_position().column + 1,
                            suggestion: Some(format!(
                                "Change variable '{}' from '{}' to 'size_t' to match the semantics of size values",
                                var_name, type_name.trim()
                            )),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn get_declarator_name(&self, declarator_node: &Node, source: &str) -> Option<String> {
        query::find_first_descendant(*declarator_node, |n| n.kind() == "identifier")
            .map(|n| get_node_text(&n, source).to_string())
    }
}
