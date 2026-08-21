//! FLP34-C: Ensure that floating-point conversions are within range of the new type
//!
//! This rule detects unchecked floating-point type conversions that can result in
//! undefined behavior when the value is outside the range of the target type.
//!
//! VIOLATIONS:
//! - i_a = f_a;                  // Float to int without range checking
//! - f_a = (float)d_a;           // Double to float cast without range checking
//! - f_b = (float)big_d;         // Long double to float cast without range checking
//!
//! COMPLIANT:
//! - if (isnan(f_a) || check_range) { /* handle */ } i_a = f_a;
//! - if (isnan(d_a) || isgreater(fabs(d_a), FLT_MAX)) { /* handle */ } f_a = (float)d_a;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::float_typing;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Flp34C;

impl CertRule for Flp34C {
    fn rule_id(&self) -> &'static str {
        "FLP34-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that floating-point conversions are within range of the new type"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "FLP34-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_recursive(node, source, violations);
    }
}

impl Flp34C {
    fn check_recursive(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // For each function definition, collect variable types and check within it
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let type_map = self.collect_variable_types(&func, source);
            self.check_function_body(&func, source, &type_map, violations);
        }

        // For cast expressions at file scope (unlikely but possible), still check.
        // Skip casts inside a function_definition; those are handled above via
        // check_function_body.
        for cast in query::find_descendants_of_kind(*node, "cast_expression") {
            if query::nearest_ancestor_of_kind(cast, "function_definition").is_none() {
                if let Some(violation) = self.check_cast_expression(&cast, source) {
                    violations.push(violation);
                }
            }
        }
    }

    /// Check all nodes within a function body, using the collected type map for assignments
    fn check_function_body(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in
            query::find_descendants_of_kinds(*node, &["cast_expression", "assignment_expression"])
        {
            match n.kind() {
                "cast_expression" => {
                    if let Some(violation) = self.check_cast_expression(&n, source) {
                        violations.push(violation);
                    }
                }
                "assignment_expression" => {
                    if let Some(violation) = self.check_assignment_conversion(&n, source, type_map)
                    {
                        violations.push(violation);
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    /// Collect variable types from function parameters and local declarations.
    /// Returns a map from variable name to its base type string. Pointer-typed
    /// declarators are recorded as `"<base type> *"` (e.g. a `float *fp`
    /// parameter maps to `"float *"`, not `"float"` -- otherwise `fp_rank`
    /// would treat the pointer value itself as float-ranked).
    fn collect_variable_types<'a>(
        &self,
        func_node: &Node<'a>,
        source: &'a str,
    ) -> HashMap<String, String> {
        float_typing::collect_variable_types(func_node, source)
    }

    /// Check if a cast expression converts floating-point types unsafely
    fn check_cast_expression(&self, cast_node: &Node, source: &str) -> Option<RuleViolation> {
        // Get the target type
        let type_node = cast_node.child_by_field_name("type")?;
        let target_type = ast_utils::get_node_text(&type_node, source);

        // Get the value being cast
        let _value_node = cast_node.child_by_field_name("value")?;

        // Check if this is a narrowing floating-point conversion
        if !self.is_narrowing_fp_conversion(&target_type) {
            return None;
        }

        // Check if there's range checking before this cast
        if self.has_range_checking(cast_node, source) {
            return None;
        }

        let start_point = cast_node.start_position();

        Some(RuleViolation {
            rule_id: "FLP34-C".to_string(),
            severity: Severity::Medium,
            message: format!(
                "Floating-point conversion to '{}' without range checking",
                target_type
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Check for isnan(), compare with FLT_MAX/FLT_MIN or DBL_MAX/DBL_MIN before conversion".to_string()
            ),
            ..Default::default()
        })
    }

    /// Check if an assignment involves unchecked floating-point conversion using type information
    fn check_assignment_conversion(
        &self,
        assignment_node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
    ) -> Option<RuleViolation> {
        let left = assignment_node.child_by_field_name("left")?;
        let right = assignment_node.child_by_field_name("right")?;

        // Get variable names
        let left_name = ast_utils::get_node_text(&left, source);
        let right_name = ast_utils::get_node_text(&right, source);

        // Only check simple identifier-to-identifier assignments
        // Skip if right side contains function calls, casts, or complex expressions
        if right.kind() != "identifier" {
            return None;
        }

        // Look up types for both sides
        let left_type = type_map.get(left_name)?;
        let right_type = type_map.get(right_name)?;

        // Check if this is a dangerous floating-point conversion
        if !self.is_dangerous_assignment(left_type, right_type) {
            return None;
        }

        // Check if there's range checking before this assignment
        if self.has_range_checking(assignment_node, source) {
            return None;
        }

        let start_point = assignment_node.start_position();

        Some(RuleViolation {
            rule_id: "FLP34-C".to_string(),
            severity: Severity::Medium,
            message: format!(
                "Floating-point conversion from '{}' to '{}' without range checking",
                right_type, left_type
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Check for isnan(), verify value is within target type's range before conversion"
                    .to_string(),
            ),
            ..Default::default()
        })
    }

    /// Check if assigning right_type to left_type is a dangerous float conversion
    fn is_dangerous_assignment(&self, left_type: &str, right_type: &str) -> bool {
        let left_fp = Self::fp_rank(left_type);
        let right_fp = Self::fp_rank(right_type);
        let left_int = Self::is_integer_type(left_type);

        // Float/double/long double assigned to integer type
        if right_fp > 0 && left_int {
            return true;
        }

        // Narrowing floating-point: higher rank to lower rank
        // double -> float, long double -> float, long double -> double
        if right_fp > left_fp && left_fp > 0 {
            return true;
        }

        false
    }

    /// Return floating-point "rank": 0 = not FP, 1 = float, 2 = double, 3 = long double
    fn fp_rank(type_text: &str) -> u8 {
        let t = type_text.trim();
        if t == "long double" {
            3
        } else if t == "double" {
            2
        } else if t == "float" {
            1
        } else {
            0
        }
    }

    /// Check if a type is an integer type
    fn is_integer_type(type_text: &str) -> bool {
        let t = type_text.trim();
        matches!(
            t,
            "int"
                | "short"
                | "long"
                | "long long"
                | "char"
                | "signed char"
                | "unsigned char"
                | "unsigned int"
                | "unsigned short"
                | "unsigned long"
                | "unsigned long long"
                | "signed"
                | "unsigned"
                | "int8_t"
                | "int16_t"
                | "int32_t"
                | "int64_t"
                | "uint8_t"
                | "uint16_t"
                | "uint32_t"
                | "uint64_t"
                | "size_t"
                | "ssize_t"
                | "ptrdiff_t"
                | "intptr_t"
                | "uintptr_t"
        )
    }

    /// Check if target type is a narrowing floating-point conversion
    fn is_narrowing_fp_conversion(&self, target_type: &str) -> bool {
        // Narrowing conversions: long double -> double/float, double -> float
        target_type.contains("float") && !target_type.contains("long")
            || target_type.contains("double") && !target_type.contains("long")
    }

    /// Check if there's range checking around the conversion
    fn has_range_checking(&self, node: &Node, source: &str) -> bool {
        // Find the containing function body
        let function_body = self.get_containing_function_body(node);
        let body = match function_body {
            Some(b) => b,
            None => return false,
        };

        // Sanitized so a comment/string literal in the function can't spoof
        // a range-check pattern and silently suppress a genuine unchecked
        // floating-point conversion.
        let body_text = ast_utils::get_sanitized_node_text(&body, source);

        // Look for range checking patterns
        if body_text.contains("isnan") {
            return true;
        }

        if body_text.contains("isgreater") || body_text.contains("isless") {
            return true;
        }

        if body_text.contains("FLT_MAX") || body_text.contains("FLT_MIN") {
            return true;
        }

        if body_text.contains("DBL_MAX") || body_text.contains("DBL_MIN") {
            return true;
        }

        if body_text.contains("INT_MAX") || body_text.contains("INT_MIN") {
            return true;
        }

        if body_text.contains("log2f") || body_text.contains("fabsf") || body_text.contains("fabs")
        {
            return true;
        }

        false
    }

    /// Get the containing function body
    fn get_containing_function_body<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = node.parent();

        while let Some(n) = current {
            if n.kind() == "compound_statement" {
                if let Some(parent) = n.parent() {
                    if parent.kind() == "function_definition" {
                        return Some(n);
                    }
                }
            }
            current = n.parent();
        }

        None
    }
}
