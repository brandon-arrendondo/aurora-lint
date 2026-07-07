//! INT18-C: Evaluate integer expressions in a larger size before comparing or assigning to that size
//!
//! This rule detects integer arithmetic operations that are compared to or assigned to
//! larger types without first casting operands to the larger size. This can lead to
//! overflow/wrapping in the smaller type before the comparison/assignment.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! size_t length;  // 32-bit
//! if (length + BLOCK_HEADER_SIZE > (unsigned long long)SIZE_MAX) {  // VIOLATION
//!     // Addition happens in 32-bit, can wrap before comparison
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! if ((unsigned long long)length + BLOCK_HEADER_SIZE > SIZE_MAX) {  // OK
//!     // Addition happens in 64-bit
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find binary expressions (+ - * /) in comparisons or assignments
//! - Check if result is compared/assigned to larger type
//! - Verify operands are not cast to larger size
//! - Report violation if arithmetic happens in smaller type

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Int18C;

impl CertRule for Int18C {
    fn rule_id(&self) -> &'static str {
        "INT18-C"
    }

    fn description(&self) -> &'static str {
        "Evaluate integer expressions in a larger size before comparing or assigning to that size"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "INT18-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Int18C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let matches = query::find_descendants_of_kinds(
            *node,
            &[
                "binary_expression",
                "assignment_expression",
                "init_declarator",
            ],
        );

        for n in matches.iter() {
            // Check binary expressions in comparisons
            if n.kind() == "binary_expression" {
                self.check_binary_in_comparison(n, source, violations);
                // Also check for size_t compared to negative literal
                self.check_unsigned_vs_negative(n, source, violations);
            }

            // Check binary expressions in assignments
            if n.kind() == "assignment_expression" || n.kind() == "init_declarator" {
                self.check_binary_in_assignment(n, source, violations);
            }
        }
    }

    /// Check if binary expression in comparison has cast on comparison side but not on operands
    fn check_binary_in_comparison(
        &self,
        comparison: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let operator = self.get_operator(comparison, source);

        // Only check comparison operators
        if !["<", ">", "<=", ">=", "==", "!="].contains(&operator.as_str()) {
            return;
        }

        // Check left side
        if let Some(left) = comparison.child_by_field_name("left") {
            if self.is_arithmetic_binary(&left) {
                // Right side might have a cast
                if let Some(right) = comparison.child_by_field_name("right") {
                    if self.has_larger_type_cast(&right, source) {
                        // Arithmetic on left, cast on right - check if arithmetic operands are uncast
                        if !self.has_cast_operand(&left, source) {
                            self.report_violation(&left, source, violations);
                        }
                    }
                }
            }
        }

        // Check right side
        if let Some(right) = comparison.child_by_field_name("right") {
            if self.is_arithmetic_binary(&right) {
                // Left side might have a cast
                if let Some(left) = comparison.child_by_field_name("left") {
                    if self.has_larger_type_cast(&left, source) {
                        // Arithmetic on right, cast on left - check if arithmetic operands are uncast
                        if !self.has_cast_operand(&right, source) {
                            self.report_violation(&right, source, violations);
                        }
                    }
                }
            }
        }
    }

    /// Check if binary expression assigned to larger type variable
    fn check_binary_in_assignment(
        &self,
        assignment: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // For assignment_expression: left = right
        if assignment.kind() == "assignment_expression" {
            if let Some(right) = assignment.child_by_field_name("right") {
                if self.is_arithmetic_binary(&right) {
                    // Check if left side has larger type cast/declaration
                    if let Some(left) = assignment.child_by_field_name("left") {
                        if self.is_larger_type_variable(&left, source) {
                            if !self.has_cast_operand(&right, source) {
                                self.report_violation(&right, source, violations);
                            }
                        }
                    }
                }
            }
        }

        // For init_declarator: type var = value
        if assignment.kind() == "init_declarator" {
            if let Some(value) = assignment.child_by_field_name("value") {
                if self.is_arithmetic_binary(&value) {
                    // Check if declarator has larger type
                    if let Some(_declarator) = assignment.child_by_field_name("declarator") {
                        // Get parent declaration to check type
                        if let Some(parent) = assignment.parent() {
                            if parent.kind() == "declaration" {
                                if self.has_larger_type_specifier(&parent, source) {
                                    if !self.has_cast_operand(&value, source) {
                                        self.report_violation(&value, source, violations);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check if node is arithmetic binary expression (+ - * /)
    fn is_arithmetic_binary(&self, node: &Node) -> bool {
        if node.kind() != "binary_expression" {
            return false;
        }

        let operator = self.get_operator(node, "");
        matches!(operator.as_str(), "+" | "-" | "*" | "/")
    }

    /// Get operator from binary expression
    fn get_operator(&self, node: &Node, _source: &str) -> String {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let kind = child.kind();
                if kind == "+"
                    || kind == "-"
                    || kind == "*"
                    || kind == "/"
                    || kind == "<"
                    || kind == ">"
                    || kind == "<="
                    || kind == ">="
                    || kind == "=="
                    || kind == "!="
                {
                    return kind.to_string();
                }
            }
        }
        String::new()
    }

    /// Check if expression has cast to larger type (unsigned long long, etc.)
    fn has_larger_type_cast(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "cast_expression" {
            if let Some(type_node) = node.child_by_field_name("type") {
                let type_str = get_node_text(&type_node, source);
                return self.is_larger_type(type_str);
            }
        }
        false
    }

    /// Check if binary expression has at least one operand cast to larger type,
    /// or if an operand is already declared as the larger type
    fn has_cast_operand(&self, binary: &Node, source: &str) -> bool {
        if let Some(left) = binary.child_by_field_name("left") {
            if self.has_larger_type_cast(&left, source) {
                return true;
            }
            if self.operand_has_larger_declared_type(&left, source) {
                return true;
            }
        }
        if let Some(right) = binary.child_by_field_name("right") {
            if self.has_larger_type_cast(&right, source) {
                return true;
            }
            if self.operand_has_larger_declared_type(&right, source) {
                return true;
            }
        }
        false
    }

    /// Check if an operand identifier has a declared type that is already a larger type
    fn operand_has_larger_declared_type(&self, node: &Node, source: &str) -> bool {
        if node.kind() != "identifier" {
            return false;
        }
        let var_name = get_node_text(node, source);

        // Walk up to the function_definition to search for declarations
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                // Check parameters
                if let Some(declarator) = parent.child_by_field_name("declarator") {
                    if self.param_has_larger_type(&declarator, var_name, source) {
                        return true;
                    }
                }
                // Check local declarations in function body
                if let Some(body) = parent.child_by_field_name("body") {
                    if self.local_decl_has_larger_type(&body, var_name, source) {
                        return true;
                    }
                }
                break;
            }
            current = parent.parent();
        }
        false
    }

    /// Check if a function parameter has a larger type
    fn param_has_larger_type(&self, declarator: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if child.kind() == "parameter_list" {
                    for j in 0..child.child_count() {
                        if let Some(param) = child.child(j) {
                            if param.kind() == "parameter_declaration" {
                                let param_text = get_node_text(&param, source);
                                if param_text.contains(var_name) {
                                    // Check type nodes
                                    for k in 0..param.child_count() {
                                        if let Some(type_node) = param.child(k) {
                                            if type_node.kind() == "type_identifier"
                                                || type_node.kind() == "primitive_type"
                                                || type_node.kind() == "sized_type_specifier"
                                            {
                                                let type_str = get_node_text(&type_node, source);
                                                if self.is_larger_type(type_str) {
                                                    return true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a local variable declaration has a larger type
    fn local_decl_has_larger_type(&self, body: &Node, var_name: &str, source: &str) -> bool {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "declaration" {
                    // Check if this declaration declares our variable with a larger type.
                    // Must check the declarator NAME only (not the full init_declarator text,
                    // which includes the initializer expression).
                    let mut has_larger = false;
                    let mut has_var = false;
                    for j in 0..child.child_count() {
                        if let Some(decl_child) = child.child(j) {
                            match decl_child.kind() {
                                "type_identifier" | "primitive_type" | "sized_type_specifier" => {
                                    let type_str = get_node_text(&decl_child, source);
                                    if self.is_larger_type(type_str) {
                                        has_larger = true;
                                    }
                                }
                                "init_declarator" => {
                                    // Only check the declarator name, not the initializer value
                                    if let Some(declarator) =
                                        decl_child.child_by_field_name("declarator")
                                    {
                                        let name = get_node_text(&declarator, source);
                                        if name == var_name {
                                            has_var = true;
                                        }
                                    }
                                }
                                "identifier" => {
                                    let text = get_node_text(&decl_child, source);
                                    if text == var_name {
                                        has_var = true;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    if has_larger && has_var {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if variable is larger type (unsigned long long, etc.)
    fn is_larger_type_variable(&self, node: &Node, source: &str) -> bool {
        // Simple heuristic: check variable name patterns
        let text = get_node_text(&node, source);

        // Variables named "alloc" or containing "long" are likely larger types
        text.contains("alloc") || text.contains("long")
    }

    /// Check if declaration has larger type specifier
    fn has_larger_type_specifier(&self, declaration: &Node, source: &str) -> bool {
        // Find type specifier in declaration
        for i in 0..declaration.child_count() {
            if let Some(child) = declaration.child(i) {
                if child.kind() == "primitive_type"
                    || child.kind() == "sized_type_specifier"
                    || child.kind() == "type_identifier"
                {
                    let type_str = get_node_text(&child, source);
                    if self.is_larger_type(type_str) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if type string represents larger type
    fn is_larger_type(&self, type_str: &str) -> bool {
        let larger_types = [
            "unsigned long long",
            "long long",
            "uint64_t",
            "int64_t",
            "uintmax_t",
            "intmax_t",
        ];

        for larger_type in &larger_types {
            if type_str.contains(larger_type) {
                return true;
            }
        }
        false
    }

    /// Check for unsigned type compared to negative literal (e.g., size_t == -1)
    fn check_unsigned_vs_negative(
        &self,
        comparison: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let operator = self.get_operator(comparison, source);

        // Only check equality/comparison operators
        if !["==", "!=", "<", ">", "<=", ">="].contains(&operator.as_str()) {
            return;
        }

        // Check if one side is negative literal and other is likely unsigned
        if let (Some(left), Some(right)) = (
            comparison.child_by_field_name("left"),
            comparison.child_by_field_name("right"),
        ) {
            let left_text = get_node_text(&left, source);
            let right_text = get_node_text(&right, source);

            // Check for pattern: unsigned_var == -1 or -1 == unsigned_var
            if (self.is_unsigned_variable(left_text) && right_text.trim() == "-1")
                || (left_text.trim() == "-1" && self.is_unsigned_variable(right_text))
            {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Comparing unsigned type to negative literal: '{}' - negative value converted to large unsigned value",
                        get_node_text(&comparison, source).trim()
                    ),
                    file_path: String::new(),
                    line: comparison.start_position().row + 1,
                    column: comparison.start_position().column + 1,
                    suggestion: Some(
                        "Cast negative literal to unsigned type or compare to appropriate unsigned value. Example: (size_t)-1 or compare to UINT_MAX".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// Check if variable name suggests unsigned type
    fn is_unsigned_variable(&self, var_name: &str) -> bool {
        // Variables with "count", "size", or "_modified" often are size_t (unsigned)
        var_name.contains("count") || var_name.contains("size") || var_name.contains("_modified")
    }

    fn report_violation(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let expr_text = get_node_text(&node, source);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Integer arithmetic '{}' evaluated in smaller type before comparison/assignment to larger type - may overflow before comparison",
                expr_text.trim()
            ),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(
                "Cast at least one operand to the larger type before performing arithmetic. Example: (unsigned long long)x + y".to_string()
            ),
            ..Default::default()
        });
    }
}
