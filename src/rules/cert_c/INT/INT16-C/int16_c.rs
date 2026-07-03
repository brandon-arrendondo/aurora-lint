//! INT16-C: Do not make assumptions about representation of signed integers
//!
//! The C Standard permits three different representations for signed integers:
//! - Two's complement
//! - One's complement
//! - Sign and magnitude
//!
//! Bitwise operations on signed integers produce implementation-defined results.
//! Always use unsigned integers for bitwise operations.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int value;
//! if (value & 0x1 != 0) {  // Bitwise operation on signed int
//!     // Check if odd - fails on one's complement
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! // Option 1: Use modulo operator
//! if (value % 2 != 0) {
//!     // Correct way to check if odd
//! }
//!
//! // Option 2: Use unsigned integers
//! unsigned int value;
//! if (value & 0x1 != 0) {
//!     // Bitwise operations are safe on unsigned types
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Int16C;

impl CertRule for Int16C {
    fn rule_id(&self) -> &'static str {
        "INT16-C"
    }

    fn description(&self) -> &'static str {
        "Do not make assumptions about representation of signed integers"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "INT16-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track signed integer variables (name -> declaration location)
        let mut signed_int_vars: HashMap<String, (usize, usize)> = HashMap::new();

        // Find all signed integer variable declarations
        self.find_signed_int_vars(node, source, &mut signed_int_vars);

        // Find bitwise operations on signed integer variables
        self.find_bitwise_operations(node, source, &signed_int_vars, &mut violations);

        // Find signed-to-unsigned conversions without range check
        self.find_signed_to_unsigned_conversions(node, source, &signed_int_vars, &mut violations);

        violations
    }
}

impl Int16C {
    /// Find signed integer variable declarations (int, short, long, signed char)
    fn find_signed_int_vars(
        &self,
        node: &Node,
        source: &str,
        signed_int_vars: &mut HashMap<String, (usize, usize)>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["declaration", "parameter_declaration"])
        {
            let decl_text = get_node_text(&n, source);

            // Check if this is a signed integer declaration
            if self.is_signed_int_declaration(&decl_text) {
                let var_name = if n.kind() == "declaration" {
                    self.extract_var_name(&n, source)
                } else {
                    self.extract_param_name(&n, source)
                };
                if let Some(var_name) = var_name {
                    signed_int_vars.insert(
                        var_name,
                        (n.start_position().row + 1, n.start_position().column + 1),
                    );
                }
            }
        }
    }

    /// Check if declaration text represents a signed integer type
    fn is_signed_int_declaration(&self, decl_text: &str) -> bool {
        // Unsigned integers are safe - do not track
        if decl_text.contains("unsigned") {
            return false;
        }

        // Check for signed integer types
        // Note: plain 'int', 'short', 'long' are signed by default
        let has_signed_type = decl_text.contains(" int ")
            || decl_text.contains(" int*")
            || decl_text.contains(" int[")
            || decl_text.contains("\\tint ")
            || decl_text.contains("\\tint*")
            || decl_text.contains("\\tint[")
            || decl_text.trim().starts_with("int ")
            || decl_text.trim().starts_with("int*")
            || decl_text.trim().starts_with("int[")
            || decl_text.contains(" short ")
            || decl_text.contains(" short*")
            || decl_text.contains(" long ")
            || decl_text.contains(" long*")
            || decl_text.contains("signed char")
            || decl_text.contains("signed int");

        has_signed_type
    }

    /// Find bitwise operations involving signed integer variables
    fn find_bitwise_operations(
        &self,
        node: &Node,
        source: &str,
        signed_int_vars: &HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["binary_expression", "unary_expression"])
        {
            // Check binary bitwise operations: &, |, ^, <<, >>
            if n.kind() == "binary_expression" {
                if let Some(operator) = n.child_by_field_name("operator") {
                    let op_text = get_node_text(&operator, source);

                    // Bitwise operators
                    let is_bitwise_op =
                        matches!(op_text, "&" | "|" | "^" | "<<" | ">>" | "&=" | "|=" | "^=");

                    if is_bitwise_op {
                        // Check left and right operands
                        if let Some(left) = n.child_by_field_name("left") {
                            self.check_operand_for_violation(
                                &left,
                                source,
                                signed_int_vars,
                                violations,
                                op_text,
                            );
                        }
                        if let Some(right) = n.child_by_field_name("right") {
                            self.check_operand_for_violation(
                                &right,
                                source,
                                signed_int_vars,
                                violations,
                                op_text,
                            );
                        }
                    }
                }
            } else {
                // Check unary bitwise NOT operation: ~
                if let Some(operator) = n.child_by_field_name("operator") {
                    let op_text = get_node_text(&operator, source);

                    if op_text == "~" {
                        if let Some(argument) = n.child_by_field_name("argument") {
                            self.check_operand_for_violation(
                                &argument,
                                source,
                                signed_int_vars,
                                violations,
                                "~",
                            );
                        }
                    }
                }
            }
        }
    }

    /// Check if an operand is a signed integer variable and report violation
    fn check_operand_for_violation(
        &self,
        operand: &Node,
        source: &str,
        signed_int_vars: &HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
        operator: &str,
    ) {
        let operand_text = get_node_text(operand, source);

        // Check if this operand is a signed integer variable
        if signed_int_vars.contains_key(operand_text) {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message: format!(
                    "Bitwise operation '{}' on signed integer variable '{}'. \
                     Signed integer representation is implementation-defined. \
                     Use unsigned integers for bitwise operations or use arithmetic operators instead.",
                    operator, operand_text
                ),
                severity: self.severity(),
                line: operand.start_position().row + 1,
                column: operand.start_position().column + 1,
                file_path: String::new(),
                suggestion: Some(format!(
                    "Change '{}' to 'unsigned int {}' or avoid bitwise operations on signed integers",
                    operand_text, operand_text
                )),
                requires_manual_review: None,
            });
        }

        // Also check if operand itself is an identifier
        if operand.kind() == "identifier" {
            // Already handled above
        } else {
            // Recursively check children (for complex expressions)
            for i in 0..operand.child_count() {
                if let Some(child) = operand.child(i) {
                    if child.kind() == "identifier" {
                        let child_text = get_node_text(&child, source);
                        if signed_int_vars.contains_key(child_text) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "Bitwise operation '{}' on signed integer variable '{}'. \
                                     Signed integer representation is implementation-defined. \
                                     Use unsigned integers for bitwise operations or use arithmetic operators instead.",
                                    operator, child_text
                                ),
                                severity: self.severity(),
                                line: child.start_position().row + 1,
                                column: child.start_position().column + 1,
                                file_path: String::new(),
                                suggestion: Some(format!(
                                    "Change '{}' to 'unsigned int {}' or avoid bitwise operations on signed integers",
                                    child_text, child_text
                                )),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Extract variable name from declaration
    fn extract_var_name(&self, decl: &Node, source: &str) -> Option<String> {
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    return self.find_identifier(&child, source);
                } else if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Extract parameter name from parameter declaration
    fn extract_param_name(&self, param: &Node, source: &str) -> Option<String> {
        for i in 0..param.child_count() {
            if let Some(child) = param.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Find identifier in node tree
    fn find_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.find_identifier(&child, source) {
                    return Some(name);
                }
            }
        }
        None
    }

    /// Detect signed-to-unsigned conversions without range checks.
    fn find_signed_to_unsigned_conversions(
        &self,
        node: &Node,
        source: &str,
        signed_int_vars: &HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kinds(
            *node,
            &[
                "function_definition",
                "declaration",
                "assignment_expression",
            ],
        ) {
            match n.kind() {
                "function_definition" => {
                    // Check function definitions for unsigned return type + signed return value
                    if self.has_unsigned_return_type(&n, source) {
                        if let Some(body) = n.child_by_field_name("body") {
                            self.check_unsigned_return_signed(
                                &body,
                                source,
                                signed_int_vars,
                                violations,
                            );
                        }
                    }
                }
                "declaration" => {
                    // Check declarations: unsigned var = signed_var
                    self.check_unsigned_init_from_signed(&n, source, signed_int_vars, violations);
                }
                _ => {
                    // Check assignments: unsigned_var = signed_var
                    self.check_unsigned_assign_from_signed(&n, source, signed_int_vars, violations);
                }
            }
        }
    }

    fn is_unsigned_type_text(text: &str) -> bool {
        text.contains("unsigned")
            || matches!(
                text.trim(),
                "size_t" | "uint8_t" | "uint16_t" | "uint32_t" | "uint64_t" | "uintptr_t"
            )
    }

    fn has_unsigned_return_type(&self, func_node: &Node, source: &str) -> bool {
        // Check type specifiers before the declarator
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if matches!(
                child.kind(),
                "sized_type_specifier" | "primitive_type" | "type_identifier"
            ) {
                let type_text = get_node_text(&child, source);
                if Self::is_unsigned_type_text(type_text) {
                    return true;
                }
            }
            // Stop at declarator
            if child.kind() == "function_declarator" || child.kind() == "pointer_declarator" {
                break;
            }
        }
        false
    }

    /// Check return statements that return a signed variable from an unsigned function.
    fn check_unsigned_return_signed(
        &self,
        node: &Node,
        source: &str,
        signed_int_vars: &HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for ret in query::find_descendants_of_kind(*node, "return_statement") {
            // Get the returned expression (skip "return" keyword)
            for i in 0..ret.child_count() {
                if let Some(child) = ret.child(i) {
                    if child.kind() == "identifier" {
                        let name = get_node_text(&child, source).to_string();
                        if signed_int_vars.contains_key(&name) {
                            if !self.has_non_negative_guard(&ret, &name, source) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    message: format!(
                                        "Signed variable '{}' returned as unsigned without range check",
                                        name
                                    ),
                                    severity: self.severity(),
                                    line: ret.start_position().row + 1,
                                    column: ret.start_position().column + 1,
                                    file_path: String::new(),
                                    suggestion: Some(format!(
                                        "Add a range check: if ({} >= 0) before returning as unsigned",
                                        name
                                    )),
                                    requires_manual_review: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check `unsigned int x = signed_var;` declarations.
    fn check_unsigned_init_from_signed(
        &self,
        decl_node: &Node,
        source: &str,
        signed_int_vars: &HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let decl_text = get_node_text(decl_node, source);
        if !Self::is_unsigned_type_text(decl_text) {
            return;
        }

        // Look for init_declarator with an identifier initializer
        let mut cursor = decl_node.walk();
        for child in decl_node.children(&mut cursor) {
            if child.kind() == "init_declarator" {
                if let Some(value) = child.child_by_field_name("value") {
                    if value.kind() == "identifier" {
                        let init_name = get_node_text(&value, source).to_string();
                        if signed_int_vars.contains_key(&init_name) {
                            if !self.has_non_negative_guard(decl_node, &init_name, source) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    message: format!(
                                        "Signed variable '{}' assigned to unsigned without range check",
                                        init_name
                                    ),
                                    severity: self.severity(),
                                    line: decl_node.start_position().row + 1,
                                    column: decl_node.start_position().column + 1,
                                    file_path: String::new(),
                                    suggestion: Some(format!(
                                        "Add a range check: if ({} >= 0) before assigning to unsigned",
                                        init_name
                                    )),
                                    requires_manual_review: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check `unsigned_var = signed_var;` assignments.
    fn check_unsigned_assign_from_signed(
        &self,
        assign_node: &Node,
        source: &str,
        signed_int_vars: &HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(right) = assign_node.child_by_field_name("right") {
            if right.kind() == "identifier" {
                let right_name = get_node_text(&right, source).to_string();
                if !signed_int_vars.contains_key(&right_name) {
                    return;
                }

                // Check if left side is an unsigned variable (not in signed_int_vars, and declared as unsigned)
                if let Some(left) = assign_node.child_by_field_name("left") {
                    let left_name = get_node_text(&left, source).to_string();
                    // If left is known signed, skip (signed = signed is fine for this rule)
                    if signed_int_vars.contains_key(&left_name) {
                        return;
                    }
                    // If left is not in signed_int_vars, it might be unsigned
                    // We flag it and rely on the unsigned declaration check
                    if !self.has_non_negative_guard(assign_node, &right_name, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "Signed variable '{}' assigned to potentially unsigned variable without range check",
                                right_name
                            ),
                            severity: self.severity(),
                            line: assign_node.start_position().row + 1,
                            column: assign_node.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(format!(
                                "Add a range check: if ({} >= 0) before assigning to unsigned",
                                right_name
                            )),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Check if the node is inside a guard like `if (var >= 0)` or `if (var > 0)`.
    fn has_non_negative_guard(&self, node: &Node, var_name: &str, source: &str) -> bool {
        let mut current = node.parent();
        while let Some(ancestor) = current {
            if matches!(
                ancestor.kind(),
                "if_statement" | "while_statement" | "for_statement"
            ) {
                if let Some(condition) = ancestor.child_by_field_name("condition") {
                    let cond_text = get_node_text(&condition, source);
                    if cond_text.contains(var_name)
                        && (cond_text.contains(">= 0")
                            || cond_text.contains("> 0")
                            || cond_text.contains("!= -")
                            || cond_text.contains(">= 0"))
                    {
                        return true;
                    }
                }
            }
            if ancestor.kind() == "function_definition" {
                break;
            }
            current = ancestor.parent();
        }
        false
    }
}
