//! FIO40-C: Reset strings on fgets() or fgetws() failure
//!
//! When fgets() or fgetws() fail, the contents of the target array are indeterminate.
//! The string must be reset to a known value (like empty string) to avoid errors
//! on subsequent string manipulation functions.
//!
//! ## Key Issues:
//! - fgets()/fgetws() failure leaves buffer with indeterminate contents
//! - Using the buffer without resetting can lead to undefined behavior
//! - String manipulation functions expect valid null-terminated strings
//!
//! ## Detected Violations:
//! - Checking fgets()/fgetws() return value without resetting buffer on failure
//! - Continuing execution after failed read without buffer reset
//! - Setting error flag but not clearing the buffer
//!
//! ## Compliant Patterns:
//! - Reset buffer to empty string (buf[0] = '\0') after fgets() returns NULL
//! - Reset buffer to empty string (buf[0] = L'\0') after fgetws() returns NULL
//! - Explicitly clear buffer contents on read failure

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio40C;

impl CertRule for Fio40C {
    fn rule_id(&self) -> &'static str {
        "FIO40-C"
    }

    fn description(&self) -> &'static str {
        "Reset strings on fgets() or fgetws() failure"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO40-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Fio40C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for if statements that check fgets/fgetws return value
        for n in query::find_descendants_of_kind(*node, "if_statement") {
            if let Some(condition) = n.child_by_field_name("condition") {
                // Check if this condition compares fgets/fgetws to NULL
                if let Some((func_name, buffer_var)) =
                    self.find_fgets_null_check(&condition, source)
                {
                    // Check if the consequence (then branch) resets the buffer
                    if let Some(consequence) = n.child_by_field_name("consequence") {
                        if !self.has_buffer_reset(&consequence, &buffer_var, source) {
                            let start_point = n.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Low,
                                message: format!(
                                    "Buffer '{}' not reset after {}() failure - buffer contents are indeterminate and must be reset",
                                    buffer_var, func_name
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some(format!(
                                    "Reset buffer in failure branch: '{}[0] = {}\\0';'",
                                    buffer_var,
                                    if func_name == "fgetws" { "L'" } else { "'" }
                                )),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check if condition is checking fgets/fgetws == NULL or NULL == fgets/fgetws
    /// Returns (function_name, buffer_variable) if found
    fn find_fgets_null_check(&self, condition: &Node, source: &str) -> Option<(String, String)> {
        // Look for binary_expression with == or !=
        if condition.kind() == "binary_expression" {
            if let (Some(left), Some(operator), Some(right)) = (
                condition.child_by_field_name("left"),
                condition.child_by_field_name("operator"),
                condition.child_by_field_name("right"),
            ) {
                let op = get_node_text(&operator, source);

                // Check for == NULL or != NULL comparisons
                if op == "==" || op == "!=" {
                    // Try left == NULL
                    if get_node_text(&right, source).trim() == "NULL" {
                        if let Some((func, buf)) = self.extract_fgets_call(&left, source) {
                            return Some((func, buf));
                        }
                    }
                    // Try NULL == left
                    if get_node_text(&left, source).trim() == "NULL" {
                        if let Some((func, buf)) = self.extract_fgets_call(&right, source) {
                            return Some((func, buf));
                        }
                    }
                }
            }
        }

        // Also check for unary ! on fgets call
        if condition.kind() == "unary_expression" {
            if let Some(argument) = condition.child_by_field_name("argument") {
                return self.extract_fgets_call(&argument, source);
            }
        }

        // Recursively check parenthesized expressions
        if condition.kind() == "parenthesized_expression" {
            for i in 0..condition.child_count() {
                if let Some(child) = condition.child(i) {
                    if let Some(result) = self.find_fgets_null_check(&child, source) {
                        return Some(result);
                    }
                }
            }
        }

        None
    }

    /// Extract fgets/fgetws function name and buffer argument from call expression
    fn extract_fgets_call(&self, node: &Node, source: &str) -> Option<(String, String)> {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "fgets" || func_name == "fgetws" {
                    // Extract first argument (the buffer)
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        let args = self.extract_arguments(&arguments);
                        if let Some(first_arg) = args.first() {
                            let buf_var = get_node_text(first_arg, source);
                            return Some((func_name.to_string(), buf_var.to_string()));
                        }
                    }
                }
            }
        }

        None
    }

    /// Check if the statement block resets the buffer (sets buf[0] = '\0')
    fn has_buffer_reset(&self, node: &Node, buffer_var: &str, source: &str) -> bool {
        match node.kind() {
            "compound_statement" => {
                // Check all statements in the block
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if self.is_buffer_reset_statement(&child, buffer_var, source) {
                            return true;
                        }
                    }
                }
                false
            }
            _ => {
                // Single statement
                self.is_buffer_reset_statement(node, buffer_var, source)
            }
        }
    }

    /// Check if this is a statement that resets the buffer
    fn is_buffer_reset_statement(&self, node: &Node, buffer_var: &str, source: &str) -> bool {
        // Look for assignment like buf[0] = '\0' or buf[0] = L'\0' or buf[0] = 0
        // Also handle *buf = '\0' (pointer dereference syntax)
        if node.kind() == "expression_statement" {
            if let Some(assignment) = self.find_assignment(node) {
                if let (Some(left), Some(right)) = (
                    assignment.child_by_field_name("left"),
                    assignment.child_by_field_name("right"),
                ) {
                    let left_text = get_node_text(&left, source);
                    let right_text = get_node_text(&right, source).trim();

                    // Check if right side is '\0' or L'\0' or 0
                    let is_null_char =
                        right_text == "'\\0'" || right_text == "L'\\0'" || right_text == "0";

                    if is_null_char {
                        // Check if left side is buf[0]
                        if left_text.contains(buffer_var) && left_text.contains("[0]") {
                            return true;
                        }
                        // Check if left side is *buf (pointer dereference)
                        if left.kind() == "pointer_expression" {
                            let deref_text = get_node_text(&left, source);
                            if deref_text == format!("*{}", buffer_var) {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Find assignment expression in node tree
    fn find_assignment<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        query::find_first_descendant(*node, |n| n.kind() == "assignment_expression")
    }

    /// Extract function call arguments
    fn extract_arguments<'a>(&self, arguments_node: &Node<'a>) -> Vec<Node<'a>> {
        let mut args = Vec::new();

        for i in 0..arguments_node.child_count() {
            if let Some(child) = arguments_node.child(i) {
                // Skip commas and parentheses
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    args.push(child);
                }
            }
        }

        args
    }
}
