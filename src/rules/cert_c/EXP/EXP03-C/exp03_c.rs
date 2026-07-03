//! EXP03-C: Do not assume the size of a structure is the sum of the sizes of its members
//!
//! This rule detects manual struct size calculations where sizeof(member1) + sizeof(member2)
//! is used instead of sizeof(struct_type). Due to padding and alignment requirements,
//! a structure's size may be greater than the sum of its members' sizes.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! struct buffer {
//!   size_t size;
//!   char bufferC[50];
//! };
//!
//! void func(const struct buffer *buf) {
//!   // WRONG: assumes no padding exists
//!   struct buffer *buf_cpy = (struct buffer *)malloc(
//!     sizeof(size_t) + (50 * sizeof(char))
//!   );
//!   memcpy(buf_cpy, buf, sizeof(struct buffer));  // Buffer overflow!
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! struct buffer {
//!   size_t size;
//!   char bufferC[50];
//! };
//!
//! void func(const struct buffer *buf) {
//!   // CORRECT: accounts for padding
//!   struct buffer *buf_cpy = (struct buffer *)malloc(sizeof(struct buffer));
//!   memcpy(buf_cpy, buf, sizeof(struct buffer));
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find allocation calls (malloc, calloc, realloc)
//! - Check if size argument contains addition of sizeof() expressions
//! - Flag as violation if multiple sizeof() calls are summed
//! - Suggest using sizeof(struct_type) instead

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp03C;

impl CertRule for Exp03C {
    fn rule_id(&self) -> &'static str {
        "EXP03-C"
    }

    fn description(&self) -> &'static str {
        "Do not assume the size of a structure is the sum of the sizes of its members"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP03-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Exp03C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for call_expression nodes
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = call_node.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source).trim().to_string();

                // Check if it's an allocation function
                if self.is_allocation_function(&func_name) {
                    // Get the arguments
                    if let Some(args_node) = call_node.child_by_field_name("arguments") {
                        // For malloc/realloc, first argument is size
                        // For calloc, second argument is size (but also check first for element count)
                        self.check_allocation_size(&args_node, source, violations, &func_name);
                    }
                }
            }
        }
    }

    fn is_allocation_function(&self, func_name: &str) -> bool {
        matches!(func_name, "malloc" | "calloc" | "realloc")
    }

    fn check_allocation_size(
        &self,
        args_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        func_name: &str,
    ) {
        // Get all argument children (skip parentheses and commas)
        let mut args = Vec::new();
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    args.push(child);
                }
            }
        }

        // Check the size argument based on function type
        let size_arg = match func_name {
            "malloc" => {
                // malloc(size) - first argument
                args.first()
            }
            "calloc" => {
                // calloc(count, size) - check both arguments
                // Check first arg for manual calculations
                if let Some(first_arg) = args.first() {
                    if self.contains_sizeof_addition(first_arg, source) {
                        self.report_violation(first_arg, source, violations);
                    }
                }
                // Check second arg
                args.get(1)
            }
            "realloc" => {
                // realloc(ptr, size) - second argument
                args.get(1)
            }
            _ => None,
        };

        if let Some(size_arg) = size_arg {
            if self.contains_sizeof_addition(size_arg, source) {
                self.report_violation(size_arg, source, violations);
            }
        }
    }

    /// Check if a node contains addition of sizeof() expressions
    fn contains_sizeof_addition(&self, node: &Node, source: &str) -> bool {
        self.check_for_sizeof_addition(node, source, 0) > 1
    }

    /// Recursively count sizeof() expressions in addition chains
    fn check_for_sizeof_addition(&self, node: &Node, source: &str, depth: usize) -> usize {
        // Prevent infinite recursion
        if depth > 20 {
            return 0;
        }

        match node.kind() {
            "binary_expression" => {
                // Check if this is an addition operator
                if let Some(operator_node) = node.child_by_field_name("operator") {
                    let operator = get_node_text(&operator_node, source).trim();
                    if operator == "+" {
                        // Count sizeof expressions in both operands
                        let mut count = 0;
                        if let Some(left) = node.child_by_field_name("left") {
                            count += self.check_for_sizeof_addition(&left, source, depth + 1);
                        }
                        if let Some(right) = node.child_by_field_name("right") {
                            count += self.check_for_sizeof_addition(&right, source, depth + 1);
                        }
                        return count;
                    } else if operator == "*" {
                        // For multiplication, check if either operand contains sizeof
                        // This catches patterns like "buffer_size * sizeof(char)"
                        let mut count = 0;
                        if let Some(left) = node.child_by_field_name("left") {
                            count += self.check_for_sizeof_in_expr(&left, source, depth + 1);
                        }
                        if let Some(right) = node.child_by_field_name("right") {
                            count += self.check_for_sizeof_in_expr(&right, source, depth + 1);
                        }
                        // A multiplication with sizeof counts as 1 sizeof expression
                        return if count > 0 { 1 } else { 0 };
                    }
                }
                0
            }
            "sizeof_expression" => {
                // Found a sizeof expression
                1
            }
            "parenthesized_expression" | "cast_expression" => {
                // Look through parentheses and casts
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        let count = self.check_for_sizeof_addition(&child, source, depth + 1);
                        if count > 0 {
                            return count;
                        }
                    }
                }
                0
            }
            _ => 0,
        }
    }

    /// Check if an expression contains sizeof anywhere
    fn check_for_sizeof_in_expr(&self, node: &Node, source: &str, depth: usize) -> usize {
        if depth > 20 {
            return 0;
        }

        match node.kind() {
            "sizeof_expression" => 1,
            "binary_expression" | "parenthesized_expression" | "cast_expression" => {
                let mut count = 0;
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        count += self.check_for_sizeof_in_expr(&child, source, depth + 1);
                    }
                }
                count
            }
            _ => 0,
        }
    }

    fn report_violation(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let start_point = node.start_position();
        let node_text = get_node_text(node, source).trim().to_string();

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Do not manually calculate struct size by adding member sizes: '{}'. Use sizeof(struct_type) instead to account for padding.",
                if node_text.len() > 60 {
                    format!("{}...", &node_text[..60])
                } else {
                    node_text
                }
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Replace manual size calculation with sizeof(struct_type) to properly account for padding and alignment".to_string()
            ),
            ..Default::default()
        });
    }
}
