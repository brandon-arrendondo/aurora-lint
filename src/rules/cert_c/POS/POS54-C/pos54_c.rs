//! POS54-C: Detect and handle POSIX library errors
//!
//! This rule detects calls to POSIX library functions that return error indicators
//! without checking the return value for errors. Failing to check error returns can
//! lead to unexpected or undefined behavior when errors occur.
//!
//! ## POSIX Functions Checked:
//!
//! | Function | Success Return | Error Return | errno |
//! |----------|---------------|--------------|-------|
//! | fmemopen() | Pointer to FILE | NULL | ENOMEM |
//! | open_memstream() | Pointer to FILE | NULL | ENOMEM |
//! | posix_memalign() | 0 | Nonzero | Unchanged |
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! FILE *in = fmemopen(data, len, "r");
//! // No NULL check - violation!
//! ```
//!
//! **Compliant:**
//! ```c
//! FILE *in = fmemopen(data, len, "r");
//! if (in == NULL) {
//!     // Handle error
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find call_expression nodes for tracked POSIX functions
//! - Check if return value is assigned to a variable
//! - Search forward for error checks (NULL check or non-zero check)
//! - Report violation if no error check found

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pos54C;

impl CertRule for Pos54C {
    fn rule_id(&self) -> &'static str {
        "POS54-C"
    }

    fn description(&self) -> &'static str {
        "Detect and handle POSIX library errors"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "POS54-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Pos54C {
    /// POSIX functions that return NULL on error
    fn is_posix_null_error_function(name: &str) -> bool {
        matches!(name, "fmemopen" | "open_memstream")
    }

    /// POSIX functions that return non-zero on error
    fn is_posix_nonzero_error_function(name: &str) -> bool {
        matches!(name, "posix_memalign")
    }

    /// Check if function name is a tracked POSIX error function
    fn is_posix_error_function(name: &str) -> bool {
        Self::is_posix_null_error_function(name) || Self::is_posix_nonzero_error_function(name)
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for call expressions
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            let node = &node;
            if let Some(function_node) = node.child_by_field_name("function") {
                let function_name = get_node_text(&function_node, source);

                if Self::is_posix_error_function(function_name) {
                    // Check if this call is part of an assignment
                    if let Some(parent) = node.parent() {
                        if parent.kind() == "init_declarator" {
                            // Pattern: type var = func();
                            if let Some(declarator) = parent.child_by_field_name("declarator") {
                                let var_name = get_node_text(&declarator, source);

                                // Search forward for error check
                                if !self.find_error_check_in_context(
                                    &parent,
                                    var_name,
                                    function_name,
                                    source,
                                ) {
                                    self.report_violation(node, function_name, source, violations);
                                }
                            }
                        } else if parent.kind() == "assignment_expression" {
                            // Pattern: var = func();
                            if let Some(left) = parent.child_by_field_name("left") {
                                let var_name = get_node_text(&left, source);

                                // Search forward for error check
                                if !self.find_error_check_in_context(
                                    &parent,
                                    var_name,
                                    function_name,
                                    source,
                                ) {
                                    self.report_violation(node, function_name, source, violations);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Search for error checks in subsequent statements
    fn find_error_check_in_context(
        &self,
        start_node: &Node,
        var_name: &str,
        function_name: &str,
        source: &str,
    ) -> bool {
        // Get the parent statement
        let mut current_opt = Some(*start_node);
        while let Some(current) = current_opt.as_ref() {
            if let Some(parent) = current.parent() {
                if parent.kind() == "declaration" || parent.kind() == "expression_statement" {
                    current_opt = Some(parent);
                    break;
                }
                current_opt = Some(parent);
            } else {
                break;
            }
        }

        let current = current_opt.as_ref().unwrap_or(start_node);

        // Get the compound statement (block) containing this statement
        let mut block_opt = Some(*current);
        while let Some(block) = block_opt.as_ref() {
            if let Some(parent) = block.parent() {
                if parent.kind() == "compound_statement" {
                    block_opt = Some(parent);
                    break;
                }
                block_opt = Some(parent);
            } else {
                break;
            }
        }

        let block_node = block_opt.as_ref().unwrap_or(current);

        // Find our statement in the block
        let mut found_our_statement = false;
        let current_line = start_node.start_position().row;

        // Search next 5 statements for error check
        let mut statements_checked = 0;
        for i in 0..block_node.child_count() {
            if let Some(child) = block_node.child(i) {
                let child_line = child.start_position().row;

                if child_line >= current_line {
                    found_our_statement = true;
                }

                if found_our_statement && statements_checked < 5 {
                    if self.statement_checks_error(&child, var_name, function_name, source) {
                        return true;
                    }
                    statements_checked += 1;
                }
            }
        }

        false
    }

    /// Check if a statement contains an error check for the variable
    fn statement_checks_error(
        &self,
        node: &Node,
        var_name: &str,
        function_name: &str,
        source: &str,
    ) -> bool {
        query::find_first_descendant(*node, |n| {
            // Look for if statements
            if n.kind() != "if_statement" {
                return false;
            }
            let Some(condition) = n.child_by_field_name("condition") else {
                return false;
            };
            let condition_text = get_node_text(&condition, source);

            // Check for NULL check (fmemopen, open_memstream)
            if Self::is_posix_null_error_function(function_name)
                && condition_text.contains(var_name)
                && (condition_text.contains("== NULL")
                    || condition_text.contains("!= NULL")
                    || condition_text.contains("==NULL")
                    || condition_text.contains("!=NULL")
                    || format!("!{}", var_name) == condition_text.trim())
            {
                return true;
            }

            // Check for non-zero check (posix_memalign)
            if Self::is_posix_nonzero_error_function(function_name)
                && condition_text.contains(var_name)
                && (condition_text.contains("!= 0")
                    || condition_text.contains("== 0")
                    || condition_text.contains("!=0")
                    || condition_text.contains("==0"))
            {
                return true;
            }
            false
        })
        .is_some()
    }

    fn report_violation(
        &self,
        node: &Node,
        function_name: &str,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let start_point = node.start_position();
        let call_text = get_node_text(node, source);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "POSIX function '{}()' return value not checked for error: '{}'",
                function_name, call_text
            ),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(format!(
                "Check the return value of {}() for error. {} returns {} on error.",
                function_name,
                function_name,
                if Self::is_posix_null_error_function(function_name) {
                    "NULL"
                } else {
                    "non-zero"
                }
            )),
            ..Default::default()
        });
    }
}
