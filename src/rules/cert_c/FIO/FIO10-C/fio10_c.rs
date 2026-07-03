//! FIO10-C: Take care when using the rename() function
//!
//! The behavior of rename() when the destination file exists is implementation-defined.
//! On POSIX systems, the destination is removed. On Windows, rename() fails.
//!
//! Compliant code must handle destination file existence BEFORE calling rename():
//!
//! ## Compliant Patterns:
//!
//! **Pattern 1: Remove existing destination explicitly**
//! ```c
//! remove(dest_file);  // Explicit removal
//! if (rename(src_file, dest_file) != 0) {
//!     // Handle error
//! }
//! ```
//!
//! **Pattern 2: Check if destination exists first**
//! ```c
//! if (!file_exists(dest_file)) {
//!     if (rename(src_file, dest_file) != 0) {
//!         // Handle error
//!     }
//! } else {
//!     // Handle existing file
//! }
//! ```
//!
//! **Non-compliant:**
//! ```c
//! // Just checking return value is NOT sufficient
//! if (rename(src, dst) != 0) {
//!     // Handle error - but didn't handle dest existence!
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio10C;

impl CertRule for Fio10C {
    fn rule_id(&self) -> &'static str {
        "FIO10-C"
    }

    fn description(&self) -> &'static str {
        "Take care when using the rename() function"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO10-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.find_unhandled_rename(node, source, &mut violations);
        violations
    }
}

impl Fio10C {
    /// Find rename() calls without proper destination file handling
    fn find_unhandled_rename(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for rename() calls
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "rename" {
                    // Check if this rename() is properly handled
                    if !self.is_properly_handled(&call, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: "rename() called without handling destination file existence. \
                                      Behavior is implementation-defined (POSIX removes dest, Windows fails)."
                                .to_string(),
                            severity: self.severity(),
                            line: call.start_position().row + 1,
                            column: call.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Either: (1) Call remove(dest) before rename(), OR \
                                 (2) Check if dest exists with file_exists()/access()/stat() \
                                 and handle accordingly"
                                    .to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Check if rename() call has proper destination handling
    fn is_properly_handled(&self, rename_node: &Node, source: &str) -> bool {
        // Pattern 1: Check if preceded by remove() call (standalone or inside if)
        if self.has_preceding_remove(rename_node, source) {
            return true;
        }

        // Pattern 2: Check if wrapped in file existence check
        if self.is_wrapped_in_existence_check(rename_node, source) {
            return true;
        }

        // Pattern 3: Check if preceded by an access/stat check (with remove inside)
        if self.has_preceding_existence_check_with_remove(rename_node, source) {
            return true;
        }

        // Pattern 4: rename() with return value check (POSIX compliant).
        // On POSIX, rename() atomically replaces the destination, so checking
        // the return value for errors is sufficient handling.
        if self.has_return_value_check(rename_node) {
            return true;
        }

        false
    }

    /// Check if there's a remove() call before this rename() in the same scope
    fn has_preceding_remove(&self, rename_node: &Node, source: &str) -> bool {
        // Get the expression_statement or parent containing this rename()
        let mut current = rename_node.parent();
        while let Some(parent) = current {
            if parent.kind() == "expression_statement" || parent.kind() == "if_statement" {
                // Found statement level, now check preceding siblings
                if let Some(grandparent) = parent.parent() {
                    let parent_id = parent.id();
                    let mut found_parent = false;

                    // Look backwards for remove() call
                    for i in (0..grandparent.child_count()).rev() {
                        if let Some(sibling) = grandparent.child(i) {
                            if found_parent {
                                // Check this sibling (which comes BEFORE our statement)
                                if self.contains_remove_call(&sibling, source) {
                                    return true;
                                }
                            }
                            if sibling.id() == parent_id {
                                found_parent = true;
                            }
                        }
                    }
                }
                break;
            }
            current = parent.parent();
        }
        false
    }

    /// Check if node or its children contain a remove() call
    fn contains_remove_call(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&function, source);
            func_name == "remove" || func_name == "unlink"
        })
        .is_some()
    }

    /// Check if rename() is wrapped in a file existence check
    fn is_wrapped_in_existence_check(&self, rename_node: &Node, source: &str) -> bool {
        // Walk up the tree looking for an if_statement
        let mut current = rename_node.parent();
        while let Some(node) = current {
            if node.kind() == "if_statement" {
                // Check if condition contains file existence check
                if let Some(condition) = node.child_by_field_name("condition") {
                    let condition_text = get_node_text(&condition, source);

                    // Look for common file existence check patterns
                    if self.is_existence_check(&condition_text) {
                        return true;
                    }
                }
            }
            current = node.parent();
        }
        false
    }

    /// Check if preceding statements contain existence check with remove
    fn has_preceding_existence_check_with_remove(&self, rename_node: &Node, source: &str) -> bool {
        // Get the statement containing this rename()
        let mut current = rename_node.parent();
        while let Some(parent) = current {
            if parent.kind() == "expression_statement" || parent.kind() == "if_statement" {
                // Found statement level, now check preceding siblings
                if let Some(grandparent) = parent.parent() {
                    let parent_id = parent.id();
                    let mut found_parent = false;

                    // Look backwards for if statement with existence check containing remove
                    for i in (0..grandparent.child_count()).rev() {
                        if let Some(sibling) = grandparent.child(i) {
                            if found_parent {
                                // Check if this is an if statement with existence check
                                if sibling.kind() == "if_statement" {
                                    if let Some(condition) =
                                        sibling.child_by_field_name("condition")
                                    {
                                        let condition_text = get_node_text(&condition, source);
                                        if self.is_existence_check(&condition_text) {
                                            // Check if the if body contains remove()
                                            if self.contains_remove_call(&sibling, source) {
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                            if sibling.id() == parent_id {
                                found_parent = true;
                            }
                        }
                    }
                }
                break;
            }
            current = parent.parent();
        }
        false
    }

    /// Check if rename()'s return value is tested (POSIX compliant pattern).
    ///
    /// Matches `if (rename(...) != 0)` and similar patterns where the rename()
    /// call is the condition (or part of the condition) of an if_statement.
    fn has_return_value_check(&self, rename_node: &Node) -> bool {
        let mut current = rename_node.parent();
        while let Some(node) = current {
            match node.kind() {
                // rename() is used directly as an if/while condition
                "parenthesized_expression" | "binary_expression" | "unary_expression" => {
                    current = node.parent();
                    continue;
                }
                "if_statement" | "while_statement" => {
                    // Check that rename_node is inside the condition, not the body
                    if let Some(condition) = node.child_by_field_name("condition") {
                        if rename_node.start_byte() >= condition.start_byte()
                            && rename_node.end_byte() <= condition.end_byte()
                        {
                            return true;
                        }
                    }
                    return false;
                }
                // If we hit a statement boundary, stop searching
                "expression_statement" | "compound_statement" | "function_definition" => {
                    return false;
                }
                _ => {
                    current = node.parent();
                    continue;
                }
            }
        }
        false
    }

    /// Check if text contains file existence check function names
    fn is_existence_check(&self, text: &str) -> bool {
        text.contains("file_exists")
            || text.contains("access")
            || text.contains("_access")
            || text.contains("stat")
            || text.contains("lstat")
            || text.contains("fstat")
            || text.contains("PathFileExists")
    }
}
