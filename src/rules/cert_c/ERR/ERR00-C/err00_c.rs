//! ERR00-C: Adopt and implement a consistent and comprehensive error-handling policy
//!
//! This recommendation emphasizes that systems must check error returns from
//! functions rather than assuming success. Focus on detecting unchecked return
//! values from common error-prone functions.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! FILE *fp = fopen("data.txt", "r");  // No check
//! fscanf(fp, "%d", &value);
//! ```
//!
//! **Compliant:**
//! ```c
//! FILE *fp = fopen("data.txt", "r");
//! if (fp == NULL) {
//!     perror("fopen failed");
//!     return -1;
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Err00C;

impl CertRule for Err00C {
    fn rule_id(&self) -> &'static str {
        "ERR00-C"
    }

    fn description(&self) -> &'static str {
        "Adopt and implement a consistent and comprehensive error-handling policy"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "ERR00-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Err00C {
    /// Check for unchecked error returns
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let matches = query::find_descendants_of_kinds(
            *node,
            &[
                "init_declarator",
                "assignment_expression",
                "expression_statement",
            ],
        );
        for n in matches {
            match n.kind() {
                "init_declarator" => {
                    // Check variable initialization with error-prone functions
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        if let Some(value) = n.child_by_field_name("value") {
                            if value.kind() == "call_expression" {
                                self.check_unchecked_assignment(
                                    &declarator,
                                    &value,
                                    source,
                                    violations,
                                );
                            }
                        }
                    }
                }
                "assignment_expression" => {
                    // Check assignments with error-prone functions
                    if let Some(left) = n.child_by_field_name("left") {
                        if let Some(right) = n.child_by_field_name("right") {
                            if right.kind() == "call_expression" {
                                self.check_unchecked_assignment(&left, &right, source, violations);
                            }
                        }
                    }
                }
                "expression_statement" => {
                    // Check standalone function calls that ignore return values
                    if let Some(child) = n.child(0) {
                        if child.kind() == "call_expression" {
                            self.check_ignored_return(&child, source, violations);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Check if an assignment from error-prone function is checked later
    fn check_unchecked_assignment(
        &self,
        _var_node: &Node,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(func) = call_node.child_by_field_name("function") {
            let func_name = get_node_text(&func, source);

            if self.is_error_prone_function(&func_name) {
                // Simple heuristic: check if there's error checking nearby
                if !self.has_nearby_error_check(call_node, source) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        message: format!(
                            "Return value from {}() should be checked for errors",
                            func_name
                        ),
                        severity: self.severity(),
                        line: call_node.start_position().row + 1,
                        column: call_node.start_position().column + 1,
                        file_path: String::new(),
                        suggestion: Some(format!(
                            "Check if {}() returned an error value (NULL, -1, etc.)",
                            func_name
                        )),
                        requires_manual_review: Some(true),
                    });
                }
            }
        }
    }

    /// Check for ignored return values from error-prone functions
    fn check_ignored_return(
        &self,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(func) = call_node.child_by_field_name("function") {
            let func_name = get_node_text(&func, source);

            if self.is_error_prone_function(&func_name) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: format!(
                        "Return value from {}() is ignored. Error handling is required.",
                        func_name
                    ),
                    severity: self.severity(),
                    line: call_node.start_position().row + 1,
                    column: call_node.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Store and check the return value from {}()",
                        func_name
                    )),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    /// Check if there's error checking code nearby
    fn has_nearby_error_check(&self, node: &Node, source: &str) -> bool {
        // Look for if statements or NULL checks in parent scope
        let mut current = node.parent();
        let mut depth = 0;

        while let Some(parent) = current {
            depth += 1;
            if depth > 3 {
                break; // Don't look too far up
            }

            // Check siblings for if statements
            if parent.kind() == "compound_statement" || parent.kind() == "translation_unit" {
                for i in 0..parent.child_count() {
                    if let Some(sibling) = parent.child(i) {
                        if sibling.kind() == "if_statement" {
                            let text = get_node_text(&sibling, source);
                            // Simple heuristic: check for NULL, error, -1, etc.
                            if text.contains("NULL")
                                || text.contains("== -1")
                                || text.contains("!= 0")
                                || text.contains("error")
                            {
                                return true;
                            }
                        }
                    }
                }
            }

            current = parent.parent();
        }

        false
    }

    /// Check if a function is known to return error indicators
    fn is_error_prone_function(&self, name: &str) -> bool {
        matches!(
            name,
            "malloc"
                | "calloc"
                | "realloc"
                | "fopen"
                | "fgets"
                | "fgetc"
                | "fclose"
                | "fseek"
                | "ftell"
                | "fread"
                | "fwrite"
                | "fscanf"
                | "scanf"
                | "sscanf"
                | "strtol"
                | "strtoul"
                | "strdup"
        )
    }
}
