//! FIO37-C: Do not assume that fgets() or fgetws() returns a nonempty string when successful
//!
//! This rule detects code that assumes fgets() or fgetws() returns a nonempty string.
//! Even when these functions succeed (return non-NULL), the buffer may contain only
//! null bytes, making operations like strlen(buf) - 1 dangerous (underflow).
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! if (fgets(buf, sizeof(buf), stdin) == NULL) {
//!     /* Handle error */
//! }
//! buf[strlen(buf) - 1] = '\0';  // VIOLATION: strlen may be 0
//! ```
//!
//! **Compliant:**
//! ```c
//! if (fgets(buf, sizeof(buf), stdin)) {
//!     p = strchr(buf, '\n');
//!     if (p) {
//!         *p = '\0';  // Safe: only if newline found
//!     }
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Track variables assigned from fgets/fgetws
//! - Look for strlen() used in subtraction on those variables
//! - Report violation if found

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Fio37C;

impl CertRule for Fio37C {
    fn rule_id(&self) -> &'static str {
        "FIO37-C"
    }

    fn description(&self) -> &'static str {
        "Do not assume that fgets() or fgetws() returns a nonempty string when successful"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO37-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Fio37C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for function bodies
        for body in query::find_descendants_of_kind(*node, "compound_statement") {
            self.check_function_body(&body, source, violations);
        }
    }

    fn check_function_body(&self, body: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Track variables that received data from fgets/fgetws
        let mut fgets_vars = HashSet::new();

        // Scan for fgets/fgetws calls
        self.collect_fgets_vars(body, source, &mut fgets_vars);

        // Scan for dangerous strlen usage on those variables
        self.check_strlen_usage(body, source, &fgets_vars, violations);
    }

    fn collect_fgets_vars(&self, node: &Node, source: &str, fgets_vars: &mut HashSet<String>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "fgets" || func_name == "fgetws" {
                    // Get the first argument (the buffer)
                    if let Some(args) = call.child_by_field_name("arguments") {
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                    // This is the buffer argument
                                    let var_name = get_node_text(&arg, source);
                                    fgets_vars.insert(var_name.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_strlen_usage(
        &self,
        node: &Node,
        source: &str,
        fgets_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for strlen() in subtraction
        for binary in query::find_descendants_of_kind(*node, "binary_expression") {
            let operator = self.get_operator(&binary, source);
            if operator == "-" {
                // Check if left side is strlen(fgets_var)
                if let Some(left) = binary.child_by_field_name("left") {
                    if let Some(var_name) = self.is_strlen_of_var(&left, source) {
                        if fgets_vars.contains(&var_name) {
                            self.report_violation(&binary, &var_name, source, violations);
                        }
                    }
                }
            }
        }
    }

    fn get_operator(&self, binary_expr: &Node, source: &str) -> String {
        // Find the operator child
        for i in 0..binary_expr.child_count() {
            if let Some(child) = binary_expr.child(i) {
                let text = get_node_text(&child, source);
                if text == "-" || text == "+" || text == "*" || text == "/" {
                    return text.to_string();
                }
            }
        }
        String::new()
    }

    /// Check if expression is strlen(var) and return var name
    fn is_strlen_of_var(&self, expr: &Node, source: &str) -> Option<String> {
        if expr.kind() == "call_expression" {
            if let Some(function) = expr.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "strlen" {
                    // Get the argument
                    if let Some(args) = expr.child_by_field_name("arguments") {
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                                    let var_name = get_node_text(&arg, source);
                                    return Some(var_name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn report_violation(
        &self,
        node: &Node,
        var_name: &str,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let expr_text = get_node_text(&node, source);

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::High,
            message: format!(
                "Dangerous use of strlen() on fgets() result '{}': '{}' - fgets() may return empty string (strlen=0), causing underflow",
                var_name, expr_text.trim()
            ),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(format!(
                "Check if '{}' is non-empty before using strlen() in arithmetic. Use strchr() to find characters instead of assuming strlen > 0",
                var_name
            )),
            ..Default::default()
        });
    }
}
