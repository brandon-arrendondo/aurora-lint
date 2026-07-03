//! CON38-C: Preserve thread safety and liveness when using condition variables
//!
//! This rule detects use of `cnd_signal()` which can cause deadlock when multiple
//! threads wait on the same condition variable with different predicates. The safer
//! alternative is `cnd_broadcast()` which wakes all waiting threads.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! // Multiple threads wait on shared condition variable
//! void process_thread(int thread_id) {
//!   mtx_lock(&mutex);
//!   while (!ready[thread_id]) {
//!     cnd_wait(&cond, &mutex);  // Multiple threads wait on same condition
//!   }
//!   // ... process ...
//!   cnd_signal(&cond);  // WRONG: May wake wrong thread, causing deadlock
//!   mtx_unlock(&mutex);
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! void process_thread(int thread_id) {
//!   mtx_lock(&mutex);
//!   while (!ready[thread_id]) {
//!     cnd_wait(&cond, &mutex);
//!   }
//!   // ... process ...
//!   cnd_broadcast(&cond);  // Correct: Wakes all threads, ensures liveness
//!   mtx_unlock(&mutex);
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find all `cnd_signal()` calls
//! - Report violations recommending `cnd_broadcast()` for safer thread coordination
//! - Note: Using `cnd_signal()` is only safe when each thread has its own unique
//!   condition variable, which is difficult to verify statically

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Con38C;

impl CertRule for Con38C {
    fn rule_id(&self) -> &'static str {
        "CON38-C"
    }

    fn description(&self) -> &'static str {
        "Preserve thread safety and liveness when using condition variables"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON38-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Con38C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for call expressions that might be cnd_signal()
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = call.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                if self.is_signal_function(&func_name) {
                    self.report_violation(&call, source, violations);
                }
            }
        }
    }

    fn is_signal_function(&self, func_name: &str) -> bool {
        // Match both C11 (cnd_signal) and POSIX (pthread_cond_signal)
        matches!(func_name.trim(), "cnd_signal" | "pthread_cond_signal")
    }

    fn report_violation(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let line = node.start_position().row + 1;
        let column = node.start_position().column + 1;

        // Get the condition variable being signaled
        let (cond_var, is_array_access) = self
            .get_condition_variable(node, source)
            .unwrap_or_else(|| ("condition variable".to_string(), false));

        // Don't flag if the condition variable is accessed via array subscript
        // (indicates unique condition variable per thread, which is compliant)
        if is_array_access {
            return;
        }

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "Use of cnd_signal() with '{}' may cause deadlock if multiple threads wait with different predicates",
                cond_var
            ),
            file_path: String::new(),
            line,
            column,
            suggestion: Some(
                "Consider using cnd_broadcast() to wake all waiting threads and ensure liveness. \
                Alternatively, use unique condition variables per thread if signaling specific threads.".to_string()
            ),
            ..Default::default()
        });
    }

    fn get_condition_variable(&self, call_node: &Node, source: &str) -> Option<(String, bool)> {
        // Get the arguments node
        if let Some(args_node) = call_node.child_by_field_name("arguments") {
            // Get the first argument (the condition variable)
            for i in 0..args_node.child_count() {
                if let Some(child) = args_node.child(i) {
                    if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                        let arg_text = get_node_text(&child, source);

                        // Check if this is an array access (subscript_expression)
                        let is_array_access = child.kind() == "subscript_expression"
                            || self.contains_subscript(&child);

                        // Extract the variable name (handle &cond, &cond[i], etc.)
                        let var_name = arg_text.trim().trim_start_matches('&').to_string();
                        return Some((var_name, is_array_access));
                    }
                }
            }
        }
        None
    }

    fn contains_subscript(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "subscript_expression").is_some()
    }
}
