//! POS47-C: Do not use threads that can be canceled asynchronously
//!
//! Threads should not be set to asynchronous cancellation mode because it can lead
//! to data races, deadlocks, and resource leaks. Asynchronous cancellation allows a
//! thread to be terminated immediately at any point, potentially interrupting critical
//! operations or leaving data in an inconsistent state.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void* worker_thread(void* dummy) {
//!   int i;
//!   int result;
//!   if ((result = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &i)) != 0) {
//!     /* handle error */
//!   }
//!   // ... thread work ...
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! void* worker_thread(void* dummy) {
//!   // Use default deferred cancellation mode
//!   // Insert cancellation points explicitly
//!   while (1) {
//!     // ... critical section ...
//!     pthread_testcancel();  // Safe cancellation point
//!   }
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find calls to pthread_setcanceltype()
//! - Check if first argument is PTHREAD_CANCEL_ASYNCHRONOUS
//! - Report a violation if asynchronous cancellation is enabled

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pos47C;

impl CertRule for Pos47C {
    fn rule_id(&self) -> &'static str {
        "POS47-C"
    }

    fn description(&self) -> &'static str {
        "Do not use threads that can be canceled asynchronously"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS47-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Pos47C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for pthread_setcanceltype() calls
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "pthread_setcanceltype" {
                    self.check_pthread_setcanceltype_call(&node, source, violations);
                }
            }
        }
    }

    fn check_pthread_setcanceltype_call(
        &self,
        call: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get arguments: pthread_setcanceltype(type, oldtype)
        let args = match call.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        // Get all children, skipping commas and parentheses
        let mut arg_nodes = Vec::new();
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                let kind = child.kind();
                // Skip structural tokens
                if kind != "," && kind != "(" && kind != ")" {
                    arg_nodes.push(child);
                }
            }
        }

        if arg_nodes.is_empty() {
            return;
        }

        // First argument is the cancel type
        let type_arg = &arg_nodes[0];
        let type_text = get_node_text(&type_arg, source);

        // Check if it's PTHREAD_CANCEL_ASYNCHRONOUS
        if type_text.contains("PTHREAD_CANCEL_ASYNCHRONOUS") {
            // VIOLATION: using asynchronous cancellation
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Medium,
                message: "pthread_setcanceltype() called with PTHREAD_CANCEL_ASYNCHRONOUS - threads should use deferred cancellation to prevent data races and resource leaks".to_string(),
                file_path: String::new(),
                line: call.start_position().row + 1,
                column: call.start_position().column + 1,
                suggestion: Some(
                    "Use the default deferred cancellation mode (PTHREAD_CANCEL_DEFERRED) and insert explicit cancellation points with pthread_testcancel()".to_string()
                ),
                ..Default::default()
            });
        }
    }
}
