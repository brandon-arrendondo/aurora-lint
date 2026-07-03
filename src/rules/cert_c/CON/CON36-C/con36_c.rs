//! CON36-C: Wrap functions that can spuriously wake up in a loop
//!
//! This rule detects uses of cnd_wait() or cnd_timedwait() wrapped in 'if'
//! statements instead of 'while' loops. Condition variables can spuriously
//! wake up, so the condition must be re-checked after waking.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! if (list.next == NULL) {
//!   if (thrd_success != cnd_wait(&condition, &lock)) {
//!     /* Handle error */
//!   }
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! while (list.next == NULL) {
//!   if (thrd_success != cnd_wait(&condition, &lock)) {
//!     /* Handle error */
//!   }
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find calls to cnd_wait() or cnd_timedwait()
//! - Check if the call is inside an 'if' statement
//! - Report violation if not wrapped in a 'while' loop

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Con36C;

impl CertRule for Con36C {
    fn rule_id(&self) -> &'static str {
        "CON36-C"
    }

    fn description(&self) -> &'static str {
        "Wrap functions that can spuriously wake up in a loop"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON36-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for condition variable wait calls
        self.check_node(node, source, &mut violations);

        violations
    }
}

impl Con36C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_cnd_wait_call(&call, source, violations);
        }
    }

    fn check_cnd_wait_call(
        &self,
        call_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the function being called
        if let Some(function) = call_node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source);

            // Check if it's cnd_wait or cnd_timedwait
            if func_name == "cnd_wait" || func_name == "cnd_timedwait" {
                // Check if this call is inside an 'if' statement instead of 'while'
                if self.is_inside_if_not_while(call_node) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "Call to '{}' is wrapped in an 'if' statement. Use 'while' loop to handle spurious wake-ups.",
                            func_name
                        ),
                        file_path: String::new(),
                        line: call_node.start_position().row + 1,
                        column: call_node.start_position().column + 1,
                        suggestion: Some(
                            "Replace the 'if' statement with a 'while' loop to re-check the condition after wake-up".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn is_inside_if_not_while(&self, node: &Node) -> bool {
        let mut current = node.parent();
        let mut found_if = false;

        while let Some(parent) = current {
            match parent.kind() {
                "if_statement" => {
                    found_if = true;
                }
                "while_statement" | "do_statement" | "for_statement" => {
                    // If we hit a loop before hitting function boundary, it's acceptable
                    return false;
                }
                "function_definition" => {
                    // Reached function boundary
                    break;
                }
                _ => {}
            }
            current = parent.parent();
        }

        found_if
    }
}
