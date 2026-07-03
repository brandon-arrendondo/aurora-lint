//! WIN01-C: Do not forcibly terminate execution of threads
//!
//! TerminateThread() forcibly kills a thread without cleanup - unsafe.
//! Use cooperative signaling instead.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! TerminateThread(hThread, 0xFF);  // VIOLATION: forced termination
//! ```
//!
//! **Compliant:**
//! ```c
//! InterlockedExchange(&ShouldThreadExit, 1);  // Signal thread to exit
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Win01C;

impl CertRule for Win01C {
    fn rule_id(&self) -> &'static str {
        "WIN01-C"
    }

    fn description(&self) -> &'static str {
        "Do not forcibly terminate execution of threads"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "WIN01-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Win01C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "TerminateThread" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: "TerminateThread() called - forcibly terminates thread without cleanup".to_string(),
                        file_path: String::new(),
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        suggestion: Some(
                            "Use cooperative signaling (e.g., InterlockedExchange) to request thread exit instead of forcing termination".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }
}
