//! WIN02-C: Restrict privileges when spawning child processes
//!
//! CreateProcess() inherits parent privileges - unsafe.
//! Use CreateProcessAsUser() to specify exact privileges.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! CreateProcess(...);  // VIOLATION: inherits privileges
//! ```
//!
//! **Compliant:**
//! ```c
//! CreateProcessAsUser(token, ...);  // OK: explicit user/token
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Win02C;

impl CertRule for Win02C {
    fn rule_id(&self) -> &'static str {
        "WIN02-C"
    }

    fn description(&self) -> &'static str {
        "Restrict privileges when spawning child processes"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "WIN02-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Win02C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "CreateProcess" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: "CreateProcess() called - spawns child with inherited privileges".to_string(),
                        file_path: String::new(),
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        suggestion: Some(
                            "Use CreateProcessAsUser() with appropriate token to explicitly control child process privileges".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }
}
