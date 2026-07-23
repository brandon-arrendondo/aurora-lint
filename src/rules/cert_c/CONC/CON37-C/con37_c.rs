//! CON37-C: Do not call signal() in a multithreaded program
//!
//! The C Standard (C11 7.14.1.1 paragraph 7) states that the use of the signal()
//! function in a multithreaded program results in undefined behavior.
//!
//! ## Rationale:
//! - Mixing signals and threads causes undefined behavior in C11
//! - Signal handlers execute in an unpredictable thread context
//! - Race conditions and data corruption can occur
//! - POSIX implementations provide defined behavior but are still discouraged

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;

pub struct Con37C;

impl CertRule for Con37C {
    fn rule_id(&self) -> &'static str {
        "CON37-C"
    }

    fn description(&self) -> &'static str {
        "Do not call signal() in a multithreaded program"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON37-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: check if the code uses threading functions
        let has_threading = self.has_threading_functions(node, source);

        // Second pass: find signal() calls
        if has_threading {
            self.check_signal_calls(node, source, &mut violations);
        }

        violations
    }
}

impl Con37C {
    /// Check if the code uses threading functions
    fn has_threading_functions(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func, source).trim();

            // Check for C11 thread functions, POSIX thread functions, and Windows thread functions
            matches!(
                func_name,
                "thrd_create"
                    | "pthread_create"
                    | "CreateThread"
                    | "_beginthread"
                    | "_beginthreadex"
                    | "thrd_join"
                    | "pthread_join"
                    | "mtx_init"
                    | "pthread_mutex_init"
            )
        })
        .is_some()
    }

    /// Find and flag signal() calls in multithreaded context
    fn check_signal_calls(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func, source).trim();

                if func_name == "signal" {
                    let line = n.start_position().row + 1;
                    let column = n.start_position().column + 1;
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: "Calling signal() in a multithreaded program causes undefined behavior."
                            .to_string(),
                        file_path: String::new(),
                        line,
                        column,
                        suggestion: Some(
                            "Use sigaction() on POSIX systems or platform-specific thread-safe alternatives."
                                .to_string(),
                        ),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }
}
