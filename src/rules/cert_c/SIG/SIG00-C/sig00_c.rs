//! SIG00-C: Mask signals handled by noninterruptible signal handlers
//!
//! This rule ensures that signal handlers that require noninterruptible execution
//! are properly protected from race conditions by using signal masking.
//!
//! ## Non-compliant example:
//!
//! ```c
//! // Using signal() - does not provide signal masking
//! signal(SIGUSR1, handler);
//!
//! // Using sigaction() without masking
//! struct sigaction act;
//! act.sa_handler = handler;
//! sigaction(SIGUSR1, &act, NULL);  // No signal masking configured
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! struct sigaction act;
//! act.sa_handler = handler;
//! sigemptyset(&act.sa_mask);
//! sigaddset(&act.sa_mask, SIGUSR1);  // Mask signal during handler execution
//! sigaddset(&act.sa_mask, SIGUSR2);
//! sigaction(SIGUSR1, &act, NULL);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Sig00C;

impl Sig00C {
    pub fn new() -> Self {
        Self
    }

    /// Check for calls to signal() function
    fn check_signal_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "call_expression" {
            return;
        }

        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            if function_name == "signal" {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: "Use of signal() function detected. signal() does not provide signal masking and can lead to race conditions in noninterruptible signal handlers. Use sigaction() with proper signal masking instead.".to_string(),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(
                        "Replace signal() with sigaction() and configure sa_mask to mask signals during handler execution using sigemptyset() and sigaddset()."
                            .to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// Check for sigaction() calls without proper signal masking
    fn check_sigaction_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "call_expression" {
            return;
        }

        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            if function_name == "sigaction" {
                // Check if there's a preceding sigaddset call in the same scope
                // This is a heuristic check - full verification would require data flow analysis
                if !self.has_preceding_sigaddset(node, source) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: "sigaction() call detected without apparent signal masking. Ensure sa_mask is properly configured with sigaddset() before calling sigaction().".to_string(),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(
                            "Use sigemptyset() and sigaddset() to configure sa_mask before calling sigaction() to prevent race conditions in signal handlers."
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Heuristic check: look for sigaddset calls before this node
    fn has_preceding_sigaddset(&self, node: &Node, source: &str) -> bool {
        // Walk up to find the compound statement containing this call
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "compound_statement" || parent.kind() == "function_definition" {
                // Search for sigaddset calls before this node
                return self.contains_sigaddset_before(&parent, node, source);
            }
            current = parent.parent();
        }
        false
    }

    /// Search for sigaddset calls before the target node.
    ///
    /// Uses an explicit stack instead of recursion: this recurses into
    /// every child unconditionally (pruned only by byte-offset position
    /// relative to `target`, not by node kind), so deeply nested code
    /// before the target would cost one native call frame per level --
    /// same unbounded-depth risk class as the original ARR00-C/MEM33-C bug
    /// (task 153). Pure existence check, so traversal order doesn't affect
    /// the result.
    fn contains_sigaddset_before(&self, scope: &Node, target: &Node, source: &str) -> bool {
        let target_start = target.start_byte();
        let mut stack = vec![*scope];

        while let Some(scope) = stack.pop() {
            for i in 0..scope.child_count() {
                if let Some(child) = scope.child(i) {
                    // Stop when we reach the target node
                    if child.start_byte() >= target_start {
                        break;
                    }

                    // Check if this is a sigaddset call
                    if self.is_sigaddset_call(&child, source) {
                        return true;
                    }

                    // Queue child nodes for checking
                    stack.push(child);
                }
            }
        }

        false
    }

    /// Check if a node is a call to sigaddset
    fn is_sigaddset_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                let function_name = get_node_text(&function_node, source);
                return function_name == "sigaddset";
            }
        }
        false
    }
}

impl CertRule for Sig00C {
    fn rule_id(&self) -> &'static str {
        "SIG00-C"
    }

    fn description(&self) -> &'static str {
        "Mask signals handled by noninterruptible signal handlers"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "SIG00-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Sig00C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for signal() and sigaction() calls
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_signal_call(&call, source, violations);
            self.check_sigaction_call(&call, source, violations);
        }
    }
}
