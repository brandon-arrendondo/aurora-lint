//! POS37-C: Ensure that privilege relinquishment is successful
//!
//! Detects two patterns:
//! 1. POSIX: setuid(getuid()) without verification via setuid(0)
//! 2. Windows: Privilege/impersonation APIs called without checking return value
//!    (ImpersonateNamedPipeClient, RpcImpersonateClient, etc.)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

pub struct Pos37C;

/// Windows privilege/impersonation APIs whose return values must be checked.
const WIN_PRIVILEGE_APIS: &[&str] = &[
    "ImpersonateNamedPipeClient",
    "RpcImpersonateClient",
    "ImpersonateLoggedOnUser",
    "CoImpersonateClient",
    "ImpersonateSelf",
    "SetThreadToken",
];

impl CertRule for Pos37C {
    fn rule_id(&self) -> &'static str {
        "POS37-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that privilege relinquishment is successful"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS37-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Both helpers recurse over the entire subtree on their own, so each is
        // invoked exactly once on the given node. The previous version ran them at
        // both the translation_unit level (whole tree) and again per function body,
        // re-walking each function and emitting every in-function finding twice
        // (task 221).
        self.check_privilege_drop(node, source, &mut violations);
        self.check_win_privilege_apis(node, source, &mut violations);

        violations
    }
}

impl Pos37C {
    fn check_privilege_drop(
        &self,
        scope: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find setuid(getuid()) or setuid(getgid()) calls (privilege drops)
        let mut drop_calls = Vec::new();
        self.find_priv_drops(scope, source, &mut drop_calls);

        // For each drop, check if there's a verification check afterward
        for drop_call in &drop_calls {
            if !self.has_verification_check(scope, source, drop_call.line) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: "setuid() called to drop privileges without verifying success - privileges may not be relinquished".to_string(),
                    file_path: String::new(),
                    line: drop_call.line,
                    column: drop_call.column,
                    suggestion: Some(
                        "After setuid(getuid()), verify privileges were dropped: if (setuid(0) != -1) { /* handle error */ }".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// Check for Windows privilege/impersonation API calls with unchecked return values.
    /// Pattern: `ImpersonateNamedPipeClient(hPipe);` as a bare expression_statement.
    fn check_win_privilege_apis(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                let func_name = func_name.trim();

                if WIN_PRIVILEGE_APIS.contains(&func_name) && self.is_unchecked_call(node) {
                    let start = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "{}() return value not checked — privilege change may silently fail",
                            func_name
                        ),
                        file_path: String::new(),
                        line: start.row + 1,
                        column: start.column + 1,
                        suggestion: Some(format!(
                            "Check the return value: if (!{}(...)) {{ /* handle error */ }}",
                            func_name
                        )),
                        ..Default::default()
                    });
                }
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_win_privilege_apis(&child, source, violations);
            }
        }
    }

    /// A call is "unchecked" if its immediate parent is an expression_statement
    /// (meaning the return value is discarded).
    fn is_unchecked_call(&self, call_node: &Node) -> bool {
        if let Some(parent) = call_node.parent() {
            return parent.kind() == "expression_statement";
        }
        false
    }

    fn find_priv_drops(&self, node: &Node, source: &str, drops: &mut Vec<PrivDrop>) {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "setuid" {
                    // Check if argument is getuid() or getgid()
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let args_text = get_node_text(&args, source);
                        if args_text.contains("getuid") || args_text.contains("getgid") {
                            drops.push(PrivDrop {
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                            });
                        }
                    }
                }
            }
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.find_priv_drops(&child, source, drops);
            }
        }
    }

    fn has_verification_check(&self, scope: &Node, source: &str, drop_line: usize) -> bool {
        // Look for setuid(0) calls after the drop line
        self.find_verification(scope, source, drop_line)
    }

    fn find_verification(&self, node: &Node, source: &str, after_line: usize) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "setuid" {
                    let line = node.start_position().row + 1;
                    if line > after_line {
                        // Check if argument is 0 (trying to regain root)
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let args_text = get_node_text(&args, source);
                            if args_text.contains("0") && !args_text.contains("getuid") {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // Recurse
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.find_verification(&child, source, after_line) {
                    return true;
                }
            }
        }

        false
    }
}

struct PrivDrop {
    line: usize,
    column: usize,
}
