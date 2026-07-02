use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// POS44-C: Do not use signals to terminate threads
///
/// Detects use of pthread_kill() to send signals to threads, which can cause
/// abnormal process termination instead of controlled thread cancellation.
pub struct Pos44C;

impl Pos44C {
    pub fn new() -> Self {
        Self
    }

    /// Check if a call_expression is pthread_kill
    fn is_pthread_kill(node: &Node, source: &str) -> bool {
        if node.kind() != "call_expression" {
            return false;
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" {
                let func_name = get_node_text(&child, source);
                return func_name == "pthread_kill";
            }
        }
        false
    }

    /// Check all nodes recursively for pthread_kill calls
    fn check_node(node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |c| Self::is_pthread_kill(&c, source)) {
            let code = get_node_text(&n, source);
            violations.push(RuleViolation {
                rule_id: "POS44-C".to_string(),
                severity: Severity::Low,
                message: format!(
                    "Use of pthread_kill() detected. Do not use signals to terminate threads as it causes abnormal process termination. Use pthread_cancel() instead. Code: {}",
                    code.trim()
                ),
                file_path: String::new(),
                line: n.start_position().row + 1,
                column: n.start_position().column + 1,
                suggestion: Some(
                    "Replace pthread_kill() with pthread_cancel() for safe thread termination.".to_string()
                ),
                requires_manual_review: None,
            });
        }
    }
}

impl CertRule for Pos44C {
    fn rule_id(&self) -> &'static str {
        "POS44-C"
    }

    fn description(&self) -> &'static str {
        "Do not use signals to terminate threads"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS44-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        Self::check_node(node, source, &mut violations);
        violations
    }
}
