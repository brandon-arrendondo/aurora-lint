//! MSC07-C: Detect and remove code that is never executed
//!
//! Detects unreachable code patterns:
//! 1. Statements after unconditional return in the same block
//! 2. Statements after noreturn function calls (exit, abort, _Exit, longjmp, etc.)
//! 3. Statements after unconditional break/continue/goto in the same block

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Msc07C;

impl Msc07C {
    pub fn new() -> Self {
        Self
    }

    fn walk_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for compound in query::find_descendants_of_kind(*node, "compound_statement") {
            self.check_unreachable_after_terminal(&compound, source, violations);
        }
    }

    /// Scan children of a compound_statement. When we hit a terminal statement
    /// (return, break, continue, goto, or noreturn call), flag all subsequent
    /// non-trivial siblings as unreachable.
    fn check_unreachable_after_terminal(
        &self,
        compound: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut seen_terminal: Option<(&str, usize)> = None; // (kind_label, line)

        for i in 0..compound.child_count() {
            let child = match compound.child(i) {
                Some(c) => c,
                None => continue,
            };

            // Skip braces, comments, and preprocessor directives
            if is_skippable(&child) {
                continue;
            }

            if let Some((terminal_kind, _)) = seen_terminal {
                // This statement is unreachable
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!("Unreachable code after unconditional '{}'.", terminal_kind,),
                    file_path: String::new(),
                    line: child.start_position().row + 1,
                    column: child.start_position().column + 1,
                    suggestion: Some(
                        "Remove the unreachable code or restructure the control flow".to_string(),
                    ),
                    ..Default::default()
                });
                // Only report the first unreachable statement per terminal
                break;
            }

            // Check if this child is a terminal statement
            if let Some(label) = terminal_label(&child, source) {
                seen_terminal = Some((label, child.start_position().row + 1));
            }
        }
    }
}

/// Returns a human-readable label if the node is a terminal (control never
/// passes to the next sibling).
fn terminal_label(node: &Node, source: &str) -> Option<&'static str> {
    match node.kind() {
        "return_statement" => Some("return"),
        "break_statement" => Some("break"),
        "continue_statement" => Some("continue"),
        "goto_statement" => Some("goto"),
        "expression_statement" => {
            if is_noreturn_call(node, source) {
                Some("noreturn function call")
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check if an expression_statement contains a call to a known noreturn function.
fn is_noreturn_call(node: &Node, source: &str) -> bool {
    let expr = match node.child(0) {
        Some(e) => e,
        None => return false,
    };
    if expr.kind() != "call_expression" {
        return false;
    }
    let func = match expr.child_by_field_name("function") {
        Some(f) => f,
        None => return false,
    };
    let name = get_node_text(&func, source);
    matches!(
        name.trim(),
        "exit"
            | "_exit"
            | "_Exit"
            | "abort"
            | "longjmp"
            | "quick_exit"
            | "thrd_exit"
            | "ExitProcess"
            | "ExitThread"
    )
}

/// Nodes that should be skipped when scanning for unreachable code.
fn is_skippable(node: &Node) -> bool {
    matches!(
        node.kind(),
        "{" | "}"
            | "comment"
            | "preproc_ifdef"
            | "preproc_if"
            | "preproc_else"
            | "preproc_elif"
            | "preproc_def"
            | "preproc_include"
            | "preproc_call"
    )
}

impl CertRule for Msc07C {
    fn rule_id(&self) -> &'static str {
        "MSC07-C"
    }

    fn description(&self) -> &'static str {
        "Detect and remove code that is never executed"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MSC07-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.walk_node(node, source, violations);
    }
}
