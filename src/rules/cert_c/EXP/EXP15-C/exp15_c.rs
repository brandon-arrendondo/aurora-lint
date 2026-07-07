//! EXP15-C: Do not place a semicolon on the same line as an if, for, or while statement
//!
//! This rule detects when a semicolon appears on the same line as an if, for, or while
//! statement. This typically indicates a programming error where an empty statement
//! is accidentally created, causing the intended body to execute unconditionally.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! if (a == b); {   // Semicolon on same line - empty statement
//!     doSomething();  // Always executes!
//! }
//!
//! while (condition); {  // Infinite loop with empty body
//!     process();        // Never part of loop!
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! if (a == b) {
//!     doSomething();  // Correctly controlled by if
//! }
//!
//! while (condition) {
//!     process();      // Correctly part of loop
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find if_statement, while_statement, for_statement nodes
//! - Check if condition node ends on same line as a semicolon appears
//! - Report violation if semicolon found on control statement line

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp15C;

impl CertRule for Exp15C {
    fn rule_id(&self) -> &'static str {
        "EXP15-C"
    }

    fn description(&self) -> &'static str {
        "Do not place a semicolon on the same line as an if, for, or while statement"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "EXP15-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Exp15C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kinds(
            *node,
            &["if_statement", "while_statement", "for_statement"],
        ) {
            let statement_type = match n.kind() {
                "if_statement" => "if",
                "while_statement" => "while",
                "for_statement" => "for",
                _ => unreachable!(),
            };
            self.check_control_statement(&n, source, statement_type, violations);
        }
    }

    fn check_control_statement(
        &self,
        node: &Node,
        source: &str,
        statement_type: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if the body of the control statement is an empty statement (just ";").
        // This is the correct signal for EXP15-C — NOT searching for any semicolon on
        // the condition line, which produces false positives for `for` statements because
        // tree-sitter exposes the two clause-separator semicolons as direct children of
        // the for_statement node on the same line as the condition.
        //
        // Note: tree-sitter-c uses "consequence" for if_statement, "body" for while/for.
        let body_field = if statement_type == "if" {
            "consequence"
        } else {
            "body"
        };
        if let Some(body) = node.child_by_field_name(body_field) {
            let is_empty_body = self.is_empty_statement(&body, source);
            if is_empty_body {
                // Suppress for while/for loops that are intentional hardware spin-polls.
                // Key signal: no compound_statement follows immediately as a sibling.
                // When a programmer accidentally semicolons a loop, the intended body
                // `{ ... }` appears as the next sibling (a detached compound_statement).
                // True busy-waits like `while (_txif0 == 0);` have no following block.
                if statement_type == "while" || statement_type == "for" {
                    if !Self::next_sibling_is_compound(node) {
                        return;
                    }
                }

                let start_point = node.start_position();
                let statement_text = get_node_text(node, source);
                let first_line = statement_text.lines().next().unwrap_or(statement_text);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Empty {} body after condition: '{}' - This likely indicates a programming error",
                        statement_type, first_line.trim()
                    ),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "If this is an intentional spin-wait, add a comment inside the braces. Otherwise, remove the semicolon.".to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// Returns true if the immediately next sibling of `node` is a compound_statement.
    /// This detects the "accidental semicolon" pattern:
    ///   `while (cond);`  followed by `{ body }` — the `{ body }` is the detached block.
    fn next_sibling_is_compound(node: &Node) -> bool {
        if let Some(parent) = node.parent() {
            let mut found_self = false;
            for i in 0..parent.child_count() {
                if let Some(child) = parent.child(i) {
                    if found_self {
                        // Skip whitespace/comment nodes
                        if child.kind() == "comment" || child.is_extra() {
                            continue;
                        }
                        return child.kind() == "compound_statement";
                    }
                    if child.id() == node.id() {
                        found_self = true;
                    }
                }
            }
        }
        false
    }

    /// Returns true if `node` represents an empty C statement (bare ";").
    ///
    /// Tree-sitter-c represents `for (...);` with a body whose kind is either
    /// `";"` directly or an `expression_statement` whose full text is just ";".
    fn is_empty_statement(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            ";" => true,
            "expression_statement" => get_node_text(node, source).trim() == ";",
            _ => false,
        }
    }
}
