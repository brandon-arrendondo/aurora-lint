// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MSC01-C: Strive for logical completeness
//!
//! Software vulnerabilities can result when a programmer fails to consider
//! all possible data states. This rule targets the two concrete, statically
//! checkable shapes of that mistake shown in the wiki's own examples:
//!
//!   - an if / else-if chain with no final, unconditional `else` -- there is
//!     no code path handling the case where none of the conditions hold
//!   - a `switch` on a non-exhaustive value (any switch not covering every
//!     enumerator is potentially non-exhaustive) with no `default` label and
//!     no fallback statement after the switch in the same block -- an
//!     unanticipated value falls through with no handling at all
//!
//! CERT C reference:
//! <https://wiki.sei.cmu.edu/confluence/display/c/MSC01-C.+Strive+for+logical+completeness>

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::next_code_offset;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Msc01C;

/// `text` begins with `keyword` as a whole word: `else`, not `elsewhere`.
fn starts_with_keyword(text: &str, keyword: &str) -> bool {
    text.strip_prefix(keyword).is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
    })
}

/// The `if_statement` that begins at byte `start` in the tree holding `node`.
fn if_statement_at<'t>(node: &Node<'t>, start: usize) -> Option<Node<'t>> {
    let mut root = *node;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    let mut candidate = root.descendant_for_byte_range(start, start + "if".len())?;
    loop {
        if candidate.start_byte() != start {
            return None;
        }
        if candidate.kind() == "if_statement" {
            return Some(candidate);
        }
        candidate = candidate.parent()?;
    }
}

impl Msc01C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc01C
    }

    /// Walk an if / else-if chain. A bare `if` with no `else` at the bottom of
    /// a chain (reached only via else-if recursion) is flagged: the case where
    /// none of the conditions hold is unhandled. A standalone `if` with no
    /// else at all (not part of any chain) is an ordinary guard clause and is
    /// never reached here, since callers only recurse into else-if bodies.
    ///
    /// `reported` holds the start byte of every tail already flagged: a chain
    /// split across directives is walked both from its first fragment and from
    /// each later fragment's own top-level `if`, and must be reported once.
    fn check_missing_final_else(
        &self,
        if_stmt: &Node,
        is_continuation: bool,
        source: &str,
        reported: &mut HashSet<usize>,
        violations: &mut Vec<RuleViolation>,
    ) {
        match if_stmt.child_by_field_name("alternative") {
            None => {
                // The chain can continue in the source but out of the tree:
                // an `else` cannot begin a block item, so one that follows a
                // directive (`#endif` / `else {`, an `#ifdef` whose arms each
                // hold their own `else {`, or `else` / `#endif` / `#ifdef Y` /
                // `if (...)`) is left unattached. Read past comments and
                // directive lines for it. A final `else` ends the chain; an
                // `else if` continues it, and the tail that decides the
                // finding is wherever the text ends (hostap's `#ifdef`-spliced
                // key-management chains, curl timeval.c).
                if let Some(i) = next_code_offset(source, if_stmt.end_byte())
                    .filter(|&i| starts_with_keyword(&source[i..], "else"))
                {
                    match next_code_offset(source, i + "else".len()) {
                        Some(j) if starts_with_keyword(&source[j..], "if") => {
                            if let Some(next_if) = if_statement_at(if_stmt, j) {
                                self.check_missing_final_else(
                                    &next_if, true, source, reported, violations,
                                );
                                return;
                            }
                            // The continuing `if` did not parse as one; judge
                            // this link as the tail, as before.
                        }
                        _ => return,
                    }
                }
                // A bare `if` with no `else` is only a violation when it's
                // the tail of an else-if chain; a standalone guard clause
                // (is_continuation == false) is not what this rule targets.
                if !is_continuation || !reported.insert(if_stmt.start_byte()) {
                    return;
                }
                let pos = if_stmt.start_position();
                violations.push(RuleViolation {
                    rule_id: "MSC01-C".to_string(),
                    severity: Severity::Medium,
                    line: pos.row + 1,
                    column: pos.column + 1,
                    message: "if / else-if chain has no final else clause -- the case where none of the conditions hold is unhandled".to_string(),
                    file_path: String::new(),
                    suggestion: Some("Add a final else clause to handle the case where none of the preceding conditions hold".to_string()),
                    requires_manual_review: Some(false),
                });
            }
            Some(alternative) => {
                // Skip a comment between `else` and its statement, or
                // `else /* ... */ if` ends the walk as if it were a final else.
                let mut cursor = alternative.walk();
                let else_body = alternative
                    .named_children(&mut cursor)
                    .find(|n| n.kind() != "comment");
                if let Some(else_body) = else_body {
                    if else_body.kind() == "if_statement" {
                        self.check_missing_final_else(
                            &else_body, true, source, reported, violations,
                        );
                    }
                }
            }
        }
    }

    fn check_switch(&self, switch_stmt: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let Some(body) = switch_stmt.child_by_field_name("body") else {
            return;
        };
        let has_default = query::find_first_descendant(body, |n| n.kind() == "default").is_some();
        if has_default {
            return;
        }

        // A switch missing `default` is only a violation if it's the last
        // statement in its enclosing block -- i.e. there is no fallback
        // statement handling the unaccounted-for case afterward.
        let Some(parent) = switch_stmt.parent() else {
            return;
        };
        if parent.kind() != "compound_statement" {
            return;
        }
        let mut cursor = parent.walk();
        let siblings: Vec<Node> = parent
            .named_children(&mut cursor)
            .filter(|n| n.kind() != "comment")
            .collect();
        if siblings.last() != Some(switch_stmt) {
            return;
        }

        let _ = source;
        let pos = switch_stmt.start_position();
        violations.push(RuleViolation {
            rule_id: "MSC01-C".to_string(),
            severity: Severity::Medium,
            line: pos.row + 1,
            column: pos.column + 1,
            message: "switch statement has no default label and no fallback statement follows it -- an unanticipated value is silently unhandled".to_string(),
            file_path: String::new(),
            suggestion: Some("Add a default label, or a fallback statement after the switch, to handle values not covered by the existing case labels".to_string()),
            requires_manual_review: Some(false),
        });
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut reported = HashSet::new();
        for if_stmt in query::find_descendants_of_kind(*root, "if_statement") {
            // Only start a chain check from a top-level `if` (not one that is
            // itself the else-if continuation of another if_statement), to
            // avoid checking -- and reporting on -- the same chain repeatedly.
            let is_else_if = if_stmt
                .parent()
                .map(|p| p.kind() == "else_clause")
                .unwrap_or(false);
            if is_else_if {
                continue;
            }
            self.check_missing_final_else(&if_stmt, false, source, &mut reported, violations);
        }

        for switch_stmt in query::find_descendants_of_kind(*root, "switch_statement") {
            self.check_switch(&switch_stmt, source, violations);
        }
    }
}

impl CertRule for Msc01C {
    fn rule_id(&self) -> &'static str {
        "MSC01-C"
    }

    fn description(&self) -> &'static str {
        "Strive for logical completeness"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "MSC01-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
