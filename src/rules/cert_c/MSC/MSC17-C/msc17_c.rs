// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! MSC17-C: Finish every set of statements associated with a case label with
//! a break statement
//!
//! A `case` section that doesn't end in `break`/`return`/`continue`/`goto`
//! falls through into the next case, silently, with no compiler diagnostic.
//! This rule flags any non-empty case section that falls through to the next
//! label without one of those terminating statements and without a trailing
//! comment marking the fallthrough as intentional (the wiki's own
//! convention: `/* ... fall through ... */`). An empty section (grouping
//! case labels with no code between them, e.g. `case A: case B:`) is never
//! flagged, and the final section of the switch is never flagged (falling
//! out of the switch is normal control flow, not a fallthrough).
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/MSC17-C.+Finish+every+set+of+statements+associated+with+a+case+label+with+a+break+statement

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Msc17C;

impl Msc17C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Msc17C
    }

    /// Items belonging to one case section, in source order.
    fn case_body_items<'a>(&self, case_stmt: &Node<'a>) -> Vec<Node<'a>> {
        let mut items = Vec::new();
        let mut past_colon = false;
        for i in 0..case_stmt.child_count() {
            if let Some(child) = case_stmt.child(i) {
                if past_colon {
                    items.push(child);
                } else if child.kind() == ":" {
                    past_colon = true;
                }
            }
        }
        items
    }

    fn terminates_section(&self, node: &Node) -> bool {
        matches!(
            node.kind(),
            "break_statement" | "return_statement" | "continue_statement" | "goto_statement"
        )
    }

    fn is_fallthrough_comment(&self, node: &Node, source: &str) -> bool {
        node.kind() == "comment"
            && ast_utils::get_node_text(node, source)
                .to_lowercase()
                .contains("fall")
    }

    fn check_switch(&self, switch_stmt: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let Some(body) = switch_stmt.child_by_field_name("body") else {
            return;
        };
        if body.kind() != "compound_statement" {
            return;
        }

        // Each segment: (label node, ordered items belonging to that case).
        let mut segments: Vec<(Node, Vec<Node>)> = Vec::new();

        let mut cursor = body.walk();
        for child in body.children(&mut cursor) {
            if child.kind() == "{" || child.kind() == "}" {
                continue;
            }
            if child.kind() == "case_statement" {
                let items = self.case_body_items(&child);
                segments.push((child, items));
            } else if let Some(last) = segments.last_mut() {
                // A statement/comment directly following a case_statement
                // sibling (tree-sitter only nests trailing content into the
                // case_statement node when a real statement follows the
                // label; a label with only a following comment leaves that
                // comment as a sibling instead) belongs to the same section.
                last.1.push(child);
            }
        }

        for i in 0..segments.len() {
            let is_last_segment = i + 1 == segments.len();
            if is_last_segment {
                continue;
            }
            let (label, items) = &segments[i];
            if items.is_empty() {
                continue;
            }
            let last_non_comment = items.iter().rev().find(|n| n.kind() != "comment");
            let terminated = last_non_comment
                .map(|n| self.terminates_section(n))
                .unwrap_or(false);
            if terminated {
                continue;
            }
            let marked_intentional = items
                .last()
                .map(|n| self.is_fallthrough_comment(n, source))
                .unwrap_or(false);
            if marked_intentional {
                continue;
            }

            let pos = label.start_position();
            violations.push(RuleViolation {
                rule_id: "MSC17-C".to_string(),
                severity: Severity::Medium,
                line: pos.row + 1,
                column: pos.column + 1,
                message: "case section falls through to the next label with no break/return/continue/goto and no comment marking it intentional".to_string(),
                file_path: String::new(),
                suggestion: Some(
                    "Add a break statement, or a comment such as \"/* fall through */\" if the fallthrough is intentional".to_string(),
                ),
                requires_manual_review: Some(false),
            });
        }
    }

    fn traverse(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for switch_stmt in query::find_descendants_of_kind(*root, "switch_statement") {
            self.check_switch(&switch_stmt, source, violations);
        }
    }
}

impl CertRule for Msc17C {
    fn rule_id(&self) -> &'static str {
        "MSC17-C"
    }

    fn description(&self) -> &'static str {
        "Finish every set of statements associated with a case label with a break statement"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "MSC17-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
