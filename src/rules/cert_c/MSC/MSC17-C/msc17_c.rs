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

    /// Last non-comment, non-brace statement directly inside a compound
    /// statement — the one whose control flow decides whether the block
    /// terminates the case section.
    fn last_meaningful_child<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut cursor = node.walk();
        let mut last = None;
        for child in node.children(&mut cursor) {
            if !matches!(child.kind(), "{" | "}" | "comment") {
                last = Some(child);
            }
        }
        last
    }

    /// Recognizes a terminating statement, descending into brace-wrapped
    /// case bodies (`case X: { ...; break; }`) and into if/else where every
    /// arm terminates. An `if` with no `else` can fall through either way,
    /// so it is never treated as terminating.
    fn terminates_section(&self, node: &Node) -> bool {
        match node.kind() {
            "break_statement" | "return_statement" | "continue_statement" | "goto_statement" => {
                true
            }
            "compound_statement" => self
                .last_meaningful_child(node)
                .map(|n| self.terminates_section(&n))
                .unwrap_or(false),
            "if_statement" => {
                let (Some(consequence), Some(alternative)) = (
                    node.child_by_field_name("consequence"),
                    node.child_by_field_name("alternative"),
                ) else {
                    return false;
                };
                let alt_stmt = alternative.named_child(0).unwrap_or(alternative);
                self.terminates_section(&consequence) && self.terminates_section(&alt_stmt)
            }
            _ => false,
        }
    }

    fn is_fallthrough_comment(&self, node: &Node, source: &str) -> bool {
        node.kind() == "comment"
            && ast_utils::get_node_text(node, source)
                .to_lowercase()
                .contains("fall")
    }

    /// Non-comment idioms that mark a fallthrough as intentional:
    /// `[[fallthrough]];`/`__attribute__((fallthrough));` (the latter isn't
    /// valid in statement position per the C grammar and surfaces as an
    /// `ERROR` node instead of a clean attribute node, so it's matched on
    /// text), a `FALLTHROUGH()`-style macro call, or a bare marker
    /// identifier such as `deliberate_fall_through;`.
    fn is_fallthrough_marker(&self, node: &Node, source: &str) -> bool {
        fn normalizes_to_fallthrough(name: &str) -> bool {
            let normalized: String = name
                .chars()
                .filter(|c| c.is_ascii_alphabetic())
                .flat_map(|c| c.to_lowercase())
                .collect();
            normalized.contains("fallthrough") || normalized.contains("fallthru")
        }

        match node.kind() {
            "attributed_statement" | "ERROR" => {
                let text = ast_utils::get_node_text(node, source).to_lowercase();
                text.contains("fallthrough") || text.contains("fall_through")
            }
            "expression_statement" => node
                .named_child(0)
                .map(|inner| match inner.kind() {
                    "identifier" => {
                        normalizes_to_fallthrough(&ast_utils::get_node_text(&inner, source))
                    }
                    "call_expression" => inner
                        .child_by_field_name("function")
                        .map(|f| normalizes_to_fallthrough(&ast_utils::get_node_text(&f, source)))
                        .unwrap_or(false),
                    _ => false,
                })
                .unwrap_or(false),
            _ => false,
        }
    }

    /// Walks a switch body (or a `#if`/`#ifdef`/`#elif`/`#else` block nested
    /// directly inside one), transparently descending into preprocessor
    /// conditionals so a `case` label or terminator hidden behind an
    /// `#ifdef` still lands in the right segment instead of being either
    /// missed entirely or tacked onto the previous segment as a bogus
    /// trailing item.
    fn collect_segments<'a>(
        &self,
        container: &Node<'a>,
        segments: &mut Vec<(Node<'a>, Vec<Node<'a>>)>,
    ) {
        let condition_id = container.child_by_field_name("condition").map(|n| n.id());
        let name_id = container.child_by_field_name("name").map(|n| n.id());
        let alternative_id = container.child_by_field_name("alternative").map(|n| n.id());

        let mut cursor = container.walk();
        for child in container.named_children(&mut cursor) {
            if Some(child.id()) == condition_id || Some(child.id()) == name_id {
                continue;
            }
            if Some(child.id()) == alternative_id
                || matches!(
                    child.kind(),
                    "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_else"
                )
            {
                self.collect_segments(&child, segments);
            } else if child.kind() == "case_statement" {
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
        self.collect_segments(&body, &mut segments);

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
            // Skip trailing comments and the stray empty `;` statement that
            // `__attribute__((fallthrough));` leaves behind (the attribute
            // itself parses as a preceding ERROR node, not part of that
            // expression_statement) to find the real trailing marker, if any.
            let marker = items.iter().rev().find(|n| {
                n.kind() != "comment"
                    && !(n.kind() == "expression_statement" && n.named_child(0).is_none())
            });
            let marked_intentional = marker
                .map(|n| {
                    self.is_fallthrough_comment(n, source) || self.is_fallthrough_marker(n, source)
                })
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
