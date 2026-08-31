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

    /// The real last child of `node` — a comment included, unlike
    /// [`Self::last_meaningful_child`] — descending into a brace-wrapped case
    /// body (`case X: { stmt(); /* marker */ }`) so a marker comment sitting
    /// just inside the closing brace is still found. Terminator checking
    /// must ignore trailing comments (a comment can't terminate control
    /// flow), but marker checking is exactly the opposite: the comment *is*
    /// the thing being looked for, and it's as valid inside a brace-wrapped
    /// section as directly in the switch body.
    /// True for a bare `;` parsed as its own `expression_statement` with no
    /// content — either a stray empty statement written as-is (`case X: {
    /// ...; break; };`, legal but pointless C) or the artifact a no-
    /// semicolon marker macro invocation (`__attribute__((fallthrough));`,
    /// `deliberate_fall_through`) leaves behind. Never itself a terminator
    /// or a marker, so both the terminator check and the marker search skip
    /// past it to find the real last item.
    fn is_stray_empty_statement(node: &Node) -> bool {
        node.kind() == "expression_statement" && node.named_child(0).is_none()
    }

    fn last_child_including_comment<'a>(&self, node: &Node<'a>) -> Node<'a> {
        if node.kind() == "compound_statement" {
            let mut cursor = node.walk();
            let mut last = None;
            for child in node.children(&mut cursor) {
                // `;` (a stray/MISSING bare terminator, e.g. the one a
                // no-semicolon macro-invocation marker such as
                // `deliberate_fall_through` leaves behind once tree-sitter
                // recovers) isn't the marker; skip past it to the real one.
                if !matches!(child.kind(), "{" | "}" | ";") {
                    last = Some(child);
                }
            }
            if let Some(l) = last {
                return self.last_child_including_comment(&l);
            }
        }
        *node
    }

    /// Recognizes a terminating statement, descending into brace-wrapped
    /// case bodies (`case X: { ...; break; }`), into if/else where every
    /// arm terminates, and into a `#if`/`#ifdef`/`#elif` chain where every
    /// arm (including a mandatory `#else`) terminates — same rule as
    /// if/else, since a case section hidden behind a conditional that
    /// *can* compile away with no `#else` can fall through either way. An
    /// `if` with no `else`, or a `#if`/`#ifdef` with no `#else`, is
    /// therefore never treated as terminating (task 633).
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
            "preproc_if" | "preproc_ifdef" | "preproc_elif" => {
                let Some(alternative) = node.child_by_field_name("alternative") else {
                    return false;
                };
                self.last_meaningful_preproc_body_child(node)
                    .map(|n| self.terminates_section(&n))
                    .unwrap_or(false)
                    && self.terminates_section(&alternative)
            }
            "preproc_else" => self
                .last_meaningful_preproc_body_child(node)
                .map(|n| self.terminates_section(&n))
                .unwrap_or(false),
            _ => false,
        }
    }

    /// Last non-comment child of a `#if`/`#ifdef`/`#elif`/`#else` node that
    /// is part of its own branch body — i.e. not its `condition`/`name`
    /// field or its `alternative` (the next `#elif`/`#else` in the chain).
    fn last_meaningful_preproc_body_child<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let condition_id = node.child_by_field_name("condition").map(|n| n.id());
        let name_id = node.child_by_field_name("name").map(|n| n.id());
        let alternative_id = node.child_by_field_name("alternative").map(|n| n.id());
        let mut cursor = node.walk();
        let mut last = None;
        for child in node.named_children(&mut cursor) {
            let id = Some(child.id());
            if id == condition_id || id == name_id || id == alternative_id {
                continue;
            }
            if child.kind() == "comment" {
                continue;
            }
            last = Some(child);
        }
        last
    }

    /// Wording (beyond "fall[ ]through") that documents *why* a case section
    /// has no `break`, without using the word "fall" at all: either the
    /// preceding call is `noreturn`-shaped (control never reaches a
    /// fallthrough, e.g. pure-ftpd's `help(); /* doesn't return */`), or the
    /// comment names the missing break directly (sqlite's
    /// `/* no break */ deliberate_fall_through`). Same intent as a
    /// fallthrough comment either way — telling the reader the missing
    /// break is deliberate and verified.
    const INTENTIONAL_NO_BREAK_PHRASES: [&'static str; 4] = [
        "doesn't return",
        "does not return",
        "never returns",
        "no break",
    ];

    fn is_fallthrough_comment(&self, node: &Node, source: &str) -> bool {
        if node.kind() != "comment" {
            return false;
        }
        let text = ast_utils::get_node_text(node, source).to_lowercase();
        text.contains("fall")
            || Self::INTENTIONAL_NO_BREAK_PHRASES
                .iter()
                .any(|p| text.contains(p))
    }

    /// Non-comment idioms that mark a fallthrough as intentional:
    /// `[[fallthrough]];`/`__attribute__((fallthrough));` (the latter isn't
    /// valid in statement position per the C grammar and surfaces as an
    /// `ERROR` node instead of a clean attribute node, so it's matched on
    /// text), a `FALLTHROUGH()`-style macro call, or a bare marker
    /// identifier such as `deliberate_fall_through;`. A marker macro used
    /// with no trailing `;` in the source (because its own expansion
    /// supplies one, e.g. sqlite's `#define deliberate_fall_through
    /// __attribute__((fallthrough));`) doesn't parse as a statement at all —
    /// tree-sitter recovers it as a bare `type_identifier`.
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
            "type_identifier" | "identifier" => {
                normalizes_to_fallthrough(&ast_utils::get_node_text(node, source))
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
        source: &str,
        segments: &mut Vec<(Node<'a>, Vec<Node<'a>>)>,
    ) {
        let condition_id = container.child_by_field_name("condition").map(|n| n.id());
        let name_id = container.child_by_field_name("name").map(|n| n.id());
        let alternative_id = container.child_by_field_name("alternative").map(|n| n.id());

        // True right after a nested `#if`/`#ifdef`/`#elif`/`#else` branch has
        // just been fully walked. A comment sitting there in the source is
        // conventionally the `#endif`'s own name annotation (`#endif /* FOO
        // */`), not a fallthrough marker for whatever case happened to be
        // last inside that branch — attaching it anyway made an unrelated
        // trailing `#endif` comment shadow (or fabricate) a case's real
        // marker, e.g. hostap's `case WLAN_AUTH_EPPKE:` (truly empty,
        // grouped across an `#ifdef` into the next case) picking up
        // `/* CONFIG_ENC_ASSOC */` as if it were content. But lua's
        // `#endif` / `/* FALLTHROUGH */` / `default:` shows the position can
        // also carry a genuine marker for the case *before* the `#ifdef`
        // block — so only a non-marker comment in this position is dropped;
        // an actual fallthrough/noreturn comment still attaches normally.
        let mut just_closed_preproc_branch = false;

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
                self.collect_segments(&child, source, segments);
                just_closed_preproc_branch = true;
            } else if child.kind() == "case_statement" {
                let items = self.case_body_items(&child);
                segments.push((child, items));
                just_closed_preproc_branch = false;
            } else if just_closed_preproc_branch
                && child.kind() == "comment"
                && !self.is_fallthrough_comment(&child, source)
            {
                // Drop the `#endif` annotation comment rather than attaching
                // it to whatever segment the branch just populated.
            } else if let Some(last) = segments.last_mut() {
                // A statement/comment directly following a case_statement
                // sibling (tree-sitter only nests trailing content into the
                // case_statement node when a real statement follows the
                // label; a label with only a following comment leaves that
                // comment as a sibling instead) belongs to the same section.
                last.1.push(child);
                just_closed_preproc_branch = false;
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
        self.collect_segments(&body, source, &mut segments);

        for i in 0..segments.len() {
            let is_last_segment = i + 1 == segments.len();
            if is_last_segment {
                continue;
            }
            let (label, items) = &segments[i];
            // A section with no *executable* content is an empty grouped
            // case label (`case A: case B: stmt; break;`), which CERT
            // explicitly permits — regardless of whether a comment (of any
            // wording) sits between the labels. A comment is not a
            // statement, so a section containing only comments has exactly
            // as much "code" as one containing nothing at all.
            let has_code = items.iter().any(|n| n.kind() != "comment");
            if !has_code {
                continue;
            }
            // Skip both comments and a stray empty `;` statement -- e.g. the
            // trailing semicolon on `case X: { ...; break; };` (legal but
            // pointless C; the compound_statement is a complete statement on
            // its own) parses as its own `expression_statement` sibling
            // *after* the compound_statement, not inside it. Counting it as
            // "the last item" would make the real terminator (the `break;`
            // inside the braces) invisible to `terminates_section`.
            let last_non_comment = items
                .iter()
                .rev()
                .find(|n| !Self::is_stray_empty_statement(n) && n.kind() != "comment");
            let terminated = last_non_comment
                .map(|n| self.terminates_section(n))
                .unwrap_or(false);
            if terminated {
                continue;
            }
            // Skip only the stray empty `;` statement (not a comment) to
            // find the real trailing marker, if any -- a trailing comment
            // (the common case) must NOT be skipped past, since the comment
            // itself is the marker.
            let marker = items
                .iter()
                .rev()
                .find(|n| !Self::is_stray_empty_statement(n))
                .map(|n| self.last_child_including_comment(n));
            let marked_intentional = marker
                .map(|n| {
                    self.is_fallthrough_comment(&n, source)
                        || self.is_fallthrough_marker(&n, source)
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
