// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::check_macros::{self, MacroDefinition};
use crate::analyze::context::ProjectContext;
use crate::analyze::control_header_preproc_guard::strip_comments;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::preproc_directive_start;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// Whether `while_node` is the `} while (0)` that closes a `do { ... }` inside
/// a `#define`, not a while statement. tree-sitter ends a macro's
/// `preproc_arg` at a `/* */` comment on a continued line and parses the rest
/// of the body as C (valkey's `ZIP_DECODE_PREVLEN`), which strands the tail
/// with the `do` on the far side of the cut. So the pairing is read from the
/// directive's own text: the `}` right before `while` must close a brace
/// opened by `do`. Anything the scan cannot pair keeps its finding.
fn closes_macro_do_block(while_node: Node, source: &str) -> bool {
    let at = while_node.start_byte();
    let Some(start) = preproc_directive_start(source, at) else {
        return false;
    };
    let text: Vec<u8> = strip_comments(&source[start..at])
        .bytes()
        .filter(|&b| b != b'\\')
        .collect();
    let skip_space = |mut i: usize| {
        while i > 0 && text[i - 1].is_ascii_whitespace() {
            i -= 1;
        }
        i
    };
    let mut i = skip_space(text.len());
    if i == 0 || text[i - 1] != b'}' {
        return false;
    }
    let mut depth = 0usize;
    while i > 0 {
        i -= 1;
        match text[i] {
            b'}' => depth += 1,
            b'{' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            _ => {}
        }
    }
    if depth != 0 {
        return false;
    }
    let end = skip_space(i);
    end >= 2
        && &text[end - 2..end] == b"do"
        && (end == 2 || !(text[end - 3].is_ascii_alphanumeric() || text[end - 3] == b'_'))
}

type Definitions = HashMap<String, Vec<MacroDefinition>>;

/// Every definition of every macro name, and the names some configuration
/// defines differently or not at all: the prescan's tables, and this file's.
struct Macros<'a> {
    project_defs: &'a Definitions,
    project_conditional: &'a HashSet<String>,
    file_defs: Definitions,
    file_conditional: HashSet<String>,
}

impl Macros<'_> {
    fn expands_to_block(&self, name: &str) -> bool {
        check_macros::expands_to_block_everywhere(
            &[self.project_defs, &self.file_defs],
            &[self.project_conditional, &self.file_conditional],
            name,
        )
    }
}

pub struct Exp19C {
    /// The prescan's `macro_definitions` and `conditional_macro_names`;
    /// `check` reads this file's own alongside them.
    project_macros: RefCell<(Arc<Definitions>, Arc<HashSet<String>>)>,
}

impl Exp19C {
    pub fn new() -> Self {
        Self {
            project_macros: RefCell::default(),
        }
    }
}

impl Default for Exp19C {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether `body` is a braced body: a compound statement, or an invocation of
/// a function-like macro, written with no semicolon, that is one `{ ... }`
/// block in every configuration. valkey's `if (c) swapcode(long, a, b, n)
/// else ...` compiles only because the expansion supplies the braces, so the
/// unbraced statement a finding would name is not in the source. Written
/// with its `;` (lua's `for (...) markvalue(g, o);`) the body is, as written,
/// a single unbraced statement, whatever the macro expands to. A macro
/// expanding to anything else — an `if`, a `do { } while (0)` — leaves the
/// body unbraced, and so does one only some build defines: sqlite's `memcpy`
/// is a block under `SQLITE_INLINE_MEMCPY` and the library call everywhere
/// else.
fn is_braced(body: Node, source: &str, macros: &Macros<'_>) -> bool {
    if body.kind() == "compound_statement" {
        return true;
    }
    if body.kind() != "expression_statement" || body.named_child_count() != 1 {
        return false;
    }
    // tree-sitter recovers the absent `;` as a zero-width MISSING node.
    let written_semicolon = (0..body.child_count())
        .filter_map(|i| body.child(i))
        .any(|c| c.kind() == ";" && !c.is_missing());
    if written_semicolon {
        return false;
    }
    let Some(call) = body
        .named_child(0)
        .filter(|c| c.kind() == "call_expression")
    else {
        return false;
    };
    call.child_by_field_name("function")
        .filter(|f| f.kind() == "identifier")
        .and_then(|f| f.utf8_text(source.as_bytes()).ok())
        .is_some_and(|name| macros.expands_to_block(name))
}

impl CertRule for Exp19C {
    fn rule_id(&self) -> &'static str {
        "EXP19-C"
    }

    fn description(&self) -> &'static str {
        "Use braces for the body of an if, for, or while statement"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "EXP19-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_macros.borrow_mut() = (
            context.macro_definitions.clone(),
            context.conditional_macro_names.clone(),
        );
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        let project = self.project_macros.borrow();
        let macros = Macros {
            project_defs: &project.0,
            project_conditional: &project.1,
            file_defs: check_macros::collect_macro_definitions(source),
            file_conditional: check_macros::collect_conditional_macro_names(source),
        };

        // Recursively check for control flow statements without braces
        violations.extend(self.check_node(*node, source, &macros));

        violations
    }
}

impl Exp19C {
    /// Recursively check nodes for control flow statements without compound statement bodies
    fn check_node(&self, node: Node, source: &str, macros: &Macros<'_>) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        for n in query::find_descendants(node, |_| true) {
            // Check if this is a control flow statement that needs braces
            match n.kind() {
                "if_statement" => {
                    if let Some(violation) = self.check_if_statement(n, source, macros) {
                        violations.push(violation);
                    }
                }
                "for_statement" => {
                    if let Some(violation) = self.check_for_statement(n, source, macros) {
                        violations.push(violation);
                    }
                }
                "while_statement" => {
                    if let Some(violation) = self.check_while_statement(n, source, macros) {
                        violations.push(violation);
                    }
                }
                "do_statement" => {
                    if let Some(violation) = self.check_do_statement(n, source, macros) {
                        violations.push(violation);
                    }
                }
                _ => {}
            }
        }

        violations
    }

    /// Check if an if_statement has braces around its body
    fn check_if_statement(
        &self,
        if_node: Node,
        source: &str,
        macros: &Macros,
    ) -> Option<RuleViolation> {
        // Get the consequence (then-branch) of the if statement
        if let Some(consequence) = if_node.child_by_field_name("consequence") {
            // If the consequence is not a compound_statement (braced block), it's a violation
            if !is_braced(consequence, source, macros) {
                return Some(self.create_violation(
                    if_node,
                    "if",
                    "if statement body should be enclosed in braces {}",
                ));
            }
        }

        // Check the else-branch if it exists
        if let Some(alternative) = if_node.child_by_field_name("alternative") {
            // Skip checking if the alternative is another if_statement (else if)
            // We'll check that if_statement separately in recursion
            if alternative.kind() == "if_statement" {
                return None; // else-if chain, will be checked recursively
            }

            // The alternative can be wrapped in an else_clause node in tree-sitter-c
            // We need to check the actual body inside it
            let body_to_check = if alternative.kind() == "else_clause" {
                // Find the actual statement inside the else_clause
                let mut body = None;
                let mut cursor = alternative.walk();
                for child in alternative.children(&mut cursor) {
                    // Skip the "else" keyword and any comment between it and
                    // the statement (`} else /* why */ {`, or sqlite's
                    // `}else` / `#endif` / `/*if( !pIncr->bUseThread )*/{`):
                    // a comment is a node here, and taking it as the body
                    // reported a braced else as unbraced.
                    if child.kind() != "else" && child.kind() != "comment" {
                        body = Some(child);
                        break;
                    }
                }
                body
            } else {
                Some(alternative)
            };

            if let Some(body) = body_to_check {
                // Skip if it's an if_statement (else if case inside else_clause)
                if body.kind() == "if_statement" {
                    return None;
                }
                // Check if the body is a compound_statement (braced block)
                if !is_braced(body, source, macros) {
                    return Some(self.create_violation(
                        if_node,
                        "else",
                        "else statement body should be enclosed in braces {}",
                    ));
                }
            }
        }

        None
    }

    /// Check if a for_statement has braces around its body
    fn check_for_statement(
        &self,
        for_node: Node,
        source: &str,
        macros: &Macros,
    ) -> Option<RuleViolation> {
        if let Some(body) = for_node.child_by_field_name("body") {
            if !is_braced(body, source, macros) {
                return Some(self.create_violation(
                    for_node,
                    "for",
                    "for statement body should be enclosed in braces {}",
                ));
            }
        }

        None
    }

    /// Check if a while_statement has braces around its body
    fn check_while_statement(
        &self,
        while_node: Node,
        source: &str,
        macros: &Macros,
    ) -> Option<RuleViolation> {
        if closes_macro_do_block(while_node, source) {
            return None;
        }
        if let Some(body) = while_node.child_by_field_name("body") {
            if !is_braced(body, source, macros) {
                return Some(self.create_violation(
                    while_node,
                    "while",
                    "while statement body should be enclosed in braces {}",
                ));
            }
        }

        None
    }

    /// Check if a do_statement has braces around its body
    fn check_do_statement(
        &self,
        do_node: Node,
        source: &str,
        macros: &Macros,
    ) -> Option<RuleViolation> {
        if let Some(body) = do_node.child_by_field_name("body") {
            if !is_braced(body, source, macros) {
                return Some(self.create_violation(
                    do_node,
                    "do-while",
                    "do-while statement body should be enclosed in braces {}",
                ));
            }
        }

        None
    }

    /// Create a rule violation for a control flow statement without braces
    fn create_violation(
        &self,
        statement_node: Node,
        statement_type: &str,
        message: &str,
    ) -> RuleViolation {
        let suggestion = format!(
            "Add braces around the {} statement body: {} {{ /* body */ }}",
            statement_type, statement_type
        );

        RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: message.to_string(),
            file_path: String::new(),
            line: statement_node.start_position().row + 1,
            column: statement_node.start_position().column + 1,
            suggestion: Some(suggestion),
            ..Default::default()
        }
    }
}
