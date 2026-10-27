// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::check_macros::{self, MacroDefinition};
use crate::analyze::context::ProjectContext;
use crate::analyze::control_header_preproc_guard::strip_comments;
use crate::manifest::Severity;
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

/// When `body` is the empty statement tree-sitter recovers for a control
/// statement whose real body comes through the `#if` chain that follows it:
///
/// ```c
/// if (x)
/// #ifdef A
///     { a(); }
/// #else
///     { b(); }
/// #endif
/// ```
///
/// `preproc_if` is a block item, not a statement, so the chain parses as the
/// statement's next SIBLING and the statement gets a zero-width
/// `(expression_statement (MISSING ";"))` body. Every configuration picks one
/// arm, and the first statement in it is the body; an arm with none, or a
/// chain with no `#else`, gives some configuration whatever follows the
/// `#endif`. So the chain and what follows it are read as
/// [`first_statement`] reads them: braced when every configuration's body
/// is, nested chains included, and one unbraced arm keeps the finding
/// (ADR-0010).
/// The `#if`/`#ifdef` chain that holds `statement`'s body, when `body` is
/// the empty statement tree-sitter recovers for one (see [`Site`]).
fn arm_chain<'t>(statement: Node<'t>, body: Node<'t>) -> Option<Node<'t>> {
    let recovered = body.kind() == "expression_statement"
        && body.named_child_count() == 0
        && (0..body.child_count())
            .filter_map(|i| body.child(i))
            .all(|c| c.is_missing());
    if !recovered {
        return None;
    }
    // The chain follows the outermost statement that ends where the body
    // does: `for (...) if (x)` hands the `for` the `if`, and the chain comes
    // after both.
    let mut item = statement;
    let chain = loop {
        let mut next = item.next_named_sibling();
        while let Some(n) = next.filter(|n| n.kind() == "comment") {
            next = n.next_named_sibling();
        }
        if let Some(next) = next {
            break next;
        }
        match item.parent() {
            Some(parent)
                if parent.end_byte() == item.end_byte()
                    && parent.kind().ends_with("_statement") =>
            {
                item = parent
            }
            _ => return None,
        }
    };
    matches!(chain.kind(), "preproc_if" | "preproc_ifdef").then_some(chain)
}

/// What one arm of an `#if` chain holds, comments aside, and the arm after
/// it.
fn arm_items(arm: Node) -> (Vec<Node>, Option<Node>) {
    let mut cursor = arm.walk();
    let mut held = Vec::new();
    let mut alternative = None;
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            match cursor.field_name() {
                Some("alternative") => alternative = Some(child),
                Some("name") | Some("condition") => {}
                _ if child.is_named() && child.kind() != "comment" => held.push(child),
                _ => {}
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    (held, alternative)
}

/// What a run of block items gives a body that comes through `#if` arms.
enum Site<'t> {
    /// An unbraced statement: the body in some configuration.
    Unbraced(Node<'t>),
    /// A braced statement ends the run.
    Braced,
    /// Directives and comments only, so the body is whatever follows.
    Nothing,
}

/// The first statement in `items`, read as a configuration reads them:
/// directives and comments are skipped, and a nested `#if` chain is looked
/// into and passed over when no arm of it holds a statement.
fn first_statement<'t>(
    items: impl Iterator<Item = Node<'t>>,
    source: &str,
    macros: &Macros<'_>,
) -> Site<'t> {
    for item in items {
        match item.kind() {
            "comment" => {}
            "preproc_if" | "preproc_ifdef" => match chain_site(item, source, macros) {
                Site::Nothing => {}
                site => return site,
            },
            kind if kind.starts_with("preproc_") => {}
            _ if is_braced(item, source, macros) => return Site::Braced,
            _ => return Site::Unbraced(item),
        }
    }
    Site::Nothing
}

/// The first unbraced statement any arm of `chain` holds. Braced when
/// every arm, `#else` included, holds a braced one first; otherwise nothing,
/// and the body follows the `#endif`.
fn chain_site<'t>(chain: Node<'t>, source: &str, macros: &Macros<'_>) -> Site<'t> {
    let mut every_arm_braced = true;
    let mut arm = chain;
    loop {
        let (held, alternative) = arm_items(arm);
        match first_statement(held.into_iter(), source, macros) {
            Site::Unbraced(statement) => return Site::Unbraced(statement),
            Site::Braced => {}
            Site::Nothing => every_arm_braced = false,
        }
        match alternative {
            Some(next) => arm = next,
            None => {
                return if every_arm_braced && arm.kind() == "preproc_else" {
                    Site::Braced
                } else {
                    Site::Nothing
                };
            }
        }
    }
}

/// Where a finding for `statement`'s `body` goes, or `None` when the body is
/// braced in every configuration. A body that comes through an `#if` chain
/// is read with the chain (see [`Site`]) and reported at the first unbraced
/// statement it can be, never a directive. So is the zero-width body of an
/// `if` split across arms, and the body an `if` takes from across an
/// `#else` (see [`crosses_an_arm`]), both read after the chain's `#endif`.
/// A body with no statement to name falls back to `keyword`.
fn judge<'t>(
    statement: Node<'t>,
    body: Node<'t>,
    keyword: Node<'t>,
    source: &str,
    macros: &Macros<'_>,
) -> Option<Node<'t>> {
    if is_braced(body, source, macros) {
        return None;
    }
    let site = if let Some(chain) = arm_chain(statement, body) {
        first_statement(
            std::iter::successors(Some(chain), |n| n.next_named_sibling()),
            source,
            macros,
        )
    } else if body.start_byte() == body.end_byte() || crosses_an_arm(body, source) {
        after_enclosing_chain(statement, source, macros).unwrap_or(Site::Nothing)
    } else {
        return Some(body);
    };
    match site {
        Site::Unbraced(statement) => Some(statement),
        Site::Braced => None,
        Site::Nothing => Some(keyword),
    }
}

/// Whether `body` is one a statement takes from another arm: the parse
/// turns the `#else` between them into an ERROR and hands the first arm's
/// `if` the next arm's `if` as its body, which no configuration has.
///
/// ```c
/// #ifdef A
///     if (a && b)
/// #else
///     if (a)
/// #endif
///         return 1;
/// ```
fn crosses_an_arm(body: Node, source: &str) -> bool {
    let mut previous = body.prev_named_sibling();
    while let Some(p) = previous.filter(|p| p.kind() == "comment") {
        previous = p.prev_named_sibling();
    }
    previous.is_some_and(|p| {
        p.is_error()
            && (0..p.named_child_count())
                .filter_map(|i| p.named_child(i))
                .filter(|c| c.kind() == "preproc_directive")
                .filter_map(|c| c.utf8_text(source.as_bytes()).ok())
                .any(|d| d.starts_with("#else") || d.starts_with("#elif"))
    })
}

/// What follows the `#endif` of the chain whose arm `statement` ends, read
/// as [`first_statement`] reads it, for an `if` split across arms:
///
/// ```c
/// #ifdef A
///     if (a && b)
/// #else
///     if (a)
/// #endif
///         return 1;
/// ```
///
/// Each arm's `if` gets a zero-width body, or the next arm's `if`, and the
/// `return` after the chain is the body in every configuration.
fn after_enclosing_chain<'t>(
    statement: Node<'t>,
    source: &str,
    macros: &Macros<'_>,
) -> Option<Site<'t>> {
    let mut item = statement;
    let mut arm = loop {
        let parent = item.parent()?;
        if parent.kind().ends_with("_statement") && parent.end_byte() == item.end_byte() {
            item = parent;
        } else {
            break parent;
        }
    };
    let mut next = item.next_named_sibling();
    while let Some(n) = next.filter(|n| n.kind() == "comment") {
        next = n.next_named_sibling();
    }
    if next.is_some_and(|n| {
        !matches!(
            n.kind(),
            "preproc_else" | "preproc_elif" | "preproc_elifdef"
        )
    }) {
        return None;
    }
    while matches!(
        arm.kind(),
        "preproc_else" | "preproc_elif" | "preproc_elifdef"
    ) {
        arm = arm.parent()?;
    }
    if !matches!(arm.kind(), "preproc_if" | "preproc_ifdef") {
        return None;
    }
    let following = std::iter::successors(arm.next_named_sibling(), |n| n.next_named_sibling());
    Some(first_statement(following, source, macros))
}

/// The `do` keyword and the block items between it and `while_node`, when
/// the parse has split a `do` statement whose body comes through an `#if`
/// chain:
///
/// ```c
/// do
/// #ifdef A
/// #pragma once
/// #endif
///     x--;
/// while (x);
/// ```
///
/// The `do` becomes an ERROR of its own and `while (x);` a while statement
/// with an empty body, which no configuration has. The items between them
/// are the `do` statement's body.
fn split_do<'t>(while_node: Node<'t>) -> Option<(Node<'t>, Vec<Node<'t>>)> {
    let body = while_node.child_by_field_name("body")?;
    let empty = body.kind() == "expression_statement"
        && body.named_child_count() == 0
        && body.start_byte() != body.end_byte();
    if !empty {
        return None;
    }
    let mut items: Vec<Node> = Vec::new();
    let mut previous = while_node.prev_named_sibling();
    while let Some(p) = previous {
        if p.is_error() {
            let is_do = p.child_count() == 1 && p.child(0).is_some_and(|c| c.kind() == "do");
            if !is_do {
                return None;
            }
            items.reverse();
            // A `do` body is one statement, so anything more between the
            // `do` and the `while` is not this statement's.
            let statements = items
                .iter()
                .filter(|n| n.kind() != "comment" && !n.kind().starts_with("preproc_"))
                .count();
            return (statements <= 1).then_some((p, items));
        }
        items.push(p);
        previous = p.prev_named_sibling();
    }
    None
}

impl CertRule for Exp19C {
    fn reads_header_facts(&self) -> bool {
        true
    }

    fn rule_id(&self) -> &'static str {
        "EXP19-C"
    }

    fn description(&self) -> &'static str {
        "Use braces for the body of an if, for, or while statement"
    }

    fn severity(&self) -> Severity {
        Severity::Low
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

        // An `if` split across arms has one `if` per arm, and each names the
        // same body after the `#endif`: one unbraced statement, which one
        // pair of braces fixes in every configuration, so one finding.
        let mut seen = HashSet::new();
        violations.retain(|v| seen.insert((v.line, v.column, v.message.clone())));
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
                    violations.extend(self.check_if_statement(n, source, macros));
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

    /// Check that each arm of an if_statement has braces around its body.
    /// Both arms are read, since an unbraced `if` does not excuse its
    /// `else`. Each finding is at the body it names, so an `if` and its
    /// `else` written on one line still get two keys (a null body,
    /// `else ;`, is at its `;`).
    fn check_if_statement(
        &self,
        if_node: Node,
        source: &str,
        macros: &Macros,
    ) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Get the consequence (then-branch) of the if statement
        if let Some(consequence) = if_node.child_by_field_name("consequence") {
            // If the consequence is not a compound_statement (braced block), it's a violation
            if let Some(site) = judge(if_node, consequence, if_node, source, macros) {
                violations.push(self.create_violation(
                    site,
                    "if",
                    "if statement body should be enclosed in braces {}",
                ));
            }
        }

        // Check the else-branch if it exists
        let Some(alternative) = if_node.child_by_field_name("alternative") else {
            return violations;
        };
        // The alternative can be wrapped in an else_clause node in tree-sitter-c
        // We need to check the actual body inside it
        let body = if alternative.kind() == "else_clause" {
            // Find the actual statement inside the else_clause
            let mut cursor = alternative.walk();
            let body = alternative.children(&mut cursor).find(|child| {
                // Skip the "else" keyword and any comment between it and
                // the statement (`} else /* why */ {`, or sqlite's
                // `}else` / `#endif` / `/*if( !pIncr->bUseThread )*/{`):
                // a comment is a node here, and taking it as the body
                // reported a braced else as unbraced.
                child.kind() != "else" && child.kind() != "comment"
            });
            body
        } else {
            Some(alternative)
        };

        // An `else if` is an if_statement of its own, checked when the walk
        // reaches it.
        if let Some(body) = body.filter(|b| b.kind() != "if_statement") {
            // Check if the body is a compound_statement (braced block)
            if let Some(site) = judge(if_node, body, alternative, source, macros) {
                violations.push(self.create_violation(
                    site,
                    "else",
                    "else statement body should be enclosed in braces {}",
                ));
            }
        }

        violations
    }

    /// Check if a for_statement has braces around its body, reported at
    /// the body like an if's arms.
    fn check_for_statement(
        &self,
        for_node: Node,
        source: &str,
        macros: &Macros,
    ) -> Option<RuleViolation> {
        if let Some(body) = for_node.child_by_field_name("body") {
            if let Some(site) = judge(for_node, body, for_node, source, macros) {
                return Some(self.create_violation(
                    site,
                    "for",
                    "for statement body should be enclosed in braces {}",
                ));
            }
        }

        None
    }

    /// Check if a while_statement has braces around its body, reported at
    /// the body like an if's arms.
    fn check_while_statement(
        &self,
        while_node: Node,
        source: &str,
        macros: &Macros,
    ) -> Option<RuleViolation> {
        if closes_macro_do_block(while_node, source) {
            return None;
        }
        if let Some((do_keyword, body)) = split_do(while_node) {
            return match first_statement(body.into_iter(), source, macros) {
                Site::Unbraced(_) => Some(self.create_violation(
                    do_keyword,
                    "do-while",
                    "do-while statement body should be enclosed in braces {}",
                )),
                Site::Braced | Site::Nothing => None,
            };
        }
        if let Some(body) = while_node.child_by_field_name("body") {
            if let Some(site) = judge(while_node, body, while_node, source, macros) {
                return Some(self.create_violation(
                    site,
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
