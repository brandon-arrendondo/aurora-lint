// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! The last plain write to an lvalue, by its spelling, before a point in a
//! function: which value of a variable a site sees, told apart by the write
//! that produced it.
//!
//! The match is by spelling, not by binding: a shadowing declaration of the
//! same name counts as a write to it. That is enough to tell apart sites
//! that see different values, for de-duplication, which is what
//! [`LastWrites`] is for. It must never decide on its own whether to
//! report: what an occurrence or a write refers to comes from
//! `ast_utils::resolve_identifier_declarator` and its neighbours (ADR-0006).
//!
//! A write is a `=` assignment whose left side is spelled `name`, or the
//! declarator that initializes `name`. A compound assignment (`p += n`)
//! derives from the value already there, so it starts no new value.
//!
//! [`last_write_before`] walks the function body once per question.
//! [`LastWrites`] answers the byte-order question for every site of a
//! function from one walk per name, for a caller that asks at each site: a
//! walk per site is quadratic in the function's length.

use super::ast_utils;
use std::collections::HashMap;
use tree_sitter::Node;

/// True for a compound assignment (`+=`, `|=`, ...), which derives its
/// value from the one already there.
pub fn is_compound(node: &Node, source: &str) -> bool {
    node.kind() == "assignment_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|op| ast_utils::get_node_text(&op, source) != "=")
}

/// True when `node` is an assignment to, or the initializing declarator of,
/// the lvalue spelled `name`.
pub fn write_target_is(node: &Node, name: &str, source: &str) -> bool {
    match node.kind() {
        "assignment_expression" => node
            .child_by_field_name("left")
            .is_some_and(|left| ast_utils::get_node_text(&left, source) == name),
        "init_declarator" => node
            .child_by_field_name("declarator")
            .is_some_and(|d| ast_utils::get_identifier_from_declarator(&d, source) == name),
        _ => false,
    }
}

/// The body of the function definition enclosing `node`, from one descent
/// ([`ast_utils::ancestors`]) rather than a climb that costs the depth per
/// step.
fn enclosing_function_body<'t>(node: &Node<'t>) -> Option<Node<'t>> {
    ast_utils::ancestors(node)
        .find(|a| a.kind() == "function_definition")?
        .child_by_field_name("body")
}

/// The last write to `name` that ends before `site` in the enclosing
/// function, in byte order (see the module documentation for what a write
/// is). Of two writes starting at the same byte, the outer one.
pub fn last_write_before<'t>(name: &str, site: &Node<'t>, source: &str) -> Option<Node<'t>> {
    let body = enclosing_function_body(site)?;
    #[cfg(test)]
    BODY_WALKS.with(|n| n.set(n.get() + 1));
    let mut last = None;
    collect_last_write(&body, name, site.start_byte(), source, &mut last);
    last
}

fn collect_last_write<'t>(
    node: &Node<'t>,
    name: &str,
    before: usize,
    source: &str,
    last: &mut Option<Node<'t>>,
) {
    if node.start_byte() >= before {
        return;
    }
    if node.end_byte() <= before
        && write_target_is(node, name, source)
        && !is_compound(node, source)
        && last.is_none_or(|l| l.start_byte() < node.start_byte())
    {
        *last = Some(*node);
    }
    // A cursor, not `node.child(i)`, which walks from the first child each
    // time. Siblings come in byte order, so the first one starting at or
    // after `before` ends the scan: it and every later one would return at
    // once.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.start_byte() >= before {
            break;
        }
        collect_last_write(&child, name, before, source, last);
    }
}

/// [`last_write_before`]'s start byte for many sites of one tree, from one
/// walk of each function body per name. Keyed by node id, so one value
/// serves one tree and must not outlive it.
#[derive(Default)]
pub struct LastWrites {
    /// Per (function body id, name), the byte span of every write, in
    /// pre-order, which is ascending by start byte.
    spans: HashMap<(usize, String), Vec<(usize, usize)>>,
}

impl LastWrites {
    /// `last_write_before(name, site, source)`'s start byte.
    pub fn start_before(&mut self, name: &str, site: &Node, source: &str) -> Option<usize> {
        let body = enclosing_function_body(site)?;
        let spans = self
            .spans
            .entry((body.id(), name.to_string()))
            .or_insert_with(|| write_spans(&body, name, source));
        let before = site.start_byte();
        // Every write starting before the site, then the latest of those that
        // also ends before it. The ones passed over from the end contain the
        // site, so there are no more of them than the site is deep.
        let starting = spans.partition_point(|&(start, _)| start < before);
        spans[..starting]
            .iter()
            .rev()
            .find(|&&(_, end)| end <= before)
            .map(|&(start, _)| start)
    }
}

/// The span of every write to `name` under `body`, in pre-order.
fn write_spans(body: &Node, name: &str, source: &str) -> Vec<(usize, usize)> {
    #[cfg(test)]
    BODY_WALKS.with(|n| n.set(n.get() + 1));
    let mut spans = Vec::new();
    let mut cursor = body.walk();
    'walk: loop {
        let node = cursor.node();
        if write_target_is(&node, name, source) && !is_compound(&node, source) {
            spans.push((node.start_byte(), node.end_byte()));
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() || cursor.node().id() == body.id() {
                break 'walk;
            }
        }
    }
    spans
}

#[cfg(test)]
thread_local! {
    /// How many function bodies [`last_write_before`] and [`LastWrites`]
    /// walked on this thread.
    static BODY_WALKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Function bodies walked on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_body_walks() -> usize {
    BODY_WALKS.with(|n| n.replace(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    fn identifiers<'t>(node: Node<'t>, name: &str, source: &str, out: &mut Vec<Node<'t>>) {
        if node.kind() == "identifier" && ast_utils::get_node_text(&node, source) == name {
            out.push(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            identifiers(child, name, source, out);
        }
    }

    /// Every occurrence of `s` gets [`last_write_before`]'s answer from
    /// [`LastWrites`], over plain, compound, nested and self-referencing
    /// writes, and the whole function costs one walk per name however many
    /// sites ask: a function of N guarded copies cost N walks. Counted
    /// rather than timed.
    #[test]
    fn one_walk_per_name_answers_as_the_per_site_walk() {
        let mut code =
            String::from("int g(int *);\nvoid f(int c, int *q, int *r) {\n    int *s = 0;\n");
        for i in 0..200 {
            code.push_str(&format!(
                "    if (c == {i}) {{ s = q; g(s); }}\n    s += 1;\n    s = (s = r) ? s : q;\n    {{ int *s = q; g(s); }}\n"
            ));
        }
        code.push_str("    g(s);\n}\n");
        let tree = parse(&code);
        let mut sites = Vec::new();
        identifiers(tree.root_node(), "s", &code, &mut sites);
        assert!(sites.len() > 1_000);

        let walked: Vec<_> = sites
            .iter()
            .map(|site| last_write_before("s", site, &code).map(|w| w.start_byte()))
            .collect();
        take_body_walks();
        let mut index = LastWrites::default();
        for (site, expected) in sites.iter().zip(walked) {
            assert_eq!(
                index.start_before("s", site, &code),
                expected,
                "at byte {}",
                site.start_byte()
            );
        }
        assert_eq!(take_body_walks(), 1);
    }
}
