//! What control has established about a value where a site executes: the
//! conditions whose truth value is known there, with stale ones dropped.
//!
//! Shared by the rules that need a value proven non-zero at one site --
//! INT33-C's divisor, MEM04-C's allocation size -- so both read a guard the
//! same way, by which way it went and whether it still holds, never by the
//! text it contains (ADR-0005). The predicate over a condition is the
//! caller's: `guard_dominance::condition_excludes_zero` for "is it non-zero",
//! or anything else that reads a condition together with its truth value.
//!
//! [`known_conditions`] extends `guard_dominance`'s dominating conditions in
//! three ways: an exit guard whose branch ends in a call that never returns
//! (only the caller's noreturn set can say), the statements of the `case`
//! holding the site, and a `while`/`do` loop that can end only by its
//! condition turning false. Every fact is then checked against
//! [`written_between`], since a guard says nothing about a value written
//! after it.

use super::ast_utils;
use super::guard_dominance;
use crate::utility::cert_c::node_children::NodeChildren;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

/// The spellings a guard on `expr` may use: the expression itself, and what
/// it is once parentheses and a sign are peeled off (`(-step)` is non-zero
/// exactly when `step` is), each whitespace-stripped. Nothing else: `*p` is
/// not `p`, a non-null pointer, and `f->den` is not some other object's
/// `den`.
pub fn peeled_spellings(expr: &Node, source: &str) -> Vec<String> {
    let mut spellings = vec![guard_dominance::squeeze_text(expr, source)];
    let mut node = *expr;
    while let Some(inner) = peel_sign(&node) {
        let text = guard_dominance::squeeze_text(&inner, source);
        if !spellings.contains(&text) {
            spellings.push(text);
        }
        node = inner;
    }
    spellings
}

/// `expr` with one layer of parentheses or unary `-`/`+` removed, if it has
/// one.
pub fn peel_sign<'a>(expr: &Node<'a>) -> Option<Node<'a>> {
    match expr.kind() {
        "parenthesized_expression" => expr.named_child(0),
        "unary_expression"
            if expr
                .child_by_field_name("operator")
                .is_some_and(|op| matches!(op.kind(), "-" | "+")) =>
        {
            expr.child_by_field_name("argument")
        }
        _ => None,
    }
}

/// Every condition whose truth value is known where `site` runs, paired with
/// that value, and not stale: nothing between the condition and `site`
/// writes one of `targets` or a variable they read ([`written_between`]).
///
/// Two sources. `guard_dominance::dominating_conditions_with_branches` gives
/// the conditions enclosing the site (an `if` branch, a loop body, a `?:`
/// arm, the right of `&&`/`||`) and a preceding lone `if` whose branch
/// returns or jumps. [`preceding_exit_facts`] adds a guard ending in a call
/// to one of `noreturn` (`if (d == 0) exit(1);`), one inside the same `case`
/// of a `switch`, and a loop's condition after the loop.
pub fn known_conditions<'a>(
    site: &Node<'a>,
    targets: &[String],
    source: &str,
    noreturn: &HashSet<String>,
) -> Vec<(Node<'a>, bool)> {
    let mut facts: Vec<(Node<'a>, bool)> =
        guard_dominance::dominating_conditions_with_branches(site)
            .into_iter()
            .filter_map(|(cond, branch)| branch.map(|truth| (cond, truth)))
            .collect();
    facts.extend(preceding_exit_facts(site, source, noreturn));
    facts.retain(|(cond, _)| !written_between(cond, site, targets, source));
    facts
}

/// Conditions of statements before `site` in one of its enclosing blocks
/// that control can pass only one way: a lone `if` whose branch always
/// leaves ([`branch_always_leaves`]) is false after it, an `if`/`else` with
/// exactly one arm that leaves holds the other arm's value, and a `while` or
/// `do` loop no `break` or `goto` leaves is false after it.
///
/// The blocks are compound statements, preprocessor arms, and the `case`
/// holding the site: the statements of one `case` run in order, but an
/// earlier `case` is not looked into, since a jump to a later label skips
/// it. An `if` nested inside an earlier statement is not looked into either:
/// `if (v) { if (d == 0) return 0; }` leaves `d` unknown when `v` is zero.
pub fn preceding_exit_facts<'a>(
    site: &Node<'a>,
    source: &str,
    noreturn: &HashSet<String>,
) -> Vec<(Node<'a>, bool)> {
    const BLOCKS: &[&str] = &[
        "compound_statement",
        "case_statement",
        "preproc_if",
        "preproc_ifdef",
        "preproc_else",
        "preproc_elif",
    ];
    let mut facts = Vec::new();
    let mut current = *site;
    while let Some(parent) = current.parent() {
        if BLOCKS.contains(&parent.kind()) {
            for stmt in parent.named_child_nodes() {
                if stmt.start_byte() >= current.start_byte() {
                    break;
                }
                statement_exit_facts(&stmt, source, noreturn, &mut facts);
            }
        }
        if parent.kind() == "function_definition" {
            break;
        }
        current = parent;
    }
    facts
}

/// [`preceding_exit_facts`] for one statement, looking through preprocessor
/// wrappers to the statements they hold.
fn statement_exit_facts<'a>(
    stmt: &Node<'a>,
    source: &str,
    noreturn: &HashSet<String>,
    out: &mut Vec<(Node<'a>, bool)>,
) {
    match stmt.kind() {
        "preproc_if" | "preproc_ifdef" | "preproc_else" | "preproc_elif" => {
            for inner in stmt.named_child_nodes() {
                statement_exit_facts(&inner, source, noreturn, out);
            }
        }
        "if_statement" => {
            let Some(cond) = stmt.child_by_field_name("condition") else {
                return;
            };
            let leaves = |arm: Option<Node>| {
                arm.and_then(|arm| unwrap_else(&arm))
                    .is_some_and(|arm| branch_always_leaves(&arm, source, noreturn))
            };
            let consequence = leaves(stmt.child_by_field_name("consequence"));
            let alternative = stmt.child_by_field_name("alternative");
            let alternative_leaves = leaves(alternative);
            if consequence && !alternative_leaves {
                out.push((cond, false));
            } else if alternative.is_some() && alternative_leaves && !consequence {
                out.push((cond, true));
            }
        }
        "while_statement" | "do_statement" => {
            if let Some(cond) = stmt.child_by_field_name("condition") {
                if !loop_can_leave_early(stmt) {
                    out.push((cond, false));
                }
            }
        }
        _ => {}
    }
}

/// An `if` arm as the statement it runs: an `else` arm is wrapped in an
/// `else_clause`.
fn unwrap_else<'a>(arm: &Node<'a>) -> Option<Node<'a>> {
    if arm.kind() == "else_clause" {
        arm.named_child(0)
    } else {
        Some(*arm)
    }
}

/// Whether a loop can be left other than by its condition turning false: a
/// `break` that ends this loop (one in a nested loop or `switch` ends only
/// that), or a `goto`. A `return` or a call that never returns leaves the
/// whole function, so no statement after the loop runs.
fn loop_can_leave_early(stmt: &Node) -> bool {
    query::find_first_descendant(*stmt, |n| match n.kind() {
        "goto_statement" => true,
        "break_statement" => query::find_ancestor(n, |a| {
            matches!(
                a.kind(),
                "for_statement" | "while_statement" | "do_statement" | "switch_statement"
            )
        })
        .is_some_and(|owner| owner.id() == stmt.id()),
        _ => false,
    })
    .is_some()
}

/// Whether a guard's branch always leaves, so the statements after the
/// guard run only when its condition was false: control cannot fall out of
/// the branch ([`guard_dominance::always_diverges_with`]). Its last
/// statement is a `return`, `break`, `continue` or `goto`, a direct call to
/// one of `noreturn` (a function that never returns under the run's
/// settings), a loop that never ends ([`guard_dominance::loops_forever`]), or
/// an `if` with an `else` whose arms both leave. A jump or call that merely
/// appears inside the branch does not count: `{ if (v) return 0; }` falls
/// through when `v` is zero, and a `break` inside a nested loop or `switch`
/// leaves only that construct. Read off the AST, never the branch's text
/// (ADR-0005).
pub fn branch_always_leaves(node: &Node, source: &str, noreturn: &HashSet<String>) -> bool {
    fn ends_path(stmt: &Node, source: &str, names: &HashSet<String>) -> bool {
        match stmt.kind() {
            "expression_statement" => {
                crate::analyze::noreturn::is_noreturn_call_statement(stmt, source, names)
            }
            "for_statement" | "while_statement" | "do_statement" => {
                guard_dominance::loops_forever(stmt, source)
            }
            "if_statement" => {
                let arm = |field: &str| {
                    stmt.child_by_field_name(field)
                        .and_then(|arm| unwrap_else(&arm))
                        .is_some_and(|arm| {
                            guard_dominance::always_diverges_with(&arm, &|s| {
                                ends_path(s, source, names)
                            })
                        })
                };
                arm("consequence") && arm("alternative")
            }
            _ => false,
        }
    }
    guard_dominance::always_diverges_with(node, &|s| ends_path(s, source, noreturn))
}

/// Whether anything between `cond` and `site` may change one of `targets`:
/// an assignment, `++`/`--` or address-of whose operand is a target or a
/// variable a target reads. "Between" is the source after the condition
/// (after the whole loop, for the condition of a loop the site follows) and
/// before the site, plus the whole body of every loop holding the site but
/// not the condition, whose later statements run again before the site on
/// the next iteration. A write holding the site, `b = a % b`, happens after
/// it and does not count.
pub fn written_between(cond: &Node, site: &Node, targets: &[String], source: &str) -> bool {
    let Some(func) = ast_utils::find_containing_function(site) else {
        return false;
    };
    // The targets, and the variables they read: `i` in `ds[i]`, `f` in
    // `f->den` (a field name is never written on its own, so including it
    // costs nothing).
    let mut names: HashSet<String> = targets.iter().cloned().collect();
    for target_text in targets {
        for word in target_text
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| !w.is_empty() && !w.starts_with(|c: char| c.is_ascii_digit()))
        {
            names.insert(word.to_string());
        }
    }

    let spans_node = |outer: &Node, inner: &Node| {
        inner.start_byte() >= outer.start_byte() && inner.end_byte() <= outer.end_byte()
    };
    // A loop's condition is known false after the whole loop, so the writes
    // that count start where the loop ends.
    let from = cond
        .parent()
        .filter(|owner| {
            matches!(
                owner.kind(),
                "while_statement" | "do_statement" | "for_statement"
            ) && !spans_node(owner, site)
        })
        .map_or(cond.end_byte(), |owner| owner.end_byte());
    let mut spans = vec![(from, site.start_byte())];
    let mut current = *site;
    while let Some(parent) = current.parent() {
        if parent.kind() == "function_definition" {
            break;
        }
        let is_loop = matches!(
            parent.kind(),
            "for_statement" | "while_statement" | "do_statement"
        );
        if is_loop && !spans_node(&parent, cond) {
            spans.push((parent.start_byte(), parent.end_byte()));
        }
        current = parent;
    }
    let within = |n: &Node| {
        !spans_node(n, site)
            && spans
                .iter()
                .any(|&(lo, hi)| n.start_byte() >= lo && n.start_byte() < hi)
    };
    let writes = |operand: Option<Node>| {
        operand.is_some_and(|op| names.contains(&guard_dominance::squeeze_text(&op, source)))
    };
    query::find_first_descendant(func, |n| {
        within(&n)
            && match n.kind() {
                "assignment_expression" => writes(n.child_by_field_name("left")),
                "update_expression" => writes(n.child_by_field_name("argument")),
                "pointer_expression" => {
                    n.child_by_field_name("operator")
                        .is_some_and(|op| op.kind() == "&")
                        && writes(n.child_by_field_name("argument"))
                }
                _ => false,
            }
    })
    .is_some()
}
