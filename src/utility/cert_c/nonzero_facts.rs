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
//! condition turning false. Every fact is then checked with
//! [`fact_reaches`], since a guard says nothing about a value written after
//! it, nor about a site control can reach around it.

use super::ast_utils;
use super::guard_dominance;
use super::std_functions;
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
/// that value, and still about the value `targets` have there
/// ([`fact_reaches`]).
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
    facts.retain(|(cond, _)| fact_reaches(cond, site, targets, source));
    facts
}

/// Whether what `cond` established about `targets` (a condition, or an
/// assignment or check statement) still describes their value at `site`.
/// It does not when:
///
/// - a name in the targets means another object at `site` than at `cond`,
///   as an inner declaration shadowing it does (ADR-0006);
/// - control can reach `site` without passing `cond` ([`entered_by_jump`]);
/// - the address of a target or a variable it reads is taken anywhere in
///   the function, so a write through a pointer can change it unseen --
///   except as an argument of a library call that keeps no copy
///   ([`passed_to_library_call`]), which writes only during the call;
/// - a target reads a file-scope variable and a call between the two may
///   write it: any call but to a library function the file does not
///   define, which cannot reach the program's own globals except through
///   an address, already ruled out;
/// - something between the two writes it ([`written_between`]).
pub fn fact_reaches(cond: &Node, site: &Node, targets: &[String], source: &str) -> bool {
    let Some(func) = ast_utils::find_containing_function(site) else {
        return true;
    };
    let names = target_names(targets);
    let words: Vec<&String> = names.iter().filter(|n| is_identifier(n)).collect();
    let binding = |at: &Node, name: &str| {
        ast_utils::resolve_identifier_declarator(at, name, source).map(|(_, d)| d.id())
    };
    let same_object = words
        .iter()
        .all(|name| binding(cond, name) == binding(site, name));
    if !same_object || entered_by_jump(cond, site, &func, source) {
        return false;
    }
    let mut root = func;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    // An address handed straight to a library call is a write at that call,
    // which `written_between` reads; any other escapes.
    let escapes = query::find_first_descendant(func, |n| {
        n.kind() == "pointer_expression"
            && n.child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "&")
            && n.child_by_field_name("argument")
                .is_some_and(|arg| names.contains(&guard_dominance::squeeze_text(&arg, source)))
            && !passed_to_library_call(&n, &root, source)
    });
    if escapes.is_some() {
        return false;
    }
    let reads_global = words.iter().any(|name| {
        matches!(
            ast_utils::resolve_identifier_binding(site, name, source),
            Some(ast_utils::IdentifierBinding::Global(_))
        )
    });
    if reads_global {
        let between = Between::new(cond, site);
        let may_write = query::find_first_descendant(func, |n| {
            n.kind() == "call_expression"
                && between.holds(&n)
                && !n.child_by_field_name("function").is_some_and(|f| {
                    f.kind() == "identifier"
                        && library_function(ast_utils::get_node_text(&f, source), &root, source)
                })
        });
        if may_write.is_some() {
            return false;
        }
    }
    !written_between(cond, site, targets, source)
}

/// Library functions that keep a pointer argument past the call: what it
/// points at can change after they return.
const RETAINS_POINTER: &[&str] = &[
    "pthread_create",
    "thrd_create",
    "setbuf",
    "setvbuf",
    "aio_read",
    "aio_write",
    "lio_listio",
];

/// Whether `expr` is itself an argument of a direct call to a library
/// function the translation unit under `root` does not define, and that
/// keeps no copy of its pointer arguments: whatever the call does through
/// `expr`, it does before it returns.
pub fn passed_to_library_call(expr: &Node, root: &Node, source: &str) -> bool {
    let Some(call) = expr
        .parent()
        .filter(|p| p.kind() == "argument_list")
        .and_then(|list| list.parent())
        .filter(|c| c.kind() == "call_expression")
    else {
        return false;
    };
    call.child_by_field_name("function").is_some_and(|f| {
        let name = ast_utils::get_node_text(&f, source);
        f.kind() == "identifier"
            && !RETAINS_POINTER.contains(&name)
            && library_function(name, root, source)
    })
}

/// A library function the translation unit under `root` does not define
/// for itself.
fn library_function(name: &str, root: &Node, source: &str) -> bool {
    std_functions::is_iso_c_or_posix_function(name)
        && query::find_first_descendant(*root, |n| {
            n.kind() == "function_definition"
                && lang_parsing_substrate::calls::get_function_name(n, source).as_deref()
                    == Some(name)
        })
        .is_none()
}

/// Whether control can arrive at `site` without having passed `cond`: a
/// `goto` from outside the stretch between them to a label inside it, or a
/// `case` label inside it whose `switch` starts before it. The stretch
/// starts after the statement owning `cond` when that statement does not
/// hold `site` -- a guard's own `goto`, `if (d == 0) goto out; ... out:
/// return a / d;`, is a way around the guard -- and right after `cond`
/// when it does.
pub fn entered_by_jump(cond: &Node, site: &Node, func: &Node, source: &str) -> bool {
    let lo = cond
        .parent()
        .filter(|owner| !spans(owner, site))
        .map_or(cond.end_byte(), |owner| owner.end_byte());
    region_entered_by_jump(func, lo, site.start_byte(), source)
}

/// Whether control can enter the source stretch `[lo, hi)` of `func` other
/// than by falling into its start: a `goto` outside the stretch naming a
/// label inside it, or a `case`/`default` label inside it belonging to a
/// `switch` that starts before it.
pub fn region_entered_by_jump(func: &Node, lo: usize, hi: usize, source: &str) -> bool {
    if lo >= hi {
        return false;
    }
    let inside = |n: &Node| n.start_byte() >= lo && n.start_byte() < hi;
    let mut labels = HashSet::new();
    for n in query::find_descendants_of_kinds(*func, &["labeled_statement", "case_statement"]) {
        if !inside(&n) {
            continue;
        }
        if n.kind() == "case_statement" {
            let dispatched_from_before =
                query::find_ancestor(n, |a| a.kind() == "switch_statement")
                    .is_some_and(|switch| switch.start_byte() < lo);
            if dispatched_from_before {
                return true;
            }
        } else if let Some(label) = n.child_by_field_name("label") {
            labels.insert(ast_utils::get_node_text(&label, source));
        }
    }
    !labels.is_empty()
        && query::find_first_descendant(*func, |n| {
            n.kind() == "goto_statement"
                && !(n.start_byte() >= lo && n.end_byte() <= hi)
                && n.child_by_field_name("label")
                    .is_some_and(|l| labels.contains(ast_utils::get_node_text(&l, source)))
        })
        .is_some()
}

/// The targets, and the variables they read: `i` in `ds[i]`, `f` in
/// `f->den` (a field name is never written on its own, so including it
/// costs nothing).
fn target_names(targets: &[String]) -> HashSet<String> {
    let mut names: HashSet<String> = targets.iter().cloned().collect();
    for target_text in targets {
        for word in target_text
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|w| is_identifier(w))
        {
            names.insert(word.to_string());
        }
    }
    names
}

/// A non-empty word that can be an identifier.
fn is_identifier(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with(|c: char| c.is_ascii_digit())
        && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `outer` spans `inner` in the source.
fn spans(outer: &Node, inner: &Node) -> bool {
    inner.start_byte() >= outer.start_byte() && inner.end_byte() <= outer.end_byte()
}

/// The source between a condition and a site that runs after it: from the
/// condition (or the end of the loop it controls, when the site follows the
/// loop) to the site, plus the whole body of every loop holding the site
/// but not the condition, whose later statements run again before the site
/// on the next iteration. Never the code holding the site itself.
struct Between {
    spans: Vec<(usize, usize)>,
    site: (usize, usize),
}

impl Between {
    fn new(cond: &Node, site: &Node) -> Self {
        // A loop's condition is known false after the whole loop, so the
        // writes that count start where the loop ends.
        let from = cond
            .parent()
            .filter(|owner| {
                matches!(
                    owner.kind(),
                    "while_statement" | "do_statement" | "for_statement"
                ) && !spans(owner, site)
            })
            .map_or(cond.end_byte(), |owner| owner.end_byte());
        let mut ranges = vec![(from, site.start_byte())];
        let mut current = *site;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition" {
                break;
            }
            let is_loop = matches!(
                parent.kind(),
                "for_statement" | "while_statement" | "do_statement"
            );
            if is_loop && !spans(&parent, cond) {
                ranges.push((parent.start_byte(), parent.end_byte()));
            }
            current = parent;
        }
        Self {
            spans: ranges,
            site: (site.start_byte(), site.end_byte()),
        }
    }

    /// Whether `n` starts in the stretch and does not hold the site.
    fn holds(&self, n: &Node) -> bool {
        let holds_site = n.start_byte() <= self.site.0 && n.end_byte() >= self.site.1;
        !holds_site
            && self
                .spans
                .iter()
                .any(|&(lo, hi)| n.start_byte() >= lo && n.start_byte() < hi)
    }
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
            if loop_can_leave_early(stmt) {
                return;
            }
            if let Some(cond) = stmt.child_by_field_name("condition") {
                out.push((cond, false));
            }
            // A `do` body runs to its end on the last pass, so what its own
            // statements establish holds after the loop, unless a
            // `continue` can cut that pass short:
            // `do { if (d == 0) return 0; } while (0);`.
            if stmt.kind() == "do_statement" && !continues(stmt) {
                if let Some(body) = stmt.child_by_field_name("body") {
                    let stmts = if body.kind() == "compound_statement" {
                        body.named_child_nodes().collect()
                    } else {
                        vec![body]
                    };
                    for inner in stmts {
                        statement_exit_facts(&inner, source, noreturn, out);
                    }
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

/// Whether a `continue` belonging to `stmt`, a loop, sits in its body.
fn continues(stmt: &Node) -> bool {
    query::find_first_descendant(*stmt, |n| {
        n.kind() == "continue_statement"
            && query::find_ancestor(n, |a| {
                matches!(
                    a.kind(),
                    "for_statement" | "while_statement" | "do_statement"
                )
            })
            .is_some_and(|owner| owner.id() == stmt.id())
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
/// it and does not count, and neither does a plain assignment of a non-zero
/// integer literal (`if (d == -1) d = 1;`): every caller of this module asks
/// whether a value is non-zero, and such a write keeps it so.
pub fn written_between(cond: &Node, site: &Node, targets: &[String], source: &str) -> bool {
    let Some(func) = ast_utils::find_containing_function(site) else {
        return false;
    };
    let names = target_names(targets);
    let between = Between::new(cond, site);
    let writes = |operand: Option<Node>| {
        operand.is_some_and(|op| names.contains(&guard_dominance::squeeze_text(&op, source)))
    };
    query::find_first_descendant(func, |n| {
        between.holds(&n)
            && match n.kind() {
                "assignment_expression" => {
                    let keeps_nonzero = n
                        .child_by_field_name("operator")
                        .is_some_and(|op| op.kind() == "=")
                        && n.child_by_field_name("right")
                            .is_some_and(|r| is_nonzero_integer_literal(&r, source));
                    !keeps_nonzero && writes(n.child_by_field_name("left"))
                }
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

/// An integer literal other than zero, possibly negated or parenthesized:
/// `1`, `-1`, `(0x10u)`.
fn is_nonzero_integer_literal(node: &Node, source: &str) -> bool {
    let mut n = *node;
    while let Some(inner) = peel_sign(&n) {
        n = inner;
    }
    if n.kind() != "number_literal" {
        return false;
    }
    let text = ast_utils::get_node_text(&n, source)
        .trim()
        .trim_end_matches(['u', 'U', 'l', 'L'])
        .to_ascii_lowercase();
    let value = if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else if text.len() > 1 && text.starts_with('0') {
        u64::from_str_radix(&text[1..], 8).ok()
    } else {
        text.parse::<u64>().ok()
    };
    value.is_some_and(|v| v != 0)
}
