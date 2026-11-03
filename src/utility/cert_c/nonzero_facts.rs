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
use crate::analyze::address_taken::{store_base, AddressTakenLocals, FunctionKey, LocalId};
use crate::utility::cert_c::node_children::NodeChildren;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;
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
/// - the address of a target or a variable it reads is taken, other than
///   as an argument of a library call that keeps no copy
///   ([`passed_to_library_call`]), which writes only during the call, and a
///   write through a pointer can change it between the two
///   ([`pointer_write_between`]);
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
    let function = FunctionFacts::of_function(&func, source);
    // An address handed straight to a library call is a write at that call,
    // which `written_between` reads; any other escapes.
    let addressed: HashSet<String> = function
        .addressed
        .iter()
        .filter(|text| names.contains(*text))
        .cloned()
        .collect();
    if !addressed.is_empty()
        && pointer_write_between(cond, site, &func, &function, &addressed, source)
    {
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
                        && library_function(ast_utils::get_node_text(&f, source), &function.defined)
                })
        });
        if may_write.is_some() {
            return false;
        }
    }
    !written_between(cond, site, targets, source)
}

/// Whether a write through a pointer may change one of `names` between
/// `cond` and `site`, for names whose address the function takes.
///
/// The condition read the variable's value after every write before it, so
/// only a write after it can make the fact stale: a store through a pointer
/// that may hold its address, or a call handed such a pointer
/// ([`AddressTakenLocals`]). Where the pointer cannot be followed the
/// answer is yes, as before: a name that is not a plain local (a member, a
/// file-scope object), a local whose address escaped into storage the
/// analysis does not track, and a local whose address, or a pointer
/// holding it, goes anywhere in the function to a call other than a
/// library call that keeps no copy, since that callee may keep the pointer
/// and write through it at any later call.
fn pointer_write_between(
    cond: &Node,
    site: &Node,
    func: &Node,
    function: &FunctionFacts,
    names: &HashSet<String>,
    source: &str,
) -> bool {
    let facts = &function.facts;
    // The objects the names mean at the site, which are the ones they meant
    // at the condition: `fact_reaches` checked that first.
    let mut guarded: HashSet<LocalId> = HashSet::new();
    for name in names {
        let local = ast_utils::resolve_identifier_declarator(site, name, source)
            .and_then(|(_, declarator)| facts.local_declared_by(&declarator));
        match local {
            Some(local) if !facts.has_escaped(local) && !function.retained.contains(&local) => {
                guarded.insert(local);
            }
            _ => return true,
        }
    }
    let reaches = |targets: HashSet<LocalId>| targets.iter().any(|t| guarded.contains(t));
    let between = Between::new(cond, site);
    query::find_first_descendant(*func, |n| {
        between.holds(&n)
            && match n.kind() {
                "assignment_expression" => n
                    .child_by_field_name("left")
                    .and_then(|l| store_base(&l))
                    .is_some_and(|base| reaches(facts.store_targets(&base, source))),
                "update_expression" => n
                    .child_by_field_name("argument")
                    .and_then(|a| store_base(&a))
                    .is_some_and(|base| reaches(facts.store_targets(&base, source))),
                "call_expression" => call_arguments(&n)
                    .iter()
                    .any(|arg| reaches(facts.argument_targets(arg, source))),
                _ => false,
            }
    })
    .is_some()
}

/// What [`fact_reaches`] reads of a whole function, built once however many
/// (condition, site) pairs of the function ask: a function of N guarded
/// divisions asked it N times, and each time every `&` and every call
/// argument looked through the whole file for a definition of its callee.
struct FunctionFacts {
    /// The functions the file defines: a call to one of those is no
    /// library call, whatever its name.
    defined: HashSet<String>,
    /// Every `&` argument's spelling, whitespace-squeezed, where some `&` of
    /// it is not passed straight to a library call that keeps no copy.
    addressed: HashSet<String>,
    facts: Arc<AddressTakenLocals>,
    /// Locals whose address, or a pointer holding it, goes to a call other
    /// than a library call that keeps no copy, anywhere in the function.
    retained: HashSet<LocalId>,
}

thread_local! {
    /// The [`FunctionFacts`] of the function last asked about on this
    /// thread.
    static LAST_FUNCTION_FACTS: RefCell<Option<(FunctionKey, Rc<FunctionFacts>)>> =
        const { RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// How many times [`FunctionFacts::of_function`] read a function,
    /// rather than remembered it, on this thread.
    static FUNCTION_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Function reads on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_function_reads() -> usize {
    FUNCTION_READS.with(|n| n.replace(0))
}

impl FunctionFacts {
    fn of_function(func: &Node, source: &str) -> Rc<Self> {
        let key = FunctionKey::of(func, source);
        let hit = LAST_FUNCTION_FACTS.with(|last| {
            last.borrow()
                .as_ref()
                .filter(|(k, _)| *k == key)
                .map(|(_, facts)| Rc::clone(facts))
        });
        if let Some(facts) = hit {
            return facts;
        }
        #[cfg(test)]
        FUNCTION_READS.with(|n| n.set(n.get() + 1));
        let defined = defined_functions(&ast_utils::tree_root(func), source);
        let addressed = query::find_descendants_of_kind(*func, "pointer_expression")
            .into_iter()
            .filter(|n| {
                n.child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "&")
                    && !passed_to_library_call_in(n, &defined, source)
            })
            .filter_map(|n| n.child_by_field_name("argument"))
            .map(|arg| guard_dominance::squeeze_text(&arg, source))
            .collect();
        let facts = AddressTakenLocals::of_function(func, source);
        let mut retained = HashSet::new();
        for call in query::find_descendants_of_kind(*func, "call_expression") {
            for arg in call_arguments(&call) {
                if !passed_to_library_call_in(&arg, &defined, source) {
                    retained.extend(facts.argument_targets(&arg, source));
                }
            }
        }
        let function = Rc::new(FunctionFacts {
            defined,
            addressed,
            facts,
            retained,
        });
        LAST_FUNCTION_FACTS.with(|last| *last.borrow_mut() = Some((key, Rc::clone(&function))));
        function
    }
}

/// The names of the functions the file under `root` defines. A definition
/// sits at file scope, in a preprocessor arm, a linkage block or a damaged
/// region, so no function body is walked: a GNU nested function, defined
/// inside another's body, is not looked for, and a call to one named as a
/// library function is read as that library function's.
fn defined_functions(root: &Node, source: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut stack = vec![*root];
    while let Some(node) = stack.pop() {
        for child in node.named_child_nodes() {
            if child.kind() == "function_definition" {
                if let Some(name) = lang_parsing_substrate::calls::get_function_name(child, source)
                {
                    out.insert(name);
                }
            } else {
                stack.push(child);
            }
        }
    }
    out
}

/// A call's argument expressions.
fn call_arguments<'a>(call: &Node<'a>) -> Vec<Node<'a>> {
    call.child_by_field_name("arguments")
        .map(|args| {
            (0..args.named_child_count())
                .filter_map(|i| args.named_child(i))
                .filter(|a| a.kind() != "comment")
                .collect()
        })
        .unwrap_or_default()
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
    passed_to_library_call_in(expr, &defined_functions(root, source), source)
}

/// [`passed_to_library_call`] for a file defining the functions `defined`.
fn passed_to_library_call_in(expr: &Node, defined: &HashSet<String>, source: &str) -> bool {
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
            && library_function(name, defined)
    })
}

/// Whether `name` is an ISO C or POSIX function and the file, defining
/// `defined`, does not define it.
fn library_function(name: &str, defined: &HashSet<String>) -> bool {
    std_functions::is_iso_c_or_posix_function(name) && !defined.contains(name)
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
/// whether a value is non-zero, and such a write keeps it so. An operand
/// that is a plain name counts only where it means the object the name
/// means at the site: in `{ int x = 2; int *q = &x; }` the inner `x` is
/// another object than an outer `x` the site divides by (ADR-0006).
pub fn written_between(cond: &Node, site: &Node, targets: &[String], source: &str) -> bool {
    let Some(func) = ast_utils::find_containing_function(site) else {
        return false;
    };
    let names = target_names(targets);
    let between = Between::new(cond, site);
    let declarator = |at: &Node, name: &str| {
        ast_utils::resolve_identifier_declarator(at, name, source).map(|(_, d)| d.id())
    };
    let writes = |operand: Option<Node>| {
        operand.is_some_and(|op| {
            let text = guard_dominance::squeeze_text(&op, source);
            names.contains(&text)
                && (op.kind() != "identifier" || declarator(&op, &text) == declarator(site, &text))
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    /// The divisions of a function, in source order.
    fn divisions<'t>(node: Node<'t>, source: &str) -> Vec<Node<'t>> {
        query::find_descendants_of_kind(node, "binary_expression")
            .into_iter()
            .filter(|b| {
                b.child_by_field_name("operator")
                    .is_some_and(|op| ast_utils::get_node_text(&op, source) == "/")
            })
            .collect()
    }

    /// A function of N guarded divisions by address-taken locals, each with
    /// a library call taking an address, reads the function once however
    /// many sites ask, and every check still holds: it was read once per
    /// (condition, site) pair, and each read looked through the whole file
    /// for every callee's definition. Counted rather than timed.
    #[test]
    fn one_read_per_function_answers_every_guarded_site() {
        let mut code = String::from(
            "void *memcpy(void *, const void *, unsigned long);\nint r(void);\nint f(void) {\n    int t = 0; int one = 1;\n",
        );
        for i in 0..60 {
            code.push_str(&format!(
                "    int x{i} = r(); int *p{i} = &x{i}; memcpy(&x{i}, &one, sizeof x{i});\n    if (x{i} != 0) {{ t += 100 / x{i}; }}\n    t += *p{i};\n"
            ));
        }
        code.push_str("    return t;\n}\n");
        let tree = parse(&code);
        let sites = divisions(tree.root_node(), &code);
        assert_eq!(sites.len(), 60);
        take_function_reads();
        for (i, site) in sites.iter().enumerate() {
            let targets = vec![format!("x{i}")];
            let facts = known_conditions(site, &targets, &code, &HashSet::new());
            assert_eq!(facts.len(), 1, "site {i} lost its guard");
        }
        assert_eq!(take_function_reads(), 1);
    }

    /// A store through a pointer to a block's own `x`, and an assignment to
    /// it, leave a check of the outer `x` standing; a store through a
    /// pointer to the outer `x` does not.
    #[test]
    fn a_write_to_a_shadowing_local_keeps_the_check() {
        let cases = [
            ("{ int x = 2; int *q = &x; *q = r(); (void)x; }", 1),
            ("{ int x = 2; x = r(); (void)x; }", 1),
            ("{ int x = 0; (void)x; } *p = r();", 0),
        ];
        for (block, kept) in cases {
            let code = format!(
                "int r(void);\nint f(void) {{ int x = r(); int *p = &x; if (x != 0) {{ {block} return 100 / x; }} return 0; }}\n"
            );
            let tree = parse(&code);
            let site = divisions(tree.root_node(), &code).pop().unwrap();
            let facts = known_conditions(&site, &["x".to_string()], &code, &HashSet::new());
            assert_eq!(facts.len(), kept, "{block}");
        }
    }
}
