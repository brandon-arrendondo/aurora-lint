//! Structural "is this variable guarded here?" queries.
//!
//! Several rules need to answer the same question about a specific site in a
//! function: *has some comparison on `var` already been evaluated by the time
//! control reaches this expression?* The recurring wrong answer is a text
//! search for a canonical spelling — `format!("if ({} < ", param)` and
//! friends — which misses the same guard written without a space
//! (`if( c<128 )`), with a reversed operand (`5 > nBuf`), against a
//! non-literal bound (`idx >= wa->num`), or as one `&&` conjunct.
//!
//! What this module provides instead is the AST relation the text search was
//! standing in for:
//!
//! * [`dominating_conditions`] — every condition expression that has been
//!   evaluated when `site` executes, in two flavours: conditions that
//!   *enclose* the site (an `if`/`while`/`for`/`switch` whose body it is in, a
//!   `?:` branch, the left operand of an `&&`/`||` whose right operand it is
//!   in) and conditions of `if` statements that *precede* it in one of its
//!   ancestor blocks.
//! * [`condition_compares_var`] — whether a condition tests `var` at all, in
//!   either operand order, with the variable nested anywhere inside an operand
//!   (`SIZE_MAX - n < x`, `p->len < n`), and with `!n` read as the `n == 0` it
//!   is. Which operators count is the caller's choice
//!   ([`ComparisonKind`]) — the answer differs for a bounds question and an
//!   overflow question.
//! * [`has_dominating_comparison`] — the two composed, which is what a rule
//!   asking "was this parameter validated before here?" wants.
//!
//! **Deliberately not here: `assert(...)`.** An assert compiles out under
//! `NDEBUG`, and task 644's re-audit of API00-C found crediting
//! assert-only guards as validation was the single largest source of missed
//! true positives in that rule. A rule for which an assert *is* the right
//! answer (a bounds precondition inside a codebase that ships with asserts
//! enabled) should collect those conditions itself and pass them to
//! [`condition_compares_var`], so that choice stays visible at the call site
//! rather than buried in a shared default.
//!
//! Dominance here is the AST approximation, not a CFG dominator computation:
//! `goto` into the middle of a guarded region, or a guard reached only through
//! a `switch` fallthrough, are not modelled. Both directions of that
//! imprecision have been acceptable for the rules using it, and the AST form
//! needs no CFG build per query.

use super::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// Operators that order a variable against something — these always bound it.
const ORDERING_OPERATORS: &[&str] = &["<", "<=", ">", ">="];

/// Which comparisons count as testing a variable, for a caller whose notion of
/// "tested" is a bound rather than an ordering.
///
/// The split exists because equality is not one thing. For a *size* question
/// (is this length checked before the copy?) `len == 5` pins `len` exactly and
/// is as good a bound as `len < 6`. For an *overflow* question it usually is
/// not: `idx == BTREE_DATA_VERSION` excludes one arbitrary value out of the
/// whole range and leaves `36 + idx*4` exactly as unbounded as before, while
/// `n == INT_MIN` before negating `n` excludes precisely the value that
/// overflows and is the entire guard.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ComparisonKind {
    /// `< <= > >=`, `==`/`!=` against anything, and `!var`.
    Any,
    /// `< <= > >=` always; `==`/`!=` only against zero or an integer limit
    /// (`INT_MIN`, `SIZE_MAX`, `SMALLEST_INT32`, …); and `!var`, which is
    /// `var == 0`.
    OrderingOrExtremeEquality,
}

/// True when some comparison on `var` has been evaluated by the time `site`
/// executes — see the module docs for exactly which relations count.
pub fn has_dominating_comparison(
    var: &str,
    site: &Node,
    source: &str,
    kind: ComparisonKind,
) -> bool {
    dominating_conditions(site)
        .iter()
        .any(|cond| condition_compares_var(cond, var, source, kind))
}

/// Per-argument "was this bounds-checked before the call?" flags for one call
/// site, in argument order.
///
/// An argument that is not a bare variable once parentheses and casts are
/// peeled off never counts as validated: `f(i)` and `f((word_t)i)` ask about
/// `i`, but `f(get_index(cap))` and `f(i + 1)` are expressions this module has
/// no dominating-comparison question to ask about.
///
/// Callers aggregating these across every call site of a function get the
/// "which parameters do all callers already check?" summary that the
/// validate-then-act split (a `decode`-style entry point range-checking every
/// argument before an `invoke`-style callee written to trust it) needs in
/// order not to read the callee's parameter as unvalidated.
pub fn call_arg_guards(call_node: &Node, source: &str) -> Vec<bool> {
    let Some(arg_list) = call_node.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut guards = Vec::new();
    for i in 0..arg_list.child_count() {
        let Some(arg) = arg_list.child(i) else {
            continue;
        };
        if !arg.is_named() || arg.kind() == "comment" {
            continue;
        }
        let inner = strip_arg_wrappers(&arg);
        guards.push(
            inner.kind() == "identifier"
                && has_dominating_comparison(
                    &get_node_text(&inner, source),
                    call_node,
                    source,
                    ComparisonKind::Any,
                ),
        );
    }
    guards
}

/// Record [`call_arg_guards`] for every call through a plain identifier under
/// `node`, keyed by callee name.
///
/// Walks the whole subtree rather than descending only into
/// `function_definition` bodies, so that a per-file caller and a project-wide
/// one summarise exactly the same set of call sites — the two scopes of this
/// question are otherwise free to drift apart, and a suppression that appears
/// or vanishes depending on which one answered would be untraceable. A call in
/// a static initializer has no dominating condition and so is recorded as
/// unguarded, which errs toward keeping the finding.
pub fn collect_call_arg_guards(
    node: &Node,
    source: &str,
    out: &mut std::collections::HashMap<String, Vec<Vec<bool>>>,
) {
    if node.kind() == "call_expression" {
        if let Some(callee) = node.child_by_field_name("function") {
            if callee.kind() == "identifier" {
                out.entry(get_node_text(&callee, source).to_string())
                    .or_default()
                    .push(call_arg_guards(node, source));
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_call_arg_guards(&child, source, out);
        }
    }
}

/// Peel parentheses and casts off a call argument, so `f((word_t)index)` reads
/// as passing `index`.
pub fn strip_arg_wrappers<'a>(node: &Node<'a>) -> Node<'a> {
    let mut current = strip_parens(node);
    while current.kind() == "cast_expression" {
        let Some(value) = current.child_by_field_name("value") else {
            break;
        };
        current = strip_parens(&value);
    }
    current
}

fn strip_parens<'a>(node: &Node<'a>) -> Node<'a> {
    let mut n = *node;
    while n.kind() == "parenthesized_expression" {
        let Some(inner) = (0..n.child_count())
            .filter_map(|i| n.child(i))
            .find(|c| !matches!(c.kind(), "(" | ")"))
        else {
            break;
        };
        n = inner;
    }
    n
}

/// Every condition expression already evaluated when `site` executes.
///
/// Two relations, in this order: conditions *enclosing* `site` (innermost
/// first) and conditions of `if` statements *preceding* it in an ancestor
/// block. Returned as nodes rather than a bool so a caller can apply its own
/// predicate (a bound on a specific expression, a null test, a status code)
/// instead of [`condition_compares_var`].
pub fn dominating_conditions<'a>(site: &Node<'a>) -> Vec<Node<'a>> {
    let mut conditions = enclosing_conditions(site);
    conditions.extend(preceding_if_conditions(site));
    conditions
}

/// Conditions that govern `site` by enclosing it.
///
/// A `do`-`while` condition is deliberately excluded: it runs *after* the body,
/// so it establishes nothing on the first iteration.
fn enclosing_conditions<'a>(site: &Node<'a>) -> Vec<Node<'a>> {
    let mut conditions = Vec::new();
    let mut current = *site;

    while let Some(parent) = current.parent() {
        match parent.kind() {
            // The condition holds throughout the body/branches. `else if` is
            // an `if_statement` inside an `else_clause`, so walking up from a
            // site in an else-if branch reaches that inner `if` first and the
            // outer one after — both are collected, which is what the
            // else-if-chain range tests (`if(c<128) … else if(c<65536) …`)
            // need.
            "if_statement"
            | "while_statement"
            | "for_statement"
            | "switch_statement"
            | "conditional_expression" => {
                if let Some(cond) = parent.child_by_field_name("condition") {
                    // A site inside the condition itself is not governed by it.
                    if !spans(&cond, site) {
                        conditions.push(cond);
                    }
                }
            }
            // `<guard> && <expr>` / `<guard> || <expr>`: short-circuiting means
            // the left operand has been evaluated wherever the right one runs.
            "binary_expression" => {
                let is_logical = parent
                    .child_by_field_name("operator")
                    .map(|op| matches!(op.kind(), "&&" | "||"))
                    .unwrap_or(false);
                if is_logical {
                    if let (Some(left), Some(right)) = (
                        parent.child_by_field_name("left"),
                        parent.child_by_field_name("right"),
                    ) {
                        if spans(&right, site) {
                            conditions.push(left);
                        }
                    }
                }
            }
            "function_definition" => break,
            _ => {}
        }
        current = parent;
    }

    conditions
}

/// Node kinds whose children are statements at the enclosing block's level.
///
/// The preprocessor wrappers are here because aurora-lint does not preprocess: a
/// `#ifdef`-guarded region keeps its own AST node, so the statements inside it
/// are one level deeper than they will be after preprocessing. Treating them
/// as block-level is what lets a guard and the arithmetic it protects be seen
/// as siblings when both live inside the same `#if` (hostap's
/// `eloop_wait_for_read_sock` has `if (sock < 0) return;` and
/// `select(sock + 1, …)` inside one `#if defined(CONFIG_ELOOP_SELECT)`). It
/// also means a guard from a *branch that will not be compiled* can be
/// credited — the same approximation every other preproc-descending rule here
/// makes, and the conservative direction for a guard search.
const BLOCK_LIKE_KINDS: &[&str] = &[
    "compound_statement",
    "preproc_if",
    "preproc_ifdef",
    "preproc_else",
    "preproc_elif",
];

/// Conditions of `if` statements that precede `site` in one of its ancestor
/// blocks.
///
/// Only `if` statements count, and only at block level. A guard nested inside
/// a preceding `if`'s own body does not reach `site`, and a preceding loop's
/// condition is false by the time the loop exits — neither is validation.
fn preceding_if_conditions<'a>(site: &Node<'a>) -> Vec<Node<'a>> {
    let mut conditions = Vec::new();
    let mut current = *site;

    while let Some(parent) = current.parent() {
        if BLOCK_LIKE_KINDS.contains(&parent.kind()) {
            let mut cursor = parent.walk();
            for stmt in parent.named_children(&mut cursor) {
                if stmt.start_byte() >= current.start_byte() {
                    break;
                }
                collect_block_level_if_conditions(&stmt, &mut conditions);
            }
        }
        if parent.kind() == "function_definition" {
            break;
        }
        current = parent;
    }

    conditions
}

/// Collect from one preceding block-level statement, looking through
/// preprocessor wrappers to the statements they hold.
fn collect_block_level_if_conditions<'a>(stmt: &Node<'a>, out: &mut Vec<Node<'a>>) {
    if BLOCK_LIKE_KINDS.contains(&stmt.kind()) && stmt.kind() != "compound_statement" {
        let mut cursor = stmt.walk();
        for inner in stmt.named_children(&mut cursor) {
            collect_block_level_if_conditions(&inner, out);
        }
        return;
    }
    collect_if_chain_conditions(stmt, out);
}

/// Push the condition of `stmt` and of every `else if` chained onto it — all of
/// them are evaluated before control leaves the statement.
fn collect_if_chain_conditions<'a>(stmt: &Node<'a>, out: &mut Vec<Node<'a>>) {
    let mut current = *stmt;
    loop {
        if current.kind() != "if_statement" {
            return;
        }
        if let Some(cond) = current.child_by_field_name("condition") {
            out.push(cond);
        }
        let alternative = match current.child_by_field_name("alternative") {
            Some(a) => a,
            None => return,
        };
        // Tree-sitter wraps `else` in an `else_clause`; an `else if` is an
        // `if_statement` inside it.
        current = if alternative.kind() == "else_clause" {
            let mut cursor = alternative.walk();
            let inner = alternative
                .named_children(&mut cursor)
                .find(|c| c.kind() == "if_statement");
            match inner {
                Some(inner) => inner,
                None => return,
            }
        } else {
            alternative
        };
    }
}

/// True when `condition` tests `var`'s value somewhere inside it.
///
/// Operand order does not matter, and the variable may sit at any depth inside
/// an operand — `x > SIZE_MAX - n` and `p->len < n` both count. `!var` is read
/// as `var == 0`.
pub fn condition_compares_var(
    condition: &Node,
    var: &str,
    source: &str,
    kind: ComparisonKind,
) -> bool {
    let operator = condition
        .child_by_field_name("operator")
        .map(|op| op.kind())
        .unwrap_or("");
    let is_test = match condition.kind() {
        "binary_expression" => {
            ORDERING_OPERATORS.contains(&operator)
                || (matches!(operator, "==" | "!=")
                    && (kind == ComparisonKind::Any || equality_bounds_var(condition, var, source)))
        }
        "unary_expression" => operator == "!",
        _ => false,
    };
    if is_test && mentions_var(condition, var, source) {
        return true;
    }

    let mut cursor = condition.walk();
    let any_child_compares = condition
        .named_children(&mut cursor)
        .any(|child| condition_compares_var(&child, var, source, kind));
    any_child_compares
}

/// For an `==`/`!=` test mentioning `var`, whether the *other* operand is a
/// value whose exclusion actually bounds `var`: zero, or an integer limit.
fn equality_bounds_var(comparison: &Node, var: &str, source: &str) -> bool {
    let (Some(left), Some(right)) = (
        comparison.child_by_field_name("left"),
        comparison.child_by_field_name("right"),
    ) else {
        return false;
    };
    // Whichever side is not the variable is the value being excluded. If both
    // sides mention it the test is between two expressions of `var`, which
    // bounds nothing.
    let other = match (
        mentions_var(&left, var, source),
        mentions_var(&right, var, source),
    ) {
        (true, false) => right,
        (false, true) => left,
        _ => return false,
    };
    let text = get_node_text(&other, source).trim();
    is_zero_literal(text) || is_integer_limit_name(text)
}

fn is_zero_literal(text: &str) -> bool {
    matches!(
        text,
        "0" | "0x0" | "0X0" | "0u" | "0U" | "0L" | "0l" | "0UL" | "0ul"
    )
}

/// Names that spell an integer type's extreme value.
///
/// Deliberately shape-matched rather than a fixed list, so a project's own
/// spelling is covered -- sqlite writes `SMALLEST_INT32`/`LARGEST_INT32` for
/// what `<limits.h>` calls `INT32_MIN`/`INT32_MAX`. Anchored at the token
/// edges so an ordinary constant that merely contains the letters (say a
/// `MAX_RETRIES_MINIMUM_BACKOFF`) is not mistaken for one.
fn is_integer_limit_name(text: &str) -> bool {
    if text.contains(char::is_lowercase) {
        return false;
    }
    text.ends_with("_MIN")
        || text.ends_with("_MAX")
        || text.starts_with("SMALLEST_")
        || text.starts_with("LARGEST_")
}

/// True when a condition already evaluated at `site` bounds one of the
/// variables appearing in `expr` against an integer limit — `n > SIZE_MAX /
/// sizeof(T)`, `count >= UINT_MAX - len`, `a > INT_MAX / b`.
///
/// This is the overflow-guard question INT30-C and INT32-C each answered with
/// a text search for one canonical spelling. Those searches required the
/// literal `" / "` and `" > "` *with surrounding spaces*, so the very idiom
/// they exist to honour slipped past whenever it was written
/// `SIZE_MAX/sizeof(x)`, and they scanned ancestor statements only, missing an
/// `&&` conjunct or a preceding `if`.
///
/// Requiring a limit name in the condition keeps this far narrower than
/// [`has_dominating_comparison`] alone: an ordinary `if (n < 5)` bounds `n`
/// but is not read here as an overflow guard.
pub fn has_dominating_limit_guard(expr: &Node, site: &Node, source: &str) -> bool {
    let vars = expression_variables(expr, source);
    if vars.is_empty() {
        return false;
    }
    dominating_conditions(site).iter().any(|cond| {
        condition_mentions_integer_limit(cond, source)
            && vars.iter().any(|v| {
                condition_compares_var(cond, v, source, ComparisonKind::OrderingOrExtremeEquality)
            })
    })
}

/// The identifier names appearing in `expr` — the operands of the arithmetic
/// whose guard is being looked for.
fn expression_variables(expr: &Node, source: &str) -> Vec<String> {
    let mut names: Vec<String> = query::find_descendants_of_kind(*expr, "identifier")
        .iter()
        .filter_map(|n| n.utf8_text(source.as_bytes()).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !is_integer_limit_name(s))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// True when `condition` names an integer type's extreme value anywhere inside
/// it — the marker that separates an overflow guard from an ordinary bound.
fn condition_mentions_integer_limit(condition: &Node, source: &str) -> bool {
    query::find_descendants_of_kind(*condition, "identifier")
        .iter()
        .filter_map(|n| n.utf8_text(source.as_bytes()).ok())
        .any(|text| is_integer_limit_name(text.trim()))
}

/// True when `var` appears as an identifier anywhere under `node`.
///
/// Matched on the AST identifier node, so it is exact rather than a substring:
/// a parameter named `c` is not found in `abc`, and `n` is not found in `len`.
/// A `p->n` field access is a `field_identifier`, not an `identifier`, so it
/// correctly does not count as a use of a variable `n`.
pub fn mentions_var(node: &Node, var: &str, source: &str) -> bool {
    if node.kind() == "identifier" {
        return get_node_text(node, source) == var;
    }
    let mut cursor = node.walk();
    let any_child_mentions = node
        .named_children(&mut cursor)
        .any(|child| mentions_var(&child, var, source));
    any_child_mentions
}

/// True when `outer`'s byte range contains `inner`'s.
fn spans(outer: &Node, inner: &Node) -> bool {
    outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
}

/// True when control cannot fall out of the bottom of `stmt`: it is itself a
/// `goto`/`return`/`break`/`continue`, or a block whose last non-comment
/// statement is one.
///
/// A block that cannot fall off its end cannot be left except by a jump
/// either, so accepting it is exact rather than optimistic. Every other shape
/// is rejected — including a block ending in a preprocessor wrapper, where
/// what runs depends on a `-D` this analyzer does not resolve.
pub fn always_diverges(stmt: &Node) -> bool {
    match stmt.kind() {
        "goto_statement" | "return_statement" | "break_statement" | "continue_statement" => true,
        "compound_statement" => {
            let mut last = None;
            for i in 0..stmt.child_count() {
                if let Some(child) = stmt.child(i) {
                    if matches!(child.kind(), "comment" | "{" | "}") {
                        continue;
                    }
                    last = Some(child);
                }
            }
            last.is_some_and(|l| always_diverges(&l))
        }
        _ => false,
    }
}

/// Which way a condition from [`dominating_conditions`] had to evaluate for
/// control to reach `site`: `Some(true)`, `Some(false)`, or `None` when the
/// relation does not pin it down.
///
/// [`dominating_conditions`] answers "was this condition evaluated before
/// `site`?" and returns bare nodes, which is all a bounds question needs — a
/// comparison that has been evaluated bounds the variable whichever way it
/// went. A *null* question additionally needs the branch, because
/// `if (!p) { site }` and `if (!p) return; site` say opposite things about the
/// very same condition. This is that missing half.
///
/// Deliberately `None` rather than a guess in three places:
///
/// - **An `else if` chain reaching past itself.** Control can arrive after
///   `if (a) X else if (!p) Y` without ever evaluating `!p` (when `a` held and
///   `X` fell through), so a site following the chain learns nothing. Only a
///   lone `if` whose consequence [`always_diverges`] pins its condition false
///   for a following site.
/// - **After a loop.** The condition is false on exit, but the body may have
///   reassigned the variable, so only the body counts.
/// - **A `switch`.** The governing relation is the case label, not the
///   condition's truthiness.
pub fn dominating_condition_branch(cond: &Node, site: &Node) -> Option<bool> {
    let parent = cond.parent()?;
    match parent.kind() {
        "if_statement" | "conditional_expression" => {
            if parent
                .child_by_field_name("consequence")
                .is_some_and(|c| spans(&c, site))
            {
                return Some(true);
            }
            if parent
                .child_by_field_name("alternative")
                .is_some_and(|a| spans(&a, site))
            {
                return Some(false);
            }
            // An `else if` is an `if_statement` under an `else_clause`. Such a
            // tail looks exactly like a lone exiting `if` from here, but a
            // site following the chain may have arrived through an earlier
            // branch that fell through, never evaluating this condition at
            // all — so the chain, not this link, is what would have to exit.
            let is_chain_tail = parent
                .parent()
                .is_some_and(|g| matches!(g.kind(), "else_clause" | "if_statement"));
            let lone_if_that_exits = parent.kind() == "if_statement"
                && !is_chain_tail
                && parent.child_by_field_name("alternative").is_none()
                && parent
                    .child_by_field_name("consequence")
                    .is_some_and(|c| always_diverges(&c));
            lone_if_that_exits.then_some(false)
        }
        "while_statement" | "for_statement" => parent
            .child_by_field_name("body")
            .and_then(|b| spans(&b, site).then_some(true)),
        // Short-circuit: the right operand runs only when the left was true
        // (`&&`) or false (`||`).
        "binary_expression" => {
            let operator = parent.child_by_field_name("operator")?;
            let right = parent.child_by_field_name("right")?;
            if !spans(&right, site) {
                return None;
            }
            match operator.kind() {
                "&&" => Some(true),
                "||" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lang_parsing_substrate::query;
    use tree_sitter::Parser;

    fn parse_c_code(code: &str) -> tree_sitter::Tree {
        let mut parser = Parser::new();
        let language = crate::parser::c_language();
        parser.set_language(&language).unwrap();
        parser.parse(code, None).unwrap()
    }

    /// Ask whether `var` is guarded at the *last* `+`/`-`/`*`/`<<` expression
    /// in `src` -- the fixtures below each have exactly one arithmetic site.
    fn guarded_at_arithmetic(src: &str, var: &str, kind: ComparisonKind) -> bool {
        let tree = parse_c_code(src);
        let site = query::find_descendants_of_kind(tree.root_node(), "binary_expression")
            .into_iter()
            .find(|n| {
                n.child_by_field_name("operator")
                    .is_some_and(|op| matches!(op.kind(), "+" | "-" | "*" | "<<"))
            })
            .expect("fixture has an arithmetic expression");
        has_dominating_comparison(var, &site, src, kind)
    }

    fn guarded(src: &str, var: &str) -> bool {
        guarded_at_arithmetic(src, var, ComparisonKind::OrderingOrExtremeEquality)
    }

    /// The branch a dominating condition took at the call marked by `sink(`.
    /// Fixtures below hold exactly one such call.
    fn branch_at_sink(src: &str) -> Vec<Option<bool>> {
        let tree = parse_c_code(src);
        let site = query::find_descendants_of_kind(tree.root_node(), "call_expression")
            .into_iter()
            .find(|n| {
                n.child_by_field_name("function")
                    .is_some_and(|f| get_node_text(&f, src) == "sink")
            })
            .expect("fixture has a sink() call");
        dominating_conditions(&site)
            .iter()
            .map(|c| dominating_condition_branch(c, &site))
            .collect()
    }

    #[test]
    fn test_branch_enclosing_consequence_is_true() {
        let out = branch_at_sink("void f(char *p) { if (p) { sink(p); } }");
        assert_eq!(out, vec![Some(true)]);
    }

    #[test]
    fn test_branch_enclosing_alternative_is_false() {
        let out = branch_at_sink("void f(char *p) { if (!p) { g(); } else { sink(p); } }");
        assert_eq!(out, vec![Some(false)]);
    }

    #[test]
    fn test_branch_lone_diverging_if_pins_following_site_false() {
        let out = branch_at_sink("void f(char *p) { if (!p) return; sink(p); }");
        assert_eq!(out, vec![Some(false)]);
    }

    #[test]
    fn test_branch_else_if_chain_reaching_past_itself_is_none() {
        // Control reaches sink() with `!p` never evaluated, when `a` held and
        // the first branch fell through. Neither condition may be credited.
        let out = branch_at_sink(
            "void f(int a, char *p) { if (a) { g(); } else if (!p) { return; } sink(p); }",
        );
        assert!(out.iter().all(|b| b.is_none()), "got {:?}", out);
    }

    #[test]
    fn test_branch_non_diverging_if_is_none() {
        let out = branch_at_sink("void f(char *p) { if (!p) { g(); } sink(p); }");
        assert!(out.iter().all(|b| b.is_none()), "got {:?}", out);
    }

    #[test]
    fn test_branch_logical_and_right_is_true() {
        let out = branch_at_sink("int f(char *p) { return p && sink(p); }");
        assert_eq!(out, vec![Some(true)]);
    }

    #[test]
    fn test_branch_logical_or_right_is_false() {
        // hostap's interworking.c:1457 shape: reaching the right operand means
        // the left disjunct was false.
        let out = branch_at_sink("int f(char *p) { return p == 0 || sink(p); }");
        assert_eq!(out, vec![Some(false)]);
    }

    #[test]
    fn test_branch_after_loop_is_none() {
        let out = branch_at_sink("void f(char *p) { while (p) { g(); } sink(p); }");
        assert!(out.iter().all(|b| b.is_none()), "got {:?}", out);
    }

    #[test]
    fn test_always_diverges_shapes() {
        let tree = parse_c_code(
            "void f(void) { { return; } { g(); } { g(); goto e; } { if (x) return; } }",
        );
        let blocks: Vec<_> =
            query::find_descendants_of_kind(tree.root_node(), "compound_statement")
                .into_iter()
                .filter(|b| b.parent().is_some_and(|p| p.kind() == "compound_statement"))
                .collect();
        let got: Vec<bool> = blocks.iter().map(always_diverges).collect();
        // return; / falls through / goto at the end / conditional return only
        assert_eq!(got, vec![true, false, true, false]);
    }

    #[test]
    fn early_return_guard_without_spaces_counts() {
        // The spelling that defeated the text patterns: `N<0`, not `N < 0`.
        assert!(guarded(
            "int f(int N){ if(N<0) return 0; return N+1; }",
            "N"
        ));
    }

    #[test]
    fn enclosing_branch_condition_counts() {
        assert!(guarded(
            "int f(int c){ if(c<128){ return c+1; } return 0; }",
            "c"
        ));
    }

    #[test]
    fn else_if_branch_carries_its_own_bound() {
        assert!(guarded(
            "int f(int c){ if(c<128){ return 0; } else if(c<65536){ return c+1; } return 0; }",
            "c"
        ));
    }

    #[test]
    fn loop_condition_bound_counts() {
        assert!(guarded(
            "int f(int argc){ int i; for(i=1;i<argc;i++){ return argc-1; } return 0; }",
            "argc"
        ));
    }

    #[test]
    fn reversed_operands_and_compound_bound_count() {
        assert!(guarded(
            "void f(struct s *p, unsigned idx){ if(idx>=p->num) return; while(idx+1<p->num) idx++; }",
            "idx"
        ));
        assert!(guarded(
            "int f(int n){ if(5>n) return 0; return n+1; }",
            "n"
        ));
    }

    #[test]
    fn guard_as_one_conjunct_counts() {
        assert!(guarded("int f(int n){ return n>0 && n+1; }", "n"));
    }

    #[test]
    fn negation_guard_counts() {
        assert!(guarded("int f(int n){ if(!n) return 0; return n*2; }", "n"));
    }

    #[test]
    fn guard_after_the_arithmetic_does_not_count() {
        assert!(!guarded(
            "int f(int n){ int d = n*2; if(n<0) return 0; return d; }",
            "n"
        ));
    }

    #[test]
    fn guard_in_a_sibling_branch_does_not_count() {
        assert!(!guarded(
            "int f(int flag, int n){ if(flag){ if(n<100) return n; return 0; } return n+1; }",
            "n"
        ));
    }

    #[test]
    fn a_comparison_containing_the_arithmetic_does_not_guard_it() {
        // `off+n > limit` can wrap before `>` is evaluated, so the check
        // cannot have bounded `n` beforehand.
        assert!(!guarded(
            "int f(unsigned off, unsigned n, unsigned limit){ if(off+n>limit) return 0; return 1; }",
            "n"
        ));
    }

    #[test]
    fn guard_on_a_different_variable_does_not_count() {
        assert!(!guarded(
            "int f(int m, int n){ if(m<0) return 0; return n+1; }",
            "n"
        ));
    }

    #[test]
    fn substring_of_another_identifier_is_not_the_variable() {
        // `len` is guarded; `n` is not, even though "n" occurs inside "len".
        assert!(!guarded(
            "int f(int len, int n){ if(len<0) return 0; return n+1; }",
            "n"
        ));
    }

    #[test]
    fn guard_and_arithmetic_inside_one_preproc_block_are_siblings() {
        // aurora-lint does not preprocess, so the `#if` keeps its own AST node and the
        // guard would otherwise be invisible to a block-level scan.
        assert!(guarded(
            "int f(int sock){\n#ifdef USE_SELECT\n if(sock<0) return 0;\n return sock+1;\n#endif\n}",
            "sock"
        ));
    }

    #[test]
    fn arbitrary_equality_bounds_nothing_for_overflow() {
        // `idx == SOME_CONST` excludes one value out of the range, leaving
        // `36 + idx*4` exactly as unbounded as before...
        let src = "int f(int idx){ if(idx==DATA_VERSION){ return 0; } return 36+idx*4; }";
        assert!(!guarded(src, "idx"));
        // ...but for a caller asking a bounds question rather than an overflow
        // question, pinning a variable to one value is a bound.
        assert!(guarded_at_arithmetic(src, "idx", ComparisonKind::Any));
    }

    #[test]
    fn equality_against_the_overflowing_extreme_is_the_guard() {
        assert!(guarded(
            "int f(int n){ if(n==INT_MIN){ return 0; } return n*-1; }",
            "n"
        ));
        assert!(guarded(
            "int f(int n){ if(n==SMALLEST_INT32){ return 0; } return n*-1; }",
            "n"
        ));
    }

    #[test]
    fn integer_limit_names_are_token_anchored() {
        assert!(is_integer_limit_name("INT_MIN"));
        assert!(is_integer_limit_name("SIZE_MAX"));
        assert!(is_integer_limit_name("SMALLEST_INT32"));
        assert!(!is_integer_limit_name("MAX_RETRIES"));
        assert!(!is_integer_limit_name("int_max"));
    }

    #[test]
    fn do_while_condition_does_not_guard_its_first_iteration() {
        assert!(!guarded(
            "int f(int n){ int t=0; do { t = n+1; } while(n>0); return t; }",
            "n"
        ));
    }
}
