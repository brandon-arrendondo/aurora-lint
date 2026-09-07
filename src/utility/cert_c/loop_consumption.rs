//! The "consume a length in a loop" idiom, recognized structurally.
//!
//! A size parameter that a loop draws down — `while (skip >= sizeof(buf))
//! { … skip -= len; }`, `while (pos < buf_len) { plen = buf_len - pos; … }`,
//! `while (len) { … len -= n; }` — reads to an overflow rule as an unguarded
//! subtraction on a parameter, because the fact that bounds it is the loop's
//! own control rather than a guard statement above the expression. Four of the
//! 40 rows in task 664's integer-overflow adjudication sample were this one
//! idiom, all false positives.
//!
//! [`guard_dominance`] already answers the two shapes whose loop condition is
//! an ordering comparison: `skip >= sizeof(buf)` and `pos < buf_len` are
//! enclosing conditions that compare the variable, so those sites are
//! suppressed without anything here. What is left is the two shapes whose loop
//! control is not an ordering comparison at all:
//!
//! * **A truthiness condition** — `while (len)`, curl's
//!   `Curl_bufq_write_pass`. For an unsigned length that *is* `len > 0`, but
//!   spelled as a condition [`guard_dominance::condition_compares_var`]
//!   correctly declines to read as a bound on its own.
//! * **An equality break** — hostap's `hmac_sha256_kdf`, whose loop is
//!   `for (;;)` and whose bound is `if (pos == outlen) break;` above the
//!   subtraction. That condition *is* collected as a dominating one, but
//!   `==` against a non-limit name is exactly what
//!   [`guard_dominance::ComparisonKind::OrderingOrExtremeEquality`] exists to
//!   refuse (`idx == BTREE_DATA_VERSION` before `36 + idx*4` bounds nothing).
//!   What distinguishes this one is that the equality is between *both
//!   operands of the subtraction*, not between the variable and an arbitrary
//!   third value.
//!
//! Neither shape is a proof on its own, which is why both are gated on a
//! monotonicity check over the loop body: the parameter may only ever
//! decrease in it and the subtrahend may only ever increase. That is what
//! separates the idiom from a loop that reassigns the length from somewhere
//! else each iteration.
//!
//! **The honest limit**, recorded by the adjudication that produced this:
//! curl's `len -= n` is bounded by `n <= len`, and `n` is what
//! `Curl_bufq_write(q, buf, len, &n)` actually wrote — a callee contract, not
//! a local fact. The rules here suppress that site on its loop guard and
//! decrement alone, so treat it as incidentally covered rather than proven.

use super::ast_utils::get_node_text;
use tree_sitter::Node;

/// True when `site` subtracts from `var` inside a loop whose own control
/// bounds the subtraction — see the module docs for the two shapes and their
/// limits.
///
/// `var` must be the *minuend*: `len -= n`, `buf_len - pos`. A parameter in
/// the subtrahend position is the unbounded side of the idiom and is left
/// alone.
pub fn is_guarded_loop_consumption(var: &str, site: &Node, source: &str) -> bool {
    let Some((minuend, subtrahend)) = subtraction_operands(site) else {
        return false;
    };
    if get_node_text(&minuend, source) != var {
        return false;
    }
    let Some(loop_node) = enclosing_loop(site) else {
        return false;
    };
    let Some(body) = loop_node.child_by_field_name("body") else {
        return false;
    };

    let subtrahend_name =
        (subtrahend.kind() == "identifier").then(|| get_node_text(&subtrahend, source).to_string());

    if !only_decreases(&body, var, source) {
        return false;
    }
    if let Some(name) = &subtrahend_name {
        if !only_increases(&body, name, source) {
            return false;
        }
    }

    // Each guard shape has to be paired with the step that makes the loop
    // terminate on it, or it bounds nothing: `while (len)` around a body that
    // never touches `len` says only `len >= 1`, and `if (pos == outlen) break`
    // above a body that never advances `pos` says only `pos != outlen`.
    let drains_var = decreases_somewhere(&body, var, source);
    let advances_subtrahend = subtrahend_name
        .as_deref()
        .is_some_and(|name| increases_somewhere(&body, name, source));

    (drains_var && loop_condition_is_nonzero_test(&loop_node, var, source))
        || (advances_subtrahend
            && subtrahend_name
                .as_deref()
                .is_some_and(|name| equality_break_precedes(&body, site, var, name, source)))
}

/// The `(minuend, subtrahend)` of `site` when it is a subtraction, in either
/// the binary (`a - b`) or compound-assignment (`a -= b`) spelling.
fn subtraction_operands<'a>(site: &Node<'a>) -> Option<(Node<'a>, Node<'a>)> {
    let operator = site.child_by_field_name("operator")?.kind();
    let wanted = match site.kind() {
        "binary_expression" => "-",
        "assignment_expression" => "-=",
        _ => return None,
    };
    if operator != wanted {
        return None;
    }
    Some((
        strip_parens(&site.child_by_field_name("left")?),
        strip_parens(&site.child_by_field_name("right")?),
    ))
}

fn strip_parens<'a>(node: &Node<'a>) -> Node<'a> {
    let mut current = *node;
    while current.kind() == "parenthesized_expression" {
        match current.named_child(0) {
            Some(inner) => current = inner,
            None => break,
        }
    }
    current
}

/// The innermost loop containing `site`, or `None` when `site` is not in one.
///
/// A `do`-`while` is included: unlike [`guard_dominance`]'s enclosing-condition
/// walk, which excludes it because its condition has not run on the first
/// iteration, what matters here is the body's monotonicity, which holds from
/// the first iteration on.
fn enclosing_loop<'a>(site: &Node<'a>) -> Option<Node<'a>> {
    let mut current = site.parent();
    while let Some(node) = current {
        match node.kind() {
            "while_statement" | "for_statement" | "do_statement" => return Some(node),
            "function_definition" => return None,
            _ => {}
        }
        current = node.parent();
    }
    None
}

/// Is the loop's condition a bare truthiness test of `var` — `while (len)` or
/// `while (len != 0)`?
fn loop_condition_is_nonzero_test(loop_node: &Node, var: &str, source: &str) -> bool {
    let Some(condition) = loop_node.child_by_field_name("condition") else {
        return false;
    };
    let condition = strip_parens(&condition);
    if condition.kind() == "identifier" {
        return get_node_text(&condition, source) == var;
    }
    if condition.kind() != "binary_expression" {
        return false;
    }
    if condition.child_by_field_name("operator").map(|o| o.kind()) != Some("!=") {
        return false;
    }
    let (Some(left), Some(right)) = (
        condition.child_by_field_name("left"),
        condition.child_by_field_name("right"),
    ) else {
        return false;
    };
    let (left, right) = (strip_parens(&left), strip_parens(&right));
    let names_var = |n: &Node| n.kind() == "identifier" && get_node_text(n, source) == var;
    let is_zero = |n: &Node| get_node_text(n, source).trim() == "0";
    (names_var(&left) && is_zero(&right)) || (names_var(&right) && is_zero(&left))
}

/// Does an `if (sub == var) break;`-shaped guard precede `site` inside `body`?
///
/// The equality must be between the two operands of the subtraction itself.
/// An equality against any other value bounds nothing, which is the whole
/// reason [`guard_dominance::ComparisonKind::OrderingOrExtremeEquality`]
/// refuses plain equality.
fn equality_break_precedes(
    body: &Node,
    site: &Node,
    var: &str,
    subtrahend: &str,
    source: &str,
) -> bool {
    lang_parsing_substrate::query::find_descendants_of_kind(*body, "if_statement")
        .iter()
        .any(|if_stmt| {
            if if_stmt.start_byte() >= site.start_byte() {
                return false;
            }
            if !exits_loop(if_stmt) {
                return false;
            }
            let Some(condition) = if_stmt.child_by_field_name("condition") else {
                return false;
            };
            condition_equates(&strip_parens(&condition), var, subtrahend, source)
        })
}

/// True when `condition` is `a == b` naming exactly `var` and `subtrahend`, in
/// either operand order.
fn condition_equates(condition: &Node, var: &str, subtrahend: &str, source: &str) -> bool {
    if condition.kind() != "binary_expression" {
        return false;
    }
    if condition.child_by_field_name("operator").map(|o| o.kind()) != Some("==") {
        return false;
    }
    let (Some(left), Some(right)) = (
        condition.child_by_field_name("left"),
        condition.child_by_field_name("right"),
    ) else {
        return false;
    };
    let (left, right) = (
        get_node_text(&strip_parens(&left), source),
        get_node_text(&strip_parens(&right), source),
    );
    (left == var && right == subtrahend) || (left == subtrahend && right == var)
}

/// Does this `if` leave the loop when taken? `break`, `return` and `goto` all
/// do; a `continue` does not, since the subtraction is still reached on a
/// later iteration.
fn exits_loop(if_stmt: &Node) -> bool {
    let Some(consequence) = if_stmt.child_by_field_name("consequence") else {
        return false;
    };
    ["break_statement", "return_statement", "goto_statement"]
        .iter()
        .any(|kind| {
            consequence.kind() == *kind
                || !lang_parsing_substrate::query::find_descendants_of_kind(consequence, kind)
                    .is_empty()
        })
}

/// Every write to `name` inside `body` decreases it (`-=`, `--`,
/// `name = name - …`), or there is none.
fn only_decreases(body: &Node, name: &str, source: &str) -> bool {
    writes_are_monotonic(body, name, source, "-=", "--", "-")
}

/// Every write to `name` inside `body` increases it (`+=`, `++`,
/// `name = name + …`), or there is none.
fn only_increases(body: &Node, name: &str, source: &str) -> bool {
    writes_are_monotonic(body, name, source, "+=", "++", "+")
}

/// `body` decreases `name` at least once.
fn decreases_somewhere(body: &Node, name: &str, source: &str) -> bool {
    has_step(body, name, source, "-=", "--", "-")
}

/// `body` increases `name` at least once.
fn increases_somewhere(body: &Node, name: &str, source: &str) -> bool {
    has_step(body, name, source, "+=", "++", "+")
}

fn has_step(
    body: &Node,
    name: &str,
    source: &str,
    compound: &str,
    update: &str,
    plain: &str,
) -> bool {
    let names_it = |n: &Node| {
        let n = strip_parens(n);
        n.kind() == "identifier" && get_node_text(&n, source) == name
    };

    let stepped_by_assignment =
        lang_parsing_substrate::query::find_descendants_of_kind(*body, "assignment_expression")
            .iter()
            .any(|assign| {
                let Some(left) = assign.child_by_field_name("left") else {
                    return false;
                };
                if !names_it(&left) {
                    return false;
                }
                match assign.child_by_field_name("operator").map(|o| o.kind()) {
                    Some(op) if op == compound => true,
                    Some("=") => assign.child_by_field_name("right").is_some_and(|right| {
                        let right = strip_parens(&right);
                        right.kind() == "binary_expression"
                            && right.child_by_field_name("operator").map(|o| o.kind())
                                == Some(plain)
                            && right
                                .child_by_field_name("left")
                                .is_some_and(|l| names_it(&l))
                    }),
                    _ => false,
                }
            });
    if stepped_by_assignment {
        return true;
    }

    lang_parsing_substrate::query::find_descendants_of_kind(*body, "update_expression")
        .iter()
        .any(|upd| {
            upd.child_by_field_name("argument")
                .is_some_and(|arg| names_it(&arg))
                && upd.child_by_field_name("operator").map(|o| o.kind()) == Some(update)
        })
}

fn writes_are_monotonic(
    body: &Node,
    name: &str,
    source: &str,
    compound: &str,
    update: &str,
    plain: &str,
) -> bool {
    let names_it = |n: &Node| {
        let n = strip_parens(n);
        n.kind() == "identifier" && get_node_text(&n, source) == name
    };

    let assignments_ok =
        lang_parsing_substrate::query::find_descendants_of_kind(*body, "assignment_expression")
            .iter()
            .all(|assign| {
                let Some(left) = assign.child_by_field_name("left") else {
                    return true;
                };
                if !names_it(&left) {
                    return true;
                }
                let Some(operator) = assign.child_by_field_name("operator").map(|o| o.kind())
                else {
                    return false;
                };
                if operator == compound {
                    return true;
                }
                // `name = name - x` is the same step written out.
                if operator != "=" {
                    return false;
                }
                let Some(right) = assign.child_by_field_name("right") else {
                    return false;
                };
                let right = strip_parens(&right);
                right.kind() == "binary_expression"
                    && right.child_by_field_name("operator").map(|o| o.kind()) == Some(plain)
                    && right
                        .child_by_field_name("left")
                        .is_some_and(|l| names_it(&l))
            });
    if !assignments_ok {
        return false;
    }

    lang_parsing_substrate::query::find_descendants_of_kind(*body, "update_expression")
        .iter()
        .all(|upd| {
            let Some(argument) = upd.child_by_field_name("argument") else {
                return true;
            };
            if !names_it(&argument) {
                return true;
            }
            upd.child_by_field_name("operator").map(|o| o.kind()) == Some(update)
        })
}
