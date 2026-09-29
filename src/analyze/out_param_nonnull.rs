// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! Which return values of a function prove that it stored a non-null
//! pointer through one of its out-parameters.
//!
//! The status-code idiom reads a pointer only when the call that fills it
//! reports success:
//!
//! ```c
//! rc = prepare(db, sql, &stmt);
//! if (rc == OK) { ... stmt->... }
//! ```
//!
//! A caller can rely on that only when the callee's own body shows it: every
//! path that returns `OK` has stored a non-null pointer through `*ppStmt`.
//! A name, or the convention that success means a usable result, is not
//! proof (ADR-0011). sqlite's `sqlite3_prepare` returns `SQLITE_OK` with
//! `*ppStmt` set to NULL for an empty statement.
//!
//! The proof is read path by path over the callee's statements. It is
//! deliberately narrow and abandons rather than guesses:
//!
//! - every `return` must return a constant (an integer literal, or a name
//!   that is not a variable in scope: a macro or enumerator). A path that
//!   returns anything else could return any value, so no value is proven;
//! - a loop, `switch`, preprocessor block or label that returns, or that
//!   writes the parameter, abandons the proof; a `goto`, `break` or
//!   `continue` outside one abandons it too;
//! - a stored value is non-null only when it is an address (`&x`), a string
//!   or compound literal, or a local that an earlier test on the same path
//!   proved non-null (`if (!p) return NOMEM;`);
//! - a call that is handed the parameter, or a write through it with a
//!   value not proven non-null, leaves the stored value unproven;
//! - a store that only may run (an arm of `?:`, the right operand of `&&`
//!   or `||`) joins with what was stored before it rather than replacing it;
//! - a statement that is a bare identifier (an object-like macro, which may
//!   hide a `return`) abandons the proof. A function-like macro's hidden
//!   jump is judged where the proof is used, with the project's macro
//!   table: see [`OutParamFacts::proof_calls`].
//!
//! What a path may leave behind is read only for a parameter whose pointee
//! is itself a pointer (`T **pp`): `*pn = 0` through a `size_t *pn` stores
//! an integer, not a null pointer.
//!
//! Constants are compared by their written form: `0` and `SQLITE_OK` are
//! different keys even where the macro expands to `0`, so a caller testing
//! one against a callee returning the other gets no credit. That costs a
//! little recall and never credits a value the callee did not return.

use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::collections::{BTreeSet, HashMap, HashSet};
use tree_sitter::Node;

/// Cap on live paths through one body; past it the proof is abandoned.
const MAX_PATHS: usize = 64;

/// The key a constant return value, or the constant a caller compares a
/// status against, is matched by: the decimal value of an integer literal
/// (`0`, `0x10` as `16`, `-1`), or the spelling of a name that no
/// variable in scope declares (`SQLITE_OK`). `None` for anything else,
/// including a local or parameter that happens to hold a constant.
pub fn constant_key(expr: &Node, source: &str) -> Option<String> {
    let expr = strip_parens_and_casts(*expr);
    match expr.kind() {
        "number_literal" => integer_literal_value(ast_utils::get_node_text(&expr, source)),
        "unary_expression" => {
            let op = expr.child_by_field_name("operator")?;
            let arg = expr.child_by_field_name("argument")?;
            if ast_utils::get_node_text(&op, source) != "-" {
                return None;
            }
            let arg = strip_parens_and_casts(arg);
            if arg.kind() != "number_literal" {
                return None;
            }
            let value = integer_literal_value(ast_utils::get_node_text(&arg, source))?;
            Some(if value == "0" {
                value
            } else {
                format!("-{value}")
            })
        }
        "identifier" => {
            let name = ast_utils::get_node_text(&expr, source);
            ast_utils::resolve_identifier_binding(&expr, name, source)
                .is_none()
                .then(|| name.to_string())
        }
        _ => None,
    }
}

/// What `func`'s body proves about the pointer it leaves in `*param`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OutParamFacts {
    /// The constants the body returns only after storing a provably non-null
    /// pointer through `param` (see the module doc). Empty when nothing is
    /// proven, including when any path returns something that is not a
    /// constant.
    pub nonnull_on_return: Vec<String>,
    /// Some path out of the body leaves a NULL it stored itself in `*param`
    /// (`*ppStmt = 0; ... return rc;`). Read path by path where the walk
    /// completes; where it abandons, any store of a null constant through
    /// `param` counts, since that is still positive evidence of one.
    pub may_leave_null: bool,
    /// The callees whose result some path may store through `param` without
    /// testing it first (`*pp = malloc(n);`, or through a local assigned
    /// from the call). Whether each can return NULL is the callee's own
    /// fact, which is not known while this body alone is read.
    pub may_store_result_of: Vec<String>,
    /// The body stores a null constant through `param` somewhere, though no
    /// path it read leaves it there. A function-like macro that jumps may
    /// still leave it (see [`Self::proof_calls`]).
    pub stores_null_elsewhere: bool,
    /// Every name the body calls. [`Self::nonnull_on_return`] holds, and
    /// [`Self::stores_null_elsewhere`] stays short of a NULL left behind,
    /// only if none of them is a function-like macro that can jump out of
    /// the statement it is invoked in, which the project's macro table
    /// decides.
    pub proof_calls: Vec<String>,
}

/// [`OutParamFacts`] for `func`'s parameter `param`.
pub fn out_param_facts(func: &Node, param: &str, source: &str) -> OutParamFacts {
    let Some(body) = func.child_by_field_name("body") else {
        return OutParamFacts::default();
    };
    let holds_pointer = pointee_is_pointer(func, param, source);
    let proof_calls: Vec<String> = query::find_descendants_of_kind(body, "call_expression")
        .iter()
        .filter_map(|call| callee_name(call, source))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut walk = Walk {
        source,
        param,
        leaves: Vec::new(),
    };
    let Some(fall_through) = walk.block(&body, vec![Path::default()]) else {
        return OutParamFacts {
            nonnull_on_return: Vec::new(),
            may_leave_null: holds_pointer && stores_null_through(&body, param, source),
            may_store_result_of: if holds_pointer {
                results_stored_through(&body, param, source)
            } else {
                Vec::new()
            },
            stores_null_elsewhere: false,
            proof_calls,
        };
    };
    let stored: Vec<&Stored> = walk
        .leaves
        .iter()
        .map(|(stored, _)| stored)
        .chain(fall_through.iter().map(|path| &path.stored))
        .collect();
    let may_leave_null = holds_pointer && stored.iter().any(|s| **s == Stored::Null);
    let stores_null_elsewhere =
        holds_pointer && !may_leave_null && stores_null_through(&body, param, source);
    let may_store_result_of: Vec<String> = if holds_pointer {
        stored
            .iter()
            .filter_map(|s| match s {
                Stored::FromCall(names) => Some(names.iter().cloned()),
                _ => None,
            })
            .flatten()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };
    // Falling off the end returns nothing a caller can test, and a returned
    // value that is not a constant could be any value.
    if !fall_through.is_empty() || walk.leaves.iter().any(|(_, key)| key.is_none()) {
        return OutParamFacts {
            nonnull_on_return: Vec::new(),
            may_leave_null,
            may_store_result_of,
            stores_null_elsewhere,
            proof_calls,
        };
    }
    let mut keys: Vec<String> = walk
        .leaves
        .iter()
        .filter_map(|(_, key)| key.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|key| {
            walk.leaves
                .iter()
                .filter(|(_, k)| k.as_deref() == Some(key.as_str()))
                .all(|(stored, _)| *stored == Stored::NonNull)
        })
        .collect();
    keys.sort();
    OutParamFacts {
        nonnull_on_return: keys,
        may_leave_null,
        may_store_result_of,
        stores_null_elsewhere,
        proof_calls,
    }
}

/// What `*param` holds on one path, as far as this body shows.
#[derive(Clone, Default, PartialEq, Eq)]
enum Stored {
    /// Nothing this body stored: whatever the caller's `p` held.
    #[default]
    Unset,
    /// A pointer the path proves non-null.
    NonNull,
    /// A null constant, or, after a join, possibly one.
    Null,
    /// The untested result of a call to one of these, or, after a join,
    /// possibly one.
    FromCall(BTreeSet<String>),
    /// Some other value, or one a callee handed the parameter may have
    /// changed.
    Unknown,
}

impl Stored {
    /// What `*param` holds where two possibilities meet (a store that may
    /// or may not run, or the arms of `?:`). A possible NULL, then a
    /// possible call result, is kept; a proof holds only if both hold it.
    fn join(self, other: Stored) -> Stored {
        match (self, other) {
            (a, b) if a == b => a,
            (Stored::Null, _) | (_, Stored::Null) => Stored::Null,
            (Stored::FromCall(mut a), Stored::FromCall(b)) => {
                a.extend(b);
                Stored::FromCall(a)
            }
            (Stored::FromCall(a), _) | (_, Stored::FromCall(a)) => Stored::FromCall(a),
            _ => Stored::Unknown,
        }
    }
}

#[derive(Clone, Default)]
struct Path {
    stored: Stored,
    /// Locals this path has proven non-null.
    nonnull: HashSet<String>,
    /// Locals holding the untested result of a call, by callee.
    results: HashMap<String, String>,
}

struct Walk<'s> {
    source: &'s str,
    param: &'s str,
    /// One entry per path that reached a `return`: what it had stored, and
    /// the constant it returned.
    leaves: Vec<(Stored, Option<String>)>,
}

impl Walk<'_> {
    /// The paths that fall through `block`'s statements, or `None` when the
    /// proof is abandoned.
    fn block(&mut self, block: &Node, mut paths: Vec<Path>) -> Option<Vec<Path>> {
        let mut cursor = block.walk();
        let stmts: Vec<Node> = block
            .named_children(&mut cursor)
            .filter(|c| c.kind() != "comment")
            .collect();
        for stmt in stmts {
            if paths.is_empty() {
                break;
            }
            paths = self.statement(&stmt, paths)?;
            if paths.len() > MAX_PATHS {
                return None;
            }
        }
        Some(paths)
    }

    fn statement(&mut self, stmt: &Node, paths: Vec<Path>) -> Option<Vec<Path>> {
        match stmt.kind() {
            "compound_statement" => self.block(stmt, paths),
            "return_statement" => {
                let key = stmt
                    .named_child(0)
                    .and_then(|e| constant_key(&e, self.source));
                for mut path in paths {
                    if let Some(value) = stmt.named_child(0) {
                        self.effects(&value, &mut path)?;
                    }
                    self.leaves.push((path.stored.clone(), key.clone()));
                }
                Some(Vec::new())
            }
            "if_statement" => self.if_statement(stmt, paths),
            "goto_statement" | "break_statement" | "continue_statement" => None,
            // `CHECK_OK;` does nothing unless it is a macro, which may
            // return.
            "expression_statement"
                if stmt
                    .named_child(0)
                    .is_some_and(|e| strip_parens_and_casts(e).kind() == "identifier") =>
            {
                None
            }
            // `exit(1);` ends the path: nothing is returned or left behind.
            "expression_statement"
                if crate::analyze::noreturn::is_stdlib_noreturn_call_statement(
                    stmt,
                    self.source,
                ) =>
            {
                Some(Vec::new())
            }
            "expression_statement" | "declaration" => {
                let mut out = Vec::with_capacity(paths.len());
                for mut path in paths {
                    self.effects(stmt, &mut path)?;
                    out.push(path);
                }
                Some(out)
            }
            _ => {
                // A loop, switch, label or preprocessor block: its paths
                // are not traced. It may not return or write the
                // parameter; anything it assigns is no longer proven.
                if contains_kind(stmt, &["return_statement", "labeled_statement"])
                    || self.mentions_param(stmt)
                {
                    return None;
                }
                let assigned = assigned_names(stmt, self.source);
                Some(
                    paths
                        .into_iter()
                        .map(|mut path| {
                            path.nonnull.retain(|name| !assigned.contains(name));
                            // Nor is a result it so much as mentions still
                            // known to be untested.
                            path.results.retain(|name, _| {
                                !assigned.contains(name) && !mentions(stmt, name, self.source)
                            });
                            path
                        })
                        .collect(),
                )
            }
        }
    }

    fn if_statement(&mut self, stmt: &Node, paths: Vec<Path>) -> Option<Vec<Path>> {
        let cond = stmt.child_by_field_name("condition")?;
        let consequence = stmt.child_by_field_name("consequence")?;
        let alternative = stmt
            .child_by_field_name("alternative")
            .and_then(|alt| alt.named_child(0));
        let (when_true, when_false) = null_test_facts(&cond, self.source);
        let mut out = Vec::new();
        for mut path in paths {
            self.effects(&cond, &mut path)?;
            // A result the code tests is handled, whichever way the branch
            // goes: `if (!s) fatal(); *pp = s;` must not read as storing it
            // untested because `fatal` is not known to end the path. Only
            // the proof of non-null needs the branch.
            for name in when_true.iter().chain(&when_false) {
                path.results.remove(name);
            }
            let mut then_path = path.clone();
            then_path.nonnull.extend(when_true.iter().cloned());
            out.extend(self.statement(&consequence, vec![then_path])?);
            let mut else_path = path;
            else_path.nonnull.extend(when_false.iter().cloned());
            match &alternative {
                Some(alt) => out.extend(self.statement(alt, vec![else_path])?),
                None => out.push(else_path),
            }
        }
        Some(out)
    }

    /// Apply what `node` does to `path`, in source order: stores through
    /// the parameter, assignments to locals, and calls that could change
    /// either. A store that only may run joins with the value before it.
    /// `None` when the parameter itself is reassigned.
    fn effects(&self, node: &Node, path: &mut Path) -> Option<()> {
        for n in query::find_descendants(*node, |_| true) {
            let may_not_run = runs_conditionally(&n, node);
            match n.kind() {
                "assignment_expression" => {
                    let left = n.child_by_field_name("left")?;
                    let right = n.child_by_field_name("right")?;
                    let op = n
                        .child_by_field_name("operator")
                        .map(|o| ast_utils::get_node_text(&o, self.source))
                        .unwrap_or("=");
                    if self.is_store_through_param(&left) {
                        let value = if op != "=" {
                            Stored::Unknown
                        } else {
                            self.classify(&right, path)
                        };
                        self.store(path, value, may_not_run);
                    } else if left.kind() == "identifier" {
                        let name = ast_utils::get_node_text(&left, self.source);
                        if name == self.param {
                            return None;
                        }
                        let assigned = (op == "=").then_some(right);
                        self.assign_local(path, name, assigned.as_ref(), may_not_run);
                    }
                }
                "init_declarator" => {
                    let Some(declarator) = n.child_by_field_name("declarator") else {
                        continue;
                    };
                    let name = ast_utils::get_identifier_from_declarator(&declarator, self.source);
                    let value = n.child_by_field_name("value");
                    self.assign_local(path, &name, value.as_ref(), may_not_run);
                }
                "update_expression" => {
                    if let Some(arg) = n.child_by_field_name("argument") {
                        let name = ast_utils::get_node_text(&arg, self.source);
                        path.nonnull.remove(name);
                        path.results.remove(name);
                    }
                }
                "call_expression" => {
                    let Some(args) = n.child_by_field_name("arguments") else {
                        continue;
                    };
                    let mut cursor = args.walk();
                    for arg in args.named_children(&mut cursor) {
                        if self.mentions_param(&arg) {
                            self.store(path, Stored::Unknown, may_not_run);
                        }
                        // `assert(s)`, `CHECK(s != NULL)`: tested.
                        let (t, f) = null_test_facts(&arg, self.source);
                        for name in t.iter().chain(&f) {
                            path.results.remove(name);
                        }
                        let arg = strip_parens_and_casts(arg);
                        if ast_utils::is_address_of_expression(&arg, self.source) {
                            if let Some(target) = arg.child_by_field_name("argument") {
                                let name = ast_utils::get_node_text(&target, self.source);
                                path.nonnull.remove(name);
                                path.results.remove(name);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Some(())
    }

    /// Record a store of `value` through the parameter; one that may not
    /// run joins with what was there.
    fn store(&self, path: &mut Path, value: Stored, may_not_run: bool) {
        path.stored = if may_not_run {
            std::mem::take(&mut path.stored).join(value)
        } else {
            value
        };
    }

    /// Record `name = value` (`None`: a compound assignment, or a
    /// declaration without an initializer). A proof that the local is
    /// non-null needs the assignment to run; that it may hold a call's
    /// untested result holds either way.
    fn assign_local(&self, path: &mut Path, name: &str, value: Option<&Node>, may_not_run: bool) {
        let proven = !may_not_run && value.is_some_and(|v| self.value_nonnull(v, path));
        if proven {
            path.nonnull.insert(name.to_string());
        } else {
            path.nonnull.remove(name);
        }
        match value.and_then(|v| call_result(v, self.source)) {
            Some(callee) => {
                path.results.insert(name.to_string(), callee);
            }
            None if !may_not_run => {
                path.results.remove(name);
            }
            None => {}
        }
    }

    /// What storing `value` through the parameter leaves there.
    fn classify(&self, value: &Node, path: &Path) -> Stored {
        if self.value_nonnull(value, path) {
            return Stored::NonNull;
        }
        if is_null_constant(value, self.source) {
            return Stored::Null;
        }
        if let Some(callee) = call_result(value, self.source) {
            return Stored::FromCall(BTreeSet::from([callee]));
        }
        let value = strip_parens_and_casts(*value);
        match value.kind() {
            "conditional_expression" => {
                let arm = |field| {
                    value
                        .child_by_field_name(field)
                        .map_or(Stored::Unknown, |v| self.classify(&v, path))
                };
                arm("consequence").join(arm("alternative"))
            }
            "identifier" => path
                .results
                .get(ast_utils::get_node_text(&value, self.source))
                .map_or(Stored::Unknown, |callee| {
                    Stored::FromCall(BTreeSet::from([callee.clone()]))
                }),
            _ => Stored::Unknown,
        }
    }

    /// `*param`, `*(param)` or `param[0]`: the object the caller's `&p`
    /// names.
    fn is_store_through_param(&self, left: &Node) -> bool {
        let left = strip_parens_and_casts(*left);
        let base = match left.kind() {
            "pointer_expression" if ast_utils::is_dereference_expression(&left, self.source) => {
                left.child_by_field_name("argument")
            }
            "subscript_expression" => {
                let index_is_zero = left
                    .child_by_field_name("index")
                    .is_some_and(|i| constant_key(&i, self.source).as_deref() == Some("0"));
                if !index_is_zero {
                    return false;
                }
                left.child_by_field_name("argument")
            }
            _ => None,
        };
        base.map(strip_parens_and_casts).is_some_and(|b| {
            b.kind() == "identifier" && ast_utils::get_node_text(&b, self.source) == self.param
        })
    }

    fn value_nonnull(&self, value: &Node, path: &Path) -> bool {
        let value = strip_parens_and_casts(*value);
        match value.kind() {
            "string_literal" | "concatenated_string" | "compound_literal_expression" => true,
            "pointer_expression" => ast_utils::is_address_of_expression(&value, self.source),
            "identifier" => path
                .nonnull
                .contains(ast_utils::get_node_text(&value, self.source)),
            _ => false,
        }
    }

    fn mentions_param(&self, node: &Node) -> bool {
        mentions(node, self.param, self.source)
    }
}

/// The locals a condition proves non-null when it is true, and when it is
/// false: `p`, `p != NULL` and `NULL != p` prove `p` when true; `!p`,
/// `p == NULL` when false. A conjunction proves each conjunct's true facts;
/// a disjunction proves each disjunct's false facts.
pub(crate) fn null_test_facts(cond: &Node, source: &str) -> (Vec<String>, Vec<String>) {
    let cond = strip_parens_and_casts(*cond);
    match cond.kind() {
        "identifier" => (vec![ast_utils::get_node_text_owned(&cond, source)], vec![]),
        "unary_expression" => {
            let is_not = cond
                .child_by_field_name("operator")
                .is_some_and(|o| ast_utils::get_node_text(&o, source) == "!");
            match (is_not, cond.child_by_field_name("argument")) {
                (true, Some(arg)) => {
                    let (t, f) = null_test_facts(&arg, source);
                    (f, t)
                }
                _ => (vec![], vec![]),
            }
        }
        "binary_expression" => {
            let op = cond
                .child_by_field_name("operator")
                .map(|o| ast_utils::get_node_text(&o, source))
                .unwrap_or("");
            let (Some(left), Some(right)) = (
                cond.child_by_field_name("left"),
                cond.child_by_field_name("right"),
            ) else {
                return (vec![], vec![]);
            };
            match op {
                "&&" => {
                    let (mut t, _) = null_test_facts(&left, source);
                    t.extend(null_test_facts(&right, source).0);
                    (t, vec![])
                }
                "||" => {
                    let (_, mut f) = null_test_facts(&left, source);
                    f.extend(null_test_facts(&right, source).1);
                    (vec![], f)
                }
                "==" | "!=" => {
                    let is_null = |n: &Node| {
                        crate::analyze::null_state::is_null_value(ast_utils::get_node_text(
                            n, source,
                        ))
                    };
                    let tested = if is_null(&right) {
                        Some(strip_parens_and_casts(left))
                    } else if is_null(&left) {
                        Some(strip_parens_and_casts(right))
                    } else {
                        None
                    };
                    match tested.filter(|n| n.kind() == "identifier") {
                        Some(id) => {
                            let name = vec![ast_utils::get_node_text_owned(&id, source)];
                            if op == "!=" {
                                (name, vec![])
                            } else {
                                (vec![], name)
                            }
                        }
                        None => (vec![], vec![]),
                    }
                }
                _ => (vec![], vec![]),
            }
        }
        _ => (vec![], vec![]),
    }
}

fn is_null_constant(value: &Node, source: &str) -> bool {
    let value = strip_parens_and_casts(*value);
    crate::analyze::null_state::is_null_value(ast_utils::get_node_text(&value, source))
}

/// Whether `node`, read as part of `root`, runs only on some evaluations of
/// `root`: under an arm of `?:`, or in the right operand of `&&` / `||`.
fn runs_conditionally(node: &Node, root: &Node) -> bool {
    let mut child = *node;
    while child.id() != root.id() {
        let Some(parent) = child.parent() else {
            return false;
        };
        let is_field = |field| {
            parent
                .child_by_field_name(field)
                .is_some_and(|c| c.id() == child.id())
        };
        match parent.kind() {
            "conditional_expression" if !is_field("condition") => return true,
            "binary_expression" if is_field("right") => {
                let op = parent.child_by_field_name("operator").map(|o| o.kind());
                if matches!(op, Some("&&" | "||")) {
                    return true;
                }
            }
            _ => {}
        }
        child = parent;
    }
    false
}

/// Whether the identifier `name` occurs anywhere in `node`.
fn mentions(node: &Node, name: &str, source: &str) -> bool {
    query::find_descendants(*node, |_| true)
        .iter()
        .any(|n| n.kind() == "identifier" && ast_utils::get_node_text(n, source) == name)
}

/// The callee `value` is a direct call to (through casts and parentheses).
fn call_result(value: &Node, source: &str) -> Option<String> {
    let value = strip_parens_and_casts(*value);
    if value.kind() != "call_expression" {
        return None;
    }
    callee_name(&value, source)
}

/// The name a call spells its callee with, when it is a plain identifier.
fn callee_name(call: &Node, source: &str) -> Option<String> {
    let function = call.child_by_field_name("function")?;
    (function.kind() == "identifier").then(|| ast_utils::get_node_text_owned(&function, source))
}

/// Whether `func`'s parameter `param` points to a pointer: declared with two
/// pointer or array layers (`T **pp`, `T *pp[]`).
fn pointee_is_pointer(func: &Node, param: &str, source: &str) -> bool {
    fn layers(declarator: &Node) -> usize {
        match declarator.kind() {
            "pointer_declarator" | "array_declarator" => {
                1 + declarator
                    .child_by_field_name("declarator")
                    .map_or(0, |d| layers(&d))
            }
            "parenthesized_declarator" => declarator.named_child(0).map_or(0, |d| layers(&d)),
            _ => 0,
        }
    }
    let Some(list) = func.child_by_field_name("declarator").and_then(|d| {
        query::find_descendants_of_kind(d, "parameter_list")
            .into_iter()
            .next()
    }) else {
        return false;
    };
    let mut cursor = list.walk();
    let found = list
        .named_children(&mut cursor)
        .filter(|p| p.kind() == "parameter_declaration")
        .filter_map(|p| p.child_by_field_name("declarator"))
        .find(|d| ast_utils::get_identifier_from_declarator(d, source) == param);
    found.is_some_and(|d| layers(&d) >= 2)
}

/// The callees whose result `body` stores directly through `param`
/// anywhere (`*pp = malloc(n)`): positive evidence of such a store where the
/// path walk abandons.
fn results_stored_through(body: &Node, param: &str, source: &str) -> Vec<String> {
    let walk = Walk {
        source,
        param,
        leaves: Vec::new(),
    };
    query::find_descendants_of_kind(*body, "assignment_expression")
        .iter()
        .filter(|a| {
            a.child_by_field_name("left")
                .is_some_and(|l| walk.is_store_through_param(&l))
        })
        .filter_map(|a| call_result(&a.child_by_field_name("right")?, source))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Whether `body` anywhere stores a null constant through `param`
/// (`*param = NULL`, `*(param) = 0`, `param[0] = NULL`).
fn stores_null_through(body: &Node, param: &str, source: &str) -> bool {
    let walk = Walk {
        source,
        param,
        leaves: Vec::new(),
    };
    query::find_descendants_of_kind(*body, "assignment_expression")
        .iter()
        .any(|a| {
            a.child_by_field_name("left")
                .is_some_and(|l| walk.is_store_through_param(&l))
                && a.child_by_field_name("right")
                    .is_some_and(|r| is_null_constant(&r, source))
        })
}

fn assigned_names(node: &Node, source: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    for n in query::find_descendants(*node, |_| true) {
        let target = match n.kind() {
            "assignment_expression" => n.child_by_field_name("left"),
            "update_expression" => n.child_by_field_name("argument"),
            "init_declarator" => n.child_by_field_name("declarator"),
            _ => None,
        };
        if let Some(t) = target {
            names.insert(ast_utils::get_identifier_from_declarator(&t, source));
        }
        if ast_utils::is_address_of_expression(&n, source) {
            if let Some(t) = n.child_by_field_name("argument") {
                names.insert(ast_utils::get_node_text_owned(&t, source));
            }
        }
    }
    names
}

fn contains_kind(node: &Node, kinds: &[&str]) -> bool {
    !query::find_descendants_of_kinds(*node, kinds).is_empty()
}

fn strip_parens_and_casts(mut node: Node) -> Node {
    loop {
        node = match node.kind() {
            "parenthesized_expression" => match node.named_child(0) {
                Some(inner) => inner,
                None => return node,
            },
            "cast_expression" => match node.child_by_field_name("value") {
                Some(inner) => inner,
                None => return node,
            },
            _ => return node,
        };
    }
}

/// The decimal value of an integer literal's text, suffixes and all
/// (`0`, `0x1F`, `010`, `42UL`); `None` for a floating literal.
fn integer_literal_value(text: &str) -> Option<String> {
    if let Some(magnitude) = text.strip_prefix('-') {
        let value = integer_literal_value(magnitude.trim_start())?;
        return Some(if value == "0" {
            value
        } else {
            format!("-{value}")
        });
    }
    let digits = text.trim_end_matches(['u', 'U', 'l', 'L']);
    let value = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        u128::from_str_radix(hex, 16).ok()?
    } else if let Some(bin) = digits
        .strip_prefix("0b")
        .or_else(|| digits.strip_prefix("0B"))
    {
        u128::from_str_radix(bin, 2).ok()?
    } else if digits.len() > 1 && digits.starts_with('0') {
        u128::from_str_radix(&digits[1..], 8).ok()?
    } else {
        digits.parse::<u128>().ok()?
    };
    Some(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(code: &str, func: &str, param: &str) -> OutParamFacts {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let def = query::find_descendants_of_kind(tree.root_node(), "function_definition")
            .into_iter()
            .find(|f| ast_utils::get_node_text(f, code).contains(&format!("{func}(")))
            .expect("function defined");
        out_param_facts(&def, param, code)
    }

    #[test]
    fn a_guarded_allocation_stored_before_ok_is_proven() {
        let f = facts(
            "int f(int **pp) { int *s; *pp = 0; s = malloc(4); if (!s) return 7; *pp = s; return 0; }",
            "f",
            "pp",
        );
        assert_eq!(f.nonnull_on_return, vec!["0".to_string()]);
        assert!(f.may_leave_null);
    }

    #[test]
    fn a_path_returning_ok_with_null_proves_nothing_for_ok() {
        let f = facts(
            "int f(const char *q, int **pp) { *pp = 0; if (!q[0]) return OK; *pp = &g; return OK; }",
            "f",
            "pp",
        );
        assert!(f.nonnull_on_return.is_empty());
        assert!(f.may_leave_null);
    }

    #[test]
    fn a_returned_variable_proves_nothing() {
        let f = facts(
            "int f(int **pp) { int rc = 0; *pp = &g; return rc; }",
            "f",
            "pp",
        );
        assert!(f.nonnull_on_return.is_empty());
        assert!(!f.may_leave_null);
    }

    #[test]
    fn handing_the_parameter_to_a_call_unproves_the_store() {
        let f = facts(
            "int f(int **pp) { *pp = &g; reset(pp); return 0; }",
            "f",
            "pp",
        );
        assert!(f.nonnull_on_return.is_empty());
    }

    #[test]
    fn a_goto_abandons_the_walk_but_a_null_store_still_counts() {
        let f = facts(
            "int f(int **pp) { *pp = 0; goto out; out: return 1; }",
            "f",
            "pp",
        );
        assert!(f.nonnull_on_return.is_empty());
        assert!(f.may_leave_null);
    }

    #[test]
    fn a_zero_stored_through_an_integer_pointer_is_no_null() {
        let f = facts(
            "int f(unsigned long *pn) { *pn = 0; *pn = 4; return 0; }",
            "f",
            "pn",
        );
        assert!(!f.may_leave_null);
        let f = facts("int f(unsigned long *pn) { *pn = 0; return 0; }", "f", "pn");
        assert!(!f.may_leave_null);
        assert!(!f.stores_null_elsewhere);
    }

    #[test]
    fn a_conditional_store_joins_with_the_one_before() {
        let f = facts(
            "int f(int c, int **pp) { c ? (*pp = 0) : (*pp = &g); return 0; }",
            "f",
            "pp",
        );
        assert!(f.nonnull_on_return.is_empty());
        assert!(f.may_leave_null);
        let f = facts(
            "int f(int c, int **pp) { *pp = &g; c && (*pp = 0); return 0; }",
            "f",
            "pp",
        );
        assert!(f.nonnull_on_return.is_empty());
        assert!(f.may_leave_null);
        let f = facts(
            "int f(int c, int **pp) { *pp = c ? &g : &h; return 0; }",
            "f",
            "pp",
        );
        assert_eq!(f.nonnull_on_return, vec!["0".to_string()]);
    }

    #[test]
    fn an_untested_call_result_is_named_and_a_tested_one_is_not() {
        let f = facts("void f(char **pp) { *pp = malloc(4); }", "f", "pp");
        assert_eq!(f.may_store_result_of, vec!["malloc".to_string()]);
        let f = facts(
            "void f(char **pp) { char *s = malloc(4); *pp = s; }",
            "f",
            "pp",
        );
        assert_eq!(f.may_store_result_of, vec!["malloc".to_string()]);
        let f = facts(
            "void f(char **pp) { char *s = malloc(4); if (!s) die(); *pp = s; }",
            "f",
            "pp",
        );
        assert!(f.may_store_result_of.is_empty());
        let f = facts(
            "void f(char **pp) { char *s = malloc(4); assert(s); *pp = s; }",
            "f",
            "pp",
        );
        assert!(f.may_store_result_of.is_empty());
    }

    #[test]
    fn a_bare_name_statement_abandons_the_proof() {
        let f = facts(
            "int f(int **pp) { *pp = 0; BAIL; *pp = &g; return 0; }",
            "f",
            "pp",
        );
        assert!(f.nonnull_on_return.is_empty());
        assert!(f.may_leave_null);
    }

    #[test]
    fn constants_are_keyed_by_value_or_name() {
        let code = "int x = 0x10; int y = -1; int z = OK;";
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let keys: Vec<Option<String>> =
            query::find_descendants_of_kind(tree.root_node(), "init_declarator")
                .iter()
                .map(|d| constant_key(&d.child_by_field_name("value").unwrap(), code))
                .collect();
        assert_eq!(
            keys,
            vec![Some("16".into()), Some("-1".into()), Some("OK".into())]
        );
    }
}
