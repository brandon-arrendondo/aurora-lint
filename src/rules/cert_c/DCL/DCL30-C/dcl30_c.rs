// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! DCL30-C: Declare objects with appropriate storage durations
//!
//! Reports the address of an object with automatic storage duration escaping
//! the call that owns it (TS 17961 5.2, addrescape): returned, or stored in
//! an object that outlives the call. What is reported is the POINTEE, an
//! automatic object, never a pointer variable for its name.
//!
//! VIOLATIONS:
//! - `return buf;` / `return &x;` / `return &s.m;` / `return (int[]){1};`
//! - `char *p = &buf[1]; return p;`   -- the pointer's value is known
//! - `global = buf;` / `global = &param;` / `file_static.p = &x;`
//! - `*out = local;` / `out->p = &x;` -- storage the caller owns
//!
//! COMPLIANT:
//! - `return p;` where `p` holds heap, static, a parameter's value, or
//!   anything the function's body does not decide
//! - `static char buf[10]; return buf;`
//! - `global = &x; use(); global = NULL;` -- reset before every return
//!
//! The object questions are `utility::cert_c::automatic_storage`'s.

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{
    declaration_has_storage_class, declaration_is_thread_local, get_node_text, IdentifierBinding,
    ScopeDeclarations,
};
use crate::utility::cert_c::automatic_storage::{
    automatic_address, names_array_object, pointer_value_origin, AutomaticKind, AutomaticObject,
};
use crate::utility::cert_c::guard_dominance::WriteIndex;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Dcl30C;

impl CertRule for Dcl30C {
    fn rule_id(&self) -> &'static str {
        "DCL30-C"
    }

    fn description(&self) -> &'static str {
        "Declare objects with appropriate storage durations"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "DCL30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        // Innermost function first: parser recovery can nest one definition
        // inside another, and each site is judged once, in the frame that
        // owns it.
        let mut seen = std::collections::HashSet::new();
        // Every name the checks resolve, through one index of the file.
        let scopes = ScopeDeclarations::indexed(*node);
        let functions = query::find_descendants_of_kind(*node, "function_definition");
        for func in functions.iter().rev() {
            let Some(body) = func.child_by_field_name("body") else {
                continue;
            };
            let index = WriteIndex::new(&body, source);
            for found in query::find_descendants_of_kinds(
                body,
                &["return_statement", "assignment_expression"],
            ) {
                if !seen.insert(found.id()) {
                    continue;
                }
                let violation = match found.kind() {
                    "return_statement" => check_return(&found, &scopes, source, &index),
                    _ => check_store(&found, &body, &scopes, source, &index),
                };
                violations.extend(violation);
            }
        }
        violations
    }
}

/// The automatic object whose address `value` is when `site` executes: read
/// from the expression, or, for a pointer variable, from the value its body
/// last stored in it on every path to `site`.
fn escaping_object<'a>(
    value: &Node<'a>,
    site: &Node<'a>,
    scopes: &ScopeDeclarations<'a>,
    source: &str,
    index: &WriteIndex,
) -> Option<AutomaticObject<'a>> {
    automatic_address(value, scopes, source)
        .or_else(|| pointer_value_origin(value, site, scopes, source, index))
}

/// `return E;` where E is the address of an automatic object of this call.
fn check_return<'a>(
    ret: &Node<'a>,
    scopes: &ScopeDeclarations<'a>,
    source: &str,
    index: &WriteIndex,
) -> Option<RuleViolation> {
    let value = ret
        .named_children(&mut ret.walk())
        .find(|c| c.kind() != "comment")?;
    let object = escaping_object(&value, ret, scopes, source, index)?;
    Some(violation(
        ret,
        format!(
            "Function returns the address of {}, whose lifetime ends when the function returns",
            describe(&object)
        ),
    ))
}

/// `T = E;` where E is the address of an automatic object of this call and T
/// outlives it, unless T is reset to something else before every return.
fn check_store<'a>(
    assign: &Node<'a>,
    body: &Node<'a>,
    scopes: &ScopeDeclarations<'a>,
    source: &str,
    index: &WriteIndex,
) -> Option<RuleViolation> {
    let op = assign.child_by_field_name("operator")?;
    if get_node_text(&op, source) != "=" {
        return None;
    }
    let left = assign.child_by_field_name("left")?;
    let right = assign.child_by_field_name("right")?;
    let target = outliving_target(&left, assign, scopes, source, index)?;
    let object = escaping_object(&right, assign, scopes, source, index)?;
    if reset_before_every_return(assign, &left, body, scopes, source, index) {
        return None;
    }
    Some(violation(
        assign,
        format!(
            "The address of {} is stored in '{}' ({}), which outlives it",
            describe(&object),
            compact(get_node_text(&left, source)),
            target
        ),
    ))
}

/// Why `lvalue` outlives this call, or `None` when it does not or is not
/// known to: it lies in a file-scope, `static`, `extern` or thread-storage
/// object, or it is reached through a dereference of a parameter (storage
/// the caller owns) that still holds the caller's value at `site`. A path
/// through a local pointer reaches storage nothing here can name, a
/// parameter retargeted to a local (`out = &tmp; *out = &x;`) reaches this
/// call's own storage, and a local or parameter object itself dies with the
/// call.
fn outliving_target<'a>(
    lvalue: &Node<'a>,
    site: &Node<'a>,
    scopes: &ScopeDeclarations<'a>,
    source: &str,
    index: &WriteIndex,
) -> Option<&'static str> {
    let mut node = strip(*lvalue);
    let mut through_pointer = false;
    loop {
        match node.kind() {
            "identifier" => break,
            "field_expression" => {
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, source) == "->")
                {
                    through_pointer = true;
                }
                node = strip(node.child_by_field_name("argument")?);
            }
            "subscript_expression" => {
                let base = strip(node.child_by_field_name("argument")?);
                if !(base.kind() == "identifier" && names_array_object(&base, scopes, source)) {
                    through_pointer = true;
                }
                node = base;
            }
            "pointer_expression" => {
                let op = node.child_by_field_name("operator")?;
                if get_node_text(&op, source) != "*" {
                    return None;
                }
                through_pointer = true;
                node = strip(node.child_by_field_name("argument")?);
            }
            _ => return None,
        }
    }
    let name = get_node_text(&node, source);
    let (decl, declarator) = scopes.resolve_identifier_declarator(&node, name, source)?;
    if declarator.kind() == "function_declarator" {
        return None;
    }
    match scopes.resolve_identifier_binding(&node, name, source)? {
        IdentifierBinding::Global(_) => Some("file scope"),
        IdentifierBinding::Local(_)
            if declaration_has_storage_class(&decl, "static", source)
                || declaration_has_storage_class(&decl, "extern", source)
                || declaration_is_thread_local(&decl, source) =>
        {
            Some("static storage")
        }
        IdentifierBinding::Parameter(_)
            if through_pointer
                && pointer_value_origin(&node, site, scopes, source, index).is_none() =>
        {
            Some("the caller's storage")
        }
        _ => None,
    }
}

/// Whether, after the store `assign`, the target (or an object containing
/// it: `p->hook = saved` resets `p->hook.ctx`) is assigned a value that is
/// not an automatic address on the way out of every block holding the store,
/// before anything leaves those blocks early. Then the address never
/// outlives the call: `db->pnBytesFreed = &n; ...; db->pnBytesFreed = 0;`.
///
/// Walks outward from the statement holding the store. In each enclosing
/// block (`{}`, a `case`, or a preprocessor arm, whose sibling `#else` and
/// `#elif` arms are another build's code and are skipped) the statements
/// after it are read in order:
/// - a reset statement answers;
/// - a statement holding `return` or `goto`, or a `break`/`continue` with no
///   target in the function, may leave with the address still stored, so
///   the answer is no;
/// - a `break` or `continue` whose loop or `switch` encloses the store lands
///   where the walk will resume after that statement, so it leaves nothing;
///   but it skips whatever follows inside that statement, so a reset found
///   there no longer answers, and the walk goes on after the statement;
/// - at the end of the block the walk continues after the statement that
///   owns the block, and at the end of the function body the answer is no.
///
/// A later store of another automatic address is no reset. A reset made by
/// a callee is not seen.
fn reset_before_every_return<'a>(
    assign: &Node<'a>,
    left: &Node<'a>,
    body: &Node<'a>,
    scopes: &ScopeDeclarations<'a>,
    source: &str,
    index: &WriteIndex,
) -> bool {
    let target = compact(get_node_text(left, source));
    let mut current = *assign;
    // The outermost loop or `switch` a jump seen so far lands after: a reset
    // inside it misses that jump's path.
    let mut skipped_to: Option<Node> = None;
    'walk: loop {
        // The statement holding `current`, directly inside a block.
        let Some(parent) = current.parent() else {
            return false;
        };
        if !BLOCK_KINDS.contains(&parent.kind()) {
            current = parent;
            continue;
        }
        let other_arm = parent.child_by_field_name("alternative").map(|a| a.id());
        let mut cursor = parent.walk();
        for stmt in parent.named_children(&mut cursor) {
            if stmt.start_byte() <= current.start_byte() || Some(stmt.id()) == other_arm {
                continue;
            }
            if let Some((e, value)) = reset_of(&stmt, &target, left, scopes, source) {
                if escaping_object(&value, &e, scopes, source, index).is_some() {
                    return false;
                }
                match skipped_to {
                    Some(owner) if encloses(&owner, &stmt) => {
                        current = owner;
                        continue 'walk;
                    }
                    _ => return true,
                }
            }
            match jump_exit(&stmt, body) {
                JumpExit::None => {}
                JumpExit::Leaves => return false,
                JumpExit::After(owner) => {
                    if skipped_to.is_none_or(|s| encloses(&owner, &s)) {
                        skipped_to = Some(owner);
                    }
                }
            }
        }
        if parent.id() == body.id() {
            return false;
        }
        current = parent;
    }
}

/// Blocks whose children run in order at one level: a `{}` body, a `case`,
/// and a preprocessor arm (aurora-lint does not preprocess, so an
/// `#ifdef`-guarded region is a node of its own).
const BLOCK_KINDS: &[&str] = &[
    "compound_statement",
    "case_statement",
    "preproc_if",
    "preproc_ifdef",
    "preproc_else",
    "preproc_elif",
    "preproc_elifdef",
];

/// Where the jumps in a statement can take control, seen from outside it.
enum JumpExit<'a> {
    /// Every jump in it lands inside it.
    None,
    /// A `return`, a `goto`, or a `break`/`continue` with no target in the
    /// function body.
    Leaves,
    /// A `break` or `continue` lands at the end of, or the next iteration
    /// of, this enclosing loop or `switch` (the outermost such, when several).
    After(Node<'a>),
}

/// Where the jumps in `stmt` can go: a `return` or `goto` at any depth
/// leaves; a `break`/`continue` that a loop (or, for `break`, a `switch`)
/// inside `stmt` captures stays; one whose loop or `switch` lies outside
/// `stmt` but inside `body` goes after that statement.
fn jump_exit<'a>(stmt: &Node<'a>, body: &Node<'a>) -> JumpExit<'a> {
    let kinds = [
        "return_statement",
        "goto_statement",
        "break_statement",
        "continue_statement",
    ];
    let jumps = if kinds.contains(&stmt.kind()) {
        vec![*stmt]
    } else {
        query::find_descendants_of_kinds(*stmt, &kinds)
    };
    let mut outermost: Option<Node> = None;
    for jump in jumps {
        if matches!(jump.kind(), "return_statement" | "goto_statement") {
            return JumpExit::Leaves;
        }
        let captured_by: &[&str] = if jump.kind() == "break_statement" {
            &[
                "for_statement",
                "while_statement",
                "do_statement",
                "switch_statement",
            ]
        } else {
            &["for_statement", "while_statement", "do_statement"]
        };
        let mut node = jump.parent();
        let target = loop {
            match node {
                Some(n) if captured_by.contains(&n.kind()) => break Some(n),
                Some(n) if n.id() == body.id() => break None,
                Some(n) => node = n.parent(),
                None => break None,
            }
        };
        match target {
            None => return JumpExit::Leaves,
            Some(t) if encloses(stmt, &t) => {}
            Some(t) => {
                if outermost.is_none_or(|o| encloses(&t, &o)) {
                    outermost = Some(t);
                }
            }
        }
    }
    outermost.map_or(JumpExit::None, JumpExit::After)
}

/// The assignment and its value when `stmt` is `T = value;` for `T` the
/// stored target (spelled `target`, rooted at `left`'s variable) or an
/// object containing it.
fn reset_of<'a>(
    stmt: &Node<'a>,
    target: &str,
    left: &Node<'a>,
    scopes: &ScopeDeclarations<'a>,
    source: &str,
) -> Option<(Node<'a>, Node<'a>)> {
    if stmt.kind() != "expression_statement" {
        return None;
    }
    let e = stmt.named_child(0)?;
    if e.kind() != "assignment_expression"
        || get_node_text(&e.child_by_field_name("operator")?, source) != "="
    {
        return None;
    }
    let l = e.child_by_field_name("left")?;
    let spelled = compact(get_node_text(&l, source));
    let contains = spelled == target
        || target
            .strip_prefix(spelled.as_str())
            .is_some_and(|rest| rest.starts_with('.') || rest.starts_with("->"));
    (contains && same_root(&l, left, scopes, source))
        .then(|| e.child_by_field_name("right").map(|r| (e, r)))?
}

/// Whether `outer` spans `inner` (or is it).
fn encloses(outer: &Node, inner: &Node) -> bool {
    outer.start_byte() <= inner.start_byte() && inner.end_byte() <= outer.end_byte()
}

/// Whether two lvalues of the same spelling name the same root variable:
/// each root identifier resolves to the same declarator.
fn same_root<'a>(a: &Node<'a>, b: &Node<'a>, scopes: &ScopeDeclarations<'a>, source: &str) -> bool {
    let decl = |n: &Node<'a>| {
        let mut n = strip(*n);
        while n.kind() != "identifier" {
            n = strip(
                n.child_by_field_name("argument")
                    .or_else(|| n.child_by_field_name("left"))?,
            );
        }
        let name = get_node_text(&n, source);
        scopes
            .resolve_identifier_declarator(&n, name, source)
            .map(|(_, d)| d.id())
    };
    match (decl(a), decl(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

fn describe(object: &AutomaticObject) -> String {
    match object.kind {
        AutomaticKind::Local => format!("automatic object '{}'", object.name),
        AutomaticKind::Parameter => format!("parameter '{}'", object.name),
        AutomaticKind::CompoundLiteral => {
            let text = compact(&object.name);
            if text.chars().count() <= 40 {
                format!("compound literal '{}'", text)
            } else {
                "a compound literal".to_string()
            }
        }
    }
}

/// `text` with whitespace runs collapsed, for messages and comparison.
fn compact(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn strip(node: Node) -> Node {
    match node.kind() {
        "parenthesized_expression" | "cast_expression" => {
            let inner = if node.kind() == "cast_expression" {
                node.child_by_field_name("value")
            } else {
                node.named_children(&mut node.walk())
                    .find(|c| c.kind() != "comment")
            };
            inner.map_or(node, strip)
        }
        _ => node,
    }
}

fn violation(node: &Node, message: String) -> RuleViolation {
    let start = node.start_position();
    RuleViolation {
        rule_id: "DCL30-C".to_string(),
        severity: Severity::High,
        message,
        file_path: String::new(),
        line: start.row + 1,
        column: start.column + 1,
        suggestion: Some(
            "Use static or allocated storage, or have the caller provide the object".to_string(),
        ),
        ..Default::default()
    }
}
