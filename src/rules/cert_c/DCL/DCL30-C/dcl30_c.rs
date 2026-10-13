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
    declaration_has_storage_class, declaration_is_thread_local, get_node_text,
    resolve_identifier_binding, resolve_identifier_declarator, IdentifierBinding,
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
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            let Some(body) = func.child_by_field_name("body") else {
                continue;
            };
            let index = WriteIndex::new(&body, source);
            for found in query::find_descendants_of_kinds(
                body,
                &["return_statement", "assignment_expression"],
            ) {
                let violation = match found.kind() {
                    "return_statement" => check_return(&found, source, &index),
                    _ => check_store(&found, &body, source, &index),
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
    source: &str,
    index: &WriteIndex,
) -> Option<AutomaticObject<'a>> {
    automatic_address(value, source).or_else(|| pointer_value_origin(value, site, source, index))
}

/// `return E;` where E is the address of an automatic object of this call.
fn check_return(ret: &Node, source: &str, index: &WriteIndex) -> Option<RuleViolation> {
    let value = ret
        .named_children(&mut ret.walk())
        .find(|c| c.kind() != "comment")?;
    let object = escaping_object(&value, ret, source, index)?;
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
fn check_store(
    assign: &Node,
    body: &Node,
    source: &str,
    index: &WriteIndex,
) -> Option<RuleViolation> {
    let op = assign.child_by_field_name("operator")?;
    if get_node_text(&op, source) != "=" {
        return None;
    }
    let left = assign.child_by_field_name("left")?;
    let right = assign.child_by_field_name("right")?;
    let target = outliving_target(&left, source)?;
    let object = escaping_object(&right, assign, source, index)?;
    if reset_before_every_return(assign, &left, body, source, index) {
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
/// the caller owns). A path through a local pointer reaches storage nothing
/// here can name, and a local or parameter object itself dies with the call.
fn outliving_target(lvalue: &Node, source: &str) -> Option<&'static str> {
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
                if !(base.kind() == "identifier" && names_array_object(&base, source)) {
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
    let (decl, declarator) = resolve_identifier_declarator(&node, name, source)?;
    if declarator.kind() == "function_declarator" {
        return None;
    }
    match resolve_identifier_binding(&node, name, source)? {
        IdentifierBinding::Global(_) => Some("file scope"),
        IdentifierBinding::Local(_)
            if declaration_has_storage_class(&decl, "static", source)
                || declaration_has_storage_class(&decl, "extern", source)
                || declaration_is_thread_local(&decl, source) =>
        {
            Some("static storage")
        }
        IdentifierBinding::Parameter(_) if through_pointer => Some("the caller's storage"),
        _ => None,
    }
}

/// Whether, after the store `assign`, the same target is assigned a value
/// that is not an automatic address by a statement at the top of the
/// function body that every return after the store must pass. Then the
/// address never outlives the call: `g = &x; use(); g = NULL;`. A later
/// store of another automatic address is no reset.
fn reset_before_every_return(
    assign: &Node,
    left: &Node,
    body: &Node,
    source: &str,
    index: &WriteIndex,
) -> bool {
    // The top-level statement holding the store.
    let mut top = *assign;
    while let Some(parent) = top.parent() {
        if parent.id() == body.id() {
            break;
        }
        top = parent;
    }
    if top.parent().map(|p| p.id()) != Some(body.id()) {
        return false;
    }
    let returns_after = |n: &Node, from: usize| {
        query::find_descendants_of_kind(*n, "return_statement")
            .iter()
            .any(|r| r.start_byte() >= from)
            || (n.kind() == "return_statement" && n.start_byte() >= from)
    };
    if returns_after(&top, assign.end_byte()) {
        return false;
    }
    let target = compact(get_node_text(left, source));
    let mut cursor = body.walk();
    for stmt in body.named_children(&mut cursor) {
        if stmt.start_byte() <= top.start_byte() {
            continue;
        }
        let reset = (stmt.kind() == "expression_statement")
            .then(|| stmt.named_child(0))
            .flatten()
            .filter(|e| e.kind() == "assignment_expression")
            .filter(|e| {
                e.child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, source) == "=")
            })
            .filter(|e| {
                e.child_by_field_name("left").is_some_and(|l| {
                    compact(get_node_text(&l, source)) == target && same_root(&l, left, source)
                })
            })
            .and_then(|e| e.child_by_field_name("right").map(|r| (e, r)));
        if let Some((e, value)) = reset {
            return escaping_object(&value, &e, source, index).is_none();
        }
        if returns_after(&stmt, 0) {
            return false;
        }
    }
    false
}

/// Whether two lvalues of the same spelling name the same root variable:
/// each root identifier resolves to the same declarator.
fn same_root(a: &Node, b: &Node, source: &str) -> bool {
    let decl = |n: &Node| {
        let mut n = strip(*n);
        while n.kind() != "identifier" {
            n = strip(
                n.child_by_field_name("argument")
                    .or_else(|| n.child_by_field_name("left"))?,
            );
        }
        let name = get_node_text(&n, source);
        resolve_identifier_declarator(&n, name, source).map(|(_, d)| d.id())
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
