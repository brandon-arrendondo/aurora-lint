// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! POS34-C: Do not call putenv() with a pointer to an automatic variable as the argument
//!
//! The POSIX `putenv()` function stores a pointer to the string argument in the environment,
//! rather than copying it. If the argument is a pointer to automatic (stack-allocated) storage,
//! the memory will be reclaimed when the function returns, leaving a dangling pointer in the
//! environment. This leads to undefined behavior and potential security vulnerabilities.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int func(const char *var) {
//!     char env[1024];  // Automatic storage
//!     snprintf(env, sizeof(env), "TEST=%s", var);
//!     return putenv(env);  // Dangling pointer after function returns
//! }
//! ```
//!
//! **Compliant (Static storage):**
//! ```c
//! int func(const char *var) {
//!     static char env[1024];  // Static storage persists
//!     snprintf(env, sizeof(env), "TEST=%s", var);
//!     return putenv(env);  // Safe: static variable persists
//! }
//! ```
//!
//! **Compliant (Heap allocation):**
//! ```c
//! int func(const char *var) {
//!     char *env = malloc(len);  // Heap allocation persists
//!     snprintf(env, len, "TEST=%s", var);
//!     putenv(env);  // Safe: heap memory persists (don't free!)
//!     return 0;
//! }
//! ```
//!
//! **Non-compliant (pointer copy, member, compound literal):**
//! ```c
//! char env[1024];
//! char *p = env;
//! putenv(p);                 /* p points at automatic storage */
//! putenv(&env[0]);           /* so does the address of its first element */
//! putenv(s.buf);             /* an array member of an automatic struct */
//! putenv((char[]){"A=1"});   /* a block-scope compound literal */
//! ```
//!
//! The storage of the argument is found by resolving each name to its own
//! declaration (ADR-0006): a `static` or `extern` declaration, a parameter
//! (the caller's storage) and a pointer with any non-automatic value are
//! never reported.
//!
//! Two named options withhold a report CERT's page would make:
//! `pos34_main_frame_exempt` (the call is in `main`) and
//! `pos34_exit_path_exempt` (every path after the call ends in
//! `exit`/`_exit`/`_Exit`/`quick_exit`/`abort`; an `exec*` call can return
//! when it fails, so it counts only where an exit follows it on every path).
//!
//! **Preferred (Use setenv):**
//! ```c
//! int func(const char *var) {
//!     return setenv("TEST", var, 1);  // Handles memory management
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{
    declaration_has_storage_class, get_identifier_from_declarator, get_node_text,
    resolve_identifier_declarator,
};
use lang_parsing_substrate::query;
use std::sync::Arc;
use tree_sitter::Node;

/// The option that exempts a call in `main`'s own frame.
const MAIN_FRAME_OPTION: &str = "pos34_main_frame_exempt";
/// The option that exempts a call every path after which ends the process.
const EXIT_PATH_OPTION: &str = "pos34_exit_path_exempt";

/// Calls that end the process. The `exec*` family is not among them: it
/// returns -1 when it fails, so a path continues past it unless an exit
/// follows.
const PROCESS_ENDING_CALLS: &[&str] = &["exit", "_exit", "_Exit", "quick_exit", "abort"];

/// How far a pointer's value is followed through copies (`q = p; r = q;`).
const MAX_COPY_DEPTH: usize = 4;

pub struct Pos34C {
    settings: std::cell::RefCell<Arc<AnalysisSettings>>,
}

impl Pos34C {
    pub fn new() -> Self {
        Self {
            settings: std::cell::RefCell::new(Arc::new(AnalysisSettings::default())),
        }
    }
}

impl CertRule for Pos34C {
    fn rule_id(&self) -> &'static str {
        "POS34-C"
    }

    fn description(&self) -> &'static str {
        "Do not call putenv() with a pointer to an automatic variable as the argument"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "POS34-C"
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_putenv_calls(node, source, violations);
    }
}

impl Pos34C {
    fn check_putenv_calls(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if !calls_putenv(&call, source) {
                continue;
            }
            let Some(arg) = first_argument(&call) else {
                continue;
            };
            if !points_to_automatic(&arg, source, 0) {
                continue;
            }
            if self.exempted(&call, source) {
                continue;
            }
            let arg_text = automatic_object_name(&arg, source);
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message: format!(
                    "putenv() called with pointer to automatic variable '{}'. \
                     The argument to putenv() must point to memory with static \
                     storage duration (static variable or heap allocation). \
                     Automatic variables are destroyed when the function returns, \
                     leaving a dangling pointer in the environment.",
                    arg_text
                ),
                severity: self.severity(),
                line: call.start_position().row + 1,
                column: call.start_position().column + 1,
                file_path: String::new(),
                suggestion: Some(
                    "Use 'static char env[...]' or malloc(), or prefer setenv() \
                     which handles memory management automatically"
                        .to_string(),
                ),
                requires_manual_review: Some(true),
            });
        }
    }

    /// Whether a named option withholds the report for this call.
    fn exempted(&self, call: &Node, source: &str) -> bool {
        let settings = self.settings.borrow();
        if settings.flag(MAIN_FRAME_OPTION) && containing_function_name(call, source) == "main" {
            return true;
        }
        settings.flag(EXIT_PATH_OPTION) && every_path_ends_process(call, source)
    }
}

/// `putenv(...)` or `(putenv)(...)`.
fn calls_putenv(call: &Node, source: &str) -> bool {
    let Some(mut function) = call.child_by_field_name("function") else {
        return false;
    };
    while function.kind() == "parenthesized_expression" {
        match function.named_child(0) {
            Some(inner) => function = inner,
            None => return false,
        }
    }
    function.kind() == "identifier" && get_node_text(&function, source) == "putenv"
}

fn first_argument<'a>(call: &Node<'a>) -> Option<Node<'a>> {
    call.child_by_field_name("arguments")?.named_child(0)
}

fn containing_function_name(node: &Node, source: &str) -> String {
    let mut current = node.parent();
    while let Some(n) = current {
        if n.kind() == "function_definition" {
            return n
                .child_by_field_name("declarator")
                .map(|d| get_identifier_from_declarator(&d, source))
                .unwrap_or_default();
        }
        current = n.parent();
    }
    String::new()
}

fn inside_function(node: &Node) -> bool {
    let mut current = node.parent();
    while let Some(n) = current {
        if n.kind() == "function_definition" {
            return true;
        }
        current = n.parent();
    }
    false
}

/// Whether the expression is a pointer to an object of automatic storage
/// duration: an array declared in a block, its address or the address of one
/// of its elements, an array member of an automatic struct, a block-scope
/// compound literal of array type, or a local pointer every value of which is
/// one of those.
fn points_to_automatic(expr: &Node, source: &str, depth: usize) -> bool {
    match expr.kind() {
        "parenthesized_expression" => expr
            .named_child(0)
            .is_some_and(|inner| points_to_automatic(&inner, source, depth)),
        "cast_expression" => expr
            .child_by_field_name("value")
            .is_some_and(|inner| points_to_automatic(&inner, source, depth)),
        "identifier" => identifier_points_to_automatic(expr, source, depth),
        "pointer_expression" => {
            let is_address_of = expr
                .child_by_field_name("operator")
                .is_some_and(|op| get_node_text(&op, source) == "&");
            is_address_of
                && expr
                    .child_by_field_name("argument")
                    .is_some_and(|operand| address_is_automatic(&operand, source))
        }
        "field_expression" => automatic_array_member(expr, source),
        // `k ? env : "B=2"`: one automatic arm is enough to dangle.
        "conditional_expression" => ["consequence", "alternative"].iter().any(|arm| {
            expr.child_by_field_name(arm)
                .is_some_and(|inner| points_to_automatic(&inner, source, depth))
        }),
        // `env[0]` of `char env[2][16]` is itself an array, so it decays to
        // a pointer into the automatic object.
        "subscript_expression" => {
            expr.child_by_field_name("argument")
                .is_some_and(|base| is_automatic_array_expr(&base, source))
                && subscript_yields_array(expr, source)
        }
        "compound_literal_expression" => {
            inside_function(expr)
                && expr.child_by_field_name("type").is_some_and(|t| {
                    query::find_first_descendant(t, |n| {
                        matches!(n.kind(), "abstract_array_declarator" | "array_declarator")
                    })
                    .is_some()
                })
        }
        _ => false,
    }
}

/// The spelling the report names for an argument that points to an automatic
/// object: the object itself (`env` for `k ? env : "B=2"`, `&env[1]`, `s.buf`),
/// or the whole expression when no single object stands out.
fn automatic_object_name(expr: &Node, source: &str) -> String {
    let named = match expr.kind() {
        "parenthesized_expression" => expr.named_child(0),
        "cast_expression" => expr.child_by_field_name("value"),
        "conditional_expression" => ["consequence", "alternative"]
            .iter()
            .filter_map(|arm| expr.child_by_field_name(arm))
            .find(|inner| points_to_automatic(inner, source, 0)),
        "pointer_expression" | "subscript_expression" | "field_expression" => {
            let base = if expr.kind() == "pointer_expression" {
                expr.child_by_field_name("argument")
            } else {
                Some(*expr)
            };
            return base
                .and_then(|b| path_root(&b))
                .map(|root| get_node_text(&root, source).to_string())
                .unwrap_or_else(|| get_node_text(expr, source).to_string());
        }
        _ => None,
    };
    match named {
        Some(inner) => automatic_object_name(&inner, source),
        None => get_node_text(expr, source).to_string(),
    }
}

/// `&operand`: the address of an automatic object or a part of one.
fn address_is_automatic(operand: &Node, source: &str) -> bool {
    match operand.kind() {
        "parenthesized_expression" => operand
            .named_child(0)
            .is_some_and(|inner| address_is_automatic(&inner, source)),
        // `&env[0]`: the element's storage is the array's, when the base is the array.
        "subscript_expression" => operand
            .child_by_field_name("argument")
            .is_some_and(|base| is_automatic_array_expr(&base, source)),
        "identifier" => resolve_object(operand, source).is_some_and(|o| o.automatic),
        "field_expression" => field_root_is_automatic_object(operand, source),
        _ => false,
    }
}

/// An expression that names an automatic array itself (not a pointer).
fn is_automatic_array_expr(expr: &Node, source: &str) -> bool {
    match expr.kind() {
        "parenthesized_expression" => expr
            .named_child(0)
            .is_some_and(|inner| is_automatic_array_expr(&inner, source)),
        "identifier" => resolve_object(expr, source).is_some_and(|o| o.automatic && o.array),
        "field_expression" => automatic_array_member(expr, source),
        _ => false,
    }
}

/// Whether `base[i]` has array type: `base` is declared with more dimensions
/// than the subscripts applied to it.
fn subscript_yields_array(subscript: &Node, source: &str) -> bool {
    let mut applied = 0;
    let mut current = *subscript;
    while current.kind() == "subscript_expression" {
        applied += 1;
        match current.child_by_field_name("argument") {
            Some(inner) => current = inner,
            None => return false,
        }
    }
    while current.kind() == "parenthesized_expression" {
        match current.named_child(0) {
            Some(inner) => current = inner,
            None => return false,
        }
    }
    current.kind() == "identifier"
        && resolve_object(&current, source).is_some_and(|o| o.dimensions > applied)
}

struct Object<'a> {
    declarator: Node<'a>,
    /// How many array dimensions the declarator has.
    dimensions: usize,
    /// A block-scope declaration with no `static`/`extern`/thread storage.
    automatic: bool,
    array: bool,
    pointer: bool,
}

/// The declaration an identifier occurrence resolves to, by scope.
fn resolve_object<'a>(ident: &Node<'a>, source: &str) -> Option<Object<'a>> {
    let name = get_node_text(ident, source);
    let (decl, declarator) = resolve_identifier_declarator(ident, name, source)?;
    let (mut array, mut pointer, mut dimensions) = (false, false, 0);
    let mut d = declarator;
    loop {
        match d.kind() {
            "array_declarator" => {
                array = true;
                dimensions += 1;
            }
            "pointer_declarator" => pointer = true,
            "parenthesized_declarator" => {}
            _ => break,
        }
        match d.child_by_field_name("declarator") {
            Some(inner) => d = inner,
            None => break,
        }
    }
    // A parameter's storage belongs to the caller: an array parameter is a pointer.
    let automatic = decl.kind() == "declaration"
        && inside_function(&decl)
        && !["static", "extern", "_Thread_local", "thread_local"]
            .iter()
            .any(|class| declaration_has_storage_class(&decl, class, source));
    Some(Object {
        declarator,
        dimensions,
        automatic,
        array,
        pointer,
    })
}

fn identifier_points_to_automatic(ident: &Node, source: &str, depth: usize) -> bool {
    let Some(object) = resolve_object(ident, source) else {
        return false;
    };
    if !object.automatic {
        return false;
    }
    if object.array {
        // A pointer to an array is not the array's first element.
        return !object.pointer;
    }
    if !object.pointer || depth >= MAX_COPY_DEPTH {
        return false;
    }
    // A pointer: every value it is given must point at automatic storage.
    let values = pointer_values(&object, ident, source);
    !values.is_empty()
        && values
            .iter()
            .all(|value| points_to_automatic(value, source, depth + 1))
}

/// The initializer and every assigned value of the pointer `object` in its
/// function. Empty when its address is taken, because then it can be written
/// where this cannot see.
fn pointer_values<'a>(object: &Object<'a>, ident: &Node<'a>, source: &str) -> Vec<Node<'a>> {
    let name = get_node_text(ident, source);
    let mut values = Vec::new();
    if let Some(parent) = object.declarator.parent() {
        if parent.kind() == "init_declarator" {
            if let Some(value) = parent.child_by_field_name("value") {
                values.push(value);
            }
        }
    }
    let mut function = object.declarator.parent();
    while let Some(n) = function {
        if n.kind() == "function_definition" {
            break;
        }
        function = n.parent();
    }
    let Some(function) = function else {
        return Vec::new();
    };
    for occurrence in query::find_descendants_of_kind(function, "identifier") {
        if get_node_text(&occurrence, source) != name {
            continue;
        }
        // Another declaration's same-named variable is not this one.
        let Some(other) = resolve_object(&occurrence, source) else {
            continue;
        };
        if other.declarator.id() != object.declarator.id() {
            continue;
        }
        let Some(parent) = occurrence.parent() else {
            continue;
        };
        match parent.kind() {
            "assignment_expression"
                if parent
                    .child_by_field_name("left")
                    .is_some_and(|l| l.id() == occurrence.id()) =>
            {
                match parent.child_by_field_name("right") {
                    Some(right)
                        if parent
                            .child_by_field_name("operator")
                            .is_some_and(|op| get_node_text(&op, source) == "=") =>
                    {
                        values.push(right)
                    }
                    _ => return Vec::new(),
                }
            }
            "pointer_expression"
                if parent
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, source) == "&") =>
            {
                return Vec::new();
            }
            "update_expression" => return Vec::new(),
            _ => {}
        }
    }
    values
}

/// `s.buf` where `s` is an automatic struct object and `buf` an array member.
fn automatic_array_member(expr: &Node, source: &str) -> bool {
    field_root_is_automatic_object(expr, source) && member_is_array(expr, source)
}

/// A `.`-only member path rooted at an automatic non-pointer object.
fn field_root_is_automatic_object(expr: &Node, source: &str) -> bool {
    let mut current = *expr;
    loop {
        match current.kind() {
            "field_expression" => {
                let is_arrow = current
                    .child_by_field_name("operator")
                    .is_some_and(|op| get_node_text(&op, source) == "->");
                if is_arrow {
                    return false;
                }
                match current.child_by_field_name("argument") {
                    Some(inner) => current = inner,
                    None => return false,
                }
            }
            "subscript_expression" => match current.child_by_field_name("argument") {
                Some(inner) => current = inner,
                None => return false,
            },
            "parenthesized_expression" => match current.named_child(0) {
                Some(inner) => current = inner,
                None => return false,
            },
            "identifier" => {
                return resolve_object(&current, source).is_some_and(|o| o.automatic && !o.pointer);
            }
            _ => return false,
        }
    }
}

/// Whether the member a `.` path ends in is declared as an array, read from
/// the struct definition the root object's type names in this file.
fn member_is_array(expr: &Node, source: &str) -> bool {
    let Some(field) = expr.child_by_field_name("field") else {
        return false;
    };
    let field_name = get_node_text(&field, source);
    let Some(argument) = expr.child_by_field_name("argument") else {
        return false;
    };
    let Some(root) = path_root(&argument) else {
        return false;
    };
    let name = get_node_text(&root, source);
    let Some((decl, _)) = resolve_identifier_declarator(&root, name, source) else {
        return false;
    };
    let Some(type_node) = decl.child_by_field_name("type") else {
        return false;
    };
    // Only the root's own struct type is read; a nested member's struct is not.
    if argument.kind() != "identifier" {
        return false;
    }
    let body = struct_body_of_type(&type_node, source, 0);
    let Some(body) = body else {
        return false;
    };
    body.named_children(&mut body.walk())
        .filter(|f| f.kind() == "field_declaration")
        .flat_map(|f| {
            let mut cursor = f.walk();
            f.children_by_field_name("declarator", &mut cursor)
                .collect::<Vec<_>>()
        })
        .any(|d| d.kind() == "array_declarator" && member_name(&d, source) == field_name)
}

/// The body of the struct or union a type specifier names: written there, by
/// tag, or through a `typedef` of either (ADR-0006: the typedef is found by
/// its declared name in this file).
fn struct_body_of_type<'a>(type_node: &Node<'a>, source: &str, depth: usize) -> Option<Node<'a>> {
    match type_node.kind() {
        "struct_specifier" | "union_specifier" => match type_node.child_by_field_name("body") {
            Some(body) => Some(body),
            None => type_node
                .child_by_field_name("name")
                .and_then(|tag| struct_body_named(type_node, get_node_text(&tag, source), source)),
        },
        "type_identifier" if depth < MAX_COPY_DEPTH => {
            let name = get_node_text(type_node, source);
            visible_typedef(type_node, name, source)
                .and_then(|td| td.child_by_field_name("type"))
                .and_then(|t| struct_body_of_type(&t, source, depth + 1))
        }
        _ => None,
    }
}

/// The `typedef` that gives `name` its meaning at `from`: the nearest one in
/// an enclosing block or the file, declared before the use. A block-scope
/// typedef in another function is not in scope, and an inner one shadows an
/// outer one (ADR-0006).
fn visible_typedef<'a>(from: &Node<'a>, name: &str, source: &str) -> Option<Node<'a>> {
    let mut scope = from.parent();
    while let Some(block) = scope {
        if let Some(found) = last_typedef_before(&block, name, source, from.start_byte()) {
            return Some(found);
        }
        scope = block.parent();
    }
    None
}

/// The last `typedef` of `name` that is a direct child of `scope` (looking
/// through preprocessor branches) and ends before `before`.
fn last_typedef_before<'a>(
    scope: &Node<'a>,
    name: &str,
    source: &str,
    before: usize,
) -> Option<Node<'a>> {
    let mut found = None;
    for child in scope.named_children(&mut scope.walk()) {
        if child.start_byte() >= before {
            break;
        }
        if child.kind() == "type_definition" {
            if child.end_byte() <= before
                && child
                    .child_by_field_name("declarator")
                    .is_some_and(|d| member_name(&d, source) == name)
            {
                found = Some(child);
            }
        } else if child.kind().starts_with("preproc_") {
            if let Some(inner) = last_typedef_before(&child, name, source, before) {
                found = Some(inner);
            }
        }
    }
    found
}

/// The member a field declarator names (`field_identifier`, which
/// `get_identifier_from_declarator` does not read).
fn member_name<'a>(declarator: &Node, source: &'a str) -> &'a str {
    let mut d = *declarator;
    while let Some(inner) = d.child_by_field_name("declarator") {
        d = inner;
    }
    get_node_text(&d, source)
}

fn path_root<'a>(expr: &Node<'a>) -> Option<Node<'a>> {
    let mut current = *expr;
    loop {
        match current.kind() {
            "identifier" => return Some(current),
            "field_expression" | "subscript_expression" => {
                current = current.child_by_field_name("argument")?
            }
            "parenthesized_expression" => current = current.named_child(0)?,
            _ => return None,
        }
    }
}

/// The body of the `struct tag { ... }` defined in the same file.
fn struct_body_named<'a>(from: &Node<'a>, tag: &str, source: &str) -> Option<Node<'a>> {
    let mut root = *from;
    while let Some(parent) = root.parent() {
        root = parent;
    }
    query::find_descendants_of_kind(root, "struct_specifier")
        .into_iter()
        .chain(query::find_descendants_of_kind(root, "union_specifier"))
        .find_map(|spec| {
            let body = spec.child_by_field_name("body")?;
            let name = spec.child_by_field_name("name")?;
            (get_node_text(&name, source) == tag).then_some(body)
        })
}

/// Whether control cannot return from the function after `call`: each
/// statement that follows ends the process before any `return` or `goto` can
/// be reached, climbing out of the blocks the call sits in.
fn every_path_ends_process(call: &Node, source: &str) -> bool {
    // The statement holding the call.
    let mut stmt = *call;
    loop {
        let Some(parent) = stmt.parent() else {
            return false;
        };
        if parent.kind() == "compound_statement" {
            break;
        }
        stmt = parent;
    }
    // A branch of the statement holding the call may return.
    if !matches!(stmt.kind(), "expression_statement" | "declaration") && contains_jump_out(&stmt) {
        return false;
    }
    loop {
        let Some(block) = stmt.parent() else {
            return false;
        };
        let mut next = stmt.next_named_sibling();
        while let Some(sibling) = next {
            if sibling.kind() == "comment" {
                next = sibling.next_named_sibling();
                continue;
            }
            if ends_process_statement(&sibling, source) {
                return true;
            }
            if contains_jump_out(&sibling) || sibling.kind() == "labeled_statement" {
                return false;
            }
            next = sibling.next_named_sibling();
        }
        // The block is exhausted: fall out into whatever encloses it.
        let Some(owner) = block.parent() else {
            return false;
        };
        match owner.kind() {
            "if_statement" | "else_clause" => {
                // Continue after the whole `if` (its else arm included).
                stmt = if owner.kind() == "else_clause" {
                    match owner.parent() {
                        Some(i) => i,
                        None => return false,
                    }
                } else {
                    owner
                };
                if stmt
                    .parent()
                    .is_none_or(|p| p.kind() != "compound_statement")
                {
                    return false;
                }
            }
            "compound_statement" => stmt = block,
            // A function falls off its end (a return); a loop can iterate; a
            // switch arm falls through: none ends the process.
            _ => return false,
        }
    }
}

fn contains_jump_out(node: &Node) -> bool {
    query::find_first_descendant(*node, |n| {
        matches!(n.kind(), "return_statement" | "goto_statement")
    })
    .is_some()
}

/// `exit(1);`, `(void)abort();`
fn ends_process_statement(stmt: &Node, source: &str) -> bool {
    if stmt.kind() != "expression_statement" {
        return false;
    }
    let Some(mut expr) = stmt.named_child(0) else {
        return false;
    };
    while matches!(expr.kind(), "cast_expression" | "parenthesized_expression") {
        match expr
            .child_by_field_name("value")
            .or_else(|| expr.named_child(0))
        {
            Some(inner) => expr = inner,
            None => return false,
        }
    }
    if expr.kind() != "call_expression" {
        return false;
    }
    expr.child_by_field_name("function")
        .filter(|f| f.kind() == "identifier")
        .is_some_and(|f| PROCESS_ENDING_CALLS.contains(&get_node_text(&f, source)))
}
