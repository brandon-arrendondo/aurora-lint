// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

// CON40-C: Do not refer to an atomic variable twice in an expression
//
// Two forms are reported:
//
// 1. One full expression that accesses the same atomic object two or more
//    times. An access is a name or member path whose declaration gives it an
//    atomic type, resolved by declaration (ADR-0006), so a struct that merely
//    has `_Atomic` members is not itself atomic and `config.x` is not an
//    access to `config.live`. The left operand of a compound assignment is
//    one access (`flag ^= 1`); a call's arguments are separate operations.
//    Each full expression is reported once, at its outermost expression.
// 2. CERT's split-statement form, reported for review: an `atomic_load` of
//    an object whose value, through a local, is what a later `atomic_store`
//    of the same object writes (`t = atomic_load(&f); t = !t;
//    atomic_store(&f, t);`).

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::{ProjectContext, VisibleTypes};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{get_node_text, ScopeDeclarations};
use crate::utility::cert_c::node_children::NodeChildren;
use crate::utility::cert_c::overflow_helpers::resolve_typedef_chain;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// Expression kinds an atomic object can be accessed twice within.
const EXPR_KINDS: &[&str] = &[
    "binary_expression",
    "assignment_expression",
    "conditional_expression",
    "unary_expression",
    "parenthesized_expression",
];

const LOAD_FUNCTIONS: &[&str] = &["atomic_load", "atomic_load_explicit"];
const STORE_FUNCTIONS: &[&str] = &["atomic_store", "atomic_store_explicit"];

type FieldTable = Arc<HashMap<String, HashMap<String, String>>>;

#[derive(Default)]
pub struct Con40C {
    /// `struct tag -> field -> type text` as this file sees it.
    struct_field_types: RefCell<FieldTable>,
    /// `struct tag -> field -> declarator shape`, filed with the types.
    struct_field_shapes: RefCell<FieldTable>,
    /// `typedef struct Tag Alias;`: alias -> tag.
    struct_typedef_aliases: RefCell<Arc<HashMap<String, String>>>,
    /// One-level typedef aliases, for `typedef atomic_int counter_t;`.
    typedef_types: RefCell<Arc<HashMap<String, String>>>,
}

/// The object an access names: the declarator its root name resolves to
/// and the members after it. `p->m` and `(*p).m` are the same object.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ObjectKey {
    root: usize,
    members: Vec<String>,
}

/// Where the members of a struct- or union-typed object are declared.
#[derive(Clone)]
enum Aggregate<'a> {
    /// A body in this file's tree, inline or tagged.
    Body(Node<'a>),
    /// A tag or typedef name, read from the struct tables.
    Named(String),
}

#[derive(Clone)]
struct Resolved<'a> {
    key: ObjectKey,
    atomic: bool,
    aggregate: Option<Aggregate<'a>>,
}

/// Per-file state: the scope index, the struct tables and every resolution
/// made so far, so a name nested in many expressions is resolved once.
struct FileCx<'a, 's> {
    source: &'s str,
    scopes: ScopeDeclarations<'a>,
    fields: FieldTable,
    shapes: FieldTable,
    aliases: Arc<HashMap<String, String>>,
    typedefs: Arc<HashMap<String, String>>,
    /// Names something in reach declares atomic: identifiers this file
    /// declares so, and members of any visible struct. Anything else is
    /// never resolved.
    candidate_names: HashSet<String>,
    memo: HashMap<usize, Option<Resolved<'a>>>,
}

/// Whether `name` is a `<stdatomic.h>` atomic type name. The standard
/// reserves `atomic_` followed by a lowercase letter for them; `atomic_flag`
/// is not usable as an operand.
fn is_atomic_type_name(name: &str) -> bool {
    name.starts_with("atomic_") && name != "atomic_flag"
}

fn has_atomic_qualifier(node: &Node, source: &str) -> bool {
    node.child_nodes()
        .any(|c| c.kind() == "type_qualifier" && get_node_text(&c, source) == "_Atomic")
}

fn is_name_node(node: &Node) -> bool {
    matches!(node.kind(), "identifier" | "field_identifier")
}

impl<'a, 's> FileCx<'a, 's> {
    /// Whether the object `declarator` names, in `decl` (a declaration,
    /// parameter or member), has an atomic type: the specifiers say
    /// `_Atomic` or name an atomic type and the declarator is the bare name,
    /// or the pointer nearest the name is itself `_Atomic` (`int *_Atomic
    /// p`). A pointer to an atomic object, an array of them and a struct
    /// with atomic members are not atomic objects.
    fn declares_atomic_object(&self, decl: &Node, declarator: &Node) -> bool {
        if is_name_node(declarator) {
            return has_atomic_qualifier(decl, self.source)
                || decl
                    .child_by_field_name("type")
                    .filter(|t| t.kind() == "type_identifier")
                    .is_some_and(|t| {
                        is_atomic_type_name(&resolve_typedef_chain(
                            get_node_text(&t, self.source),
                            &self.typedefs,
                        ))
                    });
        }
        let mut d = *declarator;
        while d.kind() == "pointer_declarator" {
            let Some(inner) = d.child_by_field_name("declarator") else {
                return false;
            };
            if is_name_node(&inner) {
                return has_atomic_qualifier(&d, self.source);
            }
            d = inner;
        }
        false
    }

    fn aggregate_of_decl(&self, decl: &Node<'a>) -> Option<Aggregate<'a>> {
        let ty = decl.child_by_field_name("type")?;
        match ty.kind() {
            "struct_specifier" | "union_specifier" => {
                if let Some(body) = ty.child_by_field_name("body") {
                    return Some(Aggregate::Body(body));
                }
                let name = get_node_text(&ty.child_by_field_name("name")?, self.source);
                Some(Aggregate::Named(name.to_string()))
            }
            "type_identifier" => Some(self.named(get_node_text(&ty, self.source))),
            _ => None,
        }
    }

    fn named(&self, name: &str) -> Aggregate<'a> {
        Aggregate::Named(
            self.aliases
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.to_string()),
        )
    }

    /// The member `name` of a struct body: its declaration and declarator,
    /// looking through anonymous inner structs and unions.
    fn member_in_body(&self, body: &Node<'a>, name: &str) -> Option<(Node<'a>, Node<'a>)> {
        for field in body
            .child_nodes()
            .filter(|c| c.kind() == "field_declaration")
        {
            let mut cursor = field.walk();
            for declarator in field.children_by_field_name("declarator", &mut cursor) {
                let mut d = declarator;
                while !is_name_node(&d) {
                    match d.child_by_field_name("declarator") {
                        Some(inner) => d = inner,
                        None => break,
                    }
                }
                if is_name_node(&d) && get_node_text(&d, self.source) == name {
                    return Some((field, declarator));
                }
            }
            if let Some(ty) = field.child_by_field_name("type") {
                if matches!(ty.kind(), "struct_specifier" | "union_specifier")
                    && ty.child_by_field_name("name").is_none()
                {
                    if let Some(found) = ty
                        .child_by_field_name("body")
                        .and_then(|inner| self.member_in_body(&inner, name))
                    {
                        return Some(found);
                    }
                }
            }
        }
        None
    }

    /// Whether member `name` of `aggregate` is an atomic object, and the
    /// aggregate its own members are declared in.
    fn member(&self, aggregate: &Aggregate<'a>, name: &str) -> (bool, Option<Aggregate<'a>>) {
        match aggregate {
            Aggregate::Body(body) => match self.member_in_body(body, name) {
                Some((field, declarator)) => (
                    self.declares_atomic_object(&field, &declarator),
                    self.aggregate_of_decl(&field),
                ),
                None => (false, None),
            },
            Aggregate::Named(tag) => {
                let Some(ty) = self.fields.get(tag).and_then(|f| f.get(name)) else {
                    return (false, None);
                };
                let shape = self
                    .shapes
                    .get(tag)
                    .and_then(|s| s.get(name))
                    .map(String::as_str)
                    .unwrap_or("");
                let tokens: Vec<&str> = ty.split_whitespace().collect();
                let atomic = shape.is_empty()
                    && !tokens.contains(&"*")
                    && tokens.iter().any(|t| {
                        *t == "_Atomic"
                            || is_atomic_type_name(&resolve_typedef_chain(t, &self.typedefs))
                    });
                let next = match tokens.iter().position(|t| *t == "struct" || *t == "union") {
                    Some(i) => tokens
                        .get(i + 1)
                        .filter(|t| !t.starts_with('{'))
                        .map(|t| Aggregate::Named(t.to_string())),
                    None => tokens
                        .iter()
                        .rev()
                        .find(|t| !matches!(**t, "*" | "const" | "volatile" | "_Atomic"))
                        .map(|t| self.named(t)),
                };
                (atomic, next)
            }
        }
    }

    /// The object `node` names, when it names one by declaration: an
    /// identifier, or a member path from one through `.`, `->`, `*` and
    /// parentheses. Anything else (a subscript, a call's result) is `None`.
    fn resolve(&mut self, node: &Node<'a>) -> Option<Resolved<'a>> {
        if let Some(r) = self.memo.get(&node.id()) {
            return r.clone();
        }
        let r = self.resolve_uncached(node);
        self.memo.insert(node.id(), r.clone());
        r
    }

    fn resolve_uncached(&mut self, node: &Node<'a>) -> Option<Resolved<'a>> {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, self.source);
                let (decl, declarator) = self
                    .scopes
                    .resolve_identifier_declarator_indexed(node, name, self.source)
                    .flatten()?;
                Some(Resolved {
                    key: ObjectKey {
                        root: declarator.id(),
                        members: Vec::new(),
                    },
                    atomic: self.declares_atomic_object(&decl, &declarator),
                    aggregate: self.aggregate_of_decl(&decl),
                })
            }
            "parenthesized_expression" => self.resolve(&node.named_child(0)?),
            "pointer_expression" => {
                let op = node.child_by_field_name("operator")?;
                if get_node_text(&op, self.source) != "*" {
                    return None;
                }
                let inner = self.resolve(&node.child_by_field_name("argument")?)?;
                Some(Resolved {
                    atomic: false,
                    ..inner
                })
            }
            "field_expression" => {
                let base = self.resolve(&node.child_by_field_name("argument")?)?;
                let field = get_node_text(&node.child_by_field_name("field")?, self.source);
                let (atomic, aggregate) = match &base.aggregate {
                    Some(agg) => self.member(agg, field),
                    None => (false, None),
                };
                let mut members = base.key.members;
                members.push(field.to_string());
                Some(Resolved {
                    key: ObjectKey {
                        root: base.key.root,
                        members,
                    },
                    atomic,
                    aggregate,
                })
            }
            _ => None,
        }
    }

    /// The atomic object `node` accesses, if it is a name or member path
    /// that something in reach declares atomic.
    fn atomic_access(&mut self, node: &Node<'a>) -> Option<ObjectKey> {
        let name_node = match node.kind() {
            "identifier" => *node,
            "field_expression" => node.child_by_field_name("field")?,
            _ => return None,
        };
        if !self
            .candidate_names
            .contains(get_node_text(&name_node, self.source))
        {
            return None;
        }
        self.resolve(node).filter(|r| r.atomic).map(|r| r.key)
    }

    /// The object an `atomic_load`/`atomic_store` call's first argument
    /// points at: `&x` names `x`, and a pointer `p` names `*p`.
    fn pointed_object(&mut self, arg: &Node<'a>) -> Option<ObjectKey> {
        let arg = strip_parens(arg);
        if arg.kind() == "pointer_expression"
            && arg
                .child_by_field_name("operator")
                .is_some_and(|o| get_node_text(&o, self.source) == "&")
        {
            return self
                .resolve(&arg.child_by_field_name("argument")?)
                .map(|r| r.key);
        }
        let mut key = self.resolve(&arg)?.key;
        key.members.push("*".to_string());
        Some(key)
    }
}

fn strip_parens<'a>(node: &Node<'a>) -> Node<'a> {
    let mut n = *node;
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => break,
        }
    }
    n
}

fn callee_name<'a>(call: &Node, source: &'a str) -> Option<&'a str> {
    let f = call.child_by_field_name("function")?;
    (f.kind() == "identifier").then(|| get_node_text(&f, source))
}

fn call_args<'a>(call: &Node<'a>) -> Vec<Node<'a>> {
    call.child_by_field_name("arguments")
        .map(|a| {
            a.named_child_nodes()
                .filter(|c| c.kind() != "comment")
                .collect()
        })
        .unwrap_or_default()
}

impl Con40C {
    fn file_cx<'a, 's>(&self, root: &Node<'a>, source: &'s str) -> FileCx<'a, 's> {
        let mut cx = FileCx {
            source,
            scopes: ScopeDeclarations::indexed(*root),
            fields: self.struct_field_types.borrow().clone(),
            shapes: self.struct_field_shapes.borrow().clone(),
            aliases: self.struct_typedef_aliases.borrow().clone(),
            typedefs: self.typedef_types.borrow().clone(),
            candidate_names: HashSet::new(),
            memo: HashMap::new(),
        };
        let mut names = HashSet::new();
        for decl in query::find_descendants_of_kinds(
            *root,
            &["declaration", "parameter_declaration", "field_declaration"],
        ) {
            let mut cursor = decl.walk();
            for declarator in decl.children_by_field_name("declarator", &mut cursor) {
                let declarator = if declarator.kind() == "init_declarator" {
                    match declarator.child_by_field_name("declarator") {
                        Some(d) => d,
                        None => continue,
                    }
                } else {
                    declarator
                };
                if cx.declares_atomic_object(&decl, &declarator) {
                    let mut d = declarator;
                    while !is_name_node(&d) {
                        match d.child_by_field_name("declarator") {
                            Some(inner) => d = inner,
                            None => break,
                        }
                    }
                    names.insert(get_node_text(&d, source).to_string());
                }
            }
        }
        for fields in cx.fields.values() {
            for (name, ty) in fields {
                if ty.split_whitespace().any(|t| {
                    t == "_Atomic" || is_atomic_type_name(&resolve_typedef_chain(t, &cx.typedefs))
                }) {
                    names.insert(name.clone());
                }
            }
        }
        cx.candidate_names = names;
        cx
    }

    /// Every expression that is the outermost of the operator expressions
    /// around it: one per full expression, and one per call argument,
    /// since a call's arguments are separate operations.
    fn report_roots<'a>(root: &Node<'a>) -> Vec<Node<'a>> {
        let mut roots = Vec::new();
        let mut stack = vec![(*root, false)];
        while let Some((node, inside)) = stack.pop() {
            let kind = node.kind();
            let is_expr = EXPR_KINDS.contains(&kind);
            if is_expr && !inside {
                roots.push(node);
            }
            let continues_chain = kind.ends_with("_expression") && kind != "call_expression";
            let child_inside = continues_chain && (inside || is_expr);
            let children: Vec<Node<'a>> = node.child_nodes().collect();
            stack.extend(children.into_iter().rev().map(|c| (c, child_inside)));
        }
        roots
    }

    /// The atomic accesses under `expr`, outside any call it makes.
    fn accesses<'a>(cx: &mut FileCx<'a, '_>, expr: &Node<'a>) -> Vec<(ObjectKey, Node<'a>)> {
        let mut found = Vec::new();
        let mut stack = vec![*expr];
        while let Some(node) = stack.pop() {
            if node.kind() == "call_expression" {
                continue;
            }
            if let Some(key) = cx.atomic_access(&node) {
                found.push((key, node));
            }
            let children: Vec<Node<'a>> = node.child_nodes().collect();
            stack.extend(children.into_iter().rev());
        }
        found
    }

    fn check_expressions<'a>(
        &self,
        cx: &mut FileCx<'a, '_>,
        root: &Node<'a>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for expr in Self::report_roots(root) {
            let mut counts: Vec<(ObjectKey, Node, usize)> = Vec::new();
            for (key, node) in Self::accesses(cx, &expr) {
                match counts.iter_mut().find(|(k, _, _)| *k == key) {
                    Some(entry) => entry.2 += 1,
                    None => counts.push((key, node, 1)),
                }
            }
            for (_, first, n) in counts.into_iter().filter(|(_, _, n)| *n >= 2) {
                let name: String = get_node_text(&first, cx.source)
                    .split_whitespace()
                    .collect();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    line: expr.start_position().row + 1,
                    column: expr.start_position().column + 1,
                    message: format!(
                        "Atomic object '{name}' is accessed {n} times in one expression; each access is a separate atomic operation, and another thread can change '{name}' between them"
                    ),
                    severity: self.severity(),
                    file_path: String::new(),
                    suggestion: Some(
                        "Read the object once into a local, or use one atomic operation (a compound assignment or atomic_fetch_*)"
                            .to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// The local a load's value is stored in: the declarator of `T t =
    /// atomic_load(..)` or the left name of `t = ..atomic_load(..)..`.
    fn receiver<'a>(cx: &mut FileCx<'a, '_>, load: &Node<'a>) -> Option<ObjectKey> {
        let mut child = *load;
        while let Some(parent) = child.parent() {
            match parent.kind() {
                "init_declarator" => {
                    let declarator = parent.child_by_field_name("declarator")?;
                    if declarator.kind() != "identifier" {
                        return None;
                    }
                    return Some(ObjectKey {
                        root: declarator.id(),
                        members: Vec::new(),
                    });
                }
                "assignment_expression" => {
                    let left = parent.child_by_field_name("left")?;
                    if left.id() == child.id() || left.kind() != "identifier" {
                        return None;
                    }
                    return cx.resolve(&left).map(|r| r.key);
                }
                kind if kind.ends_with("_expression") && kind != "call_expression" => {}
                _ => return None,
            }
            child = parent;
        }
        None
    }

    /// CERT's split-statement form: a load whose value a later store of the
    /// same object writes, through a local or directly. A presumption,
    /// reported for review.
    fn check_split_statements<'a>(
        &self,
        cx: &mut FileCx<'a, '_>,
        func: &Node<'a>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let calls = query::find_descendants_of_kind(*func, "call_expression");
        // (object, load call, the local its value went to)
        let mut loads: Vec<(ObjectKey, Node<'a>, Option<ObjectKey>)> = Vec::new();
        for call in &calls {
            let Some(name) = callee_name(call, cx.source) else {
                continue;
            };
            if !LOAD_FUNCTIONS.contains(&name) {
                continue;
            }
            let Some(object) = call_args(call).first().and_then(|a| cx.pointed_object(a)) else {
                continue;
            };
            let receiver = Self::receiver(cx, call);
            loads.push((object, *call, receiver));
        }
        if loads.is_empty() {
            return;
        }
        let mut reported = HashSet::new();
        for call in &calls {
            let Some(name) = callee_name(call, cx.source) else {
                continue;
            };
            if !STORE_FUNCTIONS.contains(&name) {
                continue;
            }
            let args = call_args(call);
            let (Some(target), Some(value)) = (args.first(), args.get(1)) else {
                continue;
            };
            let Some(object) = cx.pointed_object(target) else {
                continue;
            };
            let value_names: Vec<ObjectKey> = query::find_descendants_of_kind(*value, "identifier")
                .iter()
                .chain(std::iter::once(value).filter(|v| v.kind() == "identifier"))
                .filter_map(|id| cx.resolve(id).map(|r| r.key))
                .collect();
            for (loaded, load, receiver) in &loads {
                if *loaded != object {
                    continue;
                }
                let inside =
                    load.start_byte() >= value.start_byte() && load.end_byte() <= value.end_byte();
                let through_local = load.end_byte() <= call.start_byte()
                    && receiver.as_ref().is_some_and(|r| value_names.contains(r));
                if !(inside || through_local) || !reported.insert(load.id()) {
                    continue;
                }
                let object_text: String = get_node_text(target, cx.source)
                    .trim_start_matches('&')
                    .split_whitespace()
                    .collect();
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    line: load.start_position().row + 1,
                    column: load.start_position().column + 1,
                    message: format!(
                        "'{object_text}' is read with {} and later written with {name} using a value computed from that read; the read and the write are separate atomic operations, and another thread can change '{object_text}' between them",
                        callee_name(load, cx.source).unwrap_or("atomic_load")
                    ),
                    severity: self.severity(),
                    file_path: String::new(),
                    suggestion: Some(
                        "Make the read and the write one atomic operation: atomic_compare_exchange_weak in a loop, or an atomic_fetch_* operation"
                            .to_string(),
                    ),
                    requires_manual_review: Some(true),
                });
            }
        }
    }
}

impl CertRule for Con40C {
    fn rule_id(&self) -> &'static str {
        "CON40-C"
    }

    fn description(&self) -> &'static str {
        "Do not refer to an atomic variable twice in an expression"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "CON40-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.struct_field_types.borrow_mut() = context.struct_field_types.clone();
        *self.struct_field_shapes.borrow_mut() = context.struct_field_shapes.clone();
        *self.struct_typedef_aliases.borrow_mut() = context.struct_typedef_aliases.clone();
        *self.typedef_types.borrow_mut() = context.typedef_types.clone();
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.struct_field_types.borrow_mut() = types.struct_field_types.clone();
        *self.struct_field_shapes.borrow_mut() = types.struct_field_shapes.clone();
        *self.struct_typedef_aliases.borrow_mut() = types.struct_typedef_aliases.clone();
        *self.typedef_types.borrow_mut() = types.typedef_types.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut cx = self.file_cx(node, source);
        if !cx.candidate_names.is_empty() {
            self.check_expressions(&mut cx, node, violations);
        }
        if source.contains("atomic_store") {
            for func in query::find_descendants_of_kind(*node, "function_definition") {
                self.check_split_statements(&mut cx, &func, violations);
            }
        }
    }
}
