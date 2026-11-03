//! Which locals of a function a write through a pointer may change.
//!
//! Value-range analysis keys its state on variable names and changes a range
//! only where the variable is assigned by name. Once a local's address is
//! taken, a store through a pointer can change it with its name nowhere in
//! the statement: `int x = 1; int *q = &x; *q = read_untrusted();` leaves `x`
//! untrusted while a name-keyed state still says 1, so a divisor or an index
//! is "proved" safe from a value it no longer has. This module answers, per
//! function, which locals such a store, step or call may write.
//!
//! The analysis is flow-insensitive and intraprocedural, and errs towards
//! "may write" at every point it cannot follow:
//!
//! - A local pointer that is assigned or initialised from `&x` (through
//!   casts, parentheses, `p + n`, a conditional, a comma, or another such
//!   pointer, transitively) may point into `x`. Every write through it, and
//!   every call it is passed to, may change `x`.
//! - A pointer whose value may come from somewhere this function cannot see
//!   (a parameter, a file-scope object, a value read through memory, a call's
//!   result) may point into any local whose address escaped.
//! - A local's address escapes when it is stored anywhere but in a local
//!   pointer variable: a file-scope object, a struct member, an array
//!   element, a pointee, an initializer list. The address of a local pointer
//!   that may hold `&x` escapes `x` too, since `**pp = v` then writes it.
//!   Every store through a pointer and every call may write an escaped local.
//!
//! Passing `&x`, or a pointer holding it, to a call is a write at that call
//! (the callee may store through it), not an escape. That is the assumption
//! value-range analysis has always made for `f(&x)`: a callee that keeps the
//! pointer and writes through it at a later call is not followed.

use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

use super::argument_objects::declarator_depth;
use super::init_state::addressed_object_root;

/// Where a pointer value an expression computes may come from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Source {
    /// The address of (somewhere inside) this name's own storage.
    AddrOf(String),
    /// The value of this name.
    Name(String),
    /// A value this function cannot follow.
    Opaque,
}

/// The pointer facts of one function: which locals each local pointer may
/// point into, and which locals' addresses escaped.
#[derive(Debug, Default, Clone)]
pub struct AddressTakenLocals {
    /// Every name the function declares: its parameters and every object its
    /// body declares (`extern` declarations and prototypes excluded).
    locals: HashSet<String>,
    /// Each local's declared type specifier and pointer depth, for telling
    /// a store of the object's own type from a store through a pun.
    decls: HashMap<String, (String, usize)>,
    /// The locals each local pointer may point into.
    targets: HashMap<String, HashSet<String>>,
    /// Local pointers whose value may also come from where this function
    /// cannot see, and so may point into any escaped local.
    opaque: HashSet<String>,
    /// Locals whose address reached storage this function does not track.
    escaped: HashSet<String>,
}

impl AddressTakenLocals {
    /// The facts for `func`, a `function_definition`.
    pub fn of_function(func: &Node, source: &str) -> Self {
        let mut facts = AddressTakenLocals::default();
        if let Some(declarator) = func.child_by_field_name("declarator") {
            collect_parameters(&declarator, source, &mut facts);
        }
        let Some(body) = func.child_by_field_name("body") else {
            return facts;
        };
        collect_declarations(&body, source, &mut facts);

        let mut flows: Vec<(String, Vec<Source>)> = Vec::new();
        let mut escapes: Vec<Source> = Vec::new();
        let mut address_taken: HashSet<String> = HashSet::new();
        collect_flows(
            &body,
            source,
            &facts.locals,
            &mut flows,
            &mut escapes,
            &mut address_taken,
        );
        // Every target is some `&x`: a function that takes no address has
        // no pointer into any of its locals.
        if address_taken.is_empty() {
            return facts;
        }
        facts.solve(&flows);
        let mut escaped = HashSet::new();
        for s in &escapes {
            escaped.extend(facts.resolve(s));
        }
        // `int **pp = &q;` with `q` holding `&x`: `**pp = v` writes `x`
        // through a pointer whose own value this analysis does not follow.
        for name in &address_taken {
            if let Some(t) = facts.targets.get(name) {
                escaped.extend(t.iter().cloned());
            }
        }
        facts.escaped = escaped;
        facts
    }

    /// No store through a pointer and no call can write any local this
    /// function names, beyond what `f(&x)` already accounts for.
    pub fn is_empty(&self) -> bool {
        self.escaped.is_empty() && self.targets.values().all(HashSet::is_empty)
    }

    /// Locals whose address escaped: any store through a pointer, and any
    /// call, may write them.
    pub fn escaped(&self) -> impl Iterator<Item = &String> {
        self.escaped.iter()
    }

    /// Whether `name`'s address escaped.
    pub fn has_escaped(&self, name: &str) -> bool {
        self.escaped.contains(name)
    }

    /// Whether the function declares `name`: a parameter or an object its
    /// body declares.
    pub fn is_local(&self, name: &str) -> bool {
        self.locals.contains(name)
    }

    /// The locals a store through the pointer `base` may write, as in
    /// `*base = v`, `base[i] = v` or `base->m = v`.
    pub fn store_targets(&self, base: &Node, source: &str) -> HashSet<String> {
        let mut out = HashSet::new();
        let mut unknown = false;
        for s in sources(base, source) {
            match &s {
                Source::AddrOf(name) if self.locals.contains(name) => {
                    out.insert(name.clone());
                }
                Source::Name(name) if self.locals.contains(name) => {
                    if let Some(t) = self.targets.get(name) {
                        out.extend(t.iter().cloned());
                    }
                    unknown |= self.opaque.contains(name);
                }
                Source::AddrOf(_) => {}
                Source::Name(_) | Source::Opaque => unknown = true,
            }
        }
        if unknown {
            out.extend(self.escaped.iter().cloned());
        }
        out
    }

    /// The locals a callee handed `arg` may write through it: the locals a
    /// pointer the argument computes may point into. `&x` itself counts.
    pub fn argument_targets(&self, arg: &Node, source: &str) -> HashSet<String> {
        let mut out = HashSet::new();
        for s in sources(arg, source) {
            out.extend(self.resolve(&s));
        }
        out
    }

    /// Whether `*base = v` stores an object of `target`'s own declared type
    /// into it: `base` is a single local pointer of one level of indirection
    /// whose pointee type is spelled as `target`'s type is. Only then does
    /// the stored value become the target's value; a store through a pointer
    /// of another type (`char *c = (char *)&x; c[1] = 0;`) changes it to
    /// something that is not the stored value.
    pub fn stores_own_type(&self, base: &Node, target: &str, source: &str) -> bool {
        let base = strip_parens(base);
        if base.kind() != "identifier" {
            return false;
        }
        let name = text(&base, source);
        match (self.decls.get(name), self.decls.get(target)) {
            (Some((pointee, 1)), Some((ty, 0))) => pointee == ty,
            _ => false,
        }
    }

    /// Settle `targets` and `opaque` over every flow into a local pointer.
    fn solve(&mut self, flows: &[(String, Vec<Source>)]) {
        loop {
            let mut changed = false;
            for (lhs, srcs) in flows {
                for s in srcs {
                    let add = self.resolve(s);
                    let opaque = match s {
                        Source::Opaque => true,
                        Source::Name(n) => !self.locals.contains(n) || self.opaque.contains(n),
                        Source::AddrOf(_) => false,
                    };
                    let entry = self.targets.entry(lhs.clone()).or_default();
                    for t in add {
                        changed |= entry.insert(t);
                    }
                    if opaque {
                        changed |= self.opaque.insert(lhs.clone());
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// The locals a pointer from `s` may point into.
    fn resolve(&self, s: &Source) -> HashSet<String> {
        match s {
            Source::AddrOf(name) if self.locals.contains(name) => HashSet::from([name.clone()]),
            Source::Name(name) => self.targets.get(name).cloned().unwrap_or_default(),
            _ => HashSet::new(),
        }
    }
}

/// Whether an `assignment_expression` is a plain `=`.
fn is_plain_assignment(node: &Node) -> bool {
    node.child_by_field_name("operator")
        .is_none_or(|op| op.kind() == "=")
}

/// The node under any parentheses.
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

fn text<'a>(node: &Node, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

/// The pointer a write to `lvalue` stores through, if it stores through one:
/// `p` of `*p`, `p[i]`, `p->m` and `(*p).m`. A plain name, or a member of a
/// struct object the function holds by value, is no store through a pointer.
pub fn store_base<'a>(lvalue: &Node<'a>) -> Option<Node<'a>> {
    let lvalue = strip_parens(lvalue);
    match lvalue.kind() {
        "pointer_expression" => {
            let is_deref = lvalue
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "*");
            if is_deref {
                lvalue.child_by_field_name("argument")
            } else {
                None
            }
        }
        "subscript_expression" => lvalue.child_by_field_name("argument"),
        "field_expression" => {
            let arrow = lvalue
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "->");
            let arg = lvalue.child_by_field_name("argument")?;
            if arrow {
                Some(arg)
            } else {
                store_base(&arg)
            }
        }
        "cast_expression" => store_base(&lvalue.child_by_field_name("value")?),
        _ => None,
    }
}

/// Where the pointer value `expr` computes may come from.
fn sources(expr: &Node, source: &str) -> Vec<Source> {
    let mut out = Vec::new();
    collect_sources(expr, source, &mut out);
    out
}

fn collect_sources(expr: &Node, source: &str, out: &mut Vec<Source>) {
    match expr.kind() {
        "identifier" => out.push(Source::Name(text(expr, source).to_string())),
        "parenthesized_expression" => {
            if let Some(inner) = expr.named_child(0) {
                collect_sources(&inner, source, out);
            }
        }
        "cast_expression" => {
            if let Some(value) = expr.child_by_field_name("value") {
                collect_sources(&value, source, out);
            }
        }
        "pointer_expression" => {
            let Some(arg) = expr.child_by_field_name("argument") else {
                return;
            };
            let is_addr = expr
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "&");
            if !is_addr {
                // `*pp`: a value read through memory.
                out.push(Source::Opaque);
                return;
            }
            match addressed_object_root(&arg) {
                Some(root) => out.push(Source::AddrOf(text(&root, source).to_string())),
                // `&p->m`, `&(*p).m`, `&p[i]` through a pointer: an address
                // inside whatever `p` points to.
                None => match store_base(&arg) {
                    Some(base) => collect_sources(&base, source, out),
                    None => out.push(Source::Opaque),
                },
            }
        }
        "binary_expression" => {
            let op = expr.child_by_field_name("operator").map(|o| o.kind());
            if matches!(op, Some("+") | Some("-")) {
                for field in ["left", "right"] {
                    if let Some(side) = expr.child_by_field_name(field) {
                        collect_sources(&side, source, out);
                    }
                }
            }
        }
        "conditional_expression" => {
            for field in ["consequence", "alternative"] {
                if let Some(arm) = expr.child_by_field_name(field) {
                    collect_sources(&arm, source, out);
                }
            }
        }
        "comma_expression" => {
            if let Some(right) = expr.child_by_field_name("right") {
                collect_sources(&right, source, out);
            }
        }
        // The value of `p = v` is `v`; of `p += n`, `p` moved by an
        // integer offset, which points where `p` did.
        "assignment_expression" => {
            let field = if is_plain_assignment(expr) {
                "right"
            } else {
                "left"
            };
            if let Some(value) = expr.child_by_field_name(field) {
                collect_sources(&value, source, out);
            }
        }
        "update_expression" => {
            if let Some(arg) = expr.child_by_field_name("argument") {
                collect_sources(&arg, source, out);
            }
        }
        // `a[i]` of a two-dimensional local array is an address inside `a`;
        // of a pointer to pointers, a value read through memory.
        "subscript_expression" => {
            if let Some(arg) = expr.child_by_field_name("argument") {
                collect_sources(&arg, source, out);
            }
            out.push(Source::Opaque);
        }
        // A callee may hand back any pointer it was given, or another.
        "call_expression" => {
            if let Some(args) = expr.child_by_field_name("arguments") {
                for i in 0..args.named_child_count() {
                    if let Some(arg) = args.named_child(i) {
                        collect_sources(&arg, source, out);
                    }
                }
            }
            out.push(Source::Opaque);
        }
        "number_literal"
        | "char_literal"
        | "string_literal"
        | "concatenated_string"
        | "sizeof_expression"
        | "null"
        | "true"
        | "false"
        | "comment" => {}
        _ => out.push(Source::Opaque),
    }
}

/// The identifier a declarator declares, or `None` for a function
/// declarator (a block-scope prototype names no object).
fn declarator_name<'a>(declarator: &Node, source: &'a str) -> Option<&'a str> {
    match declarator.kind() {
        "identifier" => Some(text(declarator, source)),
        "function_declarator" => None,
        "pointer_declarator" | "array_declarator" | "init_declarator" | "attributed_declarator" => {
            declarator_name(&declarator.child_by_field_name("declarator")?, source)
        }
        "parenthesized_declarator" => declarator_name(&declarator.named_child(0)?, source),
        _ => None,
    }
}

fn record_decl(
    decl: &Node,
    declarator: &Node,
    source: &str,
    facts: &mut AddressTakenLocals,
) -> Option<String> {
    let name = declarator_name(declarator, source)?.to_string();
    let ty = decl
        .child_by_field_name("type")
        .map(|t| text(&t, source).to_string())
        .unwrap_or_default();
    facts.locals.insert(name.clone());
    facts
        .decls
        .insert(name.clone(), (ty, declarator_depth(declarator)));
    Some(name)
}

fn collect_parameters(declarator: &Node, source: &str, facts: &mut AddressTakenLocals) {
    let mut fd = *declarator;
    // `int *f(int a)`: the function declarator sits under the pointer.
    while fd.kind() != "function_declarator" {
        match fd.child_by_field_name("declarator") {
            Some(inner) => fd = inner,
            None => return,
        }
    }
    let Some(params) = fd.child_by_field_name("parameters") else {
        return;
    };
    for i in 0..params.named_child_count() {
        let Some(param) = params.named_child(i) else {
            continue;
        };
        if param.kind() != "parameter_declaration" {
            continue;
        }
        if let Some(d) = param.child_by_field_name("declarator") {
            if let Some(name) = record_decl(&param, &d, source, facts) {
                // A parameter's value comes from the caller.
                facts.opaque.insert(name);
            }
        }
    }
}

fn is_extern(decl: &Node, source: &str) -> bool {
    (0..decl.named_child_count())
        .filter_map(|i| decl.named_child(i))
        .any(|c| c.kind() == "storage_class_specifier" && text(&c, source) == "extern")
}

fn collect_declarations(node: &Node, source: &str, facts: &mut AddressTakenLocals) {
    if node.kind() == "declaration" && !is_extern(node, source) {
        let mut cursor = node.walk();
        for d in node.children_by_field_name("declarator", &mut cursor) {
            record_decl(node, &d, source, facts);
        }
    }
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            collect_declarations(&child, source, facts);
        }
    }
}

/// Every flow of a pointer value into a local pointer variable, every flow
/// into storage this analysis does not track, and every name whose own
/// address is taken.
fn collect_flows(
    node: &Node,
    source: &str,
    locals: &HashSet<String>,
    flows: &mut Vec<(String, Vec<Source>)>,
    escapes: &mut Vec<Source>,
    address_taken: &mut HashSet<String>,
) {
    match node.kind() {
        // Only `=` stores a pointer: in `p += n` and `p -= n` the right
        // side is an integer offset, which moves `p` within whatever it
        // already pointed into, and the other compound operators take no
        // pointer. Reading the offset as a source made
        // `p += read_varint(p, &len)` look like `p` may point at `len`.
        "assignment_expression" if is_plain_assignment(node) => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                let srcs = sources(&right, source);
                let left = strip_parens(&left);
                if left.kind() == "identifier" && locals.contains(text(&left, source)) {
                    flows.push((text(&left, source).to_string(), srcs));
                } else {
                    // A file-scope object, a member, an element, a pointee.
                    escapes.extend(srcs);
                }
            }
        }
        "init_declarator" => {
            if let (Some(declarator), Some(value)) = (
                node.child_by_field_name("declarator"),
                node.child_by_field_name("value"),
            ) {
                if value.kind() == "initializer_list" {
                    collect_initializer_escapes(&value, source, escapes);
                } else if let Some(name) = declarator_name(&declarator, source) {
                    flows.push((name.to_string(), sources(&value, source)));
                }
            }
        }
        "compound_literal_expression" => {
            if let Some(value) = node.child_by_field_name("value") {
                collect_initializer_escapes(&value, source, escapes);
            }
        }
        "pointer_expression" => {
            let is_addr = node
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "&");
            if is_addr {
                if let Some(root) = node
                    .child_by_field_name("argument")
                    .and_then(|a| addressed_object_root(&a))
                {
                    address_taken.insert(text(&root, source).to_string());
                }
            }
        }
        _ => {}
    }
    for i in 0..node.named_child_count() {
        if let Some(child) = node.named_child(i) {
            collect_flows(&child, source, locals, flows, escapes, address_taken);
        }
    }
}

/// Every pointer an initializer list stores: into an object this analysis
/// does not track element by element.
fn collect_initializer_escapes(list: &Node, source: &str, escapes: &mut Vec<Source>) {
    for i in 0..list.named_child_count() {
        let Some(item) = list.named_child(i) else {
            continue;
        };
        match item.kind() {
            "initializer_list" => collect_initializer_escapes(&item, source, escapes),
            "initializer_pair" => {
                if let Some(value) = item.child_by_field_name("value") {
                    if value.kind() == "initializer_list" {
                        collect_initializer_escapes(&value, source, escapes);
                    } else {
                        escapes.extend(sources(&value, source));
                    }
                }
            }
            _ => escapes.extend(sources(&item, source)),
        }
    }
}
