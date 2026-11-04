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

use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tree_sitter::Node;

use super::argument_objects::declarator_depth;
use super::init_state::addressed_object_root;
use crate::utility::cert_c::ast_utils::{tree_root, ScopeDeclarations};

/// One local of a function: the start byte of the identifier its declarator
/// declares. Two declarations of one name in nested blocks are two locals,
/// and an occurrence of the name is the one its scope resolves it to
/// (ADR-0006), never the other by its spelling.
pub type LocalId = usize;

/// Where a pointer value an expression computes may come from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Source {
    /// The address of (somewhere inside) this local's own storage.
    AddrOf(LocalId),
    /// The value of this local.
    Name(LocalId),
    /// A value this function cannot follow: a parameter's or file-scope
    /// object's, one read through memory, a call's result.
    Opaque,
}

/// The pointer facts of one function: which locals each local pointer may
/// point into, and which locals' addresses escaped.
#[derive(Debug, Default, Clone)]
pub struct AddressTakenLocals {
    /// Every local the function declares, with its name: its parameters
    /// and every object its body declares (`extern` declarations and
    /// prototypes excluded).
    names: HashMap<LocalId, String>,
    /// Each local's declared type specifier, whitespace-squeezed, and its
    /// pointer depth, for telling a store of the object's own type from a
    /// store through a pun.
    decls: HashMap<LocalId, (String, usize)>,
    /// The local each identifier occurrence in the function refers to, by
    /// the occurrence's start byte. An occurrence missing here names no
    /// local: a file-scope object, a function, an enumerator.
    occurrences: HashMap<usize, LocalId>,
    /// The locals each local pointer may point into.
    targets: HashMap<LocalId, HashSet<LocalId>>,
    /// Local pointers whose value may also come from where this function
    /// cannot see, and so may point into any escaped local.
    opaque: HashSet<LocalId>,
    /// Locals whose address reached storage this function does not track.
    escaped: HashSet<LocalId>,
}

/// The identity of one function of one parse, for memoising what is
/// computed per function: the node's id and span, the source's buffer, and
/// a hash of the function's text, so a tree or buffer freed and reallocated
/// at the same address with other text is never taken for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FunctionKey {
    id: usize,
    span: (usize, usize),
    buffer: (usize, usize),
    text: u64,
}

impl FunctionKey {
    /// The key of `func`, a node of the tree parsed from `source`.
    pub fn of(func: &Node, source: &str) -> Self {
        let mut hasher = DefaultHasher::new();
        text(func, source).hash(&mut hasher);
        FunctionKey {
            id: func.id(),
            span: (func.start_byte(), func.end_byte()),
            buffer: (source.as_ptr() as usize, source.len()),
            text: hasher.finish(),
        }
    }
}

/// What is computed once per function, remembered for every function of
/// the file being scanned. A rule walking a file asks for one function's
/// facts again after asking for every other function's (value-range
/// analysis runs over the whole file first), so one remembered function is
/// not enough.
///
/// The memo is forgotten whenever the parser reads a file
/// ([`forget_function_facts`], from `CParser`), since what is remembered
/// can depend on the rest of the file and a buffer's address and length do
/// not identify its text: the next file may be allocated where the last one
/// was. A different buffer starts it afresh as well, and so does reaching
/// [`FunctionMemo::CAPACITY`] functions.
pub struct FunctionMemo<T> {
    buffer: (usize, usize),
    entries: HashMap<FunctionKey, T>,
}

impl<T: Clone> FunctionMemo<T> {
    /// Functions remembered before the memo starts afresh.
    pub const CAPACITY: usize = 4096;

    /// An empty memo.
    pub fn new() -> Self {
        FunctionMemo {
            buffer: (0, 0),
            entries: HashMap::new(),
        }
    }

    /// What is remembered for `key`.
    pub fn get(&self, key: &FunctionKey) -> Option<T> {
        (self.buffer == key.buffer)
            .then(|| self.entries.get(key).cloned())
            .flatten()
    }

    /// Remember `value` for `key`.
    pub fn insert(&mut self, key: FunctionKey, value: T) {
        if self.buffer != key.buffer || self.entries.len() >= Self::CAPACITY {
            self.forget();
            self.buffer = key.buffer;
        }
        self.entries.insert(key, value);
    }

    /// Forget everything remembered.
    pub fn forget(&mut self) {
        self.entries.clear();
        self.buffer = (0, 0);
    }
}

/// Forget the address facts remembered on this thread; the parser calls it
/// through `nonzero_facts::forget_function_facts` before each file.
pub fn forget_function_facts() {
    FACTS.with(|memo| memo.borrow_mut().forget());
}

impl<T: Clone> Default for FunctionMemo<T> {
    fn default() -> Self {
        Self::new()
    }
}

thread_local! {
    /// The facts of the functions of the source last asked about on this
    /// thread: value-range analysis and every guard a rule checks ask for
    /// the same facts.
    static FACTS: RefCell<FunctionMemo<Arc<AddressTakenLocals>>> =
        RefCell::new(FunctionMemo::new());
}

#[cfg(test)]
thread_local! {
    /// How many times [`AddressTakenLocals::of_function`] built the facts
    /// of a function, rather than remembered them, on this thread.
    static BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Facts built on this thread since the last call.
#[cfg(test)]
pub(crate) fn take_builds() -> usize {
    BUILDS.with(|n| n.replace(0))
}

impl AddressTakenLocals {
    /// The facts for `func`, a `function_definition`, built once for the
    /// function however many callers ask ([`FunctionMemo`]).
    pub fn of_function(func: &Node, source: &str) -> Arc<Self> {
        let key = FunctionKey::of(func, source);
        if let Some(facts) = FACTS.with(|memo| memo.borrow().get(&key)) {
            return facts;
        }
        let facts = Arc::new(Self::build(func, source));
        FACTS.with(|memo| memo.borrow_mut().insert(key, Arc::clone(&facts)));
        facts
    }

    fn build(func: &Node, source: &str) -> Self {
        #[cfg(test)]
        BUILDS.with(|n| n.set(n.get() + 1));
        let mut facts = AddressTakenLocals::default();
        // Every target is some `&x`: a function that takes no address has
        // no pointer into any of its locals.
        if !takes_an_address(func) {
            return facts;
        }
        if let Some(declarator) = func.child_by_field_name("declarator") {
            collect_parameters(&declarator, source, &mut facts);
        }
        let Some(body) = func.child_by_field_name("body") else {
            return facts;
        };
        collect_declarations(&body, source, &mut facts);
        facts.resolve_occurrences(&body, source);

        let mut flows: Vec<(LocalId, Vec<Source>)> = Vec::new();
        let mut escapes: Vec<Source> = Vec::new();
        let mut address_taken: HashSet<LocalId> = HashSet::new();
        facts.collect_flows(&body, source, &mut flows, &mut escapes, &mut address_taken);
        facts.solve(&flows);
        let mut escaped = HashSet::new();
        for s in &escapes {
            escaped.extend(facts.resolve(s));
        }
        // `int **pp = &q;` with `q` holding `&x`: `**pp = v` writes `x`
        // through a pointer whose own value this analysis does not follow.
        for local in &address_taken {
            if let Some(t) = facts.targets.get(local) {
                escaped.extend(t.iter().copied());
            }
        }
        facts.escaped = escaped;
        facts
    }

    /// Map every occurrence of a local's name in `body` to the local it
    /// resolves to. Only names some local is declared with are resolved.
    fn resolve_occurrences(&mut self, body: &Node, source: &str) {
        let spelled: HashSet<&str> = self.names.values().map(String::as_str).collect();
        let root = tree_root(body);
        let declarations = ScopeDeclarations::indexed(root);
        let mut found: Vec<(usize, LocalId)> = Vec::new();
        let mut cursor = body.walk();
        'walk: loop {
            let node = cursor.node();
            if node.kind() == "identifier" {
                let name = text(&node, source);
                if spelled.contains(name) && !self.names.contains_key(&node.start_byte()) {
                    let local = declarations
                        .resolve_identifier_declarator_in(&root, &node, name, source)
                        .and_then(|(_, declarator)| declared_identifier(&declarator))
                        .map(|ident| ident.start_byte())
                        .filter(|id| self.names.contains_key(id));
                    if let Some(id) = local {
                        found.push((node.start_byte(), id));
                    }
                }
            }
            if cursor.goto_first_child() {
                continue;
            }
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() || cursor.node().id() == body.id() {
                    break 'walk;
                }
            }
        }
        // A declaration's own name is that local.
        for &id in self.names.keys() {
            self.occurrences.insert(id, id);
        }
        self.occurrences.extend(found);
    }

    /// The local the identifier `ident` refers to, if it refers to one.
    pub fn local_of(&self, ident: &Node) -> Option<LocalId> {
        if ident.kind() != "identifier" {
            return None;
        }
        self.occurrences.get(&ident.start_byte()).copied()
    }

    /// The local `declarator` (from a declaration in this function)
    /// declares, if it declares one.
    pub fn local_declared_by(&self, declarator: &Node) -> Option<LocalId> {
        declared_identifier(declarator).and_then(|ident| self.local_of(&ident))
    }

    /// The name `local` is declared with.
    pub fn name(&self, local: LocalId) -> &str {
        self.names.get(&local).map_or("", String::as_str)
    }

    /// No store through a pointer and no call can write any local this
    /// function names, beyond what `f(&x)` already accounts for.
    pub fn is_empty(&self) -> bool {
        self.escaped.is_empty() && self.targets.values().all(HashSet::is_empty)
    }

    /// Locals whose address escaped: any store through a pointer, and any
    /// call, may write them.
    pub fn escaped(&self) -> impl Iterator<Item = LocalId> + '_ {
        self.escaped.iter().copied()
    }

    /// Whether `local`'s address escaped.
    pub fn has_escaped(&self, local: LocalId) -> bool {
        self.escaped.contains(&local)
    }

    /// The locals a store through the pointer `base` may write, as in
    /// `*base = v`, `base[i] = v` or `base->m = v`.
    pub fn store_targets(&self, base: &Node, source: &str) -> HashSet<LocalId> {
        let mut out = HashSet::new();
        let mut unknown = false;
        for s in self.sources(base, source) {
            match s {
                Source::AddrOf(local) => {
                    out.insert(local);
                }
                Source::Name(local) => {
                    if let Some(t) = self.targets.get(&local) {
                        out.extend(t.iter().copied());
                    }
                    unknown |= self.opaque.contains(&local);
                }
                Source::Opaque => unknown = true,
            }
        }
        if unknown {
            out.extend(self.escaped.iter().copied());
        }
        out
    }

    /// The locals a callee handed `arg` may write through it: the locals a
    /// pointer the argument computes may point into. `&x` itself counts.
    pub fn argument_targets(&self, arg: &Node, source: &str) -> HashSet<LocalId> {
        let mut out = HashSet::new();
        for s in self.sources(arg, source) {
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
    pub fn stores_own_type(&self, base: &Node, target: LocalId) -> bool {
        let base = strip_parens(base);
        let Some(pointer) = self.local_of(&base) else {
            return false;
        };
        match (self.decls.get(&pointer), self.decls.get(&target)) {
            (Some((pointee, 1)), Some((ty, 0))) => pointee == ty,
            _ => false,
        }
    }

    /// Settle `targets` and `opaque` over every flow into a local pointer.
    fn solve(&mut self, flows: &[(LocalId, Vec<Source>)]) {
        loop {
            let mut changed = false;
            for (lhs, srcs) in flows {
                for s in srcs {
                    let add = self.resolve(s);
                    let opaque = match s {
                        Source::Opaque => true,
                        Source::Name(local) => self.opaque.contains(local),
                        Source::AddrOf(_) => false,
                    };
                    let entry = self.targets.entry(*lhs).or_default();
                    for t in add {
                        changed |= entry.insert(t);
                    }
                    if opaque {
                        changed |= self.opaque.insert(*lhs);
                    }
                }
            }
            if !changed {
                break;
            }
        }
    }

    /// The locals a pointer from `s` may point into.
    fn resolve(&self, s: &Source) -> HashSet<LocalId> {
        match s {
            Source::AddrOf(local) => HashSet::from([*local]),
            Source::Name(local) => self.targets.get(local).cloned().unwrap_or_default(),
            Source::Opaque => HashSet::new(),
        }
    }

    /// Where the pointer value `expr` computes may come from.
    fn sources(&self, expr: &Node, source: &str) -> Vec<Source> {
        let mut out = Vec::new();
        self.collect_sources(expr, source, &mut out);
        out
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

impl AddressTakenLocals {
    fn collect_sources(&self, expr: &Node, source: &str, out: &mut Vec<Source>) {
        match expr.kind() {
            "identifier" => out.push(match self.local_of(expr) {
                Some(local) => Source::Name(local),
                // A file-scope object, or a name this function cannot see.
                None => Source::Opaque,
            }),
            "parenthesized_expression" => {
                if let Some(inner) = expr.named_child(0) {
                    self.collect_sources(&inner, source, out);
                }
            }
            "cast_expression" => {
                if let Some(value) = expr.child_by_field_name("value") {
                    self.collect_sources(&value, source, out);
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
                    // The address of a file-scope object points into no
                    // local.
                    Some(root) => {
                        if let Some(local) = self.local_of(&root) {
                            out.push(Source::AddrOf(local));
                        }
                    }
                    // `&p->m`, `&(*p).m`, `&p[i]` through a pointer: an
                    // address inside whatever `p` points to.
                    None => match store_base(&arg) {
                        Some(base) => self.collect_sources(&base, source, out),
                        None => out.push(Source::Opaque),
                    },
                }
            }
            "binary_expression" => {
                let op = expr.child_by_field_name("operator").map(|o| o.kind());
                if matches!(op, Some("+") | Some("-")) {
                    for field in ["left", "right"] {
                        if let Some(side) = expr.child_by_field_name(field) {
                            self.collect_sources(&side, source, out);
                        }
                    }
                }
            }
            "conditional_expression" => {
                for field in ["consequence", "alternative"] {
                    if let Some(arm) = expr.child_by_field_name(field) {
                        self.collect_sources(&arm, source, out);
                    }
                }
            }
            "comma_expression" => {
                if let Some(right) = expr.child_by_field_name("right") {
                    self.collect_sources(&right, source, out);
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
                    self.collect_sources(&value, source, out);
                }
            }
            "update_expression" => {
                if let Some(arg) = expr.child_by_field_name("argument") {
                    self.collect_sources(&arg, source, out);
                }
            }
            // `a[i]` of a two-dimensional local array is an address inside
            // `a`; of a pointer to pointers, a value read through memory.
            "subscript_expression" => {
                if let Some(arg) = expr.child_by_field_name("argument") {
                    self.collect_sources(&arg, source, out);
                }
                out.push(Source::Opaque);
            }
            // A callee may hand back any pointer it was given, or another.
            "call_expression" => {
                if let Some(args) = expr.child_by_field_name("arguments") {
                    for i in 0..args.named_child_count() {
                        if let Some(arg) = args.named_child(i) {
                            self.collect_sources(&arg, source, out);
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

    /// Every flow of a pointer value into a local pointer variable, every
    /// flow into storage this analysis does not track, and every local
    /// whose own address is taken.
    fn collect_flows(
        &self,
        node: &Node,
        source: &str,
        flows: &mut Vec<(LocalId, Vec<Source>)>,
        escapes: &mut Vec<Source>,
        address_taken: &mut HashSet<LocalId>,
    ) {
        match node.kind() {
            // Only `=` stores a pointer: in `p += n` and `p -= n` the right
            // side is an integer offset, which moves `p` within whatever it
            // already pointed into, and the other compound operators take
            // no pointer. Reading the offset as a source made
            // `p += read_varint(p, &len)` look like `p` may point at `len`.
            "assignment_expression" if is_plain_assignment(node) => {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let srcs = self.sources(&right, source);
                    match self.local_of(&strip_parens(&left)) {
                        Some(local) => flows.push((local, srcs)),
                        // A file-scope object, a member, an element, a
                        // pointee.
                        None => escapes.extend(srcs),
                    }
                }
            }
            "init_declarator" => {
                if let (Some(declarator), Some(value)) = (
                    node.child_by_field_name("declarator"),
                    node.child_by_field_name("value"),
                ) {
                    if value.kind() == "initializer_list" {
                        self.collect_initializer_escapes(&value, source, escapes);
                    } else if let Some(local) =
                        declared_identifier(&declarator).and_then(|i| self.local_of(&i))
                    {
                        flows.push((local, self.sources(&value, source)));
                    } else {
                        escapes.extend(self.sources(&value, source));
                    }
                }
            }
            "compound_literal_expression" => {
                if let Some(value) = node.child_by_field_name("value") {
                    self.collect_initializer_escapes(&value, source, escapes);
                }
            }
            "pointer_expression" => {
                let is_addr = node
                    .child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "&");
                if is_addr {
                    if let Some(local) = node
                        .child_by_field_name("argument")
                        .and_then(|a| addressed_object_root(&a))
                        .and_then(|root| self.local_of(&root))
                    {
                        address_taken.insert(local);
                    }
                }
            }
            _ => {}
        }
        for i in 0..node.named_child_count() {
            if let Some(child) = node.named_child(i) {
                self.collect_flows(&child, source, flows, escapes, address_taken);
            }
        }
    }

    /// Every pointer an initializer list stores: into an object this
    /// analysis does not track element by element.
    fn collect_initializer_escapes(&self, list: &Node, source: &str, escapes: &mut Vec<Source>) {
        for i in 0..list.named_child_count() {
            let Some(item) = list.named_child(i) else {
                continue;
            };
            match item.kind() {
                "initializer_list" => self.collect_initializer_escapes(&item, source, escapes),
                "initializer_pair" => {
                    if let Some(value) = item.child_by_field_name("value") {
                        if value.kind() == "initializer_list" {
                            self.collect_initializer_escapes(&value, source, escapes);
                        } else {
                            escapes.extend(self.sources(&value, source));
                        }
                    }
                }
                _ => escapes.extend(self.sources(&item, source)),
            }
        }
    }
}

/// Whether `func` applies `&` anywhere.
fn takes_an_address(func: &Node) -> bool {
    let mut cursor = func.walk();
    'walk: loop {
        let node = cursor.node();
        if node.kind() == "pointer_expression"
            && node
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "&")
        {
            return true;
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() || cursor.node().id() == func.id() {
                break 'walk;
            }
        }
    }
    false
}

/// The identifier a declarator declares, or `None` for a function
/// declarator (a block-scope prototype names no object).
pub(crate) fn declared_identifier<'a>(declarator: &Node<'a>) -> Option<Node<'a>> {
    match declarator.kind() {
        "identifier" => Some(*declarator),
        "function_declarator" => None,
        "pointer_declarator" | "array_declarator" | "init_declarator" | "attributed_declarator" => {
            declared_identifier(&declarator.child_by_field_name("declarator")?)
        }
        "parenthesized_declarator" => declared_identifier(&declarator.named_child(0)?),
        _ => None,
    }
}

/// Every local `func` declares, as [`AddressTakenLocals`] counts them: its
/// parameters, then every object its body declares (`extern` declarations
/// and prototypes excluded), each with its name, whether or not the
/// function takes an address.
pub(crate) fn function_locals(func: &Node, source: &str) -> Vec<(LocalId, String)> {
    let mut facts = AddressTakenLocals::default();
    if let Some(declarator) = func.child_by_field_name("declarator") {
        collect_parameters(&declarator, source, &mut facts);
    }
    if let Some(body) = func.child_by_field_name("body") {
        collect_declarations(&body, source, &mut facts);
    }
    let mut locals: Vec<(LocalId, String)> = facts.names.into_iter().collect();
    locals.sort_unstable_by_key(|&(id, _)| id);
    locals
}

fn record_decl(
    decl: &Node,
    declarator: &Node,
    source: &str,
    facts: &mut AddressTakenLocals,
) -> Option<LocalId> {
    let ident = declared_identifier(declarator)?;
    let id = ident.start_byte();
    let ty = decl
        .child_by_field_name("type")
        .map(|t| {
            text(&t, source)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    facts.names.insert(id, text(&ident, source).to_string());
    facts.decls.insert(id, (ty, declarator_depth(declarator)));
    Some(id)
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
            if let Some(id) = record_decl(&param, &d, source, facts) {
                // A parameter's value comes from the caller.
                facts.opaque.insert(id);
            }
        }
    }
}

fn is_extern(decl: &Node, source: &str) -> bool {
    (0..decl.named_child_count())
        .filter_map(|i| decl.named_child(i))
        .any(|c| c.kind() == "storage_class_specifier" && text(&c, source) == "extern")
}

/// Record every declaration under `node`. A stack, not recursion: value-range
/// analysis asks for the locals of every function it analyses, however
/// deeply its statements nest.
fn collect_declarations(node: &Node, source: &str, facts: &mut AddressTakenLocals) {
    let mut stack = vec![*node];
    while let Some(node) = stack.pop() {
        if node.kind() == "declaration" && !is_extern(&node, source) {
            let mut cursor = node.walk();
            for d in node.children_by_field_name("declarator", &mut cursor) {
                record_decl(&node, &d, source, facts);
            }
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(code: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        parser.parse(code, None).unwrap()
    }

    fn first_function(tree: &tree_sitter::Tree) -> Node<'_> {
        let root = tree.root_node();
        (0..root.named_child_count())
            .filter_map(|i| root.named_child(i))
            .find(|n| n.kind() == "function_definition")
            .unwrap()
    }

    fn find<'t>(node: Node<'t>, source: &str, kind: &str, text: &str) -> Vec<Node<'t>> {
        let mut out = Vec::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            if n.kind() == kind && super::text(&n, source) == text {
                out.push(n);
            }
            for i in (0..n.named_child_count()).rev() {
                stack.push(n.named_child(i).unwrap());
            }
        }
        out
    }

    /// The local `name` declares at its `nth` declaration, in source order.
    fn declared(facts: &AddressTakenLocals, name: &str, nth: usize) -> LocalId {
        let mut ids: Vec<LocalId> = facts
            .names
            .iter()
            .filter(|(_, n)| n.as_str() == name)
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids[nth]
    }

    /// A store through a pointer to a block's own `x` writes that `x`, not
    /// the one it shadows: the two are two locals, told apart by scope and
    /// not by spelling.
    #[test]
    fn a_store_reaches_the_shadowing_local_alone() {
        let src = "int r(void);\nint f(void) { int x = 1; { int x = 2; int *q = &x; *q = r(); } return x; }\n";
        let tree = parse(src);
        let func = first_function(&tree);
        let facts = AddressTakenLocals::of_function(&func, src);
        let (outer, inner) = (declared(&facts, "x", 0), declared(&facts, "x", 1));
        assert_ne!(outer, inner);
        let deref = find(func, src, "pointer_expression", "*q").pop().unwrap();
        let base = store_base(&deref).unwrap();
        assert_eq!(facts.store_targets(&base, src), HashSet::from([inner]));
        assert!(facts.stores_own_type(&base, inner));
        assert!(!facts.has_escaped(outer) && !facts.has_escaped(inner));
    }

    /// `g = &x` assigns the file-scope `g` even where a block later
    /// declares a local `g`: the address escapes, and a call may write `x`.
    #[test]
    fn an_address_stored_in_a_shadowed_global_escapes() {
        let src =
            "int *g;\nint f(void) { int x = 1; g = &x; { int *g = 0; (void)g; } return x; }\n";
        let tree = parse(src);
        let func = first_function(&tree);
        let facts = AddressTakenLocals::of_function(&func, src);
        assert!(facts.has_escaped(declared(&facts, "x", 0)));
        assert_eq!(facts.escaped().count(), 1);
    }

    /// One build serves every caller that asks about the same function in a
    /// row, and a function of another text is built anew.
    #[test]
    fn the_facts_of_a_function_are_built_once() {
        let src = "int f(void) { int x = 1; int *q = &x; *q = 2; return x; }\n";
        let tree = parse(src);
        let func = first_function(&tree);
        take_builds();
        let first = AddressTakenLocals::of_function(&func, src);
        for _ in 0..50 {
            assert!(Arc::ptr_eq(
                &first,
                &AddressTakenLocals::of_function(&func, src)
            ));
        }
        assert_eq!(take_builds(), 1);
        let other = "int f(void) { int y = 1; int *q = &y; *q = 2; return y; }\n";
        let tree2 = parse(other);
        AddressTakenLocals::of_function(&first_function(&tree2), other);
        assert_eq!(take_builds(), 1);
    }

    #[test]
    fn a_function_asked_about_again_after_the_others_is_not_rebuilt() {
        // Value-range analysis asks for every function's facts before a
        // rule's checks ask for the first function's again.
        let src = "int f(void) { int x = 1; int *q = &x; *q = 2; return x; }\n\
                   int g(void) { int y = 1; int *p = &y; *p = 3; return y; }\n";
        let tree = parse(src);
        let functions: Vec<_> = (0..tree.root_node().named_child_count())
            .filter_map(|i| tree.root_node().named_child(i))
            .filter(|n| n.kind() == "function_definition")
            .collect();
        assert_eq!(functions.len(), 2);
        take_builds();
        for _ in 0..10 {
            for func in &functions {
                AddressTakenLocals::of_function(func, src);
            }
        }
        assert_eq!(take_builds(), 2);
    }
}
