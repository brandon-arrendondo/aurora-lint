// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

// CON40-C: Do not refer to an atomic variable twice in an expression
//
// Two forms are reported:
//
// 1. One full expression that accesses the same atomic object two or more
//    times. An access is a name, member path, element or dereference whose
//    declaration gives it an atomic type, resolved by declaration
//    (ADR-0006), so a struct that merely has `_Atomic` members is not itself
//    atomic and `config.x` is not an access to `config.live`; or an
//    `atomic_*` operation on the object it is handed. The left operand of a
//    compound assignment is one access (`flag ^= 1`). The operands of
//    `sizeof`, `_Alignof`, `typeof` and `&` are not accesses, nor is a
//    `_Generic` controlling expression. A call's arguments belong to the
//    call's full expression; a statement inside a GNU statement expression
//    is a full expression of its own. Each full expression is reported
//    once, at its outermost expression.
// 2. CERT's split-statement form, reported for review: an `atomic_load` of
//    an object whose value, through locals, is what a later `atomic_store`
//    of the same object writes (`t = atomic_load(&f); t = !t;
//    atomic_store(&f, t);`).
//
// Not seen: an atomic typedef declared in a header (`atomic_*` names and
// aliases of them are), a member of a header's struct reached through a
// pointer or array member, and a declaration the parser misreads other
// than `_Atomic(T) x;` without a storage class.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::{ProjectContext, VisibleTypes};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{
    get_node_text, misread_atomic_declaration, ScopeDeclarations,
};
use crate::utility::cert_c::declarator_utils::inner_declarator;
use crate::utility::cert_c::node_children::NodeChildren;
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
    "call_expression",
];

/// Expressions whose operand is not evaluated.
const UNEVALUATED_KINDS: &[&str] = &[
    "sizeof_expression",
    "alignof_expression",
    "offsetof_expression",
];

/// Calls the grammar reads where the operand is not evaluated: `typeof` in
/// an expression statement parses as a call.
const UNEVALUATED_CALLEES: &[&str] = &[
    "typeof",
    "__typeof__",
    "__typeof",
    "typeof_unqual",
    "__typeof_unqual__",
    "_Alignof",
    "alignof",
    "__alignof__",
    "__alignof",
    "offsetof",
    "__builtin_offsetof",
    "__builtin_types_compatible_p",
    "__builtin_constant_p",
];

const LOAD_FUNCTIONS: &[&str] = &["atomic_load", "atomic_load_explicit"];
const STORE_FUNCTIONS: &[&str] = &["atomic_store", "atomic_store_explicit"];

/// The `<stdatomic.h>` generic functions that access the object their first
/// argument points at (C11 7.17.7, 7.17.8 excluded: `atomic_flag` is not an
/// operand).
const ATOMIC_OPERATIONS: &[&str] = &[
    "atomic_load",
    "atomic_load_explicit",
    "atomic_store",
    "atomic_store_explicit",
    "atomic_exchange",
    "atomic_exchange_explicit",
    "atomic_compare_exchange_strong",
    "atomic_compare_exchange_strong_explicit",
    "atomic_compare_exchange_weak",
    "atomic_compare_exchange_weak_explicit",
    "atomic_fetch_add",
    "atomic_fetch_add_explicit",
    "atomic_fetch_sub",
    "atomic_fetch_sub_explicit",
    "atomic_fetch_or",
    "atomic_fetch_or_explicit",
    "atomic_fetch_xor",
    "atomic_fetch_xor_explicit",
    "atomic_fetch_and",
    "atomic_fetch_and_explicit",
];

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

/// The object an access names: the declarator its root name resolves to,
/// then each member, and `[i]` for each element or dereference. `p->m`,
/// `(*p).m` and `p[0].m` are the same object; an element is keyed by its
/// index's spelling.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ObjectKey {
    root: usize,
    members: Vec<String>,
}

/// One step between a declared name and its declaration's specifiers,
/// nearest the name first: `int *_Atomic a[4]` is an array of atomic
/// pointers to `int`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Derivation {
    Array,
    Pointer {
        atomic: bool,
    },
    Function,
    /// A shape read from type text, which says no more.
    Unknown,
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
    /// The derivations still between this object and the specifiers.
    derivations: Vec<Derivation>,
    /// Whether the specifiers give an atomic type.
    base_atomic: bool,
    aggregate: Option<Aggregate<'a>>,
}

impl Resolved<'_> {
    fn atomic(&self) -> bool {
        match self.derivations.first() {
            None => self.base_atomic,
            Some(Derivation::Pointer { atomic }) => *atomic,
            Some(_) => false,
        }
    }

    /// The object one subscript or dereference away: the element of an
    /// array, the object a pointer points at.
    fn element(mut self, index: String) -> Self {
        match self.derivations.first() {
            Some(Derivation::Array | Derivation::Pointer { .. }) => {
                self.derivations.remove(0);
            }
            Some(Derivation::Unknown) => {}
            None | Some(Derivation::Function) => self.derivations = vec![Derivation::Unknown],
        }
        self.key.members.push(format!("[{index}]"));
        self
    }
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
    /// Typedef names this file declares with `_Atomic`, which the typedef
    /// table (specifiers only) does not record.
    atomic_typedefs: HashSet<String>,
    /// `_Atomic(T) x;` with no storage class, which the grammar reads as
    /// an `ERROR` and a cast: name -> (the name's node, its scope).
    misread: HashMap<String, Vec<(Node<'a>, Node<'a>)>>,
    /// Names something in reach declares atomic: identifiers this file
    /// declares so, and members of any visible struct. Anything else is
    /// never resolved.
    candidate_names: HashSet<String>,
    /// Struct and union bodies this file defines once under a tag, and
    /// typedef names it defines as one: these are read from the tree, not
    /// from the tables' type text.
    tag_bodies: HashMap<String, Node<'a>>,
    typedef_bodies: HashMap<String, Node<'a>>,
    memo: HashMap<usize, Option<Resolved<'a>>>,
}

/// The `<stdatomic.h>` atomic type names (C11 7.17.6, and C23's
/// `atomic_char8_t`). `atomic_flag` is not usable as an operand.
const ATOMIC_TYPE_NAMES: &[&str] = &[
    "atomic_bool",
    "atomic_char",
    "atomic_schar",
    "atomic_uchar",
    "atomic_short",
    "atomic_ushort",
    "atomic_int",
    "atomic_uint",
    "atomic_long",
    "atomic_ulong",
    "atomic_llong",
    "atomic_ullong",
    "atomic_char8_t",
    "atomic_char16_t",
    "atomic_char32_t",
    "atomic_wchar_t",
    "atomic_int_least8_t",
    "atomic_uint_least8_t",
    "atomic_int_least16_t",
    "atomic_uint_least16_t",
    "atomic_int_least32_t",
    "atomic_uint_least32_t",
    "atomic_int_least64_t",
    "atomic_uint_least64_t",
    "atomic_int_fast8_t",
    "atomic_uint_fast8_t",
    "atomic_int_fast16_t",
    "atomic_uint_fast16_t",
    "atomic_int_fast32_t",
    "atomic_uint_fast32_t",
    "atomic_int_fast64_t",
    "atomic_uint_fast64_t",
    "atomic_intptr_t",
    "atomic_uintptr_t",
    "atomic_size_t",
    "atomic_ptrdiff_t",
    "atomic_intmax_t",
    "atomic_uintmax_t",
];

/// Whether `name` is a `<stdatomic.h>` atomic type name. Another name that
/// starts `atomic_` (a kernel's `atomic_t`, a `struct atomic_state`) is
/// whatever its own declaration makes it.
fn is_atomic_type_name(name: &str) -> bool {
    ATOMIC_TYPE_NAMES.contains(&name)
}

fn has_atomic_qualifier(node: &Node, source: &str) -> bool {
    node.child_nodes()
        .any(|c| c.kind() == "type_qualifier" && get_node_text(&c, source) == "_Atomic")
}

fn is_name_node(node: &Node) -> bool {
    matches!(
        node.kind(),
        "identifier" | "field_identifier" | "type_identifier"
    )
}

/// The name a declarator declares.
fn declared_name<'a>(declarator: &Node<'a>) -> Option<Node<'a>> {
    let mut d = *declarator;
    for _ in 0..64 {
        if is_name_node(&d) {
            return Some(d);
        }
        d = inner_declarator(&d)?;
    }
    None
}

/// The derivations `declarator` applies to its name, nearest the name
/// first.
fn derivations(declarator: &Node, source: &str) -> Vec<Derivation> {
    let mut outer_first = Vec::new();
    let mut d = *declarator;
    for _ in 0..64 {
        match d.kind() {
            _ if is_name_node(&d) => break,
            "init_declarator" => {}
            "pointer_declarator" => outer_first.push(Derivation::Pointer {
                atomic: has_atomic_qualifier(&d, source),
            }),
            "array_declarator" => outer_first.push(Derivation::Array),
            "function_declarator" => outer_first.push(Derivation::Function),
            "parenthesized_declarator" | "attributed_declarator" => {}
            _ => return vec![Derivation::Unknown],
        }
        match inner_declarator(&d) {
            Some(inner) if inner.id() != d.id() => d = inner,
            _ => return vec![Derivation::Unknown],
        }
    }
    outer_first.reverse();
    outer_first
}

/// The node an access's spelling ends in, which names what it accesses:
/// the identifier, the member, or that of the object subscripted or
/// dereferenced.
fn access_name<'a>(node: &Node<'a>, source: &str) -> Option<Node<'a>> {
    match node.kind() {
        "identifier" => Some(*node),
        "field_expression" => node.child_by_field_name("field"),
        "subscript_expression" => access_name(&node.child_by_field_name("argument")?, source),
        "pointer_expression" if is_deref(node, source) => {
            access_name(&node.child_by_field_name("argument")?, source)
        }
        "parenthesized_expression" => access_name(&node.named_child(0)?, source),
        _ => None,
    }
}

fn is_deref(node: &Node, source: &str) -> bool {
    node.child_by_field_name("operator")
        .is_some_and(|o| get_node_text(&o, source) == "*")
}

fn is_address_of(node: &Node, source: &str) -> bool {
    node.kind() == "pointer_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|o| get_node_text(&o, source) == "&")
}

fn spelling(node: &Node, source: &str) -> String {
    get_node_text(node, source).split_whitespace().collect()
}

/// How an element's index keys it: by spelling, so `a[i]` twice is one
/// element, unless evaluating the index calls, increments or assigns, when
/// two of the same spelling may be two elements and each is its own.
fn index_key(index: &Node, source: &str) -> String {
    let mut stack = vec![*index];
    while let Some(n) = stack.pop() {
        if unevaluated(&n, source) {
            continue;
        }
        if matches!(
            n.kind(),
            "call_expression" | "update_expression" | "assignment_expression"
        ) {
            return format!("#{}", index.id());
        }
        stack.extend(n.child_nodes());
    }
    spelling(index, source)
}

/// Whether `node` is declared at file scope: in no block, function body or
/// parameter list.
fn at_file_scope(node: &Node) -> bool {
    let mut n = *node;
    while let Some(p) = n.parent() {
        if matches!(
            p.kind(),
            "compound_statement" | "function_definition" | "parameter_list"
        ) {
            return false;
        }
        n = p;
    }
    true
}

/// Whether control cannot leave `statement` at its end: its last statement,
/// looking into a trailing block, is a `break`, `return` or `goto`.
fn ends_in_jump(statement: &Node) -> bool {
    match statement
        .named_child_nodes()
        .filter(|c| c.kind() != "comment")
        .last()
    {
        Some(last) if last.kind() == "compound_statement" => ends_in_jump(&last),
        Some(last) => matches!(
            last.kind(),
            "break_statement" | "return_statement" | "goto_statement"
        ),
        None => false,
    }
}

impl<'a, 's> FileCx<'a, 's> {
    /// Whether a typedef name stands for an atomic type, through its alias
    /// chain.
    fn typedef_is_atomic(&self, name: &str) -> bool {
        let mut current = name.trim();
        for _ in 0..16 {
            if is_atomic_type_name(current) || self.atomic_typedefs.contains(current) {
                return true;
            }
            match self.typedefs.get(current) {
                Some(next) => current = next.trim(),
                None => return false,
            }
        }
        false
    }

    /// Whether the specifiers of `decl` (a declaration, parameter, member
    /// or typedef) give an atomic type: `_Atomic`, `_Atomic(T)`, or a type
    /// name that is or aliases an atomic type.
    fn specifiers_atomic(&self, decl: &Node) -> bool {
        has_atomic_qualifier(decl, self.source)
            || decl
                .child_by_field_name("type")
                .filter(|t| t.kind() == "type_identifier")
                .is_some_and(|t| self.typedef_is_atomic(get_node_text(&t, self.source)))
    }

    /// Whether member type text, as the struct tables file it, names an
    /// atomic type. Text inside `{…}` declares the members of an inline
    /// aggregate, not the member's own type, and the word after `struct`,
    /// `union` or `enum` is a tag, not a type name.
    fn text_atomic(&self, ty: &str) -> bool {
        let mut outside = String::with_capacity(ty.len());
        let mut depth = 0usize;
        for c in ty.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                _ if depth == 0 => outside.push(c),
                _ => {}
            }
        }
        let mut after_keyword = false;
        for t in outside
            .split(|c: char| !(c.is_alphanumeric() || c == '_'))
            .filter(|t| !t.is_empty())
        {
            if after_keyword {
                after_keyword = false;
                continue;
            }
            if matches!(t, "struct" | "union" | "enum") {
                after_keyword = true;
            } else if t == "_Atomic" || self.typedef_is_atomic(t) {
                return true;
            }
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
                Some(self.tagged(name))
            }
            "type_identifier" => Some(self.named(get_node_text(&ty, self.source))),
            _ => None,
        }
    }

    /// The aggregate a typedef name stands for.
    fn named(&self, name: &str) -> Aggregate<'a> {
        if let Some(body) = self.typedef_bodies.get(name) {
            return Aggregate::Body(*body);
        }
        match self.aliases.get(name) {
            Some(tag) => self.tagged(tag),
            None => Aggregate::Named(name.to_string()),
        }
    }

    /// The aggregate a struct or union tag names.
    fn tagged(&self, tag: &str) -> Aggregate<'a> {
        match self.tag_bodies.get(tag) {
            Some(body) => Aggregate::Body(*body),
            None => Aggregate::Named(tag.to_string()),
        }
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
                if declared_name(&declarator)
                    .is_some_and(|d| get_node_text(&d, self.source) == name)
                {
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

    /// Files every struct or union body defined under a tag at file scope,
    /// and every file-scope typedef of one. A name defined twice, or also
    /// defined in a block or a parameter list, is dropped: which definition
    /// an object sees then depends on scope, and the tables decide instead.
    fn collect_bodies(&mut self, root: &Node<'a>) {
        fn file_body<'a>(
            bodies: &mut HashMap<String, Option<Node<'a>>>,
            name: String,
            body: Node<'a>,
            file_scope: bool,
        ) {
            bodies
                .entry(name)
                .and_modify(|b| *b = None)
                .or_insert(file_scope.then_some(body));
        }
        let mut tags: HashMap<String, Option<Node<'a>>> = HashMap::new();
        for spec in
            query::find_descendants_of_kinds(*root, &["struct_specifier", "union_specifier"])
        {
            let (Some(name), Some(body)) = (
                spec.child_by_field_name("name"),
                spec.child_by_field_name("body"),
            ) else {
                continue;
            };
            let name = get_node_text(&name, self.source).to_string();
            file_body(&mut tags, name, body, at_file_scope(&spec));
        }
        let mut typedefs: HashMap<String, Option<Node<'a>>> = HashMap::new();
        for td in query::find_descendants_of_kind(*root, "type_definition") {
            let Some(body) = td
                .child_by_field_name("type")
                .filter(|t| matches!(t.kind(), "struct_specifier" | "union_specifier"))
                .and_then(|t| t.child_by_field_name("body"))
            else {
                continue;
            };
            let file_scope = at_file_scope(&td);
            let mut cursor = td.walk();
            for declarator in td.children_by_field_name("declarator", &mut cursor) {
                if declarator.kind() == "type_identifier" {
                    let name = get_node_text(&declarator, self.source).to_string();
                    file_body(&mut typedefs, name, body, file_scope);
                }
            }
        }
        self.tag_bodies = tags
            .into_iter()
            .filter_map(|(k, v)| Some((k, v?)))
            .collect();
        self.typedef_bodies = typedefs
            .into_iter()
            .filter_map(|(k, v)| Some((k, v?)))
            .collect();
    }

    /// Member `name` of `aggregate`, typed: its derivations, whether its
    /// specifiers are atomic, and the aggregate its own members are
    /// declared in.
    fn member(
        &self,
        aggregate: &Aggregate<'a>,
        name: &str,
    ) -> (Vec<Derivation>, bool, Option<Aggregate<'a>>) {
        match aggregate {
            Aggregate::Body(body) => match self.member_in_body(body, name) {
                Some((field, declarator)) => (
                    derivations(&declarator, self.source),
                    self.specifiers_atomic(&field),
                    self.aggregate_of_decl(&field),
                ),
                None => (vec![Derivation::Unknown], false, None),
            },
            Aggregate::Named(tag) => {
                let Some(ty) = self.fields.get(tag).and_then(|f| f.get(name)) else {
                    return (vec![Derivation::Unknown], false, None);
                };
                let shape = self
                    .shapes
                    .get(tag)
                    .and_then(|s| s.get(name))
                    .map(String::as_str)
                    .unwrap_or("");
                // Type text says whether there is a pointer or array, not
                // what is qualified where, so such a member is not typed.
                let derived = !shape.is_empty() || ty.contains('*');
                let tokens: Vec<&str> = ty.split_whitespace().collect();
                let next = match tokens.iter().position(|t| *t == "struct" || *t == "union") {
                    Some(i) => tokens
                        .get(i + 1)
                        .filter(|t| !t.starts_with('{'))
                        .map(|t| self.tagged(t)),
                    None => tokens
                        .iter()
                        .rev()
                        .find(|t| !matches!(**t, "*" | "const" | "volatile" | "_Atomic"))
                        .map(|t| self.named(t)),
                };
                if derived {
                    (vec![Derivation::Unknown], false, next)
                } else {
                    (Vec::new(), self.text_atomic(ty), next)
                }
            }
        }
    }

    /// The object `node` names, when it names one by declaration: an
    /// identifier, or a path from one through members, subscripts,
    /// dereferences and parentheses. Anything else (a call's result) is
    /// `None`.
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
                match self
                    .scopes
                    .resolve_identifier_declarator_indexed(node, name, self.source)
                    .flatten()
                {
                    Some((decl, declarator)) => Some(Resolved {
                        key: ObjectKey {
                            root: declarator.id(),
                            members: Vec::new(),
                        },
                        derivations: derivations(&declarator, self.source),
                        base_atomic: self.specifiers_atomic(&decl),
                        aggregate: self.aggregate_of_decl(&decl),
                    }),
                    None => self.resolve_misread(node, name),
                }
            }
            "parenthesized_expression" => self.resolve(&node.named_child(0)?),
            "pointer_expression" if is_deref(node, self.source) => {
                let inner = self.resolve(&node.child_by_field_name("argument")?)?;
                Some(inner.element("0".to_string()))
            }
            "subscript_expression" => {
                let index = index_key(&node.child_by_field_name("index")?, self.source);
                let inner = self.resolve(&node.child_by_field_name("argument")?)?;
                Some(inner.element(index))
            }
            "field_expression" => {
                let mut base = self.resolve(&node.child_by_field_name("argument")?)?;
                let arrow = node
                    .child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "->");
                if arrow {
                    base = base.element("0".to_string());
                }
                let field = get_node_text(&node.child_by_field_name("field")?, self.source);
                let (derivations, base_atomic, aggregate) = match &base.aggregate {
                    Some(agg) => self.member(agg, field),
                    None => (vec![Derivation::Unknown], false, None),
                };
                let mut members = base.key.members;
                members.push(field.to_string());
                Some(Resolved {
                    key: ObjectKey {
                        root: base.key.root,
                        members,
                    },
                    derivations,
                    base_atomic,
                    aggregate,
                })
            }
            _ => None,
        }
    }

    /// A name no declaration binds, resolved to a misread `_Atomic(T) x;`
    /// in a scope around it and before it, the innermost.
    fn resolve_misread(&self, node: &Node<'a>, name: &str) -> Option<Resolved<'a>> {
        let (ident, _) = self
            .misread
            .get(name)?
            .iter()
            .filter(|(ident, scope)| {
                ident.start_byte() <= node.start_byte()
                    && scope.start_byte() <= node.start_byte()
                    && node.end_byte() <= scope.end_byte()
            })
            .max_by_key(|(_, scope)| scope.start_byte())?;
        Some(Resolved {
            key: ObjectKey {
                root: ident.id(),
                members: Vec::new(),
            },
            derivations: Vec::new(),
            base_atomic: true,
            aggregate: None,
        })
    }

    /// The atomic object `node` accesses, if it is a name, member path,
    /// element or dereference that something in reach declares atomic.
    fn atomic_access(&mut self, node: &Node<'a>) -> Option<ObjectKey> {
        if !matches!(
            node.kind(),
            "identifier" | "field_expression" | "subscript_expression" | "pointer_expression"
        ) {
            return None;
        }
        let name_node = access_name(node, self.source)?;
        if !self
            .candidate_names
            .contains(get_node_text(&name_node, self.source))
        {
            return None;
        }
        self.resolve(node).filter(|r| r.atomic()).map(|r| r.key)
    }

    /// The object an `atomic_*` call's first argument points at: `&x` names
    /// `x`, and a pointer `p` names `*p`.
    fn pointed_object(&mut self, arg: &Node<'a>) -> Option<ObjectKey> {
        let arg = strip_parens(arg);
        if is_address_of(&arg, self.source) {
            return self
                .resolve(&arg.child_by_field_name("argument")?)
                .map(|r| r.key);
        }
        let mut key = self.resolve(&arg)?.key;
        key.members.push("[0]".to_string());
        Some(key)
    }
}

/// How an `atomic_*` call's first argument names its object in a message:
/// `&(w.cnt)` as `w.cnt`, a pointer `p` as `*p`.
fn object_text(arg: &Node, source: &str) -> String {
    let arg = strip_parens(arg);
    if is_address_of(&arg, source) {
        if let Some(inner) = arg.child_by_field_name("argument") {
            return spelling(&strip_parens(&inner), source);
        }
    }
    format!("*{}", spelling(&arg, source))
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

/// Whether nothing under `node` is evaluated.
fn unevaluated(node: &Node, source: &str) -> bool {
    UNEVALUATED_KINDS.contains(&node.kind())
        || node.kind() == "call_expression"
            && callee_name(node, source).is_some_and(|n| UNEVALUATED_CALLEES.contains(&n))
}

/// Whether the children of `node` belong to the full expression `node` is
/// part of: through operators, member paths, calls and their arguments,
/// and a compound literal's initializer, but not into a statement (a GNU
/// statement expression's body is full expressions of its own) or a
/// `_Generic` association, of which only one is evaluated.
fn continues_expression(node: &Node) -> bool {
    match node.kind() {
        "argument_list" => true,
        "generic_expression" => false,
        "initializer_list" | "initializer_pair" => node.parent().is_some_and(|p| {
            matches!(
                p.kind(),
                "compound_literal_expression" | "initializer_list" | "initializer_pair"
            )
        }),
        kind => kind.ends_with("_expression"),
    }
}

/// The children of `node` a walk of its expression visits: none of an
/// unevaluated operand, and not a `_Generic` controlling expression.
fn evaluated_children<'a>(node: &Node<'a>, source: &str) -> Vec<Node<'a>> {
    if unevaluated(node, source) {
        return Vec::new();
    }
    let children = node.child_nodes();
    if node.kind() == "generic_expression" {
        let controlling = node.named_child(0).map(|c| c.id());
        return children.filter(|c| Some(c.id()) != controlling).collect();
    }
    children.collect()
}

/// The lowest node containing both `a` and `b`.
fn common_ancestor<'a>(a: &Node<'a>, b: &Node) -> Option<Node<'a>> {
    let mut n = *a;
    loop {
        if n.start_byte() <= b.start_byte() && b.end_byte() <= n.end_byte() {
            return Some(n);
        }
        n = n.parent()?;
    }
}

/// The child of `ancestor` that contains `node`.
fn child_toward<'a>(ancestor: &Node<'a>, node: &Node) -> Option<Node<'a>> {
    ancestor
        .child_nodes()
        .find(|c| c.start_byte() <= node.start_byte() && node.end_byte() <= c.end_byte())
}

/// Whether `a` and `b` lie in different arms of one `if`/`else` or `?:`, or
/// in two `case`s of a `switch` where the earlier one does not fall through,
/// with no loop around it that could carry a value from one arm to the
/// other.
fn exclusive_arms(a: &Node, b: &Node) -> bool {
    let Some(lca) = common_ancestor(a, b) else {
        return false;
    };
    let (Some(ca), Some(cb)) = (child_toward(&lca, a), child_toward(&lca, b)) else {
        return false;
    };
    if ca.id() == cb.id() {
        return false;
    }
    match lca.kind() {
        "if_statement" | "conditional_expression" => {
            let condition = lca.child_by_field_name("condition").map(|c| c.id());
            if Some(ca.id()) == condition || Some(cb.id()) == condition {
                return false;
            }
        }
        "compound_statement"
            if lca.parent().is_some_and(|p| p.kind() == "switch_statement")
                && ca.kind() == "case_statement"
                && cb.kind() == "case_statement" =>
        {
            let earlier = if ca.start_byte() < cb.start_byte() {
                ca
            } else {
                cb
            };
            if !ends_in_jump(&earlier) {
                return false;
            }
        }
        _ => return false,
    }
    let mut n = lca;
    while let Some(p) = n.parent() {
        match p.kind() {
            "for_statement" | "while_statement" | "do_statement" => return false,
            "function_definition" => break,
            _ => {}
        }
        n = p;
    }
    true
}

/// Whether `node` runs on every path that reaches `target` from where they
/// part: no arm, loop body, `case` or right operand of `&&`/`||` lies
/// between it and the lowest node containing both.
fn runs_before_reaching(node: &Node, target: &Node) -> bool {
    let Some(lca) = common_ancestor(node, target) else {
        return false;
    };
    let mut child = *node;
    while let Some(parent) = child.parent() {
        if parent.id() == lca.id() {
            return true;
        }
        let in_condition = parent
            .child_by_field_name("condition")
            .is_some_and(|c| c.id() == child.id());
        let conditional = match parent.kind() {
            "if_statement" | "conditional_expression" | "while_statement" => !in_condition,
            "for_statement" => {
                !in_condition
                    && parent
                        .child_by_field_name("initializer")
                        .is_none_or(|c| c.id() != child.id())
            }
            "switch_statement" => !in_condition,
            "case_statement" | "else_clause" => true,
            "binary_expression" => {
                parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| matches!(o.kind(), "&&" | "||"))
                    && parent
                        .child_by_field_name("right")
                        .is_some_and(|r| r.id() == child.id())
            }
            _ => false,
        };
        if conditional {
            return false;
        }
        child = parent;
    }
    false
}

/// One way a local's value is set within a function: by `=` or an
/// initializer from what the right side names, by a compound assignment
/// (which keeps its own value), or through `&x` handed to a call, which may
/// write anything.
struct Flow<'a> {
    dest: ObjectKey,
    sources: Vec<ObjectKey>,
    keeps_own: bool,
    node: Node<'a>,
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
            atomic_typedefs: HashSet::new(),
            misread: HashMap::new(),
            candidate_names: HashSet::new(),
            tag_bodies: HashMap::new(),
            typedef_bodies: HashMap::new(),
            memo: HashMap::new(),
        };
        cx.collect_bodies(root);
        let nodes = query::find_descendants_of_kinds(
            *root,
            &[
                "declaration",
                "parameter_declaration",
                "field_declaration",
                "type_definition",
                "ERROR",
            ],
        );
        // Typedefs first, so a declaration through one sees it.
        for td in nodes.iter().filter(|n| n.kind() == "type_definition") {
            if cx.specifiers_atomic(td) {
                let mut cursor = td.walk();
                for declarator in td.children_by_field_name("declarator", &mut cursor) {
                    if declarator.kind() == "type_identifier" {
                        cx.atomic_typedefs
                            .insert(get_node_text(&declarator, source).to_string());
                    }
                }
            }
        }
        let mut names = HashSet::new();
        for decl in &nodes {
            match decl.kind() {
                "type_definition" => {}
                "ERROR" => {
                    if let Some(ident) = misread_atomic_declaration(decl, source) {
                        let name = get_node_text(&ident, source).to_string();
                        names.insert(name.clone());
                        let scope = decl.parent().unwrap_or(*root);
                        cx.misread.entry(name).or_default().push((ident, scope));
                    }
                }
                _ => {
                    let mut cursor = decl.walk();
                    for declarator in decl.children_by_field_name("declarator", &mut cursor) {
                        let derivs = derivations(&declarator, source);
                        let may_be_atomic = cx.specifiers_atomic(decl)
                            || derivs.contains(&Derivation::Pointer { atomic: true });
                        if may_be_atomic {
                            if let Some(d) = declared_name(&declarator) {
                                names.insert(get_node_text(&d, source).to_string());
                            }
                        }
                    }
                }
            }
        }
        for fields in cx.fields.values() {
            for (name, ty) in fields {
                if cx.text_atomic(ty) {
                    names.insert(name.clone());
                }
            }
        }
        cx.candidate_names = names;
        cx
    }

    /// Every expression that is the outermost of the expressions around it:
    /// one per full expression.
    fn report_roots<'a>(root: &Node<'a>, source: &str) -> Vec<Node<'a>> {
        let mut roots = Vec::new();
        let mut stack = vec![(*root, false)];
        while let Some((node, inside)) = stack.pop() {
            let is_expr = EXPR_KINDS.contains(&node.kind());
            if is_expr && !inside {
                roots.push(node);
            }
            let child_inside = (inside || is_expr) && continues_expression(&node);
            let children = evaluated_children(&node, source);
            stack.extend(children.into_iter().rev().map(|c| (c, child_inside)));
        }
        roots
    }

    /// The atomic accesses in the full expression `expr`, each with how a
    /// message names its object.
    fn accesses<'a>(cx: &mut FileCx<'a, '_>, expr: &Node<'a>) -> Vec<(ObjectKey, String)> {
        let mut found = Vec::new();
        let mut stack = vec![*expr];
        while let Some(node) = stack.pop() {
            if let Some(key) = cx.atomic_access(&node) {
                found.push((key, spelling(&node, cx.source)));
            } else if node.kind() == "call_expression"
                && callee_name(&node, cx.source).is_some_and(|n| ATOMIC_OPERATIONS.contains(&n))
            {
                if let Some(arg) = call_args(&node).first() {
                    if let Some(key) = cx.pointed_object(arg) {
                        found.push((key, object_text(arg, cx.source)));
                    }
                }
            }
            if node.id() != expr.id() && !continues_expression(&node) {
                continue;
            }
            if is_address_of(&node, cx.source) {
                if let Some(operand) = node.child_by_field_name("argument") {
                    Self::push_designated(cx, &operand, &mut stack);
                }
                continue;
            }
            let children = evaluated_children(&node, cx.source);
            stack.extend(children.into_iter().rev());
        }
        found
    }

    /// The operand of `&`: the object it designates is not accessed, but
    /// what computes it is (`&p->m` reads `p`, `&a[i]` reads `i`, and `p`
    /// too when it is a pointer rather than an array).
    fn push_designated<'a>(cx: &mut FileCx<'a, '_>, node: &Node<'a>, stack: &mut Vec<Node<'a>>) {
        match node.kind() {
            "identifier" => {}
            "parenthesized_expression" => {
                if let Some(inner) = node.named_child(0) {
                    Self::push_designated(cx, &inner, stack);
                }
            }
            "field_expression" => {
                let Some(argument) = node.child_by_field_name("argument") else {
                    return;
                };
                if node
                    .child_by_field_name("operator")
                    .is_some_and(|o| o.kind() == "->")
                {
                    stack.push(argument);
                } else {
                    Self::push_designated(cx, &argument, stack);
                }
            }
            "pointer_expression" if is_deref(node, cx.source) => {
                if let Some(argument) = node.child_by_field_name("argument") {
                    stack.push(argument);
                }
            }
            "subscript_expression" => {
                if let Some(index) = node.child_by_field_name("index") {
                    stack.push(index);
                }
                let Some(argument) = node.child_by_field_name("argument") else {
                    return;
                };
                let array = cx
                    .resolve(&argument)
                    .is_some_and(|r| r.derivations.first() == Some(&Derivation::Array));
                if array {
                    Self::push_designated(cx, &argument, stack);
                } else {
                    stack.push(argument);
                }
            }
            _ => stack.push(*node),
        }
    }

    fn check_expressions<'a>(
        &self,
        cx: &mut FileCx<'a, '_>,
        root: &Node<'a>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for expr in Self::report_roots(root, cx.source) {
            let mut counts: Vec<(ObjectKey, String, usize)> = Vec::new();
            for (key, name) in Self::accesses(cx, &expr) {
                match counts.iter_mut().find(|(k, _, _)| *k == key) {
                    Some(entry) => entry.2 += 1,
                    None => counts.push((key, name, 1)),
                }
            }
            for (_, name, n) in counts.into_iter().filter(|(_, _, n)| *n >= 2) {
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

    /// The names `node` reads, resolved.
    fn names_in<'a>(cx: &mut FileCx<'a, '_>, node: &Node<'a>) -> Vec<ObjectKey> {
        query::find_descendants_of_kind(*node, "identifier")
            .iter()
            .chain(std::iter::once(node).filter(|n| n.kind() == "identifier"))
            .filter_map(|id| cx.resolve(id).map(|r| r.key))
            .collect()
    }

    /// Every way `func` sets a local's value, in source order.
    fn flows<'a>(cx: &mut FileCx<'a, '_>, func: &Node<'a>) -> Vec<Flow<'a>> {
        let mut flows = Vec::new();
        for node in query::find_descendants_of_kinds(
            *func,
            &[
                "assignment_expression",
                "init_declarator",
                "call_expression",
            ],
        ) {
            match node.kind() {
                "assignment_expression" => {
                    let (Some(left), Some(op), Some(right)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("operator"),
                        node.child_by_field_name("right"),
                    ) else {
                        continue;
                    };
                    if left.kind() != "identifier" {
                        continue;
                    }
                    let Some(dest) = cx.resolve(&left).map(|r| r.key) else {
                        continue;
                    };
                    let sources = Self::names_in(cx, &right);
                    flows.push(Flow {
                        dest,
                        sources,
                        keeps_own: op.kind() != "=",
                        node,
                    });
                }
                "init_declarator" => {
                    let (Some(declarator), Some(value)) = (
                        node.child_by_field_name("declarator"),
                        node.child_by_field_name("value"),
                    ) else {
                        continue;
                    };
                    if declarator.kind() != "identifier" {
                        continue;
                    }
                    let sources = Self::names_in(cx, &value);
                    flows.push(Flow {
                        dest: ObjectKey {
                            root: declarator.id(),
                            members: Vec::new(),
                        },
                        sources,
                        keeps_own: false,
                        node,
                    });
                }
                _ => {
                    for arg in call_args(&node) {
                        let arg = strip_parens(&arg);
                        if !is_address_of(&arg, cx.source) {
                            continue;
                        }
                        let Some(operand) = arg.child_by_field_name("argument") else {
                            continue;
                        };
                        if operand.kind() != "identifier" {
                            continue;
                        }
                        if let Some(dest) = cx.resolve(&operand).map(|r| r.key) {
                            flows.push(Flow {
                                dest,
                                sources: Vec::new(),
                                keeps_own: false,
                                node,
                            });
                        }
                    }
                }
            }
        }
        flows.sort_by_key(|f| f.node.start_byte());
        flows
    }

    /// Whether the value `load` put in `receiver` can still be, through
    /// locals, in what `store` writes from `value`.
    fn carried<'a>(
        flows: &[Flow<'a>],
        load: &Node,
        receiver: &ObjectKey,
        store: &Node,
        value_names: &[ObjectKey],
    ) -> bool {
        let mut carriers = vec![receiver.clone()];
        for flow in flows {
            let at = flow.node.start_byte();
            if at < load.end_byte() || at >= store.start_byte() {
                continue;
            }
            let from_carrier = flow.sources.iter().any(|s| carriers.contains(s));
            let dest_carries = carriers.contains(&flow.dest);
            if from_carrier && !dest_carries {
                carriers.push(flow.dest.clone());
            } else if dest_carries
                && !from_carrier
                && !flow.keeps_own
                && runs_before_reaching(&flow.node, store)
            {
                carriers.retain(|c| *c != flow.dest);
            }
        }
        value_names.iter().any(|n| carriers.contains(n))
    }

    /// CERT's split-statement form: a load whose value, through locals, a
    /// later store of the same object writes. A presumption, reported for
    /// review. A load and a store in the same full expression are the
    /// expression form's.
    fn check_split_statements<'a>(
        &self,
        cx: &mut FileCx<'a, '_>,
        func: &Node<'a>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let calls = query::find_descendants_of_kind(*func, "call_expression");
        // (object, load call, the local its value went to)
        let mut loads: Vec<(ObjectKey, Node<'a>, ObjectKey)> = Vec::new();
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
            if let Some(receiver) = Self::receiver(cx, call) {
                loads.push((object, *call, receiver));
            }
        }
        if loads.is_empty() {
            return;
        }
        let flows = Self::flows(cx, func);
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
            let value_names = Self::names_in(cx, value);
            for (loaded, load, receiver) in &loads {
                if *loaded != object
                    || load.end_byte() > call.start_byte()
                    || exclusive_arms(load, call)
                    || !Self::carried(&flows, load, receiver, call, &value_names)
                    || !reported.insert(load.id())
                {
                    continue;
                }
                let object_text = object_text(target, cx.source);
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
        if !cx.candidate_names.is_empty() || source.contains("atomic_") {
            self.check_expressions(&mut cx, node, violations);
        }
        if source.contains("atomic_store") {
            for func in query::find_descendants_of_kind(*node, "function_definition") {
                self.check_split_statements(&mut cx, &func, violations);
            }
        }
    }
}
