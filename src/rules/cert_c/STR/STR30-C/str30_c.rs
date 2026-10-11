// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! STR30-C: Do not attempt to modify string literals
//!
//! Modifying a string literal is undefined (C11 6.4.5p7). The rule reports a
//! WRITE, never a declaration: `char *s = "x";` alone is STR05-C's
//! construct. A write is
//!
//! - a store through a pointer: `p[i] = c`, `*p = c`, `*p++ = c`, `++p[i]`;
//! - a library call that writes through an argument: the copiers, formatted
//!   writers and readers `call_roles::writes_through_arg` lists (only the
//!   outputs after a scanf format, never the format), plus the fills, the
//!   tokenizers and the temporary-name builders ([`MORE_WRITERS`]);
//! - a call to a function this file defines whose body writes through the
//!   parameter, judged the same way.
//!
//! It is reported when the pointer written through may point into a string
//! literal, traced by data flow rather than by name ([`Trace`]): a literal
//! itself, a pointer declared to const characters (CERT: "a pointer to (or
//! array of) const characters must be treated as a string literal"), the
//! result of a search function (`strchr`, `strrchr`, `strstr`, ...) on
//! either, pointer arithmetic on one, an array element or struct field
//! initialized or assigned one, a pointer to a variable holding one, a
//! function of this file that returns one, or a variable whose reaching
//! assignment is one. A call to a function whose name says it changes
//! something, a `const char *` parameter, a format string and a reassigned
//! array element are not writes.

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::call_roles;
use crate::utility::cert_c::guard_dominance;
use crate::utility::cert_c::node_children::NodeChildren;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Str30C;

impl CertRule for Str30C {
    fn rule_id(&self) -> &'static str {
        "STR30-C"
    }

    fn description(&self) -> &'static str {
        "Do not attempt to modify string literals"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "STR30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let trace = Trace::new(*node, source);
        let mut seen = HashSet::new();
        let mut violations = Vec::new();
        for write in trace.writes_under(node) {
            if seen.contains(&write.site.start_byte())
                || !trace.literal_derived(&write.pointer, &write.site, None, 0)
            {
                continue;
            }
            seen.insert(write.site.start_byte());
            let pointer = get_node_text(&write.pointer, source);
            let message = match write.kind {
                WriteKind::Store => format!(
                    "Write through '{}', which may point into a string literal",
                    pointer
                ),
                WriteKind::Library(name) => format!(
                    "'{}' writes through '{}', which may point into a string literal",
                    name, pointer
                ),
                WriteKind::Callee(name) => format!(
                    "'{}' writes through the parameter it is passed '{}', which may point \
                     into a string literal",
                    name, pointer
                ),
            };
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message,
                file_path: String::new(),
                line: write.site.start_position().row + 1,
                column: write.site.start_position().column + 1,
                suggestion: Some(
                    "Copy the literal into a modifiable array (char s[] = \"...\") before writing to it"
                        .to_string(),
                ),
                ..Default::default()
            });
        }
        violations
    }
}

/// The search functions whose result points into their first argument.
const SEARCH_FUNCTIONS: &[&str] = &[
    "strchr",
    "strrchr",
    "strstr",
    "strpbrk",
    "strcasestr",
    "memchr",
    "memrchr",
    "rawmemchr",
    "index",
    "rindex",
    "wcschr",
    "wcsrchr",
    "wcsstr",
    "wcspbrk",
    "wmemchr",
];

/// Library calls that write through an argument and that
/// `call_roles::writes_through_arg` does not list: fills (which write
/// whatever the fill value is), the tokenizers, which overwrite delimiters,
/// and the functions that build a name in the caller's template.
const MORE_WRITERS: &[(&str, usize)] = &[
    ("memset", 0),
    ("wmemset", 0),
    ("memset_s", 0),
    ("explicit_bzero", 0),
    ("bzero", 0),
    ("strtok", 0),
    ("strtok_r", 0),
    ("wcstok", 0),
    ("mkstemp", 0),
    ("mkostemp", 0),
    ("mkstemps", 0),
    ("mkdtemp", 0),
    ("mktemp", 0),
    ("tmpnam", 0),
    ("strxfrm", 0),
    ("wcsxfrm", 0),
    ("getcwd", 0),
    ("realpath", 1),
    ("strerror_r", 1),
];

/// How deep one question may recurse through assignments, aliases and
/// callees before it gives up and answers "not derived".
const MAX_DEPTH: u32 = 16;

#[derive(Clone, Copy)]
enum WriteKind<'a> {
    Store,
    Library(&'a str),
    Callee(&'a str),
}

/// One write: the node it happens at and the pointer written through.
struct Write<'a> {
    site: Node<'a>,
    pointer: Node<'a>,
    kind: WriteKind<'a>,
}

/// A parameter traced as if it pointed into a literal: the start byte of its
/// function and its name. Used to ask whether a callee writes through it.
type Seed<'s> = Option<(usize, &'s str)>;

/// One file's literal-origin trace.
struct Trace<'a> {
    source: &'a str,
    /// The functions the file defines, by name.
    functions: HashMap<String, Node<'a>>,
    /// Per (function start, parameter index): whether the body writes
    /// through it. Provisionally false while being computed, so a cycle
    /// proves nothing.
    param_writes: RefCell<HashMap<(usize, usize), bool>>,
    /// Per function start: whether some `return` returns a literal-derived
    /// pointer. Provisionally false while being computed.
    returns_literal: RefCell<HashMap<usize, bool>>,
    /// Per declarator: the plain assignments to the variable it declares,
    /// as (assignment, value).
    assignments: RefCell<HashMap<usize, Vec<(Node<'a>, Node<'a>)>>>,
    root: Node<'a>,
}

impl<'a> Trace<'a> {
    fn new(root: Node<'a>, source: &'a str) -> Self {
        let mut functions = HashMap::new();
        let mut stack = vec![root];
        while let Some(scope) = stack.pop() {
            for item in scope.named_child_nodes() {
                match item.kind() {
                    "function_definition" => {
                        if let Some(name) =
                            lang_parsing_substrate::calls::get_function_name(item, source)
                        {
                            functions.entry(name).or_insert(item);
                        }
                    }
                    kind if kind.starts_with("preproc_") => stack.push(item),
                    _ => {}
                }
            }
        }
        Self {
            source,
            functions,
            param_writes: RefCell::default(),
            returns_literal: RefCell::default(),
            assignments: RefCell::default(),
            root,
        }
    }

    /// Every write under `scope`, in source order.
    fn writes_under(&self, scope: &Node<'a>) -> Vec<Write<'a>> {
        let mut out = Vec::new();
        for n in query::find_descendants_of_kinds(
            *scope,
            &[
                "assignment_expression",
                "update_expression",
                "call_expression",
            ],
        ) {
            match n.kind() {
                "assignment_expression" => {
                    if let Some(pointer) = n
                        .child_by_field_name("left")
                        .and_then(|l| Self::written_pointer(&l))
                    {
                        out.push(Write {
                            site: n,
                            pointer,
                            kind: WriteKind::Store,
                        });
                    }
                }
                "update_expression" => {
                    if let Some(pointer) = n
                        .child_by_field_name("argument")
                        .and_then(|a| Self::written_pointer(&a))
                    {
                        out.push(Write {
                            site: n,
                            pointer,
                            kind: WriteKind::Store,
                        });
                    }
                }
                _ => self.call_writes(&n, &mut out),
            }
        }
        out
    }

    /// The writes a call makes through its arguments.
    fn call_writes(&self, call: &Node<'a>, out: &mut Vec<Write<'a>>) {
        let (Some(function), Some(args)) = (
            call.child_by_field_name("function"),
            call.child_by_field_name("arguments"),
        ) else {
            return;
        };
        if function.kind() != "identifier" {
            return;
        }
        let name = get_node_text(&function, self.source);
        let args: Vec<Node<'a>> = args
            .named_child_nodes()
            .filter(|a| a.kind() != "comment")
            .collect();
        if let Some(def) = self.functions.get(name) {
            for (i, arg) in args.iter().enumerate() {
                if self.param_written(def, i) {
                    out.push(Write {
                        site: *call,
                        pointer: *arg,
                        kind: WriteKind::Callee(name),
                    });
                }
            }
            return;
        }
        for (i, arg) in args.iter().enumerate() {
            if call_roles::writes_through_arg(name, i) || MORE_WRITERS.contains(&(name, i)) {
                out.push(Write {
                    site: *call,
                    pointer: *arg,
                    kind: WriteKind::Library(name),
                });
            }
        }
    }

    /// The pointer an lvalue writes through: `p` in `p[i]`, `*p`, `*p++`
    /// and `*(p + 1)`. An lvalue that names a variable or a field writes
    /// that object, not a pointee.
    fn written_pointer(lvalue: &Node<'a>) -> Option<Node<'a>> {
        let mut lv = *lvalue;
        while lv.kind() == "parenthesized_expression" {
            lv = lv.named_child(0)?;
        }
        match lv.kind() {
            "subscript_expression" => lv.child_by_field_name("argument"),
            "pointer_expression"
                if lv
                    .child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "*") =>
            {
                let mut p = lv.child_by_field_name("argument")?;
                while p.kind() == "parenthesized_expression" {
                    p = p.named_child(0)?;
                }
                if p.kind() == "update_expression" {
                    p = p.child_by_field_name("argument")?;
                }
                Some(p)
            }
            _ => None,
        }
    }

    /// Whether the body of `def` writes through its parameter `index`, as
    /// this rule reads a write.
    fn param_written(&self, def: &Node<'a>, index: usize) -> bool {
        let key = (def.start_byte(), index);
        if let Some(&known) = self.param_writes.borrow().get(&key) {
            return known;
        }
        self.param_writes.borrow_mut().insert(key, false);
        let written = (|| {
            let params = ast_utils::get_function_parameters(def, self.source)?;
            let (name, _) = params.get(index)?;
            let body = def.child_by_field_name("body")?;
            let seed = Some((def.start_byte(), name.as_str()));
            Some(
                self.writes_under(&body)
                    .iter()
                    .any(|w| self.literal_derived(&w.pointer, &w.site, seed, 0)),
            )
        })()
        .unwrap_or(false);
        self.param_writes.borrow_mut().insert(key, written);
        written
    }

    /// Whether `expr`, evaluated at `at`, may point into a string literal.
    fn literal_derived(&self, expr: &Node<'a>, at: &Node<'a>, seed: Seed, depth: u32) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }
        let d = depth + 1;
        let field = |name: &str| expr.child_by_field_name(name);
        match expr.kind() {
            "string_literal" | "concatenated_string" => true,
            "parenthesized_expression" => expr
                .named_child(0)
                .is_some_and(|e| self.literal_derived(&e, at, seed, d)),
            "cast_expression" => {
                field("value").is_some_and(|e| self.literal_derived(&e, at, seed, d))
            }
            "conditional_expression" => ["consequence", "alternative"]
                .iter()
                .any(|f| field(f).is_some_and(|e| self.literal_derived(&e, at, seed, d))),
            "comma_expression" => {
                field("right").is_some_and(|e| self.literal_derived(&e, at, seed, d))
            }
            "assignment_expression" => {
                field("right").is_some_and(|e| self.literal_derived(&e, at, seed, d))
            }
            "binary_expression" => {
                let op = ast_utils::get_binary_operator(expr, self.source).unwrap_or_default();
                matches!(op, "+" | "-")
                    && ["left", "right"]
                        .iter()
                        .any(|f| field(f).is_some_and(|e| self.literal_derived(&e, at, seed, d)))
            }
            "update_expression" => {
                field("argument").is_some_and(|e| self.literal_derived(&e, at, seed, d))
            }
            "pointer_expression" => {
                let op = field("operator").map(|o| o.kind());
                let Some(arg) = field("argument") else {
                    return false;
                };
                match op {
                    // `&p[i]` points where `p` does.
                    Some("&") => {
                        arg.kind() == "subscript_expression"
                            && arg
                                .child_by_field_name("argument")
                                .is_some_and(|p| self.literal_derived(&p, at, seed, d))
                    }
                    Some("*") => self.pointee_derived(&arg, at, seed, d),
                    _ => false,
                }
            }
            "subscript_expression" => {
                field("argument").is_some_and(|a| self.element_derived(&a, at, seed, d))
            }
            "field_expression" => self.field_derived(expr, at, seed, d),
            "call_expression" => self.call_result_derived(expr, at, seed, d),
            "identifier" => self.variable_derived(expr, at, seed, d),
            _ => false,
        }
    }

    /// `*pp`: the pointer `pp` points at holds a literal-derived pointer --
    /// `pp` was set to `&s` where `s` is one, or `pp` is an array of them.
    fn pointee_derived(&self, pp: &Node<'a>, at: &Node<'a>, seed: Seed, depth: u32) -> bool {
        let mut pp = *pp;
        while pp.kind() == "parenthesized_expression" {
            match pp.named_child(0) {
                Some(inner) => pp = inner,
                None => return false,
            }
        }
        if pp.kind() != "identifier" {
            return false;
        }
        if self.element_derived(&pp, at, seed, depth) {
            return true;
        }
        self.reaching_values(&pp, at).iter().any(|value| {
            let value = guard_dominance::strip_arg_wrappers(value);
            value.kind() == "pointer_expression"
                && value
                    .child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "&")
                && value
                    .child_by_field_name("argument")
                    .filter(|v| v.kind() == "identifier")
                    .is_some_and(|v| self.variable_derived(&v, at, seed, depth + 1))
        })
    }

    /// `a[i]` where `a` is an array whose elements may hold literal-derived
    /// pointers: initialized with one, or an element assigned one.
    fn element_derived(&self, array: &Node<'a>, at: &Node<'a>, seed: Seed, depth: u32) -> bool {
        if array.kind() != "identifier" {
            return false;
        }
        let name = get_node_text(array, self.source);
        let Some((decl, declarator)) =
            ast_utils::resolve_identifier_declarator(array, name, self.source)
        else {
            return false;
        };
        if let Some(init) = Self::initializer_of(&declarator) {
            if init.kind() == "initializer_list"
                && init
                    .named_child_nodes()
                    .any(|e| self.literal_derived(&e, &e, seed, depth + 1))
            {
                return true;
            }
        }
        let scope = Self::scope_of(&decl).unwrap_or(self.root);
        query::find_descendants_of_kind(scope, "assignment_expression")
            .into_iter()
            .filter(|a| Self::is_plain_assignment(a))
            .any(|a| {
                let element_of_array = a
                    .child_by_field_name("left")
                    .filter(|l| l.kind() == "subscript_expression")
                    .and_then(|l| l.child_by_field_name("argument"))
                    .filter(|b| b.kind() == "identifier" && get_node_text(b, self.source) == name)
                    .is_some_and(|b| {
                        ast_utils::resolve_identifier_declarator(&b, name, self.source)
                            .is_some_and(|(_, d)| d.id() == declarator.id())
                    });
                element_of_array
                    && a.start_byte() < at.start_byte()
                    && a.child_by_field_name("right")
                        .is_some_and(|v| self.literal_derived(&v, &a, seed, depth + 1))
            })
    }

    /// `x.f` or `p->f` holding a literal-derived pointer: assigned one under
    /// the same spelling before `at`, or `x` initialized with one in the
    /// field's position (designated, or in member order). A field declared
    /// as a pointer to const characters counts as one.
    fn field_derived(&self, expr: &Node<'a>, at: &Node<'a>, seed: Seed, depth: u32) -> bool {
        let spelled = guard_dominance::squeeze_text(expr, self.source);
        let Some(field) = expr
            .child_by_field_name("field")
            .map(|f| get_node_text(&f, self.source).to_string())
        else {
            return false;
        };
        let object = expr.child_by_field_name("argument");
        let scope = ast_utils::find_containing_function(at).unwrap_or(self.root);
        let assigned = query::find_descendants_of_kind(scope, "assignment_expression")
            .into_iter()
            .filter(|a| Self::is_plain_assignment(a) && a.start_byte() < at.start_byte())
            .any(|a| {
                a.child_by_field_name("left")
                    .is_some_and(|l| guard_dominance::squeeze_text(&l, self.source) == spelled)
                    && a.child_by_field_name("right")
                        .is_some_and(|v| self.literal_derived(&v, &a, seed, depth + 1))
            });
        if assigned {
            return true;
        }
        // `struct data d = { "literal" };` then `d.name`.
        let is_dot = expr
            .child_by_field_name("operator")
            .is_some_and(|op| op.kind() == ".");
        let Some(object) = object.filter(|o| is_dot && o.kind() == "identifier") else {
            return false;
        };
        let name = get_node_text(&object, self.source);
        let Some((decl, declarator)) =
            ast_utils::resolve_identifier_declarator(&object, name, self.source)
        else {
            return false;
        };
        let members = self.struct_members(&decl);
        if members.iter().any(|(m, is_const)| *m == field && *is_const) {
            return true;
        }
        let Some(init) =
            Self::initializer_of(&declarator).filter(|i| i.kind() == "initializer_list")
        else {
            return false;
        };
        let mut position = 0;
        for element in init.named_child_nodes() {
            if element.kind() == "comment" {
                continue;
            }
            if element.kind() == "initializer_pair" {
                let designates_field = element.child_by_field_name("designator").is_some_and(|d| {
                    d.kind() == "field_designator"
                        && d.named_child(0)
                            .is_some_and(|f| get_node_text(&f, self.source) == field)
                });
                if designates_field {
                    return element
                        .child_by_field_name("value")
                        .is_some_and(|v| self.literal_derived(&v, &v, seed, depth + 1));
                }
                continue;
            }
            if members.get(position).is_some_and(|(m, _)| *m == field) {
                return self.literal_derived(&element, &element, seed, depth + 1);
            }
            position += 1;
        }
        false
    }

    /// The members of the struct a declaration's type names, in order, each
    /// with whether it is declared as a pointer to const characters. Empty
    /// when the struct's body is not in this file.
    fn struct_members(&self, decl: &Node<'a>) -> Vec<(String, bool)> {
        let Some(spec) = decl.child_by_field_name("type") else {
            return Vec::new();
        };
        if spec.kind() != "struct_specifier" {
            return Vec::new();
        }
        let body = spec.child_by_field_name("body").or_else(|| {
            let tag = spec.child_by_field_name("name")?;
            let tag = get_node_text(&tag, self.source);
            query::find_descendants_of_kind(self.root, "struct_specifier")
                .into_iter()
                .filter(|s| {
                    s.child_by_field_name("name")
                        .is_some_and(|n| get_node_text(&n, self.source) == tag)
                })
                .find_map(|s| s.child_by_field_name("body"))
        });
        let Some(body) = body else {
            return Vec::new();
        };
        let mut members = Vec::new();
        for field in body.named_child_nodes() {
            if field.kind() != "field_declaration" {
                continue;
            }
            let is_const = Self::has_const_qualifier(&field);
            let mut cursor = field.walk();
            for declarator in field.children_by_field_name("declarator", &mut cursor) {
                let Some(name) = Self::member_name(&declarator, self.source) else {
                    continue;
                };
                members.push((name, is_const && Self::is_single_pointer(&declarator)));
            }
        }
        members
    }

    /// A call's result: a search function's result on a literal-derived or
    /// const-character argument, or a pointer a function of this file
    /// returns from a literal.
    fn call_result_derived(&self, call: &Node<'a>, at: &Node<'a>, seed: Seed, depth: u32) -> bool {
        let Some(function) = call.child_by_field_name("function") else {
            return false;
        };
        if function.kind() != "identifier" {
            return false;
        }
        let name = get_node_text(&function, self.source);
        if let Some(def) = self.functions.get(name) {
            return self.returns_literal(def, depth);
        }
        if !SEARCH_FUNCTIONS.contains(&name) {
            return false;
        }
        let Some(first) = call
            .child_by_field_name("arguments")
            .and_then(|args| args.named_child_nodes().find(|a| a.kind() != "comment"))
        else {
            return false;
        };
        self.literal_derived(&first, at, seed, depth + 1)
    }

    /// Whether some `return` in `def` returns a literal-derived pointer.
    fn returns_literal(&self, def: &Node<'a>, depth: u32) -> bool {
        let key = def.start_byte();
        if let Some(&known) = self.returns_literal.borrow().get(&key) {
            return known;
        }
        self.returns_literal.borrow_mut().insert(key, false);
        let found = def.child_by_field_name("body").is_some_and(|body| {
            query::find_descendants_of_kind(body, "return_statement")
                .into_iter()
                .filter_map(|r| r.named_child(0))
                .any(|value| self.literal_derived(&value, &value, None, depth + 1))
        });
        self.returns_literal.borrow_mut().insert(key, found);
        found
    }

    /// A variable at `at`: declared as a pointer to (or array of) const
    /// characters, the parameter `seed` names, or a pointer whose reaching
    /// value is literal-derived. An array of characters is a copy of its
    /// initializer, never the literal.
    fn variable_derived(&self, ident: &Node<'a>, at: &Node<'a>, seed: Seed, depth: u32) -> bool {
        let name = get_node_text(ident, self.source);
        let Some((decl, declarator)) =
            ast_utils::resolve_identifier_declarator(ident, name, self.source)
        else {
            return false;
        };
        let is_array = declarator.kind() == "array_declarator";
        let pointee_const =
            Self::has_const_qualifier(&decl) && (is_array || Self::is_single_pointer(&declarator));
        if pointee_const {
            return true;
        }
        if is_array {
            return false;
        }
        let seeded = decl.kind() == "parameter_declaration"
            && seed.is_some_and(|(func, param)| {
                param == name
                    && ast_utils::find_containing_function(&decl)
                        .is_some_and(|f| f.start_byte() == func)
            });
        let values = self.reaching_values(ident, at);
        if seeded && !self.reassigned_on_every_path(ident, at) {
            return true;
        }
        values
            .iter()
            .any(|value| self.literal_derived(value, value, seed, depth + 1))
    }

    /// The values the variable `ident` names may hold at `at`: its
    /// initializer and the plain assignments to it that reach `at`. For a
    /// local or parameter, an assignment reaches unless a later one before
    /// `at` runs on every path to it; one after `at` inside a loop holding
    /// `at` reaches through the loop, unless the killing assignment is in
    /// that loop too. For a global, every assignment in the file counts.
    /// A variable whose address is passed to a call between its last sure
    /// assignment and `at` may hold anything, and reaches nothing.
    fn reaching_values(&self, ident: &Node<'a>, at: &Node<'a>) -> Vec<Node<'a>> {
        let name = get_node_text(ident, self.source);
        let Some((decl, declarator)) =
            ast_utils::resolve_identifier_declarator(ident, name, self.source)
        else {
            return Vec::new();
        };
        let candidates = self.assignments_to(&decl, &declarator, name);
        let init = Self::initializer_of(&declarator);
        let Some(scope) = Self::scope_of(&decl) else {
            // A global: flow-insensitive.
            return init
                .into_iter()
                .chain(candidates.iter().map(|(_, v)| *v))
                .collect();
        };

        let sure = candidates
            .iter()
            .filter(|(a, _)| guard_dominance::runs_before_on_every_path(a, at))
            .max_by_key(|(a, _)| a.start_byte())
            .map(|(a, _)| *a);
        let from = sure.map_or(scope.start_byte(), |a| a.start_byte());
        let address_passed = query::find_first_descendant(scope, |n| {
            n.kind() == "pointer_expression"
                && n.start_byte() >= from
                && n.start_byte() < at.start_byte()
                && n.child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "&")
                && n.child_by_field_name("argument")
                    .is_some_and(|v| get_node_text(&v, self.source) == name)
                && n.parent().is_some_and(|p| p.kind() == "argument_list")
        });
        if address_passed.is_some() {
            return Vec::new();
        }

        let loops: Vec<Node<'a>> = std::iter::successors(at.parent(), |n| n.parent())
            .take_while(|n| n.kind() != "function_definition")
            .filter(|n| {
                matches!(
                    n.kind(),
                    "for_statement" | "while_statement" | "do_statement"
                )
            })
            .collect();
        let inside = |outer: &Node, inner: &Node| {
            inner.start_byte() >= outer.start_byte() && inner.end_byte() <= outer.end_byte()
        };
        let mut values: Vec<Node<'a>> = candidates
            .iter()
            .filter(|(a, _)| {
                if a.start_byte() < at.start_byte() {
                    a.start_byte() >= from
                } else {
                    loops
                        .iter()
                        .any(|l| inside(l, a) && sure.is_none_or(|s| !inside(l, &s)))
                }
            })
            .map(|(_, v)| *v)
            .collect();
        if sure.is_none() {
            values.extend(init);
        }
        values
    }

    /// Whether `ident`'s variable is assigned on every path before `at`, so
    /// the value it entered with no longer reaches.
    fn reassigned_on_every_path(&self, ident: &Node<'a>, at: &Node<'a>) -> bool {
        let name = get_node_text(ident, self.source);
        let Some((decl, declarator)) =
            ast_utils::resolve_identifier_declarator(ident, name, self.source)
        else {
            return false;
        };
        self.assignments_to(&decl, &declarator, name)
            .iter()
            .any(|(a, _)| guard_dominance::runs_before_on_every_path(a, at))
    }

    /// The plain assignments `name = value` in the variable's scope whose
    /// left side resolves to `declarator`, as (assignment, value).
    fn assignments_to(
        &self,
        decl: &Node<'a>,
        declarator: &Node<'a>,
        name: &str,
    ) -> Vec<(Node<'a>, Node<'a>)> {
        let key = declarator.id();
        if let Some(found) = self.assignments.borrow().get(&key) {
            return found.clone();
        }
        let scope = Self::scope_of(decl).unwrap_or(self.root);
        let found: Vec<(Node<'a>, Node<'a>)> =
            query::find_descendants_of_kind(scope, "assignment_expression")
                .into_iter()
                .filter(|a| Self::is_plain_assignment(a))
                .filter_map(|a| {
                    let left = a.child_by_field_name("left")?;
                    let right = a.child_by_field_name("right")?;
                    let same = left.kind() == "identifier"
                        && get_node_text(&left, self.source) == name
                        && ast_utils::resolve_identifier_declarator(&left, name, self.source)
                            .is_some_and(|(_, d)| d.id() == declarator.id());
                    same.then_some((a, right))
                })
                .collect();
        self.assignments.borrow_mut().insert(key, found.clone());
        found
    }

    /// The function a local or parameter declaration belongs to; `None` for
    /// a file-scope declaration.
    fn scope_of(decl: &Node<'a>) -> Option<Node<'a>> {
        ast_utils::find_containing_function(decl)
    }

    /// The initializer of an `init_declarator`'s declarator.
    fn initializer_of(declarator: &Node<'a>) -> Option<Node<'a>> {
        declarator
            .parent()
            .filter(|p| p.kind() == "init_declarator")
            .and_then(|p| p.child_by_field_name("value"))
    }

    /// `=` rather than a compound assignment.
    fn is_plain_assignment(a: &Node) -> bool {
        a.child_by_field_name("operator")
            .is_some_and(|op| op.kind() == "=")
    }

    /// A declaration whose own specifiers include `const`: in
    /// `const char *p`, the characters; never the pointer of `char *const p`,
    /// whose qualifier sits in the declarator.
    fn has_const_qualifier(decl: &Node) -> bool {
        decl.named_child_nodes().any(|c| {
            c.kind() == "type_qualifier" && c.child(0).is_some_and(|q| q.kind() == "const")
        })
    }

    /// The member a field declarator names: `name` in `*name`, `name[4]`.
    fn member_name(declarator: &Node, source: &str) -> Option<String> {
        let mut d = *declarator;
        loop {
            if d.kind() == "field_identifier" {
                return Some(get_node_text(&d, source).to_string());
            }
            d = d.child_by_field_name("declarator")?;
        }
    }

    /// A declarator that is one level of pointer to the name: `*p`, `*const p`.
    fn is_single_pointer(declarator: &Node) -> bool {
        declarator.kind() == "pointer_declarator"
            && declarator
                .child_by_field_name("declarator")
                .is_some_and(|d| matches!(d.kind(), "identifier" | "field_identifier"))
    }
}
