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
use crate::analyze::const_eval::{self, MacroConstantMap};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::call_roles;
use crate::utility::cert_c::guard_dominance;
use crate::utility::cert_c::node_children::NodeChildren;
use crate::utility::cert_c::nonzero_facts;
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
                || !trace.literal_derived(&write.pointer, &write.site, Seed::ALL, 0)
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

/// Which values count as pointing into a literal for one question.
#[derive(Clone, Copy)]
struct Seed<'s> {
    /// When set, the only source: a parameter traced as if it pointed into
    /// a literal, by its function's start byte and its name. Used to ask
    /// whether a callee writes through, or returns, that parameter.
    param: Option<(usize, &'s str)>,
    /// Whether a pointer declared to const characters is a source. It is at
    /// a write (CERT: such a pointer "must be treated as a string literal"),
    /// but not when asking what a function returns: a const view of a
    /// parameter, returned, is the caller's argument, judged at the call.
    const_sources: bool,
}

impl Seed<'_> {
    /// Every source counts: a write's own question.
    const ALL: Seed<'static> = Seed {
        param: None,
        const_sources: true,
    };
}

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
    /// Per (function start, parameter index): whether some `return` returns
    /// a pointer derived from the parameter. Provisionally false.
    returns_params: RefCell<HashMap<(usize, usize), bool>>,
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
            returns_params: RefCell::default(),
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
            let seed = Seed {
                param: Some((def.start_byte(), name.as_str())),
                const_sources: false,
            };
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
            // Asking about one parameter, only that parameter is a source.
            "string_literal" | "concatenated_string" => seed.param.is_none(),
            "parenthesized_expression" => expr
                .named_child(0)
                .is_some_and(|e| self.literal_derived(&e, at, seed, d)),
            // A cast to an integer type is a number, not a pointer.
            "cast_expression" => {
                let to_pointer = field("type").is_some_and(|t| {
                    query::find_first_descendant(t, |n| n.kind() == "abstract_pointer_declarator")
                        .is_some()
                });
                to_pointer && field("value").is_some_and(|e| self.literal_derived(&e, at, seed, d))
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
            // `p + n`, `n + p` and `p - n` point where `p` does; `p - q` of
            // two pointers is a distance.
            "binary_expression" => {
                let op = ast_utils::get_binary_operator(expr, self.source).unwrap_or_default();
                let derived =
                    |f: &str| field(f).is_some_and(|e| self.literal_derived(&e, at, seed, d));
                match op {
                    "+" => derived("left") || derived("right"),
                    "-" => {
                        derived("left")
                            && !field("right")
                                .is_some_and(|r| derived("right") || self.is_pointer(&r))
                    }
                    _ => false,
                }
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
            "subscript_expression" => field("argument").is_some_and(|a| {
                let index = field("index").and_then(|i| self.constant(&i));
                self.element_derived(&a, index, at, seed, d)
            }),
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
        if self.element_derived(&pp, Some(0), at, seed, depth) {
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

    /// `a[i]` where `a` is an array whose element `i` (`index`, when it is a
    /// constant) may hold a literal-derived pointer at `at`: its initializer
    /// there, or an assignment to that element reaching `at` the way
    /// [`Self::reaching_values`] reads a variable's. An assignment to
    /// another constant element is a different object; one at an index not
    /// known may be this one, but kills nothing. A local array whose name is
    /// used as a value before `at` (passed, stored: its address escapes) may
    /// hold anything, and is not reported.
    fn element_derived(
        &self,
        array: &Node<'a>,
        index: Option<i64>,
        at: &Node<'a>,
        seed: Seed,
        depth: u32,
    ) -> bool {
        if array.kind() != "identifier" {
            return false;
        }
        let name = get_node_text(array, self.source);
        let Some((decl, declarator)) =
            ast_utils::resolve_identifier_declarator(array, name, self.source)
        else {
            return false;
        };
        let scope = Self::scope_of(&decl);
        let same_array = |b: &Node| {
            b.kind() == "identifier"
                && get_node_text(b, self.source) == name
                && ast_utils::resolve_identifier_declarator(b, name, self.source)
                    .is_some_and(|(_, d)| d.id() == declarator.id())
        };
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
        if let Some(scope) = scope {
            let escapes = query::find_first_descendant(scope, |n| {
                let before_or_looping =
                    n.start_byte() < at.start_byte() || loops.iter().any(|l| inside(l, &n));
                let as_value = n.parent().is_some_and(|p| {
                    let base_of_subscript = p.kind() == "subscript_expression"
                        && p.child_by_field_name("argument")
                            .is_some_and(|a| a.id() == n.id());
                    !(base_of_subscript
                        || p.kind() == "sizeof_expression"
                        || p.kind().ends_with("declarator"))
                });
                before_or_looping && as_value && same_array(&n)
            });
            if escapes.is_some() {
                return false;
            }
        }

        // (assignment, value, writes exactly element `index`)
        let assignments: Vec<(Node<'a>, Node<'a>, bool)> =
            query::find_descendants_of_kind(scope.unwrap_or(self.root), "assignment_expression")
                .into_iter()
                .filter(|a| Self::is_plain_assignment(a))
                .filter_map(|a| {
                    let left = a.child_by_field_name("left")?;
                    if left.kind() != "subscript_expression"
                        || !left
                            .child_by_field_name("argument")
                            .is_some_and(|b| same_array(&b))
                    {
                        return None;
                    }
                    let j = left
                        .child_by_field_name("index")
                        .and_then(|i| self.constant(&i));
                    if index.is_some() && j.is_some() && j != index {
                        return None;
                    }
                    let exact = index.is_some() && j == index;
                    Some((a, a.child_by_field_name("right")?, exact))
                })
                .collect();

        let sure = match scope {
            Some(_) if index.is_some() => {
                let exact: Vec<(Node<'a>, Node<'a>)> = assignments
                    .iter()
                    .filter(|(_, _, exact)| *exact)
                    .map(|(a, v, _)| (*a, *v))
                    .collect();
                Self::last_sure_assignment(&exact, at, self.source)
            }
            _ => None,
        };
        let from = sure.map_or(0, |s| s.start_byte());
        let assigned = assignments.iter().any(|(a, v, _)| {
            let reaches = match scope {
                // A global: flow-insensitive.
                None => true,
                Some(_) if a.start_byte() < at.start_byte() => {
                    a.start_byte() >= from && !Self::on_another_path(a, at, sure)
                }
                Some(_) => loops
                    .iter()
                    .any(|l| inside(l, a) && sure.is_none_or(|s| !inside(l, &s))),
            };
            reaches && self.literal_derived(v, a, seed, depth + 1)
        });
        if assigned {
            return true;
        }
        if sure.is_some() {
            return false;
        }
        let Some(init) = Self::initializer_of(&declarator) else {
            return false;
        };
        if init.kind() != "initializer_list" {
            return false;
        }
        let elements: Vec<Node<'a>> = init
            .named_child_nodes()
            .filter(|e| e.kind() != "comment")
            .collect();
        let positional = elements.iter().all(|e| e.kind() != "initializer_pair");
        match index {
            Some(k) if positional => usize::try_from(k)
                .ok()
                .and_then(|k| elements.get(k))
                .is_some_and(|e| self.literal_derived(e, e, seed, depth + 1)),
            _ => elements.iter().any(|e| {
                let value = if e.kind() == "initializer_pair" {
                    e.child_by_field_name("value").unwrap_or(*e)
                } else {
                    *e
                };
                self.literal_derived(&value, &value, seed, depth + 1)
            }),
        }
    }

    /// The value of an integer constant expression, as far as it is spelled
    /// out in the expression itself.
    fn constant(&self, expr: &Node) -> Option<i64> {
        const_eval::try_evaluate_expr(expr, self.source, &MacroConstantMap::new())
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
        if seed.param.is_none() && members.iter().any(|(m, is_const)| *m == field && *is_const) {
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
            let is_const =
                Self::has_const_qualifier(&field) && Self::is_character_type(&field, self.source);
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
            if seed.param.is_none() && self.returns_literal(def, depth) {
                return true;
            }
            // A returned parameter is whatever the caller passed there.
            let Some(params) = ast_utils::get_function_parameters(def, self.source) else {
                return false;
            };
            let args: Vec<Node<'a>> = call
                .child_by_field_name("arguments")
                .map(|a| {
                    a.named_child_nodes()
                        .filter(|n| n.kind() != "comment")
                        .collect()
                })
                .unwrap_or_default();
            return params.iter().enumerate().any(|(k, _)| {
                args.get(k).is_some_and(|arg| {
                    self.returns_param(def, k, depth)
                        && self.literal_derived(arg, at, seed, depth + 1)
                })
            });
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
                .any(|value| {
                    let own = Seed {
                        param: None,
                        const_sources: false,
                    };
                    self.literal_derived(&value, &value, own, depth + 1)
                })
        });
        self.returns_literal.borrow_mut().insert(key, found);
        found
    }

    /// Whether some `return` in `def` returns a pointer derived from its
    /// parameter `index`.
    fn returns_param(&self, def: &Node<'a>, index: usize, depth: u32) -> bool {
        let key = (def.start_byte(), index);
        if let Some(&known) = self.returns_params.borrow().get(&key) {
            return known;
        }
        self.returns_params.borrow_mut().insert(key, false);
        let found = (|| {
            let params = ast_utils::get_function_parameters(def, self.source)?;
            let (name, _) = params.get(index)?;
            let body = def.child_by_field_name("body")?;
            let seed = Seed {
                param: Some((def.start_byte(), name.as_str())),
                const_sources: false,
            };
            Some(
                query::find_descendants_of_kind(body, "return_statement")
                    .into_iter()
                    .filter_map(|r| r.named_child(0))
                    .any(|value| self.literal_derived(&value, &value, seed, depth + 1)),
            )
        })()
        .unwrap_or(false);
        self.returns_params.borrow_mut().insert(key, found);
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
        let seeded = decl.kind() == "parameter_declaration"
            && seed.param.is_some_and(|(func, param)| {
                param == name
                    && ast_utils::find_containing_function(&decl)
                        .is_some_and(|f| f.start_byte() == func)
            });
        if seeded && !self.reassigned_on_every_path(ident, at) {
            return true;
        }
        let is_array = declarator.kind() == "array_declarator";
        let pointee_const = Self::has_const_qualifier(&decl)
            && Self::is_character_type(&decl, self.source)
            && (is_array || Self::is_single_pointer(&declarator));
        if pointee_const && seed.const_sources && seed.param.is_none() {
            return true;
        }
        if is_array {
            return false;
        }
        let values = self.reaching_values(ident, at);
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
    /// A variable whose address is taken before `at`, or in a loop holding
    /// it, may be written through that pointer and hold anything: nothing
    /// reaches ([`Self::address_escapes`]).
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

        let sure = Self::last_sure_assignment(&candidates, at, self.source);
        let from = sure.map_or(scope.start_byte(), |a| a.start_byte());
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
        if self.address_escapes(&scope, &declarator, name, at, &loops, from) {
            return Vec::new();
        }
        let mut values: Vec<Node<'a>> = candidates
            .iter()
            .filter(|(a, _)| {
                if a.start_byte() < at.start_byte() {
                    a.start_byte() >= from && !Self::on_another_path(a, at, sure)
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

    /// Whether the address of the variable `declarator` declares, named
    /// `name`, is taken in `scope` where a write through it may come before
    /// `at` (before `at`, or inside one of `loops`, the loops holding `at`,
    /// which come round to it again), so the variable may hold anything.
    /// Two uses of the address are not that: an argument of a library call
    /// that keeps no copy, which writes only during the call and matters
    /// only between `from` (the last sure assignment) and `at`; and the
    /// initial value of a local pointer through which the variable is only
    /// read (`char **pp = &p; (*pp)[0] = 'x';`).
    fn address_escapes(
        &self,
        scope: &Node<'a>,
        declarator: &Node<'a>,
        name: &str,
        at: &Node<'a>,
        loops: &[Node<'a>],
        from: usize,
    ) -> bool {
        let looping = |n: &Node| {
            loops
                .iter()
                .any(|l| n.start_byte() >= l.start_byte() && n.end_byte() <= l.end_byte())
        };
        query::find_first_descendant(*scope, |n| {
            let before_or_looping = n.start_byte() < at.start_byte() || looping(&n);
            let is_address = n.kind() == "pointer_expression"
                && n.child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "&")
                && n.child_by_field_name("argument")
                    .filter(|v| v.kind() == "identifier" && get_node_text(v, self.source) == name)
                    .is_some_and(|v| {
                        ast_utils::resolve_identifier_declarator(&v, name, self.source)
                            .is_some_and(|(_, d)| d.id() == declarator.id())
                    });
            if !(before_or_looping && is_address) {
                return false;
            }
            if nonzero_facts::passed_to_library_call(&n, &self.root, self.source) {
                return (n.start_byte() >= from && n.start_byte() < at.start_byte()) || looping(&n);
            }
            !self.read_only_alias(&n)
        })
        .is_some()
    }

    /// Whether `address` (`&p`) initializes a local pointer `pp` whose every
    /// other use reads through it -- `*pp` or `pp[i]`, never assigned,
    /// incremented, or itself having its address taken -- so no write
    /// reaches `p` through it.
    fn read_only_alias(&self, address: &Node<'a>) -> bool {
        let Some(mut alias) = address
            .parent()
            .filter(|p| p.kind() == "init_declarator")
            .and_then(|p| p.child_by_field_name("declarator"))
            .filter(|d| d.kind() == "pointer_declarator")
        else {
            return false;
        };
        while alias.kind() == "pointer_declarator" {
            match alias.child_by_field_name("declarator") {
                Some(inner) => alias = inner,
                None => return false,
            }
        }
        if alias.kind() != "identifier" {
            return false;
        }
        let alias_name = get_node_text(&alias, self.source);
        let Some(func) = ast_utils::find_containing_function(address) else {
            return false;
        };
        let written = |n: &Node| {
            n.parent().is_some_and(|p| {
                (p.kind() == "assignment_expression"
                    && p.child_by_field_name("left")
                        .is_some_and(|l| l.id() == n.id()))
                    || p.kind() == "update_expression"
                    || (p.kind() == "pointer_expression"
                        && p.child_by_field_name("operator")
                            .is_some_and(|op| op.kind() == "&"))
            })
        };
        query::find_descendants_of_kind(func, "identifier")
            .into_iter()
            .filter(|n| n.id() != alias.id() && get_node_text(n, self.source) == alias_name)
            .all(|n| {
                let Some(parent) = n.parent() else {
                    return false;
                };
                let through = match parent.kind() {
                    "pointer_expression" => parent
                        .child_by_field_name("operator")
                        .is_some_and(|op| op.kind() == "*"),
                    "subscript_expression" => parent
                        .child_by_field_name("argument")
                        .is_some_and(|a| a.id() == n.id()),
                    _ => false,
                };
                through && !written(&parent) && !written(&n)
            })
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
        let candidates = self.assignments_to(&decl, &declarator, name);
        Self::last_sure_assignment(&candidates, at, self.source).is_some()
    }

    /// The last statement before `at` that assigns the variable on every
    /// path through it ([`Self::assigns_on_every_path`]), being an earlier
    /// statement of a block (or `case`) holding `at`. Values assigned before
    /// it no longer reach `at`, unless control can jump past it into the
    /// stretch before `at` (`nonzero_facts::region_entered_by_jump`): then
    /// there is none.
    fn last_sure_assignment(
        candidates: &[(Node<'a>, Node<'a>)],
        at: &Node<'a>,
        source: &str,
    ) -> Option<Node<'a>> {
        let sure = Self::last_sure_statement(candidates, at)?;
        let func = ast_utils::find_containing_function(at)?;
        (!nonzero_facts::region_entered_by_jump(&func, sure.end_byte(), at.start_byte(), source))
            .then_some(sure)
    }

    /// [`Self::last_sure_assignment`] before jumps are considered.
    fn last_sure_statement(candidates: &[(Node<'a>, Node<'a>)], at: &Node<'a>) -> Option<Node<'a>> {
        let mut current = *at;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition" {
                return None;
            }
            if matches!(parent.kind(), "compound_statement" | "case_statement") {
                let preceding: Vec<Node<'a>> = parent
                    .named_child_nodes()
                    .take_while(|stmt| stmt.end_byte() <= current.start_byte())
                    .collect();
                if let Some(stmt) = preceding
                    .iter()
                    .rev()
                    .find(|stmt| Self::assigns_on_every_path(stmt, candidates))
                {
                    return Some(*stmt);
                }
            }
            current = parent;
        }
        None
    }

    /// Whether `a`, before `at`, is on a path that cannot reach it: the two
    /// sit in the two arms of one `if`/`else`, or in different cases of one
    /// `switch` where `a`'s case does not fall through. A loop around that
    /// construct still carries `a` round to `at`, unless `sure` (the last
    /// assignment on every path to `at`) is inside that loop.
    fn on_another_path(a: &Node<'a>, at: &Node<'a>, sure: Option<Node<'a>>) -> bool {
        let inside = |outer: &Node, inner: &Node| {
            inner.start_byte() >= outer.start_byte() && inner.end_byte() <= outer.end_byte()
        };
        let mut construct = None;
        let mut current = *a;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition" {
                break;
            }
            if parent.kind() == "if_statement" && inside(&parent, at) {
                let arm = |f: &str| parent.child_by_field_name(f);
                let (Some(then), Some(other)) = (arm("consequence"), arm("alternative")) else {
                    break;
                };
                if (inside(&then, a) && inside(&other, at))
                    || (inside(&other, a) && inside(&then, at))
                {
                    construct = Some(parent);
                }
                break;
            }
            if current.kind() == "case_statement" && inside(&parent, at) && !inside(&current, at) {
                let falls_through = current
                    .named_child_nodes()
                    .filter(|s| s.kind() != "comment")
                    .last()
                    .is_none_or(|last| !guard_dominance::always_diverges(&last));
                if !falls_through {
                    construct = Some(parent);
                }
                break;
            }
            if inside(&parent, at) {
                break;
            }
            current = parent;
        }
        let Some(construct) = construct else {
            return false;
        };
        let innermost_loop = std::iter::successors(construct.parent(), |n| n.parent())
            .take_while(|n| n.kind() != "function_definition")
            .find(|n| {
                matches!(
                    n.kind(),
                    "for_statement" | "while_statement" | "do_statement"
                )
            });
        match innermost_loop {
            None => true,
            Some(l) => sure.is_some_and(|s| inside(&l, &s)),
        }
    }

    /// Whether every path through `stmt` that continues after it makes one
    /// of `candidates`: an expression statement whose expression is one (or
    /// a link of a chain, `p = q = v;`, or of a comma expression), a block
    /// with such a statement, or an `if`/`else` each of whose arms makes one
    /// or always leaves.
    fn assigns_on_every_path(stmt: &Node<'a>, candidates: &[(Node<'a>, Node<'a>)]) -> bool {
        match stmt.kind() {
            "expression_statement" => candidates.iter().any(|(a, _)| {
                let mut n = *a;
                while let Some(parent) = n.parent() {
                    if parent.id() == stmt.id() {
                        return true;
                    }
                    if !matches!(
                        parent.kind(),
                        "assignment_expression" | "parenthesized_expression" | "comma_expression"
                    ) {
                        return false;
                    }
                    n = parent;
                }
                false
            }),
            "compound_statement" => stmt
                .named_child_nodes()
                .any(|s| Self::assigns_on_every_path(&s, candidates)),
            "if_statement" => {
                let arm = |field: &str| {
                    stmt.child_by_field_name(field).is_some_and(|arm| {
                        let arm = if arm.kind() == "else_clause" {
                            match arm.named_child(0) {
                                Some(inner) => inner,
                                None => return false,
                            }
                        } else {
                            arm
                        };
                        guard_dominance::always_diverges(&arm)
                            || Self::assigns_on_every_path(&arm, candidates)
                    })
                };
                arm("consequence") && arm("alternative")
            }
            _ => false,
        }
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

    /// Whether `expr` names a pointer or an array by its declaration (through
    /// parentheses and casts), so `p - expr` is a distance between pointers.
    fn is_pointer(&self, expr: &Node<'a>) -> bool {
        let expr = guard_dominance::strip_arg_wrappers(expr);
        if expr.kind() != "identifier" {
            return false;
        }
        let name = get_node_text(&expr, self.source);
        ast_utils::resolve_identifier_declarator(&expr, name, self.source)
            .is_some_and(|(_, d)| matches!(d.kind(), "pointer_declarator" | "array_declarator"))
    }

    /// Whether a declaration's type is a character type a string literal
    /// has: plain `char`, or `wchar_t`, `char8_t`, `char16_t`, `char32_t`.
    /// `const void *` and `const unsigned char *` are buffers, not strings.
    fn is_character_type(decl: &Node, source: &str) -> bool {
        decl.child_by_field_name("type").is_some_and(|t| {
            matches!(
                (t.kind(), get_node_text(&t, source).trim()),
                ("primitive_type", "char")
                    | (
                        "type_identifier" | "primitive_type",
                        "wchar_t" | "char8_t" | "char16_t" | "char32_t"
                    )
            )
        })
    }

    /// A declarator that is one level of pointer to the name: `*p`, `*const p`.
    fn is_single_pointer(declarator: &Node) -> bool {
        declarator.kind() == "pointer_declarator"
            && declarator
                .child_by_field_name("declarator")
                .is_some_and(|d| matches!(d.kind(), "identifier" | "field_identifier"))
    }
}
