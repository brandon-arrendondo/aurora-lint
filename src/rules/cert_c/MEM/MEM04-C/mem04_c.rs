// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! MEM04-C: Beware of zero-length allocations
//!
//! A zero-size request to an allocation function is implementation-defined
//! (C11 7.22.3p1): a null pointer, or a block that may not be accessed. For
//! `realloc(p, 0)` the editions moved. C11 says the old object is not freed
//! when a null pointer is returned; C17 makes the call implementation-defined
//! and obsolescent (7.22.3.5p3, 7.31.12p2); C23 makes it undefined
//! (7.24.3.7p3). An implementation that frees and returns null turns CERT's
//! own `if (p2 == NULL) free(p);` into a double free.
//!
//! The rule reports two forms:
//!
//! - **`realloc`**: a size not proven non-zero at the call, the hazard in
//!   every edition.
//! - **`malloc`, `calloc`, `aligned_alloc`**: a size that comes from input or
//!   from a parameter of the function, and that nothing in the function
//!   proves non-zero ("possibly by user-controlled input", CERT's
//!   noncompliant example). A size the function computes itself is the
//!   function's own business.
//!
//! Any size that is the constant zero is reported for every allocator.
//!
//! A size is proven non-zero by constant evaluation (macros and enumerators
//! included), `sizeof`, `strlen(s) + 1`, a product of compile-time factors,
//! or a condition known to hold at the call that excludes zero
//! (`if (n == 0) return NULL;`, `n > 0`, `!(n < 1)`;
//! `nonzero_facts::known_conditions`). `n * sizeof(T)` is not exempt, and a
//! guard on `n` alone does not prove it: the product may wrap to zero.
//!
//! An allocator is a call to the library function: a name the file defines
//! itself, or a local or parameter spelled the same, is not one. A
//! function-like macro whose expansion passes an allocator a size reading
//! one of its parameters is an allocation too, unless the allocator is the
//! file's own; the size is read as the macro expands it at the call
//! (`ALLOC_N(int, n)` allocates `sizeof(int) * (n)`).

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval::{self, MacroConstantMap};
use crate::analyze::context::{ProjectContext, ScopedTable};
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::analyze::noreturn::ByNoreturnTrust;
use crate::manifest::Severity;
use crate::rules::cert_c::int_provenance;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils::{self, get_node_text, IdentifierBinding};
use crate::utility::cert_c::guard_dominance;
use crate::utility::cert_c::node_children::NodeChildren;
use crate::utility::cert_c::nonzero_facts;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

/// The allocation functions MEM04-C reads, with the indices of their size
/// arguments.
const ALLOCATORS: &[(&str, &[usize])] = &[
    ("malloc", &[0]),
    ("calloc", &[0, 1]),
    ("realloc", &[1]),
    ("aligned_alloc", &[1]),
];

pub struct Mem04C {
    project_macros: RefCell<Arc<MacroConstantMap>>,
    function_macros: RefCell<Arc<HashMap<String, FunctionMacro>>>,
    noreturn_functions: RefCell<ByNoreturnTrust<Arc<HashSet<String>>>>,
    function_summaries: RefCell<ScopedTable<FunctionSummary>>,
    global_writers: RefCell<Arc<HashMap<String, HashSet<String>>>>,
    settings: RefCell<Arc<AnalysisSettings>>,
}

impl Default for Mem04C {
    fn default() -> Self {
        Self::new()
    }
}

impl Mem04C {
    pub fn new() -> Self {
        Self {
            project_macros: RefCell::new(Arc::new(MacroConstantMap::new())),
            function_macros: RefCell::default(),
            noreturn_functions: RefCell::default(),
            function_summaries: RefCell::default(),
            global_writers: RefCell::default(),
            settings: RefCell::default(),
        }
    }
}

/// What one file's check needs at every allocation.
struct FileFacts {
    macros: MacroConstantMap,
    noreturn: HashSet<String>,
    /// Allocator names the file gives its own definition.
    redefined: HashSet<String>,
    /// Function-like macros that wrap an allocator, by name.
    wrappers: HashMap<String, Wrapper>,
}

/// A function-like macro whose expansion calls an allocator with a size
/// that reads one of the macro's parameters.
#[derive(Clone)]
struct Wrapper {
    allocator: &'static str,
    /// Each size argument the allocator receives, as written in the
    /// expansion with the macro's parameters replaced by [`placeholder`]s:
    /// `sizeof(int)*(__mem04_arg1__)` for `ALLOC_N(T, n)`.
    sizes: Vec<String>,
}

/// The stand-in for macro parameter `i` in a [`Wrapper`]'s sizes.
fn placeholder(i: usize) -> String {
    format!("__mem04_arg{}__", i)
}

/// What a call allocates through.
enum Allocation {
    /// The library allocator itself, with the indices of its size
    /// arguments.
    Direct(&'static str, Vec<usize>),
    /// A macro wrapping it.
    Wrapped(Wrapper),
}

/// One size an allocation receives: `expr` in `text` (the file's source, or
/// for a wrapper, the size as the macro expands it at this call), and the
/// arguments of the call that it reads outside `sizeof`.
struct Size<'t, 'a> {
    expr: Node<'t>,
    text: &'t str,
    reads: Vec<Node<'a>>,
}

impl CertRule for Mem04C {
    fn rule_id(&self) -> &'static str {
        "MEM04-C"
    }

    fn description(&self) -> &'static str {
        "Beware of zero-length allocations"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "MEM04-C"
    }

    fn reads_header_facts(&self) -> bool {
        true
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
        *self.function_macros.borrow_mut() = context.function_macros.clone();
        *self.noreturn_functions.borrow_mut() = context.noreturn_functions.clone();
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.global_writers.borrow_mut() = context.global_writers.clone();
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let settings = Arc::clone(&self.settings.borrow());
        let facts = FileFacts {
            macros: const_eval::merged_macro_constants(
                &self.project_macros.borrow(),
                node,
                source,
                settings.facts,
            ),
            noreturn: crate::analyze::noreturn::noreturn_names_for_file(
                self.noreturn_functions.borrow().get(&settings),
                node,
                source,
                &settings,
            ),
            redefined: Self::defined_function_names(node, source),
            wrappers: self.allocator_wrappers(node, source),
        };

        let mut violations = Vec::new();
        let mut risky_vars: HashMap<usize, HashSet<String>> = HashMap::new();
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&crate::parser::c_language()).is_err() {
            return Vec::new();
        }
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(allocation) = Self::allocation_at(&call, source, &facts) else {
                continue;
            };
            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };
            let args: Vec<Node> = args
                .named_child_nodes()
                .filter(|a| a.kind() != "comment")
                .collect();
            let (allocator, expansions) = match &allocation {
                Allocation::Direct(allocator, _) => (*allocator, Vec::new()),
                Allocation::Wrapped(wrapper) => {
                    let macro_args = Self::macro_arguments(&call, source);
                    (
                        wrapper.allocator,
                        wrapper
                            .sizes
                            .iter()
                            .filter_map(|template| {
                                Self::expand_size(&mut parser, template, &macro_args)
                            })
                            .collect(),
                    )
                }
            };
            let sizes: Vec<Size> = match &allocation {
                Allocation::Direct(_, indices) => indices
                    .iter()
                    .filter_map(|&i| args.get(i))
                    .map(|size| Size {
                        expr: *size,
                        text: source,
                        reads: vec![*size],
                    })
                    .collect(),
                Allocation::Wrapped(_) => expansions
                    .iter()
                    .filter_map(|(tree, text, reads)| {
                        Some(Size {
                            expr: Self::expanded_expression(tree)?,
                            text,
                            reads: reads.clone(),
                        })
                    })
                    .collect(),
            };
            for size in &sizes {
                if let Some(message) =
                    self.finding(allocator, &call, size, source, &facts, &mut risky_vars)
                {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        message,
                        severity: self.severity(),
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        file_path: String::new(),
                        suggestion: Some(format!(
                            "Check that the size is non-zero before calling {}()",
                            allocator
                        )),
                        requires_manual_review: None,
                    });
                    // One finding per call.
                    break;
                }
            }
        }
        violations
    }
}

impl Mem04C {
    /// The allocator `call` invokes and the indices of its size arguments:
    /// a direct call to the library function, or a call to a macro wrapping
    /// one.
    fn allocation_at(call: &Node, source: &str, facts: &FileFacts) -> Option<Allocation> {
        let function = call.child_by_field_name("function")?;
        if function.kind() != "identifier" {
            return None;
        }
        let name = get_node_text(&function, source);
        if let Some((allocator, sizes)) = ALLOCATORS.iter().find(|(a, _)| *a == name) {
            if facts.redefined.contains(name) {
                return None;
            }
            // A local or parameter spelled like the allocator is not it.
            if matches!(
                ast_utils::resolve_identifier_binding(&function, name, source),
                Some(IdentifierBinding::Local(_) | IdentifierBinding::Parameter(_))
            ) {
                return None;
            }
            return Some(Allocation::Direct(allocator, sizes.to_vec()));
        }
        // A macro wrapping an allocator the file defines for itself calls
        // the file's function, as a direct call would.
        facts
            .wrappers
            .get(name)
            .filter(|w| !facts.redefined.contains(w.allocator))
            .cloned()
            .map(Allocation::Wrapped)
    }

    /// The arguments of a macro invocation parsed as a call, each as its
    /// text and the nodes it spans: split at the argument list's own commas,
    /// since a type argument does not parse as one expression
    /// (`ALLOC_N(struct S, n)` holds an `ERROR`).
    fn macro_arguments<'a>(call: &Node<'a>, source: &str) -> Vec<(String, Vec<Node<'a>>)> {
        let Some(list) = call.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut bounds = vec![list.start_byte() + 1];
        let mut nodes = Vec::new();
        for child in list.child_nodes() {
            match child.kind() {
                "," => bounds.push(child.end_byte()),
                "(" | ")" | "comment" => {}
                _ => nodes.push(child),
            }
        }
        let end = list.end_byte().saturating_sub(1);
        let mut args = Vec::new();
        for (i, &from) in bounds.iter().enumerate() {
            let to = bounds.get(i + 1).map_or(end, |&next| next - 1);
            let Some(text) = source.get(from..to).map(str::trim) else {
                continue;
            };
            if text.is_empty() {
                continue;
            }
            let spanned = nodes
                .iter()
                .filter(|n| n.start_byte() >= from && n.end_byte() <= to)
                .copied()
                .collect();
            args.push((text.to_string(), spanned));
        }
        args
    }

    /// A wrapper's size `template` as this call expands it -- each
    /// placeholder replaced by the argument at its position, parenthesized
    /// when it is an expression of more than one token (never a type name,
    /// which `sizeof((struct S))` would not take) -- parsed on its own: the tree, its
    /// text, and the argument nodes it reads outside `sizeof`. `None` when
    /// an argument is missing or the result does not parse.
    fn expand_size<'a>(
        parser: &mut tree_sitter::Parser,
        template: &str,
        args: &[(String, Vec<Node<'a>>)],
    ) -> Option<(tree_sitter::Tree, String, Vec<Node<'a>>)> {
        let wrap = |expr: &str| format!("void __mem04_size(void) {{ ({}); }}", expr);
        let template_text = wrap(template);
        let template_tree = parser.parse(&template_text, None)?;
        let mut reads: Vec<Node<'a>> = Vec::new();
        for ident in query::find_descendants_of_kind(template_tree.root_node(), "identifier") {
            let name = get_node_text(&ident, &template_text);
            let Some(i) = (0..args.len()).find(|&i| placeholder(i) == name) else {
                continue;
            };
            let under_sizeof = query::find_ancestor(ident, |a| {
                matches!(a.kind(), "sizeof_expression" | "alignof_expression")
            })
            .is_some();
            if !under_sizeof {
                for node in &args[i].1 {
                    if !reads.iter().any(|r| r.id() == node.id()) {
                        reads.push(*node);
                    }
                }
            }
        }
        let mut expanded = template.to_string();
        // Highest index first, so `__mem04_arg1__` is not read inside
        // `__mem04_arg11__`.
        for i in (0..args.len()).rev() {
            let (text, nodes) = &args[i];
            let single = nodes.len() == 1
                && matches!(
                    nodes[0].kind(),
                    "identifier"
                        | "number_literal"
                        | "parenthesized_expression"
                        | "call_expression"
                );
            let arg = if single || crate::analyze::side_effects::is_type_name_text(text) {
                text.clone()
            } else {
                format!("({})", text)
            };
            expanded = expanded.replace(&placeholder(i), &arg);
        }
        if expanded.contains("__mem04_arg") {
            return None;
        }
        let text = wrap(&expanded);
        let tree = parser.parse(&text, None)?;
        if tree.root_node().has_error() {
            return None;
        }
        Some((tree, text, reads))
    }

    /// The size expression of a tree [`Self::expand_size`] parsed.
    fn expanded_expression(tree: &tree_sitter::Tree) -> Option<Node<'_>> {
        let statement =
            query::find_first_descendant(tree.root_node(), |n| n.kind() == "expression_statement")?;
        let mut expr = statement.named_child(0)?;
        if expr.kind() == "parenthesized_expression" {
            expr = expr.named_child(0)?;
        }
        Some(expr)
    }

    /// The message for `size`, a size a call to `allocator` receives, or
    /// `None` when it is not reported.
    fn finding(
        &self,
        allocator: &str,
        call: &Node,
        size: &Size,
        source: &str,
        facts: &FileFacts,
        risky_vars: &mut HashMap<usize, HashSet<String>>,
    ) -> Option<String> {
        let size_text = get_node_text(&size.expr, size.text);
        // The call as written: `os_malloc()`, or `os_malloc() (malloc)` when
        // a macro wraps the allocator.
        let callee = call
            .child_by_field_name("function")
            .map(|f| get_node_text(&f, source))
            .unwrap_or(allocator);
        let called = if callee == allocator {
            format!("{}()", allocator)
        } else {
            format!("{}() ({})", callee, allocator)
        };
        if const_eval::try_evaluate_expr(&size.expr, size.text, &facts.macros) == Some(0) {
            return Some(format!(
                "{} is called with a size of zero: the result of a zero-length \
                 allocation is implementation-defined and may not be accessed",
                called
            ));
        }
        if Self::proven_nonzero(&size.expr, size.text, call, source, facts) {
            return None;
        }
        if allocator == "realloc" {
            return Some(format!(
                "{} size '{}' is not proven non-zero: realloc(p, 0) may free p and \
                 return a null pointer (implementation-defined in C17, undefined in C23)",
                called, size_text
            ));
        }
        let reads_input = size
            .reads
            .iter()
            .any(|read| self.reads_input_or_parameter(read, call, source, risky_vars));
        if reads_input {
            return Some(format!(
                "{} size '{}' comes from input or a parameter and nothing in the \
                 function proves it non-zero: a zero-length allocation's result is \
                 implementation-defined",
                called, size_text
            ));
        }
        None
    }

    /// Whether `expr`, in `text`, is proven non-zero where `site` (in
    /// `source`) executes: a non-zero constant, `sizeof`, `strlen(s) + c`
    /// with `c > 0`, a `?:` whose arms are both proven, a product of
    /// compile-time factors ([`Self::compile_time_nonzero`]), or a
    /// condition known there excluding zero. A product with a factor known
    /// only at run time may wrap to zero however its factors are guarded:
    /// `n * sizeof(struct T)` for `n != 0` needs a check on the product.
    fn proven_nonzero(
        expr: &Node,
        text: &str,
        site: &Node,
        source: &str,
        facts: &FileFacts,
    ) -> bool {
        if let Some(v) = const_eval::try_evaluate_expr(expr, text, &facts.macros) {
            return v != 0;
        }
        match expr.kind() {
            "sizeof_expression" | "alignof_expression" => return true,
            "parenthesized_expression" => {
                if let Some(inner) = expr.named_child(0) {
                    return Self::proven_nonzero(&inner, text, site, source, facts);
                }
            }
            "cast_expression" => {
                if let Some(value) = expr.child_by_field_name("value") {
                    if Self::proven_nonzero(&value, text, site, source, facts) {
                        return true;
                    }
                }
            }
            "conditional_expression" => {
                let arms = (
                    expr.child_by_field_name("consequence"),
                    expr.child_by_field_name("alternative"),
                );
                if let (Some(a), Some(b)) = arms {
                    if Self::proven_nonzero(&a, text, site, source, facts)
                        && Self::proven_nonzero(&b, text, site, source, facts)
                    {
                        return true;
                    }
                }
            }
            "binary_expression" => {
                let op = ast_utils::get_binary_operator(expr, text).unwrap_or_default();
                let (Some(left), Some(right)) = (
                    expr.child_by_field_name("left"),
                    expr.child_by_field_name("right"),
                ) else {
                    return false;
                };
                if op == "*" && Self::compile_time_nonzero(expr, text, facts) {
                    return true;
                }
                if op == "+" {
                    let positive = |n: &Node| {
                        const_eval::try_evaluate_expr(n, text, &facts.macros).is_some_and(|v| v > 0)
                    };
                    if (Self::is_string_length(&left, text) && positive(&right))
                        || (Self::is_string_length(&right, text) && positive(&left))
                    {
                        return true;
                    }
                }
            }
            _ => {}
        }
        let targets = nonzero_facts::peeled_spellings(expr, text);
        nonzero_facts::known_conditions(site, &targets, source, &facts.noreturn)
            .iter()
            .any(|(cond, truth)| {
                guard_dominance::condition_excludes_zero(
                    cond,
                    &targets,
                    *truth,
                    source,
                    &facts.macros,
                )
            })
    }

    /// A non-zero value fixed at translation: a non-zero constant,
    /// `sizeof`, `alignof`, or a product, cast or parenthesization of them.
    fn compile_time_nonzero(expr: &Node, text: &str, facts: &FileFacts) -> bool {
        if let Some(v) = const_eval::try_evaluate_expr(expr, text, &facts.macros) {
            return v != 0;
        }
        match expr.kind() {
            "sizeof_expression" | "alignof_expression" => true,
            "parenthesized_expression" => expr
                .named_child(0)
                .is_some_and(|inner| Self::compile_time_nonzero(&inner, text, facts)),
            "cast_expression" => expr
                .child_by_field_name("value")
                .is_some_and(|value| Self::compile_time_nonzero(&value, text, facts)),
            "binary_expression" => {
                ast_utils::get_binary_operator(expr, text) == Some("*")
                    && ["left", "right"].iter().all(|f| {
                        expr.child_by_field_name(f)
                            .is_some_and(|e| Self::compile_time_nonzero(&e, text, facts))
                    })
            }
            _ => false,
        }
    }

    /// A call to `strlen`, `wcslen` or `strnlen`, possibly cast: a length,
    /// so adding a positive constant cannot give zero short of the whole
    /// address space.
    fn is_string_length(node: &Node, source: &str) -> bool {
        let node = guard_dominance::strip_arg_wrappers(node);
        node.kind() == "call_expression"
            && node.child_by_field_name("function").is_some_and(|f| {
                matches!(
                    get_node_text(&f, source).trim(),
                    "strlen" | "wcslen" | "strnlen"
                )
            })
    }

    /// Whether `size` reads a parameter of the function the call is in, a
    /// variable that function fills from an input source, a global a tainted
    /// function writes, or calls an input source itself
    /// (`int_provenance::callee_is_risky_source`). A `sizeof` operand is not
    /// read.
    fn reads_input_or_parameter(
        &self,
        size: &Node,
        site: &Node,
        source: &str,
        risky_vars: &mut HashMap<usize, HashSet<String>>,
    ) -> bool {
        let Some(func) = ast_utils::find_containing_function(site) else {
            return false;
        };
        let summaries = self.function_summaries.borrow();
        let global_writers = self.global_writers.borrow();
        let risky = risky_vars.entry(func.start_byte()).or_insert_with(|| {
            func.child_by_field_name("body")
                .map(|body| int_provenance::collect_risky_vars(&body, &summaries, source))
                .unwrap_or_default()
        });
        let mut stack = vec![*size];
        while let Some(node) = stack.pop() {
            match node.kind() {
                "sizeof_expression" | "alignof_expression" => continue,
                "call_expression" => {
                    if let Some(f) = node.child_by_field_name("function") {
                        if int_provenance::callee_is_risky_source(
                            get_node_text(&f, source),
                            &summaries,
                        ) {
                            return true;
                        }
                    }
                    if let Some(args) = node.child_by_field_name("arguments") {
                        stack.push(args);
                    }
                    continue;
                }
                "field_expression" => {
                    // `p->len` reads `p`; the field name is not a variable.
                    if let Some(arg) = node.child_by_field_name("argument") {
                        stack.push(arg);
                    }
                    continue;
                }
                "identifier" => {
                    let name = get_node_text(&node, source);
                    match ast_utils::resolve_identifier_binding(&node, name, source) {
                        Some(IdentifierBinding::Parameter(_)) => return true,
                        Some(IdentifierBinding::Local(_)) if risky.contains(name) => return true,
                        Some(IdentifierBinding::Global(_))
                            if int_provenance::global_is_tainted(
                                name,
                                &global_writers,
                                &summaries,
                            ) =>
                        {
                            return true
                        }
                        _ => {}
                    }
                    continue;
                }
                _ => {}
            }
            stack.extend(node.named_child_nodes());
        }
        false
    }

    /// The names of the allocators this file defines as functions: a call
    /// then reaches the file's own function, not the library's.
    fn defined_function_names(root: &Node, source: &str) -> HashSet<String> {
        let mut found = HashSet::new();
        let mut stack = vec![*root];
        while let Some(scope) = stack.pop() {
            for item in scope.named_child_nodes() {
                match item.kind() {
                    "function_definition" => {
                        if let Some(name) =
                            lang_parsing_substrate::calls::get_function_name(item, source)
                        {
                            if ALLOCATORS.iter().any(|(a, _)| *a == name) {
                                found.insert(name);
                            }
                        }
                    }
                    kind if kind.starts_with("preproc_") => stack.push(item),
                    _ => {}
                }
            }
        }
        found
    }

    /// Function-like macros, the project's and the file's (the file's own
    /// winning), whose expansion calls an allocator with a size argument
    /// that reads one of the macro's parameters: `#define xmalloc(n)
    /// malloc(n)`, `#define ALLOC_N(T, n) malloc(sizeof(T) * (n))`.
    fn allocator_wrappers(&self, node: &Node, source: &str) -> HashMap<String, Wrapper> {
        let mut table = HashMap::clone(&self.function_macros.borrow());
        table.extend(macro_expand::collect_function_macros(node, source));
        let mut wrappers = HashMap::new();
        for (name, def) in &table {
            if ALLOCATORS.iter().any(|(a, _)| a == name) || def.params.is_empty() {
                continue;
            }
            let placeholders: Vec<String> = (0..def.params.len()).map(placeholder).collect();
            let Some(expansion) = macro_expand::expand_invocation(&table, name, &placeholders)
            else {
                continue;
            };
            if let Some(found) = Self::allocator_in_expansion(&expansion) {
                wrappers.insert(name.clone(), found);
            }
        }
        wrappers
    }

    /// The first allocator call in `expansion` one of whose size arguments
    /// reads a placeholder, with every size argument it passes.
    fn allocator_in_expansion(expansion: &str) -> Option<Wrapper> {
        let bytes = expansion.as_bytes();
        let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
        for (allocator, sizes) in ALLOCATORS {
            let mut from = 0;
            while let Some(pos) = expansion[from..].find(allocator) {
                let start = from + pos;
                let end = start + allocator.len();
                from = end;
                if (start > 0 && is_ident(bytes[start - 1]))
                    || (end < bytes.len() && is_ident(bytes[end]))
                {
                    continue;
                }
                let rest = expansion[end..].trim_start();
                let Some(args) = rest.strip_prefix('(') else {
                    continue;
                };
                // Split the argument list at top-level commas.
                let mut depth = 0usize;
                let mut parts = vec![String::new()];
                for c in args.chars() {
                    match c {
                        '(' => depth += 1,
                        ')' if depth == 0 => break,
                        ')' => depth -= 1,
                        ',' if depth == 0 => {
                            parts.push(String::new());
                            continue;
                        }
                        _ => {}
                    }
                    if let Some(last) = parts.last_mut() {
                        last.push(c);
                    }
                }
                let size_args: Vec<String> = sizes
                    .iter()
                    .filter_map(|&i| parts.get(i).map(|p| p.trim().to_string()))
                    .collect();
                if size_args.len() == sizes.len()
                    && size_args.iter().any(|a| a.contains("__mem04_arg"))
                {
                    return Some(Wrapper {
                        allocator,
                        sizes: size_args,
                    });
                }
            }
        }
        None
    }
}
