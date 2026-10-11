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
//! included), `sizeof`, `strlen(s) + 1`, a product whose every factor is
//! proven, or a condition known to hold at the call that excludes zero
//! (`if (n == 0) return NULL;`, `n > 0`, `!(n < 1)`;
//! `nonzero_facts::known_conditions`). `n * sizeof(T)` is not exempt: `n`
//! still needs its proof.
//!
//! An allocator is a call to the library function: a name the file defines
//! itself, or a local or parameter spelled the same, is not one. A
//! function-like macro whose expansion passes one of its parameters as an
//! allocator's size is an allocation too, at that argument.

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
    /// Function-like macros that wrap an allocator: the allocator and the
    /// macro parameters it receives as sizes.
    wrappers: HashMap<String, (&'static str, Vec<usize>)>,
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
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let Some((allocator, sizes)) = Self::allocation_at(&call, source, &facts) else {
                continue;
            };
            let Some(args) = call.child_by_field_name("arguments") else {
                continue;
            };
            let args: Vec<Node> = args
                .named_child_nodes()
                .filter(|a| a.kind() != "comment")
                .collect();
            for &i in &sizes {
                let Some(size) = args.get(i) else {
                    continue;
                };
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
    fn allocation_at(
        call: &Node,
        source: &str,
        facts: &FileFacts,
    ) -> Option<(&'static str, Vec<usize>)> {
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
            return Some((allocator, sizes.to_vec()));
        }
        facts.wrappers.get(name).cloned()
    }

    /// The message for `size`, the size argument of a call to `allocator`,
    /// or `None` when it is not reported.
    fn finding(
        &self,
        allocator: &str,
        call: &Node,
        size: &Node,
        source: &str,
        facts: &FileFacts,
        risky_vars: &mut HashMap<usize, HashSet<String>>,
    ) -> Option<String> {
        let size_text = get_node_text(size, source);
        if const_eval::try_evaluate_expr(size, source, &facts.macros) == Some(0) {
            return Some(format!(
                "{}() is called with a size of zero: the result of a zero-length \
                 allocation is implementation-defined and may not be accessed",
                allocator
            ));
        }
        if Self::proven_nonzero(size, call, source, facts) {
            return None;
        }
        if allocator == "realloc" {
            return Some(format!(
                "realloc() size '{}' is not proven non-zero: realloc(p, 0) may free p and \
                 return a null pointer (implementation-defined in C17, undefined in C23)",
                size_text
            ));
        }
        if self.reads_input_or_parameter(size, call, source, risky_vars) {
            return Some(format!(
                "{}() size '{}' comes from input or a parameter and nothing in the \
                 function proves it non-zero: a zero-length allocation's result is \
                 implementation-defined",
                allocator, size_text
            ));
        }
        None
    }

    /// Whether `expr` is proven non-zero where `site` executes: a non-zero
    /// constant, `sizeof`, `strlen(s) + c` with `c > 0`, a product or a `?:`
    /// whose every operand is proven, or a condition known there excluding
    /// zero.
    fn proven_nonzero(expr: &Node, site: &Node, source: &str, facts: &FileFacts) -> bool {
        if let Some(v) = const_eval::try_evaluate_expr(expr, source, &facts.macros) {
            return v != 0;
        }
        match expr.kind() {
            "sizeof_expression" | "alignof_expression" => return true,
            "parenthesized_expression" => {
                if let Some(inner) = expr.named_child(0) {
                    return Self::proven_nonzero(&inner, site, source, facts);
                }
            }
            "cast_expression" => {
                if let Some(value) = expr.child_by_field_name("value") {
                    if Self::proven_nonzero(&value, site, source, facts) {
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
                    if Self::proven_nonzero(&a, site, source, facts)
                        && Self::proven_nonzero(&b, site, source, facts)
                    {
                        return true;
                    }
                }
            }
            "binary_expression" => {
                let op = ast_utils::get_binary_operator(expr, source).unwrap_or_default();
                let (Some(left), Some(right)) = (
                    expr.child_by_field_name("left"),
                    expr.child_by_field_name("right"),
                ) else {
                    return false;
                };
                if op == "*"
                    && Self::proven_nonzero(&left, site, source, facts)
                    && Self::proven_nonzero(&right, site, source, facts)
                {
                    return true;
                }
                if op == "+" {
                    let positive = |n: &Node| {
                        const_eval::try_evaluate_expr(n, source, &facts.macros)
                            .is_some_and(|v| v > 0)
                    };
                    if (Self::is_string_length(&left, source) && positive(&right))
                        || (Self::is_string_length(&right, source) && positive(&left))
                    {
                        return true;
                    }
                }
            }
            _ => {}
        }
        let targets = nonzero_facts::peeled_spellings(expr, source);
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
    /// winning), whose expansion calls an allocator with one of the macro's
    /// parameters, alone, as a size argument: `#define xmalloc(n) malloc(n)`.
    fn allocator_wrappers(
        &self,
        node: &Node,
        source: &str,
    ) -> HashMap<String, (&'static str, Vec<usize>)> {
        let mut table = HashMap::clone(&self.function_macros.borrow());
        table.extend(macro_expand::collect_function_macros(node, source));
        let mut wrappers = HashMap::new();
        for (name, def) in &table {
            if ALLOCATORS.iter().any(|(a, _)| a == name) || def.params.is_empty() {
                continue;
            }
            let placeholders: Vec<String> = (0..def.params.len())
                .map(|i| format!("__mem04_arg{}__", i))
                .collect();
            let Some(expansion) = macro_expand::expand_invocation(&table, name, &placeholders)
            else {
                continue;
            };
            if let Some(found) = Self::allocator_in_expansion(&expansion, &placeholders) {
                wrappers.insert(name.clone(), found);
            }
        }
        wrappers
    }

    /// The first allocator call in `expansion` one of whose size arguments
    /// is, parentheses aside, exactly one of `placeholders`: the allocator,
    /// and the placeholders' indices.
    fn allocator_in_expansion(
        expansion: &str,
        placeholders: &[String],
    ) -> Option<(&'static str, Vec<usize>)> {
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
                let indices: Vec<usize> = sizes
                    .iter()
                    .filter_map(|&i| {
                        let arg: String = parts
                            .get(i)?
                            .chars()
                            .filter(|c| !c.is_whitespace() && *c != '(' && *c != ')')
                            .collect();
                        placeholders.iter().position(|p| *p == arg)
                    })
                    .collect();
                if !indices.is_empty() {
                    return Some((allocator, indices));
                }
            }
        }
        None
    }
}
