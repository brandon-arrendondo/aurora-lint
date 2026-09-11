//! MEM03-C: Clear sensitive information stored in reusable resources
//!
//! This rule detects free() or realloc() calls on memory that may contain
//! sensitive data without first clearing the memory with memset/memset_s.
//!
//! VIOLATIONS:
//! - free(ptr) without prior memset/memset_s/explicit_bzero to clear memory
//! - realloc(ptr, size) - old memory may not be cleared before being freed
//!
//! COMPLIANT:
//! - memset/memset_s/explicit_bzero called before free()
//! - Using calloc() for new allocations (initializes to zero)
//! - A project's own clearing wrapper (mbedtls_platform_zeroize,
//!   forced_memzero, an os_memset macro) -- recognised by what its body
//!   does with the buffer, never by its name

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval;
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::call_roles;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tree_sitter::Node;

#[derive(Default)]
pub struct Mem03C {
    /// Cross-file summaries: a callee whose `clears_params` names an
    /// argument position overwrites that buffer, whatever it is called
    /// (task 1127).
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    /// Function-like macros, for `macro_clears_param_indices`.
    function_macros: RefCell<HashMap<String, FunctionMacro>>,
    /// `#define ALIAS target` map; a callee is classified by the name its
    /// alias chain ends at.
    project_aliases: RefCell<HashMap<String, String>>,
}

impl CertRule for Mem03C {
    fn rule_id(&self) -> &'static str {
        "MEM03-C"
    }

    fn description(&self) -> &'static str {
        "Clear sensitive information stored in reusable resources"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MEM03-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.function_macros.borrow_mut() = context.function_macros.clone();
        *self.project_aliases.borrow_mut() = context.macro_aliases.clone();
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Mem03C {
    pub fn new() -> Self {
        Self::default()
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let aliases =
            const_eval::merged_macro_aliases(&self.project_aliases.borrow(), node, source);
        // Check function definitions for free/realloc patterns
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function(&func, source, &aliases, violations);
        }
    }

    /// The argument positions a call to `spelled_name` overwrites, or an
    /// empty list when it clears nothing the rule can see. Three sources, in
    /// order: a library clearer by (alias-resolved) name, first argument; a
    /// function-like macro whose expansion clears its parameter
    /// (`macro_clears_param_indices`); a function whose summary says its
    /// body clears the parameter (`clears_params`) -- the fact that makes
    /// mbedtls's `mbedtls_platform_zeroize` a clearer without anyone naming
    /// it (task 1127).
    fn cleared_arg_indices(
        &self,
        spelled_name: &str,
        aliases: &HashMap<String, String>,
    ) -> Vec<usize> {
        let name = const_eval::resolve_macro_alias(aliases, spelled_name);
        if call_roles::is_memory_clearing_call(name) {
            return vec![0];
        }
        let macros = self.function_macros.borrow();
        let via_macro = macro_expand::macro_clears_param_indices(&macros, spelled_name);
        if !via_macro.is_empty() {
            return via_macro;
        }
        self.function_summaries
            .borrow()
            .get(name)
            .map(|s| {
                let mut v: Vec<usize> = s.clears_params.iter().copied().collect();
                v.sort_unstable();
                v
            })
            .unwrap_or_default()
    }

    /// Base pointers of the arguments a clearing call overwrites, or `None`
    /// when `call` clears nothing.
    fn cleared_base_ptrs(
        &self,
        call: &Node,
        source: &str,
        aliases: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        let func = call.child_by_field_name("function")?;
        let indices = self.cleared_arg_indices(get_node_text(&func, source), aliases);
        if indices.is_empty() {
            return None;
        }
        let args = call.child_by_field_name("arguments")?;
        let real: Vec<Node> = (0..args.child_count())
            .filter_map(|i| args.child(i))
            .filter(|a| !matches!(a.kind(), "(" | ")" | ","))
            .collect();
        let ptrs: Vec<String> = indices
            .iter()
            .filter_map(|&i| real.get(i))
            .map(|a| self.extract_base_ptr(a, source))
            .collect();
        (!ptrs.is_empty()).then_some(ptrs)
    }

    fn check_function(
        &self,
        node: &Node,
        source: &str,
        aliases: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get compound statement (function body)
        if let Some(body) = node.child_by_field_name("body") {
            self.analyze_block(&body, source, aliases, violations, HashSet::new());

            // CWE-226: check for sensitive data buffers not cleared before function exit
            self.check_sensitive_data_cleanup(&body, source, aliases, violations);
        }
    }

    /// Track which pointers have been cleared (memset/memset_s/etc.) before a
    /// free()/realloc() call, per branch.
    ///
    /// Uses an explicit continuation-frame stack instead of recursion:
    /// analyze_block/process_statement used to mutually recurse through
    /// every nested block and if/while/for body, and a chain of deeply
    /// nested braces (or an obfuscated/generated deep block nesting) would
    /// cost one native call frame per level -- the same hostap-style risk
    /// class as the original ARR00-C/MEM33-C bug (task 153).
    ///
    /// Each frame is `(container, next_child_index, cleared)`, mirroring
    /// where a native recursive call would resume the sibling loop, and
    /// `cleared` is an `Rc<RefCell<..>>` handle so branch-sensitive state
    /// still forks (and is discarded, never merged back) exactly like the
    /// original `cleared_ptrs.clone()` per if/while/for body: a bare nested
    /// compound_statement shares the *same* handle (mutations are visible
    /// to later siblings, matching the original `&mut` threading), while
    /// each if/while/for branch gets an independent clone.
    fn analyze_block(
        &self,
        root: &Node,
        source: &str,
        aliases: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
        initial_cleared: HashSet<String>,
    ) {
        type Cleared = Rc<RefCell<HashSet<String>>>;
        let mut frames: Vec<(Node, usize, Cleared)> =
            vec![(*root, 0, Rc::new(RefCell::new(initial_cleared)))];

        while let Some((container, start_idx, cleared)) = frames.pop() {
            let mut i = start_idx;
            while i < container.child_count() {
                let Some(stmt) = container.child(i) else {
                    i += 1;
                    continue;
                };
                let kind = stmt.kind();

                // Check for memset/memset_s calls (clear operations)
                if kind == "expression_statement" {
                    if let Some(ptrs) = self.get_clear_call_ptrs(&stmt, source, aliases) {
                        cleared.borrow_mut().extend(ptrs);
                    }
                }

                // Check for free() calls without prior clearing. Only
                // plausibly-sensitive buffers are in scope (task 317): this
                // rule previously fired on every free() regardless of what
                // the pointer held, which made it explode once macro-wrapped
                // frees were recognized (any project's dominant free-wrapper
                // macro, e.g. hostap's os_free at 3800+ call sites, would
                // have multiplied an already-unfocused rule).
                if kind == "expression_statement" {
                    if let Some(ptr) = self.get_free_ptr(&stmt, source) {
                        if Self::is_sensitive_name(&ptr) && !cleared.borrow().contains(&ptr) {
                            let pos = stmt.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "Pointer '{}' freed without clearing sensitive data first",
                                    ptr
                                ),
                                file_path: String::new(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                                suggestion: Some(format!(
                                    "Add 'memset({}, 0, size);' before free({}) to clear sensitive data",
                                    ptr, ptr
                                )),
                                ..Default::default()
                            });
                        }
                    }
                }

                // Check for realloc() calls on plausibly-sensitive buffers
                // (same sensitivity gate as the free() check above).
                if kind == "expression_statement"
                    || kind == "declaration"
                    || kind == "init_declarator"
                {
                    if let Some(ptr) = self.get_realloc_ptr(&stmt, source) {
                        if Self::is_sensitive_name(&ptr) && !cleared.borrow().contains(&ptr) {
                            let pos = stmt.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::Medium,
                                message: format!(
                                    "realloc() on '{}' may leak sensitive data from old memory",
                                    ptr
                                ),
                                file_path: String::new(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                                suggestion: Some(
                                    "Consider allocating new memory, copying, clearing old, then freeing"
                                        .to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }

                // Queue nested blocks: resume this container at i + 1 once
                // the nested work is fully drained.
                if kind == "compound_statement" {
                    frames.push((container, i + 1, Rc::clone(&cleared)));
                    frames.push((stmt, 0, Rc::clone(&cleared)));
                    break;
                } else if kind == "if_statement"
                    || kind == "while_statement"
                    || kind == "for_statement"
                {
                    frames.push((container, i + 1, Rc::clone(&cleared)));
                    // Fork an independent, throwaway clone per branch body,
                    // pushed in reverse so they drain in original document
                    // order before this container resumes.
                    for j in (0..stmt.child_count()).rev() {
                        if let Some(child) = stmt.child(j) {
                            if child.kind() == "compound_statement" {
                                let forked = Rc::new(RefCell::new(cleared.borrow().clone()));
                                frames.push((child, 0, forked));
                            }
                        }
                    }
                    break;
                }
                i += 1;
            }
        }
    }

    /// Base pointers cleared by a call directly under `node` (an expression
    /// statement), if any.
    fn get_clear_call_ptrs(
        &self,
        node: &Node,
        source: &str,
        aliases: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "call_expression" {
                    if let Some(ptrs) = self.cleared_base_ptrs(&child, source, aliases) {
                        return Some(ptrs);
                    }
                }
            }
        }
        None
    }

    fn extract_base_ptr(&self, node: &Node, source: &str) -> String {
        // Handle cast_expression like (volatile char *)ptr
        if node.kind() == "cast_expression" {
            // Find the value being cast (typically the last child that's not type_descriptor)
            for i in (0..node.child_count()).rev() {
                if let Some(child) = node.child(i) {
                    let kind = child.kind();
                    if kind != "type_descriptor" && kind != "(" && kind != ")" {
                        return self.extract_base_ptr(&child, source);
                    }
                }
            }
        }
        // Base case: identifier or other expression
        get_node_text(node, source).to_string()
    }

    fn get_free_ptr(&self, node: &Node, source: &str) -> Option<String> {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "call_expression" {
                    if let Some(func) = child.child_by_field_name("function") {
                        let func_name = get_node_text(&func, source);
                        if func_name == "free" {
                            if let Some(args) = child.child_by_field_name("arguments") {
                                for j in 0..args.child_count() {
                                    if let Some(arg) = args.child(j) {
                                        if arg.kind() != "("
                                            && arg.kind() != ")"
                                            && arg.kind() != ","
                                        {
                                            return Some(get_node_text(&arg, source).to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn get_realloc_ptr(&self, node: &Node, source: &str) -> Option<String> {
        // Find realloc call and return the pointer being reallocated
        self.find_realloc_in_node(node, source)
    }

    fn find_realloc_in_node(&self, node: &Node, source: &str) -> Option<String> {
        let call = query::find_first_descendant(*node, |n| {
            n.kind() == "call_expression"
                && n.child_by_field_name("function")
                    .map(|func| get_node_text(&func, source) == "realloc")
                    .unwrap_or(false)
        })?;

        // Get first argument (pointer being reallocated)
        let args = call.child_by_field_name("arguments")?;
        for j in 0..args.child_count() {
            if let Some(arg) = args.child(j) {
                if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                    return Some(get_node_text(&arg, source).to_string());
                }
            }
        }
        None
    }

    // ── CWE-226: Sensitive data not cleared before release ──────────────────

    const SENSITIVE_NAMES: &'static [&'static str] =
        &["password", "passwd", "secret", "credential", "passphrase"];

    /// Does `name` (a pointer expression, e.g. `p`, `ctx->key`) look like it
    /// might hold sensitive data? Matches on the same name list as
    /// [`Self::check_sensitive_data_cleanup`] so the free()/realloc() checks
    /// in `analyze_block` and the scope-exit check agree on what counts as
    /// "sensitive" (task 317).
    fn is_sensitive_name(name: &str) -> bool {
        let lower = name.to_lowercase();
        Self::SENSITIVE_NAMES.iter().any(|n| lower.contains(n))
    }

    /// Check if sensitive-named buffers are cleared before function exit
    fn check_sensitive_data_cleanup(
        &self,
        body: &Node,
        source: &str,
        aliases: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut sensitive_vars: Vec<(String, usize, usize)> = Vec::new();
        let mut cleared_vars: HashSet<String> = HashSet::new();

        self.scan_sensitive_vars_and_clears(
            body,
            source,
            aliases,
            &mut sensitive_vars,
            &mut cleared_vars,
        );

        for (var_name, line, col) in &sensitive_vars {
            if !cleared_vars.contains(var_name) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Sensitive buffer '{}' not cleared before function exit",
                        var_name
                    ),
                    file_path: String::new(),
                    line: *line,
                    column: *col,
                    suggestion: Some(format!(
                        "Call SecureZeroMemory({0}, size) or memset({0}, 0, size) before the buffer goes out of scope",
                        var_name
                    )),
                    ..Default::default()
                });
            }
        }
    }

    fn scan_sensitive_vars_and_clears(
        &self,
        node: &Node,
        source: &str,
        aliases: &HashMap<String, String>,
        sensitive_vars: &mut Vec<(String, usize, usize)>,
        cleared_vars: &mut HashSet<String>,
    ) {
        for node in query::find_descendants_of_kinds(*node, &["declaration", "call_expression"]) {
            match node.kind() {
                "declaration" => {
                    // Check for sensitive-named pointer/array declarations (buffers only)
                    let decl_text = get_node_text(&node, source);
                    let decl_lower = decl_text.to_lowercase();
                    // Must be a buffer type (pointer or array), not a scalar like size_t
                    let is_buffer = decl_text.contains('*') || decl_text.contains('[');
                    if is_buffer {
                        for name in Self::SENSITIVE_NAMES {
                            if decl_lower.contains(name) {
                                if let Some(var_name) = self.extract_decl_var_name(&node, source) {
                                    let lower = var_name.to_lowercase();
                                    if Self::SENSITIVE_NAMES.iter().any(|n| lower.contains(n)) {
                                        sensitive_vars.push((
                                            var_name,
                                            node.start_position().row + 1,
                                            node.start_position().column + 1,
                                        ));
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
                "call_expression" => {
                    // Check for clearing functions
                    if let Some(ptrs) = self.cleared_base_ptrs(&node, source, aliases) {
                        cleared_vars.extend(ptrs);
                    }
                }
                _ => {}
            }
        }
    }

    fn extract_decl_var_name(&self, decl: &Node, source: &str) -> Option<String> {
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                match child.kind() {
                    "init_declarator" => {
                        if let Some(declarator) = child.child_by_field_name("declarator") {
                            return self.find_identifier_in(&declarator, source);
                        }
                    }
                    "pointer_declarator" | "array_declarator" | "identifier" => {
                        return self.find_identifier_in(&child, source);
                    }
                    _ => {}
                }
            }
        }
        None
    }

    fn find_identifier_in(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.find_identifier_in(&child, source) {
                    return Some(name);
                }
            }
        }
        None
    }
}
