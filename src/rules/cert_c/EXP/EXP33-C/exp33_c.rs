//! EXP33-C: Do not read uninitialized memory
//!
//! Detects reads of local variables that may not have been initialized.
//! Uses CFG-based forward dataflow analysis to track initialization state
//! across branches, loops, and early returns.

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::{self as cfg_mod, FunctionCfg};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::init_state::{self, InitAnalysisResult, InitState, InitStateMap};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Exp33C {
    function_cfgs: RefCell<HashMap<usize, FunctionCfg>>,
    /// File-scope static variable init states (collected at translation_unit level).
    file_scope_statics: RefCell<InitStateMap>,
    /// Functions that return realloc results (interprocedural pre-scan).
    realloc_wrapper_fns: RefCell<HashSet<String>>,
    /// Functions with pointer params that are only conditionally initialized.
    /// Maps function name → set of pointer parameter indices that are conditional.
    conditionally_init_fns: RefCell<HashMap<String, HashSet<usize>>>,
    /// Cross-file function summaries from prescan (for inter-procedural init tracking).
    cross_file_summaries: RefCell<HashMap<String, FunctionSummary>>,
    /// File-scope constants for dead-branch elimination in init-state analysis.
    file_scope_constants: RefCell<HashMap<String, i64>>,
    /// Cross-file function-like macro definitions (from the prescan / macro
    /// engine). Used to recognize macro output arguments (e.g. `CF_DATA_SAVE`).
    function_macros: RefCell<HashMap<String, crate::analyze::macro_expand::FunctionMacro>>,
    /// Output-parameter indices for macros actually invoked in the current file
    /// (computed once per file from `function_macros`). Feeds the init-state
    /// transfer and the read-checker so macro-written args are not flagged.
    macro_output_params: RefCell<HashMap<String, Vec<usize>>>,
}

impl Exp33C {
    pub fn new() -> Self {
        Self {
            function_cfgs: RefCell::new(HashMap::new()),
            file_scope_statics: RefCell::new(InitStateMap::new()),
            realloc_wrapper_fns: RefCell::new(HashSet::new()),
            conditionally_init_fns: RefCell::new(HashMap::new()),
            cross_file_summaries: RefCell::new(HashMap::new()),
            file_scope_constants: RefCell::new(HashMap::new()),
            function_macros: RefCell::new(HashMap::new()),
            macro_output_params: RefCell::new(HashMap::new()),
        }
    }

    /// Build the read-only dereference map from cross-file summaries.
    /// Returns functions that dereference a pointer param without modifying it.
    fn build_read_only_deref_fns(&self) -> HashMap<String, HashSet<usize>> {
        let summaries = self.cross_file_summaries.borrow();
        let mut result = HashMap::new();
        for (name, summary) in summaries.iter() {
            let read_only: HashSet<usize> = summary
                .dereferences_params
                .difference(&summary.modifies_params)
                .copied()
                .collect();
            if !read_only.is_empty() {
                result.insert(name.clone(), read_only);
            }
        }
        result
    }
}

impl CertRule for Exp33C {
    fn rule_id(&self) -> &'static str {
        "EXP33-C"
    }

    fn description(&self) -> &'static str {
        "Do not read uninitialized memory"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP33-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.cross_file_summaries.borrow_mut() = context.function_summaries.clone();
        // Merge prescan global constants into file-scope constants.
        // File-scope constants (set later during check()) take precedence.
        let mut constants = self.file_scope_constants.borrow_mut();
        for (k, v) in &context.global_constants {
            constants.entry(k.clone()).or_insert(*v);
        }
        // Also include prescan macro constants (from #define directives)
        for (k, v) in &context.macro_constants {
            constants.entry(k.clone()).or_insert(*v);
        }
        drop(constants);
        // Function-like macro definitions (for macro output-arg recognition).
        *self.function_macros.borrow_mut() = context.function_macros.clone();
    }

    fn set_function_cfgs(&self, cfgs: &HashMap<usize, FunctionCfg>) {
        *self.function_cfgs.borrow_mut() = cfgs.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let cfgs = self.function_cfgs.borrow();

        for n in
            query::find_descendants_of_kinds(*node, &["translation_unit", "function_definition"])
        {
            let node = &n;
            // At translation_unit level: collect file-scope statics and pre-scan functions
            if node.kind() == "translation_unit" {
                let statics = init_state::collect_file_scope_statics(node, source);
                *self.file_scope_statics.borrow_mut() = statics;

                // Collect file-scope constants for dead-branch elimination.
                // Merge with prescan global constants (file-scope wins on conflict).
                let file_constants = init_state::collect_file_scope_constants(node, source);
                // Also collect zero-arg constant-return functions (e.g., staticReturnsTrue()).
                let fn_constants = init_state::collect_constant_functions(node, source);
                {
                    let mut constants = self.file_scope_constants.borrow_mut();
                    // File-scope constants and constant functions override prescan globals
                    constants.extend(file_constants);
                    constants.extend(fn_constants);
                }

                // Pre-scan for realloc wrapper functions
                let mut wrappers = HashSet::new();
                scan_realloc_wrappers(node, source, &mut wrappers);
                *self.realloc_wrapper_fns.borrow_mut() = wrappers;

                // Pre-scan for functions that conditionally initialize pointer params
                let mut cond_init = HashMap::new();
                scan_conditionally_init_functions(node, source, &mut cond_init);
                *self.conditionally_init_fns.borrow_mut() = cond_init;

                // Precompute output-parameter indices for the function-like macros
                // actually invoked in this file (cheap: only invoked names, once per
                // file). Macros whose body assigns a parameter (e.g. CF_DATA_SAVE)
                // write that argument — feeds the init-state transfer + read-checker.
                let macros = self.function_macros.borrow();
                if !macros.is_empty() {
                    let mut invoked = HashSet::new();
                    collect_invoked_macro_names(node, source, &macros, &mut invoked);
                    let mut out_params = HashMap::new();
                    for name in invoked {
                        let idx = crate::analyze::macro_expand::macro_output_param_indices(
                            &macros, &name,
                        );
                        if !idx.is_empty() {
                            out_params.insert(name, idx);
                        }
                    }
                    *self.macro_output_params.borrow_mut() = out_params;
                }
            }

            if node.kind() == "function_definition" {
                if let Some(body) = node.child_by_field_name("body") {
                    // Get pre-built CFG or build one on the fly
                    let inline_cfg;
                    let cfg = if let Some(c) = cfgs.get(&node.start_byte()) {
                        c
                    } else if let Some(c) = cfg_mod::build_function_cfg(node, source) {
                        inline_cfg = c;
                        &inline_cfg
                    } else {
                        continue;
                    };

                    // Run CFG-based init-state dataflow
                    let statics = self.file_scope_statics.borrow();
                    let cond_fns = self.conditionally_init_fns.borrow();
                    let realloc_fns = self.realloc_wrapper_fns.borrow();
                    let read_only_fns = self.build_read_only_deref_fns();
                    let file_constants = self.file_scope_constants.borrow();
                    let macro_out = self.macro_output_params.borrow();
                    let config = init_state::InitAnalysisConfig {
                        conditionally_init_fns: cond_fns.clone(),
                        realloc_wrapper_fns: realloc_fns.clone(),
                        read_only_deref_fns: read_only_fns.clone(),
                        file_scope_constants: file_constants.clone(),
                        macro_output_params: macro_out.clone(),
                    };
                    let analysis = init_state::analyze_init_states_with_statics(
                        cfg, node, source, &statics, &config,
                    );

                    // Walk AST for read sites and check each against dataflow result
                    let mut reported: HashSet<String> = HashSet::new();
                    check_reads(
                        &body,
                        source,
                        &analysis,
                        cfg,
                        &body,
                        &mut violations,
                        &mut reported,
                        &config,
                    );

                    // Check for cross-file calls passing &uninit_var to functions
                    // that read through the pointer (variant 63/64 pattern).
                    if !read_only_fns.is_empty() {
                        check_cross_file_uninit_calls(
                            &body,
                            source,
                            &analysis,
                            cfg,
                            &body,
                            &read_only_fns,
                            &mut violations,
                            &mut reported,
                        );
                    }
                }
            }
        }

        violations
    }
}

// ---------------------------------------------------------------------------
// AST walk for read sites
// ---------------------------------------------------------------------------

/// Walk the AST looking for reads of tracked variables.
fn check_reads(
    node: &Node,
    source: &str,
    analysis: &InitAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    violations: &mut Vec<RuleViolation>,
    reported: &mut HashSet<String>,
    config: &init_state::InitAnalysisConfig,
) {
    for n in query::find_descendants_of_kinds(
        *node,
        &["identifier", "pointer_expression", "subscript_expression"],
    ) {
        match n.kind() {
            "identifier" => {
                check_identifier_read(
                    &n, source, analysis, cfg, body, violations, reported, config,
                );
            }
            "pointer_expression" => {
                // *ptr — check if ptr content is uninitialized
                let text = get_node_text(&n, source);
                if text.starts_with('*') {
                    check_deref_read(
                        &n, source, analysis, cfg, body, violations, reported, config,
                    );
                }
            }
            "subscript_expression" => {
                check_subscript_read(
                    &n, source, analysis, cfg, body, violations, reported, config,
                );
            }
            _ => {}
        }
    }
}

/// Collect the names of function-like macros (present in `macros`) that are
/// invoked as `call_expression`s anywhere under `node`. Used to limit the
/// (slightly costly) output-param computation to macros actually used in the
/// file, rather than the whole cross-file macro table.
fn collect_invoked_macro_names(
    node: &Node,
    source: &str,
    macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
    out: &mut HashSet<String>,
) {
    for call in query::find_descendants_of_kind(*node, "call_expression") {
        if let Some(func) = call.child_by_field_name("function") {
            if func.kind() == "identifier" {
                let name = get_node_text(&func, source);
                if macros.contains_key(name) {
                    out.insert(name.to_string());
                }
            }
        }
    }
}

/// True if `node` is a bare-identifier argument occupying an *output* position
/// (per `macro_output_params`) of a function-like macro invocation — i.e. the
/// macro writes this argument, so reading it there is not a use of an
/// uninitialized value. Mirrors `macro_semantics::is_macro_output_arg` for
/// expansion-derived (rather than registry) macros.
fn is_function_macro_output_arg(
    node: &Node,
    source: &str,
    macro_output_params: &HashMap<String, Vec<usize>>,
) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    // identifier -> argument_list -> call_expression
    let arg_list = match node.parent() {
        Some(p) if p.kind() == "argument_list" => p,
        _ => return false,
    };
    let call = match arg_list.parent() {
        Some(c) if c.kind() == "call_expression" => c,
        _ => return false,
    };
    let func_name = match call.child_by_field_name("function") {
        Some(f) => get_node_text(&f, source),
        None => return false,
    };
    let out_indices = match macro_output_params.get(func_name) {
        Some(v) => v,
        None => return false,
    };
    let args = crate::analyze::macro_semantics::positional_args(&call);
    let target = node.id();
    for (pos, arg) in args.into_iter().enumerate() {
        if arg.id() == target {
            return out_indices.contains(&pos);
        }
    }
    false
}

/// Check for calls that pass `&uninit_var` to cross-file functions that read
/// through the pointer without writing first (variant 63/64 pattern).
fn check_cross_file_uninit_calls(
    node: &Node,
    source: &str,
    analysis: &InitAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    read_only_fns: &HashMap<String, HashSet<usize>>,
    violations: &mut Vec<RuleViolation>,
    reported: &mut HashSet<String>,
) {
    for call in query::find_descendants_of_kind(*node, "call_expression") {
        if let Some(func) = call.child_by_field_name("function") {
            let func_name = get_node_text(&func, source).to_string();
            if let Some(read_only_params) = read_only_fns.get(&func_name) {
                if let Some(args) = call.child_by_field_name("arguments") {
                    let mut arg_idx: usize = 0;
                    for i in 0..args.child_count() {
                        if let Some(arg) = args.child(i) {
                            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                                continue;
                            }
                            if read_only_params.contains(&arg_idx) {
                                // Check if arg is &var where var is uninitialized
                                let var_name = extract_addr_of_var(&arg, source);
                                if !var_name.is_empty()
                                    && analysis.tracked_vars.contains(&var_name)
                                    && !reported.contains(&var_name)
                                {
                                    if let Some(info) = init_state::get_var_info_at_with_config(
                                        analysis,
                                        cfg,
                                        body,
                                        source,
                                        &var_name,
                                        call.start_byte(),
                                        &init_state::InitAnalysisConfig::default(),
                                    ) {
                                        if info.state.is_unsafe() && !info.is_unsigned_char {
                                            reported.insert(var_name.clone());
                                            violations.push(RuleViolation {
                                                rule_id: "EXP33-C".to_string(),
                                                severity: Severity::High,
                                                message: format!(
                                                    "Passing pointer to uninitialized variable '{}' to '{}' which reads the value",
                                                    var_name, func_name
                                                ),
                                                file_path: String::new(),
                                                line: call.start_position().row + 1,
                                                column: call.start_position().column + 1,
                                                suggestion: Some(format!(
                                                    "Initialize '{}' before passing its address to '{}'",
                                                    var_name, func_name
                                                )),
                                                ..Default::default()
                                            });
                                        }
                                    }
                                }
                            }
                            arg_idx += 1;
                        }
                    }
                }
            }
        }
    }
}

/// Extract the variable name from an `&var` expression. Returns empty string if not `&var`.
fn extract_addr_of_var(node: &Node, source: &str) -> String {
    // Direct &var: pointer_expression with & operator
    if node.kind() == "pointer_expression" {
        let text = get_node_text(node, source);
        if text.starts_with('&') {
            if let Some(arg) = node.child_by_field_name("argument") {
                if arg.kind() == "identifier" {
                    return get_node_text(&arg, source).to_string();
                }
            }
        }
    }
    // Parenthesized: (&var)
    if node.kind() == "parenthesized_expression" {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let result = extract_addr_of_var(&child, source);
                if !result.is_empty() {
                    return result;
                }
            }
        }
    }
    String::new()
}

/// Check if an identifier read is of an uninitialized variable.
fn check_identifier_read(
    node: &Node,
    source: &str,
    analysis: &InitAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    violations: &mut Vec<RuleViolation>,
    reported: &mut HashSet<String>,
    config: &init_state::InitAnalysisConfig,
) {
    let var_name = get_node_text(node, source).to_string();

    // Skip if not tracked
    if !analysis.tracked_vars.contains(&var_name) {
        return;
    }

    // Skip if already reported
    if reported.contains(&var_name) {
        return;
    }

    // Skip if this is NOT a read context
    if !is_read_context(node, source) {
        return;
    }

    // Skip identifiers that are the iterator/temp/out argument of a known
    // iterator/find macro (utlist/uthash/BSD-queue). The macro *writes* these
    // args, so their appearance in the invocation is not a use of an
    // uninitialized value. See crate::analyze::macro_semantics (Phase 1 of
    // docs/design/macro-expansion.md).
    if crate::analyze::macro_semantics::is_macro_output_arg(node, source) {
        return;
    }

    // Skip identifiers that are the *output* argument of a function-like macro
    // whose body assigns them (e.g. curl's `CF_DATA_SAVE(save, …)`). The macro
    // writes this arg, so its appearance in the invocation is not a read of an
    // uninitialized value. Phase 2c-ii of docs/design/macro-expansion.md.
    if is_function_macro_output_arg(node, source, &config.macro_output_params) {
        return;
    }

    // Query init state at this point

    let info = match init_state::get_var_info_at_with_config(
        analysis,
        cfg,
        body,
        source,
        &var_name,
        node.start_byte(),
        config,
    ) {
        Some(i) => i,
        None => return,
    };

    // EXP33-C exception: reading uninitialized unsigned char is permitted
    if info.is_unsigned_char {
        return;
    }

    // Only flag truly uninitialized or maybe-uninitialized reads
    if !info.state.is_unsafe() {
        return;
    }

    // Arrays passed by name to unknown function calls decay to pointers.
    // The init-state transfer function treats such arrays as initialized
    // (assumes the function writes to them). Skip the read-check here
    // for consistency, but only for truly unknown functions — not for
    // known read-only or known initializing functions (handled separately).
    if info.is_array {
        if let Some(parent) = node.parent() {
            // Array-to-pointer decay: `ptr = arr` where arr is on the RHS.
            // Taking the address of a non-char array is not a content read —
            // suppress and detect later at subscript access (check_subscript_read).
            // Char arrays are kept (strcat/wcscat pattern: reads the null terminator).
            if parent.kind() == "assignment_expression" && !info.is_char_type {
                if let Some(right) = parent.child_by_field_name("right") {
                    if right.id() == node.id() {
                        return;
                    }
                }
            }
            if parent.kind() == "argument_list" {
                if let Some(call_expr) = parent.parent() {
                    if call_expr.kind() == "call_expression" {
                        if let Some(func) = call_expr.child_by_field_name("function") {
                            let fname = get_node_text(&func, source).to_string();
                            // Known functions are already handled by is_read_in_argument_list.
                            // Only suppress for truly unknown functions (not non-initializing).
                            if init_state::match_initializing_function(&fname).is_none()
                                && !init_state::is_non_initializing_function(&fname)
                            {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    reported.insert(var_name.clone());

    let message = if info.is_static {
        format!(
            "Static variable '{}' used without explicit initialization",
            var_name
        )
    } else if matches!(info.state, InitState::MaybeUninitialized) {
        format!(
            "Variable '{}' may be used uninitialized (not assigned on all paths)",
            var_name
        )
    } else {
        format!("Variable '{}' is used uninitialized", var_name)
    };

    violations.push(RuleViolation {
        rule_id: "EXP33-C".to_string(),
        severity: Severity::High,
        message,
        file_path: String::new(),
        line: node.start_position().row + 1,
        column: node.start_position().column + 1,
        suggestion: Some(format!(
            "Initialize '{}' before use, e.g., at its declaration",
            var_name
        )),
        ..Default::default()
    });
}

/// Check if a dereference (*ptr) reads uninitialized content.
fn check_deref_read(
    node: &Node,
    source: &str,
    analysis: &InitAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    violations: &mut Vec<RuleViolation>,
    reported: &mut HashSet<String>,
    config: &init_state::InitAnalysisConfig,
) {
    // Extract the pointer variable being dereferenced
    let var_name = if let Some(arg) = node.child_by_field_name("argument") {
        if arg.kind() == "identifier" {
            get_node_text(&arg, source).to_string()
        } else {
            return;
        }
    } else {
        return;
    };

    if !analysis.tracked_vars.contains(&var_name) || reported.contains(&var_name) {
        return;
    }

    // Skip non-read contexts (e.g., *ptr = value is a write)
    if !is_deref_read_context(node) {
        return;
    }

    let info = match init_state::get_var_info_at_with_config(
        analysis,
        cfg,
        body,
        source,
        &var_name,
        node.start_byte(),
        config,
    ) {
        Some(i) => i,
        None => return,
    };

    // Check both pointer and content state
    if info.state.is_unsafe() {
        // Pointer itself is uninitialized
        reported.insert(var_name.clone());
        violations.push(RuleViolation {
            rule_id: "EXP33-C".to_string(),
            severity: Severity::High,
            message: format!("Dereference of uninitialized pointer '{}'", var_name),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(format!(
                "Initialize pointer '{}' before dereferencing",
                var_name
            )),
            ..Default::default()
        });
    } else if info.state.is_content_unsafe() {
        // Pointer is set but content is uninitialized (malloc without memset)
        reported.insert(var_name.clone());
        violations.push(RuleViolation {
            rule_id: "EXP33-C".to_string(),
            severity: Severity::High,
            message: format!(
                "Reading from '{}' which points to uninitialized memory (allocated without initialization)",
                var_name
            ),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(
                "Use calloc() instead of malloc(), or memset() after allocation".to_string(),
            ),
            ..Default::default()
        });
    }
}

/// Check if a subscript access (arr[i]) reads uninitialized content.
fn check_subscript_read(
    node: &Node,
    source: &str,
    analysis: &InitAnalysisResult,
    cfg: &FunctionCfg,
    body: &Node,
    violations: &mut Vec<RuleViolation>,
    reported: &mut HashSet<String>,
    config: &init_state::InitAnalysisConfig,
) {
    // Extract base variable (handles arr[i], arr->field[i], etc.)
    let var_name = {
        let mut name = String::new();
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    name = get_node_text(&child, source).to_string();
                    break;
                }
                // Handle arr->data[i] — subscript base is a field_expression
                if child.kind() == "field_expression" {
                    name = extract_root_identifier(&child, source);
                    break;
                }
            }
        }
        name
    };

    if var_name.is_empty()
        || !analysis.tracked_vars.contains(&var_name)
        || reported.contains(&var_name)
    {
        return;
    }

    // Skip non-read contexts
    if !is_subscript_read_context(node) {
        return;
    }

    let info = match init_state::get_var_info_at_with_config(
        analysis,
        cfg,
        body,
        source,
        &var_name,
        node.start_byte(),
        config,
    ) {
        Some(i) => i,
        None => return,
    };

    // EXP33-C exception: unsigned char content reads are permitted
    if info.is_unsigned_char {
        return;
    }

    // For subscript reads, only flag definitely-uninitialized content.
    // MaybeUninitialized often results from loop-based array initialization
    // where the loop join produces a conservative MaybeUninitialized.
    let content_unsafe = matches!(
        info.state,
        InitState::Uninitialized | InitState::MallocUninitialized
    );

    if content_unsafe {
        reported.insert(var_name.clone());
        violations.push(RuleViolation {
            rule_id: "EXP33-C".to_string(),
            severity: Severity::High,
            message: format!(
                "Reading from '{}' which may contain uninitialized data",
                var_name
            ),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(format!(
                "Initialize the contents of '{}' before reading",
                var_name
            )),
            ..Default::default()
        });
    }
}

// ---------------------------------------------------------------------------
// Read-context detection
// ---------------------------------------------------------------------------

/// Check if an identifier node is in a read context (not a write target).
/// True if `node` lies inside the argument subtree of a `call_expression` whose
/// callee is a GNU asm keyword (`asm`, `__asm`, `__asm__`, any case).
///
/// tree-sitter-c misparses the `__asm("..." : "=r"(v) ...)` call forms, and the
/// *shape* of that misparse differs across grammar versions (e.g. 0.21 nested
/// the output operand as `call_expression("=r", [v])`, while 0.24 collapses the
/// operands into an `ERROR`/`concatenated_string` that can even swallow the
/// following statement). Rather than match one specific broken shape, treat
/// every identifier inside such an asm-keyword call as asm-opaque — never a
/// genuine uninitialized read. Properly-parsed `__asm__` uses `gnu_asm_*` nodes
/// and is handled by the match in `is_read_context`.
fn is_in_asm_call(node: &Node, source: &str) -> bool {
    let mut cur = node.parent();
    while let Some(n) = cur {
        if n.kind() == "call_expression" {
            if let Some(func) = n.child_by_field_name("function") {
                if func.kind() == "identifier" {
                    let name = get_node_text(&func, source).to_ascii_lowercase();
                    if name == "asm" || name == "__asm" || name == "__asm__" {
                        return true;
                    }
                }
            }
        }
        // Bound the walk at the enclosing function.
        if n.kind() == "function_definition" {
            break;
        }
        cur = n.parent();
    }
    false
}

fn is_read_context(node: &Node, source: &str) -> bool {
    // GNU asm is opaque to uninitialized analysis, and tree-sitter-c misparses
    // the __asm(...) / __ASM(...) call forms differently across grammar
    // versions. Any identifier inside such an asm-keyword call is asm-related,
    // not a real read — short-circuit before the shape-specific logic below.
    if is_in_asm_call(node, source) {
        return false;
    }

    let parent = match node.parent() {
        Some(p) => p,
        None => return true,
    };

    // Walk up ancestors to check context
    // Some non-read contexts are nested: sizeof(x) → sizeof_expression > parenthesized_expression > identifier
    let mut ancestor = Some(parent);
    let mut depth = 0;
    while let Some(anc) = ancestor {
        depth += 1;
        if depth > 5 {
            break;
        }
        match anc.kind() {
            "sizeof_expression" | "_Alignof" => return false,
            "parenthesized_expression" => {
                ancestor = anc.parent();
                continue;
            }
            _ => break,
        }
    }

    match parent.kind() {
        // LHS of assignment
        "assignment_expression" => {
            if let Some(left) = parent.child_by_field_name("left") {
                if left.id() == node.id() {
                    // Check for compound assignment (+=, -=, *=, etc.)
                    // which both reads and writes the LHS
                    for i in 0..parent.child_count() {
                        if let Some(op) = parent.child(i) {
                            let op_text = get_node_text(&op, source);
                            if matches!(
                                op_text,
                                "+=" | "-="
                                    | "*="
                                    | "/="
                                    | "%="
                                    | "<<="
                                    | ">>="
                                    | "&="
                                    | "|="
                                    | "^="
                            ) {
                                return true; // Compound assignment reads the LHS
                            }
                        }
                    }
                    return false; // Simple assignment (=) — write only
                }
            }
            true // RHS is a read
        }
        // Compound assignment (+=, -=, etc.) — both read and write
        "augmented_assignment_expression" => true,
        // Declaration — not a read
        "declaration" | "init_declarator" => false,
        // sizeof(x) — not a read
        "sizeof_expression" => false,
        // &x — address-of. Generally not a read, BUT if &x is passed to a
        // non-initializing function (one that reads from the pointer), it IS a read.
        "pointer_expression" => {
            let text = get_node_text(&parent, source);
            if !text.starts_with('&') {
                return true; // *x — dereference read
            }
            // Check if &var is inside an argument_list of a non-initializing function
            if let Some(arg_list) = parent.parent() {
                if arg_list.kind() == "argument_list" {
                    if let Some(call) = arg_list.parent() {
                        if call.kind() == "call_expression" {
                            if let Some(func) = call.child_by_field_name("function") {
                                let func_name = get_node_text(&func, source);
                                if init_state::is_non_initializing_function(&func_name) {
                                    return true; // &var passed to function that reads from it
                                }
                            }
                        }
                    }
                }
            }
            false // Regular &var — not a read
        }
        // Update expression (i++, ++i) — both read and write, but we don't flag these
        "update_expression" => false,
        // Field expression LHS — writing to a field is NOT reading the base
        "field_expression" => {
            // Check if the field expression is on the LHS of an assignment
            if let Some(grandparent) = parent.parent() {
                if grandparent.kind() == "assignment_expression" {
                    if let Some(left) = grandparent.child_by_field_name("left") {
                        if left.id() == parent.id() {
                            return false; // obj.field = val — obj is not "read"
                        }
                    }
                }
            }
            true
        }
        // Subscript base (arr[i]) — the base identifier provides the address,
        // not a value read. Content reads are handled by check_subscript_read.
        "subscript_expression" => false,
        // Parameter declaration — not a read
        "parameter_declaration" => false,
        // Cast expression — reading the value
        "cast_expression" => true,
        // Condition expressions — reading
        "binary_expression" | "unary_expression" | "conditional_expression" => true,
        // Function call argument — usually a read, but check for output args
        // of known initializing functions (e.g., fgets(input, ...) is a write to input)
        "argument_list" => {
            // Special case: `__asm("..." : "=r"(var) ...)` is misparsed by
            // tree-sitter as call_expression("__asm", [ERROR, "=r"(var), ...]).
            // The output operand `"=r"(var)` becomes call_expression("=r", [var]).
            // Detect this: identifier inside argument_list of a call whose
            // function is a string_literal with "=" (output constraint).
            if let Some(call_gp) = parent.parent() {
                if call_gp.kind() == "call_expression" {
                    if let Some(func) = call_gp.child_by_field_name("function") {
                        if func.kind() == "string_literal" {
                            let constraint = get_node_text(&func, source);
                            if constraint.contains('=') {
                                return false; // output operand of misparsed __asm
                            }
                        }
                    }
                }
            }
            is_read_in_argument_list(node, &parent, source)
        }
        // Return statement — reading
        "return_statement" => true,
        // Comma expression
        "comma_expression" => true,
        // GNU asm output operands are writes ("=r"(var)) — not reads
        "gnu_asm_output_operand" => false,
        _ => true,
    }
}

/// Check if an identifier in an argument_list is being read (vs. being an output arg).
fn is_read_in_argument_list(node: &Node, arg_list: &Node, source: &str) -> bool {
    // Find the parent call_expression
    let call_expr = match arg_list.parent() {
        Some(c) if c.kind() == "call_expression" => c,
        _ => return true,
    };

    // Get function name
    let func_name = match call_expr.child_by_field_name("function") {
        Some(f) => get_node_text(&f, source).to_string(),
        None => return true,
    };

    // va_start/va_copy: first arg is output (initializes the va_list)
    if func_name == "va_start" || func_name == "va_copy" {
        // First non-punctuation arg is the output va_list
        if let Some(first_arg) = call_expr.child_by_field_name("arguments").and_then(|args| {
            for i in 0..args.child_count() {
                if let Some(c) = args.child(i) {
                    if c.kind() != "(" && c.kind() != ")" && c.kind() != "," {
                        return Some(c);
                    }
                }
            }
            None
        }) {
            if contains_node(&first_arg, node) {
                return false; // Output arg — not a read
            }
        }
        return true;
    }

    // Check if this is a known initializing function (exact or suffix match)
    let base_name = match init_state::match_initializing_function(&func_name) {
        Some(name) => name,
        None => {
            // For unknown functions, check if the identifier is passed by name
            // (arrays passed by name to unknown functions are assumed initialized)
            return true;
        }
    };

    // Determine which argument position this identifier is at
    let output_indices = init_state::get_output_arg_indices(base_name);
    if output_indices.is_empty() {
        return true; // No output args — this is a read
    }

    let mut arg_idx = 0;
    for i in 0..arg_list.child_count() {
        if let Some(child) = arg_list.child(i) {
            if child.kind() == "," || child.kind() == "(" || child.kind() == ")" {
                continue;
            }
            // Check if this argument contains our identifier node
            if contains_node(&child, node) {
                return !output_indices.contains(&arg_idx);
            }
            arg_idx += 1;
        }
    }
    true // Couldn't determine position — assume read
}

/// Check if a node contains a specific descendant (by ID).
fn contains_node(haystack: &Node, needle: &Node) -> bool {
    let needle_id = needle.id();
    query::find_first_descendant(*haystack, |n| n.id() == needle_id).is_some()
}

/// Check if a dereference (*ptr) is in a read context.
fn is_deref_read_context(node: &Node) -> bool {
    let parent = match node.parent() {
        Some(p) => p,
        None => return true,
    };
    match parent.kind() {
        // *ptr = value is a write
        "assignment_expression" => {
            if let Some(left) = parent.child_by_field_name("left") {
                left.id() != node.id()
            } else {
                true
            }
        }
        _ => true,
    }
}

/// Check if a subscript access (arr[i]) is in a read context.
fn is_subscript_read_context(node: &Node) -> bool {
    // Walk up ancestors to find if this subscript is ultimately on the LHS of an assignment
    let mut current = *node;
    for _ in 0..5 {
        let parent = match current.parent() {
            Some(p) => p,
            None => return true,
        };
        match parent.kind() {
            "assignment_expression" => {
                if let Some(left) = parent.child_by_field_name("left") {
                    // If the subscript (or its field_expression ancestor) is on the LHS → write
                    return left.id() != current.id();
                }
                return true;
            }
            // arr[0].field — subscript is inside field_expression, keep walking up
            "field_expression" => {
                current = parent;
                continue;
            }
            _ => return true,
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Interprocedural pre-scan
// ---------------------------------------------------------------------------

/// Scan translation unit for functions that wrap realloc.
fn scan_realloc_wrappers(node: &Node, source: &str, wrappers: &mut HashSet<String>) {
    for func_def in query::find_descendants_of_kind(*node, "function_definition") {
        if let Some(body) = func_def.child_by_field_name("body") {
            let body_text = get_node_text(&body, source);
            if body_text.contains("realloc(") && !body_text.contains("memset") {
                if let Some(declarator) = func_def.child_by_field_name("declarator") {
                    let name = get_func_name(&declarator, source);
                    if !name.is_empty() {
                        wrappers.insert(name);
                    }
                }
            }
        }
    }
}

/// Scan for functions that only conditionally initialize pointer params.
/// e.g., void set_flag(int n, int *flag) { if (n > 0) *flag = 1; }
/// — doesn't init *flag on all paths.
fn scan_conditionally_init_functions(
    node: &Node,
    source: &str,
    result: &mut HashMap<String, HashSet<usize>>,
) {
    for func_def in query::find_descendants_of_kind(*node, "function_definition") {
        let cond_indices = get_conditional_init_param_indices(&func_def, source);
        if !cond_indices.is_empty() {
            if let Some(declarator) = func_def.child_by_field_name("declarator") {
                let name = get_func_name(&declarator, source);
                if !name.is_empty() {
                    result.insert(name, cond_indices);
                }
            }
        }
    }
}

/// Get the set of pointer parameter indices that are only conditionally initialized.
/// Returns indices into the full parameter list (including non-pointer params).
fn get_conditional_init_param_indices(func_node: &Node, source: &str) -> HashSet<usize> {
    let mut result = HashSet::new();
    let body = match func_node.child_by_field_name("body") {
        Some(b) => b,
        None => return result,
    };

    // Collect all parameter names with their indices in the parameter list
    let mut all_params: Vec<(usize, String, bool)> = Vec::new(); // (index, name, is_pointer)
    collect_param_list_with_indices(func_node, source, &mut all_params);

    let body_text = get_node_text(&body, source);

    for (idx, param_name, is_pointer) in &all_params {
        if !is_pointer {
            continue;
        }
        let deref_write = format!("*{}", param_name);

        if !body_text.contains(&deref_write) {
            continue; // Param not written through at all
        }

        // Check: does *param = appear at compound_statement top level?
        let mut has_unconditional_write = false;
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() == "expression_statement" {
                    let stmt_text = get_node_text(&child, source);
                    if stmt_text.contains(&deref_write) && stmt_text.contains('=') {
                        has_unconditional_write = true;
                        break;
                    }
                }
            }
        }

        if !has_unconditional_write {
            result.insert(*idx);
        }
    }

    result
}

/// Collect all parameters with their indices, names, and whether they're pointers.
fn collect_param_list_with_indices(
    func_node: &Node,
    source: &str,
    params: &mut Vec<(usize, String, bool)>,
) {
    let declarator = match func_node.child_by_field_name("declarator") {
        Some(d) => d,
        None => return,
    };
    let func_decl = match find_function_declarator_node(&declarator) {
        Some(d) => d,
        None => return,
    };

    for i in 0..func_decl.child_count() {
        if let Some(child) = func_decl.child(i) {
            if child.kind() == "parameter_list" {
                let mut param_idx = 0;
                for j in 0..child.child_count() {
                    if let Some(param) = child.child(j) {
                        if param.kind() == "parameter_declaration" {
                            let param_text = get_node_text(&param, source);
                            let is_pointer = param_text.contains('*');
                            let name = get_declarator_name_from(&param, source);
                            if !name.is_empty() {
                                params.push((param_idx, name, is_pointer));
                            }
                            param_idx += 1;
                        }
                    }
                }
            }
        }
    }
}

fn find_function_declarator_node<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    query::find_first_descendant(*node, |n| n.kind() == "function_declarator")
}

fn get_declarator_name_from(node: &Node, source: &str) -> String {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "identifier" {
                return get_node_text(&child, source).to_string();
            }
            if child.kind() == "pointer_declarator" {
                return get_declarator_name_from(&child, source);
            }
        }
    }
    String::new()
}

/// Walk down a field_expression / subscript_expression chain to find the root identifier.
/// e.g., arr->data → "arr", ptr->field[i] → "ptr"
fn extract_root_identifier(node: &Node, source: &str) -> String {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.kind() == "identifier" {
                return get_node_text(&child, source).to_string();
            }
            if child.kind() == "field_expression" || child.kind() == "subscript_expression" {
                return extract_root_identifier(&child, source);
            }
        }
    }
    String::new()
}

fn get_func_name(declarator: &Node, source: &str) -> String {
    match declarator.kind() {
        "identifier" => get_node_text(declarator, source).to_string(),
        "function_declarator" | "pointer_declarator" => {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                get_func_name(&inner, source)
            } else {
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            return get_node_text(&child, source).to_string();
                        }
                    }
                }
                String::new()
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::CParser;

    /// Helper: parse code, create rule, call check on root, return violations
    fn check_code(code: &str) -> Vec<RuleViolation> {
        let mut parser = CParser::new().expect("parser");
        let tree = parser.parse_source(code).expect("parse");
        let rule = Exp33C::new();
        rule.check(&tree.root_node(), code)
    }

    #[test]
    fn test_initialized_at_decl() {
        let violations = check_code("int f() { int result = 0; return result; }");
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C")
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "result=0 should be initialized, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_uninitialized_read() {
        let violations = check_code("int f() { int x; return x; }");
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C")
            .collect::<Vec<_>>();
        assert!(!exp33.is_empty(), "x should be flagged as uninitialized");
    }

    #[test]
    fn test_conditional_init_both_branches() {
        let violations = check_code(
            r#"
            int f(int c) {
                int x;
                if (c) { x = 1; } else { x = 2; }
                return x;
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C")
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "x init'd in both branches, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_conditional_init_one_branch() {
        let violations = check_code(
            r#"
            int f(int c) {
                int x;
                if (c) { x = 1; }
                return x;
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C")
            .collect::<Vec<_>>();
        assert!(!exp33.is_empty(), "x only init'd in one branch");
    }

    #[test]
    fn test_memset_initializes() {
        let violations = check_code(
            r#"
            typedef int mbstate_t;
            void f() {
                mbstate_t state;
                memset(&state, 0, sizeof(state));
                use(state);
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("state"))
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "memset should initialize state, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_va_start_initializes() {
        let violations = check_code(
            r#"
            typedef int va_list;
            void f(int count, ...) {
                va_list args;
                va_start(args, count);
                use(args);
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("args"))
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "va_start should initialize args, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_subscript_field_write_not_read() {
        let violations = check_code(
            r#"
            typedef struct { int a; int b; } Pair;
            void f() {
                Pair *arr = (Pair *)malloc(4 * sizeof(Pair));
                if (arr == 0) return;
                arr[0].a = 0;
                arr[0].b = 0;
                free(arr);
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("arr"))
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "arr[0].a=0 should not flag arr, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_array_loop_init() {
        let violations = check_code(
            r#"
            void f(int size) {
                int vla[10];
                for (int i = 0; i < 10; i++) {
                    vla[i] = i;
                }
                use(vla[0]);
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("vla"))
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "loop init should mark vla as initialized, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_malloc_loop_init() {
        let violations = check_code(
            r#"
            void f() {
                int *array = malloc(10 * sizeof(int));
                if (array == 0) return;
                for (int i = 0; i < 10; i++) {
                    array[i] = i + 1;
                }
                use(array[0]);
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("array"))
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "loop init after malloc should be safe, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    // --- Regression tests for the 5 remaining fail-test gaps ---

    #[test]
    fn test_thread_local_uninit() {
        let violations = check_code(
            r#"
            static int counter;
            void f(void) {
                counter += 10;
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("counter"))
            .collect::<Vec<_>>();
        assert!(
            !exp33.is_empty(),
            "static without init should be flagged, got nothing"
        );
    }

    #[test]
    fn test_mbstate_non_init_read() {
        // &state passed to mbrlen which READS from it (non-initializing)
        let violations = check_code(
            r#"
            typedef int mbstate_t;
            void f(const char *mbs) {
                mbstate_t state;
                mbrlen(mbs, 5, &state);
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("state"))
            .collect::<Vec<_>>();
        assert!(
            !exp33.is_empty(),
            "mbrlen reads &state without prior init — should flag"
        );
    }

    #[test]
    fn test_return_by_reference_partial() {
        // set_flag only inits *sign_flag on some paths
        let violations = check_code(
            r#"
            void set_flag(int number, int *sign_flag) {
                if (sign_flag == 0) return;
                if (number > 0) *sign_flag = 1;
                else if (number < 0) *sign_flag = -1;
            }
            int f(int number) {
                int sign;
                set_flag(number, &sign);
                return sign < 0;
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("sign"))
            .collect::<Vec<_>>();
        assert!(
            !exp33.is_empty(),
            "set_flag doesn't init sign for number==0 — should flag"
        );
    }

    #[test]
    fn test_cross_file_read_only_deref() {
        // Simulates variant 63 pattern: &uninit_var passed to a function that
        // reads *param without writing. With cross-file summaries, this should
        // be flagged.
        let code = r#"
            void f() {
                int data;
                badSink(&data);
            }
        "#;
        let mut parser = CParser::new().expect("parser");
        let tree = parser.parse_source(code).expect("parse");
        let rule = Exp33C::new();

        // Inject a cross-file summary: badSink dereferences param 0 without modifying
        let mut summary = FunctionSummary::default();
        summary.dereferences_params.insert(0);
        // modifies_params is empty — read-only dereference
        let mut summaries = HashMap::new();
        summaries.insert("badSink".to_string(), summary);
        *rule.cross_file_summaries.borrow_mut() = summaries;

        let violations = rule.check(&tree.root_node(), code);
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("data"))
            .collect::<Vec<_>>();
        assert!(
            !exp33.is_empty(),
            "Passing &uninit_var to read-only-deref function should flag"
        );
    }

    #[test]
    fn test_cross_file_modifying_function_ok() {
        // Function that modifies param (writes *param) — should still treat as initializing
        let code = r#"
            void f() {
                int data;
                initSink(&data);
                use(data);
            }
        "#;
        let mut parser = CParser::new().expect("parser");
        let tree = parser.parse_source(code).expect("parse");
        let rule = Exp33C::new();

        // initSink both dereferences and modifies param 0
        let mut summary = FunctionSummary::default();
        summary.dereferences_params.insert(0);
        summary.modifies_params.insert(0);
        let mut summaries = HashMap::new();
        summaries.insert("initSink".to_string(), summary);
        *rule.cross_file_summaries.borrow_mut() = summaries;

        let violations = rule.check(&tree.root_node(), code);
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("data"))
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "initSink modifies param — data should be initialized, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    // test_realloc_uninit_portion and test_flexible_array_uninit are deferred
    // — they require inter-procedural realloc tracking and flexible array patterns
    // that are beyond the current CFG analysis scope.

    #[test]
    fn test_fgets_initializes_array() {
        let violations = check_code(
            r#"
            void f() {
                char input[100];
                fgets(input, 100, 0);
                use(input);
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("input"))
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "fgets should initialize input, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_struct_field_write() {
        let violations = check_code(
            r#"
            typedef struct { int a; int b; } Pair;
            void f() {
                Pair p;
                p.a = 1;
                p.b = 2;
                use(p.a);
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("'p'"))
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "p.a=1 should initialize p, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_switch_with_initialized_default() {
        let violations = check_code(
            r#"
            int f(int op) {
                int result = 0;
                switch (op) {
                    case 1: result = 10; break;
                    default: result = -1; break;
                }
                return result;
            }
        "#,
        );
        let exp33 = violations
            .iter()
            .filter(|v| v.rule_id == "EXP33-C" && v.message.contains("result"))
            .collect::<Vec<_>>();
        assert!(
            exp33.is_empty(),
            "result=0 should be initialized, got: {:?}",
            exp33.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }
}
