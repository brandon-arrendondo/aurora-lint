use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::macro_expand::FunctionMacro;
use crate::analyze::points_to::{lvalue_of, resolve_canonical, AliasMap, LValue};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Default)]
pub struct Mem30C {
    /// Cross-file function-like macro definitions (from the prescan / macro
    /// engine). Used to recognize "safe free" macros that free AND null their
    /// argument (e.g. curl `Curl_safefree`).
    function_macros: RefCell<HashMap<String, FunctionMacro>>,
    /// Cross-file function summaries from prescan. When a callee's `frees_params`
    /// is known from real analysis of its body, that's authoritative over the
    /// "does the function's NAME contain FREE" heuristic below — the name
    /// heuristic false-positives on functions like hostap's `plink_free_count`
    /// (a pure counter, no free at all) and misattributes multi-arg frees to
    /// the wrong parameter (task 396).
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
}

impl Mem30C {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CertRule for Mem30C {
    fn rule_id(&self) -> &'static str {
        "MEM30-C"
    }

    fn description(&self) -> &'static str {
        "Do not access freed memory"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MEM30-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.function_macros.borrow_mut() = context.function_macros.clone();
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect global variable information and cross-function patterns
        let mut global_tracker = GlobalTracker::new();
        global_tracker.scan_for_globals(node, source);
        global_tracker.scan_functions(node, source);

        // Check for cross-function violations
        global_tracker.check_cross_function_violations(node, source, &mut violations);

        // Precompute "safe free" macros invoked in this file: function-like
        // macros that free AND null their argument (e.g. curl Curl_safefree).
        // MEM30 already treats them as a free (name contains FREE) but cannot
        // see the `= NULL`; this lets the analyzer clear the freed state.
        // (Guarded by a non-empty table → zero cost without a macro prescan,
        // e.g. on Juliet.) Phase 2c-iii of docs/design/macro-expansion.md.
        let macro_null_params = {
            let macros = self.function_macros.borrow();
            if macros.is_empty() {
                HashMap::new()
            } else {
                let mut invoked = HashSet::new();
                collect_invoked_macro_names(node, source, &macros, &mut invoked);
                let mut out: HashMap<String, Vec<usize>> = HashMap::new();
                for name in invoked {
                    let idx =
                        crate::analyze::macro_expand::macro_nulls_param_indices(&macros, &name);
                    if !idx.is_empty() {
                        out.insert(name, idx);
                    }
                }
                out
            }
        };

        // Names of union typedefs in this file, so the analyzer can restrict
        // member-aliasing-on-free to genuine union variables (task 181).
        let mut union_typedef_names = HashSet::new();
        collect_union_typedef_names(node, source, &mut union_typedef_names);

        // Second pass: per-function analysis
        let mut analyzer = MemoryAnalyzer::new(
            macro_null_params,
            union_typedef_names,
            self.function_summaries.borrow().clone(),
        );
        analyzer.analyze_node(node, source, &mut violations);

        violations
    }
}

/// Collect the names introduced by `typedef union {...} NAME;` (or
/// `typedef union Tag NAME;`) under `node`. These let MEM30-C recognize
/// union-typed variable declarations without full type resolution.
fn collect_union_typedef_names(node: &Node, source: &str, out: &mut HashSet<String>) {
    for td in query::find_descendants_of_kind(*node, "type_definition") {
        if let Some(ty) = td.child_by_field_name("type") {
            if ty.kind() == "union_specifier" {
                let mut cursor = td.walk();
                for decl in td.children_by_field_name("declarator", &mut cursor) {
                    let name = type_identifier_name(&decl, source);
                    if !name.is_empty() {
                        out.insert(name);
                    }
                }
            }
        }
    }
}

/// Extract the `type_identifier` name from a typedef declarator (the new type
/// name), unwrapping pointer declarators if present.
fn type_identifier_name(node: &Node, source: &str) -> String {
    match node.kind() {
        "type_identifier" => get_node_text(node, source).to_string(),
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    let name = type_identifier_name(&child, source);
                    if !name.is_empty() {
                        return name;
                    }
                }
            }
            String::new()
        }
    }
}

/// Collect names of function-like macros (present in `macros`) invoked as
/// `call_expression`s under `node` — limits the safe-free computation to macros
/// actually used in the file.
fn collect_invoked_macro_names(
    node: &Node,
    source: &str,
    macros: &HashMap<String, FunctionMacro>,
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

/// True if a function name denotes a fresh heap allocation — the libc
/// `malloc`/`calloc` or a project wrapper such as `mosquitto_malloc`,
/// `curlx_calloc`, `Curl_strdup`, `xstrndup`. Used to clear a pointer's freed
/// state on reassignment (task 181 pattern 1). `realloc` is matched and handled
/// separately by the caller (it also invalidates the old pointer), so it is
/// excluded here.
fn is_fresh_allocation_name(name: &str) -> bool {
    let u = name.to_uppercase();
    if u.contains("REALLOC") {
        return false;
    }
    u.contains("ALLOC") || u.contains("STRDUP") || u.contains("STRNDUP") || u.contains("MEMDUP")
}

/// True if `call_node`'s result is captured by an assignment or
/// initializer — `x = call(...)` or `T *x = call(...)`, unwrapping any
/// enclosing parenthesization/cast (`x = (T *)call(...)`). This is the shape
/// every real `ptr = realloc(ptr, n)` idiom takes; a realloc-*named* call
/// used as a bare, discarded-result statement (e.g. a wrapper like lua's
/// `luaD_reallocstack(L, newsize, raiseerror);`, which mutates state via its
/// first argument rather than returning a new pointer to assign back) is
/// not that idiom, and must not be treated as invalidating its first
/// argument (task 563).
fn call_result_is_assigned(call_node: &Node) -> bool {
    let mut current = *call_node;
    loop {
        let Some(parent) = current.parent() else {
            return false;
        };
        match parent.kind() {
            "parenthesized_expression" | "cast_expression" => {
                current = parent;
            }
            "assignment_expression" => {
                return parent.child_by_field_name("right").map(|r| r.id()) == Some(current.id());
            }
            "init_declarator" => {
                return parent.child_by_field_name("value").map(|v| v.id()) == Some(current.id());
            }
            _ => return false,
        }
    }
}

/// Tracks global variables and cross-function memory patterns
struct GlobalTracker {
    /// Global variable declarations
    global_vars: HashSet<String>,
    /// Subset of global_vars that are pointer or array types — only these can hold
    /// stack addresses, so stack-escape checks are gated on this set.
    global_pointer_vars: HashSet<String>,
    /// Functions that free specific global variables: function_name -> freed_globals
    functions_that_free: HashMap<String, HashSet<String>>,
    /// Functions that access specific global variables: function_name -> accessed_globals
    functions_that_access: HashMap<String, HashSet<String>>,
    /// Dangerous patterns: VLA/stack pointers assigned to globals
    stack_escape_violations: Vec<(usize, usize, String)>, // (line, col, message)
    /// Functions that free their parameters (dangerous for caller)
    functions_that_free_params: HashMap<String, HashSet<String>>, // func_name -> param_names
    /// Signal handlers that free globals
    signal_handlers: HashSet<String>,
    /// Thread functions that access globals
    thread_functions: HashSet<String>,
    /// Functions that call longjmp after freeing globals
    longjmp_after_free: HashMap<String, HashSet<String>>, // func_name -> freed_globals
    /// Recursive function patterns: func -> (accesses global, frees global, has recursive call)
    recursive_patterns: Vec<(usize, usize, String)>, // (line, col, message)
    /// Realloc with zero size patterns
    realloc_zero_patterns: Vec<(usize, usize, String)>, // (line, col, message)
}

impl GlobalTracker {
    fn new() -> Self {
        Self {
            global_vars: HashSet::new(),
            global_pointer_vars: HashSet::new(),
            functions_that_free: HashMap::new(),
            functions_that_access: HashMap::new(),
            stack_escape_violations: Vec::new(),
            functions_that_free_params: HashMap::new(),
            signal_handlers: HashSet::new(),
            thread_functions: HashSet::new(),
            longjmp_after_free: HashMap::new(),
            recursive_patterns: Vec::new(),
            realloc_zero_patterns: Vec::new(),
        }
    }

    /// First scan: identify global variables at file scope. A `declaration`
    /// with `translation_unit` as its direct parent can never itself be
    /// nested inside a `#if 0` block (a `preproc_if` node, not
    /// `translation_unit`, would be its direct parent in that case), so the
    /// original recursive `is_preproc_if_zero` prune never actually changed
    /// which declarations matched here — this flat query is behavior-identical.
    fn scan_for_globals(&mut self, node: &Node, source: &str) {
        for decl in query::find_descendants(*node, |n| {
            n.kind() == "declaration" && n.parent().is_some_and(|p| p.kind() == "translation_unit")
        }) {
            self.extract_global_declarations(&decl, source);
        }
    }

    fn extract_global_declarations(&mut self, node: &Node, source: &str) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "pointer_declarator" {
                    let name = self.extract_declarator_name(&child, source);
                    if !name.is_empty() {
                        self.global_vars.insert(name.clone());
                        self.global_pointer_vars.insert(name);
                    }
                } else if child.kind() == "init_declarator" {
                    let name = self.extract_declarator_name(&child, source);
                    if !name.is_empty() {
                        self.global_vars.insert(name.clone());
                        // init_declarator contains a pointer_declarator if declared as pointer
                        if declarator_contains_pointer_or_array(&child) {
                            self.global_pointer_vars.insert(name);
                        }
                    }
                } else if child.kind() == "array_declarator" {
                    let name = self.extract_declarator_name(&child, source);
                    if !name.is_empty() {
                        self.global_vars.insert(name.clone());
                        self.global_pointer_vars.insert(name);
                    }
                } else if child.kind() == "identifier" {
                    let name = get_node_text(&child, source).to_string();
                    self.global_vars.insert(name);
                    // plain identifier declarator → scalar, not a pointer
                }
            }
        }
    }

    /// Second scan: analyze functions for free/access patterns. Unlike
    /// `scan_for_globals`, a `function_definition` is not required to be a
    /// direct child of `translation_unit`, so a function nested inside a
    /// `#if 0` block would otherwise be picked up by a plain kind search —
    /// the ancestor check below replicates the original recursive prune that
    /// skipped descending into `is_preproc_if_zero` subtrees entirely.
    fn scan_functions(&mut self, node: &Node, source: &str) {
        for func in query::find_descendants(*node, |n| {
            n.kind() == "function_definition"
                && query::find_ancestor(n, |a| is_preproc_if_zero(&a, source)).is_none()
        }) {
            self.analyze_function_patterns(&func, source);
            // Check for realloc zero-size pattern
            self.check_realloc_noncompliant_pattern(&func, source);
        }
    }

    /// Whether `body` has a comparison guarding `size_var` against zero
    /// (`size_var != 0`, `size_var > 0`, `0 != size_var`, `0 < size_var`),
    /// matched structurally against the comparison's own operand nodes —
    /// never against raw text, so a comment or string mentioning the same
    /// words can't fake a guard that isn't actually there.
    fn body_has_positive_size_guard(body: &Node, size_var: &str, source: &str) -> bool {
        query::find_descendants_of_kind(*body, "binary_expression")
            .iter()
            .any(|cmp| {
                let Some(op) = cmp
                    .child_by_field_name("operator")
                    .map(|o| get_node_text(&o, source))
                else {
                    return false;
                };
                if !matches!(op, "!=" | ">" | "<") {
                    return false;
                }
                let (Some(left), Some(right)) = (
                    cmp.child_by_field_name("left"),
                    cmp.child_by_field_name("right"),
                ) else {
                    return false;
                };
                let is_var =
                    |n: &Node| n.kind() == "identifier" && get_node_text(n, source) == size_var;
                let is_zero =
                    |n: &Node| n.kind() == "number_literal" && get_node_text(n, source) == "0";
                (is_var(&left) && is_zero(&right)) || (is_zero(&left) && is_var(&right))
            })
    }

    /// Check for wiki_noncompliant_3 pattern: `realloc(ptr, size)` without a
    /// guard that `size` is nonzero, followed later in the body by
    /// `free(ptr)` — realloc is permitted to free `ptr` and return `NULL`
    /// when `size == 0`, so the later `free(ptr)` can be a double-free.
    fn check_realloc_noncompliant_pattern(&mut self, func_node: &Node, source: &str) {
        let Some(body) = func_node.child_by_field_name("body") else {
            return;
        };

        for realloc_call in query::find_descendants_of_kind(body, "call_expression") {
            let is_realloc = realloc_call
                .child_by_field_name("function")
                .is_some_and(|f| get_node_text(&f, source) == "realloc");
            if !is_realloc {
                continue;
            }
            let Some(args) = realloc_call.child_by_field_name("arguments") else {
                continue;
            };
            let named_args: Vec<Node> = (0..args.named_child_count())
                .filter_map(|i| args.named_child(i))
                .collect();
            let [ptr_arg, size_arg] = named_args.as_slice() else {
                continue;
            };

            // A clearly-positive size (a literal, or `sizeof(...)` without a
            // zero-valued multiplier) can never realloc-as-free — skip.
            if self.is_constant_positive_size(get_node_text(size_arg, source)) {
                continue;
            }
            // A runtime guard on the size variable makes this the compliant
            // pattern.
            if size_arg.kind() == "identifier"
                && Self::body_has_positive_size_guard(
                    &body,
                    get_node_text(size_arg, source),
                    source,
                )
            {
                continue;
            }

            let ptr_var = self.extract_base_variable(ptr_arg, source);
            if ptr_var.is_empty() {
                continue;
            }
            let freed_after = query::find_descendants_of_kind(body, "call_expression")
                .into_iter()
                .filter(|c| c.start_byte() > realloc_call.start_byte())
                .any(|c| {
                    c.child_by_field_name("function")
                        .is_some_and(|f| get_node_text(&f, source) == "free")
                        && c.child_by_field_name("arguments")
                            .and_then(|a| a.named_child(0))
                            .is_some_and(|arg| self.extract_base_variable(&arg, source) == ptr_var)
                });
            if freed_after {
                self.realloc_zero_patterns.push((
                    func_node.start_position().row + 1,
                    1,
                    format!(
                        "Potential double-free: realloc({}, ...) may free memory when size is 0, then free({}) is called",
                        ptr_var, ptr_var
                    ),
                ));
            }
        }
    }

    /// Check if a size expression is clearly a positive constant
    fn is_constant_positive_size(&self, size_expr: &str) -> bool {
        let expr = size_expr.trim();

        // If it contains sizeof with a non-zero multiplier, it's positive
        // e.g., "10 * sizeof(int)", "sizeof(int) * 10"
        if expr.contains("sizeof") {
            // If there's a multiplier that's clearly positive
            let has_positive_mult = expr.chars().any(|c| c.is_ascii_digit() && c != '0');
            if has_positive_mult {
                return true;
            }
            // sizeof alone without multiplication could be valid
            if !expr.contains('*') && !expr.contains('+') {
                // Just sizeof(something) - always positive
                return true;
            }
        }

        // If it's a simple positive integer constant
        if let Ok(val) = expr.parse::<u64>() {
            return val > 0;
        }

        // If it starts with a non-zero digit (like "10 * ...")
        if expr
            .chars()
            .next()
            .map(|c| c.is_ascii_digit() && c != '0')
            .unwrap_or(false)
        {
            return true;
        }

        false
    }

    fn analyze_function_patterns(&mut self, func_node: &Node, source: &str) {
        // Get function name
        let func_name = self.get_function_name(func_node, source);
        if func_name.is_empty() {
            return;
        }

        // Get function parameters
        let params = self.get_function_params(func_node, source);

        let mut freed_globals = HashSet::new();
        let mut accessed_globals = HashSet::new();
        let mut freed_params = HashSet::new();
        let mut has_longjmp = false;
        let mut has_recursive_call = false;
        let mut global_access_after_recursive: Vec<(String, usize, usize)> = Vec::new();

        // Scan function body
        if let Some(body) = func_node.child_by_field_name("body") {
            self.scan_function_body(
                &body,
                source,
                &params,
                &mut freed_globals,
                &mut accessed_globals,
                &mut freed_params,
                &func_name,
                &mut has_longjmp,
                &mut has_recursive_call,
                &mut global_access_after_recursive,
            );
        }

        if !freed_globals.is_empty() {
            self.functions_that_free
                .insert(func_name.clone(), freed_globals.clone());
        }
        if !accessed_globals.is_empty() {
            self.functions_that_access
                .insert(func_name.clone(), accessed_globals);
        }
        if !freed_params.is_empty() {
            self.functions_that_free_params
                .insert(func_name.clone(), freed_params);
        }

        // Track longjmp after free pattern
        if has_longjmp && !freed_globals.is_empty() {
            self.longjmp_after_free
                .insert(func_name.clone(), freed_globals.clone());
        }

        // Check for recursive UAF pattern
        if has_recursive_call && !freed_globals.is_empty() {
            for (global, line, col) in global_access_after_recursive {
                if freed_globals.contains(&global) {
                    self.recursive_patterns.push((
                        line,
                        col,
                        format!(
                            "Recursive UAF: '{}' accesses global '{}' after recursive call that may free it",
                            func_name, global
                        ),
                    ));
                }
            }
        }
    }

    /// Preorder scan, left-to-right, same order as the original recursive
    /// walk — `has_recursive_call` is order-dependent (it's read by
    /// `scan_identifier_access` at the point of traversal), so the explicit
    /// stack below must visit nodes in exactly the same sequence a recursive
    /// descent would. Converted (task 295) after a deep-if-nesting stress
    /// fixture showed this walk — despite being described as a "secondary,
    /// bounded-depth concern" — does in fact overflow the native stack on
    /// the same adversarial input class the main `MemoryAnalyzer` conversion
    /// targets.
    fn scan_function_body(
        &mut self,
        node: &Node,
        source: &str,
        params: &HashSet<String>,
        freed_globals: &mut HashSet<String>,
        accessed_globals: &mut HashSet<String>,
        freed_params: &mut HashSet<String>,
        func_name: &str,
        has_longjmp: &mut bool,
        has_recursive_call: &mut bool,
        global_access_after_recursive: &mut Vec<(String, usize, usize)>,
    ) {
        let mut stack: Vec<Node> = vec![*node];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "call_expression" => {
                    self.scan_call_expression(
                        &n,
                        source,
                        params,
                        freed_globals,
                        freed_params,
                        func_name,
                        has_longjmp,
                        has_recursive_call,
                    );
                }
                "identifier" => {
                    self.scan_identifier_access(
                        &n,
                        source,
                        accessed_globals,
                        has_recursive_call,
                        global_access_after_recursive,
                    );
                }
                "assignment_expression" => {
                    self.scan_assignment_escape(&n, source, params, func_name);
                }
                _ => {}
            }

            let count = n.child_count();
            for i in (0..count).rev() {
                if let Some(child) = n.child(i) {
                    if is_preproc_if_zero(&child, source) {
                        continue;
                    }
                    stack.push(child);
                }
            }
        }
    }

    /// Text of the `n`-th (1-based) non-punctuation argument of a call expression.
    fn nth_arg_text(&self, node: &Node, n: usize, source: &str) -> Option<String> {
        let args = node.child_by_field_name("arguments")?;
        let mut arg_count = 0;
        for i in 0..args.child_count() {
            if let Some(arg) = args.child(i) {
                if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                    arg_count += 1;
                    if arg_count == n {
                        return Some(get_node_text(&arg, source).to_string());
                    }
                }
            }
        }
        None
    }

    /// Handle a `call_expression` node: track free()'d globals/params, signal &
    /// pthread handler registrations, longjmp use, and recursive self-calls.
    #[allow(clippy::too_many_arguments)]
    fn scan_call_expression(
        &mut self,
        node: &Node,
        source: &str,
        params: &HashSet<String>,
        freed_globals: &mut HashSet<String>,
        freed_params: &mut HashSet<String>,
        func_name: &str,
        has_longjmp: &mut bool,
        has_recursive_call: &mut bool,
    ) {
        let Some(func) = node.child_by_field_name("function") else {
            return;
        };
        let called_func = get_node_text(&func, source);

        // Check for free() calls
        if called_func == "free" {
            if let Some(args) = node.child_by_field_name("arguments") {
                for i in 0..args.child_count() {
                    if let Some(arg) = args.child(i) {
                        if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                            let var_name = self.extract_base_variable(&arg, source);
                            if self.global_vars.contains(&var_name) {
                                freed_globals.insert(var_name.clone());
                            }
                            if params.contains(&var_name) {
                                freed_params.insert(var_name);
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Check for signal() registration - second argument is the handler
        if called_func == "signal" {
            if let Some(handler) = self.nth_arg_text(node, 2, source) {
                self.signal_handlers.insert(handler);
            }
        }

        // Check for pthread_create - third argument is thread function
        if called_func == "pthread_create" {
            if let Some(thread_func) = self.nth_arg_text(node, 3, source) {
                self.thread_functions.insert(thread_func);
            }
        }

        // Check for longjmp
        if called_func == "longjmp" {
            *has_longjmp = true;
        }

        // Check for recursive call
        if called_func == func_name {
            *has_recursive_call = true;
            // After this call, scan for global accesses
            // We need to track accesses that come AFTER this recursive call
            // This is tricky with recursion, so we'll collect all accesses
            // and check later
        }

        // Note: realloc zero-size pattern removed - too many false positives
        // The pattern where realloc(ptr, 0) may free ptr is implementation-defined
        // and hard to detect without knowing if size can be 0
    }

    /// Handle an `identifier` node: record reads of global variables (outside free()
    /// args), tracking those that occur after a recursive call for pattern detection.
    fn scan_identifier_access(
        &mut self,
        node: &Node,
        source: &str,
        accessed_globals: &mut HashSet<String>,
        has_recursive_call: &mut bool,
        global_access_after_recursive: &mut Vec<(String, usize, usize)>,
    ) {
        // Check if accessing a global variable
        let var_name = get_node_text(node, source).to_string();
        if self.global_vars.contains(&var_name) {
            // Check if this is a read access (not inside free() args)
            if !self.is_inside_free_call(node, source) {
                accessed_globals.insert(var_name.clone());
                // Track line/col for recursive pattern detection
                if *has_recursive_call {
                    global_access_after_recursive.push((
                        var_name,
                        node.start_position().row + 1,
                        node.start_position().column + 1,
                    ));
                }
            }
        }
    }

    /// Handle an `assignment_expression` node: flag a stack pointer escape when a
    /// local array/VLA is assigned to a global pointer variable.
    fn scan_assignment_escape(
        &mut self,
        node: &Node,
        source: &str,
        params: &HashSet<String>,
        func_name: &str,
    ) {
        // Check for VLA/stack pointer escape to global
        if let Some(left) = node.child_by_field_name("left") {
            // Writing to an array element (arr[i] = x) is never a stack pointer
            // escape; only a direct assignment to the pointer/array variable itself
            // (global_ptr = local_arr) can escape a stack address.
            if left.kind() != "subscript_expression" {
                let left_var = self.extract_base_variable(&left, source);
                // Only pointer/array globals can actually hold a stack address;
                // scalar integer globals (u8/u16/u32 counters, state vars, etc.) cannot.
                if self.global_pointer_vars.contains(&left_var) {
                    // Check if right side is a local array/VLA
                    if let Some(right) = node.child_by_field_name("right") {
                        if self.is_local_array_or_vla(&right, source, params, func_name) {
                            self.stack_escape_violations.push((
                                node.start_position().row + 1,
                                node.start_position().column + 1,
                                format!(
                                    "Stack pointer escape: local array/VLA assigned to global '{}'",
                                    left_var
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Check for realloc with potentially zero size followed by free on failure
    #[allow(dead_code)]
    fn check_realloc_zero_pattern(&mut self, node: &Node, source: &str) {
        // Check if this realloc is in an if/initialization context where
        // the old pointer is freed on NULL return
        // Pattern: c_str2 = realloc(c_str1, size); if (c_str2 == NULL) { free(c_str1); }

        // Get the old pointer being reallocated
        if let Some(args) = node.child_by_field_name("arguments") {
            let mut old_ptr = String::new();
            let mut size_param = String::new();
            let mut arg_count = 0;

            for i in 0..args.child_count() {
                if let Some(arg) = args.child(i) {
                    if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                        arg_count += 1;
                        if arg_count == 1 {
                            old_ptr = self.extract_base_variable(&arg, source);
                        } else if arg_count == 2 {
                            size_param = get_node_text(&arg, source).to_string();
                        }
                    }
                }
            }

            // If size could be 0, and this is followed by free(old_ptr) on NULL,
            // it's potentially a double-free
            // For now, flag if size is a variable (could be 0) and pattern matches
            if !old_ptr.is_empty() && !size_param.is_empty() {
                // Check if size is not a constant > 0
                let size_is_constant_positive =
                    size_param.parse::<u64>().map(|v| v > 0).unwrap_or(false);

                if !size_is_constant_positive {
                    // Check if this realloc is followed by if (result == NULL) { free(old_ptr); }
                    if self.is_followed_by_null_check_and_free(node, &old_ptr, source) {
                        self.realloc_zero_patterns.push((
                            node.start_position().row + 1,
                            node.start_position().column + 1,
                            format!(
                                "Potential double-free: realloc({}, {}) with size 0 may free memory, then free({}) is called on NULL",
                                old_ptr, size_param, old_ptr
                            ),
                        ));
                    }
                }
            }
        }
    }

    fn is_followed_by_null_check_and_free(
        &self,
        realloc_node: &Node,
        old_ptr: &str,
        source: &str,
    ) -> bool {
        // Walk up to find if we're in an initialization/assignment
        // Then look for sibling if-statement that checks NULL and frees

        let mut current = realloc_node.parent();
        while let Some(parent) = current {
            if parent.kind() == "init_declarator" || parent.kind() == "assignment_expression" {
                // Found the assignment, now look for sibling if-statement
                if let Some(stmt_parent) = parent.parent() {
                    if let Some(container) = stmt_parent.parent() {
                        // Look for if-statement siblings
                        for i in 0..container.child_count() {
                            if let Some(sibling) = container.child(i) {
                                if sibling.kind() == "if_statement" {
                                    // Check if this if-statement has a free(old_ptr) call
                                    let if_text = get_node_text(&sibling, source);
                                    let free_pattern = format!("free({})", old_ptr);
                                    if if_text.contains(&free_pattern) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            current = parent.parent();
        }
        false
    }

    fn is_local_array_or_vla(
        &self,
        node: &Node,
        source: &str,
        params: &HashSet<String>,
        _func_name: &str,
    ) -> bool {
        // Check if the expression refers to a local array
        let var_name = self.extract_base_variable(node, source);

        // If it's not a global and not a parameter, it's local
        if !var_name.is_empty()
            && !self.global_vars.contains(&var_name)
            && !params.contains(&var_name)
        {
            // This is a local variable - could be VLA or stack array
            return true;
        }
        false
    }

    fn is_inside_free_call(&self, node: &Node, source: &str) -> bool {
        // Walk up to find if we're inside a free() argument list
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "argument_list" {
                // Check if the grandparent is actually a call to free() —
                // any other call (e.g. printf(x, *global)) must NOT suppress
                // the access, or genuine UAF reads passed to unrelated
                // functions go untracked.
                if let Some(call) = parent.parent() {
                    if call.kind() == "call_expression" {
                        if let Some(func) = call.child_by_field_name("function") {
                            if func.kind() == "identifier" && get_node_text(&func, source) == "free"
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            current = parent.parent();
        }
        false
    }

    /// Check for cross-function violations
    fn check_cross_function_violations(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Add stack escape violations
        for (line, col, msg) in &self.stack_escape_violations {
            violations.push(RuleViolation {
                rule_id: "MEM30-C".to_string(),
                severity: Severity::Critical,
                message: msg.clone(),
                file_path: String::new(),
                line: *line,
                column: *col,
                suggestion: Some(
                    "Do not save pointers to stack-allocated memory in global variables."
                        .to_string(),
                ),
                ..Default::default()
            });
        }

        // Add recursive UAF violations
        for (line, col, msg) in &self.recursive_patterns {
            violations.push(RuleViolation {
                rule_id: "MEM30-C".to_string(),
                severity: Severity::Critical,
                message: msg.clone(),
                file_path: String::new(),
                line: *line,
                column: *col,
                suggestion: Some(
                    "Save or guard global pointer before recursive call that may free it."
                        .to_string(),
                ),
                ..Default::default()
            });
        }

        // Add realloc zero-size violations (from text-based pattern matching)
        for (line, col, msg) in &self.realloc_zero_patterns {
            violations.push(RuleViolation {
                rule_id: "MEM30-C".to_string(),
                severity: Severity::Critical,
                message: msg.clone(),
                file_path: String::new(),
                line: *line,
                column: *col,
                suggestion: Some(
                    "Check size != 0 before calling realloc, or handle size == 0 explicitly."
                        .to_string(),
                ),
                ..Default::default()
            });
        }

        // Check for setjmp/longjmp UAF pattern
        self.check_setjmp_longjmp_pattern(node, source, violations);

        // Check for global-based UAF patterns
        // Pattern: func A frees global, func B accesses it, and main calls A then B
        self.check_call_sequence_violations(node, source, violations);

        // Note: Parameter-freed pattern removed - freeing a parameter is not itself a
        // MEM30-C violation; it's a valid API pattern (e.g., "consume" functions).
        // The actual UAF happens in the *caller* if they access the pointer after.

        // Check for signal handler freeing globals that main uses
        for handler in &self.signal_handlers {
            if let Some(freed) = self.functions_that_free.get(handler) {
                for global in freed {
                    // Check if any function accesses this global after signal could fire
                    for (func, accessed) in &self.functions_that_access {
                        if func != handler && accessed.contains(global) {
                            violations.push(RuleViolation {
                                rule_id: "MEM30-C".to_string(),
                                severity: Severity::Critical,
                                message: format!(
                                    "Signal handler '{}' frees global '{}' which is accessed in '{}' - potential UAF",
                                    handler, global, func
                                ),
                                file_path: String::new(),
                                line: 1,
                                column: 1,
                                suggestion: Some(
                                    "Avoid freeing memory in signal handlers that may be accessed elsewhere."
                                        .to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }

        // Check for thread function race conditions
        for thread_func in &self.thread_functions {
            if let Some(accessed) = self.functions_that_access.get(thread_func) {
                for global in accessed {
                    // Check if any other function frees this global
                    for (func, freed) in &self.functions_that_free {
                        if func != thread_func && freed.contains(global) {
                            violations.push(RuleViolation {
                                rule_id: "MEM30-C".to_string(),
                                severity: Severity::Critical,
                                message: format!(
                                    "Thread function '{}' accesses global '{}' which is freed in '{}' - race condition",
                                    thread_func, global, func
                                ),
                                file_path: String::new(),
                                line: 1,
                                column: 1,
                                suggestion: Some(
                                    "Use synchronization to protect shared memory in multi-threaded code."
                                        .to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Whether `scope` contains a genuine dereference of `var`: `*var`,
    /// `var->field`, or `var[i]`. Matched against the actual
    /// pointer/field/subscript expression nodes' `argument` field, never
    /// against raw text, so a comment or string literal mentioning the same
    /// variable name can't fake an access that isn't really there.
    fn scope_derefs_var(scope: &Node, var: &str, source: &str) -> bool {
        query::find_descendants_of_kinds(
            *scope,
            &[
                "pointer_expression",
                "field_expression",
                "subscript_expression",
            ],
        )
        .iter()
        .any(|n| {
            if n.kind() == "pointer_expression"
                && n.child_by_field_name("operator")
                    .is_none_or(|o| get_node_text(&o, source) != "*")
            {
                return false; // `&var` is an address-of, not a dereference
            }
            n.child_by_field_name("argument")
                .is_some_and(|a| get_node_text(&a, source) == var)
        })
    }

    /// Check for setjmp/longjmp UAF pattern
    /// Pattern: setjmp() followed by call to function that frees global and longjmps,
    /// with else branch accessing the freed global
    fn check_setjmp_longjmp_pattern(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for if_node in query::find_descendants_of_kind(*node, "if_statement") {
            let Some(condition) = if_node.child_by_field_name("condition") else {
                continue;
            };
            let condition_calls_setjmp =
                query::find_descendants_of_kind(condition, "call_expression")
                    .iter()
                    .any(|c| {
                        c.child_by_field_name("function")
                            .is_some_and(|f| get_node_text(&f, source) == "setjmp")
                    });
            if !condition_calls_setjmp {
                continue;
            }
            let Some(consequence) = if_node.child_by_field_name("consequence") else {
                continue;
            };

            for (func_name, freed_globals) in &self.longjmp_after_free {
                let consequence_calls_func =
                    query::find_descendants_of_kind(consequence, "call_expression")
                        .iter()
                        .any(|c| {
                            c.child_by_field_name("function")
                                .is_some_and(|f| get_node_text(&f, source) == func_name.as_str())
                        });
                if !consequence_calls_func {
                    continue;
                }
                let Some(alternative) = if_node.child_by_field_name("alternative") else {
                    continue;
                };
                for global in freed_globals {
                    if Self::scope_derefs_var(&alternative, global, source) {
                        violations.push(RuleViolation {
                            rule_id: "MEM30-C".to_string(),
                            severity: Severity::Critical,
                            message: format!(
                                "setjmp/longjmp UAF: '{}' frees global '{}' and longjmps, then else branch accesses it",
                                func_name, global
                            ),
                            file_path: String::new(),
                            line: alternative.start_position().row + 1,
                            column: alternative.start_position().column + 1,
                            suggestion: Some(
                                "Do not access memory freed before longjmp in else branch."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check for sequences like: call free_func(); call access_func();
    fn check_call_sequence_violations(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find function bodies and check call sequences
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(body) = func.child_by_field_name("body") {
                self.analyze_call_sequence(&body, source, violations);
            }
        }
    }

    fn analyze_call_sequence(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Collect all call expressions in order
        let mut calls: Vec<(String, usize, usize)> = Vec::new();
        self.collect_calls(node, source, &mut calls);

        // Track which globals have been freed so far
        let mut freed_globals: HashSet<String> = HashSet::new();

        for (func_name, line, col) in &calls {
            // Check if this function accesses any freed globals
            if let Some(accessed) = self.functions_that_access.get(func_name) {
                for global in accessed {
                    if freed_globals.contains(global) {
                        violations.push(RuleViolation {
                            rule_id: "MEM30-C".to_string(),
                            severity: Severity::Critical,
                            message: format!(
                                "Cross-function UAF: '{}' accesses global '{}' which was freed earlier",
                                func_name, global
                            ),
                            file_path: String::new(),
                            line: *line,
                            column: *col,
                            suggestion: Some(
                                "Do not access global memory after it has been freed."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }

            // Update freed globals based on this call
            if let Some(freed) = self.functions_that_free.get(func_name) {
                for global in freed {
                    freed_globals.insert(global.clone());
                }
            }
        }
    }

    /// Collect all call expressions under `node` in source order — order
    /// matters here (the result feeds a sequential scan in
    /// `analyze_call_sequence`). `query::find_descendants_of_kind` preserves
    /// the same left-to-right pre-order a recursive descent produces, so
    /// this is order-identical to the original recursive walk.
    fn collect_calls(&self, node: &Node, source: &str, calls: &mut Vec<(String, usize, usize)>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = call.child_by_field_name("function") {
                let func_name = get_node_text(&func, source).to_string();
                calls.push((
                    func_name,
                    call.start_position().row + 1,
                    call.start_position().column + 1,
                ));
            }
        }
    }

    fn get_function_name(&self, func_node: &Node, source: &str) -> String {
        if let Some(declarator) = func_node.child_by_field_name("declarator") {
            return self.extract_function_declarator_name(&declarator, source);
        }
        String::new()
    }

    fn extract_function_declarator_name(&self, node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => get_node_text(node, source).to_string(),
            "function_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.extract_function_declarator_name(&declarator, source)
                } else {
                    String::new()
                }
            }
            "pointer_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.extract_function_declarator_name(&declarator, source)
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        }
    }

    fn get_function_params(&self, func_node: &Node, source: &str) -> HashSet<String> {
        let mut params = HashSet::new();
        if let Some(declarator) = func_node.child_by_field_name("declarator") {
            self.extract_params_from_declarator(&declarator, source, &mut params);
        }
        params
    }

    fn extract_params_from_declarator(
        &self,
        node: &Node,
        source: &str,
        params: &mut HashSet<String>,
    ) {
        match node.kind() {
            "function_declarator" => {
                if let Some(parameters) = node.child_by_field_name("parameters") {
                    for i in 0..parameters.child_count() {
                        if let Some(param) = parameters.child(i) {
                            if param.kind() == "parameter_declaration" {
                                if let Some(declarator) = param.child_by_field_name("declarator") {
                                    let name = self.extract_declarator_name(&declarator, source);
                                    if !name.is_empty() {
                                        params.insert(name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "pointer_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.extract_params_from_declarator(&declarator, source, params);
                }
            }
            _ => {}
        }
    }

    fn extract_declarator_name(&self, node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => get_node_text(node, source).to_string(),
            "pointer_declarator" | "init_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.extract_declarator_name(&declarator, source)
                } else {
                    // Try to find identifier child
                    for i in 0..node.child_count() {
                        if let Some(child) = node.child(i) {
                            if child.kind() == "identifier" {
                                return get_node_text(&child, source).to_string();
                            }
                        }
                    }
                    String::new()
                }
            }
            "array_declarator" => {
                // int arr[10] - get the identifier
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "identifier" {
                            return get_node_text(&child, source).to_string();
                        }
                    }
                }
                String::new()
            }
            _ => String::new(),
        }
    }

    fn extract_base_variable(&self, node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => get_node_text(node, source).to_string(),
            "pointer_expression" | "field_expression" | "subscript_expression" => {
                if let Some(arg) = node.child_by_field_name("argument") {
                    self.extract_base_variable(&arg, source)
                } else {
                    String::new()
                }
            }
            "parenthesized_expression" => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "(" && child.kind() != ")" {
                            return self.extract_base_variable(&child, source);
                        }
                    }
                }
                String::new()
            }
            "cast_expression" => {
                if let Some(value) = node.child_by_field_name("value") {
                    self.extract_base_variable(&value, source)
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        }
    }
}

/// Which branch of an if-statement corresponds to realloc returning NULL
#[derive(Debug, PartialEq)]
enum ReallocNullBranch {
    Then, // if (result == NULL) or if (!result) — then-branch is the NULL case
    Else, // if (result) or if (result != NULL) — else-branch is the NULL case
}

/// The subset of `MemoryAnalyzer`'s fields that are forked across an
/// `if`/`else` branch and either merged back (via `MemoryAnalyzer::
/// merge_if_branches`) or restored verbatim before the else-branch walk.
#[derive(Clone)]
struct BranchState {
    freed_vars: HashSet<LValue>,
    nullified_vars: HashSet<LValue>,
    aliases: AliasMap,
    realloc_updated: HashSet<LValue>,
    realloc_invalidated: HashSet<LValue>,
}

impl BranchState {
    fn fork(analyzer: &MemoryAnalyzer) -> Self {
        Self {
            freed_vars: analyzer.freed_vars.clone(),
            nullified_vars: analyzer.nullified_vars.clone(),
            aliases: analyzer.aliases.clone(),
            realloc_updated: analyzer.realloc_updated.clone(),
            realloc_invalidated: analyzer.realloc_invalidated.clone(),
        }
    }

    fn restore(&self, analyzer: &mut MemoryAnalyzer) {
        analyzer.freed_vars = self.freed_vars.clone();
        analyzer.nullified_vars = self.nullified_vars.clone();
        analyzer.aliases = self.aliases.clone();
        analyzer.realloc_updated = self.realloc_updated.clone();
        analyzer.realloc_invalidated = self.realloc_invalidated.clone();
    }
}

struct MemoryAnalyzer {
    // Track which variables are currently freed
    freed_vars: HashSet<LValue>,
    // Byte offset (start_byte) of the free site that most recently marked each
    // name freed. Consulted only on a candidate double-free, to detect whether a
    // preprocessor conditional directive separates the two free sites (task 251).
    freed_at: HashMap<LValue, usize>,
    // Track aliases: if alias = ptr, then aliases[alias] = ptr
    aliases: AliasMap,
    // Track which variables have been set to NULL after free
    nullified_vars: HashSet<LValue>,
    // Track realloc old pointers that have been updated to new pointer
    realloc_updated: HashSet<LValue>,
    // Track realloc relationships: realloc_map[old_ptr] = new_ptr
    // When we see new_ptr = realloc(old_ptr, ...), old_ptr becomes potentially invalid
    realloc_invalidated: HashSet<LValue>,
    // Maps realloc result variable -> original pointers that were invalidated.
    // Used to clear invalidation in else-branches where realloc returned NULL
    // (meaning the original pointer is still valid).
    realloc_source: HashMap<LValue, Vec<LValue>>,
    // Track union members - when one member is freed, all are freed. Keyed by
    // the base variable's name (union tracking is base-variable-scoped, not
    // field-sensitive); values are the member LValues so they stay
    // comparable against freed_vars/realloc_invalidated.
    union_members: HashMap<String, HashSet<LValue>>,
    // Function-like "safe free" macros (free AND null their arg): macro name ->
    // nulled parameter indices. A call to one of these clears the freed state of
    // its argument, matching the macro's own `= NULL` (Phase 2c-iii).
    macro_null_params: HashMap<String, Vec<usize>>,
    // Names of union *typedefs* in this translation unit (e.g.
    // `typedef union {...} ptr_union_t;` -> "ptr_union_t"). Used to recognize
    // union-typed variable declarations. File-global; cloned per function.
    union_typedef_names: HashSet<String>,
    // Names of variables in the CURRENT function declared with a union type
    // (directly `union {...}`/`union Tag`, or a union typedef). ONLY for these
    // does freeing one member invalidate the sibling members (genuine storage
    // aliasing). Struct/struct-pointer bases are excluded, which prevents the
    // struct-field-free cascade FP — e.g. `free(data->state.range)` must not
    // poison `data->state` / other `data->*` fields (task 181). Repopulated per
    // function in `analyze_function`.
    union_typed_vars: HashSet<String>,
    // Cross-file function summaries from prescan. When a callee's real
    // `frees_params` is known, it overrides the name-based free heuristic
    // below (task 396) — see `process_call_expression`.
    function_summaries: HashMap<String, FunctionSummary>,
}

impl MemoryAnalyzer {
    fn new(
        macro_null_params: HashMap<String, Vec<usize>>,
        union_typedef_names: HashSet<String>,
        function_summaries: HashMap<String, FunctionSummary>,
    ) -> Self {
        Self {
            freed_vars: HashSet::new(),
            freed_at: HashMap::new(),
            aliases: HashMap::new(),
            nullified_vars: HashSet::new(),
            realloc_updated: HashSet::new(),
            realloc_invalidated: HashSet::new(),
            realloc_source: HashMap::new(),
            union_members: HashMap::new(),
            macro_null_params,
            union_typedef_names,
            union_typed_vars: HashSet::new(),
            function_summaries,
        }
    }

    /// Main analysis entry point - recursively analyze the AST
    fn analyze_node(&mut self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if is_preproc_if_zero(node, source) {
            return;
        }
        if node.kind() == "function_definition" {
            // Analyze each function with fresh state to avoid cross-function pollution
            let mut func_analyzer = MemoryAnalyzer::new(
                self.macro_null_params.clone(),
                self.union_typedef_names.clone(),
                self.function_summaries.clone(),
            );
            func_analyzer.analyze_function(node, source, violations);
            return; // Don't recurse further - function handled completely
        }

        // Recursively process child nodes (top-level traversal)
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.analyze_node(&child, source, violations);
            }
        }
    }

    /// Analyze a single function with isolated state
    fn analyze_function(&mut self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Identify union-typed locals/params first so member-aliasing on free is
        // restricted to genuine unions (not struct fields). See task 181.
        self.collect_union_typed_vars(node, source);
        self.analyze_function_body(node, source, violations);
    }

    /// Walk a function for declarations whose type is a union (directly
    /// `union {...}`/`union Tag`, or a union typedef from `union_typedef_names`)
    /// and record the declared variable names in `union_typed_vars`.
    fn collect_union_typed_vars(&mut self, node: &Node, source: &str) {
        let candidates =
            query::find_descendants_of_kinds(*node, &["declaration", "parameter_declaration"]);
        for decl_node in candidates {
            if let Some(ty) = decl_node.child_by_field_name("type") {
                let is_union = ty.kind() == "union_specifier"
                    || (ty.kind() == "type_identifier"
                        && self
                            .union_typedef_names
                            .contains(get_node_text(&ty, source)));
                if is_union {
                    let mut cursor = decl_node.walk();
                    for decl in decl_node.children_by_field_name("declarator", &mut cursor) {
                        let name = self.extract_declarator_name(&decl, source);
                        if !name.is_empty() {
                            self.union_typed_vars.insert(name);
                        }
                    }
                }
            }
        }
    }

    /// Analyze nodes within a function.
    ///
    /// Uses an explicit heap-allocated frame stack instead of native
    /// recursion (task 295): deeply/adversarially nested `if`/expression
    /// trees (Juliet-style generated code) can otherwise blow the native
    /// call stack, one frame per nesting level. `Frame::Visit` mirrors the
    /// original per-node dispatch + "recurse into children" fallthrough;
    /// `if_statement` additionally needs to suspend mid-procedure across its
    /// condition/then/else parts and resume with a branch merge, which the
    /// `AfterCondition`/`AfterThen`/`AfterElse` continuation frames encode
    /// (condition -> then-branch -> capture -> reset -> else-branch ->
    /// capture -> merge -> resume caller). This is a pure mechanical
    /// conversion: merge policy and ordering of side effects are preserved
    /// exactly, including the pre-existing quirk that `self.aliases` is
    /// reset before the else-branch but never re-merged afterward (it ends
    /// up as whatever the else-branch — or the reset, if there's no else —
    /// last left it as).
    fn analyze_function_body(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        enum Frame<'a> {
            Visit(Node<'a>),
            AfterCondition {
                if_node: Node<'a>,
                consequence: Option<Node<'a>>,
                alternative: Option<Node<'a>>,
            },
            AfterThen {
                if_node: Node<'a>,
                consequence: Option<Node<'a>>,
                alternative: Option<Node<'a>>,
                pre_state: BranchState,
                realloc_null_branch: Option<ReallocNullBranch>,
            },
            AfterElse {
                alternative: Option<Node<'a>>,
                pre_state: BranchState,
                then_state: BranchState,
                then_returns: bool,
            },
            /// `switch` statement whose condition has just been visited —
            /// forks the pre-switch state and starts the first case arm
            /// (task 398).
            StartSwitchCases {
                cases: Vec<Node<'a>>,
            },
            /// A `case`/`default` arm's own statements have just been
            /// visited — record its exit state + whether it unconditionally
            /// diverges (break/return/goto/continue), then either start the
            /// next arm (from a FRESH copy of `pre_state`, unioned with this
            /// arm's exit state if it fell through) or, if this was the last
            /// arm, merge all non-diverging arms' states back onto the
            /// analyzer.
            SwitchCaseDone {
                cases: Vec<Node<'a>>,
                idx: usize,
                pre_state: BranchState,
                exit_states: Vec<(BranchState, bool)>,
            },
        }

        // `skip_ids` names argument nodes a just-processed call_expression
        // already marked freed (task 400's `freed_arg_ids`) — the free's own
        // target isn't a use of the pointer it just freed, so re-walking it
        // as one would misreport "accessing freed memory" at the free
        // call's own line. Empty for every non-call_expression caller.
        // Separately, a `sizeof` operand is never evaluated in C (barring
        // the rare VLA case), so it's never a real use of whatever it names
        // either — skipped unconditionally.
        fn push_children<'a>(
            stack: &mut Vec<Frame<'a>>,
            node: &Node<'a>,
            source: &str,
            skip_ids: &HashSet<usize>,
        ) {
            let count = node.child_count();
            for i in (0..count).rev() {
                let Some(child) = node.child(i) else { continue };
                if is_preproc_if_zero(&child, source) || child.kind() == "sizeof_expression" {
                    continue;
                }
                if child.kind() == "argument_list" && !skip_ids.is_empty() {
                    push_call_args(stack, &child, source, skip_ids);
                    continue;
                }
                stack.push(Frame::Visit(child));
            }
        }

        fn push_call_args<'a>(
            stack: &mut Vec<Frame<'a>>,
            args_node: &Node<'a>,
            source: &str,
            skip_ids: &HashSet<usize>,
        ) {
            let count = args_node.child_count();
            for i in (0..count).rev() {
                let Some(arg) = args_node.child(i) else {
                    continue;
                };
                if is_preproc_if_zero(&arg, source)
                    || skip_ids.contains(&arg.id())
                    || arg.kind() == "sizeof_expression"
                {
                    continue;
                }
                stack.push(Frame::Visit(arg));
            }
        }

        /// The top-level `case_statement` children of a `switch` statement's
        /// body, in source order.
        fn collect_switch_cases<'a>(switch_node: &Node<'a>) -> Vec<Node<'a>> {
            let mut cases = Vec::new();
            if let Some(body) = switch_node.child_by_field_name("body") {
                let mut cursor = body.walk();
                for child in body.named_children(&mut cursor) {
                    if child.kind() == "case_statement" {
                        cases.push(child);
                    }
                }
            }
            cases
        }

        /// Handle a `Frame::StartSwitchCases` frame: fork the pre-switch
        /// state and kick off the first arm (or do nothing for an empty
        /// switch body).
        fn handle_start_switch_cases<'a>(
            analyzer: &mut MemoryAnalyzer,
            stack: &mut Vec<Frame<'a>>,
            source: &str,
            cases: Vec<Node<'a>>,
        ) {
            if cases.is_empty() {
                return;
            }
            let pre_state = BranchState::fork(analyzer);
            push_switch_case(analyzer, stack, source, cases, 0, pre_state, Vec::new());
        }

        /// Handle a `Frame::SwitchCaseDone` frame: record the arm just
        /// finished, then either start the next arm or, if this was the
        /// last, merge every arm's contribution back onto the analyzer.
        fn handle_switch_case_done<'a>(
            analyzer: &mut MemoryAnalyzer,
            stack: &mut Vec<Frame<'a>>,
            source: &str,
            cases: Vec<Node<'a>>,
            idx: usize,
            pre_state: BranchState,
            mut exit_states: Vec<(BranchState, bool)>,
        ) {
            let exit_state = BranchState::fork(analyzer);
            let diverges = analyzer.case_arm_diverges(&cases[idx]);
            exit_states.push((exit_state, diverges));
            let next_idx = idx + 1;
            if next_idx < cases.len() {
                push_switch_case(
                    analyzer,
                    stack,
                    source,
                    cases,
                    next_idx,
                    pre_state,
                    exit_states,
                );
            } else {
                MemoryAnalyzer::merge_switch_arms(analyzer, &pre_state, &cases, &exit_states);
            }
        }

        /// Reset analyzer state to `pre_state`, union in the previous arm's
        /// exit state if it fell through (fallthrough means the previous
        /// arm's state is ALSO reachable at the top of this one, in addition
        /// to a direct jump from the switch dispatch, which only ever sees
        /// `pre_state`), then push this case's own statements (excluding the
        /// `case`/`default` keyword and value) onto the stack followed by a
        /// `SwitchCaseDone` continuation (task 398).
        fn push_switch_case<'a>(
            analyzer: &mut MemoryAnalyzer,
            stack: &mut Vec<Frame<'a>>,
            source: &str,
            cases: Vec<Node<'a>>,
            idx: usize,
            pre_state: BranchState,
            exit_states: Vec<(BranchState, bool)>,
        ) {
            pre_state.restore(analyzer);
            if let Some((prev_state, prev_diverges)) = exit_states.last() {
                if !prev_diverges {
                    analyzer.union_state_from(prev_state);
                }
            }

            let case_node = cases[idx];
            stack.push(Frame::SwitchCaseDone {
                cases: cases.clone(),
                idx,
                pre_state,
                exit_states,
            });
            let value_id = case_node.child_by_field_name("value").map(|v| v.id());
            let stmts: Vec<Node<'a>> = (0..case_node.child_count())
                .filter_map(|i| case_node.child(i))
                .filter(|c| {
                    !matches!(c.kind(), "case" | "default" | ":") && Some(c.id()) != value_id
                })
                .collect();
            for stmt in stmts.into_iter().rev() {
                if !is_preproc_if_zero(&stmt, source) {
                    stack.push(Frame::Visit(stmt));
                }
            }
        }

        let no_skip: HashSet<usize> = HashSet::new();
        let mut stack: Vec<Frame> = vec![Frame::Visit(*node)];
        while let Some(frame) = stack.pop() {
            match frame {
                Frame::Visit(n) => match n.kind() {
                    "if_statement" => {
                        let consequence = n.child_by_field_name("consequence");
                        let alternative = n.child_by_field_name("alternative");
                        let condition = n.child_by_field_name("condition");
                        stack.push(Frame::AfterCondition {
                            if_node: n,
                            consequence,
                            alternative,
                        });
                        if let Some(condition) = condition {
                            stack.push(Frame::Visit(condition));
                        }
                    }
                    "switch_statement" => {
                        // Each `case`/`default` arm is mutually exclusive with
                        // its siblings — a free in one arm must not poison a
                        // later arm's use of the same variable (task 398).
                        // Collect the arms first, then visit the condition
                        // before starting the first arm.
                        stack.push(Frame::StartSwitchCases {
                            cases: collect_switch_cases(&n),
                        });
                        if let Some(condition) = n.child_by_field_name("condition") {
                            stack.push(Frame::Visit(condition));
                        }
                    }
                    "call_expression" => {
                        let freed_arg_ids = self.process_call_expression(&n, source, violations);
                        push_children(&mut stack, &n, source, &freed_arg_ids);
                    }
                    "assignment_expression" => {
                        self.process_assignment(&n, source, violations);
                        push_children(&mut stack, &n, source, &no_skip);
                    }
                    "init_declarator" => {
                        self.process_init_declarator(&n, source, violations);
                        push_children(&mut stack, &n, source, &no_skip);
                    }
                    "pointer_expression" => {
                        // Check for dereference of freed memory (*ptr)
                        self.check_pointer_dereference(&n, source, violations);
                        push_children(&mut stack, &n, source, &no_skip);
                    }
                    "subscript_expression" => {
                        // Check for array access on freed memory (arr[i]).
                        // Don't recurse into it — we already checked the
                        // argument, which prevents double-checking field
                        // expressions that are subscript arguments.
                        self.check_subscript_access(&n, source, violations);
                    }
                    "binary_expression" => {
                        // Check for pointer arithmetic on freed memory (ptr + n)
                        self.check_binary_expression(&n, source, violations);
                        push_children(&mut stack, &n, source, &no_skip);
                    }
                    "return_statement" => {
                        // Check for returning freed memory
                        self.check_return_statement(&n, source, violations);
                        push_children(&mut stack, &n, source, &no_skip);
                    }
                    "for_statement" => {
                        // Check for dangerous loop free patterns
                        self.check_for_loop_pattern(&n, source, violations);
                        push_children(&mut stack, &n, source, &no_skip);
                    }
                    "field_expression" => {
                        // Check for field access on freed memory (ptr->field)
                        self.check_field_access(&n, source, violations);
                        push_children(&mut stack, &n, source, &no_skip);
                    }
                    _ => {
                        push_children(&mut stack, &n, source, &no_skip);
                    }
                },
                Frame::AfterCondition {
                    if_node,
                    consequence,
                    alternative,
                } => {
                    // Check if the condition tests a realloc result variable.
                    // Pattern: if (temp) or if (temp != NULL) means then=realloc succeeded, else=failed.
                    // Pattern: if (!temp) or if (temp == NULL) means then=realloc failed, else=succeeded.
                    // When realloc fails (returns NULL), the original pointer is still valid.
                    let realloc_null_branch =
                        self.detect_realloc_condition_branch(&if_node, source);

                    // Save state before branches
                    let pre_state = BranchState::fork(self);

                    // If the then-branch is the realloc-failed path, clear invalidation there
                    if realloc_null_branch == Some(ReallocNullBranch::Then) {
                        if let Some(cond) = if_node.child_by_field_name("condition") {
                            self.clear_realloc_invalidation_for_condition(&cond, source);
                        }
                    }

                    stack.push(Frame::AfterThen {
                        if_node,
                        consequence,
                        alternative,
                        pre_state,
                        realloc_null_branch,
                    });
                    if let Some(consequence) = consequence {
                        stack.push(Frame::Visit(consequence));
                    }
                }
                Frame::AfterThen {
                    if_node,
                    consequence,
                    alternative,
                    pre_state,
                    realloc_null_branch,
                } => {
                    // Save state after then-branch
                    let then_state = BranchState::fork(self);
                    let then_returns = consequence
                        .map(|c| self.unconditionally_diverges(&c))
                        .unwrap_or(false);

                    // Reset state for else branch (starts from saved state)
                    pre_state.restore(self);

                    // If the else-branch is the realloc-failed path, clear invalidation there
                    if realloc_null_branch == Some(ReallocNullBranch::Else) {
                        if let Some(cond) = if_node.child_by_field_name("condition") {
                            self.clear_realloc_invalidation_for_condition(&cond, source);
                        }
                    }

                    stack.push(Frame::AfterElse {
                        alternative,
                        pre_state,
                        then_state,
                        then_returns,
                    });
                    if let Some(alternative) = alternative {
                        stack.push(Frame::Visit(alternative));
                    }
                }
                Frame::AfterElse {
                    alternative,
                    pre_state,
                    then_state,
                    then_returns,
                } => {
                    let else_state = BranchState::fork(self);
                    let else_returns = alternative
                        .map(|a| self.unconditionally_diverges(&a))
                        .unwrap_or(false);
                    Self::merge_if_branches(
                        self,
                        &pre_state,
                        &then_state,
                        then_returns,
                        &else_state,
                        else_returns,
                    );
                }
                Frame::StartSwitchCases { cases } => {
                    handle_start_switch_cases(self, &mut stack, source, cases);
                }
                Frame::SwitchCaseDone {
                    cases,
                    idx,
                    pre_state,
                    exit_states,
                } => {
                    handle_switch_case_done(
                        self,
                        &mut stack,
                        source,
                        cases,
                        idx,
                        pre_state,
                        exit_states,
                    );
                }
            }
        }
    }

    /// Union `other`'s tracked sets into the analyzer's current state
    /// (used for switch-arm fallthrough — the state carried in from the
    /// previous arm is possible IN ADDITION TO whatever this arm's own
    /// statements do, not instead of it).
    fn union_state_from(&mut self, other: &BranchState) {
        self.freed_vars.extend(other.freed_vars.iter().cloned());
        self.nullified_vars
            .extend(other.nullified_vars.iter().cloned());
        self.realloc_invalidated
            .extend(other.realloc_invalidated.iter().cloned());
        self.realloc_updated
            .extend(other.realloc_updated.iter().cloned());
        for (k, v) in other.aliases.iter() {
            self.aliases.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    /// Merge every arm's exit state that actually reaches the code after the
    /// `switch` back onto `analyzer`, mirroring `merge_if_branches`'
    /// semantics generalized to N arms: union freed/nullified/
    /// realloc-tracked sets across all such arms, except a variable
    /// nullified in EVERY live arm is not considered freed. Liveness here is
    /// `case_reaches_after_switch` (return/goto/continue truly skip past the
    /// switch; a `break`, unlike in `case_arm_diverges`'s fallthrough sense,
    /// does NOT — it's exactly how an arm reaches the code after the switch)
    /// — using `case_arm_diverges` here instead was task 398's bug: it
    /// treated a free-then-`break` arm as "unreachable after the switch"
    /// and silently dropped the free from the merged state. If the switch
    /// has no `default` arm, a value that matches none of the cases falls
    /// through untouched, so `pre_state` itself is always one of the live
    /// possibilities. If no arm reaches the code after the switch, it's
    /// unreachable — keep `pre_state`, matching `merge_if_branches`' "both
    /// branches return" case. `aliases` is left as whatever the
    /// last-processed arm set it to, mirroring `merge_if_branches`'
    /// documented aliases quirk.
    fn merge_switch_arms(
        analyzer: &mut Self,
        pre_state: &BranchState,
        cases: &[Node],
        exit_states: &[(BranchState, bool)],
    ) {
        let has_default = cases
            .iter()
            .any(|c| c.child_by_field_name("value").is_none());

        let mut live: Vec<&BranchState> = cases
            .iter()
            .zip(exit_states.iter())
            .filter(|(case_node, _)| Self::case_reaches_after_switch(case_node))
            .map(|(_, (s, _))| s)
            .collect();
        if !has_default {
            live.push(pre_state);
        }

        if live.is_empty() {
            pre_state.restore(analyzer);
            return;
        }

        let mut freed_vars = HashSet::new();
        let mut nullified_vars = HashSet::new();
        let mut realloc_invalidated = HashSet::new();
        let mut realloc_updated = HashSet::new();
        for s in &live {
            freed_vars.extend(s.freed_vars.iter().cloned());
            nullified_vars.extend(s.nullified_vars.iter().cloned());
            realloc_invalidated.extend(s.realloc_invalidated.iter().cloned());
            realloc_updated.extend(s.realloc_updated.iter().cloned());
        }
        // A variable nullified in EVERY live arm was safely NULL-guarded
        // everywhere it could have been freed — don't treat it as freed
        // after the switch (mirrors merge_if_branches' both-branches check).
        for var in pre_state.nullified_vars.iter() {
            if live.iter().all(|s| s.nullified_vars.contains(var)) {
                freed_vars.remove(var);
            }
        }
        // A var carried into nullified_vars from an arm that never freed it
        // (e.g. an untaken arm's stale pre-switch state) must not mask a
        // real free hit from another arm — freed and nullified are mutually
        // exclusive terminal states for the same var on the same path.
        nullified_vars.retain(|var| !freed_vars.contains(var));
        analyzer.freed_vars = freed_vars;
        analyzer.nullified_vars = nullified_vars;
        analyzer.realloc_invalidated = realloc_invalidated;
        analyzer.realloc_updated = realloc_updated;
    }

    /// Merge post-then/post-else state back onto `analyzer` after an
    /// `if`/`else`, per which branch(es) unconditionally diverge. `aliases`
    /// is deliberately excluded — see the note on `analyze_function_body`.
    fn merge_if_branches(
        analyzer: &mut Self,
        pre_state: &BranchState,
        then_state: &BranchState,
        then_returns: bool,
        else_state: &BranchState,
        else_returns: bool,
    ) {
        if then_returns && else_returns {
            // Both branches return - code after is unreachable, keep saved state
            analyzer.freed_vars = pre_state.freed_vars.clone();
            analyzer.nullified_vars = pre_state.nullified_vars.clone();
            analyzer.realloc_invalidated = pre_state.realloc_invalidated.clone();
            analyzer.realloc_updated = pre_state.realloc_updated.clone();
        } else if then_returns {
            // Only then returns - use else branch state
            analyzer.freed_vars = else_state.freed_vars.clone();
            analyzer.nullified_vars = else_state.nullified_vars.clone();
            analyzer.realloc_invalidated = else_state.realloc_invalidated.clone();
            analyzer.realloc_updated = else_state.realloc_updated.clone();
        } else if else_returns {
            // Only else returns - use then branch state
            analyzer.freed_vars = then_state.freed_vars.clone();
            analyzer.nullified_vars = then_state.nullified_vars.clone();
            analyzer.realloc_invalidated = then_state.realloc_invalidated.clone();
            analyzer.realloc_updated = then_state.realloc_updated.clone();
        } else {
            // Neither returns - merge states
            // For use-after-free detection: if freed in EITHER branch, it's potentially freed after
            // This ensures we catch use-after-free even on conditional frees
            let mut freed_vars = then_state.freed_vars.clone();
            for var in else_state.freed_vars.iter() {
                freed_vars.insert(var.clone());
            }
            // But remove vars that were nullified in both branches
            for var in pre_state.nullified_vars.iter() {
                if then_state.nullified_vars.contains(var)
                    && else_state.nullified_vars.contains(var)
                {
                    freed_vars.remove(var);
                }
            }
            analyzer.freed_vars = freed_vars;

            // Union of nullified, minus anything that ends up freed above —
            // freed and nullified are mutually exclusive terminal states for
            // the same var on the same path, and a var nullified in only one
            // branch (e.g. carried over from stale pre-if state) must not
            // mask a real free hit from the other branch via is_freed()'s
            // nullified-checked-first ordering.
            let mut nullified_vars = then_state.nullified_vars.clone();
            for var in else_state.nullified_vars.iter() {
                nullified_vars.insert(var.clone());
            }
            nullified_vars.retain(|var| !analyzer.freed_vars.contains(var));
            analyzer.nullified_vars = nullified_vars;

            // For realloc_invalidated: use union (if invalidated in either branch, could be invalid)
            // This is conservative for detecting use-after-free
            let mut realloc_invalidated = then_state.realloc_invalidated.clone();
            for var in else_state.realloc_invalidated.iter() {
                realloc_invalidated.insert(var.clone());
            }
            analyzer.realloc_invalidated = realloc_invalidated;

            // Union of realloc_updated
            let mut realloc_updated = then_state.realloc_updated.clone();
            for var in else_state.realloc_updated.iter() {
                realloc_updated.insert(var.clone());
            }
            analyzer.realloc_updated = realloc_updated;
        }
    }

    /// Check if a branch unconditionally diverges — i.e. control does NOT fall
    /// through to the statement after the enclosing `if`. That is true not only
    /// for `return`, but for any branch terminator that transfers control
    /// elsewhere: `goto`, `break`, `continue`. A free inside such a branch must
    /// not propagate to the post-`if` merged state, or the next statement (or a
    /// sibling `if(...){ free(p); goto/break; }`) is wrongly flagged as
    /// use-after-free / double-free. This was the dominant remaining MEM30 FP on
    /// real-world C (curl ldap.c / fopen.c, mosquitto ctrl_shell_*.c), where
    /// error branches free-then-`goto cleanup` / free-then-`break` (task 181
    /// pattern 2). The merge only recognized `return` before.
    fn unconditionally_diverges(&self, node: &Node) -> bool {
        Self::control_flow_diverges(node, true)
    }

    /// Core of `unconditionally_diverges`, parameterized on whether a bare
    /// `break_statement` counts as diverging. Two callers need different
    /// answers to "does control fall through to the code right after this
    /// construct": for an `if`-branch nested inside a `switch`/loop, `break`
    /// jumps OUT of that enclosing construct, so it correctly counts as
    /// diverging relative to the code after the `if` (this is
    /// `unconditionally_diverges`'s existing, unchanged behavior). But for a
    /// `switch` ARM itself, `break` is exactly how control reaches the code
    /// after the *switch* — the opposite of diverging past it — while
    /// `return`/`goto`/`continue` still skip past it entirely (task 398; see
    /// `case_reaches_after_switch`).
    fn control_flow_diverges(node: &Node, break_diverges: bool) -> bool {
        // Explicit work/result stacks instead of native recursion (task 295):
        // a chain of else-less nested `if`s (each testing this function on
        // its own consequence) recurses once per nesting level here too,
        // independent of `analyze_function_body`'s own conversion, so it
        // needs the same treatment to stay stack-safe on deeply nested input.
        enum Frame<'a> {
            Eval(Node<'a>),
            /// No node to evaluate (e.g. an `if` with no `else`) — contributes
            /// `false`, matching the original `.unwrap_or(false)`.
            PushFalse,
            AndCombine,
        }

        // A compound statement's result is exactly its last real statement's
        // result (braces/comments aren't statements), so chains of nested
        // compounds can be unwrapped in a plain loop — no stack growth.
        // tree-sitter-c wraps an `else` branch's body in its own `else_clause`
        // node (the `alternative` field's value), distinct from the `if`/`for`
        // body node returned directly by the `consequence`/`body` field — so an
        // else-branch's terminator was never being seen at all (every
        // `else_clause` fell through to the `_ => false` arm below), making
        // `else_returns` always false and any free in an `else` arm leak into
        // the general "neither branch returns" union-merge as if it hadn't
        // terminated. Unwrap it the same way as `compound_statement` (task 563).
        fn resolve<'a>(mut node: Node<'a>) -> Option<Node<'a>> {
            loop {
                match node.kind() {
                    "compound_statement" => {
                        let mut last_child = None;
                        for i in 0..node.child_count() {
                            if let Some(child) = node.child(i) {
                                if child.kind() != "{"
                                    && child.kind() != "}"
                                    && child.kind() != "comment"
                                {
                                    last_child = Some(child);
                                }
                            }
                        }
                        match last_child {
                            Some(last) => node = last,
                            None => return None,
                        }
                    }
                    "else_clause" => {
                        let mut inner = None;
                        for i in 0..node.child_count() {
                            if let Some(child) = node.child(i) {
                                if child.kind() != "else" && child.kind() != "comment" {
                                    inner = Some(child);
                                }
                            }
                        }
                        match inner {
                            Some(n) => node = n,
                            None => return None,
                        }
                    }
                    _ => return Some(node),
                }
            }
        }

        let mut work: Vec<Frame> = vec![Frame::Eval(*node)];
        let mut results: Vec<bool> = Vec::new();
        while let Some(frame) = work.pop() {
            match frame {
                Frame::PushFalse => results.push(false),
                Frame::AndCombine => {
                    let b = results.pop().unwrap_or(false);
                    let a = results.pop().unwrap_or(false);
                    results.push(a && b);
                }
                Frame::Eval(n) => match resolve(n) {
                    None => results.push(false),
                    Some(resolved) => match resolved.kind() {
                        "return_statement" | "goto_statement" | "continue_statement" => {
                            results.push(true);
                        }
                        "break_statement" => {
                            results.push(break_diverges);
                        }
                        "if_statement" => {
                            // An if-statement unconditionally diverges only if
                            // BOTH branches unconditionally diverge.
                            work.push(Frame::AndCombine);
                            match resolved.child_by_field_name("alternative") {
                                Some(alt) => work.push(Frame::Eval(alt)),
                                None => work.push(Frame::PushFalse),
                            }
                            match resolved.child_by_field_name("consequence") {
                                Some(cons) => work.push(Frame::Eval(cons)),
                                None => work.push(Frame::PushFalse),
                            }
                        }
                        _ => results.push(false),
                    },
                },
            }
        }
        results.pop().unwrap_or(false)
    }

    /// True if a `case`/`default` arm unconditionally diverges — i.e. it
    /// doesn't fall through into the next arm — by checking whether its
    /// LAST statement diverges (`break`/`return`/`goto`/`continue`, or an
    /// `if` whose both branches do), same simplification level as
    /// `unconditionally_diverges` itself. An arm with no statements at all
    /// (a bare grouped `case` label, e.g. `case B:` immediately followed by
    /// `case C:`) trivially falls through.
    fn case_arm_diverges(&self, case_node: &Node) -> bool {
        match Self::case_last_statement(case_node) {
            Some(stmt) => Self::control_flow_diverges(&stmt, true),
            None => false,
        }
    }

    /// True if control can reach the code AFTER THE WHOLE `switch` from this
    /// arm — the complement of "diverges past the switch". Unlike
    /// `case_arm_diverges` (which asks "does this arm avoid falling through
    /// to the NEXT arm", where `break` counts the same as `return`/`goto`/
    /// `continue`), a `break` here is exactly how an arm normally reaches
    /// the code after the switch, so it must NOT be treated the same as
    /// `return`/`goto`/`continue` (which really do skip past it). Getting
    /// this wrong made a free-then-break arm look "unreachable after the
    /// switch" and silently drop the free from the merged post-switch state
    /// (task 398).
    fn case_reaches_after_switch(case_node: &Node) -> bool {
        match Self::case_last_statement(case_node) {
            Some(stmt) => !Self::control_flow_diverges(&stmt, false),
            // No statements at all (a bare grouped case label, e.g. `case
            // B:` immediately followed by `case C:`) always falls through
            // to the next arm rather than reaching the code after the
            // switch on its own — whatever that next arm (or the arm it
            // eventually falls into) contributes is already counted there.
            None => false,
        }
    }

    /// The last real statement child of a `case`/`default` arm, excluding
    /// the `case`/`default` keyword, `:`, and the case value expression.
    fn case_last_statement<'a>(case_node: &Node<'a>) -> Option<Node<'a>> {
        let value_id = case_node.child_by_field_name("value").map(|v| v.id());
        (0..case_node.child_count())
            .filter_map(|i| case_node.child(i))
            .rfind(|c| !matches!(c.kind(), "case" | "default" | ":") && Some(c.id()) != value_id)
    }

    /// Detect if an if-statement's condition tests a realloc result variable.
    /// Returns which branch corresponds to realloc returning NULL (failed).
    fn detect_realloc_condition_branch(
        &self,
        if_node: &Node,
        source: &str,
    ) -> Option<ReallocNullBranch> {
        let condition = if_node.child_by_field_name("condition")?;
        // Unwrap parenthesized_expression
        let cond = if condition.kind() == "parenthesized_expression" {
            condition.child(1).unwrap_or(condition)
        } else {
            condition
        };

        match cond.kind() {
            // if (result) — non-null in then, null in else
            "identifier" => {
                let var = LValue::Var(get_node_text(&cond, source).to_string());
                if self.realloc_updated.contains(&var) {
                    Some(ReallocNullBranch::Else)
                } else {
                    None
                }
            }
            // if (!result) — null in then, non-null in else
            "unary_expression" => {
                if let Some(op) = cond.child(0) {
                    if get_node_text(&op, source) == "!" {
                        if let Some(arg) = cond.child_by_field_name("argument") {
                            let inner = if arg.kind() == "parenthesized_expression" {
                                arg.child(1).unwrap_or(arg)
                            } else {
                                arg
                            };
                            if inner.kind() == "identifier" {
                                let var = LValue::Var(get_node_text(&inner, source).to_string());
                                if self.realloc_updated.contains(&var) {
                                    return Some(ReallocNullBranch::Then);
                                }
                            }
                        }
                    }
                }
                None
            }
            // if (result != NULL) or if (result == NULL)
            "binary_expression" => {
                if let (Some(left), Some(op), Some(right)) = (
                    cond.child_by_field_name("left"),
                    cond.child_by_field_name("operator"),
                    cond.child_by_field_name("right"),
                ) {
                    let op_text = get_node_text(&op, source);
                    let left_text = get_node_text(&left, source);
                    let right_text = get_node_text(&right, source);

                    let (var, is_null_cmp) =
                        if right_text == "NULL" || right_text == "0" || right_text == "nullptr" {
                            (left_text, true)
                        } else if left_text == "NULL" || left_text == "0" || left_text == "nullptr"
                        {
                            (right_text, true)
                        } else {
                            ("", false)
                        };
                    let var = LValue::Var(var.to_string());

                    if is_null_cmp && self.realloc_updated.contains(&var) {
                        match op_text {
                            // if (result == NULL) — then=null, else=non-null
                            "==" => Some(ReallocNullBranch::Then),
                            // if (result != NULL) — then=non-null, else=null
                            "!=" => Some(ReallocNullBranch::Else),
                            _ => None,
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Clear realloc invalidation for the original pointer(s) corresponding to
    /// the realloc result tested in the given condition. Called in the branch
    /// where realloc returned NULL, meaning the original pointer is still valid.
    fn clear_realloc_invalidation_for_condition(&mut self, condition: &Node, source: &str) {
        let cond = if condition.kind() == "parenthesized_expression" {
            condition.child(1).unwrap_or(*condition)
        } else {
            *condition
        };

        // Extract the variable being tested
        let var_name = match cond.kind() {
            "identifier" => get_node_text(&cond, source).to_string(),
            "unary_expression" => {
                if let Some(arg) = cond.child_by_field_name("argument") {
                    let inner = if arg.kind() == "parenthesized_expression" {
                        arg.child(1).unwrap_or(arg)
                    } else {
                        arg
                    };
                    if inner.kind() == "identifier" {
                        get_node_text(&inner, source).to_string()
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            }
            "binary_expression" => {
                if let (Some(left), Some(right)) = (
                    cond.child_by_field_name("left"),
                    cond.child_by_field_name("right"),
                ) {
                    let lt = get_node_text(&left, source);
                    let rt = get_node_text(&right, source);
                    if rt == "NULL" || rt == "0" || rt == "nullptr" {
                        lt.to_string()
                    } else if lt == "NULL" || lt == "0" || lt == "nullptr" {
                        rt.to_string()
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            }
            _ => return,
        };
        let var_name = LValue::Var(var_name);

        // Look up which original pointers this realloc result corresponds to
        if let Some(old_ptrs) = self.realloc_source.get(&var_name) {
            for old_ptr in old_ptrs.clone() {
                self.realloc_invalidated.remove(&old_ptr);
            }
        }
    }

    /// Check if a node contains a return statement
    #[allow(dead_code)]
    fn contains_return(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| n.kind() == "return_statement").is_some()
    }

    /// Process function calls - free(), malloc(), printf(), etc.
    /// Returns the node ids of arguments this call just marked freed (task
    /// 400) — the call site that passes a pointer to be freed must not be
    /// re-walked as a "use" of that same pointer, or the free call's own
    /// argument gets flagged as accessing freed memory at its own line.
    fn process_call_expression(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) -> HashSet<usize> {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            match function_name {
                "free" => {
                    return self.process_free_call(node, source, violations);
                }
                "malloc" | "calloc" => {
                    // Allocation will be tracked via assignment
                    return HashSet::new();
                }
                "realloc" => {
                    // For realloc, the original pointer may become invalid
                    // Track the old pointer as invalidated in case it's used
                    self.track_realloc_old_pointer(node, source);
                    return HashSet::new();
                }
                _ => {
                    let upper_name = function_name.to_uppercase();

                    // A realloc-*named* wrapper (hostap's `os_realloc`: malloc
                    // new, copy, free old) is used at call sites via the
                    // standard `x = os_realloc(x, n)` / `nbuf = os_realloc(old,
                    // n); if (!nbuf) ...; else old = nbuf;` idiom, which always
                    // captures the call's result in an assignment — exactly what
                    // `track_realloc_old_pointer`'s
                    // pending-invalidation-then-clear-on-reassign tracking exists
                    // for. Gated on the call's result actually being assigned
                    // (`call_result_is_assigned`), NOT on a cross-file
                    // FunctionSummary crediting an unconditional free: the
                    // summary can't be computed at all when the wrapper's own
                    // free call goes through another project wrapper that's
                    // only extern-declared in scope (hostap's real `os_free`),
                    // and even when a summary *is* available, requiring it
                    // reintroduces the exact bug this gate fixes — a
                    // realloc-named function whose result is discarded (lua's
                    // `luaD_reallocstack(L, newsize, raiseerror);`, a bare
                    // statement whose first argument is a stable `lua_State*`
                    // handle, not the pointer being reallocated) must NOT be
                    // pushed through `track_realloc_old_pointer`, which would
                    // wrongly invalidate that handle with no reassignment to
                    // ever clear it (task 563).
                    if upper_name.contains("REALLOC") && call_result_is_assigned(node) {
                        self.track_realloc_old_pointer(node, source);
                        return HashSet::new();
                    }

                    // A cross-file FunctionSummary (real analysis of the callee's
                    // body) is authoritative over the name-based heuristic below —
                    // it fixes both false positives (e.g. hostap's
                    // `plink_free_count`, a pure counter whose name happens to
                    // contain "FREE") and misattribution (freeing the wrong
                    // parameter of a multi-arg call like `ap_free_sta(hapd, sta)`,
                    // task 396). Only fall back to the name heuristic when we have
                    // no summary for this callee (library/system function, or no
                    // -d cross-file scan).
                    //
                    // Uses `unconditional_frees_params`, NOT the broader (MAY-free)
                    // `frees_params`: a callee that only frees its argument on some
                    // conditional path (e.g. an error branch) doesn't definitely
                    // free it at every call site, and marking it as freed
                    // unconditionally here caused cascading false UAF/double-free
                    // reports at callers who took a different path (task 401).
                    if let Some(summary) = self.function_summaries.get(function_name).cloned() {
                        if !summary.unconditional_frees_params.is_empty() {
                            return self.process_summary_free_call(
                                node,
                                source,
                                &summary.unconditional_frees_params,
                                violations,
                            );
                        } else {
                            self.check_function_args_for_freed(node, source, violations);
                        }
                        return HashSet::new();
                    }

                    // Check for common free-related macros
                    if upper_name.contains("FREE")
                        || upper_name == "XFREE"
                        || upper_name == "G_FREE"
                        || upper_name == "SAFE_DELETE"
                        || upper_name == "DELETE"
                    {
                        // Treat as free() call
                        let freed_arg_ids = self.process_free_call(node, source, violations);
                        // "Safe free" macros (curl Curl_safefree, mosquitto
                        // mosquitto_FREE, …) also set the argument to NULL inside
                        // the macro body — invisible to us without expansion. If
                        // the macro engine flagged this macro as nulling a
                        // parameter, clear that argument's freed state, exactly
                        // as an explicit `p = NULL;` would. Phase 2c-iii.
                        if let Some(indices) = self.macro_null_params.get(function_name).cloned() {
                            self.clear_freed_for_nulled_args(node, source, &indices);
                        }
                        return freed_arg_ids;
                    } else {
                        // Check if any argument is a freed pointer
                        self.check_function_args_for_freed(node, source, violations);
                    }
                }
            }
        }
        HashSet::new()
    }

    /// Process free() call - mark variable as freed
    fn process_free_call(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) -> HashSet<usize> {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return HashSet::new();
        };

        // Collect the real (non-punctuation) argument nodes.
        let mut arg_nodes = Vec::new();
        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                    arg_nodes.push(arg);
                }
            }
        }

        // A free-like call frees exactly ONE object. For the standard single-argument
        // `free(p)` that is trivially the only argument. For allocator/context APIs with
        // a `(handle, target)` signature — e.g. sqlite3DbFree(db, x), sqlite3*Delete(db, x),
        // g_slice_free(type, x) — the freed object is the LAST operand; the leading
        // handle/type operand is a live object that must NOT be marked freed. Treating
        // every argument as freed was the dominant MEM30-C false-positive source on
        // real-world C (the live db handle was flagged as use-after-free / double-free).
        let Some(arg) = arg_nodes.last().copied() else {
            return HashSet::new();
        };
        self.mark_arg_freed(node, arg, source, violations)
            .into_iter()
            .collect()
    }

    /// Mark the SPECIFIC parameter positions a cross-file `FunctionSummary`
    /// determined this callee actually frees (task 396). Unlike
    /// `process_free_call`'s "assume it's the last argument" heuristic —
    /// needed when all we have is the callee's *name* — this is driven by
    /// real analysis of the callee's body, so it correctly frees e.g. the
    /// 2nd argument of `ap_free_sta(hapd, sta)` without the leading `hapd`
    /// handle ever being touched.
    fn process_summary_free_call(
        &mut self,
        node: &Node,
        source: &str,
        param_indices: &HashSet<usize>,
        violations: &mut Vec<RuleViolation>,
    ) -> HashSet<usize> {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return HashSet::new();
        };
        let mut arg_nodes = Vec::new();
        for i in 0..arguments.child_count() {
            if let Some(arg) = arguments.child(i) {
                if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                    arg_nodes.push(arg);
                }
            }
        }
        let mut freed_arg_ids = HashSet::new();
        for &idx in param_indices {
            if let Some(&arg) = arg_nodes.get(idx) {
                if let Some(id) = self.mark_arg_freed(node, arg, source, violations) {
                    freed_arg_ids.insert(id);
                }
            }
        }
        freed_arg_ids
    }

    /// Shared "mark this argument's lvalue as freed" logic — double-free
    /// check, union-member propagation, alias propagation — factored out of
    /// `process_free_call` so `process_summary_free_call` can drive it with
    /// summary-resolved argument positions instead of a name-based guess.
    fn mark_arg_freed(
        &mut self,
        node: &Node,
        arg: Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) -> Option<usize> {
        // For pointer dereference expressions like free(*ptr),
        // the memory pointed to by *ptr is freed, not ptr itself.
        // Skip tracking for these complex patterns to avoid false positives.
        if arg.kind() == "pointer_expression" {
            // We're freeing *ptr, not ptr. Skip tracking.
            return None;
        }

        // For subscript expressions like free(arr[i]),
        // the memory at arr[i] is freed, not arr itself.
        // Skip tracking to avoid false positives.
        if arg.kind() == "subscript_expression" {
            // We're freeing arr[i], not arr. Skip tracking.
            return None;
        }

        // For cast expressions like free((type)ptr), extract the inner value
        let actual_arg = if arg.kind() == "cast_expression" {
            if let Some(value) = arg.child_by_field_name("value") {
                value
            } else {
                arg
            }
        } else {
            arg
        };

        // For field expressions like free(data->name), track the full field
        // path, not just the base variable; for a bare identifier this is
        // just the identifier. Only these two top-level kinds are accepted
        // as free targets — everything else (e.g. a cast-wrapped
        // `&x`/`*x`, which `lvalue_of` would otherwise happily unwrap) is
        // skipped to avoid false positives, matching the original behavior.
        if actual_arg.kind() != "identifier" && actual_arg.kind() != "field_expression" {
            return None;
        }
        let lv = lvalue_of(&actual_arg, source)?;
        // For union support: also track the base variable — when
        // free(u.member1) is called, u.member2 also becomes invalid.
        let base_var = lv.is_field().then(|| lv.root_var().to_string());
        let display_name = get_node_text(&actual_arg, source);

        // Resolve to canonical name (in case of alias)
        let canonical = resolve_canonical(&self.aliases, &lv);

        // Check for double-free (only check freed_vars, not realloc_invalidated)
        // It's OK to free a realloc-invalidated pointer (that's expected when realloc fails)
        //
        // Suppress when a preprocessor *conditional* directive separates this free
        // from the one that marked the object freed: sqc has no preprocessor, so the
        // two frees may sit in mutually-exclusive build configurations (sibling
        // `#if`-guarded `else if` arms, or a diverging `#else` branch followed by a
        // fall-through free). Their parse order is not a real execution sequence, so
        // the inferred double-free is unsound (task 251).
        let preproc_split = self
            .freed_at
            .get(&canonical)
            .or_else(|| self.freed_at.get(&lv))
            .copied()
            .is_some_and(|prior| {
                let here = node.start_byte();
                preproc_conditional_between(source, prior.min(here), prior.max(here))
            });
        if self.is_actually_freed(&canonical)
            && !self.nullified_vars.contains(&canonical)
            && !preproc_split
        {
            violations.push(RuleViolation {
                rule_id: "MEM30-C".to_string(),
                severity: Severity::Critical,
                message: format!("Double-free: '{}' freed multiple times", display_name),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some(
                    "Set pointer to NULL after freeing to prevent double-free.".to_string(),
                ),
                ..Default::default()
            });
        }

        // Mark as freed
        self.freed_vars.insert(canonical.clone());
        self.freed_vars.insert(lv.clone());
        // Record the free site for the preproc-split double-free check above.
        let free_byte = node.start_byte();
        self.freed_at.insert(canonical.clone(), free_byte);
        self.freed_at.insert(lv.clone(), free_byte);

        // For union support: track union member relationships
        // When free(u.member) is called, all u.* accesses become invalid.
        // GATED on the base being a genuine union-typed variable: freeing a
        // struct field (e.g. `free(data->state.range)`) must NOT poison sibling
        // fields, which was the dominant MEM30 cascade FP on real-world C
        // (task 181). Members of a true union overlap in storage, so freeing one
        // does invalidate the others; struct fields are independent allocations.
        if let Some(base) = base_var {
            if !base.is_empty() && self.union_typed_vars.contains(&base) {
                // Add to union tracking - all field accesses on this base are suspect
                self.union_members
                    .entry(base)
                    .or_default()
                    .insert(lv.clone());
            }
        }

        // Also mark any aliases as freed
        let aliases_to_free: Vec<LValue> = self
            .aliases
            .iter()
            .filter(|(_, v)| **v == canonical || **v == lv)
            .map(|(k, _)| k.clone())
            .collect();
        for alias in aliases_to_free {
            self.freed_vars.insert(alias);
        }

        // Report this argument's node id so callers can skip re-walking it
        // as a "use" of the pointer it just marked freed — the call site
        // that passes a pointer to be freed isn't itself a use-after-free
        // (task 400).
        Some(arg.id())
    }

    /// For a "safe free" macro call (frees AND nulls its argument), clear the
    /// freed state of each nulled positional argument — mirroring the macro's
    /// own `arg = NULL` (which `process_free_call` cannot see). Replicates the
    /// NULL-assignment clearing in [`process_assignment`]. Phase 2c-iii.
    fn clear_freed_for_nulled_args(&mut self, call: &Node, source: &str, indices: &[usize]) {
        let args = crate::analyze::macro_semantics::positional_args(call);
        for &idx in indices {
            let Some(arg) = args.get(idx) else { continue };
            let Some(lv) = lvalue_of(arg, source) else {
                continue;
            };
            self.nullified_vars.insert(lv.clone());
            self.freed_vars.remove(&lv);
            self.realloc_invalidated.remove(&lv);

            // Also clear the base variable, matching the original dual-key
            // (full-path + base) clearing: e.g. `SAFE_FREE(data->x)` must
            // not leave `data` itself considered freed by some other
            // (possibly heuristic-driven) tracking elsewhere in the function.
            let base = LValue::Var(lv.root_var().to_string());
            self.nullified_vars.insert(base.clone());
            self.freed_vars.remove(&base);
        }
    }

    /// Process assignment expression - track aliases and NULL assignments
    fn process_assignment(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            // Full lvalue for field expressions (e.g., im->clip->list); None
            // for anything that isn't a trackable storage location.
            let Some(left_lv) = lvalue_of(&left, source) else {
                return;
            };
            let left_var = LValue::Var(left_lv.root_var().to_string());

            // Check if assigning NULL - this clears freed status
            let right_text = get_node_text(&right, source);
            if right_text.trim() == "NULL" || right_text.trim() == "0" {
                // For field expressions like data->name = NULL, track the full path
                self.nullified_vars.insert(left_lv.clone());
                self.freed_vars.remove(&left_lv);
                self.realloc_invalidated.remove(&left_lv);

                // Also track base variable
                self.nullified_vars.insert(left_var.clone());
                self.freed_vars.remove(&left_var);
                return;
            }

            // Check if this is a dereference write (*ptr = value)
            if left.kind() == "pointer_expression" {
                // This is writing through a pointer
                if let Some(arg) = left.child_by_field_name("argument") {
                    if let Some(ptr_var) = lvalue_of(&arg, source) {
                        let ptr_var = LValue::Var(ptr_var.root_var().to_string());
                        if self.is_freed(&ptr_var) {
                            violations.push(RuleViolation {
                                rule_id: "MEM30-C".to_string(),
                                severity: Severity::Critical,
                                message: format!(
                                    "Use-after-free: writing to freed memory via '{}'",
                                    ptr_var.root_var()
                                ),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(
                                    "Do not access memory after freeing it.".to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
                return;
            }

            // Writing to a container ELEMENT (`arr[i] = value`, including
            // `container->field[i] = value`) never reassigns the
            // container's own pointer identity — unlike a plain identifier
            // or field LHS, it must not clear the container's freed/
            // realloc-invalidated state below (that logic is for "this
            // storage location now holds a fresh/live value", which isn't
            // true here: only one element changed). `lvalue_of` is
            // deliberately index-insensitive (task 1), so a subscript LHS's
            // `left_lv` collapses to the exact same LValue as the
            // container/field itself — without this early return, the
            // "reassigning to a live value" branch below would incorrectly
            // erase that container's real invalidation (e.g. the realloc
            // self-assign-into-field UAF pattern, CERT wiki noncompliant
            // example: `im->clip->list[i] = x;` after `gdRealloc(im->clip
            // ->list, ...)` without writing the result back). No violation
            // is reported here: the left-hand subscript_expression node is
            // still independently visited via the generic child traversal
            // (unlike a field-expression LHS, check_subscript_access has no
            // "skip if LHS of assignment" guard), so it already reports the
            // UAF on its own — reporting here too would just duplicate it.
            if left.kind() == "subscript_expression" {
                return;
            }

            // Check if right side is a realloc result variable
            // If we're assigning a realloc result to the original pointer (ptr = new_ptr),
            // clear the freed status since the pointer is now valid again
            let right_var =
                lvalue_of(&right, source).map(|rv| LValue::Var(rv.root_var().to_string()));
            if let Some(right_var) = right_var {
                // Check if right_var was the result of a realloc on left_var
                // This handles: new_ptr = realloc(ptr, ...); ptr = new_ptr;
                // Also handles: im->clip->list = more; after more = gdRealloc(im->clip->list, ...)
                if self.realloc_updated.contains(&right_var) {
                    // Clear both base variable and full path
                    self.freed_vars.remove(&left_var);
                    self.nullified_vars.remove(&left_var);
                    self.realloc_invalidated.remove(&left_var);
                    // For field expressions, also clear the full path
                    self.freed_vars.remove(&left_lv);
                    self.nullified_vars.remove(&left_lv);
                    self.realloc_invalidated.remove(&left_lv);
                    // Also clear any aliases pointing to the old value
                    self.aliases.remove(&left_var);
                }

                if right.kind() == "identifier" && self.is_freed(&right_var) {
                    // Aliasing a dangling pointer (`p = q;` after free(q)) — the
                    // new variable also dangles. Gated on an identifier RHS:
                    // a subscript/field RHS copies a value out of a container,
                    // not the dangling pointer itself (task 232).
                    self.freed_vars.insert(left_var.clone());
                    self.aliases.insert(left_var.clone(), right_var.clone());
                } else {
                    // Reassigning the pointer to a live value overwrites any
                    // prior dangling state: `free(p); p = newbuf;` and the
                    // reassign-before-return shape (`free(text); text = temp;
                    // return text;`) must clear `p`/`text` (task 232 patterns
                    // 1 & 2). Clear the assigned lvalue path; for a plain
                    // identifier that IS the base name, so `free(s); s->f = x;`
                    // does not un-track the still-freed base `s`.
                    self.freed_vars.remove(&left_lv);
                    self.nullified_vars.remove(&left_lv);
                    self.realloc_invalidated.remove(&left_lv);
                    self.aliases.remove(&left_var);
                    if right.kind() == "identifier" && left.kind() == "identifier" {
                        // Track a fresh pointer-to-pointer alias.
                        self.aliases.insert(left_var.clone(), right_var.clone());
                    }
                }
            } else if left.kind() == "identifier" {
                // RHS is a non-variable expression (call result, etc.). A plain
                // pointer reassignment still overwrites any prior dangling
                // state (`free(p); p = make_buffer();`), so clear it.
                self.freed_vars.remove(&left_var);
                self.nullified_vars.remove(&left_var);
                self.realloc_invalidated.remove(&left_var);
                self.aliases.remove(&left_var);
            } else if left.kind() == "field_expression" {
                // Same reassignment-overwrites-dangling-state principle as the
                // identifier case above, for a field LHS whose RHS is a
                // non-variable expression (typically a call result). Without
                // this, `os_free(data->x); data->x = some_wrapper();` only
                // cleared the freed state when `some_wrapper`'s name matched
                // the `is_fresh_allocation_name` heuristic below — an
                // arbitrary project function (e.g. hostap's
                // `eap_sim_db_get_next_pseudonym`) left the field permanently
                // marked freed even though this statement, like any
                // reassignment, plainly gives it a fresh value (task 563).
                self.freed_vars.remove(&left_var);
                self.nullified_vars.remove(&left_var);
                self.realloc_invalidated.remove(&left_var);
                self.freed_vars.remove(&left_lv);
                self.nullified_vars.remove(&left_lv);
                self.realloc_invalidated.remove(&left_lv);
                self.aliases.remove(&left_var);
            }

            // Check if right side is pointer arithmetic on freed memory
            if right.kind() == "binary_expression" {
                self.check_binary_expression(&right, source, violations);
            }

            // Clear freed status if reassigning the pointer to a fresh
            // allocation. Reassignment overwrites the dangling pointer, so the
            // variable is no longer freed; `FREE(p); p = wrapper_alloc(...);
            // if(!p){}` was a dominant free-then-reassign FP (task 181 pattern
            // 1). Two generalizations over the old literal `malloc`/`calloc`
            // check: (a) the RHS may be cast-wrapped, e.g. `p = (char *)x_malloc(n)`;
            // (b) the allocator is often a project *wrapper* — mosquitto_malloc,
            // curlx_calloc, Curl_strdup — not the bare libc name. The freed
            // full path is cleared too (e.g. `s->buf = pkg_malloc(...)`).
            let alloc_rhs = if right.kind() == "cast_expression" {
                right.child_by_field_name("value").unwrap_or(right)
            } else {
                right
            };
            if alloc_rhs.kind() == "call_expression" {
                if let Some(func) = alloc_rhs.child_by_field_name("function") {
                    let func_name = get_node_text(&func, source);
                    let upper_func_name = func_name.to_uppercase();
                    if upper_func_name.contains("REALLOC") {
                        // Track the old pointer passed to realloc as invalidated
                        let old_ptrs = self.track_realloc_old_pointer(&alloc_rhs, source);
                        // For realloc, track that the result location holds the
                        // realloc result. Key on BOTH the base var and the full
                        // field path: a self-assign `cfg->topics = realloc(cfg->topics,
                        // n)` stores the result back into the field path, so the
                        // field — not just the base `cfg` — must be recorded as
                        // holding a realloc result (otherwise the recursion below
                        // re-invalidates it and the later `cfg->topics[i]` reads
                        // false-flag as use-after-free).
                        self.realloc_updated.insert(left_var.clone());
                        if left_lv != left_var {
                            self.realloc_updated.insert(left_lv.clone());
                        }
                        if !old_ptrs.is_empty() {
                            self.realloc_source
                                .insert(left_var.clone(), old_ptrs.clone());
                            if left_lv != left_var {
                                self.realloc_source.insert(left_lv.clone(), old_ptrs);
                            }
                        }
                        self.clear_freed_state(&left_var, &left_lv);
                    } else if is_fresh_allocation_name(&func_name) {
                        self.clear_freed_state(&left_var, &left_lv);
                    }
                }
            }
        }
    }

    /// Clear all freed/nullified/realloc-invalidation tracking for a variable
    /// (both its base name and full field path), e.g. after reassigning it to a
    /// fresh allocation.
    fn clear_freed_state(&mut self, base: &LValue, full_path: &LValue) {
        for key in [base, full_path] {
            self.freed_vars.remove(key);
            self.nullified_vars.remove(key);
            self.realloc_invalidated.remove(key);
        }
    }

    /// Process variable initialization (int *p = ptr)
    fn process_init_declarator(
        &mut self,
        node: &Node,
        source: &str,
        _violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(declarator), Some(value)) = (
            node.child_by_field_name("declarator"),
            node.child_by_field_name("value"),
        ) {
            let left_var = self.extract_declarator_name(&declarator, source);
            if left_var.is_empty() {
                return;
            }
            let left_var = LValue::Var(left_var);

            // A declaration introduces a FRESH binding for `left_var`. The
            // analyzer is scope-flat, so a same-named local re-declared in a
            // sibling block (`{ T *temp = RL_CALLOC(..); ..; RL_FREE(temp); }`
            // repeated per if/else arm — rmodels.c glTF loaders) would
            // otherwise inherit the prior arm's freed state and false-flag the
            // new buffer's use/free. Clearing on declaration is always sound:
            // the new variable cannot alias the old freed storage (task 232,
            // init-declarator analog of free-then-reassign). The alias branch
            // below re-marks it freed if it genuinely aliases a freed pointer.
            self.freed_vars.remove(&left_var);
            self.nullified_vars.remove(&left_var);
            self.realloc_invalidated.remove(&left_var);
            self.aliases.remove(&left_var);

            // Check if this is a realloc initialization
            if value.kind() == "call_expression" {
                if let Some(func) = value.child_by_field_name("function") {
                    let func_name = get_node_text(&func, source);
                    let upper_func_name = func_name.to_uppercase();
                    if func_name == "realloc" || upper_func_name.contains("REALLOC") {
                        // Track that left_var is the result of realloc
                        self.realloc_updated.insert(left_var.clone());
                        // Also track what pointer was passed to realloc (it's now invalidated)
                        let old_ptrs = self.track_realloc_old_pointer(&value, source);
                        if !old_ptrs.is_empty() {
                            self.realloc_source.insert(left_var.clone(), old_ptrs);
                        }
                        return;
                    } else if func_name == "malloc" || func_name == "calloc" {
                        // Fresh allocation, nothing special to track
                        return;
                    }
                }
            }

            // Check for cast expression wrapping a call
            if value.kind() == "cast_expression" {
                if let Some(inner_value) = value.child_by_field_name("value") {
                    if inner_value.kind() == "call_expression" {
                        if let Some(func) = inner_value.child_by_field_name("function") {
                            let func_name = get_node_text(&func, source);
                            let upper_func_name = func_name.to_uppercase();
                            if func_name == "realloc" || upper_func_name.contains("REALLOC") {
                                self.realloc_updated.insert(left_var.clone());
                                let old_ptrs = self.track_realloc_old_pointer(&inner_value, source);
                                if !old_ptrs.is_empty() {
                                    self.realloc_source.insert(left_var.clone(), old_ptrs);
                                }
                                return;
                            } else if func_name == "malloc" || func_name == "calloc" {
                                return;
                            }
                        }
                    }
                }
            }

            // Only a *direct* pointer copy (`T *q = p;`) aliases the same
            // storage. A subscript/field/cast initializer (`Image f =
            // imFonts[0];`) copies a value OUT of a container — freeing the
            // container (`free(imFonts)`) must NOT mark the copy freed
            // (task 232 container-vs-member; rtext.c fullFont). Restricting
            // aliasing to an identifier RHS prevents that false UAF.
            if value.kind() == "identifier" {
                let right_var = LValue::Var(get_node_text(&value, source).to_string());
                self.aliases.insert(left_var.clone(), right_var.clone());
                // If source is freed, the new variable is also freed
                if self.is_freed(&right_var) {
                    self.freed_vars.insert(left_var);
                }
            }
        }
    }

    /// Check pointer dereference (*ptr) for use-after-free
    fn check_pointer_dereference(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Skip if this is the left side of an assignment (handled separately)
        if let Some(parent) = node.parent() {
            if parent.kind() == "assignment_expression" {
                if let Some(left) = parent.child_by_field_name("left") {
                    if left.start_byte() == node.start_byte() {
                        return; // Handled in process_assignment
                    }
                }
            }
        }

        if let Some(arg) = node.child_by_field_name("argument") {
            if let Some(lv) = lvalue_of(&arg, source) {
                let var_name = LValue::Var(lv.root_var().to_string());
                if self.is_freed(&var_name) {
                    violations.push(RuleViolation {
                        rule_id: "MEM30-C".to_string(),
                        severity: Severity::Critical,
                        message: format!(
                            "Use-after-free: dereferencing freed pointer '{}'",
                            var_name.root_var()
                        ),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some("Do not access memory after freeing it.".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check array subscript access (arr[i]) for use-after-free
    fn check_subscript_access(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(arg) = node.child_by_field_name("argument") {
            let Some(lv) = lvalue_of(&arg, source) else {
                return;
            };
            // First check if the full path is freed (e.g., obj->data.values)
            if self.is_freed(&lv) {
                violations.push(RuleViolation {
                    rule_id: "MEM30-C".to_string(),
                    severity: Severity::Critical,
                    message: format!(
                        "Use-after-free: accessing freed array '{}'",
                        get_node_text(&arg, source)
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some("Do not access memory after freeing it.".to_string()),
                    ..Default::default()
                });
                return;
            }

            // Also check base variable
            let var_name = LValue::Var(lv.root_var().to_string());
            if self.is_freed(&var_name) {
                violations.push(RuleViolation {
                    rule_id: "MEM30-C".to_string(),
                    severity: Severity::Critical,
                    message: format!(
                        "Use-after-free: accessing freed array '{}'",
                        var_name.root_var()
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some("Do not access memory after freeing it.".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    /// Check binary expression for pointer arithmetic on freed memory
    fn check_binary_expression(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for ptr + n or ptr - n patterns
        if let (Some(left), Some(operator)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("operator"),
        ) {
            let op_text = get_node_text(&operator, source);
            if op_text == "+" || op_text == "-" {
                if let Some(left_var) = lvalue_of(&left, source) {
                    let left_var = LValue::Var(left_var.root_var().to_string());
                    if self.is_freed(&left_var) {
                        violations.push(RuleViolation {
                            rule_id: "MEM30-C".to_string(),
                            severity: Severity::Critical,
                            message: format!(
                                "Use-after-free: pointer arithmetic on freed pointer '{}'",
                                left_var.root_var()
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Do not use freed pointers in arithmetic.".to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check function arguments for use of freed memory
    fn check_function_args_for_freed(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                        continue;
                    }

                    if let Some(lv) = lvalue_of(&arg, source) {
                        let var_name = LValue::Var(lv.root_var().to_string());
                        if self.is_freed(&var_name) {
                            violations.push(RuleViolation {
                                rule_id: "MEM30-C".to_string(),
                                severity: Severity::Critical,
                                message: format!(
                                    "Use-after-free: passing freed pointer '{}' to function",
                                    var_name.root_var()
                                ),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(
                                    "Do not pass freed memory to functions.".to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check return statement for returning freed memory
    fn check_return_statement(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if the return value is a freed pointer
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "return" {
                    continue;
                }
                if let Some(lv) = lvalue_of(&child, source) {
                    let var_name = LValue::Var(lv.root_var().to_string());
                    if self.is_freed(&var_name) {
                        violations.push(RuleViolation {
                            rule_id: "MEM30-C".to_string(),
                            severity: Severity::Critical,
                            message: format!(
                                "Use-after-free: returning freed pointer '{}'",
                                var_name.root_var()
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Do not return freed memory from functions.".to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check for loop pattern for dangerous p = p->next after free(p)
    /// Look for the classic linked-list free error:
    /// `for (p = head; p != NULL; p = p->next) { free(p); }` — `free(p)` in
    /// the body invalidates `p` before the update clause dereferences it via
    /// `p->next`.
    fn check_for_loop_pattern(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(update) = node.child_by_field_name("update") else {
            return;
        };
        if update.kind() != "assignment_expression" {
            return;
        }
        let (Some(left), Some(right)) = (
            update.child_by_field_name("left"),
            update.child_by_field_name("right"),
        ) else {
            return;
        };
        if left.kind() != "identifier" {
            return;
        }
        let var = get_node_text(&left, source);
        // `p = p->next`-shaped advance: RHS is a field access on `p` itself.
        let advances_via_field = right.kind() == "field_expression"
            && right
                .child_by_field_name("argument")
                .is_some_and(|a| get_node_text(&a, source) == var);
        if !advances_via_field {
            return;
        }

        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let frees_var = query::find_descendants_of_kind(body, "call_expression")
            .iter()
            .any(|c| {
                c.child_by_field_name("function")
                    .is_some_and(|f| get_node_text(&f, source) == "free")
                    && c.child_by_field_name("arguments")
                        .and_then(|a| a.named_child(0))
                        .and_then(|arg| lvalue_of(&arg, source))
                        .is_some_and(|lv| lv.root_var() == var)
            });
        if frees_var {
            violations.push(RuleViolation {
                rule_id: "MEM30-C".to_string(),
                severity: Severity::Critical,
                message: format!(
                    "Use-after-free in loop: accessing '{}'->next after free({})",
                    var, var
                ),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some("Save pointer->next before freeing pointer.".to_string()),
                ..Default::default()
            });
        }
    }

    /// Check field access for use-after-free (ptr->field)
    fn check_field_access(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Skip if parent is a subscript_expression (checked in check_subscript_access)
        if let Some(parent) = node.parent() {
            if parent.kind() == "subscript_expression" {
                return;
            }
        }

        // Skip if this is inside a free() or realloc() call - handled separately
        if let Some(parent) = node.parent() {
            if parent.kind() == "argument_list" {
                if let Some(grandparent) = parent.parent() {
                    if grandparent.kind() == "call_expression" {
                        if let Some(func) = grandparent.child_by_field_name("function") {
                            let func_name = get_node_text(&func, source);
                            let upper_func_name = func_name.to_uppercase();
                            // Skip for free, realloc, and custom variants
                            if func_name == "free"
                                || func_name == "realloc"
                                || upper_func_name.contains("FREE")
                                || upper_func_name.contains("REALLOC")
                            {
                                return;
                            }
                        }
                    }
                }
            }
            // Skip if this is the left side of an assignment (handled elsewhere)
            if parent.kind() == "assignment_expression" {
                if let Some(left) = parent.child_by_field_name("left") {
                    if left.start_byte() == node.start_byte() {
                        return;
                    }
                }
            }
        }

        // Check if the full field expression is freed (e.g., buf->data) —
        // structurally, so `p->buf` and `(*p).buf` are recognized as the
        // same field regardless of spelling (task 1).
        let Some(lv) = lvalue_of(node, source) else {
            return;
        };
        if self.is_freed(&lv) {
            violations.push(RuleViolation {
                rule_id: "MEM30-C".to_string(),
                severity: Severity::Critical,
                message: format!(
                    "Use-after-free: accessing freed pointer '{}'",
                    get_node_text(node, source)
                ),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some("Do not access freed memory.".to_string()),
                ..Default::default()
            });
            return;
        }

        // Check if the base of field expression is freed
        let var_name = LValue::Var(lv.root_var().to_string());
        if self.is_freed(&var_name) {
            violations.push(RuleViolation {
                rule_id: "MEM30-C".to_string(),
                severity: Severity::Critical,
                message: format!(
                    "Use-after-free: accessing member of freed pointer '{}'",
                    var_name.root_var()
                ),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some("Do not access members of freed memory.".to_string()),
                ..Default::default()
            });
        }
    }

    /// Check if a variable is in freed state (considering aliases and realloc invalidation)
    /// Used for use-after-free detection
    fn is_freed(&self, lv: &LValue) -> bool {
        if self.nullified_vars.contains(lv) {
            return false;
        }
        if self.freed_vars.contains(lv) {
            return true;
        }
        // Check if invalidated by realloc (old pointer after realloc)
        if self.realloc_invalidated.contains(lv) {
            return true;
        }
        // Check if it's an alias of a freed or invalidated variable
        if let Some(canonical) = self.aliases.get(lv) {
            if self.nullified_vars.contains(canonical) {
                return false;
            }
            if self.freed_vars.contains(canonical) || self.realloc_invalidated.contains(canonical) {
                return true;
            }
        }
        // Check if any union member sharing this base is freed.
        // Require that `lv` is a field of `base` — not `base` itself, which
        // would incorrectly trigger on `free(base->field)` and then flag the
        // subsequent `free(base)` as a use-after-free.
        if lv.is_field() {
            if let Some(members) = self.union_members.get(lv.root_var()) {
                for member in members {
                    if self.freed_vars.contains(member) || self.realloc_invalidated.contains(member)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Check if a variable has actually been freed (not just realloc-invalidated)
    /// Used for double-free detection - it's OK to free a realloc-invalidated pointer
    fn is_actually_freed(&self, lv: &LValue) -> bool {
        if self.nullified_vars.contains(lv) {
            return false;
        }
        if self.freed_vars.contains(lv) {
            return true;
        }
        // Check if it's an alias of a freed variable (not realloc-invalidated)
        if let Some(canonical) = self.aliases.get(lv) {
            if self.nullified_vars.contains(canonical) {
                return false;
            }
            if self.freed_vars.contains(canonical) {
                return true;
            }
        }
        false
    }

    /// Track the old pointer passed to realloc as invalidated.
    /// Returns the old pointer lvalues that were invalidated (for realloc_source tracking).
    fn track_realloc_old_pointer(&mut self, call_node: &Node, source: &str) -> Vec<LValue> {
        let mut invalidated = Vec::new();
        if let Some(args) = call_node.child_by_field_name("arguments") {
            // First argument to realloc is the old pointer
            for i in 0..args.child_count() {
                if let Some(arg) = args.child(i) {
                    if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                        // For an out-param idiom like `realloc(*out, n)` or
                        // `realloc(out[i], n)` — the double/triple-pointer
                        // shape used by e.g. `get_if_names(char ***out)` —
                        // the argument is the *pointee* `*out`/`out[i]`, not
                        // `out` itself. `lvalue_of` unwraps derefs/subscripts
                        // down to the base identifier (by design, for
                        // field-sensitivity elsewhere — see points_to.rs), so
                        // without this guard the base variable `out` would
                        // be recorded as invalidated even though `out` the
                        // pointer variable was never freed; only the buffer
                        // it pointed to was. That false invalidation then
                        // self-triggers on this very same argument node when
                        // the generic traversal re-visits it as a plain
                        // dereference (`*out` is a `pointer_expression`,
                        // independently checked by `check_pointer_dereference`),
                        // reporting a UAF on the realloc call's own old-pointer
                        // read. `mark_arg_freed` already declines to track a
                        // `free(*ptr)`/`free(arr[i])` argument for the same
                        // reason (task: MEM30-C false UAF on triple-pointer
                        // out-params) — mirror that here for realloc.
                        if matches!(arg.kind(), "pointer_expression" | "subscript_expression") {
                            break;
                        }
                        // For field expressions (like im->clip->list), track the full
                        // field path since only that specific field becomes invalid;
                        // `lvalue_of` already gives exactly that for a top-level
                        // field_expression, and collapses to the base identifier for
                        // every other node kind — matching the old
                        // extract_base_variable fallback in one call.
                        let old_ptr = lvalue_of(&arg, source);

                        if let Some(old_ptr) = old_ptr {
                            // Self-realloc guard: if the old pointer already holds a
                            // realloc result (`X = realloc(X, n)`), the result is
                            // stored straight back into X, so X is not dangling. The
                            // assignment handler clears X within the statement, but
                            // the post-assignment recursion re-enters this realloc
                            // call; without this guard it would re-invalidate the
                            // just-cleared self-assigned pointer (a false UAF on the
                            // subsequent `X[i]` read). A genuine `new = realloc(old, n)`
                            // is unaffected: `old` is not in realloc_updated.
                            if self.realloc_updated.contains(&old_ptr) {
                                break;
                            }
                            // The old pointer is now potentially invalid
                            self.realloc_invalidated.insert(old_ptr.clone());
                            invalidated.push(old_ptr.clone());
                            // Also invalidate any aliases pointing to the old pointer
                            let aliases_to_invalidate: Vec<LValue> = self
                                .aliases
                                .iter()
                                .filter(|(_, v)| **v == old_ptr)
                                .map(|(k, _)| k.clone())
                                .collect();
                            for alias in aliases_to_invalidate {
                                self.realloc_invalidated.insert(alias.clone());
                                invalidated.push(alias);
                            }
                        }
                        break; // Only need the first argument
                    }
                }
            }
        }
        invalidated
    }

    /// Extract variable name from a declarator node
    fn extract_declarator_name(&self, node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => get_node_text(node, source).to_string(),
            "pointer_declarator" => {
                if let Some(declarator) = node.child_by_field_name("declarator") {
                    self.extract_declarator_name(&declarator, source)
                } else {
                    String::new()
                }
            }
            _ => {
                // Try to find an identifier child
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "identifier" {
                            return get_node_text(&child, source).to_string();
                        }
                    }
                }
                String::new()
            }
        }
    }
}

/// Returns true if `node` is a `#if 0 … #endif` preprocessor block.
/// Tree-sitter C represents this as a `preproc_if` with a `condition` field
/// whose text is the literal `0`. Code inside such a block is never compiled
/// and must not be analysed by any rule.
fn is_preproc_if_zero(node: &tree_sitter::Node, source: &str) -> bool {
    if node.kind() != "preproc_if" {
        return false;
    }
    if let Some(cond) = node.child_by_field_name("condition") {
        return get_node_text(&cond, source).trim() == "0";
    }
    false
}

/// Returns true if a C preprocessor *conditional* directive (`#if`, `#ifdef`,
/// `#ifndef`, `#elif`, `#else`, `#endif`) appears textually in `source` between
/// byte offsets `start` and `end`. Used to suppress a double-free inferred across
/// such a directive: without a preprocessor sqc cannot know whether the two free
/// sites are co-compiled or live in mutually-exclusive configurations, so their
/// raw parse order is not a sound execution sequence (task 251). `#define` /
/// `#include` and other non-conditional directives are ignored — they do not
/// gate code in or out.
fn preproc_conditional_between(source: &str, start: usize, end: usize) -> bool {
    if start >= end || end > source.len() {
        return false;
    }
    for line in source[start..end].lines() {
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let word: String = rest
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphabetic())
            .collect();
        if matches!(
            word.as_str(),
            "if" | "ifdef" | "ifndef" | "elif" | "else" | "endif"
        ) {
            return true;
        }
    }
    false
}

/// Returns true if the declarator node (e.g., an init_declarator) contains a
/// pointer_declarator or array_declarator child, meaning the variable is a
/// pointer or array rather than a scalar integer.
fn declarator_contains_pointer_or_array(node: &tree_sitter::Node) -> bool {
    query::find_first_descendant(*node, |n| {
        matches!(n.kind(), "pointer_declarator" | "array_declarator")
    })
    .is_some()
}
