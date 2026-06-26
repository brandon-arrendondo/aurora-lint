use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::FunctionMacro;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

#[derive(Default)]
pub struct Mem30C {
    /// Cross-file function-like macro definitions (from the prescan / macro
    /// engine). Used to recognize "safe free" macros that free AND null their
    /// argument (e.g. curl `Curl_safefree`).
    function_macros: RefCell<HashMap<String, FunctionMacro>>,
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
        let mut analyzer = MemoryAnalyzer::new(macro_null_params, union_typedef_names);
        analyzer.analyze_node(node, source, &mut violations);

        violations
    }
}

/// Collect the names introduced by `typedef union {...} NAME;` (or
/// `typedef union Tag NAME;`) under `node`. These let MEM30-C recognize
/// union-typed variable declarations without full type resolution.
fn collect_union_typedef_names(node: &Node, source: &str, out: &mut HashSet<String>) {
    if node.kind() == "type_definition" {
        if let Some(ty) = node.child_by_field_name("type") {
            if ty.kind() == "union_specifier" {
                let mut cursor = node.walk();
                for decl in node.children_by_field_name("declarator", &mut cursor) {
                    let name = type_identifier_name(&decl, source);
                    if !name.is_empty() {
                        out.insert(name);
                    }
                }
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_union_typedef_names(&child, source, out);
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
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" {
                let name = get_node_text(&func, source);
                if macros.contains_key(name) {
                    out.insert(name.to_string());
                }
            }
        }
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_invoked_macro_names(&child, source, macros, out);
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

    /// First scan: identify global variables at file scope
    fn scan_for_globals(&mut self, node: &Node, source: &str) {
        if is_preproc_if_zero(node, source) {
            return;
        }
        if node.kind() == "declaration" {
            // Check if this is at file scope (parent is translation_unit)
            if let Some(parent) = node.parent() {
                if parent.kind() == "translation_unit" {
                    // Extract declared variable names
                    self.extract_global_declarations(node, source);
                }
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.scan_for_globals(&child, source);
            }
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

    /// Second scan: analyze functions for free/access patterns
    fn scan_functions(&mut self, node: &Node, source: &str) {
        if is_preproc_if_zero(node, source) {
            return;
        }
        if node.kind() == "function_definition" {
            self.analyze_function_patterns(node, source);
            // Also check for recursive UAF pattern via text analysis
            self.check_recursive_uaf_text_pattern(node, source);
            // Check for realloc zero-size pattern
            self.check_realloc_noncompliant_pattern(node, source);
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.scan_functions(&child, source);
            }
        }
    }

    /// Text-based check for recursive function accessing global after recursive call
    fn check_recursive_uaf_text_pattern(&mut self, func_node: &Node, source: &str) {
        let func_name = self.get_function_name(func_node, source);
        if func_name.is_empty() {
            return;
        }

        if let Some(body) = func_node.child_by_field_name("body") {
            let body_text = get_node_text(&body, source);

            // Check if function calls itself
            let recursive_call = format!("{}(", func_name);
            if !body_text.contains(&recursive_call) {
                return;
            }

            // Check if function frees a global
            for global in &self.global_vars.clone() {
                let free_pattern = format!("free({})", global);
                if body_text.contains(&free_pattern) {
                    // Check if there's a dereference of this global AFTER the recursive call
                    // Look for pattern: recursive_call ... *global or global-> or global[
                    if let Some(rec_pos) = body_text.find(&recursive_call) {
                        let after_recursive = &body_text[rec_pos..];
                        let deref_pattern = format!("*{}", global);
                        let arrow_pattern = format!("{}->", global);
                        let subscript_pattern = format!("{}[", global);

                        if after_recursive.contains(&deref_pattern)
                            || after_recursive.contains(&arrow_pattern)
                            || after_recursive.contains(&subscript_pattern)
                        {
                            // Find approximate line number
                            let line_num = func_node.start_position().row
                                + 1
                                + body_text[..rec_pos].matches('\n').count();

                            self.recursive_patterns.push((
                                line_num,
                                1,
                                format!(
                                    "Recursive UAF: function '{}' accesses global '{}' after recursive call that may free it",
                                    func_name, global
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Check for wiki_noncompliant_3 pattern: realloc without size guard followed by free
    fn check_realloc_noncompliant_pattern(&mut self, func_node: &Node, source: &str) {
        if let Some(body) = func_node.child_by_field_name("body") {
            let body_text = get_node_text(&body, source);

            // Pattern: realloc(ptr, size_var) followed by if (NULL) { free(ptr) }
            // Without a guard like if (size != 0)

            // Check if there's a realloc call
            if !body_text.contains("realloc(") {
                return;
            }

            // Check if there's NOT a size != 0 or size > 0 guard before realloc
            let has_size_guard = body_text.contains("size != 0")
                || body_text.contains("size > 0")
                || body_text.contains("0 != size")
                || body_text.contains("0 < size");

            if has_size_guard {
                return; // Properly guarded, this is the compliant pattern
            }

            // Look for pattern: realloc(var, size_param) ... if (...NULL) { free(var) }
            // Use regex-like pattern matching
            if let Some(realloc_start) = body_text.find("realloc(") {
                let after_realloc = &body_text[realloc_start..];

                // Extract the arguments to realloc
                if let Some(paren_end) = after_realloc.find(')') {
                    let args = &after_realloc[8..paren_end]; // Skip "realloc("
                    if let Some(comma_pos) = args.find(',') {
                        let first_arg = args[..comma_pos].trim();
                        let second_arg = args[comma_pos + 1..].trim();

                        // If the size argument is clearly a constant expression, skip
                        // Look for patterns like "10 * sizeof", "sizeof", or a number
                        if self.is_constant_positive_size(second_arg) {
                            return;
                        }

                        // Check if there's a free(first_arg) after realloc
                        let free_pattern = format!("free({})", first_arg);
                        if after_realloc.contains(&free_pattern) {
                            self.realloc_zero_patterns.push((
                                func_node.start_position().row + 1,
                                1,
                                format!(
                                    "Potential double-free: realloc({}, ...) may free memory when size is 0, then free({}) is called",
                                    first_arg, first_arg
                                ),
                            ));
                        }
                    }
                }
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
        match node.kind() {
            "call_expression" => {
                self.scan_call_expression(
                    node,
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
                    node,
                    source,
                    accessed_globals,
                    has_recursive_call,
                    global_access_after_recursive,
                );
            }
            "assignment_expression" => {
                self.scan_assignment_escape(node, source, params, func_name);
            }
            _ => {}
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if is_preproc_if_zero(&child, source) {
                    continue;
                }
                self.scan_function_body(
                    &child,
                    source,
                    params,
                    freed_globals,
                    accessed_globals,
                    freed_params,
                    func_name,
                    has_longjmp,
                    has_recursive_call,
                    global_access_after_recursive,
                );
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
            if !self.is_inside_free_call(node) {
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

    fn is_inside_free_call(&self, node: &Node) -> bool {
        // Walk up to find if we're inside a free() argument list
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "argument_list" {
                // Check if the grandparent is a call to free
                if let Some(call) = parent.parent() {
                    if call.kind() == "call_expression" {
                        if let Some(func) = call.child_by_field_name("function") {
                            if func.kind() == "identifier" {
                                // Check function name - we can't access source here,
                                // so just check if we're in an argument list of a call
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

    /// Check for setjmp/longjmp UAF pattern
    /// Pattern: setjmp() followed by call to function that frees global and longjmps,
    /// with else branch accessing the freed global
    fn check_setjmp_longjmp_pattern(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for if statements with setjmp condition
        if node.kind() == "if_statement" {
            if let Some(condition) = node.child_by_field_name("condition") {
                let cond_text = get_node_text(&condition, source);
                // Check if condition involves setjmp
                if cond_text.contains("setjmp") {
                    // Check the consequence (then branch) for calls to functions that longjmp after free
                    if let Some(consequence) = node.child_by_field_name("consequence") {
                        let then_text = get_node_text(&consequence, source);

                        // Check if calls function that longjmps after freeing
                        for (func_name, freed_globals) in &self.longjmp_after_free {
                            if then_text.contains(func_name) {
                                // Check the alternative (else branch) for access to freed globals
                                if let Some(alternative) = node.child_by_field_name("alternative") {
                                    let else_text = get_node_text(&alternative, source);

                                    for global in freed_globals {
                                        // Check if global is accessed in else branch
                                        // Look for *global or global-> or global[
                                        let deref_pattern = format!("*{}", global);
                                        let arrow_pattern = format!("{}->", global);
                                        let subscript_pattern = format!("{}[", global);

                                        if else_text.contains(&deref_pattern)
                                            || else_text.contains(&arrow_pattern)
                                            || else_text.contains(&subscript_pattern)
                                        {
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
                    }
                }
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_setjmp_longjmp_pattern(&child, source, violations);
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
        if node.kind() == "function_definition" {
            if let Some(body) = node.child_by_field_name("body") {
                self.analyze_call_sequence(&body, source, violations);
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_call_sequence_violations(&child, source, violations);
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

    fn collect_calls(&self, node: &Node, source: &str, calls: &mut Vec<(String, usize, usize)>) {
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source).to_string();
                calls.push((
                    func_name,
                    node.start_position().row + 1,
                    node.start_position().column + 1,
                ));
            }
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_calls(&child, source, calls);
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

struct MemoryAnalyzer {
    // Track which variables are currently freed
    freed_vars: HashSet<String>,
    // Byte offset (start_byte) of the free site that most recently marked each
    // name freed. Consulted only on a candidate double-free, to detect whether a
    // preprocessor conditional directive separates the two free sites (task 251).
    freed_at: HashMap<String, usize>,
    // Track aliases: if alias = ptr, then aliases["alias"] = "ptr"
    aliases: HashMap<String, String>,
    // Track which variables have been set to NULL after free
    nullified_vars: HashSet<String>,
    // Track realloc old pointers that have been updated to new pointer
    realloc_updated: HashSet<String>,
    // Track realloc relationships: realloc_map[old_ptr] = new_ptr
    // When we see new_ptr = realloc(old_ptr, ...), old_ptr becomes potentially invalid
    realloc_invalidated: HashSet<String>,
    // Maps realloc result variable -> original pointers that were invalidated.
    // Used to clear invalidation in else-branches where realloc returned NULL
    // (meaning the original pointer is still valid).
    realloc_source: HashMap<String, Vec<String>>,
    // Track union members - when one member is freed, all are freed
    union_members: HashMap<String, HashSet<String>>,
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
}

impl MemoryAnalyzer {
    fn new(
        macro_null_params: HashMap<String, Vec<usize>>,
        union_typedef_names: HashSet<String>,
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
        if node.kind() == "declaration" || node.kind() == "parameter_declaration" {
            if let Some(ty) = node.child_by_field_name("type") {
                let is_union = ty.kind() == "union_specifier"
                    || (ty.kind() == "type_identifier"
                        && self
                            .union_typedef_names
                            .contains(get_node_text(&ty, source)));
                if is_union {
                    let mut cursor = node.walk();
                    for decl in node.children_by_field_name("declarator", &mut cursor) {
                        let name = self.extract_declarator_name(&decl, source);
                        if !name.is_empty() {
                            self.union_typed_vars.insert(name);
                        }
                    }
                }
            }
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.collect_union_typed_vars(&child, source);
            }
        }
    }

    /// Analyze nodes within a function
    fn analyze_function_body(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        match node.kind() {
            "if_statement" => {
                // Handle if-else with branch-sensitive analysis
                self.analyze_if_statement(node, source, violations);
                return; // Don't recurse - handled by analyze_if_statement
            }
            "call_expression" => {
                self.process_call_expression(node, source, violations);
            }
            "assignment_expression" => {
                self.process_assignment(node, source, violations);
            }
            "init_declarator" => {
                self.process_init_declarator(node, source, violations);
            }
            "pointer_expression" => {
                // Check for dereference of freed memory (*ptr)
                self.check_pointer_dereference(node, source, violations);
            }
            "subscript_expression" => {
                // Check for array access on freed memory (arr[i])
                self.check_subscript_access(node, source, violations);
                // Don't recurse into subscript - we already checked the argument
                // This prevents double-checking field expressions that are subscript arguments
                return;
            }
            "binary_expression" => {
                // Check for pointer arithmetic on freed memory (ptr + n)
                self.check_binary_expression(node, source, violations);
            }
            "return_statement" => {
                // Check for returning freed memory
                self.check_return_statement(node, source, violations);
            }
            "for_statement" => {
                // Check for dangerous loop free patterns
                self.check_for_loop_pattern(node, source, violations);
            }
            "field_expression" => {
                // Check for field access on freed memory (ptr->field)
                self.check_field_access(node, source, violations);
            }
            _ => {}
        }

        // Recursively process child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if is_preproc_if_zero(&child, source) {
                    continue;
                }
                self.analyze_function_body(&child, source, violations);
            }
        }
    }

    /// Analyze if-statement with branch-sensitive analysis
    fn analyze_if_statement(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // First analyze the condition (it's executed in the current state)
        if let Some(condition) = node.child_by_field_name("condition") {
            self.analyze_function_body(&condition, source, violations);
        }

        // Check if the condition tests a realloc result variable.
        // Pattern: if (temp) or if (temp != NULL) means then=realloc succeeded, else=failed.
        // Pattern: if (!temp) or if (temp == NULL) means then=realloc failed, else=succeeded.
        // When realloc fails (returns NULL), the original pointer is still valid.
        let realloc_null_branch = self.detect_realloc_condition_branch(node, source);

        // Save state before branches
        let saved_freed = self.freed_vars.clone();
        let saved_nullified = self.nullified_vars.clone();
        let saved_aliases = self.aliases.clone();
        let saved_realloc_updated = self.realloc_updated.clone();
        let saved_realloc_invalidated = self.realloc_invalidated.clone();

        // If the then-branch is the realloc-failed path, clear invalidation there
        if realloc_null_branch == Some(ReallocNullBranch::Then) {
            if let Some(cond) = node.child_by_field_name("condition") {
                self.clear_realloc_invalidation_for_condition(&cond, source);
            }
        }

        // Analyze the "consequence" (then branch)
        let mut then_returns = false;
        if let Some(consequence) = node.child_by_field_name("consequence") {
            self.analyze_function_body(&consequence, source, violations);
            then_returns = self.unconditionally_diverges(&consequence);
        }

        // Save state after then-branch
        let then_freed = self.freed_vars.clone();
        let then_nullified = self.nullified_vars.clone();
        let then_realloc_invalidated = self.realloc_invalidated.clone();
        let then_realloc_updated = self.realloc_updated.clone();

        // Reset state for else branch (starts from saved state)
        self.freed_vars = saved_freed.clone();
        self.nullified_vars = saved_nullified.clone();
        self.aliases = saved_aliases.clone();
        self.realloc_updated = saved_realloc_updated.clone();
        self.realloc_invalidated = saved_realloc_invalidated.clone();

        // If the else-branch is the realloc-failed path, clear invalidation there
        if realloc_null_branch == Some(ReallocNullBranch::Else) {
            if let Some(cond) = node.child_by_field_name("condition") {
                self.clear_realloc_invalidation_for_condition(&cond, source);
            }
        }

        // Analyze the "alternative" (else branch) if present
        let mut else_returns = false;
        if let Some(alternative) = node.child_by_field_name("alternative") {
            self.analyze_function_body(&alternative, source, violations);
            else_returns = self.unconditionally_diverges(&alternative);
        }

        let else_freed = self.freed_vars.clone();
        let else_nullified = self.nullified_vars.clone();
        let else_realloc_invalidated = self.realloc_invalidated.clone();
        let else_realloc_updated = self.realloc_updated.clone();

        // Merge states based on which branches return
        if then_returns && else_returns {
            // Both branches return - code after is unreachable, keep saved state
            self.freed_vars = saved_freed;
            self.nullified_vars = saved_nullified;
            self.realloc_invalidated = saved_realloc_invalidated;
            self.realloc_updated = saved_realloc_updated;
        } else if then_returns {
            // Only then returns - use else branch state
            self.freed_vars = else_freed;
            self.nullified_vars = else_nullified;
            self.realloc_invalidated = else_realloc_invalidated;
            self.realloc_updated = else_realloc_updated;
        } else if else_returns {
            // Only else returns - use then branch state
            self.freed_vars = then_freed;
            self.nullified_vars = then_nullified;
            self.realloc_invalidated = then_realloc_invalidated;
            self.realloc_updated = then_realloc_updated;
        } else {
            // Neither returns - merge states
            // For use-after-free detection: if freed in EITHER branch, it's potentially freed after
            // This ensures we catch use-after-free even on conditional frees
            self.freed_vars = then_freed;
            for var in else_freed {
                self.freed_vars.insert(var);
            }
            // But remove vars that were nullified in both branches
            for var in saved_nullified.iter() {
                if then_nullified.contains(var) && else_nullified.contains(var) {
                    self.freed_vars.remove(var);
                }
            }
            // Union of nullified
            self.nullified_vars = then_nullified;
            for var in else_nullified {
                self.nullified_vars.insert(var);
            }
            // For realloc_invalidated: use union (if invalidated in either branch, could be invalid)
            // This is conservative for detecting use-after-free
            self.realloc_invalidated = then_realloc_invalidated;
            for var in else_realloc_invalidated {
                self.realloc_invalidated.insert(var);
            }
            // Union of realloc_updated
            self.realloc_updated = then_realloc_updated;
            for var in else_realloc_updated {
                self.realloc_updated.insert(var);
            }
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
        match node.kind() {
            "return_statement" | "goto_statement" | "break_statement" | "continue_statement" => {
                true
            }
            "compound_statement" => {
                // A compound statement unconditionally diverges if its last real
                // statement diverges. Braces and trailing comments are not
                // statements: a `comment` node after `goto cleanup;` would
                // otherwise become the "last child" and defeat the check (a
                // common shape in real error branches).
                let mut last_child = None;
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() != "{" && child.kind() != "}" && child.kind() != "comment" {
                            last_child = Some(child);
                        }
                    }
                }
                if let Some(last) = last_child {
                    self.unconditionally_diverges(&last)
                } else {
                    false
                }
            }
            "if_statement" => {
                // An if-statement unconditionally returns only if BOTH branches unconditionally return
                let then_returns = node
                    .child_by_field_name("consequence")
                    .map(|c| self.unconditionally_diverges(&c))
                    .unwrap_or(false);
                let else_returns = node
                    .child_by_field_name("alternative")
                    .map(|c| self.unconditionally_diverges(&c))
                    .unwrap_or(false);
                then_returns && else_returns
            }
            _ => false,
        }
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
                let var = get_node_text(&cond, source);
                if self.realloc_updated.contains(var) {
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
                                let var = get_node_text(&inner, source);
                                if self.realloc_updated.contains(var) {
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

                    if is_null_cmp && self.realloc_updated.contains(var) {
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
        if node.kind() == "return_statement" {
            return true;
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if self.contains_return(&child) {
                    return true;
                }
            }
        }
        false
    }

    /// Process function calls - free(), malloc(), printf(), etc.
    fn process_call_expression(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            match function_name {
                "free" => {
                    self.process_free_call(node, source, violations);
                }
                "malloc" | "calloc" => {
                    // Allocation will be tracked via assignment
                }
                "realloc" => {
                    // For realloc, the original pointer may become invalid
                    // Track the old pointer as invalidated in case it's used
                    self.track_realloc_old_pointer(node, source);
                }
                _ => {
                    // Check for common free-related macros
                    let upper_name = function_name.to_uppercase();
                    if upper_name.contains("FREE")
                        || upper_name == "XFREE"
                        || upper_name == "G_FREE"
                        || upper_name == "SAFE_DELETE"
                        || upper_name == "DELETE"
                    {
                        // Treat as free() call
                        self.process_free_call(node, source, violations);
                        // "Safe free" macros (curl Curl_safefree, mosquitto
                        // mosquitto_FREE, …) also set the argument to NULL inside
                        // the macro body — invisible to us without expansion. If
                        // the macro engine flagged this macro as nulling a
                        // parameter, clear that argument's freed state, exactly
                        // as an explicit `p = NULL;` would. Phase 2c-iii.
                        if let Some(indices) = self.macro_null_params.get(function_name).cloned() {
                            self.clear_freed_for_nulled_args(node, source, &indices);
                        }
                    } else if upper_name.contains("REALLOC") {
                        // Treat as realloc() call - track old pointer as invalidated
                        // Don't check args for freed - realloc expects a possibly-allocated pointer
                        self.track_realloc_old_pointer(node, source);
                    } else {
                        // Check if any argument is a freed pointer
                        self.check_function_args_for_freed(node, source, violations);
                    }
                }
            }
        }
    }

    /// Process free() call - mark variable as freed
    fn process_free_call(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
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
            return;
        };

        // For pointer dereference expressions like free(*ptr),
        // the memory pointed to by *ptr is freed, not ptr itself.
        // Skip tracking for these complex patterns to avoid false positives.
        if arg.kind() == "pointer_expression" {
            // We're freeing *ptr, not ptr. Skip tracking.
            return;
        }

        // For subscript expressions like free(arr[i]),
        // the memory at arr[i] is freed, not arr itself.
        // Skip tracking to avoid false positives.
        if arg.kind() == "subscript_expression" {
            // We're freeing arr[i], not arr. Skip tracking.
            return;
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

        // For field expressions like free(data->name), track the full path
        // not just the base variable
        let (var_name, base_var) = if actual_arg.kind() == "field_expression" {
            let full_path = get_node_text(&actual_arg, source).to_string();
            // For union support: also track the base variable
            // When free(u.member1) is called, u.member2 also becomes invalid
            let base = self.extract_base_variable(&actual_arg, source);
            (full_path, Some(base))
        } else if actual_arg.kind() == "identifier" {
            (get_node_text(&actual_arg, source).to_string(), None)
        } else {
            // For other complex expressions, skip to avoid false positives
            return;
        };

        if var_name.is_empty() {
            return;
        }

        // Resolve to canonical name (in case of alias)
        let canonical = self.resolve_canonical(&var_name);

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
            .or_else(|| self.freed_at.get(&var_name))
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
                message: format!("Double-free: '{}' freed multiple times", var_name),
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
        self.freed_vars.insert(var_name.clone());
        // Record the free site for the preproc-split double-free check above.
        let free_byte = node.start_byte();
        self.freed_at.insert(canonical.clone(), free_byte);
        self.freed_at.insert(var_name.clone(), free_byte);

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
                    .entry(base.clone())
                    .or_default()
                    .insert(var_name.clone());
            }
        }

        // Also mark any aliases as freed
        let aliases_to_free: Vec<String> = self
            .aliases
            .iter()
            .filter(|(_, v)| **v == canonical || **v == var_name)
            .map(|(k, _)| k.clone())
            .collect();
        for alias in aliases_to_free {
            self.freed_vars.insert(alias);
        }
    }

    /// For a "safe free" macro call (frees AND nulls its argument), clear the
    /// freed state of each nulled positional argument — mirroring the macro's
    /// own `arg = NULL` (which `process_free_call` cannot see). Replicates the
    /// NULL-assignment clearing in [`process_assignment`]. Phase 2c-iii.
    fn clear_freed_for_nulled_args(&mut self, call: &Node, source: &str, indices: &[usize]) {
        let args = crate::analyze::macro_semantics::positional_args(call);
        for &idx in indices {
            let Some(arg) = args.get(idx) else { continue };
            let full_path = get_node_text(arg, source).to_string();
            if !full_path.is_empty() {
                self.nullified_vars.insert(full_path.clone());
                self.freed_vars.remove(&full_path);
                self.realloc_invalidated.remove(&full_path);
            }
            let base = self.extract_base_variable(arg, source);
            if !base.is_empty() {
                self.nullified_vars.insert(base.clone());
                self.freed_vars.remove(&base);
            }
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
            // Get full path for field expressions (e.g., im->clip->list)
            let left_full_path = get_node_text(&left, source).to_string();

            // Check if assigning NULL - this clears freed status
            let right_text = get_node_text(&right, source);
            if right_text.trim() == "NULL" || right_text.trim() == "0" {
                // For field expressions like data->name = NULL, track the full path
                self.nullified_vars.insert(left_full_path.clone());
                self.freed_vars.remove(&left_full_path);
                self.realloc_invalidated.remove(&left_full_path);

                // Also track base variable
                let left_var = self.extract_base_variable(&left, source);
                if !left_var.is_empty() {
                    self.nullified_vars.insert(left_var.clone());
                    self.freed_vars.remove(&left_var);
                }
                return;
            }

            let left_var = self.extract_base_variable(&left, source);
            if left_var.is_empty() && left_full_path.is_empty() {
                return;
            }

            // Check if this is a dereference write (*ptr = value)
            if left.kind() == "pointer_expression" {
                // This is writing through a pointer
                if let Some(arg) = left.child_by_field_name("argument") {
                    let ptr_var = self.extract_base_variable(&arg, source);
                    if !ptr_var.is_empty() && self.is_freed(&ptr_var) {
                        violations.push(RuleViolation {
                            rule_id: "MEM30-C".to_string(),
                            severity: Severity::Critical,
                            message: format!(
                                "Use-after-free: writing to freed memory via '{}'",
                                ptr_var
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some("Do not access memory after freeing it.".to_string()),
                            ..Default::default()
                        });
                    }
                }
                return;
            }

            // Check if right side is a realloc result variable
            // If we're assigning a realloc result to the original pointer (ptr = new_ptr),
            // clear the freed status since the pointer is now valid again
            let right_var = self.extract_base_variable(&right, source);
            if !right_var.is_empty() {
                // Check if right_var was the result of a realloc on left_var
                // This handles: new_ptr = realloc(ptr, ...); ptr = new_ptr;
                // Also handles: im->clip->list = more; after more = gdRealloc(im->clip->list, ...)
                if self.realloc_updated.contains(&right_var) {
                    // Clear both base variable and full path
                    self.freed_vars.remove(&left_var);
                    self.nullified_vars.remove(&left_var);
                    self.realloc_invalidated.remove(&left_var);
                    // For field expressions, also clear the full path
                    self.freed_vars.remove(&left_full_path);
                    self.nullified_vars.remove(&left_full_path);
                    self.realloc_invalidated.remove(&left_full_path);
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
                    self.freed_vars.remove(&left_full_path);
                    self.nullified_vars.remove(&left_full_path);
                    self.realloc_invalidated.remove(&left_full_path);
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
                        if !left_full_path.is_empty() && left_full_path != left_var {
                            self.realloc_updated.insert(left_full_path.clone());
                        }
                        if !old_ptrs.is_empty() {
                            self.realloc_source
                                .insert(left_var.clone(), old_ptrs.clone());
                            if !left_full_path.is_empty() && left_full_path != left_var {
                                self.realloc_source.insert(left_full_path.clone(), old_ptrs);
                            }
                        }
                        self.clear_freed_state(&left_var, &left_full_path);
                    } else if is_fresh_allocation_name(&func_name) {
                        self.clear_freed_state(&left_var, &left_full_path);
                    }
                }
            }
        }
    }

    /// Clear all freed/nullified/realloc-invalidation tracking for a variable
    /// (both its base name and full field path), e.g. after reassigning it to a
    /// fresh allocation.
    fn clear_freed_state(&mut self, base: &str, full_path: &str) {
        for key in [base, full_path] {
            if !key.is_empty() {
                self.freed_vars.remove(key);
                self.nullified_vars.remove(key);
                self.realloc_invalidated.remove(key);
            }
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
                let right_var = get_node_text(&value, source).to_string();
                if !right_var.is_empty() {
                    self.aliases.insert(left_var.clone(), right_var.clone());
                    // If source is freed, the new variable is also freed
                    if self.is_freed(&right_var) {
                        self.freed_vars.insert(left_var);
                    }
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
            let var_name = self.extract_base_variable(&arg, source);
            if !var_name.is_empty() && self.is_freed(&var_name) {
                violations.push(RuleViolation {
                    rule_id: "MEM30-C".to_string(),
                    severity: Severity::Critical,
                    message: format!("Use-after-free: dereferencing freed pointer '{}'", var_name),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some("Do not access memory after freeing it.".to_string()),
                    ..Default::default()
                });
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
            // First check if the full path is freed (e.g., obj->data.values)
            let full_path = get_node_text(&arg, source);
            if self.is_freed(&full_path) {
                violations.push(RuleViolation {
                    rule_id: "MEM30-C".to_string(),
                    severity: Severity::Critical,
                    message: format!("Use-after-free: accessing freed array '{}'", full_path),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some("Do not access memory after freeing it.".to_string()),
                    ..Default::default()
                });
                return;
            }

            // Also check base variable
            let var_name = self.extract_base_variable(&arg, source);
            if !var_name.is_empty() && self.is_freed(&var_name) {
                violations.push(RuleViolation {
                    rule_id: "MEM30-C".to_string(),
                    severity: Severity::Critical,
                    message: format!("Use-after-free: accessing freed array '{}'", var_name),
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
                let left_var = self.extract_base_variable(&left, source);
                if !left_var.is_empty() && self.is_freed(&left_var) {
                    violations.push(RuleViolation {
                        rule_id: "MEM30-C".to_string(),
                        severity: Severity::Critical,
                        message: format!(
                            "Use-after-free: pointer arithmetic on freed pointer '{}'",
                            left_var
                        ),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some("Do not use freed pointers in arithmetic.".to_string()),
                        ..Default::default()
                    });
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

                    let var_name = self.extract_base_variable(&arg, source);
                    if !var_name.is_empty() && self.is_freed(&var_name) {
                        violations.push(RuleViolation {
                            rule_id: "MEM30-C".to_string(),
                            severity: Severity::Critical,
                            message: format!(
                                "Use-after-free: passing freed pointer '{}' to function",
                                var_name
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some("Do not pass freed memory to functions.".to_string()),
                            ..Default::default()
                        });
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
                let var_name = self.extract_base_variable(&child, source);
                if !var_name.is_empty() && self.is_freed(&var_name) {
                    violations.push(RuleViolation {
                        rule_id: "MEM30-C".to_string(),
                        severity: Severity::Critical,
                        message: format!("Use-after-free: returning freed pointer '{}'", var_name),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some("Do not return freed memory from functions.".to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check for loop pattern for dangerous p = p->next after free(p)
    fn check_for_loop_pattern(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the loop text for pattern matching
        let loop_text = get_node_text(node, source);

        // Look for classic linked list free error:
        // for (p = head; p != NULL; p = p->next) { free(p); }
        if loop_text.contains("free(") && loop_text.contains("->") {
            // Check if free happens before the pointer is used in update
            // This is a heuristic check
            if let Some(update) = node.child_by_field_name("update") {
                let update_text = get_node_text(&update, source);
                // Look for patterns like: p = p->next
                if update_text.contains("->") {
                    // Check if there's a free() in the body that frees the same variable
                    if let Some(body) = node.child_by_field_name("body") {
                        let body_text = get_node_text(&body, source);
                        // Extract the variable from update (e.g., "p" from "p = p->next")
                        if let Some(eq_pos) = update_text.find('=') {
                            let var_part = update_text[..eq_pos].trim();
                            // Check if free(var) is in the body
                            let free_pattern = format!("free({})", var_part);
                            if body_text.contains(&free_pattern) {
                                violations.push(RuleViolation {
                                    rule_id: "MEM30-C".to_string(),
                                    severity: Severity::Critical,
                                    message: format!(
                                        "Use-after-free in loop: accessing '{}'->next after free({})",
                                        var_part, var_part
                                    ),
                                    file_path: String::new(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    suggestion: Some(
                                        "Save pointer->next before freeing pointer.".to_string(),
                                    ),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
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

        // Check if the full field expression is freed (e.g., buf->data)
        let full_path = get_node_text(node, source);
        if self.is_freed(&full_path) {
            violations.push(RuleViolation {
                rule_id: "MEM30-C".to_string(),
                severity: Severity::Critical,
                message: format!("Use-after-free: accessing freed pointer '{}'", full_path),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some("Do not access freed memory.".to_string()),
                ..Default::default()
            });
            return;
        }

        // Check if the base of field expression is freed
        if let Some(arg) = node.child_by_field_name("argument") {
            let var_name = self.extract_base_variable(&arg, source);
            if !var_name.is_empty() && self.is_freed(&var_name) {
                violations.push(RuleViolation {
                    rule_id: "MEM30-C".to_string(),
                    severity: Severity::Critical,
                    message: format!(
                        "Use-after-free: accessing member of freed pointer '{}'",
                        var_name
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some("Do not access members of freed memory.".to_string()),
                    ..Default::default()
                });
            }
        }
    }

    /// Check if a variable is in freed state (considering aliases and realloc invalidation)
    /// Used for use-after-free detection
    fn is_freed(&self, var_name: &str) -> bool {
        if self.nullified_vars.contains(var_name) {
            return false;
        }
        if self.freed_vars.contains(var_name) {
            return true;
        }
        // Check if invalidated by realloc (old pointer after realloc)
        if self.realloc_invalidated.contains(var_name) {
            return true;
        }
        // Check if it's an alias of a freed or invalidated variable
        if let Some(canonical) = self.aliases.get(var_name) {
            if self.nullified_vars.contains(canonical) {
                return false;
            }
            if self.freed_vars.contains(canonical) || self.realloc_invalidated.contains(canonical) {
                return true;
            }
        }
        // Check if any union member sharing this base is freed.
        // Require that var_name is `base->...` or `base.member` — not `base`
        // itself, which would incorrectly trigger on `free(base->field)` and
        // then flag the subsequent `free(base)` as a use-after-free.
        for (base, members) in &self.union_members {
            let rest = match var_name.strip_prefix(base.as_str()) {
                Some(r) => r,
                None => continue,
            };
            if !rest.starts_with("->") && !rest.starts_with('.') {
                continue; // var_name IS the base, not a member of it
            }
            for member in members {
                if self.freed_vars.contains(member) || self.realloc_invalidated.contains(member) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a variable has actually been freed (not just realloc-invalidated)
    /// Used for double-free detection - it's OK to free a realloc-invalidated pointer
    fn is_actually_freed(&self, var_name: &str) -> bool {
        if self.nullified_vars.contains(var_name) {
            return false;
        }
        if self.freed_vars.contains(var_name) {
            return true;
        }
        // Check if it's an alias of a freed variable (not realloc-invalidated)
        if let Some(canonical) = self.aliases.get(var_name) {
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
    /// Returns the old pointer names that were invalidated (for realloc_source tracking).
    fn track_realloc_old_pointer(&mut self, call_node: &Node, source: &str) -> Vec<String> {
        let mut invalidated = Vec::new();
        if let Some(args) = call_node.child_by_field_name("arguments") {
            // First argument to realloc is the old pointer
            for i in 0..args.child_count() {
                if let Some(arg) = args.child(i) {
                    if arg.kind() != "(" && arg.kind() != ")" && arg.kind() != "," {
                        // For field expressions (like im->clip->list), track the full path
                        // since only that specific field becomes invalid
                        let old_ptr = if arg.kind() == "field_expression" {
                            get_node_text(&arg, source).to_string()
                        } else {
                            self.extract_base_variable(&arg, source)
                        };

                        if !old_ptr.is_empty() {
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
                            let aliases_to_invalidate: Vec<String> = self
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

    /// Resolve a variable to its canonical name (follow alias chain)
    fn resolve_canonical(&self, var_name: &str) -> String {
        let mut current = var_name.to_string();
        let mut visited = HashSet::new();
        while let Some(target) = self.aliases.get(&current) {
            if visited.contains(target) {
                break; // Avoid infinite loop
            }
            visited.insert(current.clone());
            current = target.clone();
        }
        current
    }

    /// Extract the base variable name from various node types
    fn extract_base_variable(&self, node: &Node, source: &str) -> String {
        match node.kind() {
            "identifier" => get_node_text(node, source).to_string(),
            "pointer_expression" => {
                // *ptr - get the base pointer
                if let Some(arg) = node.child_by_field_name("argument") {
                    self.extract_base_variable(&arg, source)
                } else {
                    String::new()
                }
            }
            "field_expression" => {
                // ptr->field - get the base
                if let Some(arg) = node.child_by_field_name("argument") {
                    self.extract_base_variable(&arg, source)
                } else {
                    String::new()
                }
            }
            "subscript_expression" => {
                // arr[i] - get the base array
                if let Some(arg) = node.child_by_field_name("argument") {
                    self.extract_base_variable(&arg, source)
                } else {
                    String::new()
                }
            }
            "parenthesized_expression" => {
                // (ptr) - unwrap
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
                // (type)ptr - get the operand
                if let Some(value) = node.child_by_field_name("value") {
                    self.extract_base_variable(&value, source)
                } else {
                    String::new()
                }
            }
            _ => String::new(),
        }
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
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "pointer_declarator" | "array_declarator" => return true,
                _ => {
                    if declarator_contains_pointer_or_array(&child) {
                        return true;
                    }
                }
            }
        }
    }
    false
}
