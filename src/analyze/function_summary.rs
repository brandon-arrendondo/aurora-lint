//! Function summary computation for inter-procedural analysis.
//!
//! Computes lightweight summaries of each function's behavior during the prescan
//! phase. These summaries are used by rules to reason about callee behavior
//! without re-analyzing the callee's body.

use crate::analyze::const_eval::{self, MacroConstantMap, ValueRange, VarRangeMap};
use crate::analyze::null_state::NullState;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Summary of a function's behavior relevant to CERT C rules.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FunctionSummary {
    /// Parameter indices that this function frees (e.g., free(param[0])).
    pub frees_params: HashSet<usize>,
    /// Whether this function can return NULL.
    pub can_return_null: bool,
    /// Whether this function returns dynamically allocated memory.
    pub returns_allocation: bool,
    /// Parameter indices that this function checks for NULL.
    pub checks_null_params: HashSet<usize>,
    /// Parameter indices that this function writes through (modifies via pointer).
    pub modifies_params: HashSet<usize>,
    /// Parameter indices that this function dereferences in any way (read or write).
    /// Superset of modifies_params — includes `*param`, `param[i]`, `param->field`.
    pub dereferences_params: HashSet<usize>,
    /// Whether this function never returns (calls abort/exit/longjmp).
    pub never_returns: bool,
    /// Aggregated null states of arguments at all call sites (populated by prescan second pass).
    /// Maps parameter index → joined NullState from all callers.
    pub callsite_param_null_states: HashMap<usize, NullState>,
    /// Aggregated null states of struct fields within arguments at all call sites.
    /// Maps parameter index → field name → joined NullState from all callers.
    /// Used for variant 67 struct field null propagation across functions.
    #[serde(default)]
    pub callsite_param_field_null_states: HashMap<usize, HashMap<String, NullState>>,
    /// Aggregated null states of pointed-to values in address-of arguments.
    /// Maps parameter index → null state of the variable whose address was taken.
    /// Used for variant 63 pointer-to-pointer null propagation across functions.
    #[serde(default)]
    pub callsite_param_pointee_null_states: HashMap<usize, NullState>,
    /// Computed return value range for integer-returning functions.
    /// `Some(range)` when all return paths provably return values in [min, max].
    /// `None` for void, pointer-returning, or unevaluable return expressions.
    pub return_range: Option<ValueRange>,
    /// Parameter pass-through: which of this function's params are forwarded to
    /// callees. Maps caller_param_idx → Vec<(callee_name, callee_param_idx)>.
    /// Used for transitive free propagation (MEM31-C).
    #[serde(default)]
    pub param_passthroughs: HashMap<usize, Vec<(String, usize)>>,
    /// Struct field names freed directly off a parameter within this function's
    /// body, e.g. `free(param->name)` or `free((*param)->name)`. Maps
    /// param_idx → set of field names. Lets MEM31-C credit a custom
    /// deallocator (e.g. `destroy_person(&p)`) with freeing `p->name` even
    /// though the free happens inside the callee, not the caller (task 2:
    /// MEM31-C ownership model).
    #[serde(default)]
    pub frees_param_fields: HashMap<usize, HashSet<String>>,
    /// True if the function body contains a call to a known taint-source
    /// function (recv, fgets, scanf, getenv, ...). Used by ENV03-C to
    /// decide whether a helper function's callers are passing in
    /// externally-controlled data.
    #[serde(default)]
    pub has_env03_taint_source: bool,
    /// True if this function's return value may carry externally-controlled
    /// data. Seeded from `has_env03_taint_source` for non-void returns, then
    /// propagated to fixpoint through `returns_from_callees` so a wrapper
    /// like `char *wrap() { return readIt(); }` is also marked tainted.
    #[serde(default)]
    pub returns_tainted: bool,
    /// Names of callees whose return values flow directly to a `return`
    /// statement in this function's body. Used for transitive return-value
    /// taint propagation in prescan.
    #[serde(default)]
    pub returns_from_callees: HashSet<String>,
    /// True if this function calls strcpy/strcat/wcscpy/wcscat with a second
    /// argument that is a known non-absolute-path macro (e.g.,
    /// `BAD_OS_COMMAND = "ls -la"`). Used by ENV03-C's caller-aware
    /// suppression: a sink's callers that set relative-path commands are NOT
    /// clean, regardless of `has_env03_taint_source`.
    #[serde(default)]
    pub has_relative_command_write: bool,
    /// Integer constant values for parameters where ALL call sites within the
    /// project pass the same constant literal. Maps parameter index → value.
    /// Absent entry means callers disagree or pass non-constant arguments.
    /// Used by VRA to narrow parameter entry ranges so integer overflow rules
    /// suppress goodG2B-style FPs where data is provably a small constant.
    #[serde(default)]
    pub callsite_param_const_int: HashMap<usize, i64>,
    /// Minimum element-count buffer size passed by callers at each parameter
    /// position, recorded only when EVERY call site within the project passes a
    /// pointer to a buffer of statically-known size. Absent when any caller
    /// passes an unresolvable buffer, or the function is header-declared (so
    /// external callers are unknown). Used by STR31-C to prove a parameter
    /// destination is large enough for the copied content and suppress the
    /// cross-function goodG2BSink false positives (Juliet variants 41+).
    #[serde(default)]
    pub callsite_param_buffer_size: HashMap<usize, usize>,
}

/// Names of functions that read externally-controlled data into their
/// arguments or return values. A function whose body calls any of these
/// is treated as a potential taint origin for ENV03-C caller analysis.
/// Keep in sync with `env03_c::TAINT_SOURCES`.
pub const ENV03_TAINT_SOURCE_FUNCTIONS: &[&str] = &[
    "recv",
    "recvfrom",
    "recvmsg",
    "WSARecv",
    "WSARecvFrom",
    "accept",
    "read",
    "fread",
    "fgets",
    "gets",
    "getchar",
    "getc",
    "fgetc",
    "scanf",
    "fscanf",
    "sscanf",
    "vscanf",
    "vfscanf",
    // Wide-character input — mirror the narrow-char taint sources.
    // Juliet's wchar_t_console / wchar_t_file variants read via fgetws,
    // and without these the caller's summary is (incorrectly) clean,
    // causing caller-aware suppression to drop the bad-path TP.
    "fgetws",
    "getwchar",
    "getwc",
    "fgetwc",
    "wscanf",
    "fwscanf",
    "swscanf",
    "vwscanf",
    "vfwscanf",
    "_getws",
    "_getws_s",
    "getenv",
    "secure_getenv",
    "_wgetenv",
    "_wgetenv_s",
    "ReadFile",
    "ReadConsole",
    "ReadConsoleA",
    "ReadConsoleW",
    "RegQueryValueExA",
    "RegQueryValueExW",
];

fn body_contains_taint_source(body_text: &str) -> bool {
    ENV03_TAINT_SOURCE_FUNCTIONS
        .iter()
        .any(|name| body_text.contains(&format!("{}(", name)))
}

fn body_contains_alias(body_text: &str, aliases: &[String]) -> bool {
    aliases
        .iter()
        .any(|alias| body_text.contains(&format!("{}(", alias)))
}

/// True if the function body calls strcpy/strcat/wcscpy/wcscat with a second
/// argument that is a macro identifier whose string value is a non-absolute path.
/// Detects CWE-426 patterns like `strcpy(data, BAD_OS_COMMAND)` where
/// `BAD_OS_COMMAND = "ls -la"`.
fn body_has_relative_command_write(
    body: &Node,
    source: &str,
    string_macros: &HashMap<String, String>,
) -> bool {
    let mut found = false;
    walk_for_relative_command_write(body, source, string_macros, &mut found);
    found
}

fn walk_for_relative_command_write(
    node: &Node,
    source: &str,
    string_macros: &HashMap<String, String>,
    found: &mut bool,
) {
    if *found {
        return;
    }
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            let raw = func.utf8_text(source.as_bytes()).unwrap_or("");
            let ident = raw
                .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
                .unwrap_or(raw);
            if matches!(
                ident,
                "strcpy"
                    | "strcat"
                    | "stncpy"
                    | "strncat"
                    | "wcscpy"
                    | "wcscat"
                    | "wcsncpy"
                    | "wcsncat"
            ) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    let named: Vec<_> = (0..args.child_count())
                        .filter_map(|i| args.child(i))
                        .filter(|c| c.is_named())
                        .collect();
                    // Second named arg is the source string for str/wcs copy/cat
                    if let Some(second) = named.get(1) {
                        let s = *second;
                        if s.kind() == "identifier" {
                            let nm = s.utf8_text(source.as_bytes()).unwrap_or("");
                            if const_eval::is_relative_command_macro(string_macros, nm) {
                                *found = true;
                                return;
                            }
                        }
                    }
                }
            }
        }
        // Don't recurse into call_expression arguments here — the call
        // itself was checked; inner calls are handled by the outer loop.
        return;
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            // Don't cross into a nested (swallowed-sibling) function boundary.
            if is_real_nested_function_definition(&child, source) {
                continue;
            }
            walk_for_relative_command_write(&child, source, string_macros, found);
            if *found {
                return;
            }
        }
    }
}

/// Compute function summaries for all function definitions in the AST.
///
/// When `compute_return_ranges` is true, also computes return value ranges
/// for integer-returning functions (needed for VRA inter-procedural analysis).
/// Pass false during prescan when no VRA-consuming rules are enabled.
pub fn compute_summaries(
    root: &Node,
    source: &str,
    macros: &MacroConstantMap,
    compute_return_ranges: bool,
    taint_source_aliases: &[String],
    string_macros: &HashMap<String, String>,
) -> HashMap<String, FunctionSummary> {
    let mut summaries = HashMap::new();

    collect_function_summaries(
        root,
        source,
        macros,
        compute_return_ranges,
        taint_source_aliases,
        string_macros,
        &mut summaries,
    );

    summaries
}

fn collect_function_summaries(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    compute_return_ranges: bool,
    taint_source_aliases: &[String],
    string_macros: &HashMap<String, String>,
    summaries: &mut HashMap<String, FunctionSummary>,
) {
    if node.kind() == "function_definition" && !is_macro_function_definition(node) {
        if let Some(name) = extract_function_name(node, source) {
            let summary = analyze_function(
                node,
                source,
                macros,
                compute_return_ranges,
                taint_source_aliases,
                string_macros,
            );
            summaries.insert(name, summary);
        }
    }

    // Recurse into every child unconditionally, not just preproc wrappers.
    // A brace that opens and closes in different branches of the same
    // repeated #ifdef guard makes tree-sitter-c's preprocessor-less parse
    // swallow every subsequent sibling function_definition as a nested
    // descendant of the corrupted one (see `is_real_nested_function_definition`
    // and lang_parsing_substrate::calls, which hit the identical failure
    // mode for call-graph edges). Stopping at preproc_* children only would
    // leave every swallowed sibling permanently invisible to this map — a
    // silent false-negative for every interprocedural rule keyed on
    // FunctionSummary (MSC04-C, EXP34-C, MEM30/31-C, null-state, taint).
    // Recursing everywhere instead still finds and summarizes it under its
    // own name, even though it's nested in the AST.
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            collect_function_summaries(
                &child,
                source,
                macros,
                compute_return_ranges,
                taint_source_aliases,
                string_macros,
                summaries,
            );
        }
    }
}

/// True when a `function_definition` node is actually a macro invocation
/// mis-parsed as one (declarator is a parenthesized macro call like
/// `DEFINE_HANDLER(foo) { ... }`), not a real function.
fn is_macro_function_definition(node: &Node) -> bool {
    node.kind() == "function_definition"
        && node
            .child_by_field_name("declarator")
            .map(|d| d.kind() == "parenthesized_declarator")
            .unwrap_or(false)
}

/// True when `node` is a `function_definition` that represents a genuine
/// nested function boundary and not tree-sitter error-recovery debris (a
/// keyword like `if`/`while` mis-parsed as a nameless function whose "name"
/// resolves to the keyword itself) or a macro-invocation function_definition.
/// C has no real nested functions, so any node satisfying this while walking
/// another function's body is swallowed sibling content from a corrupted
/// parse and must not be treated as part of the enclosing function's own
/// summary — mirrors `lang_parsing_substrate::calls`'s identical guard for
/// call-graph edges.
fn is_real_nested_function_definition(node: &Node, source: &str) -> bool {
    if node.kind() != "function_definition" || is_macro_function_definition(node) {
        return false;
    }
    match extract_function_name(node, source) {
        Some(name) => !is_c_keyword(&name),
        None => true,
    }
}

fn is_c_keyword(name: &str) -> bool {
    matches!(
        name,
        "if" | "else"
            | "for"
            | "while"
            | "do"
            | "switch"
            | "case"
            | "default"
            | "return"
            | "break"
            | "continue"
            | "goto"
            | "sizeof"
            | "typedef"
            | "struct"
            | "union"
            | "enum"
    )
}

/// Finds the start byte of the first real nested `function_definition`
/// inside `node`'s subtree (`node` itself excluded), if any. Only meaningful
/// to call when `node.has_error()` — see `is_real_nested_function_definition`.
fn find_nested_function_boundary(node: &Node, source: &str) -> Option<usize> {
    for i in 0..node.child_count() {
        let child = node.child(i)?;
        if is_real_nested_function_definition(&child, source) {
            return Some(child.start_byte());
        }
        if let Some(boundary) = find_nested_function_boundary(&child, source) {
            return Some(boundary);
        }
    }
    None
}

/// Analyze a single function definition to produce its summary.
///
/// `taint_source_aliases` names any macro identifier whose target resolves to
/// a taint source (e.g. `#define GETENV getenv`) — treated as additional
/// text-scan keywords when computing `has_env03_taint_source`.
fn analyze_function(
    func_node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    compute_return_ranges: bool,
    taint_source_aliases: &[String],
    string_macros: &HashMap<String, String>,
) -> FunctionSummary {
    let mut summary = FunctionSummary::default();

    // Collect parameter names
    let params = collect_param_names(func_node, source);

    // Check the return type
    let is_pointer_return;
    let is_void_return;
    if let Some(return_type) = func_node.child_by_field_name("type") {
        let type_text = return_type.utf8_text(source.as_bytes()).unwrap_or("");
        // Functions returning pointer types might return NULL
        let decl_text = func_node
            .child_by_field_name("declarator")
            .map(|d| d.utf8_text(source.as_bytes()).unwrap_or(""))
            .unwrap_or("");
        is_pointer_return = decl_text.contains('*');
        is_void_return = type_text == "void";
        if is_pointer_return {
            // Could return NULL unless proven otherwise
            summary.can_return_null = true;
        }
        // void functions can't return NULL
        if is_void_return {
            summary.can_return_null = false;
        }
    } else {
        is_pointer_return = false;
        is_void_return = false;
    }

    // Analyze function body
    if let Some(body) = func_node.child_by_field_name("body") {
        // When the body's parse contains an error, it may be a case of the
        // brace-in-different-#ifdef-branches corruption: this function's
        // span swallowed a subsequent sibling as a nested function_definition
        // descendant. Bound the plain text scans below to the source before
        // that boundary so this function's summary isn't polluted with the
        // swallowed sibling's content (which gets its own, correctly-scoped
        // summary via `collect_function_summaries`'s unconditional recursion).
        // The AST-walking helpers below (check_never_returns is text-only;
        // the rest take `body` directly) each stop at the same boundary via
        // `is_real_nested_function_definition`, independent of this text
        // bound, so this stays correct even if boundary detection here ever
        // disagrees with theirs.
        let text_end = if body.has_error() {
            find_nested_function_boundary(&body, source).unwrap_or_else(|| body.end_byte())
        } else {
            body.end_byte()
        };
        let body_text = &source[body.start_byte()..text_end];

        // Check for never-returns patterns
        summary.never_returns = check_never_returns(body_text);

        // Check for returns-allocation pattern
        summary.returns_allocation = body_text.contains("malloc(")
            || body_text.contains("calloc(")
            || body_text.contains("realloc(")
            || body_text.contains("aligned_alloc(");

        // Quick text scan for taint-source calls — used by ENV03-C to
        // classify callers as tainted/clean. Also matches any macro
        // identifier that aliases a known taint source (e.g.
        // `#define GETENV getenv`) so Juliet macro-wrapped sources still
        // poison the caller's summary.
        summary.has_env03_taint_source = body_contains_taint_source(body_text)
            || body_contains_alias(body_text, taint_source_aliases);

        // Detect CWE-426-style relative-path command writes: strcpy/strcat
        // with a macro identifier whose value is a known non-absolute path.
        // Used alongside `has_env03_taint_source` to prevent caller-aware
        // suppression from masking CWE-426 sinks.
        if !string_macros.is_empty() {
            summary.has_relative_command_write =
                body_has_relative_command_write(&body, source, string_macros);
        }

        // Seed return-value taint: a function that directly calls a taint
        // source and returns non-void may carry that taint back to callers.
        // Refined in the cross-function fixpoint pass.
        if !is_void_return {
            summary.returns_tainted = summary.has_env03_taint_source;
        }

        // Collect callees whose returns flow directly to this function's
        // return statements. Consumed by `propagate_return_taint` after all
        // summaries are computed.
        collect_returns_from_callees(&body, source, &mut summary.returns_from_callees);

        // Check for NULL return
        if !summary.can_return_null {
            // Even non-pointer return types: check if the function returns NULL
            summary.can_return_null = check_returns_null(&body, source);
        }

        // For pointer-returning functions: if every return statement provably
        // returns a non-null value (e.g. `return &s_switches`), clear the
        // pessimistic can_return_null flag set above.
        if is_pointer_return && summary.can_return_null {
            if check_all_returns_nonnull(&body, source) {
                summary.can_return_null = false;
            }
        }

        // Analyze parameter usage
        analyze_param_usage(&body, source, body_text, &params, &mut summary);

        // Compute return value range for integer-returning functions (only when VRA is needed)
        if compute_return_ranges && !is_void_return && !is_pointer_return {
            summary.return_range = compute_return_range(&body, source, macros);
        }
    }

    summary
}

/// Collect parameter names from a function declaration.
pub fn collect_param_names(func_node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(declarator) = func_node.child_by_field_name("declarator") {
        collect_params_recursive(&declarator, source, &mut params);
    }

    params
}

fn collect_params_recursive(node: &Node, source: &str, params: &mut Vec<String>) {
    if node.kind() == "function_declarator" {
        if let Some(param_list) = node.child_by_field_name("parameters") {
            for i in 0..param_list.child_count() {
                if let Some(param) = param_list.child(i) {
                    if param.kind() == "parameter_declaration" {
                        if let Some(decl) = param.child_by_field_name("declarator") {
                            let name = extract_leaf_identifier(&decl, source);
                            params.push(name);
                        } else {
                            params.push(String::new()); // Unnamed parameter
                        }
                    }
                }
            }
        }
    } else {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                collect_params_recursive(&child, source, params);
            }
        }
    }
}

/// Check if a function body always calls abort/exit/longjmp (never returns normally).
fn check_never_returns(body_text: &str) -> bool {
    // Quick text check — if none of these are present, the function can return
    if !body_text.contains("abort(")
        && !body_text.contains("exit(")
        && !body_text.contains("_Exit(")
        && !body_text.contains("longjmp(")
        && !body_text.contains("quick_exit(")
    {
        return false;
    }

    // More precise: check if every code path ends with a no-return call.
    // For simplicity, check if the function's body ends with a no-return call
    // (last statement is abort/exit/etc. — no return statement after it).
    let has_return = body_text.contains("return ");
    let ends_with_noreturn = body_text.contains("abort()")
        || body_text.contains("exit(EXIT_FAILURE)")
        || body_text.contains("exit(1)")
        || body_text.contains("exit(EXIT_SUCCESS)")
        || body_text.contains("exit(0)");

    // If the function has no return statements and ends with a no-return call
    if !has_return && ends_with_noreturn {
        return true;
    }

    // Simple heuristic: if every path through the function ends with
    // abort/exit, it never returns. This is too expensive to check fully
    // without a CFG, so we use a conservative approach.
    false
}

/// Check if a function body contains any `return NULL` / `return 0` statements.
/// Returns true when every `return` statement in `body` provably returns a non-null
/// value. Currently recognises `return &expr` (address-of — always non-null).
/// Returns false conservatively if ANY return path is not recognised as non-null,
/// or if there are no return statements.
fn check_all_returns_nonnull(body: &Node, source: &str) -> bool {
    let mut found_any = false;
    let result = check_returns_all_nonnull_recursive(body, source, &mut found_any);
    found_any && result
}

/// Recursive helper: returns (all_nonnull) and populates found_any.
fn check_returns_all_nonnull_recursive(node: &Node, source: &str, found_any: &mut bool) -> bool {
    if node.kind() == "return_statement" {
        *found_any = true;
        // Check if the returned value is provably non-null
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "return" || child.kind() == ";" {
                    continue;
                }
                // `return &expr` — address-of is always non-null
                if child.kind() == "pointer_expression" {
                    if let Some(op) = child.child_by_field_name("operator") {
                        if op.utf8_text(source.as_bytes()).unwrap_or("") == "&" {
                            return true;
                        }
                    }
                }
                // Text-level: `return &identifier`
                let text = child.utf8_text(source.as_bytes()).unwrap_or("").trim();
                if text.starts_with('&') {
                    return true;
                }
                return false;
            }
        }
        return false;
    }

    // Don't cross nested function definitions
    if node.kind() == "function_definition" {
        return true; // Neutral for parent's all-nonnull check
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if !check_returns_all_nonnull_recursive(&child, source, found_any) {
                return false;
            }
        }
    }
    true
}

fn check_returns_null(body: &Node, source: &str) -> bool {
    if body.kind() == "return_statement" {
        for i in 0..body.child_count() {
            if let Some(child) = body.child(i) {
                if child.kind() != "return" {
                    let text = child.utf8_text(source.as_bytes()).unwrap_or("").trim();
                    if text == "NULL" || text == "0" || text == "nullptr" {
                        return true;
                    }
                }
            }
        }
    }

    for i in 0..body.child_count() {
        if let Some(child) = body.child(i) {
            // Don't cross into a nested (swallowed-sibling) function boundary.
            if is_real_nested_function_definition(&child, source) {
                continue;
            }
            if check_returns_null(&child, source) {
                return true;
            }
        }
    }

    false
}

/// Analyze how parameters are used in the function body. `body_text` may be
/// a boundary-truncated slice of `body`'s source (see `analyze_function`);
/// `collect_param_passthroughs` walks `body` itself and applies its own
/// nested-function boundary guard independently.
fn analyze_param_usage(
    body: &Node,
    source: &str,
    body_text: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    for (idx, param_name) in params.iter().enumerate() {
        if param_name.is_empty() {
            continue;
        }

        // Check if parameter is freed
        if body_text.contains(&format!("free({})", param_name))
            || body_text.contains(&format!("free( {} )", param_name))
        {
            summary.frees_params.insert(idx);
        }

        // Check if parameter is null-checked.
        // Handles all spacings and both NULL/0/nullptr literals since C
        // allows any of these to denote the null pointer.
        //
        // Also recognizes alias null-checks: `TYPE *alias = param;` followed
        // by a null check on `alias` logically null-checks `param` too.
        // Common in libcurl/sqlite wrappers that cast-copy the param first.
        if body_matches_null_check(body_text, param_name)
            || body_matches_alias_null_check(body_text, param_name)
        {
            summary.checks_null_params.insert(idx);
        }

        // Check if parameter is written through (dereferenced on left side of assignment)
        if body_text.contains(&format!("*{} =", param_name))
            || body_text.contains(&format!("{}->", param_name))
            || body_text.contains(&format!("{}[", param_name))
        {
            summary.modifies_params.insert(idx);
        }

        // Check if parameter is dereferenced in any way (read or write)
        if body_text.contains(&format!("*{}", param_name))
            || body_text.contains(&format!("{}->", param_name))
            || body_text.contains(&format!("{}[", param_name))
            // Cast-then-deref pattern: (type *)param — used for void* params
            // where the cast result is subsequently dereferenced.
            || body_text.contains(&format!("*){}", param_name))
        {
            summary.dereferences_params.insert(idx);
        }
    }

    // Detect param pass-through: when a parameter is forwarded to a callee
    collect_param_passthroughs(body, source, params, summary);

    // Detect direct field frees off a parameter: free(param->field) or
    // free((*param)->field) (the double-pointer-deref idiom used by
    // `void destroy(T **param)` style destructors).
    collect_frees_param_fields(body, source, params, summary);
}

/// Scan for `free(...)`-shaped calls whose argument is a field access rooted
/// in one of `params` (via `points_to::lvalue_of`, which unwraps
/// `*`/parens/casts), recording the arrow-joined field chain (e.g. `"will"`
/// or `"will->topic"`) against that parameter's index. AST-based (unlike the
/// sibling `free(param)` text scan above) because the chain must be
/// extracted precisely, not just detected.
///
/// Matches literal `free` as well as any call whose name matches
/// `ast_utils::is_deallocation_call_name` (destroy_*/free_*/..._free/etc.),
/// since real-world code overwhelmingly wraps `free` in a macro or helper
/// (e.g. mosquitto's `#define mosquitto_FREE(A) do{ mosquitto_free(A); (A) =
/// NULL; }while(0)`) rather than calling it directly — sqc has no
/// preprocessor, so the macro call itself is the only AST evidence available
/// (task 2: MEM31-C ownership model).
fn collect_frees_param_fields(
    body: &Node,
    source: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    use crate::analyze::points_to::LValue;
    use crate::utility::cert_c::ast_utils;
    use lang_parsing_substrate::query;

    // Flatten a field-access chain into (root variable, arrow-joined field
    // path), e.g. `m->will->topic` -> ("m", "will->topic").
    fn flatten(lv: &LValue) -> (String, Vec<String>) {
        match lv {
            LValue::Var(name) => (name.clone(), Vec::new()),
            LValue::Field(base, field) => {
                let (root, mut fields) = flatten(base);
                fields.push(field.clone());
                (root, fields)
            }
        }
    }

    for call in query::find_descendants_of_kind(*body, "call_expression") {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        let func_name = function.utf8_text(source.as_bytes()).unwrap_or("");
        if func_name != "free" && !ast_utils::is_deallocation_call_name(func_name) {
            continue;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            let Some(lv) = crate::analyze::points_to::lvalue_of(&arg, source) else {
                continue;
            };
            let (root_name, fields) = flatten(&lv);
            if fields.is_empty() {
                continue;
            }
            let Some(idx) = params.iter().position(|p| p == &root_name) else {
                continue;
            };
            summary
                .frees_param_fields
                .entry(idx)
                .or_default()
                .insert(fields.join("->"));
        }
    }
}

/// Match a null-check expression on `param_name` anywhere in `body_text`.
///
/// Recognizes all spacings of `PARAM op LIT` / `LIT op PARAM` where op is
/// `==`/`!=` and LIT is `NULL`/`0`/`nullptr`, plus the `!PARAM` unary form.
/// Guards against false matches on substrings (e.g., `foo` matching inside
/// `foobar`) via word-boundary checks.
fn body_matches_null_check(body_text: &str, param_name: &str) -> bool {
    // Fast reject: body must at least contain the param name
    if !body_text.contains(param_name) {
        return false;
    }

    // `!{param}` — matches the unary negation null-check idiom
    if contains_word_after_prefix(body_text, "!", param_name) {
        return true;
    }

    for op in ["==", "!="] {
        for lit in ["NULL", "0", "nullptr"] {
            // PARAM op LIT — various spacings
            if contains_word_with_op(body_text, param_name, op, lit) {
                return true;
            }
            // LIT op PARAM — various spacings
            if contains_lit_with_op_word(body_text, lit, op, param_name) {
                return true;
            }
        }
    }

    false
}

/// True if `text` contains `prefix` immediately followed by `word` at a
/// word boundary (prev char not identifier-continuing, next char not
/// identifier-continuing). Used for `!PARAM`.
fn contains_word_after_prefix(text: &str, prefix: &str, word: &str) -> bool {
    let needle = format!("{}{}", prefix, word);
    let bytes = text.as_bytes();
    let needle_bytes = needle.as_bytes();
    let mut start = 0;
    while start + needle_bytes.len() <= bytes.len() {
        if let Some(pos) = text[start..].find(&needle) {
            let absolute = start + pos;
            let after = absolute + needle_bytes.len();
            let next_is_ident = bytes
                .get(after)
                .map(|b| is_ident_continue(*b))
                .unwrap_or(false);
            if !next_is_ident {
                return true;
            }
            start = absolute + 1;
        } else {
            break;
        }
    }
    false
}

/// True if `text` contains `word` followed by `op` and `lit`, with word
/// boundaries around the identifiers and arbitrary whitespace between tokens.
/// Uses a hand-rolled scan to avoid pulling in a regex dep for one pattern.
fn contains_word_with_op(text: &str, word: &str, op: &str, lit: &str) -> bool {
    let bytes = text.as_bytes();
    let word_bytes = word.as_bytes();
    let mut start = 0;
    while start + word_bytes.len() <= bytes.len() {
        let pos = match text[start..].find(word) {
            Some(p) => start + p,
            None => break,
        };
        // Word boundary before
        let prev_is_ident = if pos == 0 {
            false
        } else {
            is_ident_continue(bytes[pos - 1])
        };
        let after = pos + word_bytes.len();
        let next_is_ident = bytes
            .get(after)
            .map(|b| is_ident_continue(*b))
            .unwrap_or(false);
        if !prev_is_ident && !next_is_ident {
            // Skip whitespace, then op, then whitespace, then lit (with word boundary after if applicable)
            let mut idx = after;
            while idx < bytes.len() && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
                idx += 1;
            }
            if bytes[idx..].starts_with(op.as_bytes()) {
                idx += op.len();
                while idx < bytes.len() && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
                    idx += 1;
                }
                if bytes[idx..].starts_with(lit.as_bytes()) {
                    let lit_end = idx + lit.len();
                    let next = bytes
                        .get(lit_end)
                        .map(|b| is_ident_continue(*b))
                        .unwrap_or(false);
                    if !next {
                        return true;
                    }
                }
            }
        }
        start = pos + 1;
    }
    false
}

/// Symmetric to `contains_word_with_op` but with `lit` on the left, `word` on the right.
fn contains_lit_with_op_word(text: &str, lit: &str, op: &str, word: &str) -> bool {
    let bytes = text.as_bytes();
    let lit_bytes = lit.as_bytes();
    let mut start = 0;
    while start + lit_bytes.len() <= bytes.len() {
        let pos = match text[start..].find(lit) {
            Some(p) => start + p,
            None => break,
        };
        let prev_is_ident = if pos == 0 {
            false
        } else {
            is_ident_continue(bytes[pos - 1])
        };
        let after = pos + lit_bytes.len();
        let next_is_ident = bytes
            .get(after)
            .map(|b| is_ident_continue(*b))
            .unwrap_or(false);
        if !prev_is_ident && !next_is_ident {
            let mut idx = after;
            while idx < bytes.len() && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
                idx += 1;
            }
            if bytes[idx..].starts_with(op.as_bytes()) {
                idx += op.len();
                while idx < bytes.len() && (bytes[idx] == b' ' || bytes[idx] == b'\t') {
                    idx += 1;
                }
                if bytes[idx..].starts_with(word.as_bytes()) {
                    let word_end = idx + word.len();
                    let next = bytes
                        .get(word_end)
                        .map(|b| is_ident_continue(*b))
                        .unwrap_or(false);
                    if !next {
                        return true;
                    }
                }
            }
        }
        start = pos + 1;
    }
    false
}

fn is_ident_continue(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Detect alias null-check patterns: `TYPE *alias = param;` (or
/// `alias = param;`) followed by a null check on `alias`. Common in
/// libcurl/sqlite wrappers that cast-copy the pointer param first, then
/// null-check the copy (e.g. `struct Curl_easy *data = d; if(!data) ...`).
fn body_matches_alias_null_check(body_text: &str, param_name: &str) -> bool {
    // Scan for `= param_name` occurrences. Each is a candidate assignment.
    // Then find the alias identifier (LHS of that assignment) and check if
    // the body has a null check on the alias.
    let bytes = body_text.as_bytes();
    let mut search_from = 0;
    while search_from < bytes.len() {
        // Find `= param_name` — plain assignment. Must be preceded by non-`=`
        // (to exclude `==`, `!=`) and followed by `;`, `,`, or `)`.
        let needle = format!("= {}", param_name);
        let pos = match body_text[search_from..].find(&needle) {
            Some(p) => search_from + p,
            None => break,
        };
        search_from = pos + 1;

        // Preceded by `=`, `!`, `<`, `>` → not a simple assignment
        if pos > 0 {
            let prev = bytes[pos - 1];
            if prev == b'=' || prev == b'!' || prev == b'<' || prev == b'>' {
                continue;
            }
        }
        let after = pos + needle.len();
        // Must end the identifier: next char not identifier-continuing
        let next = bytes.get(after).copied().unwrap_or(0);
        if is_ident_continue(next) {
            continue;
        }
        // Must be a statement terminator within a few chars
        if next != b';' && next != b',' && next != b')' && !next.is_ascii_whitespace() {
            continue;
        }

        // Scan backward from pos to find the LHS identifier: skip whitespace,
        // then read identifier chars. Stop at `=` / `(` / `,` / `;` / `*`.
        let mut end = pos;
        while end > 0 && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
            end -= 1;
        }
        let lhs_end = end;
        while end > 0 && is_ident_continue(bytes[end - 1]) {
            end -= 1;
        }
        let lhs_start = end;
        if lhs_start >= lhs_end {
            continue;
        }
        let alias = &body_text[lhs_start..lhs_end];
        if alias == param_name {
            continue;
        }
        // Sanity: alias must start with a letter/underscore
        if !matches!(alias.as_bytes()[0], b'a'..=b'z' | b'A'..=b'Z' | b'_') {
            continue;
        }

        // Now check if the body null-checks the alias
        if body_matches_null_check(body_text, alias) {
            return true;
        }
    }
    false
}

/// Detect param pass-through patterns: when a function parameter is directly
/// forwarded as an argument to a callee. Used for transitive free propagation.
fn collect_param_passthroughs(
    node: &Node,
    source: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    if node.kind() == "call_expression" {
        if let Some(func_node) = node.child_by_field_name("function") {
            let callee_name = func_node
                .utf8_text(source.as_bytes())
                .unwrap_or("")
                .to_string();
            // Skip free/realloc — already handled by frees_params
            if !callee_name.is_empty() && callee_name != "free" && callee_name != "realloc" {
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    let mut callee_idx = 0usize;
                    for i in 0..arguments.child_count() {
                        if let Some(arg) = arguments.child(i) {
                            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                                continue;
                            }
                            if arg.kind() == "identifier" {
                                let arg_text = arg.utf8_text(source.as_bytes()).unwrap_or("");
                                for (param_idx, param_name) in params.iter().enumerate() {
                                    if !param_name.is_empty() && arg_text == param_name {
                                        summary
                                            .param_passthroughs
                                            .entry(param_idx)
                                            .or_default()
                                            .push((callee_name.clone(), callee_idx));
                                    }
                                }
                            }
                            callee_idx += 1;
                        }
                    }
                }
            }
        }
        return; // Don't recurse into call_expression children
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            // Don't cross into a nested (swallowed-sibling) function boundary.
            if is_real_nested_function_definition(&child, source) {
                continue;
            }
            collect_param_passthroughs(&child, source, params, summary);
        }
    }
}

/// Propagate transitive frees through param pass-through chains.
///
/// If function B passes param 0 to callee C at param 0, and C frees param 0,
/// then B transitively frees param 0. Iterates to fixpoint for deep chains
/// (e.g., A → B → C → D where D calls free).
pub fn propagate_transitive_frees(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let mut changed = false;
        let frees_snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.frees_params.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    if let Some(callee_frees) = frees_snapshot.get(callee_name) {
                        if callee_frees.contains(callee_idx)
                            && !summary.frees_params.contains(caller_idx)
                        {
                            summary.frees_params.insert(*caller_idx);
                            changed = true;
                        }
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Propagate transitive field-frees through param pass-through chains.
///
/// Mirrors `propagate_transitive_frees` but for `frees_param_fields`: if
/// function B passes its param 0 to callee C at param 0, and C frees field
/// `name` off that param, then B transitively frees field `name` off its
/// own param 0. Needed because real-world destructors usually delegate to
/// helper cleanup functions rather than calling `free(param->field)`
/// directly — e.g. mosquitto's `mosquitto__destroy(mosq)` calls
/// `message__cleanup_all(mosq)` and `will__clear(mosq)`, which are the ones
/// that actually free `mosq`'s fields (task 2: MEM31-C ownership model).
pub fn propagate_transitive_frees_param_fields(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let mut changed = false;
        let snapshot: HashMap<String, HashMap<usize, HashSet<String>>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.frees_param_fields.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    let Some(callee_fields) =
                        snapshot.get(callee_name).and_then(|m| m.get(callee_idx))
                    else {
                        continue;
                    };
                    let entry = summary.frees_param_fields.entry(*caller_idx).or_default();
                    for field in callee_fields {
                        if entry.insert(field.clone()) {
                            changed = true;
                        }
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Walk every `return_statement` under `body` and, when the return
/// expression unwraps to a call, record the callee identifier. Used as
/// the transitive-propagation seed for `returns_tainted`.
fn collect_returns_from_callees(body: &Node, source: &str, out: &mut HashSet<String>) {
    let mut returns = Vec::new();
    collect_return_expressions(body, source, &mut returns);
    for ret in returns {
        let inner = unwrap_to_call_node(ret);
        if inner.kind() == "call_expression" {
            if let Some(func) = inner.child_by_field_name("function") {
                let name = func.utf8_text(source.as_bytes()).unwrap_or("");
                let ident = name
                    .rsplit(|c: char| !c.is_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or(name);
                if !ident.is_empty() {
                    out.insert(ident.to_string());
                }
            }
        }
    }
}

/// Peel `parenthesized_expression` / `cast_expression` wrappers so we can
/// see whether the underlying expression is a `call_expression`.
fn unwrap_to_call_node<'a>(mut node: Node<'a>) -> Node<'a> {
    loop {
        match node.kind() {
            "parenthesized_expression" => {
                if let Some(inner) = node.named_child(0) {
                    node = inner;
                    continue;
                }
                break;
            }
            "cast_expression" => {
                if let Some(value) = node.child_by_field_name("value") {
                    node = value;
                    continue;
                }
                break;
            }
            _ => break,
        }
    }
    node
}

/// Propagate `returns_tainted` through the call chain formed by
/// `returns_from_callees`. If `g` returns the result of `f(...)` and
/// `f.returns_tainted`, then `g.returns_tainted` too.
///
/// Bounded at 10 passes (matches `propagate_transitive_frees`) to keep
/// prescan cost predictable; Juliet's deepest wrapper chains are 2-3 hops.
pub fn propagate_return_taint(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let mut changed = false;
        let snapshot: HashMap<String, bool> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.returns_tainted))
            .collect();

        for summary in summaries.values_mut() {
            if summary.returns_tainted {
                continue;
            }
            for callee in &summary.returns_from_callees {
                if let Some(&callee_tainted) = snapshot.get(callee) {
                    if callee_tainted {
                        summary.returns_tainted = true;
                        changed = true;
                        break;
                    }
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Compute the return value range for an integer-returning function.
///
/// Collects all `return expr;` statements in the body, evaluates each
/// expression as a constant range, and joins them. Returns `None` if any
/// return expression cannot be evaluated (conservative).
fn compute_return_range(
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
) -> Option<ValueRange> {
    let mut return_exprs = Vec::new();
    collect_return_expressions(body, source, &mut return_exprs);

    if return_exprs.is_empty() {
        return None;
    }

    let empty_vars = VarRangeMap::new();
    let mut combined: Option<ValueRange> = None;

    for expr_node in &return_exprs {
        // Try to evaluate the return expression as a constant range.
        // Uses empty var_ranges — only resolves literals, macros, sizeof, and
        // arithmetic on those. Parameter-dependent returns yield None.
        let range = const_eval::try_evaluate_range(expr_node, source, macros, &empty_vars)?;
        combined = Some(match combined {
            Some(existing) => {
                ValueRange::new(existing.min.min(range.min), existing.max.max(range.max))
            }
            None => range,
        });
    }

    combined
}

/// Recursively collect the expression child of every `return_statement` in `node`.
fn collect_return_expressions<'a>(node: &Node<'a>, source: &str, out: &mut Vec<Node<'a>>) {
    if node.kind() == "return_statement" {
        // The return expression is the first non-keyword child
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() != "return" && child.kind() != ";" {
                    out.push(child);
                    return;
                }
            }
        }
        // Bare `return;` — no expression (void-style)
        return;
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            // Don't cross into a nested (swallowed-sibling) function boundary.
            if is_real_nested_function_definition(&child, source) {
                continue;
            }
            collect_return_expressions(&child, source, out);
        }
    }
}

pub fn extract_function_name(func_node: &Node, source: &str) -> Option<String> {
    let declarator = func_node.child_by_field_name("declarator")?;
    let name = extract_leaf_identifier(&declarator, source);
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn extract_leaf_identifier(node: &Node, source: &str) -> String {
    match node.kind() {
        "identifier" => node.utf8_text(source.as_bytes()).unwrap_or("").to_string(),
        "function_declarator" | "pointer_declarator" | "array_declarator" => {
            if let Some(inner) = node.child_by_field_name("declarator") {
                extract_leaf_identifier(&inner, source)
            } else {
                String::new()
            }
        }
        _ => {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "identifier" {
                        return child.utf8_text(source.as_bytes()).unwrap_or("").to_string();
                    }
                }
            }
            String::new()
        }
    }
}

/// Infer the null state of a call argument from AST structure alone.
///
/// Used during prescan to collect argument states at each call site without
/// running full dataflow. Returns:
/// - DefinitelyNull for NULL/0/nullptr literals or casts wrapping them
/// - NotNull for string literals, &var, non-zero numeric literals
/// - Unknown for identifiers and complex expressions (conservative)
pub fn infer_arg_null_state(arg: &Node, source: &str) -> NullState {
    match arg.kind() {
        "null" | "nullptr" => NullState::DefinitelyNull,
        "number_literal" => {
            let text = arg.utf8_text(source.as_bytes()).unwrap_or("").trim();
            if text == "0" {
                NullState::DefinitelyNull
            } else {
                NullState::NotNull
            }
        }
        "string_literal" | "concatenated_string" | "char_literal" => NullState::NotNull,
        "unary_expression" => {
            // &var is always non-null
            if let Some(op) = arg.child_by_field_name("operator") {
                if op.utf8_text(source.as_bytes()).unwrap_or("") == "&" {
                    return NullState::NotNull;
                }
            }
            NullState::Unknown
        }
        "pointer_expression" => {
            // tree-sitter-c parses both `&var` and `*ptr` as pointer_expression.
            // The address of anything is always non-null; the pointee of `*ptr`
            // is unknown. Address-of is the common form for call arguments
            // (`&buf[i]`, `&obj.field`, `&var`), so without this arm caller-context
            // never accumulates non-null evidence from address-of call sites.
            if let Some(op) = arg.child_by_field_name("operator") {
                if op.utf8_text(source.as_bytes()).unwrap_or("") == "&" {
                    return NullState::NotNull;
                }
            }
            NullState::Unknown
        }
        "cast_expression" => {
            // (type*)NULL or (type*)0
            if let Some(value) = arg.child_by_field_name("value") {
                let inner = infer_arg_null_state(&value, source);
                if inner == NullState::DefinitelyNull {
                    return NullState::DefinitelyNull;
                }
            }
            NullState::Unknown
        }
        "parenthesized_expression" => {
            // Unwrap (expr)
            if let Some(inner) = arg.child(1) {
                return infer_arg_null_state(&inner, source);
            }
            NullState::Unknown
        }
        "identifier" => {
            let text = arg.utf8_text(source.as_bytes()).unwrap_or("");
            if text == "NULL" {
                NullState::DefinitelyNull
            } else if matches!(text, "stdout" | "stderr" | "stdin") {
                // Standard C streams are guaranteed non-null
                NullState::NotNull
            } else {
                NullState::Unknown
            }
        }
        _ => NullState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_and_summarize(code: &str) -> HashMap<String, FunctionSummary> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).unwrap();
        let tree = parser.parse(code, None).unwrap();
        let macros = const_eval::collect_macro_constants(&tree.root_node(), code);
        compute_summaries(&tree.root_node(), code, &macros, true, &[], &HashMap::new())
    }

    #[test]
    fn test_never_returns() {
        let code = r#"
        void die(const char *msg) {
            fprintf(stderr, "%s\n", msg);
            abort();
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("die").unwrap();
        assert!(summary.never_returns);
    }

    #[test]
    fn test_frees_params() {
        let code = r#"
        void cleanup(void *ptr) {
            free(ptr);
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("cleanup").unwrap();
        assert!(summary.frees_params.contains(&0));
    }

    #[test]
    fn test_can_return_null() {
        let code = r#"
        char *find_match(const char *haystack, const char *needle) {
            char *result = strstr(haystack, needle);
            if (!result) {
                return NULL;
            }
            return result;
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("find_match").unwrap();
        assert!(summary.can_return_null);
    }

    #[test]
    fn test_checks_null_params() {
        let code = r#"
        int safe_strlen(const char *s) {
            if (s == NULL) {
                return 0;
            }
            return strlen(s);
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("safe_strlen").unwrap();
        assert!(summary.checks_null_params.contains(&0));
    }

    #[test]
    fn test_modifies_params() {
        let code = r#"
        void init_struct(struct config *cfg) {
            cfg->value = 0;
            cfg->name = "default";
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("init_struct").unwrap();
        assert!(summary.modifies_params.contains(&0));
    }

    #[test]
    fn test_returns_allocation() {
        let code = r#"
        char *create_buffer(size_t size) {
            char *buf = malloc(size);
            if (!buf) return NULL;
            memset(buf, 0, size);
            return buf;
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("create_buffer").unwrap();
        assert!(summary.returns_allocation);
        assert!(summary.can_return_null);
    }

    #[test]
    fn test_return_range_constant() {
        let code = r#"
        int get_five(void) { return 5; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_five").unwrap();
        assert_eq!(summary.return_range, Some(ValueRange::exact(5)));
    }

    #[test]
    fn test_return_range_multiple_paths() {
        let code = r#"
        int get_bounded(int flag) {
            if (flag) return 1;
            return 10;
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_bounded").unwrap();
        assert_eq!(summary.return_range, Some(ValueRange::new(1, 10)));
    }

    #[test]
    fn test_return_range_void() {
        let code = r#"
        void do_nothing(void) { return; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("do_nothing").unwrap();
        assert_eq!(summary.return_range, None);
    }

    #[test]
    fn test_return_range_pointer() {
        let code = r#"
        int *get_ptr(void) { return 0; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_ptr").unwrap();
        assert_eq!(summary.return_range, None);
    }

    #[test]
    fn test_return_range_param_dependent() {
        let code = r#"
        int identity(int x) { return x; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("identity").unwrap();
        // Parameter-dependent return — not evaluable
        assert_eq!(summary.return_range, None);
    }

    #[test]
    fn test_return_range_macro() {
        let code = r#"
        #define MAX_COUNT 100
        int get_max(void) { return MAX_COUNT; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_max").unwrap();
        assert_eq!(summary.return_range, Some(ValueRange::exact(100)));
    }

    #[test]
    fn test_return_range_zero() {
        let code = r#"
        int get_zero(void) { return 0; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_zero").unwrap();
        assert_eq!(summary.return_range, Some(ValueRange::exact(0)));
    }

    #[test]
    fn test_return_range_negative() {
        let code = r#"
        int get_error(void) { return -1; }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("get_error").unwrap();
        assert_eq!(summary.return_range, Some(ValueRange::exact(-1)));
    }

    #[test]
    fn test_ifdef_spanning_brace_does_not_swallow_sibling_summary() {
        // Regression for task 267/296 (see the identical fixture and bug
        // description in prescan.rs's
        // test_collect_call_graph_ifdef_spanning_brace_does_not_leak_swallowed_sibling_calls):
        // a brace that opens under `#ifndef SQLITE_OMIT_AUTHORIZATION` and
        // closes under a second, identical guard a few lines later can't be
        // reconciled by tree-sitter-c without a real preprocessor.
        // sqlite3InitOne's function_definition never closes normally
        // ([0..8717] out of an 8718-byte file), nesting sqlite3Init as a
        // descendant at [7870..8717]. Before this fix,
        // `collect_function_summaries` only matched `function_definition` as
        // a direct child of the translation unit (or of a `preproc_*`
        // wrapper), so sqlite3Init -- now nested inside sqlite3InitOne --
        // got zero summary entry: invisible to every interprocedural rule
        // keyed on FunctionSummary (MSC04-C, EXP34-C, MEM30/31-C, null-state,
        // taint) for the rest of the file.
        let code = r#"int sqlite3InitOne(sqlite3 *db, int iDb, char **pzErrMsg, u32 mFlags){
  int rc;
  int i;
#ifndef SQLITE_OMIT_DEPRECATED
  int size;
#endif
  Db *pDb;
  char const *azArg[6];
  int meta[5];
  InitData initData;
  const char *zSchemaTabName;
  int openedTransaction = 0;
  int mask = ((db->mDbFlags & DBFLAG_EncodingFixed) | ~DBFLAG_EncodingFixed);

  assert( (db->mDbFlags & DBFLAG_SchemaKnownOk)==0 );
  assert( iDb>=0 && iDb<db->nDb );
  assert( db->aDb[iDb].pSchema );
  assert( sqlite3_mutex_held(db->mutex) );
  assert( iDb==1 || sqlite3BtreeHoldsMutex(db->aDb[iDb].pBt) );

  db->init.busy = 1;

  /* Construct the in-memory representation schema tables (sqlite_schema or
  ** sqlite_temp_schema) by invoking the parser directly.  The appropriate
  ** table name will be inserted automatically by the parser so we can just
  ** use the abbreviation "x" here.  The parser will also automatically tag
  ** the schema table as read-only. */
  azArg[0] = "table";
  azArg[1] = zSchemaTabName = SCHEMA_TABLE(iDb);
  azArg[2] = azArg[1];
  azArg[3] = "1";
  azArg[4] = "CREATE TABLE x(type text,name text,tbl_name text,"
                            "rootpage int,sql text)";
  azArg[5] = 0;
  initData.db = db;
  initData.iDb = iDb;
  initData.rc = SQLITE_OK;
  initData.pzErrMsg = pzErrMsg;
  initData.mInitFlags = mFlags;
  initData.nInitRow = 0;
  initData.mxPage = 0;
  sqlite3InitCallback(&initData, 5, (char **)azArg, 0);
  db->mDbFlags &= mask;
  if( initData.rc ){
    rc = initData.rc;
    goto error_out;
  }

  /* Create a cursor to hold the database open
  */
  pDb = &db->aDb[iDb];
  if( pDb->pBt==0 ){
    assert( iDb==1 );
    DbSetProperty(db, 1, DB_SchemaLoaded);
    rc = SQLITE_OK;
    goto error_out;
  }

  /* If there is not already a read-only (or read-write) transaction opened
  ** on the b-tree database, open one now. If a transaction is opened, it 
  ** will be closed before this function returns.  */
  sqlite3BtreeEnter(pDb->pBt);
  if( sqlite3BtreeTxnState(pDb->pBt)==SQLITE_TXN_NONE ){
    rc = sqlite3BtreeBeginTrans(pDb->pBt, 0, 0);
    if( rc!=SQLITE_OK ){
      sqlite3SetString(pzErrMsg, db, sqlite3ErrStr(rc));
      goto initone_error_out;
    }
    openedTransaction = 1;
  }

  /* Get the database meta information.
  **
  ** Meta values are as follows:
  **    meta[0]   Schema cookie.  Changes with each schema change.
  **    meta[1]   File format of schema layer.
  **    meta[2]   Size of the page cache.
  **    meta[3]   Largest rootpage (auto/incr_vacuum mode)
  **    meta[4]   Db text encoding. 1:UTF-8 2:UTF-16LE 3:UTF-16BE
  **    meta[5]   User version
  **    meta[6]   Incremental vacuum mode
  **    meta[7]   unused
  **    meta[8]   unused
  **    meta[9]   unused
  **
  ** Note: The #defined SQLITE_UTF* symbols in sqliteInt.h correspond to
  ** the possible values of meta[4].
  */
  for(i=0; i<ArraySize(meta); i++){
    sqlite3BtreeGetMeta(pDb->pBt, i+1, (u32 *)&meta[i]);
  }
  if( (db->flags & SQLITE_ResetDatabase)!=0 ){
    memset(meta, 0, sizeof(meta));
  }
  pDb->pSchema->schema_cookie = meta[BTREE_SCHEMA_VERSION-1];

  /* If opening a non-empty database, check the text encoding. For the
  ** main database, set sqlite3.enc to the encoding of the main database.
  ** For an attached db, it is an error if the encoding is not the same
  ** as sqlite3.enc.
  */
  if( meta[BTREE_TEXT_ENCODING-1] ){  /* text encoding */
    if( iDb==0 && (db->mDbFlags & DBFLAG_EncodingFixed)==0 ){
      u8 encoding;
#ifndef SQLITE_OMIT_UTF16
      /* If opening the main database, set ENC(db). */
      encoding = (u8)meta[BTREE_TEXT_ENCODING-1] & 3;
      if( encoding==0 ) encoding = SQLITE_UTF8;
#else
      encoding = SQLITE_UTF8;
#endif
      sqlite3SetTextEncoding(db, encoding);
    }else{
      /* If opening an attached database, the encoding much match ENC(db) */
      if( (meta[BTREE_TEXT_ENCODING-1] & 3)!=ENC(db) ){
        sqlite3SetString(pzErrMsg, db, "attached databases must use the same"
            " text encoding as main database");
        rc = SQLITE_ERROR;
        goto initone_error_out;
      }
    }
  }
  pDb->pSchema->enc = ENC(db);

  if( pDb->pSchema->cache_size==0 ){
#ifndef SQLITE_OMIT_DEPRECATED
    size = sqlite3AbsInt32(meta[BTREE_DEFAULT_CACHE_SIZE-1]);
    if( size==0 ){ size = SQLITE_DEFAULT_CACHE_SIZE; }
    pDb->pSchema->cache_size = size;
#else
    pDb->pSchema->cache_size = SQLITE_DEFAULT_CACHE_SIZE;
#endif
    sqlite3BtreeSetCacheSize(pDb->pBt, pDb->pSchema->cache_size);
  }

  /*
  ** file_format==1    Version 3.0.0.
  ** file_format==2    Version 3.1.3.  // ALTER TABLE ADD COLUMN
  ** file_format==3    Version 3.1.4.  // ditto but with non-NULL defaults
  ** file_format==4    Version 3.3.0.  // DESC indices.  Boolean constants
  */
  pDb->pSchema->file_format = (u8)meta[BTREE_FILE_FORMAT-1];
  if( pDb->pSchema->file_format==0 ){
    pDb->pSchema->file_format = 1;
  }
  if( pDb->pSchema->file_format>SQLITE_MAX_FILE_FORMAT ){
    sqlite3SetString(pzErrMsg, db, "unsupported file format");
    rc = SQLITE_ERROR;
    goto initone_error_out;
  }

  /* Ticket #2804:  When we open a database in the newer file format,
  ** clear the legacy_file_format pragma flag so that a VACUUM will
  ** not downgrade the database and thus invalidate any descending
  ** indices that the user might have created.
  */
  if( iDb==0 && meta[BTREE_FILE_FORMAT-1]>=4 ){
    db->flags &= ~(u64)SQLITE_LegacyFileFmt;
  }

  /* Read the schema information out of the schema tables
  */
  assert( db->init.busy );
  initData.mxPage = sqlite3BtreeLastPage(pDb->pBt);
  {
    char *zSql;
    zSql = sqlite3MPrintf(db, 
        "SELECT*FROM\"%w\".%s ORDER BY rowid",
        db->aDb[iDb].zDbSName, zSchemaTabName);
#ifndef SQLITE_OMIT_AUTHORIZATION
    {
      sqlite3_xauth xAuth;
      xAuth = db->xAuth;
      db->xAuth = 0;
#endif
      rc = sqlite3_exec(db, zSql, sqlite3InitCallback, &initData, 0);
#ifndef SQLITE_OMIT_AUTHORIZATION
      db->xAuth = xAuth;
    }
#endif
    if( rc==SQLITE_OK ) rc = initData.rc;
    sqlite3DbFree(db, zSql);
#ifndef SQLITE_OMIT_ANALYZE
    if( rc==SQLITE_OK ){
      sqlite3AnalysisLoad(db, iDb);
    }
#endif
  }
  assert( pDb == &(db->aDb[iDb]) );
  if( db->mallocFailed ){
    rc = SQLITE_NOMEM_BKPT;
    sqlite3ResetAllSchemasOfConnection(db);
    pDb = &db->aDb[iDb];
  }else
  if( rc==SQLITE_OK || ((db->flags&SQLITE_NoSchemaError) && rc!=SQLITE_NOMEM)){
    /* Hack: If the SQLITE_NoSchemaError flag is set, then consider
    ** the schema loaded, even if errors (other than OOM) occurred. In
    ** this situation the current sqlite3_prepare() operation will fail,
    ** but the following one will attempt to compile the supplied statement
    ** against whatever subset of the schema was loaded before the error
    ** occurred.
    **
    ** The primary purpose of this is to allow access to the sqlite_schema
    ** table even when its contents have been corrupted.
    */
    DbSetProperty(db, iDb, DB_SchemaLoaded);
    rc = SQLITE_OK;
  }

  /* Jump here for an error that occurs after successfully allocating
  ** curMain and calling sqlite3BtreeEnter(). For an error that occurs
  ** before that point, jump to error_out.
  */
initone_error_out:
  if( openedTransaction ){
    sqlite3BtreeCommit(pDb->pBt);
  }
  sqlite3BtreeLeave(pDb->pBt);

error_out:
  if( rc ){
    if( rc==SQLITE_NOMEM || rc==SQLITE_IOERR_NOMEM ){
      sqlite3OomFault(db);
    }
    sqlite3ResetOneSchema(db, iDb);
  }
  db->init.busy = 0;
  return rc;
}

/*
** Initialize all database files - the main database file, the file
** used to store temporary tables, and any additional database files
** created using ATTACH statements.  Return a success code.  If an
** error occurs, write an error message into *pzErrMsg.
**
** After a database is initialized, the DB_SchemaLoaded bit is set
** bit is set in the flags field of the Db structure. 
*/
int sqlite3Init(sqlite3 *db, char **pzErrMsg){
  int i, rc;
  int commit_internal = !(db->mDbFlags&DBFLAG_SchemaChange);
  
  assert( sqlite3_mutex_held(db->mutex) );
  assert( sqlite3BtreeHoldsMutex(db->aDb[0].pBt) );
  assert( db->init.busy==0 );
  ENC(db) = SCHEMA_ENC(db);
  assert( db->nDb>0 );
  /* Do the main schema first */
  if( !DbHasProperty(db, 0, DB_SchemaLoaded) ){
    rc = sqlite3InitOne(db, 0, pzErrMsg, 0);
    if( rc ) return rc;
  }
  /* All other schemas after the main schema. The "temp" schema must be last */
  for(i=db->nDb-1; i>0; i--){
    assert( i==1 || sqlite3BtreeHoldsMutex(db->aDb[i].pBt) );
    if( !DbHasProperty(db, i, DB_SchemaLoaded) ){
      rc = sqlite3InitOne(db, i, pzErrMsg, 0);
      if( rc ) return rc;
    }
  }
  if( commit_internal ){
    sqlite3CommitInternalChanges(db);
  }
  return SQLITE_OK;
}"#;
        let summaries = parse_and_summarize(code);
        assert!(
            summaries.contains_key("sqlite3Init"),
            "sqlite3Init was swallowed into sqlite3InitOne's corrupted span \
             and got no summary entry of its own: {:?}",
            summaries.keys().collect::<Vec<_>>()
        );
        assert!(summaries.contains_key("sqlite3InitOne"));
    }

    #[test]
    fn test_ifdef_spanning_brace_does_not_contaminate_outer_summary() {
        // Same corruption as above, with a third function appended
        // (`extra_leak_marker`, containing malloc()/abort() -- signals not
        // present anywhere in the real sqlite3InitOne/sqlite3Init source)
        // that also ends up nested inside sqlite3InitOne's corrupted span.
        // Before the has_error()-gated boundary in `analyze_function`,
        // sqlite3InitOne's `body_text` spanned its own source AND both
        // swallowed siblings, so these plain text scans (returns_allocation,
        // never_returns) would wrongly flip true for sqlite3InitOne itself.
        let code = r#"int sqlite3InitOne(sqlite3 *db, int iDb, char **pzErrMsg, u32 mFlags){
  int rc;
  int i;
#ifndef SQLITE_OMIT_DEPRECATED
  int size;
#endif
  Db *pDb;
  char const *azArg[6];
  int meta[5];
  InitData initData;
  const char *zSchemaTabName;
  int openedTransaction = 0;
  int mask = ((db->mDbFlags & DBFLAG_EncodingFixed) | ~DBFLAG_EncodingFixed);

  assert( (db->mDbFlags & DBFLAG_SchemaKnownOk)==0 );
  assert( iDb>=0 && iDb<db->nDb );
  assert( db->aDb[iDb].pSchema );
  assert( sqlite3_mutex_held(db->mutex) );
  assert( iDb==1 || sqlite3BtreeHoldsMutex(db->aDb[iDb].pBt) );

  db->init.busy = 1;

  /* Construct the in-memory representation schema tables (sqlite_schema or
  ** sqlite_temp_schema) by invoking the parser directly.  The appropriate
  ** table name will be inserted automatically by the parser so we can just
  ** use the abbreviation "x" here.  The parser will also automatically tag
  ** the schema table as read-only. */
  azArg[0] = "table";
  azArg[1] = zSchemaTabName = SCHEMA_TABLE(iDb);
  azArg[2] = azArg[1];
  azArg[3] = "1";
  azArg[4] = "CREATE TABLE x(type text,name text,tbl_name text,"
                            "rootpage int,sql text)";
  azArg[5] = 0;
  initData.db = db;
  initData.iDb = iDb;
  initData.rc = SQLITE_OK;
  initData.pzErrMsg = pzErrMsg;
  initData.mInitFlags = mFlags;
  initData.nInitRow = 0;
  initData.mxPage = 0;
  sqlite3InitCallback(&initData, 5, (char **)azArg, 0);
  db->mDbFlags &= mask;
  if( initData.rc ){
    rc = initData.rc;
    goto error_out;
  }

  /* Create a cursor to hold the database open
  */
  pDb = &db->aDb[iDb];
  if( pDb->pBt==0 ){
    assert( iDb==1 );
    DbSetProperty(db, 1, DB_SchemaLoaded);
    rc = SQLITE_OK;
    goto error_out;
  }

  /* If there is not already a read-only (or read-write) transaction opened
  ** on the b-tree database, open one now. If a transaction is opened, it 
  ** will be closed before this function returns.  */
  sqlite3BtreeEnter(pDb->pBt);
  if( sqlite3BtreeTxnState(pDb->pBt)==SQLITE_TXN_NONE ){
    rc = sqlite3BtreeBeginTrans(pDb->pBt, 0, 0);
    if( rc!=SQLITE_OK ){
      sqlite3SetString(pzErrMsg, db, sqlite3ErrStr(rc));
      goto initone_error_out;
    }
    openedTransaction = 1;
  }

  /* Get the database meta information.
  **
  ** Meta values are as follows:
  **    meta[0]   Schema cookie.  Changes with each schema change.
  **    meta[1]   File format of schema layer.
  **    meta[2]   Size of the page cache.
  **    meta[3]   Largest rootpage (auto/incr_vacuum mode)
  **    meta[4]   Db text encoding. 1:UTF-8 2:UTF-16LE 3:UTF-16BE
  **    meta[5]   User version
  **    meta[6]   Incremental vacuum mode
  **    meta[7]   unused
  **    meta[8]   unused
  **    meta[9]   unused
  **
  ** Note: The #defined SQLITE_UTF* symbols in sqliteInt.h correspond to
  ** the possible values of meta[4].
  */
  for(i=0; i<ArraySize(meta); i++){
    sqlite3BtreeGetMeta(pDb->pBt, i+1, (u32 *)&meta[i]);
  }
  if( (db->flags & SQLITE_ResetDatabase)!=0 ){
    memset(meta, 0, sizeof(meta));
  }
  pDb->pSchema->schema_cookie = meta[BTREE_SCHEMA_VERSION-1];

  /* If opening a non-empty database, check the text encoding. For the
  ** main database, set sqlite3.enc to the encoding of the main database.
  ** For an attached db, it is an error if the encoding is not the same
  ** as sqlite3.enc.
  */
  if( meta[BTREE_TEXT_ENCODING-1] ){  /* text encoding */
    if( iDb==0 && (db->mDbFlags & DBFLAG_EncodingFixed)==0 ){
      u8 encoding;
#ifndef SQLITE_OMIT_UTF16
      /* If opening the main database, set ENC(db). */
      encoding = (u8)meta[BTREE_TEXT_ENCODING-1] & 3;
      if( encoding==0 ) encoding = SQLITE_UTF8;
#else
      encoding = SQLITE_UTF8;
#endif
      sqlite3SetTextEncoding(db, encoding);
    }else{
      /* If opening an attached database, the encoding much match ENC(db) */
      if( (meta[BTREE_TEXT_ENCODING-1] & 3)!=ENC(db) ){
        sqlite3SetString(pzErrMsg, db, "attached databases must use the same"
            " text encoding as main database");
        rc = SQLITE_ERROR;
        goto initone_error_out;
      }
    }
  }
  pDb->pSchema->enc = ENC(db);

  if( pDb->pSchema->cache_size==0 ){
#ifndef SQLITE_OMIT_DEPRECATED
    size = sqlite3AbsInt32(meta[BTREE_DEFAULT_CACHE_SIZE-1]);
    if( size==0 ){ size = SQLITE_DEFAULT_CACHE_SIZE; }
    pDb->pSchema->cache_size = size;
#else
    pDb->pSchema->cache_size = SQLITE_DEFAULT_CACHE_SIZE;
#endif
    sqlite3BtreeSetCacheSize(pDb->pBt, pDb->pSchema->cache_size);
  }

  /*
  ** file_format==1    Version 3.0.0.
  ** file_format==2    Version 3.1.3.  // ALTER TABLE ADD COLUMN
  ** file_format==3    Version 3.1.4.  // ditto but with non-NULL defaults
  ** file_format==4    Version 3.3.0.  // DESC indices.  Boolean constants
  */
  pDb->pSchema->file_format = (u8)meta[BTREE_FILE_FORMAT-1];
  if( pDb->pSchema->file_format==0 ){
    pDb->pSchema->file_format = 1;
  }
  if( pDb->pSchema->file_format>SQLITE_MAX_FILE_FORMAT ){
    sqlite3SetString(pzErrMsg, db, "unsupported file format");
    rc = SQLITE_ERROR;
    goto initone_error_out;
  }

  /* Ticket #2804:  When we open a database in the newer file format,
  ** clear the legacy_file_format pragma flag so that a VACUUM will
  ** not downgrade the database and thus invalidate any descending
  ** indices that the user might have created.
  */
  if( iDb==0 && meta[BTREE_FILE_FORMAT-1]>=4 ){
    db->flags &= ~(u64)SQLITE_LegacyFileFmt;
  }

  /* Read the schema information out of the schema tables
  */
  assert( db->init.busy );
  initData.mxPage = sqlite3BtreeLastPage(pDb->pBt);
  {
    char *zSql;
    zSql = sqlite3MPrintf(db, 
        "SELECT*FROM\"%w\".%s ORDER BY rowid",
        db->aDb[iDb].zDbSName, zSchemaTabName);
#ifndef SQLITE_OMIT_AUTHORIZATION
    {
      sqlite3_xauth xAuth;
      xAuth = db->xAuth;
      db->xAuth = 0;
#endif
      rc = sqlite3_exec(db, zSql, sqlite3InitCallback, &initData, 0);
#ifndef SQLITE_OMIT_AUTHORIZATION
      db->xAuth = xAuth;
    }
#endif
    if( rc==SQLITE_OK ) rc = initData.rc;
    sqlite3DbFree(db, zSql);
#ifndef SQLITE_OMIT_ANALYZE
    if( rc==SQLITE_OK ){
      sqlite3AnalysisLoad(db, iDb);
    }
#endif
  }
  assert( pDb == &(db->aDb[iDb]) );
  if( db->mallocFailed ){
    rc = SQLITE_NOMEM_BKPT;
    sqlite3ResetAllSchemasOfConnection(db);
    pDb = &db->aDb[iDb];
  }else
  if( rc==SQLITE_OK || ((db->flags&SQLITE_NoSchemaError) && rc!=SQLITE_NOMEM)){
    /* Hack: If the SQLITE_NoSchemaError flag is set, then consider
    ** the schema loaded, even if errors (other than OOM) occurred. In
    ** this situation the current sqlite3_prepare() operation will fail,
    ** but the following one will attempt to compile the supplied statement
    ** against whatever subset of the schema was loaded before the error
    ** occurred.
    **
    ** The primary purpose of this is to allow access to the sqlite_schema
    ** table even when its contents have been corrupted.
    */
    DbSetProperty(db, iDb, DB_SchemaLoaded);
    rc = SQLITE_OK;
  }

  /* Jump here for an error that occurs after successfully allocating
  ** curMain and calling sqlite3BtreeEnter(). For an error that occurs
  ** before that point, jump to error_out.
  */
initone_error_out:
  if( openedTransaction ){
    sqlite3BtreeCommit(pDb->pBt);
  }
  sqlite3BtreeLeave(pDb->pBt);

error_out:
  if( rc ){
    if( rc==SQLITE_NOMEM || rc==SQLITE_IOERR_NOMEM ){
      sqlite3OomFault(db);
    }
    sqlite3ResetOneSchema(db, iDb);
  }
  db->init.busy = 0;
  return rc;
}

/*
** Initialize all database files - the main database file, the file
** used to store temporary tables, and any additional database files
** created using ATTACH statements.  Return a success code.  If an
** error occurs, write an error message into *pzErrMsg.
**
** After a database is initialized, the DB_SchemaLoaded bit is set
** bit is set in the flags field of the Db structure. 
*/
int sqlite3Init(sqlite3 *db, char **pzErrMsg){
  int i, rc;
  int commit_internal = !(db->mDbFlags&DBFLAG_SchemaChange);
  
  assert( sqlite3_mutex_held(db->mutex) );
  assert( sqlite3BtreeHoldsMutex(db->aDb[0].pBt) );
  assert( db->init.busy==0 );
  ENC(db) = SCHEMA_ENC(db);
  assert( db->nDb>0 );
  /* Do the main schema first */
  if( !DbHasProperty(db, 0, DB_SchemaLoaded) ){
    rc = sqlite3InitOne(db, 0, pzErrMsg, 0);
    if( rc ) return rc;
  }
  /* All other schemas after the main schema. The "temp" schema must be last */
  for(i=db->nDb-1; i>0; i--){
    assert( i==1 || sqlite3BtreeHoldsMutex(db->aDb[i].pBt) );
    if( !DbHasProperty(db, i, DB_SchemaLoaded) ){
      rc = sqlite3InitOne(db, i, pzErrMsg, 0);
      if( rc ) return rc;
    }
  }
  if( commit_internal ){
    sqlite3CommitInternalChanges(db);
  }
  return SQLITE_OK;
}

void extra_leak_marker(void){
  void *buf = malloc(4);
  free(buf);
  abort();
}"#;
        let summaries = parse_and_summarize(code);
        let outer = summaries
            .get("sqlite3InitOne")
            .expect("sqlite3InitOne should still get its own summary");
        assert!(
            !outer.returns_allocation,
            "sqlite3InitOne's summary was contaminated with extra_leak_marker's malloc() call"
        );
        assert!(
            !outer.never_returns,
            "sqlite3InitOne's summary was contaminated with extra_leak_marker's abort() call"
        );
        // Both swallowed siblings must still get their own, correctly-scoped summaries.
        assert!(summaries.contains_key("sqlite3Init"));
        let marker = summaries
            .get("extra_leak_marker")
            .expect("extra_leak_marker should get its own summary entry");
        assert!(marker.returns_allocation);
        assert!(marker.never_returns);
    }
}
