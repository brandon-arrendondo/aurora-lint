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
    if node.kind() == "function_definition" {
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

    // Recurse into preproc blocks
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_definition" => {
                    if let Some(name) = extract_function_name(&child, source) {
                        let summary = analyze_function(
                            &child,
                            source,
                            macros,
                            compute_return_ranges,
                            taint_source_aliases,
                            string_macros,
                        );
                        summaries.insert(name, summary);
                    }
                }
                kind if kind.starts_with("preproc_") => {
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
                _ => {}
            }
        }
    }
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
        let body_text = body.utf8_text(source.as_bytes()).unwrap_or("");

        // Check for never-returns patterns
        summary.never_returns = check_never_returns(&body, source);

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
        analyze_param_usage(&body, source, &params, &mut summary);

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
fn check_never_returns(body: &Node, source: &str) -> bool {
    let body_text = body.utf8_text(source.as_bytes()).unwrap_or("");

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
            if check_returns_null(&child, source) {
                return true;
            }
        }
    }

    false
}

/// Analyze how parameters are used in the function body.
fn analyze_param_usage(
    body: &Node,
    source: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    let body_text = body.utf8_text(source.as_bytes()).unwrap_or("");

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

/// Walk every `return_statement` under `body` and, when the return
/// expression unwraps to a call, record the callee identifier. Used as
/// the transitive-propagation seed for `returns_tainted`.
fn collect_returns_from_callees(body: &Node, source: &str, out: &mut HashSet<String>) {
    let mut returns = Vec::new();
    collect_return_expressions(body, &mut returns);
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
    collect_return_expressions(body, &mut return_exprs);

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
fn collect_return_expressions<'a>(node: &Node<'a>, out: &mut Vec<Node<'a>>) {
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
            collect_return_expressions(&child, out);
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
}
