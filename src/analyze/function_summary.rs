//! Function summary computation for inter-procedural analysis.
//!
//! Computes lightweight summaries of each function's behavior during the prescan
//! phase. These summaries are used by rules to reason about callee behavior
//! without re-analyzing the callee's body.

use crate::analyze::const_eval::{self, MacroConstantMap, ValueRange, VarRangeMap};
use crate::analyze::init_state;
use crate::analyze::null_state::NullState;
use crate::utility::cert_c::guard_dominance;
use std::collections::{BTreeSet, HashMap, HashSet};
use tree_sitter::Node;

/// Summary of a function's behavior relevant to CERT C rules.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FunctionSummary {
    /// Parameter indices that this function frees (e.g., free(param[0])).
    /// This is a MAY-free fact: the free can be nested inside a conditional
    /// (if/switch/loop/ternary), so it does not mean every call reaches it.
    pub frees_params: HashSet<usize>,
    /// Parameter indices that this function UNCONDITIONALLY frees — the free
    /// is not nested inside any conditional construct other than a null test
    /// on the very pointer being freed (`if (p != NULL) free(p);`, whose
    /// skipped path has nothing to free and so leaves nothing for a caller to
    /// use — task 988, tools_sqc), so it executes
    /// whenever the function itself is entered (modulo an early return
    /// before it, which the AST-position check already accounts for since
    /// it only asks "is this call inside a conditional", not "could an
    /// earlier statement return first"). Subset of `frees_params`. This is
    /// the MUST-free fact rules like MEM30-C need to safely mark an argument
    /// as definitely freed after a call — trusting the MAY-free set for that
    /// purpose caused cascading false UAF/double-free reports when a helper
    /// only frees its argument on an error path a given caller didn't take
    /// (task 401).
    #[serde(default)]
    pub unconditional_frees_params: HashSet<usize>,
    /// Subset of `modifies_params` whose write through the parameter is not
    /// known to be conditional — the MUST-write fact, and the output-param
    /// counterpart of `unconditional_frees_params`.
    ///
    /// A rule that clears an "uninitialised" state because a callee writes
    /// through an output parameter needs MUST, not MAY. `set_flag(n, &sign)`
    /// writes `*sign_flag` under `if (n > 0)` and `else if (n < 0)` and writes
    /// nothing when `n == 0`, so the caller can still read `sign`
    /// uninitialised — the CERT wiki's own noncompliant example, which
    /// EXP33-C missed for as long as MAY was all the summary offered
    /// (task 988, tools_sqc).
    ///
    /// Built by DEMOTION rather than by re-derivation: a parameter leaves the
    /// set only when the AST pass found writes through it and every one of
    /// them was conditional. A parameter whose writes the pass cannot see —
    /// through a macro, or a nested helper — stays in, so the narrower AST
    /// view can only act on positive evidence and never silently withdraws a
    /// write the text scan did find.
    #[serde(default)]
    pub unconditional_modifies_params: HashSet<usize>,
    /// Parameters the coverage walk could only cover by FORWARDING them to a
    /// callee, keyed to the `(callee, callee parameter index)` pairs that
    /// have to be MUST-writes themselves for the coverage to hold.
    ///
    /// The obligation cannot be discharged where it is raised: a callee
    /// defined in another file has no summary yet while this one is being
    /// built, which is why the free version propagates in prescan rather
    /// than in `analyze_param_usage` too. `propagate_transitive_modifies`
    /// settles these once every file's summary exists.
    ///
    /// Kept separate from `unconditional_param_passthroughs` because that
    /// set answers a different question -- whether the forwarding call site
    /// is unconditionally reached -- and the answer here is routinely no.
    /// sqlite's `fts5CsrPoslist` forwards `pa` from inside an if/else whose
    /// other arm writes it directly, so no single call site is
    /// unconditional and yet no returning path leaves `pa` untouched
    /// (task 1011, tools_sqc).
    #[serde(default)]
    pub modifies_params_pending: HashMap<usize, Vec<(String, usize)>>,
    /// Parameters PROVEN to have a returning path that writes nothing through
    /// them — the positive-evidence half of what `modifies_params` minus
    /// `unconditional_modifies_params` only hints at.
    ///
    /// The difference matters because the MUST set is deliberately
    /// incomplete: it is built by demotion from a text scan and cannot see
    /// through an indirect call, so a genuine write-on-every-path function
    /// routinely fails to reach it. curl's `Curl_conn_get_current_host` fills
    /// both its outputs on every path, one of them via
    /// `cf_proxy->cft->query(...)` through a function pointer — absent from
    /// MUST, and yet crediting its callers is correct. Withholding the
    /// `&var`-initializes default on "not in MUST" alone therefore reports
    /// every such caller (task 1065 bug #3, tools_sqc).
    ///
    /// So this set answers the other question outright: is there a path that
    /// reaches a `return` (or the end of a void body) having neither written
    /// through the parameter nor handed it to anything that might?
    /// `Curl_sasl_decode_mech`'s trailing `return 0` is exactly that path —
    /// every write to `*len` sits inside the table-match `if`, and a caller
    /// reading the length on the no-match path reads it uninitialised.
    #[serde(default)]
    pub conditional_modifies_params: HashSet<usize>,
    /// Parameter indices whose **pointee** this function frees — `free(*param)`,
    /// the `void **` "safe free" wrapper idiom:
    ///
    /// ```c
    /// void safe_free(void **ptr) { if (ptr && *ptr) { free(*ptr); *ptr = NULL; } }
    /// ```
    ///
    /// Distinct from `frees_params`, which says the pointer value handed in is
    /// released. Here it is the caller's own pointer *variable* that is
    /// released, and the call site names it as `&var`, so a rule matching
    /// arguments by identifier never sees the connection — which is what made
    /// every allocation in a `safe_free()`-using function look unmatched.
    /// A MAY-free fact, like `frees_params`.
    #[serde(default)]
    pub frees_param_pointees: HashSet<usize>,
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
    /// Parameter indices this function null-checks **before** its first
    /// dereference of them. Subset of `checks_null_params`.
    ///
    /// The ordering is the whole point. A caller asking "is it safe to hand
    /// this callee an unvalidated pointer?" is answered by
    /// `checks_null_params` only when the check happens first: a callee that
    /// dereferences `conn` at `if (conn->client)` and null-tests it on some
    /// later path has still crashed. That distinction is what separates a
    /// real callee summary from "the pointer was forwarded to a helper,
    /// assume it is checked" — a shortcut that turns confirmed true positives
    /// into misses, since at the flagged function a safe forwarding wrapper
    /// and an unsafe one are structurally identical and only the callee's
    /// body tells them apart (task 744, tools_sqc).
    #[serde(default)]
    pub checks_null_params_before_deref: HashSet<usize>,
    /// Whether this function never returns (calls abort/exit/longjmp).
    pub never_returns: bool,
    /// Aggregated null states of arguments at all call sites (populated by prescan second pass).
    /// Maps parameter index → joined NullState from all callers.
    pub callsite_param_null_states: HashMap<usize, NullState>,
    /// Argument-position pairs `(lower, higher)` at which SOME call site
    /// anywhere in the pre-scanned project hands this function two named,
    /// DIFFERENT storage objects.
    ///
    /// The caller-side fact ARR36-C's parameter model needs: two pointer
    /// parameters are taken to share an object unless a caller proves
    /// otherwise, and a callee whose callers all live in other translation
    /// units has no such proof in its own file (task 936). Distinctness is
    /// per CALL SITE rather than per position -- one caller passing `a` at
    /// index 0 and a different caller passing `b` at index 1 proves nothing,
    /// because no single path ever holds both. One proving call site IS
    /// enough: the comparison inside the callee is undefined whenever that
    /// caller's path runs.
    #[serde(default)]
    pub distinct_object_param_pairs: HashSet<(usize, usize)>,
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
    /// True when the function returns a value and EVERY `return` expression in
    /// its body is fixed at compile time — a literal, `sizeof`, a macro
    /// constant or enumerator, or arithmetic over those — in the weak sense of
    /// [`const_eval::is_compile_time_constant_expr`], which does not require
    /// the value to fold.
    ///
    /// The fact `return_range` cannot carry: seL4's `pageBitsForSize()` is a
    /// switch returning one of three enumerators whose definitions live in a
    /// generated header outside the scan, so every return expression is
    /// unfoldable and `return_range` is `None` even though the call is no more
    /// of a runtime hazard than a literal. Lets INT34-C hoist its
    /// constant-shift-amount reasoning across a call.
    #[serde(default)]
    pub returns_only_compile_time_constants: bool,
    /// Parameter pass-through: which of this function's params are forwarded to
    /// callees. Maps caller_param_idx → Vec<(callee_name, callee_param_idx)>.
    /// Used for transitive free propagation (MEM31-C).
    #[serde(default)]
    pub param_passthroughs: HashMap<usize, Vec<(String, usize)>>,
    /// Subset of `param_passthroughs` whose forwarding CALL SITE is itself
    /// unconditional (not nested inside an if/switch/loop/ternary). Used to
    /// propagate `unconditional_frees_params` transitively — a passthrough
    /// at a conditional call site can't make the caller's free
    /// unconditional even if the callee's own free is (task 401).
    #[serde(default)]
    pub unconditional_param_passthroughs: HashMap<usize, Vec<(String, usize)>>,
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
    /// Like `callsite_param_buffer_size`, but for a struct-by-value
    /// parameter whose FIELD (not the parameter itself) holds the buffer
    /// pointer: maps parameter index → field name → minimum element-count
    /// buffer size that field resolves to across every call site. A field
    /// is present only when every call site passing a value at that
    /// parameter position is a plain identifier AND that identifier's
    /// caller-local tracking resolved this exact field to a known static
    /// buffer size — a call site that passes a non-identifier expression,
    /// or an identifier whose tracking never pins this field down,
    /// disqualifies the field entirely rather than being skipped, mirroring
    /// `callsite_param_buffer_size`'s "trust only when every caller
    /// resolves" discipline at field granularity. Used by ARR38-C to
    /// resolve Juliet flow variant 67 (`data flow: data passed in a struct
    /// from one function to another, often in different source files`),
    /// where the sink function's own body only sees `data = myStruct.field;`
    /// with no idea what the caller set `field` to.
    #[serde(default)]
    pub callsite_param_field_buffer_size: HashMap<usize, HashMap<String, usize>>,
    /// Maximum element-count buffer size or memset-fill content length this
    /// function itself writes into a parameter (via a direct/aliased
    /// malloc-family allocation assigned to it, or a `memset` fill followed
    /// by an explicit null terminator on it) before returning. The opposite
    /// direction of `callsite_param_buffer_size`: that records what CALLERS
    /// pass in, this records what THIS function PRODUCES for its own
    /// parameter. Lets STR31-C resolve a same-file-or-cross-file "source
    /// relay" pattern — `data = someSource(data)`, where `someSource`
    /// conditionally allocates or content-fills its own parameter and
    /// returns it (Juliet flow variants 21/22) — without needing the
    /// callee's AST in the current file, the way the same-file case does.
    #[serde(default)]
    pub produces_param_buffer_size: HashMap<usize, usize>,
    /// Parameter indices that this function closes (e.g., `fclose(param)`,
    /// `close(param)`, `CloseHandle(param)`). Mirrors `frees_params` but for
    /// FIO42-C's file/descriptor/handle resources instead of heap memory.
    /// Propagated transitively through `param_passthroughs` by
    /// `propagate_transitive_closes`, so a resource opened in one function and
    /// closed by a sink helper it's passed to (directly or through a chain of
    /// forwarding wrappers) is recognized as closed (task 146).
    #[serde(default)]
    pub closes_params: HashSet<usize>,
    /// Parameter indices where at least one call site within the project
    /// passes an argument recognized as tainted (a known user-input source,
    /// `argv`, or data traced back to one via a direct assignment/string-copy
    /// chain within the caller). Paired with `callsite_param_taint_observed`
    /// so an absent index can be told apart from "definitely never tainted":
    /// only trust an index as taint-free when `callsite_param_taint_observed`
    /// also contains it. Used by FIO30-C to extend its intra-file wrapper
    /// taint fixpoint across files — Juliet's CWE-134 b/c/d/e flow variants
    /// put the sink helper (e.g. `badSink`/`goodG2BSink`) in a different file
    /// than its single caller, so a per-translation-unit analysis can never
    /// observe whether that caller passed a literal or tainted value (task 201).
    #[serde(default)]
    pub callsite_param_tainted: HashSet<usize>,
    /// Parameter indices for which at least one call site within the project
    /// was observed at all (regardless of taintedness). See
    /// `callsite_param_tainted` for why this companion set exists.
    #[serde(default)]
    pub callsite_param_taint_observed: HashSet<usize>,
    /// Parameter indices whose argument EVERY call site seen anywhere in the
    /// scanned project already bounds-checks with a dominating comparison
    /// before passing (`if (i < n) callee(i)`), with at least one such call
    /// site observed. The cross-file half of ARR30-C's validate-then-act
    /// suppression: a callee written to trust an index its callers range-check
    /// reads, on its own body, exactly like one that forgot to check.
    ///
    /// Only bare-variable arguments can be validated — see
    /// `guard_dominance::call_arg_guards`, which produces the per-site flags
    /// this aggregates — so a single call site passing an expression, or
    /// passing an unguarded variable, disqualifies the position entirely.
    #[serde(default)]
    pub callsite_param_validated: HashSet<usize>,
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
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
) -> HashMap<String, FunctionSummary> {
    let mut summaries = HashMap::new();

    collect_function_summaries(
        root,
        source,
        macros,
        compute_return_ranges,
        taint_source_aliases,
        string_macros,
        function_macros,
        &mut summaries,
    );

    summaries
}

#[allow(clippy::too_many_arguments)]
fn collect_function_summaries(
    node: &Node,
    source: &str,
    macros: &MacroConstantMap,
    compute_return_ranges: bool,
    taint_source_aliases: &[String],
    string_macros: &HashMap<String, String>,
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
    summaries: &mut HashMap<String, FunctionSummary>,
) {
    // Iterative pre-order rather than recursion, and the order is the same one
    // a recursive descent produced (children pushed reversed, popped LIFO), so
    // which definition wins a duplicate name is unchanged.
    //
    // The walk below descends into EVERY child, so its depth is the AST's own
    // nesting depth -- unbounded, and reached in practice by a file whose
    // #ifdef braces make tree-sitter nest every remaining function inside the
    // last good one. As recursion that cost one stack frame per level, each
    // holding an `analyze_function` result, so the frame grew with
    // `FunctionSummary` itself: raylib's parse aborted the entire scan the
    // next time the struct gained a field, and would have again on the one
    // after that (task 1011, tools_sqc). Depth now costs heap.
    let mut stack = vec![*node];
    while let Some(current) = stack.pop() {
        if current.kind() == "function_definition" && !is_macro_function_definition(&current) {
            if let Some(name) = extract_function_name(&current, source) {
                let summary = analyze_function(
                    &current,
                    source,
                    macros,
                    compute_return_ranges,
                    taint_source_aliases,
                    string_macros,
                    function_macros,
                );
                summaries.insert(name, summary);
            }
        }

        // Descend into every child unconditionally, not just preproc wrappers.
        // A brace that opens and closes in different branches of the same
        // repeated #ifdef guard makes tree-sitter-c's preprocessor-less parse
        // swallow every subsequent sibling function_definition as a nested
        // descendant of the corrupted one (see `is_real_nested_function_definition`
        // and lang_parsing_substrate::calls, which hit the identical failure
        // mode for call-graph edges). Stopping at preproc_* children only would
        // leave every swallowed sibling permanently invisible to this map — a
        // silent false-negative for every interprocedural rule keyed on
        // FunctionSummary (MSC04-C, EXP34-C, MEM30/31-C, null-state, taint).
        // Walking everywhere instead still finds and summarizes it under its
        // own name, even though it's nested in the AST.
        for i in (0..current.child_count()).rev() {
            if let Some(child) = current.child(i) {
                stack.push(child);
            }
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

/// True if `func_node` (a whole `function_definition`) sits inside a
/// preprocessor conditional branch (`#if`/`#ifdef`/`#ifndef`/`#elif`/`#else`).
/// aurora-lint has no preprocessor, so when a function has one definition guarded by
/// such a branch and another unconditional (or differently-guarded)
/// definition of the same name, only one is ever really compiled in — but
/// both get parsed and their facts unioned into one cross-file
/// `FunctionSummary` (needed for cases like hostap's `os_free`, whose
/// several platform-variant bodies all agree). That union is unsound when a
/// conditional definition is a semantically different fallback rather than a
/// same-behavior variant: hostap's `eapol_supp_sm.h` declares the real
/// `eapol_sm_init` under `#if IEEE8021X_EAPOL` but also provides a
/// `#else`-guarded stub `eapol_sm_init` that unconditionally
/// `free(ctx)`s and returns a dummy sentinel. Crediting that stub's
/// unconditional free into the summary poisoned every call site of the
/// *real* `eapol_sm_init` with a phantom already-freed `ctx`, which then
/// made MEM30-C flag three independent, mutually-exclusive
/// `if (...) { os_free(ctx); return -1; }` early-return checks in
/// `wpa_supplicant/eapol_test.c` as double-freeing each other (task 654).
/// Excluding a conditional definition's free-crediting facts from the
/// summary is conservative in the same direction as the rest of MEM30-C:
/// worst case it silently loses a real MUST-free fact (a false negative),
/// never gains a phantom one (a false positive).
fn function_definition_is_preproc_conditional(func_node: &Node) -> bool {
    let mut current = *func_node;
    while let Some(parent) = current.parent() {
        if matches!(
            parent.kind(),
            "preproc_if" | "preproc_ifdef" | "preproc_elif" | "preproc_else"
        ) {
            return true;
        }
        current = parent;
    }
    false
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
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
) -> FunctionSummary {
    let mut summary = FunctionSummary::default();

    // Collect parameter names
    let params = collect_param_names(func_node, source);

    // Check the return type
    let is_pointer_return;
    let is_void_return;
    if let Some(return_type) = func_node.child_by_field_name("type") {
        let type_text = return_type.utf8_text(source.as_bytes()).unwrap_or("");
        // Functions returning pointer types might return NULL. Walk the
        // declarator chain rather than substring-searching its text: a
        // plain `T foo(const u8 *arg)` declarator's *text* also contains
        // '*' (from the pointer parameter), which previously made every
        // function taking a pointer argument look like it returns a
        // pointer regardless of its actual return type (task 425).
        is_pointer_return = func_node
            .child_by_field_name("declarator")
            .is_some_and(|d| declarator_denotes_pointer_return(&d));
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

        // Check for returns-allocation pattern. Gated on the function's own
        // declared return type actually being a pointer: a non-pointer
        // (enum/int/u16/bool/...) function that merely calls malloc/calloc/
        // etc. somewhere in its body -- e.g. to fill an out-param or a
        // struct field -- does not hand a fresh allocation back to its
        // caller via the return value, so callers assigning its result to a
        // local must not have that local treated as owning fresh memory
        // (task 425: MEM31-C flagging non-pointer status locals like `enum
        // wpa_validate_result`/`u16`/`int` as leaked/double-freed because
        // the assigning callee's body happened to contain a malloc call).
        // Comments are stripped first (task 427): a borrowed-accessor
        // function whose body has no allocator call at all but a doc
        // comment merely *mentioning* one -- e.g. sqlite3_column_blob()'s
        // "might need to call malloc() to expand..." -- must not count.
        let body_text_no_comments = strip_comments_multiline(body_text);
        summary.returns_allocation = is_pointer_return
            && (body_text_no_comments.contains("malloc(")
                || body_text_no_comments.contains("calloc(")
                || body_text_no_comments.contains("realloc(")
                || body_text_no_comments.contains("aligned_alloc("));

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
        analyze_param_usage(
            &body,
            source,
            body_text,
            &params,
            function_macros,
            !function_definition_is_preproc_conditional(func_node),
            &mut summary,
        );

        // Compute return value range for integer-returning functions (only when VRA is needed)
        if compute_return_ranges && !is_void_return && !is_pointer_return {
            summary.return_range = compute_return_range(&body, source, macros);
            summary.returns_only_compile_time_constants =
                returns_only_compile_time_constants(&body, source, macros);
        }

        // Only a pointer-returning function can hand a written-into
        // parameter back to its caller by value (Juliet's "source relay"
        // pattern: `data = someSource(data)`) — a void function's writes
        // to a parameter are visible through the pointer itself, not this
        // summary.
        if is_pointer_return {
            summary.produces_param_buffer_size =
                compute_produces_param_buffer_size(&body, source, &params, macros);
        }
    }

    summary
}

/// For each parameter, the largest buffer size or memset-fill content length
/// this function itself writes into it — directly, or through one local
/// alias hop (`char *buf = malloc(...); data = buf;`) — before returning.
/// See [`FunctionSummary::produces_param_buffer_size`].
fn compute_produces_param_buffer_size(
    body: &Node,
    source: &str,
    params: &[String],
    macros: &MacroConstantMap,
) -> HashMap<usize, usize> {
    let start = body.start_position().row;
    let end = body.end_position().row;
    let mut result = HashMap::new();
    for (idx, param_name) in params.iter().enumerate() {
        if let Some(size) = produced_size_for_var(param_name, body, source, start, end, macros) {
            result.insert(idx, size);
            continue;
        }
        if let Some(alias) =
            crate::analyze::buffer_size::resolve_bare_alias_in_range(param_name, source, start, end)
        {
            if let Some(size) = produced_size_for_var(&alias, body, source, start, end, macros) {
                result.insert(idx, size);
            }
        }
    }
    result
}

/// Combine every buffer-size resolver a relay function's own body can prove
/// a variable safe under, within an explicit row range: allocation size,
/// memset-fill content length, a fixed array declaration's element count, or
/// a strlen/wcslen-derived allocation. Only one is ever meaningful for a
/// given relay function in practice, so whichever resolves first is the
/// answer. Mirrors the resolver chain `Str31C::find_buffer_size` uses for
/// its own same-file relay lookup (task 506) — kept in lock-step so the
/// same-file and cross-file relay-resolution paths stay equally capable.
fn produced_size_for_var(
    var_name: &str,
    body: &Node,
    source: &str,
    start: usize,
    end: usize,
    macros: &MacroConstantMap,
) -> Option<usize> {
    crate::analyze::buffer_size::resolve_alloc_assigned_in_range(var_name, source, start, end)
        .or_else(|| {
            crate::analyze::buffer_size::memset_content_length_in_range(
                var_name,
                source,
                start,
                end + 1,
            )
        })
        .or_else(|| {
            crate::analyze::array_size::resolve_declared_array_size(body, var_name, source, macros)
        })
        .or_else(|| {
            let lines: Vec<&str> = source.lines().collect();
            crate::analyze::buffer_size::resolve_strlen_based_alloc_size(
                var_name, &lines, start, end,
            )
        })
}

/// Collect parameter names from a function declaration.
pub fn collect_param_names(func_node: &Node, source: &str) -> Vec<String> {
    let mut params = Vec::new();

    if let Some(declarator) = func_node.child_by_field_name("declarator") {
        collect_params_recursive(&declarator, source, &mut params);
    }

    params
}

/// Walk a function's top-level declarator chain to determine whether the
/// function's *return type* is a pointer, without descending into the
/// parameter list (where `pointer_declarator`/`*` from an argument type
/// would otherwise be mistaken for the return type's own pointer-ness).
/// `T *foo(...)` parses as `pointer_declarator(declarator: function_declarator(...))`;
/// `T foo(...)` parses as a bare `function_declarator`; multi-level pointers
/// and parenthesized declarators nest further before reaching either.
fn declarator_denotes_pointer_return(declarator: &Node) -> bool {
    let mut node = *declarator;
    loop {
        match node.kind() {
            "pointer_declarator" => return true,
            "function_declarator" => return false,
            _ => match node.child_by_field_name("declarator") {
                Some(inner) => node = inner,
                None => return false,
            },
        }
    }
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

/// Strip `/* ... */` and `// ...` comments from a (possibly multi-line)
/// function body before a plain substring scan. Without this, a comment
/// merely *mentioning* an allocator call -- e.g. sqlite's own
/// `sqlite3_column_blob`, whose body has no `malloc()` call at all but a
/// doc comment reading "might need to call malloc() to expand the result of
/// a zeroblob()" -- makes `returns_allocation`'s substring check below
/// misfire on a borrowed-accessor function that never allocates anything
/// (task 427). Unlike `macro_expand::strip_comments` (single-line macro
/// replacement lists, where hitting `//` means "rest of the line is gone"),
/// this must span a whole multi-line function body: a `//` only blanks out
/// to the next newline, not to the end of the text.
fn strip_comments_multiline(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(chars.len());
            out.push(' ');
        } else if chars[i] == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
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

/// True if `body_text` writes through `param_name` via a bare dereference
/// assignment, `*param_name = …`, tolerating an intervening `++`/`--`
/// (`*param_name++ = …`) between the identifier and the `=`. Excludes
/// comparison operators (`==`, `!=`, `<=`, `>=`) the same way the plain
/// `*param =` check historically did.
///
/// The walking-pointer buffer-fill idiom this exists for --
/// `*rnd++ = (unsigned char)(r & 0xFF);` -- is curl's `Curl_rand_bytes`
/// (task 589/456: `EXP33-C`'s macro-forwarding fix for `Curl_rand` only
/// pays off once the forwarded function's own summary actually recognizes
/// its write). A literal `"*{param} ="` substring match (the previous
/// check) misses this because of the `++` in between.
fn body_has_deref_write(body_text: &str, param_name: &str) -> bool {
    let pattern = format!("*{param_name}");
    let mut search_from = 0;
    while let Some(rel) = body_text[search_from..].find(&pattern) {
        let pos = search_from + rel;
        let after = pos + pattern.len();
        search_from = after;
        let rest = body_text[after..].trim_start();
        let rest = rest
            .strip_prefix("++")
            .or_else(|| rest.strip_prefix("--"))
            .unwrap_or(rest)
            .trim_start();
        if let Some(after_eq) = rest.strip_prefix('=') {
            if !after_eq.starts_with('=') {
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
/// True if some line in `body_text` writes through `param_name` via
/// `param_name->...` or `param_name[...]` -- i.e. the arrow/subscript access
/// is followed by a genuine assignment operator (not `==`/`!=`/`<=`/`>=`) on
/// the same line. A bare `param_name->field` or `param_name[i]` with no
/// following `=` is a READ, not a write (see modifies_params call site).
fn line_has_arrow_or_subscript_write(body_text: &str, param_name: &str) -> bool {
    let arrow_pattern = format!("{}->", param_name);
    let subscript_pattern = format!("{}[", param_name);
    for line in body_text.lines() {
        let access_pos = line
            .find(&arrow_pattern)
            .or_else(|| line.find(&subscript_pattern));
        let Some(access_pos) = access_pos else {
            continue;
        };
        // Find an `=` after the access that isn't part of ==, !=, <=, >=.
        let after_access = &line[access_pos..];
        let mut search_from = 0;
        while let Some(rel_eq) = after_access[search_from..].find('=') {
            let eq_pos = search_from + rel_eq;
            let before = &after_access[..eq_pos];
            let after = &after_access[eq_pos + 1..];
            let is_comparison = before.ends_with('!')
                || before.ends_with('<')
                || before.ends_with('>')
                || before.ends_with('=')
                || after.starts_with('=');
            if !is_comparison {
                return true;
            }
            search_from = eq_pos + 1;
        }
    }
    false
}

/// True if `node` is unconditionally reached whenever `body` (the enclosing
/// function's own compound_statement) is entered — i.e. no ancestor between
/// `node` and `body` is a construct that might not execute (an `if`/`switch`
/// arm, a loop body that could run zero times, a ternary branch, or a
/// preprocessor conditional). Plain nested `{ }` scoping blocks are
/// transparent (still unconditional). Used to distinguish a MUST-free from
/// a merely-possible MAY-free (task 401).
fn is_unconditionally_reached(node: &Node, body: &Node) -> bool {
    let mut current = *node;
    loop {
        let Some(parent) = current.parent() else {
            return true;
        };
        if parent.id() == body.id() {
            return true;
        }
        if matches!(
            parent.kind(),
            "if_statement"
                | "switch_statement"
                | "case_statement"
                | "conditional_expression"
                | "for_statement"
                | "while_statement"
                | "do_statement"
        ) || parent.kind().starts_with("preproc_if")
        {
            return false;
        }
        current = parent;
    }
}

/// Whether `condition` is EXACTLY a null test of `name` and nothing else,
/// reporting which branch is the one on which `name` is non-null:
/// `Some(true)` when that is the consequence, `Some(false)` when it is the
/// `else`.
///
/// Deliberately narrower than `null_state`'s condition parser, which unions
/// the operands of `&&` and `||`. Here a compound condition must yield
/// `None`: `if (ptr && ready)` guards its body on something this frame knows
/// nothing about, and treating it as a bare null check is exactly the
/// over-trust that made MAY-frees unusable (task 401).
fn null_guard_on(condition: &Node, source: &str, name: &str) -> Option<bool> {
    let text = |n: &Node| n.utf8_text(source.as_bytes()).unwrap_or("").trim();
    let is_null_literal = |n: &Node| matches!(text(n), "NULL" | "0" | "nullptr");
    let is_name = |n: &Node| n.kind() == "identifier" && text(n) == name;

    match condition.kind() {
        "parenthesized_expression" => null_guard_on(&condition.child(1)?, source, name),
        "identifier" => is_name(condition).then_some(true),
        "unary_expression" => {
            let operator = condition.child(0)?;
            let argument = condition.child_by_field_name("argument")?;
            (text(&operator) == "!" && is_name(&argument)).then_some(false)
        }
        "binary_expression" => {
            let left = condition.child_by_field_name("left")?;
            let right = condition.child_by_field_name("right")?;
            let operator = condition.child_by_field_name("operator")?;
            let compares_name = (is_name(&left) && is_null_literal(&right))
                || (is_null_literal(&left) && is_name(&right));
            if !compares_name {
                return None;
            }
            match text(&operator) {
                "!=" => Some(true),
                "==" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `is_unconditionally_reached`, except that an `if` guarding only on whether
/// `guarded` is null is transparent.
///
/// A free reached solely under `if (ptr != NULL)` — or in the `else` of
/// `if (ptr == NULL)` — is effectively a MUST-free: on the branch that skips
/// it there is nothing to free, so nothing survives the call for the caller
/// to use. Marking the argument freed therefore cannot invent a
/// use-after-free, which is the failure the MUST set exists to prevent
/// (task 988, tools_sqc).
///
/// The guard must be on the pointer being freed and on nothing else. Any
/// other condition — a different variable, a flag, a compound test — is a
/// real MAY-free and reinstates task 401's answer, because there the skipped
/// path can leave a live pointer the caller goes on to use.
fn is_unconditionally_reached_modulo_null_guard(
    node: &Node,
    body: &Node,
    source: &str,
    guarded: &str,
) -> bool {
    let mut current = *node;
    loop {
        let Some(parent) = current.parent() else {
            return true;
        };
        if parent.id() == body.id() {
            return true;
        }
        if parent.kind() == "if_statement" {
            let Some(condition) = parent.child_by_field_name("condition") else {
                return false;
            };
            let Some(non_null_on_true) = null_guard_on(&condition, source, guarded) else {
                return false;
            };
            // Which arm did the walk come up through? `alternative` is the
            // `else_clause` wrapper, so an identity test against both fields
            // answers it without assuming either is present.
            let from = |field: &str| {
                parent
                    .child_by_field_name(field)
                    .is_some_and(|arm| arm.id() == current.id())
            };
            let reached_when_non_null = if from("consequence") {
                non_null_on_true
            } else if from("alternative") {
                !non_null_on_true
            } else {
                // The condition itself, or some other child: not an arm.
                return false;
            };
            if !reached_when_non_null {
                return false;
            }
        } else if matches!(
            parent.kind(),
            "switch_statement"
                | "case_statement"
                | "conditional_expression"
                | "for_statement"
                | "while_statement"
                | "do_statement"
        ) || parent.kind().starts_with("preproc_if")
        {
            return false;
        }
        current = parent;
    }
}

/// Reduce a `free()` argument to the identifier it releases, reporting whether
/// the release goes through the identifier's pointee.
///
/// `free(p)` yields `(p, false)`; `free(*p)` and `free((*p))` yield `(p, true)`
/// — the `void **` "safe free" wrapper shape. Parentheses and casts are
/// transparent, so `free((char *) *p)` still resolves. Anything else (a field,
/// a subscript, a call) yields `None`.
fn strip_free_argument(arg: Node) -> Option<(Node, bool)> {
    fn peel(mut n: Node) -> Node {
        loop {
            let inner = match n.kind() {
                "parenthesized_expression" => n.named_child(0),
                "cast_expression" => n.child_by_field_name("value"),
                _ => None,
            };
            match inner {
                Some(i) => n = i,
                None => return n,
            }
        }
    }

    let node = peel(arg);
    if node.kind() == "identifier" {
        return Some((node, false));
    }
    if node.kind() == "pointer_expression" {
        let op = node.child_by_field_name("operator")?;
        if op.kind() != "*" {
            return None;
        }
        let inner = peel(node.child_by_field_name("argument")?);
        if inner.kind() == "identifier" {
            return Some((inner, true));
        }
    }
    None
}

/// Credit `summary.frees_params` (MAY-free) and `summary.
/// unconditional_frees_params` (MUST-free) for every `free(param)` call in
/// `body` whose sole argument is exactly one of `params` by simple
/// identifier — AST-based rather than the old text-substring scan so
/// `is_unconditionally_reached` can be checked per call site (task 401).
/// The parameter-rooted lvalue an assignment writes THROUGH, if any.
///
/// `*p`, `p->f`, `p[i]`, `(*p).f` and `*p++` all write to storage the caller
/// owns; a bare `p = ...` rebinds the local copy of the pointer and writes
/// nothing the caller can observe, which is why a dereference has to be seen
/// somewhere on the path before the root identifier counts.
fn deref_write_root<'a>(lvalue: &Node<'a>, saw_deref: bool) -> Option<Node<'a>> {
    match lvalue.kind() {
        "identifier" => saw_deref.then_some(*lvalue),
        "parenthesized_expression" => deref_write_root(&lvalue.child(1)?, saw_deref),
        "cast_expression" => deref_write_root(&lvalue.child_by_field_name("value")?, saw_deref),
        "update_expression" => {
            deref_write_root(&lvalue.child_by_field_name("argument")?, saw_deref)
        }
        "pointer_expression" => {
            let operator = lvalue.child(0)?;
            let is_deref = operator.kind() == "*";
            deref_write_root(
                &lvalue.child_by_field_name("argument")?,
                saw_deref || is_deref,
            )
        }
        "subscript_expression" => deref_write_root(&lvalue.child_by_field_name("argument")?, true),
        "field_expression" => {
            // `p->f` dereferences p; `s.f` does not, and only reaches a
            // parameter's storage if something below it did.
            let arrow = lvalue
                .child_by_field_name("operator")
                .is_some_and(|op| op.kind() == "->");
            deref_write_root(&lvalue.child_by_field_name("argument")?, saw_deref || arrow)
        }
        _ => None,
    }
}

/// The parameter-rooted objects a call writes through by virtue of being a
/// known initializing library function: `memset(e, 0, sizeof(*e))` writes
/// `e`, `os_memcpy(e->buf, src, n)` writes `e`.
///
/// `modifies_params`' three existing detectors (`body_has_deref_write`,
/// `line_has_arrow_or_subscript_write`, `is_fd_set_macro_write`) all require
/// an ASSIGNMENT OPERATOR rooted at the parameter, so a callee whose entire
/// initialisation of its output is a memory-writing library call never entered
/// the map -- and `credit_modifies_params`, the MUST/MAY refinement and the
/// forwarded-write obligations are every one of them reached only from there.
/// hostap's `ieee802_11_parse_elems`, whose body is `os_memset(elems, 0, ...)`
/// and a forward, had 65 callers reported uninitialised on that account (task
/// 1026, tools_sqc).
///
/// Name-independent by construction: resolution is
/// `init_state::match_initializing_function`, whose suffix matcher is what
/// turns `os_memset` into `memset`, over that module's own output-index
/// tables. Nothing here carries a second list to disagree with them.
fn library_written_roots<'a>(call: &Node<'a>, source: &str) -> Vec<Node<'a>> {
    let mut roots = Vec::new();
    let Some(func) = call.child_by_field_name("function") else {
        return roots;
    };
    let func_name = func.utf8_text(source.as_bytes()).unwrap_or("");
    let Some(base) = init_state::match_initializing_function(func_name) else {
        return roots;
    };
    // `regexec`/`mbrlen` and friends are listed as initializers but read
    // through their pointer arguments; that judgement lives in one place.
    if init_state::is_non_initializing_function(base) {
        return roots;
    }
    let indices = init_state::get_output_arg_indices(base);
    let variadic_from = init_state::variadic_output_from_index(base);
    let Some(args) = call.child_by_field_name("arguments") else {
        return roots;
    };
    let mut arg_idx = 0usize;
    for i in 0..args.child_count() {
        let Some(arg) = args.child(i) else { continue };
        if matches!(arg.kind(), "," | "(" | ")") {
            continue;
        }
        let is_output =
            indices.contains(&arg_idx) || variadic_from.is_some_and(|first| arg_idx >= first);
        if is_output {
            if let Some(root) = written_arg_root(&arg) {
                roots.push(root);
            }
        }
        arg_idx += 1;
    }
    roots
}

/// The object an output argument writes through, when it reaches storage the
/// CALLER owns.
///
/// A bare `e` counts: handing the pointer over is itself the dereference.
/// Below that, `deref_write_root` decides, so this draws exactly the line an
/// assignment already does and cannot drift from it -- `e->buf` and `e[i]`
/// count, `&e.f` does not.
fn written_arg_root<'a>(arg: &Node<'a>) -> Option<Node<'a>> {
    match arg.kind() {
        "identifier" => Some(*arg),
        "parenthesized_expression" => written_arg_root(&arg.child(1)?),
        "cast_expression" => written_arg_root(&arg.child_by_field_name("value")?),
        _ => deref_write_root(arg, false),
    }
}

/// Every name an initializing library call in `body` writes through. The
/// MAY-write half of `library_written_roots`; the MUST/MAY refinement is
/// `credit_modifies_params`' business, as it is for an assignment.
///
/// Returned as a set rather than answered per parameter, because the walk
/// costs the same whether one name or eight are being asked about and this
/// file has been the source of superlinear scan behaviour before.
fn library_written_names(body: &Node, source: &str) -> HashSet<String> {
    use lang_parsing_substrate::query;

    query::find_descendants_of_kind(*body, "call_expression")
        .into_iter()
        .flat_map(|call| library_written_roots(&call, source))
        .filter_map(|root| root.utf8_text(source.as_bytes()).ok().map(str::to_string))
        .collect()
}

/// The `(callee, callee parameter index)` pairs a coverage answer is
/// contingent on. Empty means the answer stands on this function's own
/// writes; see `FunctionSummary::modifies_params_pending`.
type WriteObligations = BTreeSet<(String, usize)>;

/// Whether every path that falls out of `stmt` writes through `param`, and
/// what that answer rests on: `None` is not covered, `Some(set)` is covered
/// provided every pair in `set` is itself a MUST-write, and `Some(empty)` is
/// covered outright.
///
/// The exhaustiveness question AST position cannot answer. sqlite's
/// `fts5CsrPoslist` sets `*pn` and `*pa` in each arm of an if/else and again
/// in both arms of a trailing `if (rc == SQLITE_OK) ... else ...`: every
/// write is nested inside a conditional, and yet no returning path leaves the
/// outputs untouched. Judging such a function by position alone reports its
/// callers' variables uninitialised (task 988, tools_sqc).
///
/// One arm of that function writes `*pa` only by handing `pa` to
/// `sqlite3Fts5ExprPoslist`, which a structural walk cannot see through. That
/// leg returns an obligation rather than a verdict, so the interprocedural
/// half of the answer is deferred instead of guessed (task 1011, tools_sqc).
///
/// Only an if/else with BOTH arms covered counts. A bare `if` without an
/// `else` and a loop that may run zero times are left as partial -- which is
/// the honest reading and the one the fixture depends on: `set_flag`'s
/// `if`/`else if` has no final `else`. A `switch` is partial too UNLESS it
/// carries a `default`, which makes it exhaustive by construction; see
/// `switch_writes_on_all_paths` (task 1025, tools_sqc).
///
/// Early `return`s are not modelled, matching the simplification
/// `is_unconditionally_reached` already makes.
///
/// Depth-capped. An `if`/`else if` chain nests one level per arm, so a
/// machine-generated chain thousands long recurses as deep, and this runs on
/// prescan worker threads whose stacks are far smaller than the main one --
/// raylib overflowed and aborted the whole scan. Past the cap the answer is
/// the conservative one, which is the same thing an uncovered branch returns.
fn writes_on_all_paths(stmt: &Node, source: &str, param: &str) -> Option<WriteObligations> {
    writes_on_all_paths_capped(stmt, source, param, 0)
}

/// Deep enough for any hand-written nesting, far below the stack a prescan
/// worker gets.
const WRITE_COVERAGE_MAX_DEPTH: u32 = 96;

fn writes_on_all_paths_capped(
    stmt: &Node,
    source: &str,
    param: &str,
    depth: u32,
) -> Option<WriteObligations> {
    if depth >= WRITE_COVERAGE_MAX_DEPTH {
        return None;
    }
    let writes_on_all_paths = |stmt: &Node, source: &str, param: &str| {
        writes_on_all_paths_capped(stmt, source, param, depth + 1)
    };
    match stmt.kind() {
        "compound_statement" | "translation_unit" => {
            // One covering statement is enough, so this is a disjunction --
            // and the cheapest covering statement is the one to report, since
            // an obligation a sibling already discharges outright would just
            // make the whole answer wait on a callee for nothing.
            let mut cursor = stmt.walk();
            let children: Vec<Node> = stmt.named_children(&mut cursor).collect();
            let mut best: Option<WriteObligations> = None;
            for child in &children {
                match writes_on_all_paths(child, source, param) {
                    Some(obligations) if obligations.is_empty() => return Some(obligations),
                    Some(obligations)
                        if best.as_ref().is_none_or(|b| obligations.len() < b.len()) =>
                    {
                        best = Some(obligations);
                    }
                    Some(_) => {}
                    None => {}
                }
            }
            best
        }
        "labeled_statement" => stmt
            .named_child(stmt.named_child_count().saturating_sub(1))
            .and_then(|inner| writes_on_all_paths(&inner, source, param)),
        "else_clause" => stmt
            .named_child(0)
            .and_then(|inner| writes_on_all_paths(&inner, source, param)),
        "if_statement" => {
            // Both arms, so this is a conjunction: the answer needs every
            // obligation either arm raised.
            let (Some(consequence), Some(alternative)) = (
                stmt.child_by_field_name("consequence"),
                stmt.child_by_field_name("alternative"),
            ) else {
                return None;
            };
            let mut obligations = writes_on_all_paths(&consequence, source, param)?;
            obligations.extend(writes_on_all_paths(&alternative, source, param)?);
            Some(obligations)
        }
        "expression_statement" => {
            let expr = stmt.named_child(0)?;
            let lvalue = match expr.kind() {
                "assignment_expression" => expr.child_by_field_name("left"),
                "update_expression" => expr.child_by_field_name("argument"),
                _ => None,
            };
            let writes_here = lvalue
                .and_then(|l| deref_write_root(&l, false))
                .is_some_and(|root| root.utf8_text(source.as_bytes()).unwrap_or("") == param);
            // `os_memset(out, 0, n);` is a write on this path with no
            // assignment operator to find (task 1026, tools_sqc). Asked here
            // rather than credited outright so a call under an `if` stays a
            // MAY-write, exactly as an assignment under one does.
            let library_writes_here = library_written_names(&expr, source).contains(param);
            if writes_here || library_writes_here {
                return Some(WriteObligations::new());
            }
            // `*pn = callee(..., pa)` writes through `pn` here and through
            // `pa` only inside the callee, so the same statement can be a
            // direct write for one parameter and a forwarded one for another.
            let (callee, idx) = forwarded_write_obligation(&expr, source, param)?;
            Some(WriteObligations::from([(callee, idx)]))
        }
        "switch_statement" => switch_writes_on_all_paths(stmt, source, param, depth),
        _ => None,
    }
}

/// A `switch` covers every path leaving it when it has a `default` label and
/// every case group writes through `param`.
///
/// The reason a switch was left partial was "whose `default` may be absent",
/// and that reason expires when the default is present: such a switch is
/// exhaustive by construction, so if every arm writes then so does every path
/// out of the statement. curl's `cw_get_writefunc` assigns all four of its
/// output parameters in each of its three arms and every caller was still
/// reported uninitialised (task 1025, tools_sqc).
///
/// A conjunction over the groups, so the obligations are the union — the same
/// shape the `if`/`else` arm has, one level wider.
fn switch_writes_on_all_paths(
    stmt: &Node,
    source: &str,
    param: &str,
    depth: u32,
) -> Option<WriteObligations> {
    let body = stmt.child_by_field_name("body")?;
    let mut cursor = body.walk();
    let cases: Vec<Node> = body
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "case_statement")
        .collect();
    if cases.is_empty() {
        return None;
    }
    // Without a `default`, some value of the controlling expression leaves the
    // switch having executed none of it.
    if !cases
        .iter()
        .any(|c| c.child_by_field_name("value").is_none())
    {
        return None;
    }

    let mut obligations = WriteObligations::new();
    // Walked in reverse because fall-through runs the other way: a group that
    // does not break continues into the next one, and is covered by whatever
    // covers that. `None` here means the group after this one is not covered.
    let mut next_covered: Option<WriteObligations> = None;
    for case in cases.iter().rev() {
        let covered = match case_group_writes(case, source, param, depth) {
            Some(own) => own,
            None if !case_group_breaks(case) => next_covered.clone()?,
            None => return None,
        };
        obligations.extend(covered.iter().cloned());
        next_covered = Some(covered);
    }
    Some(obligations)
}

/// Coverage of one case group's own statements: a disjunction, since one
/// covering statement in the group is enough — the same rule
/// `compound_statement` applies, over children that share their parent with a
/// `value` label rather than sitting in a block of their own.
fn case_group_writes(
    case: &Node,
    source: &str,
    param: &str,
    depth: u32,
) -> Option<WriteObligations> {
    let value_id = case.child_by_field_name("value").map(|v| v.id());
    let mut cursor = case.walk();
    let mut best: Option<WriteObligations> = None;
    for child in case.named_children(&mut cursor) {
        if Some(child.id()) == value_id {
            continue;
        }
        match writes_on_all_paths_capped(&child, source, param, depth + 1) {
            Some(o) if o.is_empty() => return Some(o),
            Some(o) if best.as_ref().is_none_or(|b| o.len() < b.len()) => best = Some(o),
            Some(_) | None => {}
        }
    }
    best
}

/// Whether a case group ends in a statement that leaves the switch, so it does
/// NOT fall into the group below it. A group with no statements of its own —
/// stacked labels, `case A: case B:` — never breaks, which is what makes it
/// inherit the next group's coverage rather than fail for having written
/// nothing.
fn case_group_breaks(case: &Node) -> bool {
    let value_id = case.child_by_field_name("value").map(|v| v.id());
    let mut cursor = case.walk();
    let statements: Vec<Node> = case
        .named_children(&mut cursor)
        .filter(|c| Some(c.id()) != value_id && c.kind() != "comment")
        .collect();
    statements.last().is_some_and(|last| {
        matches!(
            last.kind(),
            "break_statement" | "return_statement" | "goto_statement" | "continue_statement"
        )
    })
}

/// The `(callee, parameter index)` a statement hands `param` to, if any --
/// the interprocedural leg of the coverage walk.
///
/// Argument position is counted exactly as `collect_param_passthroughs`
/// counts it, since the index is looked up against the callee's own summary
/// and the two have to agree. Only a bare identifier counts: `&param` and
/// `param->field` hand the callee something other than the parameter.
///
/// The first forwarding call in source order wins. A statement that forwards
/// `param` to two callees is really a disjunction -- either writing it
/// suffices -- which a flat obligation set cannot express, so taking one is
/// an under-approximation. That direction only leaves an existing false
/// positive standing; the alternative would suppress a real finding.
/// Every name `body` hands to a callee as a whole argument, casts included.
///
/// Asks the same question as `collect_param_passthroughs`, which strips casts
/// the same way, but keyed on the name rather than on a parameter index: this
/// one only has to know whether a name left the function, not where it landed.
///
/// A set for the same reason as `library_written_names`: one walk, however
/// many parameters ask.
fn forwarded_argument_names(body: &Node, source: &str) -> HashSet<String> {
    use lang_parsing_substrate::query;

    let mut names = HashSet::new();
    for call in query::find_descendants_of_kind(*body, "call_expression") {
        let callee = call
            .child_by_field_name("function")
            .and_then(|f| f.utf8_text(source.as_bytes()).ok())
            .unwrap_or("");
        // The same exclusion `forwarded_write_obligation` makes: these two are
        // the free path's business, not an output-parameter write.
        if callee.is_empty() || callee == "free" || callee == "realloc" {
            continue;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            let stripped = init_state::strip_arg_casts(&arg);
            if stripped.kind() == "identifier" {
                if let Ok(name) = stripped.utf8_text(source.as_bytes()) {
                    names.insert(name.to_string());
                }
            }
        }
    }
    names
}

fn forwarded_write_obligation(expr: &Node, source: &str, param: &str) -> Option<(String, usize)> {
    use lang_parsing_substrate::query;

    for call in query::find_descendants_of_kind(*expr, "call_expression") {
        let Some(func_node) = call.child_by_field_name("function") else {
            continue;
        };
        let callee = func_node.utf8_text(source.as_bytes()).unwrap_or("");
        // Same exclusion `collect_param_passthroughs` makes: these two are
        // the free path's business, not an output-parameter write.
        if callee.is_empty() || callee == "free" || callee == "realloc" {
            continue;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut callee_idx = 0usize;
        for i in 0..arguments.child_count() {
            let Some(arg) = arguments.child(i) else {
                continue;
            };
            if matches!(arg.kind(), "," | "(" | ")") {
                continue;
            }
            // `Curl_ssl_random(data, (unsigned char *)rnd, sizeof(*rnd))`
            // forwards `rnd` as surely as a bare `rnd` would; matching only a
            // bare identifier is what hid it (task 1027, tools_sqc).
            let stripped = init_state::strip_arg_casts(&arg);
            if stripped.kind() == "identifier"
                && stripped.utf8_text(source.as_bytes()).unwrap_or("") == param
            {
                return Some((callee.to_string(), callee_idx));
            }
            callee_idx += 1;
        }
    }
    None
}

/// Whether a `while`/`for` head is one that cannot be skipped: no condition at
/// all (`for(;;)`), or a non-zero integer literal (`while(1)`).
///
/// Anything needing evaluation is treated as skippable, which is the
/// conservative reading everywhere else in `clean_paths`.
fn loop_always_enters(stmt: &Node, source: &str) -> bool {
    match stmt.child_by_field_name("condition") {
        None => true,
        Some(condition) => {
            // A `while` head is a `parenthesized_expression`; a `for` head is
            // the expression itself.
            let mut inner = condition;
            while inner.kind() == "parenthesized_expression" {
                match inner.named_child(0) {
                    Some(child) => inner = child,
                    None => return false,
                }
            }
            let text = inner.utf8_text(source.as_bytes()).unwrap_or("").trim();
            inner.kind() == "number_literal" && text.parse::<i64>().is_ok_and(|v| v != 0)
        }
    }
}

/// Whether some path through this function reaches a `return` — or the end of
/// a void body — without the parameter having been written or handed to
/// anything that could write it.
///
/// The dual of `writes_on_all_paths`, and deliberately not its negation:
/// that walk answers "is coverage proven?", where a `None` covers both "there
/// is a path with no write" and "this pass cannot tell". Only the first is a
/// reason to withhold a caller's initialisation credit, so this asks for the
/// path directly. See `FunctionSummary::conditional_modifies_params`.
///
/// "Touched" is any mention of the parameter's identifier, not just a write.
/// A statement that merely reads it is still refused as a clean path, because
/// the mention may be a forward: `query(cf, data, kind, pport, phost)` writes
/// through both pointers and looks like nothing but two identifiers here.
/// Erring this way costs detections, never adds reports.
fn may_return_without_writing(body: &Node, source: &str, param: &str) -> bool {
    let (passes, returns) = clean_paths(body, source, param, 0);
    passes || returns
}

/// Same reasoning and the same cap as `writes_on_all_paths`: this walks a
/// prescan worker's stack, and an unbounded `if`/`else if` chain nests one
/// level per arm.
const CLEAN_PATH_MAX_DEPTH: u32 = 96;

/// `(a path leaves this statement untouched, a path returns from inside it
/// untouched)`.
///
/// Past the depth cap both answers are `false`, which claims nothing — the
/// same direction every other unhandled shape takes.
fn clean_paths(stmt: &Node, source: &str, param: &str, depth: u32) -> (bool, bool) {
    use lang_parsing_substrate::query;

    if depth >= CLEAN_PATH_MAX_DEPTH {
        return (false, false);
    }

    // Asked before the untouched-subtree shortcut below, which would otherwise
    // report a bare `return;` as merely passing through.
    if stmt.kind() == "return_statement" {
        return if guard_dominance::mentions_var(stmt, param, source) {
            (false, false)
        } else {
            (false, true)
        };
    }

    let mentions = guard_dominance::mentions_var(stmt, param, source);
    let returns_somewhere =
        || !query::find_descendants_of_kind(*stmt, "return_statement").is_empty();
    if !mentions && !returns_somewhere() {
        // Nothing in here touches the parameter and nothing in here leaves the
        // function, so every path through it is clean and none of them return.
        return (true, false);
    }

    match stmt.kind() {
        "compound_statement" => {
            let mut cursor = stmt.walk();
            let children: Vec<Node> = stmt.named_children(&mut cursor).collect();
            let mut passes = true;
            let mut returns = false;
            for child in &children {
                if child.kind() == "comment" {
                    continue;
                }
                let (child_passes, child_returns) = clean_paths(child, source, param, depth + 1);
                // Only reachable-while-still-clean returns count.
                returns |= child_returns;
                if !child_passes {
                    passes = false;
                    break;
                }
            }
            (passes, returns)
        }
        "labeled_statement" => stmt
            .named_child(stmt.named_child_count().saturating_sub(1))
            .map(|inner| clean_paths(&inner, source, param, depth + 1))
            .unwrap_or((false, false)),
        "else_clause" => stmt
            .named_child(0)
            .map(|inner| clean_paths(&inner, source, param, depth + 1))
            .unwrap_or((true, false)),
        "if_statement" => {
            let Some(condition) = stmt.child_by_field_name("condition") else {
                return (false, false);
            };
            if guard_dominance::mentions_var(&condition, param, source) {
                // `if (NULL == sign_flag) return;` mentions the parameter
                // without writing or forwarding it, and the arm it guards is
                // one no caller that goes on to READ the variable ever takes.
                // Counting that arm's `return` as an unwritten returning path
                // would make every optional-output function conditional on
                // the strength of a branch its callers cannot reach -- the
                // same discount `is_unconditionally_reached_modulo_null_guard`
                // makes for the MUST set.
                let Some(non_null_on_true) = null_guard_on(&condition, source, param) else {
                    return (false, false);
                };
                let reached = if non_null_on_true {
                    stmt.child_by_field_name("consequence")
                        .map(|c| clean_paths(&c, source, param, depth + 1))
                        .unwrap_or((true, false))
                } else {
                    match stmt.child_by_field_name("alternative") {
                        Some(alternative) => clean_paths(&alternative, source, param, depth + 1),
                        None => (true, false),
                    }
                };
                return reached;
            }
            let (then_passes, then_returns) = stmt
                .child_by_field_name("consequence")
                .map(|c| clean_paths(&c, source, param, depth + 1))
                .unwrap_or((true, false));
            // No `else` is an empty, untouched false branch -- which is
            // precisely why a bare `if` around every write leaves the
            // parameter unwritten.
            let (else_passes, else_returns) = match stmt.child_by_field_name("alternative") {
                Some(alternative) => clean_paths(&alternative, source, param, depth + 1),
                None => (true, false),
            };
            (then_passes || else_passes, then_returns || else_returns)
        }
        "while_statement" | "for_statement" => {
            // Zero iterations is a path through the loop, provided nothing
            // evaluated on the way in touches the parameter -- but only if
            // the loop can decline to run at all. `while(1)` and `for(;;)`
            // always enter, so their bodies write on every path that reaches
            // them: curl's `Curl_get_line` sets `*eof` at the top of a
            // `while(1)`, and reading a zero-iteration path into it reports
            // every caller.
            if loop_always_enters(stmt, source) {
                return stmt
                    .child_by_field_name("body")
                    .map(|b| clean_paths(&b, source, param, depth + 1))
                    .unwrap_or((false, false));
            }
            let body = stmt.child_by_field_name("body");
            let mut cursor = stmt.walk();
            let header_touches = stmt
                .named_children(&mut cursor)
                .filter(|c| body.is_none_or(|b| c.id() != b.id()))
                .any(|c| guard_dominance::mentions_var(&c, param, source));
            if header_touches {
                return (false, false);
            }
            let returns = body
                .map(|b| clean_paths(&b, source, param, depth + 1).1)
                .unwrap_or(false);
            (true, returns)
        }
        "do_statement" => {
            // The body runs before the condition is ever evaluated, so there
            // is no zero-iteration path to fall back on.
            if stmt
                .child_by_field_name("condition")
                .is_some_and(|c| guard_dominance::mentions_var(&c, param, source))
            {
                return (false, false);
            }
            stmt.child_by_field_name("body")
                .map(|b| clean_paths(&b, source, param, depth + 1))
                .unwrap_or((false, false))
        }
        "switch_statement" => {
            // Mirrors `switch_writes_on_all_paths` from the other side: a
            // `switch` with no `default` is not exhaustive, so a controlling
            // value matching no case leaves it having executed nothing. With
            // a `default` nothing is claimed -- proving a clean path through
            // one arm would have to reason about fall-through.
            let Some(condition) = stmt.child_by_field_name("condition") else {
                return (false, false);
            };
            if guard_dominance::mentions_var(&condition, param, source) {
                return (false, false);
            }
            let Some(body) = stmt.child_by_field_name("body") else {
                return (true, false);
            };
            let mut cursor = body.walk();
            let has_default = body
                .named_children(&mut cursor)
                .filter(|c| c.kind() == "case_statement")
                .any(|c| c.child_by_field_name("value").is_none());
            if has_default {
                (false, false)
            } else {
                (true, false)
            }
        }
        // Everything else that mentions the parameter -- an assignment, a
        // declaration, a call, a `goto` -- is refused rather than reasoned
        // about.
        _ => (false, false),
    }
}

/// Demote parameters whose every AST-visible write through them is
/// conditional out of the MUST-write set. See
/// `FunctionSummary::unconditional_modifies_params` for why this subtracts
/// from `modifies_params` instead of rebuilding it.
fn credit_modifies_params(
    body: &Node,
    source: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    use lang_parsing_substrate::query;

    // Every write through a parameter this pass can see, as (the node whose
    // position decides conditionality, the parameter-rooted identifier).
    let mut writes: Vec<(Node, Node)> = Vec::new();
    for node in query::find_descendants_of_kind(*body, "assignment_expression") {
        if let Some(root) = node
            .child_by_field_name("left")
            .and_then(|left| deref_write_root(&left, false))
        {
            writes.push((node, root));
        }
    }
    // `(*p)++` and `++*p` write through p just as `*p = *p + 1` does.
    for node in query::find_descendants_of_kind(*body, "update_expression") {
        if let Some(root) = node
            .child_by_field_name("argument")
            .and_then(|argument| deref_write_root(&argument, false))
        {
            writes.push((node, root));
        }
    }
    // A library call that writes its output argument is a write at its own
    // position, so it belongs in this list as well as in the MAY set --
    // otherwise `if (x) os_memset(out, 0, n);` reaches the "no write this pass
    // could see" arm below and is promoted to a MUST-write for having been
    // invisible (task 1026, tools_sqc). `library_written_roots` already
    // returns the root, so no `deref_write_root` here: a bare `out` handed to
    // the call is the dereference, and asking again would reject it.
    for call in query::find_descendants_of_kind(*body, "call_expression") {
        for root in library_written_roots(&call, source) {
            writes.push((call, root));
        }
    }

    // param index -> (any write seen, any unconditional write seen)
    let mut seen: HashMap<usize, (bool, bool)> = HashMap::new();
    for (node, root) in &writes {
        let name = root.utf8_text(source.as_bytes()).unwrap_or("");
        let Some(idx) = params.iter().position(|p| !p.is_empty() && p == name) else {
            continue;
        };
        let entry = seen.entry(idx).or_insert((false, false));
        entry.0 = true;
        // `if (out) *out = v;` is the optional-output-parameter idiom, and
        // it writes on every path a caller who passes a real pointer can
        // take -- which every caller that goes on to READ the variable did.
        // Counting it conditional makes the standard shape
        // `rc = f(&n, ...); if (rc) return; use(n);` report uninitialised,
        // and sqlite's fts3 alone writes its outputs that way dozens of
        // times over (task 988, tools_sqc).
        entry.1 |= is_unconditionally_reached_modulo_null_guard(node, body, source, name);
    }

    for &idx in &summary.modifies_params {
        match seen.get(&idx) {
            // Writes found, all of them conditional by position -- a
            // MAY-write unless the branches between them are exhaustive.
            Some((true, false)) => match writes_on_all_paths(body, source, &params[idx]) {
                Some(obligations) if obligations.is_empty() => {
                    summary.unconditional_modifies_params.insert(idx);
                }
                // Covered only through a callee. Park the obligation for
                // `propagate_transitive_modifies`, which runs once every
                // file's summary exists.
                Some(obligations) => {
                    summary
                        .modifies_params_pending
                        .insert(idx, obligations.into_iter().collect());
                }
                None => {}
            },
            // Either an unconditional write, or no write this pass could
            // see -- in which case the text scan's finding stands unrefined.
            _ => {
                summary.unconditional_modifies_params.insert(idx);
            }
        }
    }

    // A callee that performs NO direct write through the parameter never
    // entered `modifies_params`, so the loop above never iterated it and the
    // whole forwarded-write mechanism was unreachable for precisely the class
    // it was built for: curl's `my_md5_init(void *ctx) { md5_init(ctx); }`
    // stayed flagged at every call site. That is why the obligation lattice
    // measured -2 across nine corpora while the class it aimed at was still
    // standing (task 1027, tools_sqc).
    //
    // Gated on `forwarded_argument_names` so the coverage walk is asked only
    // about parameters the body actually hands to a callee. Without a gate
    // this runs the walk -- whose `expression_statement` leg searches each
    // statement's subtree -- over every parameter of every function, which is
    // the superlinear shape this file has been bitten by before.
    let forwarded = forwarded_argument_names(body, source);
    let candidates: Vec<usize> = (0..params.len())
        .filter(|idx| !params[*idx].is_empty())
        .filter(|idx| !summary.modifies_params.contains(idx))
        .filter(|idx| forwarded.contains(&params[*idx]))
        .collect();
    for idx in candidates {
        let Some(obligations) = writes_on_all_paths(body, source, &params[idx]) else {
            continue;
        };
        if obligations.is_empty() {
            // The walk proved a direct write on every path that the text
            // detectors could not see.
            summary.modifies_params.insert(idx);
            summary.unconditional_modifies_params.insert(idx);
        } else {
            // Nothing is claimed yet, and nothing may be: an obligation is a
            // QUESTION about a callee, not a MAY-write. Entering the parameter
            // into `modifies_params` here would answer it in the affirmative
            // for every consumer that reads the MAY set -- including
            // `build_read_only_deref_fns`, which subtracts it, so a callee
            // whose forwarding is never discharged would stop suppressing the
            // conservative `&var` fallback and be credited anyway.
            // `propagate_transitive_modifies` inserts into both sets when it
            // discharges, which is the point at which something IS known.
            summary
                .modifies_params_pending
                .insert(idx, obligations.into_iter().collect());
        }
    }

    // Positive evidence of a conditional write, for the parameters where the
    // MUST verdict came out "not proven": the coverage walk failing is not
    // itself a finding, so ask the dual question and record only a proven
    // answer. Pending parameters are skipped -- their coverage rests on a
    // callee `propagate_transitive_modifies` has yet to settle, and a
    // clean-path proof over this body alone would be answering a question
    // that is still open.
    let conditional: Vec<usize> = summary
        .modifies_params
        .iter()
        .filter(|idx| !summary.unconditional_modifies_params.contains(idx))
        .filter(|idx| !summary.modifies_params_pending.contains_key(idx))
        .filter(|idx| params.get(**idx).is_some_and(|p| !p.is_empty()))
        .copied()
        .collect();
    for idx in conditional {
        if may_return_without_writing(body, source, &params[idx]) {
            summary.conditional_modifies_params.insert(idx);
        }
    }
}

fn credit_frees_params(
    body: &Node,
    source: &str,
    params: &[String],
    summary: &mut FunctionSummary,
) {
    use lang_parsing_substrate::query;

    for call in query::find_descendants_of_kind(*body, "call_expression") {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        if function.utf8_text(source.as_bytes()).unwrap_or("") != "free" {
            continue;
        }
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = arguments.walk();
        let real: Vec<Node> = arguments.named_children(&mut cursor).collect();
        let [arg] = real.as_slice() else {
            continue;
        };
        let Some((target, through_pointee)) = strip_free_argument(*arg) else {
            continue;
        };
        let arg_name = target.utf8_text(source.as_bytes()).unwrap_or("");
        let Some(idx) = params.iter().position(|p| !p.is_empty() && p == arg_name) else {
            continue;
        };
        if through_pointee {
            summary.frees_param_pointees.insert(idx);
            continue;
        }
        summary.frees_params.insert(idx);
        if is_unconditionally_reached_modulo_null_guard(&call, body, source, arg_name) {
            summary.unconditional_frees_params.insert(idx);
        }
    }
}

fn analyze_param_usage(
    body: &Node,
    source: &str,
    body_text: &str,
    params: &[String],
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
    credit_frees: bool,
    summary: &mut FunctionSummary,
) {
    // Gated on `credit_frees`: a definition inside a preprocessor
    // conditional (see `function_definition_is_preproc_conditional`) may be
    // a mutually-exclusive alternate body, not a same-behavior variant, so
    // its free-related facts must not be unioned into the cross-file
    // summary as if they always held (task 654).
    if credit_frees {
        credit_frees_params(body, source, params, summary);
    }

    // One walk for the whole body, not one per parameter.
    let library_written = library_written_names(body, source);

    for (idx, param_name) in params.iter().enumerate() {
        if param_name.is_empty() {
            continue;
        }

        // Check if parameter is closed as a file/descriptor/handle resource
        // (FIO42-C) BEFORE it is ever reassigned. A plain "closer(param)"
        // text scan can't tell Juliet's goodB2GSink shape (close old handle,
        // *then* reassign) apart from its badSink twin (reassign to a new
        // handle, then close *that*, leaking the original) — both bodies
        // contain the literal substring `fclose(data)`. Only the "closes
        // first" ordering is a real, provable close of the value the caller
        // handed in (task 146).
        if closes_param_before_reassignment(body, source, param_name) {
            summary.closes_params.insert(idx);
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
            // ... and, separately, whether that check happens before the
            // first dereference. Same predicates, run against the body text
            // truncated at the first deref, so no spelling drifts between the
            // two answers.
            let before_deref = match first_deref_offset(body_text, param_name) {
                Some(offset) => &body_text[..offset],
                None => body_text,
            };
            if body_matches_null_check(before_deref, param_name)
                || body_matches_alias_null_check(before_deref, param_name)
            {
                summary.checks_null_params_before_deref.insert(idx);
            }
        }

        // Check if parameter is written through (dereferenced on left side of assignment).
        // Unlike the dereferences_params check below (a deliberate read-or-write
        // superset), `param->field`/`param[i]` alone is NOT enough here -- that
        // matches a plain READ too (e.g. `printIntLine(data->intOne)`), which
        // would wrongly claim the callee initializes/writes the param. Require
        // an actual assignment operator after the arrow/subscript on the same
        // line, mirroring ARR00-C's own write-vs-read line scan.
        if body_has_deref_write(body_text, param_name)
            || line_has_arrow_or_subscript_write(body_text, param_name)
            || is_fd_set_macro_write(body, source, param_name)
            // `os_memset(elems, 0, sizeof(*elems))` writes the output with no
            // assignment operator anywhere (task 1026, tools_sqc).
            || library_written.contains(param_name)
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

    // Must run after the loop above: it refines `modifies_params` rather
    // than deriving its own write set.
    credit_modifies_params(body, source, params, summary);

    // Detect param pass-through: when a parameter is forwarded to a callee
    collect_param_passthroughs(body, body, source, params, summary);

    // Detect direct field frees off a parameter: free(param->field) or
    // free((*param)->field) (the double-pointer-deref idiom used by
    // `void destroy(T **param)` style destructors). Gated on `credit_frees`
    // for the same reason as `credit_frees_params` above.
    if credit_frees {
        collect_frees_param_fields(body, source, params, function_macros, summary);
    }
}

/// POSIX fd_set macros (`FD_ZERO`, `FD_SET`, `FD_CLR`) write through their
/// `fd_set *` argument -- the sole arg for `FD_ZERO`, the last arg for
/// `FD_SET`/`FD_CLR` -- but they're opaque system macros aurora-lint's
/// macro-expansion engine never sees a definition for, so the arrow/subscript
/// text scan above can't see the write either (task 456; hostap's
/// `eloop_sock_table_set_fds(struct eloop_sock_table *table, fd_set *fds)`
/// writes its `fds` param purely through `FD_ZERO(fds)`/`FD_SET(sock, fds)`,
/// leaving `fds` looking never-written to callers passing a malloc'd
/// `fd_set *` bare, e.g. `eloop_sock_table_set_fds(&eloop.readers, rfds)`).
fn is_fd_set_macro_write(body: &Node, source: &str, param_name: &str) -> bool {
    use lang_parsing_substrate::query;

    for call in query::find_descendants_of_kind(*body, "call_expression") {
        let Some(func) = call.child_by_field_name("function") else {
            continue;
        };
        if func.kind() != "identifier" {
            continue;
        }
        if !matches!(
            query::node_text(func, source.as_bytes()),
            "FD_ZERO" | "FD_SET" | "FD_CLR"
        ) {
            continue;
        }
        let Some(args) = call.child_by_field_name("arguments") else {
            continue;
        };
        let mut cursor = args.walk();
        let real: Vec<Node> = args.named_children(&mut cursor).collect();
        let Some(last) = real.last() else { continue };
        if last.kind() == "identifier" && query::node_text(*last, source.as_bytes()) == param_name {
            return true;
        }
    }
    false
}

/// True if `body` calls `fclose`/`close`/`CloseHandle` with `param_name` as
/// its sole argument at a source position strictly before the first plain
/// reassignment `param_name = ...`. If `param_name` is never reassigned, any
/// closing call anywhere in the body counts. Order-sensitive by design (see
/// call site in `analyze_param_usage`): a body that reassigns before closing
/// only ever closes the *new* value, never the one the caller passed in, so
/// that shape must NOT be credited.
fn closes_param_before_reassignment(body: &Node, source: &str, param_name: &str) -> bool {
    use lang_parsing_substrate::query;

    let first_reassign = query::find_descendants_of_kind(*body, "assignment_expression")
        .into_iter()
        .filter(|n| {
            n.child_by_field_name("left")
                .map(|l| {
                    l.kind() == "identifier" && query::node_text(l, source.as_bytes()) == param_name
                })
                .unwrap_or(false)
        })
        .map(|n| n.start_byte())
        .min();

    let first_close = query::find_descendants_of_kind(*body, "call_expression")
        .into_iter()
        .filter(|call| {
            call.child_by_field_name("function")
                .map(|f| {
                    matches!(
                        query::node_text(f, source.as_bytes()),
                        "fclose" | "close" | "CloseHandle"
                    )
                })
                .unwrap_or(false)
        })
        .filter(|call| {
            call.child_by_field_name("arguments")
                .map(|args| {
                    let real: Vec<_> = (0..args.child_count())
                        .filter_map(|i| args.child(i))
                        .filter(|a| a.is_named())
                        .collect();
                    real.len() == 1
                        && real[0].kind() == "identifier"
                        && query::node_text(real[0], source.as_bytes()) == param_name
                })
                .unwrap_or(false)
        })
        .map(|n| n.start_byte())
        .min();

    match (first_close, first_reassign) {
        (Some(close), Some(reassign)) => close < reassign,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Scan for `free(...)`-shaped calls whose argument is a field access rooted
/// in one of `params` (via `points_to::lvalue_of`, which unwraps
/// `*`/parens/casts), recording the arrow-joined field chain (e.g. `"will"`
/// or `"will->topic"`) against that parameter's index. AST-based (unlike the
/// sibling `free(param)` text scan above) because the chain must be
/// extracted precisely, not just detected.
///
/// Three ways a call is recognized as freeing its argument, in preference
/// order:
///  1. Literal `free` — every argument is a candidate.
///  2. A function-like macro matching the "safe free" idiom (frees AND nulls
///     its parameter — `macro_expand::macro_nulls_param_indices`), e.g.
///     mosquitto's `#define mosquitto_FREE(A) do{ mosquitto_free(A); (A) =
///     NULL; }while(0)`. This is genuine engine-based detection (the macro
///     body is expanded and inspected), independent of the macro's name —
///     "engine, not allowlist", matching MEM30-C's existing use of the same
///     API. Only the argument position(s) the engine identifies are
///     credited.
///  3. A plain call whose name matches `ast_utils::is_deallocation_call_name`
///     (destroy_*/free_*/..._free/etc.) — a name-heuristic fallback for
///     ordinary C helper functions (not macros) and free-shaped macros that
///     don't null their argument, where the engine has nothing to say.
///     Every argument is a candidate, as for literal `free`.
///
/// aurora-lint has no preprocessor, so for (2)/(3) the macro/helper call itself is
/// the only AST evidence available that a free happened inside it (task 2:
/// MEM31-C ownership model).
fn collect_frees_param_fields(
    body: &Node,
    source: &str,
    params: &[String],
    function_macros: &HashMap<String, crate::analyze::macro_expand::FunctionMacro>,
    summary: &mut FunctionSummary,
) {
    use crate::analyze::macro_expand::macro_nulls_param_indices;
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

    // Real (non-punctuation) arguments in call order, matching how macro/
    // function parameter indices are counted.
    fn real_args<'a>(arguments: &Node<'a>) -> Vec<Node<'a>> {
        (0..arguments.child_count())
            .filter_map(|i| arguments.child(i))
            .filter(|a| !matches!(a.kind(), "," | "(" | ")"))
            .collect()
    }

    let credit_field = |summary: &mut FunctionSummary, arg: &Node| {
        let Some(lv) = crate::analyze::points_to::lvalue_of(arg, source) else {
            return;
        };
        let (root_name, fields) = flatten(&lv);
        if fields.is_empty() {
            return;
        }
        let Some(idx) = params.iter().position(|p| p == &root_name) else {
            return;
        };
        summary
            .frees_param_fields
            .entry(idx)
            .or_default()
            .insert(fields.join("->"));
    };

    for call in query::find_descendants_of_kind(*body, "call_expression") {
        let Some(function) = call.child_by_field_name("function") else {
            continue;
        };
        let func_name = function.utf8_text(source.as_bytes()).unwrap_or("");
        let Some(arguments) = call.child_by_field_name("arguments") else {
            continue;
        };
        let args = real_args(&arguments);

        if func_name == "free" {
            for arg in &args {
                credit_field(summary, arg);
            }
            continue;
        }

        let null_idxs = macro_nulls_param_indices(function_macros, func_name);
        if !null_idxs.is_empty() {
            for idx in null_idxs {
                if let Some(arg) = args.get(idx) {
                    credit_field(summary, arg);
                }
            }
            continue;
        }

        if ast_utils::is_deallocation_call_name(func_name) {
            for arg in &args {
                credit_field(summary, arg);
            }
        }
    }
}

/// Match a null-check expression on `param_name` anywhere in `body_text`.
///
/// Recognizes all spacings of `PARAM op LIT` / `LIT op PARAM` where op is
/// `==`/`!=` and LIT is `NULL`/`0`/`nullptr`, plus the `!PARAM` unary form.
/// Guards against false matches on substrings (e.g., `foo` matching inside
/// `foobar`) via word-boundary checks.
/// Byte offset of the first dereference of `param_name` in `body_text`, or
/// `None` when there is none.
///
/// The patterns are exactly the ones `dereferences_params` is computed from,
/// so the two answers cannot disagree about what a dereference is. `*param`
/// also matches a multiplication (`x * param`), which shortens the
/// before-the-deref prefix and so can only *withhold* a
/// `checks_null_params_before_deref` credit — the conservative direction for
/// a caller using it to suppress.
fn first_deref_offset(body_text: &str, param_name: &str) -> Option<usize> {
    [
        format!("*{}", param_name),
        format!("{}->", param_name),
        format!("{}[", param_name),
        format!("*){}", param_name),
    ]
    .iter()
    .filter_map(|pattern| body_text.find(pattern.as_str()))
    .min()
}

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

/// Detect param pass-through patterns: when a function parameter is forwarded
/// as a whole argument to a callee, casts and parentheses stripped. Used for
/// transitive free propagation. `body` is the enclosing function's own
/// compound_statement, threaded through unchanged across the recursion (distinct from `node`,
/// the recursive traversal cursor) so `is_unconditionally_reached` can be
/// checked against it at each call site (task 401).
fn collect_param_passthroughs(
    node: &Node,
    body: &Node,
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
                    let unconditional = is_unconditionally_reached(node, body);
                    let mut callee_idx = 0usize;
                    for i in 0..arguments.child_count() {
                        if let Some(arg) = arguments.child(i) {
                            if arg.kind() == "," || arg.kind() == "(" || arg.kind() == ")" {
                                continue;
                            }
                            // `backend_free((unsigned char *)p)` forwards
                            // `p` as surely as a bare `p` would; matching only
                            // a bare identifier left the transitive-free walk
                            // with no edge to follow (task 1034, tools_sqc).
                            let stripped = init_state::strip_arg_casts(&arg);
                            if stripped.kind() == "identifier" {
                                let arg_text = stripped.utf8_text(source.as_bytes()).unwrap_or("");
                                for (param_idx, param_name) in params.iter().enumerate() {
                                    if !param_name.is_empty() && arg_text == param_name {
                                        summary
                                            .param_passthroughs
                                            .entry(param_idx)
                                            .or_default()
                                            .push((callee_name.clone(), callee_idx));
                                        if unconditional {
                                            summary
                                                .unconditional_param_passthroughs
                                                .entry(param_idx)
                                                .or_default()
                                                .push((callee_name.clone(), callee_idx));
                                        }
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
            collect_param_passthroughs(&child, body, source, params, summary);
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

    // Same fixpoint, restricted to the MUST-free (unconditional) subset: a
    // transitive free is only trustworthy for MEM30-C/MEM31-C's "mark as
    // definitely freed" purposes when BOTH the callee's own free and the
    // forwarding call site in each hop of the chain are unconditional
    // (task 401) — otherwise a helper that only frees its argument on an
    // error path gets treated as always freeing it at every call site.
    for _pass in 0..10 {
        let mut changed = false;
        let unconditional_snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.unconditional_frees_params.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.unconditional_param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    if let Some(callee_frees) = unconditional_snapshot.get(callee_name) {
                        if callee_frees.contains(callee_idx)
                            && !summary.unconditional_frees_params.contains(caller_idx)
                        {
                            summary.unconditional_frees_params.insert(*caller_idx);
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

/// Discharge the coverage obligations `credit_modifies_params` parked in
/// `modifies_params_pending`, promoting a parameter into the MUST-write set
/// once every callee it was forwarded to is known to MUST-write the index it
/// received it at.
///
/// Why this runs here and not where the obligation was raised: the callee's
/// own summary does not exist yet while a file is being analyzed, and for a
/// cross-file callee it cannot -- the same ordering constraint that puts
/// `propagate_transitive_frees` in prescan.
///
/// Iterated to a fixpoint, because promoting one function's output parameter
/// is what discharges its own caller's obligation, and the chains are as deep
/// as the forwarding is (`a -> b -> c`). Purely additive: a pass only ever
/// inserts, so it converges and cannot withdraw a write already proven.
pub fn propagate_transitive_modifies(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.unconditional_modifies_params.clone()))
            .collect();

        // The conditional half of the same fixpoint: a parameter whose
        // coverage rests on a forwarded callee is UNWRITTEN on some path
        // exactly when that callee leaves it unwritten on some path.
        // `classify(number, out)` writes `*out` directly on one arm and hands
        // `out` to `set_flag` on the other, and `set_flag` writes nothing when
        // `number == 0` -- so `classify` can return without writing too, and a
        // structural walk of its body alone can never see that (task 1078,
        // tools_sqc).
        let conditional_snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.conditional_modifies_params.clone()))
            .collect();

        let mut changed = false;
        for summary in summaries.values_mut() {
            let conditional: Vec<usize> = summary
                .modifies_params_pending
                .iter()
                .filter(|(idx, _)| !summary.unconditional_modifies_params.contains(idx))
                .filter(|(idx, _)| !summary.conditional_modifies_params.contains(idx))
                .filter(|(_, obligations)| {
                    obligations.iter().any(|(callee, callee_idx)| {
                        conditional_snapshot
                            .get(callee)
                            .is_some_and(|unwritten| unwritten.contains(callee_idx))
                    })
                })
                .map(|(idx, _)| *idx)
                .collect();
            for idx in conditional {
                summary.conditional_modifies_params.insert(idx);
                changed = true;
            }

            let discharged: Vec<usize> = summary
                .modifies_params_pending
                .iter()
                .filter(|(idx, _)| !summary.unconditional_modifies_params.contains(idx))
                .filter(|(_, obligations)| {
                    obligations.iter().all(|(callee, callee_idx)| {
                        snapshot
                            .get(callee)
                            .is_some_and(|writes| writes.contains(callee_idx))
                    })
                })
                .map(|(idx, _)| *idx)
                .collect();
            for idx in discharged {
                summary.unconditional_modifies_params.insert(idx);
                // Pending parameters never entered the conditional set, but
                // keep the two disjoint by construction rather than by
                // argument -- both are read as a pair.
                summary.conditional_modifies_params.remove(&idx);
                // Keeps `unconditional_modifies_params` a subset of the MAY
                // set for a parameter that reached here through a forward and
                // never had a direct write to put it there (task 1027,
                // tools_sqc).
                summary.modifies_params.insert(idx);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }
}

/// Propagate `callsite_param_tainted`/`callsite_param_taint_observed` through
/// param pass-through chains.
///
/// The base aggregation (`prescan::aggregate_callsite_taint_args`) only sees
/// taint at the *direct* call site — it can't tell that a forwarding
/// wrapper's own parameter is externally tainted, since that wrapper's body
/// contains no taint source, just `callee(param)`. If function B is proven
/// to receive tainted (or proven-clean) data at param `p` and B forwards `p`
/// straight through to callee C at param `q`, then C's call site at `q` is
/// tainted (or clean) too. Iterates to fixpoint for deep chains — Juliet's
/// CWE-134 flow variants nest up to 5 files deep (variant 54). Skips
/// header-declared callees: their external callers are unknowable, so
/// nothing here should assert their call sites are conclusively observed.
pub fn propagate_transitive_param_taint(
    summaries: &mut HashMap<String, FunctionSummary>,
    header_declared: &HashSet<String>,
) {
    for _pass in 0..10 {
        let mut changed = false;

        // Snapshot every forwarding edge (is the source param observed/
        // tainted, and which callee/param does it feed) before mutating —
        // the callee being written may be a different map entry than the
        // caller being read, so this can't be done through a single
        // `values_mut()` pass like `propagate_transitive_frees`.
        let edges: Vec<(bool, bool, String, usize)> = summaries
            .values()
            .flat_map(|s| {
                let observed = s.callsite_param_taint_observed.clone();
                let tainted = s.callsite_param_tainted.clone();
                s.param_passthroughs
                    .iter()
                    .flat_map(move |(caller_idx, callees)| {
                        let is_observed = observed.contains(caller_idx);
                        let is_tainted = tainted.contains(caller_idx);
                        callees
                            .iter()
                            .map(move |(callee_name, callee_idx)| {
                                (is_observed, is_tainted, callee_name.clone(), *callee_idx)
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        for (is_observed, is_tainted, callee_name, callee_idx) in edges {
            if !is_observed || header_declared.contains(&callee_name) {
                continue;
            }
            if let Some(callee_summary) = summaries.get_mut(&callee_name) {
                if callee_summary
                    .callsite_param_taint_observed
                    .insert(callee_idx)
                {
                    changed = true;
                }
                if is_tainted && callee_summary.callsite_param_tainted.insert(callee_idx) {
                    changed = true;
                }
            }
        }

        if !changed {
            break;
        }
    }
}

/// Propagate transitive closes through param pass-through chains.
///
/// If function B passes param 0 to callee C at param 0, and C closes param 0
/// (fclose/close/CloseHandle), then B transitively closes param 0. Mirrors
/// `propagate_transitive_frees` for FIO42-C's resource-close tracking.
pub fn propagate_transitive_closes(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let mut changed = false;
        let closes_snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.closes_params.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    if let Some(callee_closes) = closes_snapshot.get(callee_name) {
                        if callee_closes.contains(callee_idx)
                            && !summary.closes_params.contains(caller_idx)
                        {
                            summary.closes_params.insert(*caller_idx);
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

/// Propagate transitive pointee-frees through param pass-through chains.
///
/// Mirrors `propagate_transitive_frees` but for `frees_param_pointees`: a
/// wrapper that hands its own `void **` parameter to a `safe_free()`-style
/// callee frees that parameter's pointee too. Same shape as the field version,
/// and needed for the same reason — real code layers these helpers.
pub fn propagate_transitive_frees_param_pointees(summaries: &mut HashMap<String, FunctionSummary>) {
    for _pass in 0..10 {
        let mut changed = false;
        let snapshot: HashMap<String, HashSet<usize>> = summaries
            .iter()
            .map(|(n, s)| (n.clone(), s.frees_param_pointees.clone()))
            .collect();

        for summary in summaries.values_mut() {
            for (caller_idx, callees) in &summary.param_passthroughs {
                for (callee_name, callee_idx) in callees {
                    let frees_pointee = snapshot
                        .get(callee_name)
                        .is_some_and(|s| s.contains(callee_idx));
                    if frees_pointee && !summary.frees_param_pointees.contains(caller_idx) {
                        summary.frees_param_pointees.insert(*caller_idx);
                        changed = true;
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

/// True when the body has at least one `return expr;` and every one of them is
/// a compile-time constant in the weak sense of
/// [`const_eval::is_compile_time_constant_expr`] — see
/// [`FunctionSummary::returns_only_compile_time_constants`].
///
/// Only per-file macro names are available here, so the project-wide sets are
/// [`const_eval::ConstantNameSets::none`]; the unresolvable-identifier rule
/// inside the predicate is what carries the cross-header cases.
fn returns_only_compile_time_constants(
    body: &Node,
    source: &str,
    macros: &MacroConstantMap,
) -> bool {
    let mut return_exprs = Vec::new();
    collect_return_expressions(body, source, &mut return_exprs);

    if return_exprs.is_empty() {
        return false;
    }

    return_exprs.iter().all(|expr| {
        const_eval::is_compile_time_constant_expr(
            expr,
            source,
            macros,
            const_eval::ConstantNameSets::none(),
        )
    })
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

/// The declared name of a function definition node, or `None` if it can't
/// be extracted (e.g. a malformed declarator).
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
        compute_summaries(
            &tree.root_node(),
            code,
            &macros,
            true,
            &[],
            &HashMap::new(),
            &HashMap::new(),
        )
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
    fn test_modifies_params_excludes_read_only_arrow_access() {
        // task 195/319 follow-on regression: a plain READ through param->field
        // or param[i] (no assignment) must NOT count as modifies_params --
        // confirmed as a real Juliet CWE-476 false-negative source when this
        // was wrongly treated as a write (badSink(struct *data) { if (cond)
        // printIntLine(data->intOne); } was credited with initializing data).
        let code = r#"
        void read_only_sink(struct thing *data) {
            if (cond) {
                printIntLine(data->intOne);
            }
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("read_only_sink").unwrap();
        assert!(
            !summary.modifies_params.contains(&0),
            "a read-only data->field access must not be treated as a write"
        );
        assert!(
            summary.dereferences_params.contains(&0),
            "it should still count as a dereference (the read-or-write superset)"
        );
    }

    #[test]
    fn test_modifies_params_still_detects_arrow_write() {
        let code = r#"
        void write_sink(struct thing *data) {
            data->intOne = 5;
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("write_sink").unwrap();
        assert!(summary.modifies_params.contains(&0));
    }

    #[test]
    fn test_modifies_params_still_detects_subscript_write() {
        let code = r#"
        void fill(int *buf) {
            for (int i = 0; i < 10; i++) {
                buf[i] = i;
            }
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("fill").unwrap();
        assert!(summary.modifies_params.contains(&0));
    }

    #[test]
    fn test_modifies_params_detects_walking_pointer_deref_write() {
        // curl's Curl_rand_bytes shape (task 589): `*rnd++ = value;` -- a
        // bare deref-write with a post-increment interposed between the
        // identifier and `=`, which a literal `"*rnd ="` substring match
        // misses entirely.
        let code = r#"
        void fill_random(unsigned char *rnd, size_t num) {
            while (num) {
                *rnd++ = 0x42;
                num--;
            }
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("fill_random").unwrap();
        assert!(summary.modifies_params.contains(&0));
    }

    #[test]
    fn test_modifies_params_deref_write_excludes_comparison() {
        let code = r#"
        void check(int *p) {
            if (*p == 5) {
                do_thing();
            }
        }
        "#;
        let summaries = parse_and_summarize(code);
        let summary = summaries.get("check").unwrap();
        assert!(
            !summary.modifies_params.contains(&0),
            "*p == 5 is a comparison, not a write"
        );
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

void *extra_leak_marker(void){
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
