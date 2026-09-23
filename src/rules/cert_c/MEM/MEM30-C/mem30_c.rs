use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval;
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::analyze::macro_expand::FunctionMacro;
use crate::analyze::macro_gaps;
use crate::analyze::points_to::{lvalue_of, resolve_canonical, AliasMap, LValue};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::call_roles;
use crate::utility::cert_c::clearing_extent::cleared_extent;
use crate::utility::cert_c::overflow_helpers;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

#[derive(Default)]
pub struct Mem30C {
    /// Cross-file function-like macro definitions (from the prescan / macro
    /// engine). Used to recognize "safe free" macros that free AND null their
    /// argument (e.g. curl `Curl_safefree`).
    function_macros: RefCell<Arc<HashMap<String, FunctionMacro>>>,
    /// Cross-file function summaries from prescan. When a callee's `frees_params`
    /// is known from real analysis of its body, that's authoritative over the
    /// "does the function's NAME contain FREE" heuristic below — the name
    /// heuristic false-positives on functions like hostap's `plink_free_count`
    /// (a pure counter, no free at all) and misattributes multi-arg frees to
    /// the wrong parameter.
    function_summaries: RefCell<Arc<HashMap<String, FunctionSummary>>>,
    /// Project-wide `#define ALIAS target` map, merged in `check` with this
    /// file's own, so `mbedtls_free(p)` dispatches as the literal `free` it
    /// expands to rather than through the name-contains-FREE guess
    /// .
    project_aliases: RefCell<Arc<HashMap<String, String>>>,
    /// Function-like macros the prescan found defined more than one way in a
    /// single file under conditions the platform profile cannot settle
    /// (`macro_gaps::MacroGapKind::AmbiguousDefinition`). Merged in `check`
    /// with this file's own; see `MemoryAnalyzer::ambiguous_macros`.
    project_ambiguous_macros: RefCell<Arc<HashSet<String>>>,
    /// Cross-file noreturn function names from the prescan, unioned in
    /// `check` with this file's own declarations and the stdlib set, so a
    /// branch ending in `exit(1)` or a project `fatal()` is known to have
    /// no successor.
    noreturn_functions: RefCell<Arc<HashSet<String>>>,
    /// Typedefs that hide a pointer, and the project-wide one-level typedef
    /// alias map. Both feed `arg_can_be_freed`, which must not read a
    /// pointer-hiding alias (`client`, `LPPOINT`) as a non-pointer and drop a
    /// real free on the name-heuristic path.
    pointer_typedef_names: RefCell<Arc<HashSet<String>>>,
    project_typedef_types: RefCell<Arc<HashMap<String, String>>>,
    /// Project-wide `#define NAME value` / enumerator values, merged in
    /// `check` with this file's own, so two constant names an `if` compares
    /// a value against are told apart by VALUE where the value is known:
    /// `x == A` and `x == B` partition nothing if both are 1.
    project_macros: RefCell<Arc<const_eval::MacroConstantMap>>,
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
        *self.project_aliases.borrow_mut() = context.macro_aliases.clone();
        *self.noreturn_functions.borrow_mut() = context.noreturn_functions.clone();
        *self.pointer_typedef_names.borrow_mut() = context.pointer_typedef_names.clone();
        *self.project_typedef_types.borrow_mut() = context.typedef_types.clone();
        *self.project_macros.borrow_mut() = context.macro_constants.clone();
        *self.project_ambiguous_macros.borrow_mut() = Arc::new(
            context
                .macro_gaps
                .iter()
                .filter(|g| g.kind == macro_gaps::MacroGapKind::AmbiguousDefinition)
                .map(|g| g.name.clone())
                .collect(),
        );
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
        // Phase 2c-iii of docs/design/macro-expansion.md.
        //
        // The table is the project prescan's merged with this file's own
        // definitions (per-file wins, as INT34-C/PRE31-C do). A scan with no
        // `-d` has no prescan table at all, so a macro defined in the scanned
        // file itself was invisible and every later `free(p)` after
        // `my_safefree(p)` was reported as a double-free (the follow-up to
        // MEM31-C ownership an earlier fix). Collecting from the file is one AST
        // walk; the old "skip when the prescan table is empty" shortcut is
        // what hid the macro.
        let (macro_null_params, macro_clear_params) = {
            let mut macros = HashMap::clone(&self.function_macros.borrow());
            macros.extend(crate::analyze::macro_expand::collect_function_macros(
                node, source,
            ));
            let mut invoked = HashSet::new();
            collect_invoked_macro_names(node, source, &macros, &mut invoked);
            let mut nulls: HashMap<String, Vec<usize>> = HashMap::new();
            let mut clears: HashMap<String, Vec<usize>> = HashMap::new();
            for name in invoked {
                let idx = crate::analyze::macro_expand::macro_nulls_param_indices(&macros, &name);
                if !idx.is_empty() {
                    nulls.insert(name.clone(), idx);
                }
                // The macro half of clearing-call recognition, paired with
                // `FunctionSummary::clears_params` (the function half)
                // exactly as MEM03-C pairs them: hostap's `#define
                // os_memset(s, c, n) memset(s, c, n)` is the same overwrite
                // as a direct `memset`, and must clear the same freed paths.
                let idx = crate::analyze::macro_expand::macro_clears_param_indices(&macros, &name);
                if !idx.is_empty() {
                    clears.insert(name, idx);
                }
            }
            (nulls, clears)
        };

        // Names of union typedefs in this file, so the analyzer can restrict
        // member-aliasing-on-free to genuine union variables.
        let mut union_typedef_names = HashSet::new();
        collect_union_typedef_names(node, source, &mut union_typedef_names);

        let macro_aliases =
            const_eval::merged_macro_aliases(&self.project_aliases.borrow(), node, source);

        // Function-like macros this file defines more than one way under a
        // condition the platform profile cannot settle -- curl's
        // `FREE_ON_WINLDAP(x)` is `curlx_free(x)` under `#ifdef
        // USE_WIN32_LDAP` and `do {} while(0)` in the `#else`. The collector
        // keeps the first body; whether the macro frees anything is
        // genuinely unknown to a scan with no configuration, so the
        // name-contains-FREE guess must not turn such a call into a free
        // (the same audit `--report-macro-gaps` prints).
        let mut ambiguous_macros: HashSet<String> =
            HashSet::clone(&self.project_ambiguous_macros.borrow());
        ambiguous_macros.extend(
            macro_gaps::audit_definitions(source, "")
                .gaps
                .into_iter()
                .filter(|g| g.kind == macro_gaps::MacroGapKind::AmbiguousDefinition)
                .map(|g| g.name),
        );

        // Functions that never return to their caller: the stdlib set, the
        // prescan's cross-file `_Noreturn`/`__attribute__((noreturn))`
        // declarations, and this file's own.
        let mut noreturn_names = HashSet::clone(&self.noreturn_functions.borrow());
        noreturn_names.extend(crate::analyze::noreturn::collect_noreturn_function_names(
            node, source,
        ));

        let macro_constants =
            const_eval::merged_macro_constants(&self.project_macros.borrow(), node, source);

        // Second pass: per-function analysis
        let mut analyzer = MemoryAnalyzer::new(
            macro_null_params,
            macro_clear_params,
            union_typedef_names,
            self.function_summaries.borrow().clone(),
            macro_aliases,
            ambiguous_macros,
            noreturn_names,
            self.pointer_typedef_names.borrow().clone(),
            self.project_typedef_types.borrow().clone(),
            macro_constants,
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
/// state on reassignment (an earlier fix pattern 1). `realloc` is matched and handled
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
/// argument.
/// The `<stem>` of a `<stem>_init` callee name, the in-place initializer
/// half of the `X_init(obj)` / `X_free(obj)` convention.
fn init_stem(function_name: &str) -> Option<&str> {
    function_name
        .strip_suffix("_init")
        .filter(|stem| !stem.is_empty())
}

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

/// `expr` with any enclosing parentheses removed.
fn unwrap_parens<'a>(expr: &Node<'a>) -> Node<'a> {
    let mut current = *expr;
    while current.kind() == "parenthesized_expression" {
        match current.named_child(0) {
            Some(inner) => current = inner,
            None => break,
        }
    }
    current
}

/// `expr` with any enclosing parentheses and casts removed: a cast changes
/// the type of an address, never which object it addresses.
fn unwrap_parens_and_casts<'a>(expr: &Node<'a>) -> Node<'a> {
    let mut current = *expr;
    loop {
        match current.kind() {
            "parenthesized_expression" => match current.named_child(0) {
                Some(inner) => current = inner,
                None => return current,
            },
            "cast_expression" => match current.child_by_field_name("value") {
                Some(inner) => current = inner,
                None => return current,
            },
            _ => return current,
        }
    }
}

/// Does this declarator declare an ARRAY -- the wrapper nearest the name is
/// an `array_declarator`? `char *arr[10]` (pointer_declarator around
/// array_declarator around the name) is an array of pointers, so yes;
/// `char (*p)[10]` (array_declarator around a parenthesized
/// pointer_declarator) is a pointer to an array, so no.
fn declarator_is_array(declarator: &Node) -> bool {
    let mut current = *declarator;
    let mut nearest = None;
    loop {
        match current.kind() {
            "array_declarator" | "pointer_declarator" | "function_declarator" => {
                nearest = Some(current.kind());
                match current.child_by_field_name("declarator") {
                    Some(inner) => current = inner,
                    None => break,
                }
            }
            "parenthesized_declarator" => match current.named_child(0) {
                Some(inner) => current = inner,
                None => break,
            },
            _ => break,
        }
    }
    nearest == Some("array_declarator")
}

/// The left-hand side of the plain `=` assignment whose right-hand side is
/// this call (through parentheses and casts), or `None` when the call's
/// result goes anywhere else. `x = (T *) f(x)` gives `x`; a compound
/// assignment reads its destination and is not a plain overwrite.
fn assignment_target_of_call<'a>(call_node: &Node<'a>) -> Option<Node<'a>> {
    let mut current = *call_node;
    loop {
        let parent = current.parent()?;
        match parent.kind() {
            "parenthesized_expression" | "cast_expression" => current = parent,
            "assignment_expression" => {
                let is_rhs =
                    parent.child_by_field_name("right").map(|r| r.id()) == Some(current.id());
                let plain = parent
                    .child_by_field_name("operator")
                    .is_none_or(|op| op.kind() == "=");
                return (is_rhs && plain).then(|| parent.child_by_field_name("left"))?;
            }
            _ => return None,
        }
    }
}

/// Tracks global variables and cross-function memory patterns
/// True if a field-access chain (`a[i].f`, `p->arr[i].f`, `a[i]->f`) passes
/// through a subscript anywhere below its top.
fn path_has_subscript(node: &Node) -> bool {
    let mut cur = *node;
    loop {
        match cur.kind() {
            "subscript_expression" => return true,
            "field_expression"
            | "pointer_expression"
            | "parenthesized_expression"
            | "cast_expression" => {
                let next = cur
                    .child_by_field_name("argument")
                    .or_else(|| cur.child_by_field_name("value"))
                    .or_else(|| {
                        (0..cur.child_count())
                            .filter_map(|i| cur.child(i))
                            .find(|c| c.is_named())
                    });
                match next {
                    Some(n) => cur = n,
                    None => return false,
                }
            }
            _ => return false,
        }
    }
}

/// `&x` -- a `pointer_expression` whose operator is `&` rather than `*`.
/// The operand of an address-of expression `&x`, or `None` for anything
/// else (a deref `*x` is the same node kind with a different operator).
/// The operand-returning companion to [`is_address_of`], which answers the
/// same question without handing back what was addressed.
fn address_of_operand<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() != "pointer_expression" {
        return None;
    }
    let op = node.child_by_field_name("operator")?;
    (op.kind() == "&").then(|| node.child_by_field_name("argument"))?
}

/// A call passing exactly ONE argument, by value: `sqlite3_free(p)` and not
/// `sqlite3_free(&p)`.
///
/// Both halves guard the same credit. Arity one is the summary's
/// one-nameable-argument rule: a deallocator NAME says a release happened
/// and never says through which parameter, so with a second argument there
/// is nothing to attach it to (`Curl_hash_delete(h, key, key_len)` reported
/// the lookup KEY freed when MEM31-C tried it without the guard). And an
/// `&var` argument is a claim about the pointee, not the parameter -- the
/// same line MEM31-C draws with `through_address_of` -- so it is left to
/// `process_address_of_args`, which already treats an unknown callee's
/// `&var` as a possible refill.
fn sole_by_value_argument(call: &Node) -> bool {
    let args = crate::analyze::macro_semantics::positional_args(call);
    matches!(args.as_slice(), [arg] if address_of_operand(arg).is_none())
}

fn is_address_of(node: &Node, source: &str) -> bool {
    node.kind() == "pointer_expression"
        && node
            .child_by_field_name("operator")
            .map(|op| get_node_text(&op, source) == "&")
            .unwrap_or(false)
}

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
    /// descent would. Converted after a deep-if-nesting stress
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
                    self.scan_assignment_escape(&n, source);
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

    /// Handle an `assignment_expression` node: flag a stack pointer escape when
    /// the address of automatic storage is assigned to a global pointer
    /// variable.
    ///
    /// Two things have to be true, and each is read from the declarators
    /// rather than from a name being global or not (ADR-0006):
    ///
    /// - The assignment's target IS the global pointer variable. A field,
    ///   dereference or element on the left (`mct->global.tcon = GTCON_EN`
    ///   through sel4's file-scope MMIO pointer, valkey's `myself->flags |=
    ///   ...`) writes into the object the global points at and never changes
    ///   what the global holds; the global was only the BASE of the lvalue,
    ///   and 32 of the 35 misfires were that.
    /// - The assigned value is the address of automatic storage: a local
    ///   array or VLA (its name decays to a pointer to it), or `&` of a local
    ///   or parameter object. A local POINTER (`EvictionPoolLRU = ep` after
    ///   `ep = zmalloc(...)`, `Users = old_users`) holds whatever it points
    ///   at -- heap, the previous value of the global -- and "not a global and
    ///   not a parameter" said nothing about that.
    fn scan_assignment_escape(&mut self, node: &Node, source: &str) {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        let target = unwrap_parens(&left);
        if target.kind() != "identifier" {
            return;
        }
        let left_var = get_node_text(&target, source).to_string();
        // Only pointer/array globals can actually hold a stack address;
        // scalar integer globals (u8/u16/u32 counters, state vars, etc.) cannot.
        if !self.global_pointer_vars.contains(&left_var) {
            return;
        }
        if !matches!(
            ast_utils::resolve_identifier_binding(&target, &left_var, source),
            Some(ast_utils::IdentifierBinding::Global(_))
        ) {
            // The name is shadowed here by a local or parameter of its own.
            return;
        }
        if Self::is_address_of_automatic_storage(&right, source) {
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

    /// Does `expr` evaluate to the address of an object with automatic
    /// storage duration, as its declarators say? Through parentheses and
    /// casts: a local array or VLA used as a value (it decays), or `&` of a
    /// local or parameter object -- the object itself, a `.` member of it, or
    /// an element of a local array. `&p->f` and `&p[i]` for a pointer `p`
    /// address whatever `p` points at, which is not known to be automatic.
    /// A `static` local is not automatic. Anything unresolvable is not
    /// claimed.
    fn is_address_of_automatic_storage(expr: &Node, source: &str) -> bool {
        let expr = unwrap_parens_and_casts(expr);
        match expr.kind() {
            "identifier" => {
                Self::automatic_declarator(&expr, source).is_some_and(|d| declarator_is_array(&d))
            }
            "pointer_expression" => {
                let is_address_of = expr
                    .child_by_field_name("operator")
                    .is_some_and(|op| op.kind() == "&")
                    || (0..expr.child_count())
                        .filter_map(|i| expr.child(i))
                        .any(|c| c.kind() == "&");
                if !is_address_of {
                    return false;
                }
                let Some(arg) = expr.child_by_field_name("argument") else {
                    return false;
                };
                Self::is_automatic_object(&unwrap_parens(&arg), source)
            }
            _ => false,
        }
    }

    /// Is `lv` an object with automatic storage duration: a local or
    /// parameter name, a `.` member of one, or an element of a local array?
    fn is_automatic_object(lv: &Node, source: &str) -> bool {
        match lv.kind() {
            "identifier" => Self::automatic_declarator(lv, source).is_some(),
            "field_expression" => {
                let through_pointer = (0..lv.child_count())
                    .filter_map(|i| lv.child(i))
                    .any(|c| c.kind() == "->");
                !through_pointer
                    && lv
                        .child_by_field_name("argument")
                        .is_some_and(|a| Self::is_automatic_object(&unwrap_parens(&a), source))
            }
            "subscript_expression" => lv.child_by_field_name("argument").is_some_and(|a| {
                let a = unwrap_parens(&a);
                a.kind() == "identifier"
                    && Self::automatic_declarator(&a, source)
                        .is_some_and(|d| declarator_is_array(&d))
            }),
            _ => false,
        }
    }

    /// The declarator binding this occurrence, when the binding is a local
    /// declaration without `static`/`extern` or a parameter -- automatic
    /// storage either way. `None` for a global, a static local, a function,
    /// or a name that resolves to nothing in this file.
    fn automatic_declarator<'a>(ident: &Node<'a>, source: &str) -> Option<Node<'a>> {
        let name = get_node_text(ident, source);
        let (decl, declarator) = ast_utils::resolve_identifier_declarator(ident, name, source)?;
        if declarator.kind() == "function_declarator" {
            return None;
        }
        match decl.kind() {
            "parameter_declaration" => Some(declarator),
            _ => {
                let static_or_extern =
                    (0..decl.child_count())
                        .filter_map(|i| decl.child(i))
                        .any(|c| {
                            c.kind() == "storage_class_specifier"
                                && matches!(get_node_text(&c, source), "static" | "extern")
                        });
                // A file-scope declaration is never automatic; the binding
                // fallback reaches one only when no local or parameter binds
                // the name.
                let file_scope = decl
                    .parent()
                    .is_some_and(|p| p.kind() == "translation_unit");
                (!static_or_extern && !file_scope).then_some(declarator)
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

/// A literal, or an identifier that reads as a named constant (all-caps,
/// no lowercase) rather than a variable -- the same "known value, not
/// something else's current value" test `EqPred`'s condition parsing and
/// the branch-sibling status-assignment scan both need.
fn is_all_caps_or_literal_constant(node: &Node, source: &str) -> bool {
    match node.kind() {
        "number_literal" | "char_literal" => true,
        "identifier" => {
            let t = get_node_text(node, source);
            t.chars().any(|c| c.is_ascii_uppercase()) && !t.chars().any(|c| c.is_ascii_lowercase())
        }
        _ => false,
    }
}

/// `lv` is (or, `negated`, is not) one of `constants`: what an `if`
/// condition of the form `x == A`, `x == A || x == B` or `x != A` asserts on
/// the arm it guards, with `A`/`B` literals or ALL_CAPS names. Two such
/// predicates on the same `lv` can be provably disjoint, which is what makes
/// a free under one of them not a free under the other.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EqPred {
    lv: LValue,
    constants: HashSet<String>,
    negated: bool,
}

impl EqPred {
    /// Whether no value of `lv` satisfies both `self` and `other`.
    fn disjoint_from(&self, other: &EqPred) -> bool {
        if self.lv != other.lv {
            return false;
        }
        match (self.negated, other.negated) {
            (false, false) => self.constants.is_disjoint(&other.constants),
            (false, true) => self.constants.is_subset(&other.constants),
            (true, false) => other.constants.is_subset(&self.constants),
            // Two complements always overlap on an unknown domain.
            (true, true) => false,
        }
    }

    fn negation(&self) -> EqPred {
        EqPred {
            lv: self.lv.clone(),
            constants: self.constants.clone(),
            negated: !self.negated,
        }
    }
}

/// The subset of `MemoryAnalyzer`'s fields that are forked across an
/// `if`/`else` branch and either merged back (via `MemoryAnalyzer::
/// merge_if_branches`) or restored verbatim before the else-branch walk.
#[derive(Clone)]
struct BranchState {
    freed_vars: HashSet<LValue>,
    /// Objects whose free happened only on paths where predicates on other
    /// lvalues held: `if (rep->type == ARRAY) zfree(rep->val.array);`
    /// records `rep->val.array -> [rep->type == ARRAY]`, and a free nested
    /// under two such tests records both. A later arm guarded by a
    /// predicate disjoint from ANY of them -- `if (rep->type == MAP)` --
    /// does not have the object freed. A predicate is dropped
    /// when its lvalue is assigned; the record is ignored once the object
    /// is no longer in `freed_vars`.
    freed_under: HashMap<LValue, Vec<EqPred>>,
    /// Where each freed object was freed. Forked with `freed_vars`: the
    /// preprocessor-split test compares a report site against this, and a
    /// then-branch free must not become the "prior free" the else-branch
    /// is measured from.
    freed_at: HashMap<LValue, usize>,
    nullified_vars: HashSet<LValue>,
    aliases: AliasMap,
    realloc_updated: HashSet<LValue>,
    realloc_invalidated: HashSet<LValue>,
}

impl BranchState {
    fn fork(analyzer: &MemoryAnalyzer) -> Self {
        Self {
            freed_vars: analyzer.freed_vars.clone(),
            freed_under: analyzer.freed_under.clone(),
            freed_at: analyzer.freed_at.clone(),
            nullified_vars: analyzer.nullified_vars.clone(),
            aliases: analyzer.aliases.clone(),
            realloc_updated: analyzer.realloc_updated.clone(),
            realloc_invalidated: analyzer.realloc_invalidated.clone(),
        }
    }

    fn restore(&self, analyzer: &mut MemoryAnalyzer) {
        analyzer.freed_vars = self.freed_vars.clone();
        analyzer.freed_under = self.freed_under.clone();
        analyzer.freed_at = self.freed_at.clone();
        analyzer.nullified_vars = self.nullified_vars.clone();
        analyzer.aliases = self.aliases.clone();
        analyzer.realloc_updated = self.realloc_updated.clone();
        analyzer.realloc_invalidated = self.realloc_invalidated.clone();
    }

    /// This path leaves `lv` holding NULL, so nothing it pointed to is
    /// reachable through it any more.
    fn forget_freed(&mut self, lv: &LValue) {
        self.freed_vars.remove(lv);
        self.freed_under.remove(lv);
        self.freed_at.remove(lv);
        self.realloc_invalidated.remove(lv);
    }
}

struct MemoryAnalyzer {
    // Track which variables are currently freed
    freed_vars: HashSet<LValue>,
    // See `BranchState::freed_under`.
    freed_under: HashMap<LValue, Vec<EqPred>>,
    // Byte offset (start_byte) of the free site that most recently marked each
    // name freed. Consulted only on a candidate double-free, to detect whether a
    // preprocessor conditional directive separates the two free sites.
    freed_at: HashMap<LValue, usize>,
    // The callee whose summary marked each name freed on a NAME GUESS alone
    // (`FunctionSummary::frees_params_guessed`): the free was credited because
    // some callee down the chain is spelled like a deallocator, not because
    // any body was seen to release the parameter. Like
    // `freed_at`, consulted only while the name is in `freed_vars`; a later
    // free backed by real evidence removes the entry.
    guessed_freed: HashMap<LValue, String>,
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
    // Function-like macros that overwrite a destination parameter (hostap's
    // `os_memset`): macro name -> destination parameter indices. The macro
    // half of `clear_freed_paths_overwritten_by_clearing_call`.
    macro_clear_params: HashMap<String, Vec<usize>>,
    // Names of union *typedefs* in this translation unit (e.g.
    // `typedef union {...} ptr_union_t;` -> "ptr_union_t"). Used to recognize
    // union-typed variable declarations. File-global; cloned per function.
    union_typedef_names: HashSet<String>,
    // Names of variables in the CURRENT function declared with a union type
    // (directly `union {...}`/`union Tag`, or a union typedef). ONLY for these
    // does freeing one member invalidate the sibling members (genuine storage
    // aliasing). Struct/struct-pointer bases are excluded, which prevents the
    // struct-field-free cascade FP — e.g. `free(data->state.range)` must not
    // poison `data->state` / other `data->*` fields. Repopulated per
    // function in `analyze_function`.
    union_typed_vars: HashSet<String>,
    // Cross-file function summaries from prescan. When a callee's real
    // `frees_params` is known, it overrides the name-based free heuristic
    // below — see `process_call_expression`.
    function_summaries: Arc<HashMap<String, FunctionSummary>>,
    // `#define ALIAS target` map (project-wide plus this file); a callee is
    // dispatched on the name its alias chain ends at.
    macro_aliases: HashMap<String, String>,
    // Objects this function has handed to a `<stem>_init(obj)` callee, keyed
    // by canonical lvalue, with the set of stems: `mbedtls_x509_crt_init(p)`
    // records `p -> {"mbedtls_x509_crt"}`. A later name-shaped
    // `<stem>_free(obj)` with the SAME stem on the SAME object does not end
    // obj's lifetime for this caller: either the init was handed
    // caller-owned storage and the free releases its contents (mbedtls's
    // `X_init`/`X_free` on a malloc'd struct, followed by the real
    // `free(p)`), or the init took a functional reference and the free drops
    // a structural one (OpenSSL's `ENGINE_init`/`ENGINE_free`, after which
    // `ENGINE_finish(engine)` is still legitimate). An earlier fix.
    // Function-scoped and monotone: it is evidence about the API's
    // ownership convention, not path state, so it is not forked or merged
    // with the branch state.
    init_stems: HashMap<LValue, HashSet<String>>,
    // Function-like macros with more than one live definition (project-wide
    // plus this file). A callee named here whose only claim to being a free
    // is its NAME is treated as an opaque call, not a free.
    ambiguous_macros: HashSet<String>,
    /// Callees that never return to this function (`exit`, `abort`,
    /// `longjmp`, anything declared noreturn). A branch ending in one has
    /// no join edge: whatever it freed is not carried past the `if`,
    /// `switch` or label it sits in.
    noreturn_names: HashSet<String>,
    // Typedefs that hide a pointer, and the project-wide one-level typedef
    // alias map. `arg_can_be_freed` needs both to tell a genuine non-pointer
    // argument from a pointer wearing an alias.
    pointer_typedef_names: Arc<HashSet<String>>,
    typedef_types: Arc<HashMap<String, String>>,
    /// The open `break` targets around the statement being walked, innermost
    /// last: `Some(exits)` for a loop, collecting the state at each `break`
    /// and `continue` that leaves its body, `None` for a `switch`, whose
    /// `break` belongs to the switch and is merged by `merge_switch_arms`.
    /// Read by `Frame::AfterLoop` Each exit records whether it
    /// was a `continue`, which re-tests the loop's condition before it can
    /// reach the code after the loop; a `break` does not.
    breakables: Vec<Option<Vec<(BranchState, bool)>>>,
    /// Known compile-time constant values (project `#define`s and
    /// enumerators plus this file's), for `equality_predicate`.
    macro_constants: const_eval::MacroConstantMap,
}

impl MemoryAnalyzer {
    fn new(
        macro_null_params: HashMap<String, Vec<usize>>,
        macro_clear_params: HashMap<String, Vec<usize>>,
        union_typedef_names: HashSet<String>,
        function_summaries: Arc<HashMap<String, FunctionSummary>>,
        macro_aliases: HashMap<String, String>,
        ambiguous_macros: HashSet<String>,
        noreturn_names: HashSet<String>,
        pointer_typedef_names: Arc<HashSet<String>>,
        typedef_types: Arc<HashMap<String, String>>,
        macro_constants: const_eval::MacroConstantMap,
    ) -> Self {
        Self {
            freed_vars: HashSet::new(),
            freed_under: HashMap::new(),
            freed_at: HashMap::new(),
            guessed_freed: HashMap::new(),
            aliases: HashMap::new(),
            nullified_vars: HashSet::new(),
            realloc_updated: HashSet::new(),
            realloc_invalidated: HashSet::new(),
            realloc_source: HashMap::new(),
            union_members: HashMap::new(),
            macro_null_params,
            macro_clear_params,
            union_typedef_names,
            pointer_typedef_names,
            typedef_types,
            union_typed_vars: HashSet::new(),
            function_summaries,
            macro_aliases,
            init_stems: HashMap::new(),
            ambiguous_macros,
            noreturn_names,
            breakables: Vec::new(),
            macro_constants,
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
                self.macro_clear_params.clone(),
                self.union_typedef_names.clone(),
                self.function_summaries.clone(),
                self.macro_aliases.clone(),
                self.ambiguous_macros.clone(),
                self.noreturn_names.clone(),
                self.pointer_typedef_names.clone(),
                self.typedef_types.clone(),
                self.macro_constants.clone(),
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
        // restricted to genuine unions (not struct fields). See an earlier fix.
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
    /// recursion: deeply/adversarially nested `if`/expression
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
                /// Boxed: a `BranchState` is several maps, and the frame
                /// stack holds one per open `if`.
                pre_state: Box<BranchState>,
                realloc_null_branch: Option<ReallocNullBranch>,
                /// What the condition asserts on the then arm, when it is
                /// an equality test against constants (`EqPred`).
                then_pred: Option<EqPred>,
            },
            AfterElse {
                consequence: Option<Node<'a>>,
                alternative: Option<Node<'a>>,
                pre_state: Box<BranchState>,
                then_state: Box<BranchState>,
                then_returns: bool,
                then_pred: Option<EqPred>,
            },
            /// `switch` statement whose condition has just been visited —
            /// forks the pre-switch state and starts the first case arm
            /// .
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
                pre_state: Box<BranchState>,
                exit_states: Vec<(BranchState, bool)>,
            },
            /// A loop's body has just been walked. The code after the loop
            /// is reached from the state before it (zero iterations), from
            /// every `break` and `continue` in the body (collected in
            /// `breakables` while the body was walked), and from the end of
            /// the body -- unless the body's last statement leaves the
            /// function, in which case the end of the body reaches nothing
            /// .
            AfterLoop {
                body: Option<Node<'a>>,
                condition: Option<Node<'a>>,
                pre_state: Box<BranchState>,
            },
        }

        // `skip_ids` names argument nodes a just-processed call_expression
        // already marked freed (an earlier fix's `freed_arg_ids`) — the free's own
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
            // A `break` in an arm ends the switch, not any loop around it.
            analyzer.breakables.push(None);
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
            let diverges = analyzer.case_arm_diverges(&cases[idx], source);
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
                analyzer.breakables.pop();
                MemoryAnalyzer::merge_switch_arms(
                    analyzer,
                    source,
                    &pre_state,
                    &cases,
                    &exit_states,
                );
            }
        }

        /// Reset analyzer state to `pre_state`, union in the previous arm's
        /// exit state if it fell through (fallthrough means the previous
        /// arm's state is ALSO reachable at the top of this one, in addition
        /// to a direct jump from the switch dispatch, which only ever sees
        /// `pre_state`), then push this case's own statements (excluding the
        /// `case`/`default` keyword and value) onto the stack followed by a
        /// `SwitchCaseDone` continuation.
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
                pre_state: Box::new(pre_state),
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
                        // later arm's use of the same variable.
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
                        self.clear_freed_args_overwritten_by_result(&n, source, &freed_arg_ids);
                        self.clear_freed_paths_overwritten_by_clearing_call(&n, source);
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
                    "declaration" => {
                        self.process_plain_declarators(&n, source);
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
                    "for_statement" | "while_statement" | "do_statement" => {
                        if n.kind() == "for_statement" {
                            // Check for dangerous loop free patterns
                            self.check_for_loop_pattern(&n, source, violations);
                        }
                        self.breakables.push(Some(Vec::new()));
                        stack.push(Frame::AfterLoop {
                            body: n.child_by_field_name("body"),
                            condition: n.child_by_field_name("condition"),
                            pre_state: Box::new(BranchState::fork(self)),
                        });
                        push_children(&mut stack, &n, source, &no_skip);
                    }
                    "break_statement" => self.record_loop_exit(false),
                    "continue_statement" => self.record_loop_exit(true),
                    "labeled_statement" => {
                        self.reset_state_if_label_unreachable_by_fallthrough(&n, source);
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
                    let (pre_state, realloc_null_branch, then_pred) =
                        self.enter_then_arm(&if_node, source);
                    stack.push(Frame::AfterThen {
                        if_node,
                        consequence,
                        alternative,
                        pre_state: Box::new(pre_state),
                        realloc_null_branch,
                        then_pred,
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
                    then_pred,
                } => {
                    let then_state = BranchState::fork(self);
                    let then_returns = consequence
                        .map(|c| self.unconditionally_diverges(&c, source))
                        .unwrap_or(false);
                    self.enter_else_arm(
                        &if_node,
                        &pre_state,
                        realloc_null_branch,
                        &then_pred,
                        source,
                    );
                    stack.push(Frame::AfterElse {
                        consequence,
                        alternative,
                        pre_state,
                        then_state: Box::new(then_state),
                        then_returns,
                        then_pred,
                    });
                    if let Some(alternative) = alternative {
                        stack.push(Frame::Visit(alternative));
                    }
                }
                Frame::AfterElse {
                    consequence,
                    alternative,
                    pre_state,
                    then_state,
                    then_returns,
                    then_pred,
                } => {
                    let else_state = BranchState::fork(self);
                    let else_returns = alternative
                        .map(|a| self.unconditionally_diverges(&a, source))
                        .unwrap_or(false);
                    Self::merge_if_branches(
                        self,
                        &pre_state,
                        &then_state,
                        then_returns,
                        &else_state,
                        else_returns,
                    );
                    self.record_frees_under(
                        &pre_state,
                        &then_state,
                        &else_state,
                        then_pred,
                        consequence,
                        alternative,
                        source,
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
                        *pre_state,
                        exit_states,
                    );
                }
                Frame::AfterLoop {
                    body,
                    condition,
                    pre_state,
                } => self.finish_loop(body, condition, &pre_state, source),
            }
        }
    }

    /// The condition of an `if` has been visited; set up the then arm.
    /// Returns the state to restore for the else arm, which arm (if any) is
    /// a realloc's NULL-result path, and what the condition asserts on the
    /// then arm when it is an equality test against constants.
    fn enter_then_arm(
        &mut self,
        if_node: &Node,
        source: &str,
    ) -> (BranchState, Option<ReallocNullBranch>, Option<EqPred>) {
        // Check if the condition tests a realloc result variable.
        // Pattern: if (temp) or if (temp != NULL) means then=realloc succeeded, else=failed.
        // Pattern: if (!temp) or if (temp == NULL) means then=realloc failed, else=succeeded.
        // When realloc fails (returns NULL), the original pointer is still valid.
        let realloc_null_branch = self.detect_realloc_condition_branch(if_node, source);
        let pre_state = BranchState::fork(self);
        let condition = if_node.child_by_field_name("condition");

        // If the then-branch is the realloc-failed path, clear invalidation there
        if realloc_null_branch == Some(ReallocNullBranch::Then) {
            if let Some(cond) = condition {
                self.clear_realloc_invalidation_for_condition(&cond, source);
            }
        }

        let then_pred = condition.and_then(|c| self.equality_predicate(&c, source));
        if let Some(pred) = &then_pred {
            self.drop_frees_disjoint_from(pred);
        }
        // `if (buf != staticbuf)`: on this arm the two are not the same
        // object, whatever `char *buf = staticbuf;` recorded earlier --
        // valkey's sds.c frees `buf` under exactly that test, and the alias
        // made it a free of `staticbuf` too. The else arm of
        // `==` is the same fact; `enter_else_arm` handles it.
        if let Some((a, b)) = condition.and_then(|c| Self::pointer_comparison(&c, source, true)) {
            self.unalias_pair(&a, &b);
        }
        (pre_state, realloc_null_branch, then_pred)
    }

    /// The then arm has been walked (and forked by the caller); reset to the
    /// pre-`if` state and assert on it what the else arm knows.
    fn enter_else_arm(
        &mut self,
        if_node: &Node,
        pre_state: &BranchState,
        realloc_null_branch: Option<ReallocNullBranch>,
        then_pred: &Option<EqPred>,
        source: &str,
    ) {
        pre_state.restore(self);
        let condition = if_node.child_by_field_name("condition");
        // If the else-branch is the realloc-failed path, clear invalidation there
        if realloc_null_branch == Some(ReallocNullBranch::Else) {
            if let Some(cond) = condition {
                self.clear_realloc_invalidation_for_condition(&cond, source);
            }
        }
        if let Some(pred) = then_pred {
            self.drop_frees_disjoint_from(&pred.negation());
        }
        if let Some((a, b)) = condition.and_then(|c| Self::pointer_comparison(&c, source, false)) {
            self.unalias_pair(&a, &b);
        }
    }

    /// Union `other`'s tracked sets into the analyzer's current state
    /// (used for switch-arm fallthrough — the state carried in from the
    /// previous arm is possible IN ADDITION TO whatever this arm's own
    /// statements do, not instead of it).
    fn union_state_from(&mut self, other: &BranchState) {
        self.freed_vars.extend(other.freed_vars.iter().cloned());
        for (k, v) in &other.freed_at {
            self.freed_at.entry(k.clone()).or_insert(*v);
        }
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
    /// — using `case_arm_diverges` here instead was an earlier fix's bug: it
    /// treated a free-then-`break` arm as "unreachable after the switch"
    /// and silently dropped the free from the merged state. If the switch
    /// has no `default` arm, a value that matches none of the cases falls
    /// through untouched, so `pre_state` itself is always one of the live
    /// possibilities. If no arm reaches the code after the switch, it's
    /// unreachable — keep `pre_state`, matching `merge_if_branches`' "both
    /// branches return" case. `aliases` is left as whatever the
    /// last-processed arm set it to, mirroring `merge_if_branches`'
    /// documented aliases quirk.
    /// The `freed_under` records that survive a join: an object keeps its
    /// record only if every live path on which it is freed carries that same
    /// record. A path that frees it unconditionally, or under another
    /// predicate, makes the record a lie about the merged state.
    fn merge_freed_under(
        live: &[&BranchState],
        freed_vars: &HashSet<LValue>,
    ) -> HashMap<LValue, Vec<EqPred>> {
        let mut out = HashMap::new();
        for var in freed_vars {
            let mut agreed: Option<Vec<EqPred>> = None;
            for state in live.iter().filter(|s| s.freed_vars.contains(var)) {
                let here = state.freed_under.get(var).cloned().unwrap_or_default();
                agreed = Some(match agreed {
                    None => here,
                    Some(acc) => acc.into_iter().filter(|p| here.contains(p)).collect(),
                });
            }
            if let Some(preds) = agreed {
                if !preds.is_empty() {
                    out.insert(var.clone(), preds);
                }
            }
        }
        out
    }

    /// After an `if`: an object freed in exactly one arm, and not before the
    /// `if`, was freed only where that arm held. Two independent sources of
    /// "where that arm held" are recorded, unioned: `pred`, when the `if`'s
    /// own condition is an equality test against constants; and, always,
    /// `branch_sibling_const_facts` on that arm's body -- a status variable
    /// the arm itself unconditionally sets, sitting beside the free rather
    /// than gating it (sqlite fts3_write.c: the free and `rc = SQLITE_NOMEM`
    /// are sibling statements under a *pointer*-comparison `if`, which is no
    /// `EqPred`, but a later `if (rc == SQLITE_OK)` is -- and disjoint from
    /// it). Records nothing for an object already freed on entry (that free
    /// was unconditional) or freed in both arms.
    fn record_frees_under(
        &mut self,
        pre_state: &BranchState,
        then_state: &BranchState,
        else_state: &BranchState,
        pred: Option<EqPred>,
        consequence: Option<Node>,
        alternative: Option<Node>,
        source: &str,
    ) {
        let then_facts =
            Self::branch_sibling_const_facts(consequence, source, &self.macro_constants);
        for var in &then_state.freed_vars {
            if !pre_state.freed_vars.contains(var)
                && !else_state.freed_vars.contains(var)
                && self.freed_vars.contains(var)
            {
                let new: Vec<&EqPred> = pred.iter().chain(then_facts.iter()).collect();
                if !new.is_empty() {
                    let preds = self.freed_under.entry(var.clone()).or_default();
                    for p in new {
                        if !preds.contains(p) {
                            preds.push(p.clone());
                        }
                    }
                }
            }
        }
        let neg = pred.as_ref().map(EqPred::negation);
        let else_facts =
            Self::branch_sibling_const_facts(alternative, source, &self.macro_constants);
        for var in &else_state.freed_vars {
            if !pre_state.freed_vars.contains(var)
                && !then_state.freed_vars.contains(var)
                && self.freed_vars.contains(var)
            {
                let new: Vec<&EqPred> = neg.iter().chain(else_facts.iter()).collect();
                if !new.is_empty() {
                    let preds = self.freed_under.entry(var.clone()).or_default();
                    for p in new {
                        if !preds.contains(p) {
                            preds.push(p.clone());
                        }
                    }
                }
            }
        }
    }

    /// Constant-equality facts a branch arm's body establishes unconditionally
    /// through its own direct-child statements: `x = A;` where `A` is a
    /// literal or ALL_CAPS name, the same shape `equality_predicate` reads out
    /// of a *condition*, here read out of a *sibling assignment* instead. Only
    /// direct children of `branch` count -- an assignment inside a further
    /// nested `if`/`while`/`for`/`switch` is conditional relative to `branch`,
    /// not a fact true of the whole arm. A later assignment to the same
    /// variable overrides an earlier one (source order).
    fn branch_sibling_const_facts(
        branch: Option<Node>,
        source: &str,
        macro_constants: &const_eval::MacroConstantMap,
    ) -> Vec<EqPred> {
        let Some(branch) = branch else {
            return Vec::new();
        };
        let stmts: Vec<Node> = if branch.kind() == "compound_statement" {
            let mut cursor = branch.walk();
            branch.children(&mut cursor).collect()
        } else {
            vec![branch]
        };
        let mut facts: Vec<EqPred> = Vec::new();
        for stmt in stmts {
            let assignment = if stmt.kind() == "expression_statement" {
                stmt.child(0)
            } else {
                None
            };
            let Some(assignment) = assignment else {
                continue;
            };
            if assignment.kind() != "assignment_expression" {
                continue;
            }
            let is_plain_eq = assignment
                .child_by_field_name("operator")
                .is_some_and(|op| get_node_text(&op, source) == "=");
            if !is_plain_eq {
                continue;
            }
            let Some(left) = assignment.child_by_field_name("left") else {
                continue;
            };
            let Some(right) = assignment.child_by_field_name("right") else {
                continue;
            };
            if !is_all_caps_or_literal_constant(&right, source) {
                continue;
            }
            let Some(lv) = lvalue_of(&left, source) else {
                continue;
            };
            let text = get_node_text(&right, source);
            let key = match const_eval::try_evaluate_text_public(text, macro_constants) {
                Some(v) => format!("#{v}"),
                None => text.to_string(),
            };
            facts.retain(|f| f.lv != lv);
            facts.push(EqPred {
                lv,
                constants: [key].into_iter().collect(),
                negated: false,
            });
        }
        facts
    }

    /// Entering an arm on which `pred` holds: an object freed only under a
    /// predicate disjoint from it is not freed here. valkey's call_reply.c
    /// frees `rep->val.array` under `rep->type == ARRAY || rep->type ==
    /// SET` and walks it again under `rep->type == MAP || rep->type ==
    /// ATTRIBUTE`; sqlite's update.c ends the WHERE loop under `eOnePass ==
    /// ONEPASS_OFF` and uses it in the else of the same test.
    fn drop_frees_disjoint_from(&mut self, pred: &EqPred) {
        let dropped: Vec<LValue> = self
            .freed_under
            .iter()
            .filter(|(var, under)| {
                self.freed_vars.contains(*var) && under.iter().any(|u| u.disjoint_from(pred))
            })
            .map(|(var, _)| var.clone())
            .collect();
        for var in dropped {
            self.freed_vars.remove(&var);
            self.freed_at.remove(&var);
            self.freed_under.remove(&var);
        }
    }

    /// `a != b` (`want_unequal`) or `a == b` (not) between two plain
    /// lvalues, through parentheses: the pair whose arm of the `if` is the
    /// one on which they are known to be different objects.
    fn pointer_comparison(
        condition: &Node,
        source: &str,
        want_unequal: bool,
    ) -> Option<(LValue, LValue)> {
        let cond = unwrap_parens(condition);
        if cond.kind() != "binary_expression" {
            return None;
        }
        let op = get_node_text(&cond.child_by_field_name("operator")?, source);
        if op != if want_unequal { "!=" } else { "==" } {
            return None;
        }
        let l = unwrap_parens(&cond.child_by_field_name("left")?);
        let r = unwrap_parens(&cond.child_by_field_name("right")?);
        Some((lvalue_of(&l, source)?, lvalue_of(&r, source)?))
    }

    /// Forget that `a` and `b` name the same object, in either direction.
    /// Branch-local: `aliases` is forked and restored around each arm.
    fn unalias_pair(&mut self, a: &LValue, b: &LValue) {
        if self.aliases.get(a) == Some(b) {
            self.aliases.remove(a);
        }
        if self.aliases.get(b) == Some(a) {
            self.aliases.remove(b);
        }
    }

    /// `x == A`, `x == A || x == B`, `x != A`, through parentheses, where
    /// `x` is a plain lvalue and each constant a literal or an ALL_CAPS
    /// name -- the shapes that can be read as a partition of `x`'s value
    /// without knowing anything else. A lower-case identifier may be a
    /// variable equal to another, so it does not count. A constant whose
    /// value is known (`macro_constants`) is recorded by value, so two names
    /// for the same number are the same constant; one whose value is not
    /// (an enumerator without an initializer) is recorded by name.
    fn equality_predicate(&self, condition: &Node, source: &str) -> Option<EqPred> {
        fn is_constant(node: &Node, source: &str) -> bool {
            is_all_caps_or_literal_constant(node, source)
        }
        fn one(node: &Node, source: &str) -> Option<(LValue, String, bool)> {
            let node = unwrap_parens(node);
            if node.kind() != "binary_expression" {
                return None;
            }
            let op = node.child_by_field_name("operator")?;
            let negated = match get_node_text(&op, source) {
                "==" => false,
                "!=" => true,
                _ => return None,
            };
            let l = unwrap_parens(&node.child_by_field_name("left")?);
            let r = unwrap_parens(&node.child_by_field_name("right")?);
            let (lv, c) = if is_constant(&r, source) {
                (lvalue_of(&l, source)?, r)
            } else if is_constant(&l, source) {
                (lvalue_of(&r, source)?, l)
            } else {
                return None;
            };
            Some((lv, get_node_text(&c, source).to_string(), negated))
        }
        let cond = unwrap_parens(condition);
        // A disjunction of equalities on one lvalue, or a single test.
        let mut leaves = vec![cond];
        let mut terms = Vec::new();
        while let Some(n) = leaves.pop() {
            let n = unwrap_parens(&n);
            if n.kind() == "binary_expression"
                && n.child_by_field_name("operator")
                    .is_some_and(|o| get_node_text(&o, source) == "||")
            {
                leaves.push(n.child_by_field_name("right")?);
                leaves.push(n.child_by_field_name("left")?);
            } else {
                terms.push(one(&n, source)?);
            }
        }
        let (lv, _, negated) = terms.first()?.clone();
        if negated && terms.len() > 1 {
            // `x != A || x != B` is always true for A != B; not a partition.
            return None;
        }
        let mut constants = HashSet::new();
        for (tlv, c, tneg) in terms {
            if tlv != lv || tneg != negated {
                return None;
            }
            let key = match const_eval::try_evaluate_text_public(&c, &self.macro_constants) {
                Some(v) => format!("#{v}"),
                None => c,
            };
            constants.insert(key);
        }
        Some(EqPred {
            lv,
            constants,
            negated,
        })
    }

    fn merge_switch_arms(
        analyzer: &mut Self,
        source: &str,
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
            .filter(|(case_node, _)| analyzer.case_reaches_after_switch(case_node, source))
            .map(|(_, (s, _))| s)
            .collect();
        if !has_default {
            live.push(pre_state);
        }

        if live.is_empty() {
            pre_state.restore(analyzer);
            return;
        }
        Self::merge_live_states(analyzer, pre_state, &live);
    }

    /// The state after a construct that several paths reach: the union of
    /// what each live path freed and invalidated. Shared by `switch` arms
    /// and loop exits.
    fn merge_live_states(analyzer: &mut Self, pre_state: &BranchState, live: &[&BranchState]) {
        let mut freed_vars = HashSet::new();
        let mut freed_at = HashMap::new();
        let mut nullified_vars = HashSet::new();
        let mut realloc_invalidated = HashSet::new();
        let mut realloc_updated = HashSet::new();
        for s in live {
            freed_vars.extend(s.freed_vars.iter().cloned());
            for (k, v) in &s.freed_at {
                freed_at.entry(k.clone()).or_insert(*v);
            }
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
        analyzer.freed_under = Self::merge_freed_under(live, &freed_vars);
        analyzer.freed_vars = freed_vars;
        analyzer.freed_at = freed_at;
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
            analyzer.freed_under = pre_state.freed_under.clone();
            analyzer.freed_at = pre_state.freed_at.clone();
            analyzer.nullified_vars = pre_state.nullified_vars.clone();
            analyzer.realloc_invalidated = pre_state.realloc_invalidated.clone();
            analyzer.realloc_updated = pre_state.realloc_updated.clone();
        } else if then_returns {
            // Only then returns - use else branch state
            analyzer.freed_vars = else_state.freed_vars.clone();
            analyzer.freed_under = else_state.freed_under.clone();
            analyzer.freed_at = else_state.freed_at.clone();
            analyzer.nullified_vars = else_state.nullified_vars.clone();
            analyzer.realloc_invalidated = else_state.realloc_invalidated.clone();
            analyzer.realloc_updated = else_state.realloc_updated.clone();
        } else if else_returns {
            // Only else returns - use then branch state
            analyzer.freed_vars = then_state.freed_vars.clone();
            analyzer.freed_under = then_state.freed_under.clone();
            analyzer.freed_at = then_state.freed_at.clone();
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
            analyzer.freed_under = Self::merge_freed_under(&[then_state, else_state], &freed_vars);
            analyzer.freed_vars = freed_vars;
            // Free sites follow the union: whichever branch freed it, that is
            // where it was freed (then-branch wins a tie; the site only feeds
            // the preprocessor-split test).
            let mut freed_at = else_state.freed_at.clone();
            freed_at.extend(then_state.freed_at.iter().map(|(k, v)| (k.clone(), *v)));
            analyzer.freed_at = freed_at;

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
    /// error branches free-then-`goto cleanup` / free-then-`break` (an earlier fix
    /// pattern 2). The merge only recognized `return` before.
    /// This walker processes a function body as one linear sequence,
    /// threading free-tracking state through textual/AST order (if/switch
    /// are the only forks). A label whose immediately preceding sibling
    /// statement unconditionally diverges (return/goto/continue, or a bare
    /// break) can only be reached via a `goto NAME;` elsewhere in the
    /// function -- NOT by falling through from that preceding statement,
    /// since it never falls through at all. Carrying forward the state
    /// accumulated up to that point is therefore wrong: e.g. hostap's
    /// eap_sim.c pattern frees `resp` on the normal post-loop
    /// fallthrough path, `return`s, and an `invalid:` label after that
    /// return (reached only via a forward `goto invalid;` from inside the
    /// loop) frees the SAME variable again on its own, mutually exclusive
    /// path -- not a real double-free, but the linear walk sees the second
    /// free right after the first with no reset in between. Reset the
    /// free/realloc tracking state before processing the label's target
    /// statement in that case.
    fn reset_state_if_label_unreachable_by_fallthrough(&mut self, label_node: &Node, source: &str) {
        // A comment is a named sibling too, and valkey's cluster.c puts a
        // three-line one between `return;` and `socket_err:`; the label's
        // predecessor in the FLOW is the last statement before it.
        let mut prev = label_node.prev_named_sibling();
        while let Some(p) = prev {
            if p.kind() != "comment" {
                break;
            }
            prev = p.prev_named_sibling();
        }
        let Some(prev) = prev else {
            return;
        };
        if !self.control_flow_diverges(&prev, source, true) {
            return;
        }
        self.freed_vars.clear();
        self.freed_at.clear();
        self.nullified_vars.clear();
        self.realloc_updated.clear();
        self.realloc_invalidated.clear();
    }

    fn unconditionally_diverges(&self, node: &Node, source: &str) -> bool {
        self.control_flow_diverges(node, source, true)
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
    /// `return`/`goto`/`continue` still skip past it entirely (see
    /// `case_reaches_after_switch`).
    ///
    /// A statement that calls a noreturn function (`exit(1)`, `abort()`,
    /// `longjmp`, a project `fatal()` declared `_Noreturn`) diverges the
    /// same way a `return` does: control never comes back to this function,
    /// so the arm has no join edge and nothing it freed is carried past the
    /// merge. sqlite's `if( rc!=SQLITE_OK ){ ...;
    /// sqlite3_close(db); exit(1); }` was reporting every later use of `db`
    /// as a use-after-free, and valkey's `freeReplyObject(reply);
    /// valkeyFree(ctx); exit(1);` the single legitimate frees after it.
    fn control_flow_diverges(&self, node: &Node, source: &str, break_diverges: bool) -> bool {
        // Explicit work/result stacks instead of native recursion:
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
        // terminated. Unwrap it the same way as `compound_statement`.
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
                        "expression_statement" => {
                            results.push(crate::analyze::noreturn::is_noreturn_call_statement(
                                &resolved,
                                source,
                                &self.noreturn_names,
                            ));
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
    fn case_arm_diverges(&self, case_node: &Node, source: &str) -> bool {
        match Self::case_last_statement(case_node) {
            Some(stmt) => self.control_flow_diverges(&stmt, source, true),
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
    /// .
    fn case_reaches_after_switch(&self, case_node: &Node, source: &str) -> bool {
        match Self::case_last_statement(case_node) {
            Some(stmt) => !self.control_flow_diverges(&stmt, source, false),
            // No statements at all (a bare grouped case label, e.g. `case
            // B:` immediately followed by `case C:`) always falls through
            // to the next arm rather than reaching the code after the
            // switch on its own — whatever that next arm (or the arm it
            // eventually falls into) contributes is already counted there.
            None => false,
        }
    }

    /// A `break` (`continuing` false) or `continue` has been reached: the
    /// state here reaches the code after the innermost loop. A `break` binds
    /// to the innermost breakable, and only a loop needs telling -- a switch
    /// arm's exit state is recorded by `SwitchCaseDone`; a `continue` goes
    /// back to the head of the innermost LOOP, through any switch in
    /// between, and the condition there can fail.
    fn record_loop_exit(&mut self, continuing: bool) {
        let state = BranchState::fork(self);
        let target = if continuing {
            self.breakables.iter_mut().rev().flatten().next()
        } else {
            self.breakables.last_mut().and_then(|b| b.as_mut())
        };
        if let Some(exits) = target {
            exits.push((state, continuing));
        }
    }

    /// The loop's body has been walked: the code after the loop is reached
    /// from the state before it, from every recorded `break`/`continue`,
    /// and from the end of the body unless its last statement leaves the
    /// function. `break` is how a body reaches the code after the loop and
    /// `continue` re-tests the condition, so neither leaves; a body whose
    /// last statement returns, jumps away or never returns does. valkey's
    /// acl.c ends a `for` body with `sdsfreesplitres(argv, argc); ...;
    /// return 1;` and frees `argv` again right after the loop, on the path
    /// that only the body's `continue`s reach.
    ///
    /// Every path but a `break` reaches the code after the loop only by
    /// failing the loop's condition. When that condition is a non-NULL test
    /// of one pointer -- `for (; p; p = pNext) { ...; free(p); }` -- those
    /// paths leave with that pointer NULL, so the last iteration's freed mark
    /// does not survive on them: sqlite's vdbesort.c stores `p` back into the
    /// list head after such a loop. A `break` skips the test and can leave
    /// the pointer freed and non-NULL, so its exits keep the mark.
    fn finish_loop(
        &mut self,
        body: Option<Node>,
        condition: Option<Node>,
        pre_state: &BranchState,
        source: &str,
    ) {
        let exits = self.breakables.pop().flatten().unwrap_or_default();
        let end_state = BranchState::fork(self);
        let body_reaches_after = body.is_none_or(|b| !self.loop_body_leaves_function(&b, source));
        let mut tested_pre = pre_state.clone();
        let mut tested_end = end_state;
        let mut exits = exits;
        if let Some(lv) = condition.and_then(|c| Self::condition_tests_non_null(&c, source)) {
            tested_pre.forget_freed(&lv);
            tested_end.forget_freed(&lv);
            for (state, continuing) in &mut exits {
                if *continuing {
                    state.forget_freed(&lv);
                }
            }
        }
        let mut live: Vec<&BranchState> = vec![&tested_pre];
        live.extend(exits.iter().map(|(state, _)| state));
        if body_reaches_after {
            live.push(&tested_end);
        }
        Self::merge_live_states(self, pre_state, &live);
    }

    /// The pointer a loop condition proves NULL when it fails: `p`,
    /// `p != NULL` and `NULL != p` (or `0`/`nullptr`), where `p` is a
    /// variable or a member path. Anything else -- a dereference, a
    /// subscript, a conjunction -- proves nothing about one pointer.
    fn condition_tests_non_null(condition: &Node, source: &str) -> Option<LValue> {
        fn path(node: &Node, source: &str) -> Option<LValue> {
            let node = unwrap_parens(node);
            match node.kind() {
                "identifier" => lvalue_of(&node, source),
                "field_expression" => {
                    path(&node.child_by_field_name("argument")?, source)?;
                    lvalue_of(&node, source)
                }
                _ => None,
            }
        }
        fn is_null(node: &Node, source: &str) -> bool {
            matches!(
                get_node_text(&unwrap_parens(node), source),
                "NULL" | "0" | "nullptr"
            )
        }
        let cond = unwrap_parens(condition);
        if cond.kind() != "binary_expression" {
            return path(&cond, source);
        }
        let op = cond.child_by_field_name("operator")?;
        if get_node_text(&op, source) != "!=" {
            return None;
        }
        let left = cond.child_by_field_name("left")?;
        let right = cond.child_by_field_name("right")?;
        if is_null(&right, source) {
            path(&left, source)
        } else if is_null(&left, source) {
            path(&right, source)
        } else {
            None
        }
    }

    /// Whether a loop body's last statement leaves the function -- returns,
    /// jumps to a label, or calls something that never returns -- so the end
    /// of the body reaches nothing. A `break` reaches the code after the
    /// loop and a `continue` re-tests the condition, so neither counts here;
    /// both record their state in `breakables` when walked.
    fn loop_body_leaves_function(&self, body: &Node, source: &str) -> bool {
        let resolved = match body.kind() {
            "compound_statement" => Self::compound_last_statement(body),
            _ => Some(*body),
        };
        match resolved {
            Some(last) if last.kind() == "continue_statement" => false,
            Some(last) => self.control_flow_diverges(&last, source, false),
            None => false,
        }
    }

    /// The last statement of a compound statement, skipping comments.
    fn compound_last_statement<'a>(block: &Node<'a>) -> Option<Node<'a>> {
        (0..block.child_count())
            .filter_map(|i| block.child(i))
            .rfind(|c| !matches!(c.kind(), "{" | "}" | "comment"))
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
    /// Returns the node ids of arguments this call just marked freed --
    /// the call site that passes a pointer to be freed must not be
    /// re-walked as a "use" of that same pointer, or the free call's own
    /// argument gets flagged as accessing freed memory at its own line.
    fn process_call_expression(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) -> HashSet<usize> {
        if let Some(function_node) = node.child_by_field_name("function") {
            // The spelling in the source keys the safe-free macro table
            // (`macro_null_params`); everything else classifies the callee
            // by the name its `#define` alias chain ends at.
            let spelled_name = get_node_text(&function_node, source);
            let function_name = const_eval::resolve_macro_alias(&self.macro_aliases, spelled_name);

            match function_name {
                "free" => {
                    return self.process_free_call(node, source, None, violations);
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
                    // `<stem>_init(obj, ...)`: record every plain-lvalue
                    // argument as initialized in place under `stem` (consumed by
                    // `is_contents_free_of_initialized`).
                    // `function_name` borrows `self.macro_aliases`, so the
                    // insert is on the field, not through a `&mut self` call.
                    if let Some(stem) = init_stem(function_name) {
                        for lv in self.call_arg_lvalues(node, source) {
                            self.init_stems
                                .entry(lv)
                                .or_default()
                                .insert(stem.to_string());
                        }
                    }

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
                    // ever clear it.
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
                    // an earlier fix). Only fall back to the name heuristic when we have
                    // no summary for this callee (library/system function, or no
                    // -d cross-file scan).
                    //
                    // Uses `unconditional_frees_params`, NOT the broader (MAY-free)
                    // `frees_params`: a callee that only frees its argument on some
                    // conditional path (e.g. an error branch) doesn't definitely
                    // free it at every call site, and marking it as freed
                    // unconditionally here caused cascading false UAF/double-free
                    // reports at callers who took a different path.
                    // The callee that credits the free below on its NAME
                    // alone, when its own body could not be read past a
                    // function-pointer call. `None` for every other route.
                    let mut escaped_sole_param: Option<String> = None;
                    if let Some(summary) = self.function_summaries.get(function_name).cloned() {
                        if !summary.unconditional_frees_params.is_empty() {
                            let callee = function_name.to_string();
                            let freed = self.process_summary_free_call(
                                node,
                                source,
                                &summary.unconditional_frees_params,
                                &summary.frees_params_guessed,
                                &callee,
                                violations,
                            );
                            self.process_address_of_args(node, source, Some(&summary), violations);
                            return freed;
                        } else if summary.sole_param_escapes_unnamed_call
                            && sole_by_value_argument(node)
                        {
                            // An empty free set refutes the name only when the
                            // body was READABLE throughout. `sqlite3_free(void
                            // *p)` releases through
                            // `sqlite3GlobalConfig.m.xFree(p)`, so every free
                            // set comes out empty and the summary -- present,
                            // and therefore trusted over the name -- said
                            // sqlite's one deallocator frees nothing. MEM31-C
                            // reads that as a leak it must not report; here
                            // the polarity is inverted, so it is a
                            // use-after-free this rule never got to see. Fall
                            // through to the name heuristic, which is the
                            // reading a callee with NO summary already gets,
                            // and carry the callee so the finding says the
                            // free was inferred from a name.
                            //
                            // A body that was read all the way through and
                            // releases nothing -- mbedtls's
                            // `mbedtls_gcm_free(ctx)`, which only zeroizes
                            // members -- still refutes its name.
                            escaped_sole_param = Some(function_name.to_string());
                        } else {
                            self.check_function_args_for_freed(node, source, violations);
                            self.process_address_of_args(node, source, Some(&summary), violations);
                            return HashSet::new();
                        }
                    }

                    // Check for common free-related macros. A name is the
                    // weakest evidence of a free, and it is overruled when the
                    // callee is a macro this file defines more than one way
                    // under a condition no platform profile settles (curl's
                    // `FREE_ON_WINLDAP`: a real free in one arm, a no-op in the
                    // other, with the non-Windows arm's `attr = attribute`
                    // alias visible in the same walk -- so the guess produced a
                    // "double-free" of `attribute` on every error branch of
                    // ldap.c). Such a call is opaque: its argument
                    // is still checked for prior frees like any other call.
                    let ambiguous_free_macro = (upper_name.contains("FREE")
                        || upper_name == "XFREE"
                        || upper_name == "G_FREE"
                        || upper_name == "SAFE_DELETE"
                        || upper_name == "DELETE")
                        && self.ambiguous_macros.contains(spelled_name);
                    if !ambiguous_free_macro
                        && (upper_name.contains("FREE")
                            || upper_name == "XFREE"
                            || upper_name == "G_FREE"
                            || upper_name == "SAFE_DELETE"
                            || upper_name == "DELETE")
                    {
                        // `<stem>_free(obj)` after `<stem>_init(obj)` in this
                        // function does not release obj itself (contents-free
                        // of caller-owned storage, or a structural-reference
                        // drop; see `init_stems`), so obj is not marked freed
                        // and the real `free(p)` that follows is not a double
                        // free. It is still a use of obj, so a
                        // prior free of it is reported.
                        if self.is_contents_free_of_initialized(function_name, node, source) {
                            self.check_function_args_for_freed(node, source, violations);
                            return HashSet::new();
                        }
                        // Treat as free() call
                        let freed_arg_ids = self.process_free_call(
                            node,
                            source,
                            escaped_sole_param.as_deref(),
                            violations,
                        );
                        // "Safe free" macros (curl Curl_safefree, mosquitto
                        // mosquitto_FREE, …) also set the argument to NULL inside
                        // the macro body — invisible to us without expansion. If
                        // the macro engine flagged this macro as nulling a
                        // parameter, clear that argument's freed state, exactly
                        // as an explicit `p = NULL;` would. Phase 2c-iii.
                        if let Some(indices) = self.macro_null_params.get(spelled_name).cloned() {
                            self.clear_freed_for_nulled_args(node, source, &indices);
                        }
                        return freed_arg_ids;
                    } else {
                        // Check if any argument is a freed pointer
                        self.check_function_args_for_freed(node, source, violations);
                        self.process_address_of_args(node, source, None, violations);
                    }
                }
            }
        }
        HashSet::new()
    }

    /// The canonical lvalues of a call's plain `identifier` / `field_expression`
    /// arguments (cast-unwrapped), in argument order.
    fn call_arg_lvalues(&self, call: &Node, source: &str) -> Vec<LValue> {
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0..arguments.child_count() {
            let Some(mut arg) = arguments.child(i) else {
                continue;
            };
            if matches!(arg.kind(), "," | "(" | ")") {
                continue;
            }
            if arg.kind() == "cast_expression" {
                if let Some(value) = arg.child_by_field_name("value") {
                    arg = value;
                }
            }
            if arg.kind() != "identifier" && arg.kind() != "field_expression" {
                continue;
            }
            if let Some(lv) = lvalue_of(&arg, source) {
                out.push(resolve_canonical(&self.aliases, &lv));
            }
        }
        out
    }

    /// Is this name-shaped free a `<stem>_free(obj)` whose `obj` this function
    /// earlier passed to `<stem>_init`? The freed operand is the last argument,
    /// as `process_free_call` assumes.
    fn is_contents_free_of_initialized(
        &self,
        function_name: &str,
        call: &Node,
        source: &str,
    ) -> bool {
        let Some(stem) = function_name.strip_suffix("_free") else {
            return false;
        };
        let Some(target) = self.call_arg_lvalues(call, source).pop() else {
            return false;
        };
        self.init_stems
            .get(&target)
            .is_some_and(|stems| stems.contains(stem))
    }

    /// Process free() call - mark variable as freed
    fn process_free_call(
        &mut self,
        node: &Node,
        source: &str,
        guessed_by: Option<&str>,
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
        if !self.arg_can_be_freed(arg, source) {
            return HashSet::new();
        }
        self.mark_arg_freed(node, arg, source, guessed_by, violations)
            .into_iter()
            .collect()
    }

    /// Can this argument name an object a free-shaped call releases?
    ///
    /// Only consulted on the NAME-heuristic path, where all we know is that
    /// the callee is spelled like a deallocator: a resolved `FunctionSummary`
    /// already says which parameter is freed and is trusted over this.
    ///
    /// Nothing is released through a non-pointer. sel4 spells ordinary
    /// accessors with FREE in the name -- `cap_untyped_cap_get_capFreeIndex(cap)`
    /// takes a `cap_t` BY VALUE, `OFFSET_TO_FREE_INDEX(offset)` an integer
    /// counter -- and the last-argument rule marked each one freed, so every
    /// later read of the cap or the counter became a use-after-free
    /// .
    ///
    /// The bar is POSITIVE evidence of a non-pointer, never the absence of a
    /// `*` in the type's spelling. `resolve_identifier_declared_type` hands
    /// back the declaration's type field verbatim, so a typedef that hides the
    /// pointer answers with no `*` in it: valkey's `typedef struct _client
    /// {...} *client;` makes `freeClient(client c)` look non-pointer, and
    /// rejecting there deleted a real use-after-free (`zfree(c)` then
    /// `listSearchKey(config.clients, c)`, valkey-benchmark.c:556) -- resolving
    /// the declarator and then asking a spelling question about the answer is
    /// the same mistake ADR-0006 is about. So a type is only non-pointer once
    /// the shared pointer-typedef set and the shared typedef chain both say it
    /// is not one, and anything unresolved is left alone.
    fn arg_can_be_freed(&self, arg: Node, source: &str) -> bool {
        let inner = if arg.kind() == "cast_expression" {
            arg.child_by_field_name("value").unwrap_or(arg)
        } else {
            arg
        };
        if inner.kind() != "identifier" {
            return true;
        }
        let name = get_node_text(&inner, source);
        // A function designator is not an object, so it is not what any call
        // releases. `listSetFreeMethod(list, aofListFree)` REGISTERS a free
        // callback on a list; the last-argument rule read the callback itself
        // as the freed thing, and registering the same one on two lists in a
        // function came back as "aofListFree freed multiple times" (valkey
        // aof.c, sentinel.c, valkey-cli.c). A name carrying a
        // FunctionSummary is one the prescan saw defined, which is what makes
        // this a resolution rather than a guess about the spelling.
        if self.function_summaries.contains_key(name) {
            return false;
        }
        let Some(ty) = ast_utils::resolve_identifier_declared_type(&inner, &name, source) else {
            return true;
        };
        if ast_utils::is_pointer_type(&ty) {
            return true;
        }
        let bare = ty.trim();
        if self.pointer_typedef_names.contains(bare) {
            return true;
        }
        ast_utils::is_pointer_type(&overflow_helpers::resolve_typedef_chain(
            bare,
            &self.typedef_types,
        ))
    }

    /// Mark the SPECIFIC parameter positions a cross-file `FunctionSummary`
    /// determined this callee actually frees. Unlike
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
        guessed_indices: &HashSet<usize>,
        callee: &str,
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
                let guessed_by = guessed_indices.contains(&idx).then_some(callee);
                if let Some(id) = self.mark_arg_freed(node, arg, source, guessed_by, violations) {
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
        guessed_by: Option<&str>,
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
        // `free(a[i].f)`: the freed object is a member of ONE element, and
        // `lvalue_of` drops the index, so `a[1].f` and `a[0].f` would share a
        // key -- curl's `socks_sspi.c` frees `sspi_w_token[1].pvBuffer` on
        // the success path and `sspi_w_token[0].pvBuffer` right after, and
        // was reported as a double-free. Same policy as the
        // `free(arr[i])` skip above: not tracked rather than tracked wrongly.
        if path_has_subscript(&actual_arg) {
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
        // from the one that marked the object freed: aurora-lint has no preprocessor, so the
        // two frees may sit in mutually-exclusive build configurations (sibling
        // `#if`-guarded `else if` arms, or a diverging `#else` branch followed by a
        // fall-through free). Their parse order is not a real execution sequence, so
        // the inferred double-free is unsound.
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
            let mut violation = RuleViolation {
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
            };
            // Either free resting on a name guess makes the pair an
            // inference, so the finding is marked the way `uaf` marks one.
            let prior = self
                .guessed_free_of(&canonical)
                .or_else(|| self.guessed_free_of(&lv))
                .map(String::as_str);
            let mut callees: Vec<&str> = prior.into_iter().chain(guessed_by).collect();
            callees.dedup();
            if !callees.is_empty() {
                violation.requires_manual_review = Some(true);
                if std::env::var_os("AURORA_MEM30_GUESS_DEBUG").is_some() {
                    violation.message = format!(
                        "{} [guessed-free via {}]",
                        violation.message,
                        callees.join(", ")
                    );
                }
            }
            violations.push(violation);
        }

        // Mark as freed
        self.freed_vars.insert(canonical.clone());
        self.freed_vars.insert(lv.clone());
        // Record the free site for the preproc-split double-free check above.
        let free_byte = node.start_byte();
        self.freed_at.insert(canonical.clone(), free_byte);
        self.freed_at.insert(lv.clone(), free_byte);
        // Record -- or, on real evidence, retract -- that this free is a name
        // guess.
        match guessed_by {
            Some(callee) => {
                self.guessed_freed
                    .insert(canonical.clone(), callee.to_string());
                self.guessed_freed.insert(lv.clone(), callee.to_string());
            }
            None => {
                self.guessed_freed.remove(&canonical);
                self.guessed_freed.remove(&lv);
            }
        }

        // For union support: track union member relationships
        // When free(u.member) is called, all u.* accesses become invalid.
        // GATED on the base being a genuine union-typed variable: freeing a
        // struct field (e.g. `free(data->state.range)`) must NOT poison sibling
        // fields, which was the dominant MEM30 cascade FP on real-world C
        // . Members of a true union overlap in storage, so freeing one
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
            match guessed_by {
                Some(callee) => {
                    self.guessed_freed.insert(alias.clone(), callee.to_string());
                }
                None => {
                    self.guessed_freed.remove(&alias);
                }
            }
            self.freed_vars.insert(alias);
        }

        // Report this argument's node id so callers can skip re-walking it
        // as a "use" of the pointer it just marked freed — the call site
        // that passes a pointer to be freed isn't itself a use-after-free
        // .
        Some(arg.id())
    }

    /// `f(&p)` after `free(p)`: the callee was handed the SLOT, and the
    /// idiom is that it refills it -- curl's `curlx_free(newhost); result =
    /// ftp_control_addr_dup(data, &newhost);` writes `*newhostp` on every
    /// path (confirmed against the source: the failure path assigns NULL and
    /// returns an error), and every later use of `newhost` was reported
    /// against the original free -- seven findings off one repair, and the
    /// same shape runs through curl's `Curl_urldecode(..., &unescaped, ...)`
    /// and `Curl_cwriter_create(&writer, ...)`, hostap's gnutls and EHT
    /// paths, and 88 findings from a single `cmd` in valkey-benchmark.c
    /// .
    ///
    /// Policy mirrors EXP33-C's `&var`-initializes rule (an earlier fix bug #3):
    /// credit the write by DEFAULT -- for a callee with no summary as much
    /// as for one that writes on every path -- and withhold it only on
    /// POSITIVE evidence. "Absent from the MUST set" is not evidence: that
    /// set cannot see through a function pointer, and withholding on the
    /// absence of an answer is the mistake ADR-0006 names.
    ///
    /// Two kinds of positive evidence. A summary proving a returning path
    /// writes nothing through the parameter
    /// (`conditional_modifies_params`) keeps `p` freed, because that path
    /// leaves it dangling. And a callee that frees the POINTEE
    /// (`frees_param_pointees`, the `void **` safe-free wrapper) is a second
    /// free of `p`, not a refill, so `free(p); safe_free(&p);` stays a
    /// double free rather than being silently cleared.
    fn process_address_of_args(
        &mut self,
        call: &Node,
        source: &str,
        summary: Option<&FunctionSummary>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let args = crate::analyze::macro_semantics::positional_args(call);
        for (idx, arg) in args.iter().enumerate() {
            let Some(inner) = address_of_operand(arg) else {
                continue;
            };
            if inner.kind() != "identifier" && inner.kind() != "field_expression" {
                continue;
            }
            if summary.is_some_and(|s| s.frees_param_pointees.contains(&idx)) {
                self.mark_arg_freed(call, inner, source, None, violations);
                continue;
            }
            if summary.is_some_and(|s| s.conditional_modifies_params.contains(&idx)) {
                continue;
            }
            let Some(lv) = lvalue_of(&inner, source) else {
                continue;
            };
            // The slot is rebound exactly as `process_assignment` rebinds it
            // for `p = make_buffer()`: the written lvalue AS SPELLED (no alias
            // resolution -- `target` still holds the old value after `p` is
            // refilled), a field path clears only itself so `free(s);
            // f(&s->x);` keeps `s` freed, and a plain identifier drops its own
            // alias link.
            self.freed_vars.remove(&lv);
            self.nullified_vars.remove(&lv);
            self.realloc_invalidated.remove(&lv);
            self.freed_at.remove(&lv);
            self.guessed_freed.remove(&lv);
            if inner.kind() == "identifier" {
                self.sever_aliases_of(&lv);
            }
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
        self.process_assignment_inner(node, source, violations);
        // Only now, with the right-hand side accounted for: `ptr =
        // realloc(ptr, n)` needs `old_ptr -> ptr` still in place while the
        // realloc tracking above marks the aliases of the OLD block
        // invalidated. After that, nothing that aliased the assigned
        // lvalue refers to what it now holds.
        if let Some(left) = node.child_by_field_name("left") {
            if matches!(left.kind(), "identifier" | "field_expression") {
                if let Some(left_lv) = lvalue_of(&left, source) {
                    self.aliases.retain(|_, target| *target != left_lv);
                    // A predicate on a value that has just changed says
                    // nothing about later tests of it: the frees it guarded
                    // become unconditional.
                    let root = left_lv.root_var().to_string();
                    for under in self.freed_under.values_mut() {
                        under.retain(|p| p.lv.root_var() != root);
                    }
                    self.freed_under.retain(|_, under| !under.is_empty());
                }
            }
        }
    }

    fn process_assignment_inner(
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
                self.rebind_forgets_paths_inside(&left_lv);
                return;
            }

            // Check if this is a dereference write (*ptr = value)
            if left.kind() == "pointer_expression" {
                // This is writing through a pointer
                if let Some(arg) = left.child_by_field_name("argument") {
                    if let Some(ptr_var) = lvalue_of(&arg, source) {
                        let ptr_var = LValue::Var(ptr_var.root_var().to_string());
                        if self.is_freed(&ptr_var) {
                            violations.extend(self.uaf(
                                RuleViolation {
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
                                },
                                &ptr_var,
                                source,
                            ));
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
            // deliberately index-insensitive, so a subscript LHS's
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
                self.rebind_from_variable(&left, &right, &left_lv, &left_var, &right_var);
            } else if left.kind() == "identifier" {
                // RHS is a non-variable expression (call result, etc.). A plain
                // pointer reassignment still overwrites any prior dangling
                // state (`free(p); p = make_buffer();`), so clear it.
                self.freed_vars.remove(&left_var);
                self.nullified_vars.remove(&left_var);
                self.realloc_invalidated.remove(&left_var);
                self.aliases.remove(&left_var);
                self.rebind_forgets_paths_inside(&left_var);
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
                // reassignment, plainly gives it a fresh value.
                self.freed_vars.remove(&left_var);
                self.nullified_vars.remove(&left_var);
                self.realloc_invalidated.remove(&left_var);
                self.freed_vars.remove(&left_lv);
                self.nullified_vars.remove(&left_lv);
                self.realloc_invalidated.remove(&left_lv);
                self.aliases.remove(&left_var);
                self.rebind_forgets_paths_inside(&left_lv);
            }

            // Check if right side is pointer arithmetic on freed memory
            if right.kind() == "binary_expression" {
                self.check_binary_expression(&right, source, violations);
            }

            // Clear freed status if reassigning the pointer to a fresh
            // allocation. Reassignment overwrites the dangling pointer, so the
            // variable is no longer freed; `FREE(p); p = wrapper_alloc(...);
            // if(!p){}` was a dominant free-then-reassign FP (an earlier fix pattern
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

    /// `x = f(x)` where `f` freed `x`: the store of `f`'s result
    /// into `x` follows the call, so `x` no longer holds the value that was
    /// freed and does not keep its state -- the same overwrite-clears rule
    /// `process_assignment` applies to `free(p); p = make_buffer();`. That
    /// visit is pre-order and had nothing to clear when it ran: the free
    /// happens inside the right-hand side it walks into afterwards, and
    /// its mark was landing on the variable AFTER the clear. hostap's
    /// consume-and-rebuild helpers (`wpabuf_zeropad`, `wpabuf_concat`,
    /// `asn1_encaps`, ...) are used this way at every call site, and every
    /// later use, free or re-pass of `x` -- `pfs->secret = wpabuf_zeropad(
    /// pfs->secret, ...)` included -- was reported against the stale state.
    ///
    /// Only the arguments this call actually freed are considered (the ids
    /// `process_call_expression` returned), and only the one the result is
    /// stored into: `y = f(x)` leaves `x` freed, which it is.
    fn clear_freed_args_overwritten_by_result(
        &mut self,
        call: &Node,
        source: &str,
        freed_arg_ids: &HashSet<usize>,
    ) {
        if freed_arg_ids.is_empty() {
            return;
        }
        let Some(left) = assignment_target_of_call(call) else {
            return;
        };
        let Some(left_lv) = lvalue_of(&left, source) else {
            return;
        };
        let Some(arguments) = call.child_by_field_name("arguments") else {
            return;
        };
        let overwritten = (0..arguments.named_child_count())
            .filter_map(|i| arguments.named_child(i))
            .filter(|arg| freed_arg_ids.contains(&arg.id()))
            .map(|arg| match arg.kind() {
                "cast_expression" => arg.child_by_field_name("value").unwrap_or(arg),
                _ => arg,
            })
            .any(|arg| lvalue_of(&arg, source).as_ref() == Some(&left_lv));
        if !overwritten {
            return;
        }
        let left_var = LValue::Var(left_lv.root_var().to_string());
        self.clear_freed_state(&left_var, &left_lv);
        self.sever_aliases_of(&left_var);
    }

    /// A clearing call overwrites the pointer members inside its
    /// destination, so a path freed before it no longer holds the value a
    /// later read returns -- the same overwrite-clears rule
    /// `process_assignment` applies to `free(p); p = NULL;`, reached by a
    /// route that assignment tracking cannot see.
    ///
    /// sqlite uses both spellings of the idiom. `sqlite3session.c`'s
    /// `sqlite3_free(sOut.aBuf); memset(&sOut, 0, sizeof(sOut));` nulls the
    /// member and the function then frees `sOut.aBuf` again on its way out,
    /// which was reported as a double free of a pointer the memset had
    /// already set to NULL. `fts3_aux.c` frees three members of `*pCsr` and
    /// then zeroes from one member to the end of the object -- `memset(
    /// &pCsr->csr, 0, ((u8*)&pCsr[1]) - (u8*)&pCsr->csr)` -- after which
    /// every one of those members reads NULL, not freed storage.
    ///
    /// Runs after `process_call_expression`, so a clearing call that is
    /// *itself* a use of freed memory (`free(p); memset(p, 0, n);`) is
    /// reported first and only then forgotten. Only field paths are
    /// cleared: a bare variable is the pointer, which lives outside the
    /// memory written, and rebinding one through `&p` is
    /// `process_address_of_args`'s job.
    fn clear_freed_paths_overwritten_by_clearing_call(&mut self, call: &Node, source: &str) {
        if self.freed_vars.is_empty() {
            return;
        }
        let Some(function_node) = call.child_by_field_name("function") else {
            return;
        };
        // Same classification order as `process_call_expression`: the
        // source spelling keys the macro table, everything else resolves
        // through the `#define` alias chain first.
        let spelled_name = get_node_text(&function_node, source);
        let function_name = const_eval::resolve_macro_alias(&self.macro_aliases, spelled_name);
        let dest_indices: Vec<usize> = if call_roles::is_memory_clearing_call(function_name) {
            vec![0]
        } else if let Some(indices) = self.macro_clear_params.get(spelled_name) {
            indices.clone()
        } else if let Some(summary) = self.function_summaries.get(function_name) {
            let mut indices: Vec<usize> = summary.clears_params.iter().copied().collect();
            indices.sort_unstable();
            indices
        } else {
            Vec::new()
        };
        if dest_indices.is_empty() {
            return;
        }
        let args = crate::analyze::macro_semantics::positional_args(call);
        for idx in dest_indices {
            let Some(dest) = args.get(idx) else { continue };
            let rest: Vec<Node> = args.iter().skip(idx + 1).copied().collect();
            let Some(extent) = cleared_extent(dest, &rest, source) else {
                continue;
            };
            let overwritten: Vec<LValue> = self
                .freed_vars
                .iter()
                .filter(|lv| extent.covers(lv))
                .cloned()
                .collect();
            for lv in overwritten {
                self.forget_freed_path(&lv);
            }
        }
    }

    /// Drop every trace of one freed field path, leaving the object it sits
    /// in alone. The companion to `clear_freed_state`, which also clears the
    /// base variable -- wrong here, because overwriting `s`'s members says
    /// nothing about `s` itself.
    /// A rebind of `lv` also invalidates every freed path INSIDE it: once
    /// `p` points at different storage, `p->buf` names a different object
    /// and the mark left by freeing the previous object's buffer is stale.
    ///
    /// sqlite's fts3_write.c flush loop is the case: `for(i=0;i<iRoot;i++){
    /// NodeWriter *pNode = &pWriter->aNodeWriter[i]; ...
    /// sqlite3_free(pNode->block.a); sqlite3_free(pNode->key.a); }` frees a
    /// DIFFERENT element's two buffers each time round, and without this the
    /// second iteration read as a repeat free of `pNode->block.a`. Every
    /// rebind site already cleared the rebound lvalue itself;
    /// none of them reached the paths hanging off it.
    ///
    /// The counterpart of `forget_freed_path`'s other caller
    /// from the opposite direction: there the storage was overwritten, here
    /// the path now names different storage.
    fn rebind_forgets_paths_inside(&mut self, lv: &LValue) {
        let stale: Vec<LValue> = self
            .freed_vars
            .iter()
            .chain(self.realloc_invalidated.iter())
            .filter(|path| path.is_inside(lv))
            .cloned()
            .collect();
        for path in stale {
            self.forget_freed_path(&path);
        }
    }

    fn forget_freed_path(&mut self, lv: &LValue) {
        self.freed_vars.remove(lv);
        self.freed_at.remove(lv);
        self.freed_under.remove(lv);
        self.guessed_freed.remove(lv);
        self.nullified_vars.remove(lv);
        self.realloc_invalidated.remove(lv);
    }

    /// `left = right` where the right-hand side names a variable: the alias
    /// and realloc bookkeeping of a pointer copy (extracted from
    /// `process_assignment_inner`).
    fn rebind_from_variable(
        &mut self,
        left: &Node,
        right: &Node,
        left_lv: &LValue,
        left_var: &LValue,
        right_var: &LValue,
    ) {
        // Check if right_var was the result of a realloc on left_var
        // This handles: new_ptr = realloc(ptr, ...); ptr = new_ptr;
        // Also handles: im->clip->list = more; after more = gdRealloc(im->clip->list, ...)
        if self.realloc_updated.contains(right_var) {
            // Clear both base variable and full path
            self.freed_vars.remove(left_var);
            self.nullified_vars.remove(left_var);
            self.realloc_invalidated.remove(left_var);
            // For field expressions, also clear the full path
            self.freed_vars.remove(left_lv);
            self.nullified_vars.remove(left_lv);
            self.realloc_invalidated.remove(left_lv);
            // Also clear any aliases pointing to the old value
            self.aliases.remove(left_var);
        }

        if right.kind() == "identifier" && self.is_freed(right_var) {
            // Aliasing a dangling pointer (`p = q;` after free(q)) — the
            // new variable also dangles. Gated on an identifier RHS:
            // a subscript/field RHS copies a value out of a container,
            // not the dangling pointer itself.
            //
            // What dangles is the ASSIGNED LOCATION, not the object it
            // sits in. `h->head = p;` after free(p) makes `h->head`
            // dangle; `h` itself was never freed, and marking the root
            // reported every unrelated sibling (`h->count`) as a
            // use-after-free of `h`. For a plain identifier
            // LHS the path IS the root, so that case is unchanged.
            self.freed_vars.insert(left_lv.clone());
            self.copy_guessed_free(left_lv, right_var);
            self.aliases.insert(left_lv.clone(), right_var.clone());
        } else {
            // Reassigning the pointer to a live value overwrites any
            // prior dangling state: `free(p); p = newbuf;` and the
            // reassign-before-return shape (`free(text); text = temp;
            // return text;`) must clear `p`/`text` (an earlier fix patterns
            // 1 & 2). Clear the assigned lvalue path; for a plain
            // identifier that IS the base name, so `free(s); s->f = x;`
            // does not un-track the still-freed base `s`.
            self.freed_vars.remove(left_lv);
            self.nullified_vars.remove(left_lv);
            self.realloc_invalidated.remove(left_lv);
            self.aliases.remove(left_var);
            if right.kind() == "identifier" && left.kind() == "identifier" {
                // Track a fresh pointer-to-pointer alias.
                self.aliases.insert(left_var.clone(), right_var.clone());
            }
        }
        // Either way the assigned location now holds a different pointer,
        // so the paths hanging off it name different storage.
        self.rebind_forgets_paths_inside(left_lv);
    }

    /// A variable that has just been given a new value aliases nothing it
    /// aliased before, and nothing that aliased IT still refers to the object
    /// it now holds. `aliases` is keyed alias -> target, so removing the key
    /// alone left `old_s -> s` in place across `old_s = s; s = create(); free(
    /// old_s);`, and the free of the previous object reached the fresh one
    /// through the stale entry: valkey's debug_lua.c reported `return s` as
    /// returning freed memory.
    fn sever_aliases_of(&mut self, var: &LValue) {
        self.aliases.remove(var);
        self.aliases.retain(|_, target| target != var);
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

    /// A declaration WITHOUT an initializer (`char *unescaped;`) is as much a
    /// fresh binding as one with (`process_init_declarator`), and
    /// needs the same clearing: the analyzer is scope-flat, so curl's
    /// `ldap.c::_ldap_url_parse2`, which declares `char *unescaped;` in
    /// three sibling blocks and frees it in each, saw the second block's
    /// `Curl_urldecode(..., &unescaped, ...)` as a use of the FIRST block's
    /// freed pointer. `init_declarator` children are left to
    /// their own handler; only bare `identifier`/`pointer_declarator`
    /// declarators are cleared here.
    fn process_plain_declarators(&mut self, node: &Node, source: &str) {
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else { continue };
            if !matches!(child.kind(), "identifier" | "pointer_declarator") {
                continue;
            }
            let name = self.extract_declarator_name(&child, source);
            if name.is_empty() {
                continue;
            }
            let lv = LValue::Var(name);
            self.freed_vars.remove(&lv);
            self.nullified_vars.remove(&lv);
            self.realloc_invalidated.remove(&lv);
            self.sever_aliases_of(&lv);
            self.rebind_forgets_paths_inside(&lv);
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
            // the new variable cannot alias the old freed storage (
            // init-declarator analog of free-then-reassign). The alias branch
            // below re-marks it freed if it genuinely aliases a freed pointer.
            self.freed_vars.remove(&left_var);
            self.nullified_vars.remove(&left_var);
            self.realloc_invalidated.remove(&left_var);
            self.sever_aliases_of(&left_var);
            self.rebind_forgets_paths_inside(&left_var);

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
            // (an earlier fix container-vs-member; rtext.c fullFont). Restricting
            // aliasing to an identifier RHS prevents that false UAF.
            if value.kind() == "identifier" {
                let right_var = LValue::Var(get_node_text(&value, source).to_string());
                self.aliases.insert(left_var.clone(), right_var.clone());
                // If source is freed, the new variable is also freed
                if self.is_freed(&right_var) {
                    self.copy_guessed_free(&left_var, &right_var);
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

        // `&p` is address-of, not a dereference: it names the variable's own
        // storage, which is live whatever `p` points at.
        if is_address_of(node, source) {
            return;
        }

        if let Some(arg) = node.child_by_field_name("argument") {
            if let Some(lv) = lvalue_of(&arg, source) {
                let var_name = LValue::Var(lv.root_var().to_string());
                if self.is_freed(&var_name) {
                    violations.extend(self.uaf(
                        RuleViolation {
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
                        },
                        &var_name,
                        source,
                    ));
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
                violations.extend(self.uaf(
                    RuleViolation {
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
                    },
                    &lv,
                    source,
                ));
                return;
            }

            // Also check base variable
            let var_name = LValue::Var(lv.root_var().to_string());
            if self.is_freed(&var_name) {
                violations.extend(self.uaf(
                    RuleViolation {
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
                    },
                    &var_name,
                    source,
                ));
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
                        violations.extend(self.uaf(
                            RuleViolation {
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
                            },
                            &left_var,
                            source,
                        ));
                    }
                }
            }
        }
    }

    /// Check function arguments for use of freed memory
    fn check_function_args_for_freed(
        &mut self,
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

                    // `f(&p)` passes the ADDRESS of the variable, not the
                    // freed pointer it holds; the callee receiving a slot is
                    // the out-parameter idiom that refills it
                    // (`process_address_of_args`), not a use (
                    // 1234).
                    if is_address_of(&arg, source) {
                        continue;
                    }

                    if let Some(lv) = lvalue_of(&arg, source) {
                        let var_name = LValue::Var(lv.root_var().to_string());
                        if self.is_freed(&var_name) {
                            violations.extend(self.uaf(
                                RuleViolation {
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
                                },
                                &var_name,
                                source,
                            ));
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
                        violations.extend(self.uaf(
                            RuleViolation {
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
                            },
                            &var_name,
                            source,
                        ));
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
        // same field regardless of spelling.
        let Some(lv) = lvalue_of(node, source) else {
            return;
        };
        if self.is_freed(&lv) {
            violations.extend(self.uaf(
                RuleViolation {
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
                },
                &lv,
                source,
            ));
            return;
        }

        // Check if the base of field expression is freed
        let var_name = LValue::Var(lv.root_var().to_string());
        if self.is_freed(&var_name) {
            violations.extend(self.uaf(
                RuleViolation {
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
                },
                &var_name,
                source,
            ));
        }
    }

    /// Finish a use-after-free finding on `lv` with what is known about how
    /// `lv` came to be freed.
    ///
    /// A free that reached this rule on a callee's NAME alone -- `frees_params_
    /// guessed` in the summary that credited it -- is a MAY-free, the same
    /// evidence 1269 judged insufficient for MEM31-C to accuse a double free.
    /// For a use-after-free it is still the only evidence the analyzer will
    /// ever have for a wrapper whose body frees through a function pointer
    /// (`sqlite3_free`), so the finding is kept and marked for manual review
    /// rather than dropped: the reader sees that the "free" is an inference
    /// from a name, and the oracle keeps the key.
    fn uaf(
        &self,
        mut violation: RuleViolation,
        lv: &LValue,
        source: &str,
    ) -> Option<RuleViolation> {
        // A preprocessor conditional between the free and this use puts the
        // two in what may be mutually exclusive build configurations --
        // curl's `curl_dbg_freeaddrinfo` frees `freethis` in each arm of an
        // `#ifdef USE_LWIPSOCK / #elif / #else` chain, and the linear walk
        // sees arm two "use" what arm one freed. The double-free path has
        // declined to report across such a split since an earlier fix; a
        // use-after-free across one is the same unsound sequence.
        let freed_byte = self
            .freed_at
            .get(lv)
            .or_else(|| self.aliases.get(lv).and_then(|c| self.freed_at.get(c)))
            .copied();
        if let Some(prior) = freed_byte {
            let here = byte_offset_of_line(source, violation.line);
            if preproc_conditional_between(source, prior.min(here), prior.max(here)) {
                return None;
            }
        }
        if let Some(callee) = self.guessed_free_of(lv) {
            violation.requires_manual_review = Some(true);
            if std::env::var_os("AURORA_MEM30_GUESS_DEBUG").is_some() {
                violation.message = format!("{} [guessed-free via {}]", violation.message, callee);
            }
        }
        Some(violation)
    }

    /// The callee whose name alone credited the free of `lv`, looked up on
    /// `lv` itself or, one hop, on what it aliases.
    fn guessed_free_of(&self, lv: &LValue) -> Option<&String> {
        self.guessed_freed
            .get(lv)
            .or_else(|| self.aliases.get(lv).and_then(|c| self.guessed_freed.get(c)))
    }

    /// `to` just took its freed state from `from` by copy (`q = p;`,
    /// `h->head = p;`, `T *q = p;`): the guess mark travels with it. The
    /// one-hop alias lookup in [`Self::guessed_free_of`] does not cover a
    /// chain, and `r = q;` after `q = p;` links `r` to `q`, not to `p`.
    fn copy_guessed_free(&mut self, to: &LValue, from: &LValue) {
        match self.guessed_free_of(from).cloned() {
            Some(callee) => {
                self.guessed_freed.insert(to.clone(), callee);
            }
            None => {
                self.guessed_freed.remove(to);
            }
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
/// such a directive: without a preprocessor aurora-lint cannot know whether the two free
/// sites are co-compiled or live in mutually-exclusive configurations, so their
/// raw parse order is not a sound execution sequence. `#define` /
/// `#include` and other non-conditional directives are ignored — they do not
/// gate code in or out.
/// Byte offset at which 1-based `line` starts (the source length when the
/// line is past the end), for comparing a reported site against `freed_at`.
fn byte_offset_of_line(source: &str, line: usize) -> usize {
    if line <= 1 {
        return 0;
    }
    let mut remaining = line - 1;
    for (i, b) in source.bytes().enumerate() {
        if b == b'\n' {
            remaining -= 1;
            if remaining == 0 {
                return i + 1;
            }
        }
    }
    source.len()
}

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
