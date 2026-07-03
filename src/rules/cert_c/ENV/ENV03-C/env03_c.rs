//! ENV03-C: Sanitize the environment when invoking external programs
//!
//! This rule detects when external programs are invoked via system() or popen()
//! without first sanitizing the environment (clearing or setting PATH/IFS).
//!
//! Resolves macro aliases (#define SYSTEM system) via project context.
//!
//! Sanitization is checked per function scope: clearenv()/setenv()/putenv()
//! must appear in the same function as the system()/popen() call.
//!
//! Violation pattern:
//!   system("/bin/ls");  // No clearenv() or setenv("PATH"/"IFS") in this function
//!
//! Compliant patterns:
//!   clearenv();
//!   setenv("PATH", "/bin", 1);
//!   setenv("IFS", " \t\n", 1);
//!   system("/bin/ls");  // Environment sanitized in same function

use crate::analyze::cfg;
use crate::analyze::const_eval;
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::{get_node_text, is_function_parameter};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Functions that read externally-controlled data into a variable.
/// If none of these appear in the containing function, a local-variable
/// command argument to system/popen is treated as program-controlled
/// (no taint path) and the ENV03-C warning is suppressed.
///
/// Must stay in sync with
/// `function_summary::ENV03_TAINT_SOURCE_FUNCTIONS` so that the
/// scope-local scan here and the cross-function summary bit agree on
/// which calls introduce taint.
const TAINT_SOURCES: &[&str] = &[
    // Sockets / network
    "recv",
    "recvfrom",
    "recvmsg",
    "WSARecv",
    "WSARecvFrom",
    "accept",
    // File / stream I/O
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
    // Wide-character input
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
    // Environment / command line
    "getenv",
    "secure_getenv",
    "_wgetenv",
    "_wgetenv_s",
    // Windows stdin / registry
    "ReadFile",
    "ReadConsole",
    "ReadConsoleA",
    "ReadConsoleW",
    "RegQueryValueExA",
    "RegQueryValueExW",
];

pub struct Env03C {
    project_aliases: RefCell<HashMap<String, String>>,
    current_aliases: RefCell<HashMap<String, String>>,
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    /// Reverse call graph: callee_name → set of caller names. Built from
    /// ProjectContext's forward `call_graph`.
    callers: RefCell<HashMap<String, HashSet<String>>>,
    /// File-scope static pointer writers from prescan: global_name → writer
    /// function names. A read like `char *data = g_static;` is treated as
    /// clean iff every writer's summary has `has_env03_taint_source == false`
    /// and `returns_tainted == false`. Targets Juliet CWE-78 variant 45
    /// (goodG2BSink pattern).
    global_writers: RefCell<HashMap<String, HashSet<String>>>,
    /// Per-file `#define NAME "string"` map for checking whether a strcpy/strcat
    /// source macro expands to an absolute path (safe) vs. a relative command.
    file_string_macros: RefCell<HashMap<String, String>>,
}

impl Env03C {
    pub fn new() -> Self {
        Self {
            project_aliases: RefCell::new(HashMap::new()),
            current_aliases: RefCell::new(HashMap::new()),
            function_summaries: RefCell::new(HashMap::new()),
            callers: RefCell::new(HashMap::new()),
            global_writers: RefCell::new(HashMap::new()),
            file_string_macros: RefCell::new(HashMap::new()),
        }
    }
}

impl Default for Env03C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Env03C {
    fn rule_id(&self) -> &'static str {
        "ENV03-C"
    }

    fn description(&self) -> &'static str {
        "Sanitize the environment when invoking external programs"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "ENV03-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_aliases.borrow_mut() = context.macro_aliases.clone();
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();
        *self.global_writers.borrow_mut() = context.global_writers.clone();

        // Invert the forward call_graph (caller → callees) into a reverse
        // map (callee → callers) for fast lookup.
        let mut callers: HashMap<String, HashSet<String>> = HashMap::new();
        for (caller, callees) in &context.call_graph {
            for callee in callees {
                callers
                    .entry(callee.clone())
                    .or_default()
                    .insert(caller.clone());
            }
        }
        *self.callers.borrow_mut() = callers;
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // Merge project-level aliases with per-file aliases
        let mut aliases = self.project_aliases.borrow().clone();
        aliases.extend(const_eval::collect_macro_aliases(node, source));
        *self.current_aliases.borrow_mut() = aliases;
        *self.file_string_macros.borrow_mut() =
            const_eval::collect_string_literal_macros(node, source);

        let mut violations = Vec::new();
        self.check_all_calls(node, source, &mut violations);
        violations
    }
}

impl Env03C {
    /// Resolve a function name through macro aliases.
    fn resolve_name(&self, name: &str) -> String {
        let aliases = self.current_aliases.borrow();
        if let Some(target) = aliases.get(name) {
            target.clone()
        } else {
            name.to_string()
        }
    }

    /// Find all system()/popen() calls and check if their containing scope
    /// has environment sanitization.
    fn check_all_calls(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let calls = query::find_descendants_of_kind(*node, "call_expression");
        for node in calls {
            let node = &node;
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                let resolved = self.resolve_name(&func_name);

                if resolved == "system" || resolved == "popen" {
                    // Find containing function, or root for bare code
                    let scope = self.find_containing_function_or_root(node);
                    let scope_node = scope.unwrap_or(*node);

                    // Check if that scope has sanitization
                    let mut has_sanitization = false;
                    self.check_for_sanitization(&scope_node, source, &mut has_sanitization);

                    if !has_sanitization && self.command_arg_is_untrusted(node, &scope_node, source)
                    {
                        let start_point = node.start_position();
                        let call_text = get_node_text(node, source);

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "External program invocation '{}' without environment sanitization. \
                                The environment should be sanitized before invoking external programs \
                                to prevent environment variable manipulation attacks.",
                                call_text
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Call clearenv() to clear the environment, then use setenv() to set \
                                PATH and IFS to known safe values before invoking external programs."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Find the containing function_definition, or the translation_unit root.
    fn find_containing_function_or_root<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = *node;
        let mut root = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition" {
                return Some(parent);
            }
            root = parent;
            current = parent;
        }
        // No function found — return the root (translation_unit)
        Some(root)
    }

    fn check_for_sanitization(&self, node: &Node, source: &str, has_sanitization: &mut bool) {
        if *has_sanitization {
            return; // Already found
        }

        let calls = query::find_descendants_of_kind(*node, "call_expression");
        for node in &calls {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // clearenv() clears the entire environment
                if func_name == "clearenv" {
                    *has_sanitization = true;
                    return;
                }

                // setenv("PATH", ...) or setenv("IFS", ...) sanitizes those variables
                if func_name == "setenv" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        // Get first argument
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                if arg.kind() == "string_literal" {
                                    let arg_text = get_node_text(&arg, source);
                                    // Check for PATH or IFS
                                    if arg_text.contains("PATH") || arg_text.contains("IFS") {
                                        *has_sanitization = true;
                                        return;
                                    }
                                }
                                break; // Only check first argument
                            }
                        }
                    }
                }

                // putenv() with PATH= or IFS=
                if func_name == "putenv" {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                if arg.kind() == "string_literal" {
                                    let arg_text = get_node_text(&arg, source);
                                    if arg_text.contains("PATH=") || arg_text.contains("IFS=") {
                                        *has_sanitization = true;
                                        return;
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Decide whether the command argument of a system()/popen() call is
    /// untrusted enough to warrant an ENV03-C finding.
    ///
    /// Returns true (flag) by default. Returns false (suppress) only when we
    /// can positively prove the argument is a local variable whose value is
    /// entirely program-controlled: initialized from a local literal-backed
    /// buffer, never assigned from a function call or foreign identifier,
    /// and only mutated via strcat/strcpy with string-literal sources.
    fn command_arg_is_untrusted(&self, call: &Node, scope: &Node, source: &str) -> bool {
        let Some(args) = call.child_by_field_name("arguments") else {
            return true;
        };
        let Some(first_arg) = first_non_paren_arg(&args) else {
            return true;
        };

        let arg = strip_casts_and_parens(first_arg);

        if arg.kind() != "identifier" {
            return true;
        }

        if scope.kind() != "function_definition" {
            return true;
        }

        let var_name = get_node_text(&arg, source);
        if is_function_parameter(scope, var_name, source) {
            // Cross-function caller taint check: the command variable is
            // this function's parameter, so defer to callers. If every
            // caller's body is free of taint sources, treat the param as
            // safe (Juliet goodG2BSink pattern). If any caller taints
            // data, or we have no caller info, stay conservative.
            return !self.callers_are_all_clean(scope, source);
        }

        if scope_has_taint_source(scope, source) {
            return true;
        }

        // Command var is a local, not a parameter. But if it's initialized
        // solely from parameter-derived expressions (*p, p[i], p.f, p->f,
        // chained through casts and intermediate locals), then taint is
        // upstream — defer to the same caller-aware check. Juliet variants
        // 63/64/66/67 use this shape: a cross-file sink receives data via
        // pointer-to-pointer / void* / array / struct parameter, then copies
        // it into a local before the popen call.
        if is_command_var_parameter_derived(scope, var_name, source) {
            return !self.callers_are_all_clean(scope, source);
        }

        let summaries = self.function_summaries.borrow();
        let global_writers = self.global_writers.borrow();
        let string_macros = self.file_string_macros.borrow();
        !is_command_var_locally_safe(
            scope,
            var_name,
            source,
            &summaries,
            &global_writers,
            &string_macros,
        )
    }

    /// Return true when we can prove every caller of `scope`'s function
    /// has no taint-source call in its body. False when we lack caller
    /// info or when at least one caller is tainted.
    fn callers_are_all_clean(&self, scope: &Node, source: &str) -> bool {
        let Some(scope_name) = cfg::get_function_name(scope, source) else {
            return false;
        };

        let callers = self.callers.borrow();
        let Some(caller_set) = callers.get(scope_name) else {
            return false;
        };
        if caller_set.is_empty() {
            return false;
        }

        let summaries = self.function_summaries.borrow();
        for caller in caller_set {
            match summaries.get(caller) {
                Some(s) if !s.has_env03_taint_source && !s.has_relative_command_write => {}
                _ => return false,
            }
        }
        true
    }
}

/// Return the first argument node of an `argument_list`, skipping the
/// surrounding `(` / `)` punctuation tokens.
fn first_non_paren_arg<'a>(args: &Node<'a>) -> Option<Node<'a>> {
    for i in 0..args.child_count() {
        if let Some(child) = args.child(i) {
            if child.is_named() {
                return Some(child);
            }
        }
    }
    None
}

/// Peel off redundant parens and C-style casts so we can inspect the
/// underlying expression (e.g. `(char *)data` → `data`).
fn strip_casts_and_parens<'a>(mut node: Node<'a>) -> Node<'a> {
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

/// True if any call_expression under `scope` targets a known taint source.
fn scope_has_taint_source(scope: &Node, source: &str) -> bool {
    let mut found = false;
    walk_for_taint(scope, source, &mut found);
    found
}

fn walk_for_taint(node: &Node, source: &str, found: &mut bool) {
    if *found {
        return;
    }
    let call = query::find_first_descendant(*node, |n| {
        if n.kind() != "call_expression" {
            return false;
        }
        let Some(function) = n.child_by_field_name("function") else {
            return false;
        };
        let name = get_node_text(&function, source);
        let ident = trailing_identifier(name);
        // Check exact match first, then case-insensitive for UPPERCASE macro
        // aliases (e.g. Juliet's `#define GETENV getenv`).
        if TAINT_SOURCES.contains(&ident) {
            return true;
        }
        let lower = ident.to_lowercase();
        lower != ident && TAINT_SOURCES.contains(&lower.as_str())
    });
    if call.is_some() {
        *found = true;
    }
}

/// Take the trailing identifier token from a possibly-qualified name
/// (e.g. `std::foo`, `obj->bar`, `POPEN`). Keeps alnum + underscores.
fn trailing_identifier(name: &str) -> &str {
    name.rsplit(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or(name)
}

/// Return true when every write to `var_name` in `scope` is an expression
/// derived from a function parameter via deref (`*p`), subscript (`p[i]`),
/// field access (`p.f` / `p->f`), or cast (`(T)p`) — possibly chained
/// through intermediate locals that are themselves parameter-derived.
///
/// Targets Juliet CWE-78 variants 63/64/66/67 where a cross-file "sink"
/// function receives tainted-or-not data via a pointer-to-pointer / void*
/// / array / struct parameter and copies it into a local before calling
/// popen/system. Combined with `callers_are_all_clean`, this suppresses
/// the goodG2BSink FP without affecting the badSink TP (the bad caller
/// has recv/fgets so its summary is tainted).
///
/// Requires at least one write so an uninitialised pointer never counts.
fn is_command_var_parameter_derived(scope: &Node, var_name: &str, source: &str) -> bool {
    let Some(body) = scope.child_by_field_name("body") else {
        return false;
    };
    let params: HashSet<String> = collect_param_names(scope, source).into_iter().collect();
    if params.is_empty() {
        return false;
    }

    // Collect every variable's write-RHS list once, then iterate a
    // fixpoint: add `v` to `derived` when every RHS evaluates to a
    // parameter-derived expression under the current `derived` set.
    let mut writes: HashMap<String, Vec<Node>> = HashMap::new();
    collect_variable_writes(&body, source, &mut writes);

    let mut derived = params.clone();
    loop {
        let before = derived.len();
        for (name, rhs_list) in &writes {
            if derived.contains(name) {
                continue;
            }
            if !rhs_list.is_empty()
                && rhs_list
                    .iter()
                    .all(|r| is_param_derived_expr(r, &derived, source))
            {
                derived.insert(name.clone());
            }
        }
        if derived.len() == before {
            break;
        }
    }

    // The var itself must be present (has at least one write) and every
    // write must be derived — i.e. var_name was added to derived by the
    // loop above. Parameters aren't command vars here (handled earlier).
    !params.contains(var_name) && derived.contains(var_name)
}

/// Parameter-declarator identifiers for a `function_definition` node.
fn collect_param_names(scope: &Node, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    let Some(decl) = scope.child_by_field_name("declarator") else {
        return names;
    };
    let Some(params) = find_parameter_list(&decl) else {
        return names;
    };
    for i in 0..params.child_count() {
        let Some(child) = params.child(i) else {
            continue;
        };
        if child.kind() != "parameter_declaration" {
            continue;
        }
        let Some(pd) = child.child_by_field_name("declarator") else {
            continue;
        };
        if let Some(name) = extract_declarator_name(&pd, source) {
            names.push(name);
        }
    }
    names
}

fn find_parameter_list<'a>(node: &Node<'a>) -> Option<Node<'a>> {
    if node.kind() == "function_declarator" {
        for i in 0..node.child_count() {
            if let Some(c) = node.child(i) {
                if c.kind() == "parameter_list" {
                    return Some(c);
                }
            }
        }
    }
    // Nested declarators (e.g. pointer_declarator → function_declarator).
    for i in 0..node.child_count() {
        if let Some(c) = node.child(i) {
            if let Some(found) = find_parameter_list(&c) {
                return Some(found);
            }
        }
    }
    None
}

/// Gather `(var_name, Vec<rhs>)` for every assignment to a named local
/// variable under `body`. Covers both `init_declarator` (declaration with
/// initializer) and plain `lhs = rhs` assignment expressions. Only `=` is
/// tracked; compound assignments like `+=` are ignored (they mean the
/// write isn't purely derived from the RHS).
fn collect_variable_writes<'a>(
    node: &Node<'a>,
    source: &str,
    writes: &mut HashMap<String, Vec<Node<'a>>>,
) {
    let candidates =
        query::find_descendants_of_kinds(*node, &["init_declarator", "assignment_expression"]);
    for node in &candidates {
        match node.kind() {
            "init_declarator" => {
                if let Some(decl) = node.child_by_field_name("declarator") {
                    if let Some(name) = extract_declarator_name(&decl, source) {
                        if let Some(value) = node.child_by_field_name("value") {
                            writes.entry(name).or_default().push(value);
                        }
                    }
                }
            }
            "assignment_expression" => {
                if let Some(lhs) = node.child_by_field_name("left") {
                    let lhs = strip_casts_and_parens(lhs);
                    if lhs.kind() == "identifier" {
                        let op_is_plain = node_operator(node, source)
                            .map(|op| op == "=")
                            .unwrap_or(true);
                        if op_is_plain {
                            if let Some(rhs) = node.child_by_field_name("right") {
                                let name = get_node_text(&lhs, source).to_string();
                                writes.entry(name).or_default().push(rhs);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// True if `expr` is a parameter-derived expression given the current
/// `derived` set. Peels casts/parens, then unwraps deref, subscript, and
/// field access to reach an identifier, which must be in `derived`.
fn is_param_derived_expr(expr: &Node, derived: &HashSet<String>, source: &str) -> bool {
    let e = strip_casts_and_parens(*expr);
    match e.kind() {
        "identifier" => derived.contains(get_node_text(&e, source)),
        "pointer_expression" | "unary_expression" => e
            .child_by_field_name("argument")
            .is_some_and(|a| is_param_derived_expr(&a, derived, source)),
        "subscript_expression" => e
            .child_by_field_name("argument")
            .is_some_and(|a| is_param_derived_expr(&a, derived, source)),
        "field_expression" => e
            .child_by_field_name("argument")
            .is_some_and(|a| is_param_derived_expr(&a, derived, source)),
        _ => false,
    }
}

/// Can we prove the local variable `var_name` in this function scope is
/// entirely program-controlled up to the point of use? "Safe" means:
/// - every assignment's RHS is a string literal, or an identifier that
///   names a local buffer with a literal initializer;
/// - no assignment comes from a function call;
/// - the declaration initializer (if any) is similarly restricted;
/// - any in-place mutation is `strcat`/`strcpy` with a string-literal
///   source argument.
///
/// The aim is to recognize Juliet `goodG2B` patterns like
/// ```c
/// char data_buf[100] = "ls ";
/// char *data = data_buf;
/// strcat(data, "*.*");
/// popen(data, "w");
/// ```
/// without suppressing Juliet `*_bad` variants where `data` is assigned
/// from a helper-function return value, a static global, or receives
/// taint from `recv`/`fgets`/`scanf`/etc.
fn is_command_var_locally_safe(
    scope: &Node,
    var_name: &str,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
    global_writers: &HashMap<String, HashSet<String>>,
    string_macros: &HashMap<String, String>,
) -> bool {
    let body = match scope.child_by_field_name("body") {
        Some(b) => b,
        None => return false,
    };
    let local_buffers = collect_local_literal_buffers(&body, source, summaries, global_writers);

    let mut all_safe = true;
    check_writes(
        &body,
        var_name,
        &local_buffers,
        source,
        summaries,
        string_macros,
        &mut all_safe,
    );
    all_safe
}

/// Identifiers of local variables whose declarations make them safe
/// sources for the command variable. Starts with `char`/`wchar_t` arrays
/// initialized from string literals (or macros), then iterates to fold in
/// pointer variables initialized from an already-safe identifier.
///
/// Also seeds with file-scope static globals whose every writer function
/// has a taint-free summary — the Juliet v45 goodG2BSink pattern where
/// `char *data = g_goodG2BData;` reads a global that's only written by
/// functions that don't introduce taint.
fn collect_local_literal_buffers(
    body: &Node,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
    global_writers: &HashMap<String, HashSet<String>>,
) -> HashSet<String> {
    let mut buffers = HashSet::new();
    for (global_name, writers) in global_writers {
        if writers.iter().all(|w| match summaries.get(w) {
            Some(s) => !s.has_env03_taint_source && !s.returns_tainted,
            None => false,
        }) {
            buffers.insert(global_name.clone());
        }
    }
    // Pass 1: arrays with literal/macro initializers.
    walk_buffer_decls(body, source, &mut buffers);
    // Passes 2+: propagate through pointer aliases until fixpoint.
    loop {
        let before = buffers.len();
        walk_pointer_aliases(body, source, summaries, &mut buffers);
        if buffers.len() == before {
            break;
        }
    }
    buffers
}

fn walk_buffer_decls(node: &Node, source: &str, out: &mut HashSet<String>) {
    let decls = query::find_descendants_of_kind(*node, "declaration");
    for node in &decls {
        for i in 0..node.child_count() {
            let Some(child) = node.child(i) else { continue };
            let (decl_node, init_node) = match child.kind() {
                "array_declarator" => (child, None),
                "init_declarator" => {
                    let Some(d) = child.child_by_field_name("declarator") else {
                        continue;
                    };
                    if d.kind() != "array_declarator" {
                        continue;
                    }
                    (d, child.child_by_field_name("value"))
                }
                _ => continue,
            };
            if !initializer_is_safe_for_buffer(&init_node) {
                continue;
            }
            if let Some(name) = extract_declarator_name(&decl_node, source) {
                out.insert(name);
            }
        }
    }
}

fn walk_pointer_aliases(
    node: &Node,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
    out: &mut HashSet<String>,
) {
    let candidates =
        query::find_descendants_of_kinds(*node, &["declaration", "assignment_expression"]);
    for node in &candidates {
        match node.kind() {
            "declaration" => {
                for i in 0..node.child_count() {
                    let Some(child) = node.child(i) else { continue };
                    if child.kind() != "init_declarator" {
                        continue;
                    }
                    let Some(decl) = child.child_by_field_name("declarator") else {
                        continue;
                    };
                    if decl.kind() != "pointer_declarator" {
                        continue;
                    }
                    let Some(value) = child.child_by_field_name("value") else {
                        continue;
                    };
                    if rhs_is_safe(Some(&value), out, source, summaries) {
                        if let Some(name) = extract_declarator_name(&decl, source) {
                            out.insert(name);
                        }
                    }
                }
            }
            "assignment_expression" => {
                if let Some(lhs) = node.child_by_field_name("left") {
                    let lhs = strip_casts_and_parens(lhs);
                    let op_is_plain = node_operator(node, source)
                        .map(|op| op == "=")
                        .unwrap_or(true);
                    if lhs.kind() == "identifier" && op_is_plain {
                        let rhs = node.child_by_field_name("right");
                        if rhs_is_safe(rhs.as_ref(), out, source, summaries) {
                            out.insert(get_node_text(&lhs, source).to_string());
                        }
                    } else if lhs.kind() == "field_expression" && op_is_plain {
                        // union_var.member = safe_value → mark the aggregate variable
                        // as a safe source. Only `.` access (local aggregate), not `->`
                        // (pointer dereference). Handles Juliet v34: union data flow
                        // where the same slot is read back through the other member alias.
                        if let Some(base) = field_expr_dot_base(&lhs, source) {
                            let rhs = node.child_by_field_name("right");
                            if rhs_is_safe(rhs.as_ref(), out, source, summaries) {
                                out.insert(base);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn initializer_is_safe_for_buffer(init: &Option<Node>) -> bool {
    let Some(init) = init else {
        return true;
    };
    // `char buf[N] = X;` is only legal C when X is a string literal, an
    // initializer list, or a macro that expands to one of those, so any
    // bare identifier here is treated as a macro-backed literal.
    matches!(
        init.kind(),
        "string_literal" | "concatenated_string" | "initializer_list" | "identifier"
    )
}

fn extract_declarator_name(decl: &Node, source: &str) -> Option<String> {
    let mut current = *decl;
    loop {
        match current.kind() {
            "identifier" | "field_identifier" | "type_identifier" => {
                return Some(get_node_text(&current, source).to_string());
            }
            _ => {
                if let Some(inner) = current.child_by_field_name("declarator") {
                    current = inner;
                    continue;
                }
                // Try named children until we find one shaped like an
                // inner declarator.
                let mut next = None;
                for i in 0..current.child_count() {
                    if let Some(c) = current.child(i) {
                        if c.is_named() && c.kind() != "number_literal" {
                            next = Some(c);
                            break;
                        }
                    }
                }
                match next {
                    Some(n) => current = n,
                    None => return None,
                }
            }
        }
    }
}

fn check_writes(
    node: &Node,
    var: &str,
    safe_sources: &HashSet<String>,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
    string_macros: &HashMap<String, String>,
    all_safe: &mut bool,
) {
    let candidates = query::find_descendants_of_kinds(
        *node,
        &[
            "init_declarator",
            "assignment_expression",
            "call_expression",
        ],
    );
    for node in &candidates {
        if !*all_safe {
            return;
        }
        match node.kind() {
            "init_declarator" => {
                check_init_declarator_write(node, var, safe_sources, source, summaries, all_safe);
            }
            "assignment_expression" => {
                check_assignment_write(node, var, safe_sources, source, summaries, all_safe);
            }
            "call_expression" => {
                check_str_append_write(node, var, safe_sources, source, string_macros, all_safe);
            }
            _ => {}
        }
    }
}

/// `T var = <rhs>;` — clear `all_safe` if the initializer of `var` is not a safe source.
fn check_init_declarator_write(
    node: &Node,
    var: &str,
    safe_sources: &HashSet<String>,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
    all_safe: &mut bool,
) {
    if let Some(decl) = node.child_by_field_name("declarator") {
        if declarator_names(&decl, source).iter().any(|n| n == var) {
            let value = node.child_by_field_name("value");
            if !rhs_is_safe(value.as_ref(), safe_sources, source, summaries) {
                *all_safe = false;
            }
        }
    }
}

/// `var = <rhs>;` (or `var += ...`) — clear `all_safe` if a direct write to `var`
/// assigns an unsafe source. Index writes (`var[i] = ...`) are neutral.
fn check_assignment_write(
    node: &Node,
    var: &str,
    safe_sources: &HashSet<String>,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
    all_safe: &mut bool,
) {
    let Some(lhs) = node.child_by_field_name("left") else {
        // No lhs field — nothing to check here; the caller recurses into children.
        return;
    };
    let lhs = strip_casts_and_parens(lhs);
    // Only plain `var = ...` matters. `var[i] = ...` is an index
    // write, which doesn't change the pointer itself; treat as
    // neutral (and let strcat/recv checks cover buffer contents).
    if lhs.kind() == "identifier" && get_node_text(&lhs, source) == var {
        let op_matches = node_operator(node, source)
            .map(|op| op == "=")
            .unwrap_or(true);
        if op_matches {
            let rhs = node.child_by_field_name("right");
            if !rhs_is_safe(rhs.as_ref(), safe_sources, source, summaries) {
                *all_safe = false;
            }
        } else {
            // += / -= etc. on a char pointer command variable is
            // unusual; be conservative.
            *all_safe = false;
        }
    }
}

/// `strcat(var, X)` / `strcpy(var, X)` and wide/n variants — when the destination
/// is `var`, clear `all_safe` unless the appended/copied source `X` is safe.
fn check_str_append_write(
    node: &Node,
    var: &str,
    safe_sources: &HashSet<String>,
    source: &str,
    string_macros: &HashMap<String, String>,
    all_safe: &mut bool,
) {
    let Some(function) = node.child_by_field_name("function") else {
        return;
    };
    let name = get_node_text(&function, source);
    let ident = trailing_identifier(name);
    // strcat(var, X) or strcpy(var, X) — dest is var; check X.
    if !matches!(
        ident,
        "strcat" | "strcpy" | "strncat" | "strncpy" | "wcscat" | "wcscpy"
    ) {
        return;
    }
    let Some(args) = node.child_by_field_name("arguments") else {
        return;
    };
    let named: Vec<_> = (0..args.child_count())
        .filter_map(|i| args.child(i))
        .filter(|c| c.is_named())
        .collect();
    let Some(first) = named.first() else {
        return;
    };
    let first_stripped = strip_casts_and_parens(*first);
    if first_stripped.kind() == "identifier"
        && get_node_text(&first_stripped, source) == var
        && !str_append_source_is_safe(named.get(1), safe_sources, source, string_macros)
    {
        *all_safe = false;
    }
}

/// Whether the source operand of a strcat/strcpy is a compile-time-safe value: a
/// string literal, a known safe buffer, or a safe command macro.
fn str_append_source_is_safe(
    arg: Option<&Node>,
    safe_sources: &HashSet<String>,
    source: &str,
    string_macros: &HashMap<String, String>,
) -> bool {
    let Some(n) = arg else {
        return false;
    };
    let s = strip_casts_and_parens(*n);
    match s.kind() {
        "string_literal" | "concatenated_string" => true,
        // ALL_CAPS identifiers are compile-time macro constants
        // (e.g. Juliet CWE-426 GOOD_OS_COMMAND = "/usr/bin/ls").
        // Lowercase identifiers remain conservative.
        "identifier" => {
            let nm = get_node_text(&s, source);
            // A local safe buffer, or a macro that
            // expands to an absolute path or an argument
            // fragment (starts with space/dash — safe
            // to append). ALL-CAPS alone is not sufficient:
            // BAD_OS_COMMAND is also all-caps.
            safe_sources.contains(nm) || const_eval::is_safe_command_macro(string_macros, nm)
        }
        _ => false,
    }
}

fn rhs_is_safe(
    rhs: Option<&Node>,
    safe_sources: &HashSet<String>,
    source: &str,
    summaries: &HashMap<String, FunctionSummary>,
) -> bool {
    let Some(rhs) = rhs else {
        // No initializer — the declared pointer is null, technically safe
        // from a taint perspective (a later null-check would be ENV03-C
        // unrelated).
        return true;
    };
    let rhs = strip_casts_and_parens(*rhs);
    match rhs.kind() {
        "string_literal" | "concatenated_string" => true,
        "null" | "number_literal" => true,
        "identifier" => safe_sources.contains(get_node_text(&rhs, source)),
        // Taking the address of a local buffer: `&data_buf`.
        "pointer_expression" | "unary_expression" => {
            if let Some(arg) = rhs.child_by_field_name("argument") {
                let a = strip_casts_and_parens(arg);
                if a.kind() == "identifier" {
                    return safe_sources.contains(get_node_text(&a, source));
                }
            }
            false
        }
        // `data = helper(...)` — safe iff the helper has no taint-source
        // call and its return value is not transitively tainted. Suppresses
        // Juliet v42-style goodG2B(Source) wrappers without masking the
        // corresponding `data = badSource(...)` bad paths.
        "call_expression" => call_is_clean(&rhs, source, summaries),
        // `data = union_var.member` — safe if the union/struct aggregate was
        // itself populated only from safe sources. Only `.` access (local
        // aggregate), not `->` (pointer to potentially external data).
        // This suppresses Juliet v34 FPs where goodG2B writes a safe buffer
        // to one union member and reads it back through the other alias.
        "field_expression" => field_expr_dot_base(&rhs, source)
            .map(|base| safe_sources.contains(&base as &str))
            .unwrap_or(false),
        _ => false,
    }
}

/// Return true when `call`'s callee has a summary that proves it does not
/// introduce taint into the caller's variable. Requires both a direct
/// taint-source bit and the transitive `returns_tainted` bit to be false,
/// plus a known summary (unknown callees remain conservative).
fn call_is_clean(call: &Node, source: &str, summaries: &HashMap<String, FunctionSummary>) -> bool {
    let Some(func) = call.child_by_field_name("function") else {
        return false;
    };
    let raw = get_node_text(&func, source);
    let name = trailing_identifier(raw);
    match summaries.get(name) {
        Some(s) => !s.has_env03_taint_source && !s.returns_tainted && !s.has_relative_command_write,
        None => false,
    }
}

/// If `node` is a `field_expression` using the `.` (dot) operator, return the
/// base identifier name. Returns `None` for `->` access or when the base is
/// not a simple identifier (pointer arithmetic, nested field, etc.).
fn field_expr_dot_base(node: &Node, source: &str) -> Option<String> {
    // Distinguish `.` from `->` via the unnamed operator child.
    let mut is_dot = false;
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if !child.is_named() {
                match get_node_text(&child, source) {
                    "." => {
                        is_dot = true;
                        break;
                    }
                    "->" => break,
                    _ => {}
                }
            }
        }
    }
    if !is_dot {
        return None;
    }
    node.child_by_field_name("argument").and_then(|arg| {
        let base = strip_casts_and_parens(arg);
        if base.kind() == "identifier" {
            Some(get_node_text(&base, source).to_string())
        } else {
            None
        }
    })
}

fn node_operator<'a>(node: &'a Node<'a>, source: &'a str) -> Option<&'a str> {
    // Prefer the explicit field when available.
    if let Some(op) = node.child_by_field_name("operator") {
        return Some(get_node_text(&op, source));
    }
    // Otherwise find the unnamed operator token between LHS and RHS.
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if !child.is_named() {
                let text = get_node_text(&child, source);
                if text.contains('=') {
                    return Some(text);
                }
            }
        }
    }
    None
}

fn declarator_names(decl: &Node, source: &str) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(name) = extract_declarator_name(decl, source) {
        names.push(name);
    }
    names
}
