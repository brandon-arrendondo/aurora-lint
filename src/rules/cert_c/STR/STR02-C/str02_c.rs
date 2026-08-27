//! STR02-C: Sanitize data passed to complex subsystems
//!
//! This rule detects when string data is passed to complex subsystems (command
//! processors, databases, external programs) without proper sanitization, which
//! can lead to injection vulnerabilities.
//!
//! Resolves macro aliases (#define SYSTEM system) via project context.
//!
//! Uses intra-function taint tracking: only flags system()/popen() calls when
//! the argument is tainted by external input sources (recv, scanf, fgets, etc.).
//!
//! Also covers SQL injection (CWE-89, task 8/301): `sqlite3_exec`,
//! `mysql_query`, `mysql_real_query`, and `PQexec` build/execute a SQL
//! statement from a single string with no separate parameter binding, so
//! they are exactly the "complex subsystem" this rule's CERT text
//! describes -- the same shape as `system()`/`popen()`, just a different
//! interpreter. Deliberately excludes the parameterized-query APIs
//! (`sqlite3_prepare_v2` + `sqlite3_bind_*`, `PQexecParams`,
//! `mysql_stmt_prepare` + `mysql_stmt_bind_param`) since those don't build
//! a query by string concatenation at all -- there's nothing for this rule
//! to sanitize.
//!
//! `query_buffer_inputs_all_validated` recognizes one real-world defensive
//! shape found while validating this against hostap (task 8/301): a raw
//! tainted var explicitly checked against a project-local allow-list
//! function (`if (!valid_db_string(x)) return NULL;`) before being
//! `snprintf`'d into the query buffer, even though STR02-C has no way to
//! know that validator's name in advance.
//!
//! Parameters are tainted-by-default (external input), but
//! `collect_literal_only_static_params` (task 469) lifts that default for
//! a `static` function's parameter when every call site *in this same
//! file* passes a string literal at that position -- e.g. hostap's
//! `db_table_exists(sqlite3 *db, const char *name)`, reimplemented as a
//! `static` helper in 3 files and called only as `db_table_exists(db,
//! "pseudonyms")` / `db_table_exists(db, "reauth")`, no longer flags
//! `name`. Deliberately scoped to `static` functions and literal-only
//! observations rather than reusing prescan's project-wide
//! `callsite_param_tainted`/`callsite_param_taint_observed` bits (as
//! FIO30-C does): those bits call an argument "tainted" only when a
//! *recognized* taint source produced it, so a pointer parameter fed by a
//! deeper taint chain the narrow call-site scan can't see (e.g. hostap's
//! `db_update_milenage_sqn(struct milenage_parameters *m)`, where `m`
//! carries an EAP-AKA IMSI read over a socket several calls upstream)
//! would read as "observed, not tainted" and get wrongly suppressed --
//! confirmed by a full-hostap rerun during this task's validation, which
//! went from 3 residual findings to 0 under that broader signal. The
//! narrower literal-only signal has no such failure mode: a string literal
//! is unconditionally safe regardless of how deep the taint analysis goes.
//!
//! Two more FP shapes found adjudicating hostap's remaining findings
//! (task 470), both fixed:
//!
//! - `is_char_loop_validated_before` recognizes an inline char-allowlist
//!   validation loop (`for (i = 0; i < len; i++) { if (allowed) continue;
//!   return -1; }`) as a validator alongside `is_validated_before`'s
//!   call-shaped guard -- hostap's `eap_user_sqlite_get` validates its
//!   identity string exactly this way before building a query from it.
//! - `TAINT_OVERWRITE_PROPAGATORS` (the subset of `TAINT_PROPAGATORS`
//!   that overwrite dest from scratch, e.g. `snprintf`/`strcpy`, as
//!   opposed to append-style `strcat`) clears a variable's taint when one
//!   of these calls rewrites it from non-tainted sources -- hostap's
//!   `eap_user_db.c` reuses one `cmd` buffer for two queries in the same
//!   function; the second is a pure literal, but without this fix `cmd`
//!   stayed tainted from the first query's build for the rest of the
//!   function.
//!
//! ## Non-compliant example:
//!
//! ```c
//! char buffer[512];
//! sprintf(buffer, "/bin/mail %s < /tmp/email", addr);
//! system(buffer);  // User-controlled addr can inject commands
//! ```
//!
//! ```c
//! char query[256];
//! sprintf(query, "SELECT * FROM users WHERE name='%s'", username);
//! sqlite3_exec(db, query, 0, 0, &errmsg);  // User-controlled username can inject SQL
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! // Use execl() instead of system() to avoid shell interpretation
//! execl("/bin/mail", "mail", addr, (char *)NULL);
//! ```
//!
//! ```c
//! // Use a parameterized query instead of building SQL from a string
//! sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name=?", -1, &stmt, NULL);
//! sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg;
use crate::analyze::const_eval;
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{
    get_node_text, get_sanitized_node_text, is_function_parameter,
};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// Functions whose return values or output parameters introduce tainted data.
const TAINT_SOURCES: &[&str] = &[
    "recv", "recvfrom", "recvmsg", "read", "fread", "fgets", "fgetws", "gets", "scanf", "fscanf",
    "sscanf", "getenv", "getchar", "getwchar", "fgetc", "fgetwc", "getc", "getwc", "gets_s",
    "fgets_s", "wscanf", "fwscanf", "swscanf",
];

/// Functions that copy/concatenate taint: if any source arg is tainted,
/// the destination becomes tainted. (dest is typically first arg.)
const TAINT_PROPAGATORS: &[&str] = &[
    "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf", "memcpy", "memmove", "wcscpy",
    "wcsncpy", "wcscat", "wcsncat", "swprintf",
];

/// The subset of `TAINT_PROPAGATORS` that *overwrite* dest from scratch
/// (as opposed to `strcat`/`wcscat`-style append, which layers onto
/// dest's existing content and so can't launder prior taint). When one of
/// these calls has no tainted source arg, dest's taint from an earlier,
/// unrelated write is stale and gets cleared (task 470): hostap's
/// `eap_user_db.c` reuses one `cmd` buffer for two separate queries in the
/// same function -- the first `os_snprintf` pulls in a tainted `id_str`,
/// the second is a pure string literal with no substitutions -- and
/// without this, `cmd` reads as permanently tainted for the rest of the
/// function.
const TAINT_OVERWRITE_PROPAGATORS: &[&str] = &[
    "strcpy", "strncpy", "sprintf", "snprintf", "memcpy", "memmove", "wcscpy", "wcsncpy",
    "swprintf",
];

pub struct Str02C {
    project_aliases: RefCell<HashMap<String, String>>,
    current_aliases: RefCell<HashMap<String, String>>,
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    /// Reverse call graph: callee_name → set of caller names. Built from
    /// ProjectContext's forward `call_graph` in `set_project_context`.
    callers: RefCell<HashMap<String, HashSet<String>>>,
    /// Per-file (task 469): `static` function name → parameter indices
    /// where every in-file call site passed a string literal. Recomputed
    /// at the start of every `check()` call by
    /// `collect_literal_only_static_params`.
    literal_only_params: RefCell<HashMap<String, HashSet<usize>>>,
}

impl Str02C {
    pub fn new() -> Self {
        Self {
            project_aliases: RefCell::new(HashMap::new()),
            current_aliases: RefCell::new(HashMap::new()),
            function_summaries: RefCell::new(HashMap::new()),
            callers: RefCell::new(HashMap::new()),
            literal_only_params: RefCell::new(HashMap::new()),
        }
    }

    /// Resolve a function name through macro aliases.
    fn resolve_name(&self, name: &str) -> String {
        let aliases = self.current_aliases.borrow();
        if let Some(target) = aliases.get(name) {
            target.clone()
        } else {
            name.to_string()
        }
    }

    /// Walk all nodes: for function bodies use taint tracking,
    /// for bare code (no function) fall back to non-literal detection.
    ///
    /// Uses an explicit stack instead of recursion. The prune at
    /// `function_definition` keeps this shallow in practice (bounded by
    /// non-function nesting at translation-unit scope, which is rarely deep
    /// in real C), but it's still an unbounded native recursion in
    /// principle -- the same risk class as the original ARR00-C/MEM33-C bug
    /// (task 153) -- so it gets the same treatment for consistency.
    fn check_functions(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut stack = vec![*root];
        while let Some(node) = stack.pop() {
            if node.kind() == "function_definition" {
                self.check_single_function(&node, source, violations);
                continue;
            }
            // Bare code at translation_unit level: use non-literal fallback
            if node.kind() == "call_expression" && self.find_containing_function(&node).is_none() {
                self.check_dangerous_function_call_legacy(&node, source, violations);
            }
            for i in (0..node.child_count()).rev() {
                if let Some(child) = node.child(i) {
                    stack.push(child);
                }
            }
        }
    }

    /// Find the containing function_definition for a node, if any.
    fn find_containing_function<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition" {
                return Some(parent);
            }
            current = parent;
        }
        None
    }

    /// Analyze a single function: collect tainted variables, then check sinks.
    fn check_single_function(
        &self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let mut tainted: HashSet<String> = HashSet::new();

        // Function parameters are tainted by default (external input)
        self.collect_param_names(func_node, source, &mut tainted);

        // Collect tainted variables from the function body
        self.collect_tainted_vars(func_node, source, &mut tainted);

        // Check sinks (system/popen/exec) for tainted arguments
        self.check_sinks(func_node, source, &tainted, func_node, violations);
    }

    /// Extract parameter names from a function definition and mark them as
    /// tainted -- unless every call site to this (necessarily `static`)
    /// function within this same file passes a string literal at that
    /// parameter position (e.g. hostap's `db_table_exists(db, name)`,
    /// always called with a literal table name; task 469). Looked up from
    /// `literal_only_params`, populated per-file by
    /// `collect_literal_only_static_params`.
    fn collect_param_names(&self, func_node: &Node, source: &str, tainted: &mut HashSet<String>) {
        let literal_only = cfg::get_function_name(func_node, source)
            .and_then(|name| self.literal_only_params.borrow().get(name).cloned());
        if let Some(declarator) = func_node.child_by_field_name("declarator") {
            self.find_param_names(&declarator, source, tainted, literal_only.as_ref());
        }
    }

    fn find_param_names(
        &self,
        node: &Node,
        source: &str,
        tainted: &mut HashSet<String>,
        literal_only: Option<&HashSet<usize>>,
    ) {
        for (idx, node) in query::find_descendants_of_kind(*node, "parameter_declaration")
            .into_iter()
            .enumerate()
        {
            // Get the declarator child which has the parameter name
            if let Some(decl) = node.child_by_field_name("declarator") {
                let name = get_node_text(&decl, source);
                let base = extract_base_var(&name);
                if base.is_empty() {
                    continue;
                }
                if literal_only.is_some_and(|idxs| idxs.contains(&idx)) {
                    continue;
                }
                tainted.insert(base);
            }
        }
    }

    /// For each `static` function defined in this file, the set of
    /// parameter indices where every call site in this file passes a
    /// string literal argument at that position. Restricted to `static`
    /// functions specifically: that's the only case where "every call site
    /// visible in this file" is the same as "every call site, period" -- a
    /// non-static function could have external callers this file can't
    /// see, so its parameters must stay conservatively tainted-by-default.
    fn collect_literal_only_static_params(
        &self,
        root: &Node,
        source: &str,
    ) -> HashMap<String, HashSet<usize>> {
        let mut static_fns: HashSet<String> = HashSet::new();
        for func in query::find_descendants_of_kind(*root, "function_definition") {
            if Self::is_static_function(&func, source) {
                if let Some(name) = cfg::get_function_name(&func, source) {
                    static_fns.insert(name.to_string());
                }
            }
        }
        if static_fns.is_empty() {
            return HashMap::new();
        }

        let mut call_sites: HashMap<String, Vec<Vec<bool>>> = HashMap::new();
        for call in query::find_descendants_of_kind(*root, "call_expression") {
            let Some(function_node) = call.child_by_field_name("function") else {
                continue;
            };
            if function_node.kind() != "identifier" {
                continue;
            }
            let name = get_node_text(&function_node, source);
            let resolved = self.resolve_name(&name);
            if !static_fns.contains(&resolved) {
                continue;
            }
            let Some(args_node) = call.child_by_field_name("arguments") else {
                continue;
            };
            let arg_literal: Vec<bool> = self
                .collect_argument_nodes(&args_node)
                .iter()
                .map(|a| self.is_string_literal(a))
                .collect();
            call_sites.entry(resolved).or_default().push(arg_literal);
        }

        let mut result: HashMap<String, HashSet<usize>> = HashMap::new();
        for (name, sites) in call_sites {
            let max_params = sites.iter().map(|v| v.len()).max().unwrap_or(0);
            let mut literal_idxs = HashSet::new();
            for idx in 0..max_params {
                let mut any_site = false;
                let mut all_literal = true;
                for site in &sites {
                    match site.get(idx) {
                        Some(true) => any_site = true,
                        Some(false) => {
                            any_site = true;
                            all_literal = false;
                        }
                        None => {}
                    }
                }
                if any_site && all_literal {
                    literal_idxs.insert(idx);
                }
            }
            if !literal_idxs.is_empty() {
                result.insert(name, literal_idxs);
            }
        }
        result
    }

    /// True if a `function_definition` node carries the `static`
    /// storage-class specifier.
    fn is_static_function(func: &Node, source: &str) -> bool {
        (0..func.child_count()).any(|i| {
            func.child(i).is_some_and(|c| {
                c.kind() == "storage_class_specifier" && get_node_text(&c, source) == "static"
            })
        })
    }

    /// Walk a function body to find variables tainted by external input.
    fn collect_tainted_vars(&self, node: &Node, source: &str, tainted: &mut HashSet<String>) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_taint_from_call(&n, source, tainted);
        }
    }

    /// Check if a call expression introduces taint into a variable.
    fn check_taint_from_call(&self, call_node: &Node, source: &str, tainted: &mut HashSet<String>) {
        let func_name = match call_node.child_by_field_name("function") {
            Some(f) => {
                let name = get_node_text(&f, source);
                self.resolve_name(&name)
            }
            None => return,
        };

        let args_node = match call_node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        let args = self.collect_arguments(&args_node, source);

        // Direct taint sources: the function returns or writes tainted data
        if TAINT_SOURCES.contains(&func_name.as_str()) {
            match func_name.as_str() {
                // recv(sock, buf, ...) — buf (arg 1) is tainted
                "recv" | "recvfrom" | "recvmsg" | "read" | "fread" => {
                    if let Some(buf_name) = args.get(1) {
                        tainted.insert(extract_base_var(buf_name));
                    }
                }
                // fgets(buf, size, stream) — buf (arg 0) is tainted
                "fgets" | "fgetws" | "fgets_s" | "gets" | "gets_s" => {
                    if let Some(buf_name) = args.first() {
                        tainted.insert(extract_base_var(buf_name));
                    }
                }
                // scanf("%s", &var) — all args after format are tainted
                "scanf" | "fscanf" | "sscanf" | "wscanf" | "fwscanf" | "swscanf" => {
                    for arg in args.iter().skip(1) {
                        tainted.insert(extract_base_var(arg));
                    }
                }
                // getenv() — return value is tainted (check assignment)
                "getenv" => {
                    self.taint_assignment_target(call_node, source, tainted);
                }
                _ => {
                    // Generic: taint the assignment target if any
                    self.taint_assignment_target(call_node, source, tainted);
                }
            }
        }

        // Taint propagation: strcpy(dest, src) — if src is tainted, dest becomes tainted
        if TAINT_PROPAGATORS.contains(&func_name.as_str()) {
            let has_tainted_source = args.iter().skip(1).any(|arg| {
                let base = extract_base_var(arg);
                tainted.contains(&base)
            });
            if let Some(dest) = args.first() {
                let dest_base = extract_base_var(dest);
                if has_tainted_source {
                    tainted.insert(dest_base);
                } else if TAINT_OVERWRITE_PROPAGATORS.contains(&func_name.as_str()) {
                    // Clean overwrite: whatever taint `dest_base` carried
                    // from an earlier, unrelated write no longer applies.
                    tainted.remove(&dest_base);
                }
            }
        }
    }

    /// If a call is used in an assignment (e.g., `data = getenv("HOME")`),
    /// taint the assigned variable.
    fn taint_assignment_target(
        &self,
        call_node: &Node,
        source: &str,
        tainted: &mut HashSet<String>,
    ) {
        if let Some(parent) = call_node.parent() {
            match parent.kind() {
                "assignment_expression" => {
                    if let Some(left) = parent.child_by_field_name("left") {
                        tainted.insert(extract_base_var(&get_node_text(&left, source)));
                    }
                }
                "init_declarator" => {
                    if let Some(decl) = parent.child_by_field_name("declarator") {
                        tainted.insert(extract_base_var(&get_node_text(&decl, source)));
                    }
                }
                _ => {}
            }
        }
    }

    /// Collect argument text strings from an argument_list node.
    fn collect_arguments(&self, args_node: &Node, source: &str) -> Vec<String> {
        let mut args = Vec::new();
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    args.push(get_node_text(&child, source).to_string());
                }
            }
        }
        args
    }

    /// Check system()/popen()/exec*() calls for tainted arguments.
    fn check_sinks(
        &self,
        node: &Node,
        source: &str,
        tainted: &HashSet<String>,
        func_scope: &Node,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_dangerous_function_call(&n, source, tainted, func_scope, violations);
        }
    }

    /// Check for calls to dangerous functions with potentially unsanitized arguments
    fn check_dangerous_function_call(
        &self,
        node: &Node,
        source: &str,
        tainted: &HashSet<String>,
        func_scope: &Node,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "call_expression" {
            return;
        }

        if let Some(function_node) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function_node, source);
            let resolved = self.resolve_name(&func_name);

            match resolved.as_str() {
                "system" | "popen" => {
                    self.check_command_injection_risk(
                        node, source, &func_name, &resolved, tainted, func_scope, violations,
                    );
                }
                "sqlite3_exec" | "mysql_query" | "mysql_real_query" | "PQexec" => {
                    let arg_index = 1; // query is the 2nd argument for all four
                    self.check_sql_injection_risk(
                        node, source, &func_name, &resolved, arg_index, tainted, func_scope,
                        violations,
                    );
                }
                "execl" | "execle" | "execlp" | "execv" | "execvp" | "execve" | "_execl"
                | "_execle" | "_execlp" | "_execv" | "_execvp" | "_execve" => {
                    self.check_exec_family_call(node, source, &func_name, &resolved, violations);
                }
                _ => {}
            }
        }
    }

    /// Check sqlite3_exec()/mysql_query()/mysql_real_query()/PQexec() calls
    /// for SQL injection risk (CWE-89). Only flags when the query argument
    /// (at `arg_index`) is tainted by external input -- mirrors
    /// `check_command_injection_risk` exactly, including the cross-function
    /// suppression, since these are the same "tainted string reaches a
    /// complex-subsystem interpreter" shape STR02-C already models for
    /// system()/popen().
    fn check_sql_injection_risk(
        &self,
        node: &Node,
        source: &str,
        display_name: &str,
        resolved_name: &str,
        arg_index: usize,
        tainted: &HashSet<String>,
        func_scope: &Node,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(args_node) = node.child_by_field_name("arguments") else {
            return;
        };
        let args = self.collect_argument_nodes(&args_node);
        let Some(&query_arg) = args.get(arg_index) else {
            return;
        };

        // String literals are always safe
        if self.is_string_literal(&query_arg) {
            return;
        }

        let arg_text = get_node_text(&query_arg, source);
        let base_var = extract_base_var(&arg_text);

        // Only flag if the argument is tainted by external input
        if !tainted.contains(&base_var) {
            return;
        }

        // Cross-function suppression (Juliet helper-sink pattern): see
        // check_command_injection_risk's identical comment.
        if is_function_parameter(func_scope, &base_var, source)
            && !self.scope_has_taint_source(func_scope, source)
            && self.callers_are_all_clean(func_scope, source)
        {
            return;
        }

        // Intra-function allow-list validation guard: the query variable
        // (`cmd`, `zSql`, ...) is usually a local buffer built by a
        // sprintf/snprintf-family call from the actually-tainted source
        // vars, not the raw tainted var itself. Real-world code (found on
        // hostap's src/eap_server/eap_sim_db.c during task 8) commonly
        // validates those SOURCE vars against a character allow-list
        // (`if (!valid_db_string(pseudonym)) return NULL;`) before the
        // snprintf that builds the query -- an unnamed, project-local
        // sanitizer STR02-C has no way to recognize by function name, but
        // CAN recognize by shape: an `if` whose condition calls a function
        // with the source var as an argument, guarding an early exit,
        // textually before this sink. If every var that fed the query
        // buffer was guarded this way, this is exactly CERT's own
        // "understand the data and validate it" compliant pattern, not a
        // defect.
        if self.query_buffer_inputs_all_validated(func_scope, source, &base_var, node.start_byte())
        {
            return;
        }

        let label = if display_name != resolved_name {
            format!("{} (macro for {})", display_name, resolved_name)
        } else {
            resolved_name.to_string()
        };

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "Call to {}() with tainted query argument '{}'. Data from external input sources must be sanitized (or passed via a parameterized query) before being used to build a SQL statement.",
                label, arg_text.trim()
            ),
            file_path: String::new(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
            suggestion: Some(format!(
                "Use a parameterized query (sqlite3_prepare_v2+sqlite3_bind_*, PQexecParams, or mysql_stmt_prepare+mysql_stmt_bind_param) instead of building the SQL statement passed to {}() from unsanitized input.",
                resolved_name
            )),
            ..Default::default()
        });
    }

    /// True iff every raw variable that fed `dest_var` (the query buffer)
    /// through the most recent preceding sprintf/snprintf-family call was
    /// guarded by an earlier `if (<call using that var>) { ...early exit... }`
    /// in `func_scope`. Conservative: any propagator call not found, or any
    /// contributing var not validated, returns false (still flagged).
    fn query_buffer_inputs_all_validated(
        &self,
        func_scope: &Node,
        source: &str,
        dest_var: &str,
        before_byte: usize,
    ) -> bool {
        let Some(propagator) =
            self.find_last_propagator_call(func_scope, source, dest_var, before_byte)
        else {
            return false;
        };
        let Some(args_node) = propagator.child_by_field_name("arguments") else {
            return false;
        };
        let args = self.collect_arguments(&args_node, source);
        // Skip the destination (arg 0) and format string (arg 1); check
        // every remaining substituted value.
        let contributors: Vec<String> = args
            .iter()
            .skip(2)
            .map(|a| extract_base_var(a))
            .filter(|v| !v.is_empty())
            .collect();
        if contributors.is_empty() {
            return false;
        }
        contributors.iter().all(|var| {
            self.is_validated_before(func_scope, source, var, before_byte)
                || self.is_char_loop_validated_before(func_scope, source, var, before_byte)
        })
    }

    /// Find the last call to a `TAINT_PROPAGATORS` function (after macro
    /// alias resolution) before `before_byte` whose first argument's base
    /// variable is `dest_var` -- i.e. the call that most recently built
    /// `dest_var` from other values.
    fn find_last_propagator_call<'a>(
        &self,
        func_scope: &Node<'a>,
        source: &str,
        dest_var: &str,
        before_byte: usize,
    ) -> Option<Node<'a>> {
        let mut best: Option<Node<'a>> = None;
        for call in query::find_descendants_of_kind(*func_scope, "call_expression") {
            if call.start_byte() >= before_byte {
                continue;
            }
            let Some(function_node) = call.child_by_field_name("function") else {
                continue;
            };
            let name = get_node_text(&function_node, source);
            let resolved = self.resolve_name(&name);
            if !TAINT_PROPAGATORS.contains(&resolved.as_str()) {
                continue;
            }
            let Some(args_node) = call.child_by_field_name("arguments") else {
                continue;
            };
            let args = self.collect_arguments(&args_node, source);
            let Some(dest_arg) = args.first() else {
                continue;
            };
            if extract_base_var(dest_arg) != dest_var {
                continue;
            }
            if best.is_none_or(|b: Node<'a>| call.start_byte() > b.start_byte()) {
                best = Some(call);
            }
        }
        best
    }

    /// True iff `func_scope` contains an `if` statement, before
    /// `before_byte`, whose condition calls a function with `var` as an
    /// argument, and whose guarded branch contains an early exit
    /// (`return`/`goto`) -- the "validate or bail out" shape.
    fn is_validated_before(
        &self,
        func_scope: &Node,
        source: &str,
        var: &str,
        before_byte: usize,
    ) -> bool {
        for if_stmt in query::find_descendants_of_kind(*func_scope, "if_statement") {
            if if_stmt.start_byte() >= before_byte {
                continue;
            }
            let Some(condition) = if_stmt.child_by_field_name("condition") else {
                continue;
            };
            if !self.condition_calls_with_arg(&condition, source, var) {
                continue;
            }
            let Some(consequence) = if_stmt.child_by_field_name("consequence") else {
                continue;
            };
            let has_early_exit = query::find_first_descendant(consequence, |n| {
                matches!(n.kind(), "return_statement" | "goto_statement")
            })
            .is_some();
            if has_early_exit {
                return true;
            }
        }
        false
    }

    /// True iff any `call_expression` within `condition` has `var` as one
    /// of its arguments' base variable.
    fn condition_calls_with_arg(&self, condition: &Node, source: &str, var: &str) -> bool {
        for call in query::find_descendants_of_kind(*condition, "call_expression") {
            let Some(args_node) = call.child_by_field_name("arguments") else {
                continue;
            };
            let args = self.collect_arguments(&args_node, source);
            if args.iter().any(|a| extract_base_var(a) == var) {
                return true;
            }
        }
        false
    }

    /// True iff `func_scope` contains a `for`/`while` loop, before
    /// `before_byte`, that subscripts `var` by character (`var[i]`) and
    /// denies by default: the loop body's *last* statement is an
    /// unconditional early exit (`return`/`goto`), reached only when none
    /// of the preceding per-character checks decided otherwise (typically
    /// via `continue`). This is the inline char-allowlist validation
    /// shape found on hostap's `eap_user_sqlite_get` (task 470) --
    /// CERT's own "validate then use" pattern, just spelled as a loop
    /// instead of the single guard call `is_validated_before` recognizes.
    fn is_char_loop_validated_before(
        &self,
        func_scope: &Node,
        source: &str,
        var: &str,
        before_byte: usize,
    ) -> bool {
        for loop_stmt in
            query::find_descendants_of_kinds(*func_scope, &["for_statement", "while_statement"])
        {
            if loop_stmt.start_byte() >= before_byte {
                continue;
            }
            if !Self::loop_subscripts_var(&loop_stmt, source, var) {
                continue;
            }
            let Some(body) = loop_stmt.child_by_field_name("body") else {
                continue;
            };
            if body.kind() != "compound_statement" {
                continue;
            }
            let Some(last) = (0..body.child_count())
                .filter_map(|i| body.child(i))
                .rfind(|c| !matches!(c.kind(), "{" | "}"))
            else {
                continue;
            };
            if matches!(last.kind(), "return_statement" | "goto_statement") {
                return true;
            }
        }
        false
    }

    /// True iff a `subscript_expression` with base `var` (e.g. `var[i]`)
    /// appears anywhere within `loop_stmt`.
    fn loop_subscripts_var(loop_stmt: &Node, source: &str, var: &str) -> bool {
        query::find_descendants_of_kind(*loop_stmt, "subscript_expression")
            .iter()
            .any(|sub| {
                sub.child_by_field_name("argument")
                    .is_some_and(|base| get_node_text(&base, source) == var)
            })
    }

    /// Check system() and popen() calls for command injection risk.
    /// Only flags when the argument is tainted by external input.
    fn check_command_injection_risk(
        &self,
        node: &Node,
        source: &str,
        display_name: &str,
        resolved_name: &str,
        tainted: &HashSet<String>,
        func_scope: &Node,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(args_node) = node.child_by_field_name("arguments") {
            if let Some(first_arg) = self.get_first_argument(&args_node) {
                // String literals are always safe
                if self.is_string_literal(&first_arg) {
                    return;
                }

                let arg_text = get_node_text(&first_arg, source);
                let base_var = extract_base_var(&arg_text);

                // Only flag if the argument is tainted by external input
                if !tainted.contains(&base_var) {
                    return;
                }

                // Cross-function suppression (Juliet helper-sink pattern):
                // when the tainted arg is this function's parameter AND the
                // function body itself has no direct taint-source call, the
                // only taint path is through the caller. If every transitive
                // caller's prescan summary is clean (no taint source, no
                // returns_tainted), suppress.
                if is_function_parameter(func_scope, &base_var, source)
                    && !self.scope_has_taint_source(func_scope, source)
                    && self.callers_are_all_clean(func_scope, source)
                {
                    return;
                }

                let label = if display_name != resolved_name {
                    format!("{} (macro for {})", display_name, resolved_name)
                } else {
                    resolved_name.to_string()
                };

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Call to {}() with tainted argument '{}'. Data from external input sources must be sanitized before passing to command processors.",
                        label, arg_text.trim()
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(
                        format!(
                            "Sanitize the string argument before passing to {}() by whitelisting acceptable characters, or use exec*() functions instead of system() to avoid shell interpretation.",
                            resolved_name
                        )
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// Legacy check for bare code (no function context): flag any non-literal
    /// argument to system()/popen(). Used when taint tracking isn't possible.
    fn check_dangerous_function_call_legacy(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "call_expression" {
            return;
        }
        if let Some(function_node) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function_node, source);
            let resolved = self.resolve_name(&func_name);

            match resolved.as_str() {
                "system" | "popen" => {
                    if let Some(args_node) = node.child_by_field_name("arguments") {
                        if let Some(first_arg) = self.get_first_argument(&args_node) {
                            if !self.is_string_literal(&first_arg) {
                                let arg_text = get_node_text(&first_arg, source);
                                let label = if func_name != resolved {
                                    format!("{} (macro for {})", func_name, resolved)
                                } else {
                                    resolved.to_string()
                                };
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    message: format!(
                                        "Call to {}() with non-literal argument '{}' detected. This may allow command injection if the string contains unsanitized user input or environment variables.",
                                        label, arg_text.trim()
                                    ),
                                    file_path: String::new(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    suggestion: Some(format!(
                                        "Sanitize the string argument before passing to {}() by whitelisting acceptable characters, or use exec*() functions instead of system() to avoid shell interpretation.",
                                        resolved
                                    )),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
                "sqlite3_exec" | "mysql_query" | "mysql_real_query" | "PQexec" => {
                    if let Some(args_node) = node.child_by_field_name("arguments") {
                        let args = self.collect_argument_nodes(&args_node);
                        if let Some(&query_arg) = args.get(1) {
                            if !self.is_string_literal(&query_arg) {
                                let arg_text = get_node_text(&query_arg, source);
                                let label = if func_name != resolved {
                                    format!("{} (macro for {})", func_name, resolved)
                                } else {
                                    resolved.to_string()
                                };
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    message: format!(
                                        "Call to {}() with non-literal query argument '{}' detected. This may allow SQL injection if the string contains unsanitized user input.",
                                        label, arg_text.trim()
                                    ),
                                    file_path: String::new(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    suggestion: Some(format!(
                                        "Use a parameterized query (sqlite3_prepare_v2+sqlite3_bind_*, PQexecParams, or mysql_stmt_prepare+mysql_stmt_bind_param) instead of building the SQL statement passed to {}() from unsanitized input.",
                                        resolved
                                    )),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
                "execl" | "execle" | "execlp" | "execv" | "execvp" | "execve" | "_execl"
                | "_execle" | "_execlp" | "_execv" | "_execvp" | "_execve" => {
                    self.check_exec_family_call(node, source, &func_name, &resolved, violations);
                }
                _ => {}
            }
        }
    }

    /// Check exec*() family calls for command injection risk
    /// exec*() is generally safer than system() because it doesn't invoke the shell
    /// We only flag exec*() when user data is passed in arguments without proper protection
    fn check_exec_family_call(
        &self,
        node: &Node,
        source: &str,
        display_name: &str,
        resolved_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(args_node) = node.child_by_field_name("arguments") {
            // For exec*() functions, we look for getenv() calls in arguments
            // which indicate potentially unsanitized user/environment data
            let args_text = get_node_text(&args_node, source);

            // Check if getenv() is used in arguments without protection
            // getenv returns environment variables which may be user-controlled
            if args_text.contains("getenv(") {
                // Check if "--" appears BEFORE getenv() in the arguments
                // The "--" argument signals "end of options" to prevent option injection
                if let Some(getenv_pos) = args_text.find("getenv(") {
                    let before_getenv = &args_text[..getenv_pos];
                    // If "--" appears before getenv, the user data cannot be interpreted
                    // as command-line options, which is the proper protection
                    if before_getenv.contains("\"--\"") {
                        return; // Properly protected with end-of-options marker
                    }
                }

                // Check if there's any indication of sanitization in the containing scope
                let scope = self.find_containing_scope(node);
                if let Some(scope) = scope {
                    // Sanitized so a comment/string literal in the scope
                    // can't spoof a sanitization pattern and silently
                    // suppress a genuine command-injection violation.
                    let scope_text = get_sanitized_node_text(&scope, source);
                    // If strspn or similar sanitization is present, it's likely safe
                    if scope_text.contains("strspn(")
                        || scope_text.contains("strcspn(")
                        || scope_text.contains("ok_chars")
                    {
                        return; // Likely sanitized
                    }
                }

                let label = if display_name != resolved_name {
                    format!("{} (macro for {})", display_name, resolved_name)
                } else {
                    resolved_name.to_string()
                };

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Medium,
                    message: format!(
                        "Call to {}() with getenv() in arguments without '--' end-of-options marker. Environment variables may contain values that could be interpreted as command options.",
                        label
                    ),
                    file_path: String::new(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    suggestion: Some(
                        "Add '--' argument before user-controlled data to prevent option injection, or sanitize the data before passing to exec*() functions."
                            .to_string(),
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// Find the containing function or scope for a node
    fn find_containing_scope<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition"
                || parent.kind() == "compound_statement"
                || parent.kind() == "translation_unit"
            {
                return Some(parent);
            }
            current = parent;
        }
        None
    }

    /// Collect the argument nodes (in order) from an argument list node.
    fn collect_argument_nodes<'a>(&self, args_node: &Node<'a>) -> Vec<Node<'a>> {
        let mut args = Vec::new();
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    args.push(child);
                }
            }
        }
        args
    }

    /// Get the first argument from an argument list node
    fn get_first_argument<'a>(&self, args_node: &Node<'a>) -> Option<Node<'a>> {
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                // Skip '(' and ')' and ',' tokens
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Check if a node represents a string literal
    fn is_string_literal(&self, node: &Node) -> bool {
        node.kind() == "string_literal" || node.kind() == "concatenated_string"
    }

    /// True if any call_expression under `scope` targets a known taint source.
    /// Resolves macro aliases before matching.
    fn scope_has_taint_source(&self, scope: &Node, source: &str) -> bool {
        query::find_first_descendant(*scope, |node| {
            if node.kind() != "call_expression" {
                return false;
            }
            let Some(function) = node.child_by_field_name("function") else {
                return false;
            };
            let raw = get_node_text(&function, source);
            let ident = trailing_identifier(raw);
            let resolved = self.resolve_name(ident);
            TAINT_SOURCES.contains(&resolved.as_str()) || TAINT_SOURCES.contains(&ident)
        })
        .is_some()
    }

    /// BFS over the reverse call graph: returns true when every transitive
    /// caller of `scope`'s function has a prescan summary showing no direct
    /// taint source and no transitively-tainted return value. Returns false
    /// when caller info is missing at any level or any caller is tainted.
    ///
    /// Multi-level walk matches Juliet's variants 52/53/54 where data is
    /// forwarded through several clean pass-through sinks before reaching
    /// the actual bad source.
    fn callers_are_all_clean(&self, scope: &Node, source: &str) -> bool {
        let Some(name) = cfg::get_function_name(scope, source) else {
            return false;
        };
        let callers = self.callers.borrow();
        let Some(root_callers) = callers.get(name) else {
            return false;
        };
        if root_callers.is_empty() {
            return false;
        }

        let summaries = self.function_summaries.borrow();
        let mut visited: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = root_callers.iter().cloned().collect();

        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            match summaries.get(&current) {
                Some(s) if !s.has_env03_taint_source && !s.returns_tainted => {}
                _ => return false,
            }
            if let Some(next) = callers.get(&current) {
                for c in next {
                    if !visited.contains(c) {
                        stack.push(c.clone());
                    }
                }
            }
        }
        true
    }
}

/// Take the trailing identifier token from a possibly-qualified name
/// (e.g. `obj->bar`, `POPEN`). Keeps alnum + underscores.
fn trailing_identifier(name: &str) -> &str {
    name.rsplit(|c: char| !c.is_alphanumeric() && c != '_')
        .next()
        .unwrap_or(name)
}

/// Extract the base variable name from an expression.
/// "data" → "data", "&data" → "data", "data + offset" → "data",
/// "data_buf" → "data_buf", "*ptr" → "ptr",
/// "(char *)(data + dataLen)" → "data"
fn extract_base_var(expr: &str) -> String {
    let s = expr.trim();
    // Strip leading & or *
    let s = s.strip_prefix('&').unwrap_or(s);
    let s = s.strip_prefix('*').unwrap_or(s);
    let s = s.trim();

    // Handle cast expressions: (type)(expr) or (type)expr
    // Skip past (type) prefix(es), then extract from the remaining expression
    let s = strip_casts(s);

    // Take up to first non-identifier character
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// Strip C cast prefixes like "(char *)", "(int)", etc.
/// Returns the remaining expression after all leading casts are removed.
fn strip_casts(s: &str) -> &str {
    let mut s = s;
    loop {
        let trimmed = s.trim();
        if !trimmed.starts_with('(') {
            return trimmed;
        }
        // Find matching close paren
        if let Some(close) = trimmed.find(')') {
            let inside = &trimmed[1..close];
            // If content looks like a type cast (contains * or is a known type keyword),
            // strip it and continue
            if inside.contains('*')
                || matches!(
                    inside.trim(),
                    "char"
                        | "int"
                        | "long"
                        | "short"
                        | "unsigned"
                        | "signed"
                        | "void"
                        | "size_t"
                        | "ssize_t"
                        | "uint8_t"
                        | "int8_t"
                )
            {
                s = &trimmed[close + 1..];
                continue;
            }
            // Otherwise it's a parenthesized expression like (data + len)
            // — extract from inside
            return inside;
        }
        return trimmed;
    }
}

impl CertRule for Str02C {
    fn rule_id(&self) -> &'static str {
        "STR02-C"
    }

    fn description(&self) -> &'static str {
        "Sanitize data passed to complex subsystems"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "STR02-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project_aliases.borrow_mut() = context.macro_aliases.clone();
        *self.function_summaries.borrow_mut() = context.function_summaries.clone();

        // Invert the forward call_graph (caller → callees) into a reverse
        // map (callee → callers) for fast caller lookup.
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
        // Merge project-level aliases with per-file aliases (per-file wins)
        *self.current_aliases.borrow_mut() =
            const_eval::merged_macro_aliases(&self.project_aliases.borrow(), node, source);
        *self.literal_only_params.borrow_mut() =
            self.collect_literal_only_static_params(node, source);

        let mut violations = Vec::new();
        self.check_functions(node, source, &mut violations);
        violations
    }
}
