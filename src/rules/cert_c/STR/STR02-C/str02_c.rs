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
//! ## Non-compliant example:
//!
//! ```c
//! char buffer[512];
//! sprintf(buffer, "/bin/mail %s < /tmp/email", addr);
//! system(buffer);  // User-controlled addr can inject commands
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! // Use execl() instead of system() to avoid shell interpretation
//! execl("/bin/mail", "mail", addr, (char *)NULL);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg;
use crate::analyze::const_eval;
use crate::analyze::context::ProjectContext;
use crate::analyze::function_summary::FunctionSummary;
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{get_node_text, is_function_parameter};
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

pub struct Str02C {
    project_aliases: RefCell<HashMap<String, String>>,
    current_aliases: RefCell<HashMap<String, String>>,
    function_summaries: RefCell<HashMap<String, FunctionSummary>>,
    /// Reverse call graph: callee_name → set of caller names. Built from
    /// ProjectContext's forward `call_graph` in `set_project_context`.
    callers: RefCell<HashMap<String, HashSet<String>>>,
}

impl Str02C {
    pub fn new() -> Self {
        Self {
            project_aliases: RefCell::new(HashMap::new()),
            current_aliases: RefCell::new(HashMap::new()),
            function_summaries: RefCell::new(HashMap::new()),
            callers: RefCell::new(HashMap::new()),
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

    /// Extract parameter names from a function definition and mark them as tainted.
    fn collect_param_names(&self, func_node: &Node, source: &str, tainted: &mut HashSet<String>) {
        if let Some(declarator) = func_node.child_by_field_name("declarator") {
            self.find_param_names(&declarator, source, tainted);
        }
    }

    fn find_param_names(&self, node: &Node, source: &str, tainted: &mut HashSet<String>) {
        for node in query::find_descendants_of_kind(*node, "parameter_declaration") {
            // Get the declarator child which has the parameter name
            if let Some(decl) = node.child_by_field_name("declarator") {
                let name = get_node_text(&decl, source);
                let base = extract_base_var(&name);
                if !base.is_empty() {
                    tainted.insert(base);
                }
            }
        }
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
            if has_tainted_source {
                if let Some(dest) = args.first() {
                    tainted.insert(extract_base_var(dest));
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
                "execl" | "execle" | "execlp" | "execv" | "execvp" | "execve" | "_execl"
                | "_execle" | "_execlp" | "_execv" | "_execvp" | "_execve" => {
                    self.check_exec_family_call(node, source, &func_name, &resolved, violations);
                }
                _ => {}
            }
        }
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
                    let scope_text = get_node_text(&scope, source);
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
        // Merge project-level aliases with per-file aliases
        let mut aliases = self.project_aliases.borrow().clone();
        aliases.extend(const_eval::collect_macro_aliases(node, source));
        *self.current_aliases.borrow_mut() = aliases;

        let mut violations = Vec::new();
        self.check_functions(node, source, &mut violations);
        violations
    }
}
