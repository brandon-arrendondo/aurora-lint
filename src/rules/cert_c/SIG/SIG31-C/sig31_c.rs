//! SIG31-C: Do not access shared objects in signal handlers
//!
//! Accessing shared objects (global/static variables) in signal handlers causes
//! race conditions and undefined behavior. Only `volatile sig_atomic_t` variables
//! may be safely accessed.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int global_counter = 0;  // Shared, not sig_atomic_t
//! void handler(int sig) {
//!     global_counter++;    // VIOLATION: accessing shared int
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! volatile sig_atomic_t flag = 0;
//! void handler(int sig) {
//!     flag = 1;  // OK: volatile sig_atomic_t
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Sig31C;

impl CertRule for Sig31C {
    fn rule_id(&self) -> &'static str {
        "SIG31-C"
    }

    fn description(&self) -> &'static str {
        "Do not access shared objects in signal handlers"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "SIG31-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Find all signal handler functions
        let handler_names = self.find_signal_handlers(node, source);

        // Find all global/static variables and their types
        let global_vars = self.find_global_variables(node, source);

        // Check each handler for shared object access
        self.check_node(node, source, &handler_names, &global_vars, &mut violations);

        // A shared object reached via `g->field` / `g.field` is reported once by
        // the field_expression branch and again when the recursion reaches the
        // base identifier — both at the same position — producing an exact
        // duplicate. Collapse those; distinct accesses always start at distinct
        // (line, column), so genuine multi-access lines are preserved (task 222).
        let mut seen = HashSet::new();
        violations.retain(|v| seen.insert((v.line, v.column)));

        violations
    }
}

impl Sig31C {
    /// Recursively collect file-scope declarations, including inside preprocessor blocks.
    fn collect_file_scope_declarations<'a>(node: &Node<'a>, decls: &mut Vec<Node<'a>>) {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "declaration" {
                    decls.push(child);
                } else if child.kind().starts_with("preproc_") {
                    Self::collect_file_scope_declarations(&child, decls);
                }
            }
        }
    }

    fn find_signal_handlers(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut handlers = HashSet::new();
        self.collect_handlers(node, source, &mut handlers);
        handlers
    }

    fn collect_handlers(&self, node: &Node, source: &str, handlers: &mut HashSet<String>) {
        for n in
            query::find_descendants_of_kinds(*node, &["call_expression", "assignment_expression"])
        {
            if n.kind() == "call_expression" {
                if let Some(function) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);

                    if func_name == "signal" || func_name == "sigaction" {
                        if let Some(args) = n.child_by_field_name("arguments") {
                            let arg_list = self.get_arguments(&args, source);

                            if func_name == "signal" && arg_list.len() >= 2 {
                                let handler_name = arg_list[1].trim();
                                if !handler_name.starts_with("SIG_")
                                    && handler_name != "NULL"
                                    && handler_name != "0"
                                    && !handler_name.is_empty()
                                {
                                    handlers.insert(handler_name.to_string());
                                }
                            }
                            // For sigaction, need to look for struct sigaction with .sa_handler assignment
                            // The handler is typically assigned via: sa.sa_handler = handler_func;
                            // We'll detect handlers from sigaction struct initialization elsewhere
                        }
                    }
                }
            }

            // Also detect signal handlers from struct sigaction assignment
            // Pattern: sa.sa_handler = unsafe_handler;
            if n.kind() == "assignment_expression" {
                if let Some(left) = n.child_by_field_name("left") {
                    if left.kind() == "field_expression" {
                        if let Some(field) = left.child_by_field_name("field") {
                            let field_name = get_node_text(&field, source);
                            if field_name == "sa_handler" {
                                if let Some(right) = n.child_by_field_name("right") {
                                    let handler_name = get_node_text(&right, source);
                                    if !handler_name.starts_with("SIG_")
                                        && handler_name != "NULL"
                                        && handler_name != "0"
                                        && !handler_name.is_empty()
                                    {
                                        handlers.insert(handler_name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn get_arguments(&self, args_node: &Node, source: &str) -> Vec<String> {
        let mut arguments = Vec::new();

        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                let kind = child.kind();
                if kind != "," && kind != "(" && kind != ")" {
                    let arg_text = get_node_text(&child, source).to_string();
                    arguments.push(arg_text);
                }
            }
        }

        arguments
    }

    /// Find all global/static variables and determine if they're volatile sig_atomic_t
    fn find_global_variables(&self, node: &Node, source: &str) -> HashMap<String, bool> {
        let mut vars = HashMap::new();

        // Look at file-scope declarations, including those inside preprocessor blocks
        if node.kind() == "translation_unit" {
            let mut decls = Vec::new();
            Self::collect_file_scope_declarations(node, &mut decls);
            for child in &decls {
                let decl_text = get_node_text(child, source);

                // Parse type - check if it's safe
                // Safe types: ONLY volatile sig_atomic_t, atomic_* types
                // Everything else (int, struct, arrays, etc.) is UNSAFE
                let is_safe = (decl_text.contains("volatile")
                    && decl_text.contains("sig_atomic_t"))
                    || decl_text.contains("atomic_");

                // Extract ALL declarators (handles init_declarator, pointer_declarator, etc.)
                for j in 0..child.child_count() {
                    if let Some(decl_child) = child.child(j) {
                        let kind = decl_child.kind();
                        if kind == "init_declarator"
                            || kind == "pointer_declarator"
                            || kind == "array_declarator"
                            || kind == "identifier"
                        {
                            self.extract_var_names(&decl_child, source, &mut vars, is_safe);
                        }
                    }
                }
            }
        }

        vars
    }

    fn extract_var_names(
        &self,
        declarator: &Node,
        source: &str,
        vars: &mut HashMap<String, bool>,
        is_safe: bool,
    ) {
        match declarator.kind() {
            "identifier" => {
                let var_name = get_node_text(&declarator, source);
                vars.insert(var_name.to_string(), is_safe);
            }
            "init_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.extract_var_names(&inner, source, vars, is_safe);
                }
            }
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.extract_var_names(&inner, source, vars, is_safe);
                }
            }
            _ => {
                // Try to find identifier child
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            let var_name = get_node_text(&child, source);
                            vars.insert(var_name.to_string(), is_safe);
                        } else if child.kind() != "," {
                            self.extract_var_names(&child, source, vars, is_safe);
                        }
                    }
                }
            }
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        handlers: &HashSet<String>,
        global_vars: &HashMap<String, bool>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(declarator) = func.child_by_field_name("declarator") {
                if let Some(func_name) = self.get_function_name_text(&declarator, source) {
                    if handlers.contains(&func_name) {
                        if let Some(body) = func.child_by_field_name("body") {
                            self.check_handler_body(
                                &body,
                                source,
                                &func_name,
                                global_vars,
                                violations,
                            );
                        }
                    }
                }
            }
        }
    }

    fn get_function_name_text(&self, declarator: &Node, source: &str) -> Option<String> {
        if declarator.kind() == "function_declarator" {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                let text = get_node_text(&inner, source);
                return Some(text.to_string());
            }
        }

        if declarator.kind() == "pointer_declarator" {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                return self.get_function_name_text(&inner, source);
            }
        }

        if declarator.kind() == "identifier" {
            let text = get_node_text(&declarator, source);
            return Some(text.to_string());
        }

        None
    }

    fn check_handler_body(
        &self,
        body: &Node,
        source: &str,
        handler_name: &str,
        global_vars: &HashMap<String, bool>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Collect all local variables declared in this handler
        let mut local_vars = HashSet::new();
        self.collect_local_vars(body, source, &mut local_vars);

        self.check_for_global_access(
            body,
            source,
            handler_name,
            global_vars,
            &local_vars,
            violations,
        );
    }

    fn collect_local_vars(&self, node: &Node, source: &str, locals: &mut HashSet<String>) {
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            if let Some(declarator) = decl.child_by_field_name("declarator") {
                self.extract_local_var_names(&declarator, source, locals);
            }
        }
    }

    fn extract_local_var_names(
        &self,
        declarator: &Node,
        source: &str,
        locals: &mut HashSet<String>,
    ) {
        match declarator.kind() {
            "identifier" => {
                let var_name = get_node_text(&declarator, source);
                locals.insert(var_name.to_string());
            }
            "init_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.extract_local_var_names(&inner, source, locals);
                }
            }
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                if let Some(inner) = declarator.child_by_field_name("declarator") {
                    self.extract_local_var_names(&inner, source, locals);
                }
            }
            _ => {
                for i in 0..declarator.child_count() {
                    if let Some(child) = declarator.child(i) {
                        if child.kind() == "identifier" {
                            let var_name = get_node_text(&child, source);
                            locals.insert(var_name.to_string());
                        } else if child.kind() != "," {
                            self.extract_local_var_names(&child, source, locals);
                        }
                    }
                }
            }
        }
    }

    fn check_for_global_access(
        &self,
        node: &Node,
        source: &str,
        handler_name: &str,
        global_vars: &HashMap<String, bool>,
        local_vars: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check for identifier references AND field_expression (for struct member access)
        for n in query::find_descendants_of_kinds(*node, &["identifier", "field_expression"]) {
            if n.kind() == "identifier" {
                let id_name = get_node_text(&n, source);

                // Skip if it's a local variable
                if local_vars.contains(id_name) {
                    continue; // Don't treat this identifier as a global access
                }

                // Skip if this identifier is used as an argument to an async-signal-safe function
                if self.is_used_in_async_safe_call(&n, source) {
                    continue;
                }

                if let Some(&is_safe) = global_vars.get(id_name) {
                    if !is_safe {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::High,
                            message: format!(
                                "Signal handler '{}' accesses shared object '{}' which is not 'volatile sig_atomic_t'",
                                handler_name, id_name
                            ),
                            file_path: String::new(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            suggestion: Some(
                                "Change variable to 'volatile sig_atomic_t' or use a flag-based approach where the handler only sets a volatile sig_atomic_t flag".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            } else if n.kind() == "field_expression" {
                // For struct member access like global_signal_state.signal_history[0]
                // Check if the base object is a global variable
                if let Some(argument) = n.child_by_field_name("argument") {
                    let base_text = get_node_text(&argument, source);

                    // Extract just the identifier (handle cases like "(*ptr)" or just "var")
                    let base_id = if base_text.starts_with('(') && base_text.ends_with(')') {
                        &base_text[1..base_text.len() - 1]
                            .trim_start_matches('*')
                            .trim()
                    } else {
                        base_text.trim_start_matches('*').trim()
                    };

                    // Skip if it's a local variable
                    if local_vars.contains(base_id) {
                        continue;
                    }

                    if let Some(&is_safe) = global_vars.get(base_id) {
                        if !is_safe {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Signal handler '{}' accesses shared object '{}' which is not 'volatile sig_atomic_t'",
                                    handler_name, base_id
                                ),
                                file_path: String::new(),
                                line: n.start_position().row + 1,
                                column: n.start_position().column + 1,
                                suggestion: Some(
                                    "Change variable to 'volatile sig_atomic_t' or use a flag-based approach where the handler only sets a volatile sig_atomic_t flag".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check if this identifier is used as an argument to an async-signal-safe function
    /// Common async-signal-safe functions: write, read, _exit, signal, raise, abort, etc.
    fn is_used_in_async_safe_call(&self, node: &Node, source: &str) -> bool {
        // Walk up the AST to find if we're inside a call_expression
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "call_expression" {
                if let Some(function) = parent.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);

                    // List of async-signal-safe functions from POSIX
                    // https://man7.org/linux/man-pages/man7/signal-safety.7.html
                    let async_safe_funcs = [
                        "write",
                        "read",
                        "_exit",
                        "_Exit",
                        "abort",
                        "raise",
                        "signal",
                        "sigaction",
                        "sigaddset",
                        "sigdelset",
                        "sigemptyset",
                        "sigfillset",
                        "sigismember",
                        "sigpending",
                        "sigprocmask",
                        "sigsuspend",
                        "kill",
                        "pause",
                        "sleep",
                        "alarm",
                        "getpid",
                        "getppid",
                        "getuid",
                        "geteuid",
                        "getgid",
                        "getegid",
                        "close",
                        "dup",
                        "dup2",
                        "fcntl",
                        "pipe",
                    ];

                    if async_safe_funcs.contains(&func_name) {
                        return true;
                    }
                }
                // Don't continue searching up past the call_expression
                return false;
            }

            // Don't search past function boundaries
            if parent.kind() == "function_definition" {
                return false;
            }

            current = parent.parent();
        }

        false
    }
}
