// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! SIG30-C: Call only asynchronous-safe functions within signal handlers
//!
//! Signal handlers can interrupt program execution at any point. Calling functions
//! that are not async-signal-safe from within a signal handler leads to undefined
//! behavior.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void handler(int sig) {
//!     printf("Signal %d\n", sig);  // VIOLATION: printf not async-safe
//!     malloc(100);                  // VIOLATION: malloc not async-safe
//!     free(ptr);                    // VIOLATION: free not async-safe
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! volatile sig_atomic_t flag = 0;
//! void handler(int sig) {
//!     flag = 1;  // OK: only set flag
//! }
//! // Check flag in main loop and perform unsafe operations there
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval;
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::signal_handlers::RegisteredHandlers;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tree_sitter::Node;

pub struct Sig30C {
    /// The prescan's context: handlers declared only in a header, and the
    /// project's function-like macros (a call through one is judged by what
    /// it expands to).
    project: RefCell<Option<ProjectContext>>,
}

impl Sig30C {
    pub fn new() -> Self {
        Self {
            project: RefCell::new(None),
        }
    }
}

impl Default for Sig30C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Sig30C {
    fn rule_id(&self) -> &'static str {
        "SIG30-C"
    }

    fn description(&self) -> &'static str {
        "Call only asynchronous-safe functions within signal handlers"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "SIG30-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Find all signal handler functions
        let handler_names = self.find_signal_handlers(node, source);

        // Check each handler for unsafe function calls
        self.check_node(node, source, &handler_names, &mut violations);

        violations
    }
}

impl Sig30C {
    /// Every function this translation unit registers as a signal handler,
    /// through `signal()` or `sigaction()` (`sa_handler`/`sa_sigaction`),
    /// resolved by declaration (see [`RegisteredHandlers`]).
    fn find_signal_handlers(&self, node: &Node, source: &str) -> HashSet<String> {
        RegisteredHandlers::collect_in(node, source, self.project.borrow().as_ref())
            .signal_handler_names()
    }

    /// The object-like aliases (`#define xwrite write`) in scope for this
    /// file: the project's, with this file's own over them.
    fn macro_aliases(&self, node: &Node, source: &str) -> HashMap<String, String> {
        let project = self.project.borrow();
        let empty = HashMap::new();
        let table = project
            .as_ref()
            .map(|p| &*p.macro_aliases)
            .unwrap_or(&empty);
        const_eval::merged_macro_aliases(table, node, source)
    }

    /// The function-like macros in scope for this file: the project's, with
    /// this file's own definitions over them.
    fn function_macros(&self, node: &Node, source: &str) -> HashMap<String, FunctionMacro> {
        let mut table = self
            .project
            .borrow()
            .as_ref()
            .map(|p| Arc::clone(&p.function_macros))
            .map(|t| HashMap::clone(&t))
            .unwrap_or_default();
        table.extend(macro_expand::collect_function_macros(node, source));
        table
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        handlers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if handlers.is_empty() {
            return;
        }
        let project = self.project.borrow();
        let real_functions = functions_named_in(node, source);
        let macros = Macros {
            functions: self.function_macros(node, source),
            aliases: self.macro_aliases(node, source),
            real_functions,
            project: project.as_ref(),
        };
        // Check if this is a function definition that's a signal handler
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(declarator) = func.child_by_field_name("declarator") {
                if let Some(func_name) = self.get_function_name_text(&declarator, source) {
                    if handlers.contains(&func_name) {
                        // This is a signal handler - check for unsafe calls
                        if let Some(body) = func.child_by_field_name("body") {
                            self.check_handler_body(
                                &body, source, &func_name, handlers, &macros, violations,
                            );
                        }
                    }
                }
            }
        }
    }

    fn get_function_name_text(&self, declarator: &Node, source: &str) -> Option<String> {
        // Handle function_declarator -> identifier
        if declarator.kind() == "function_declarator" {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                let text = get_node_text(&inner, source);
                return Some(text.to_string());
            }
        }

        // Handle pointer_declarator wrapping
        if declarator.kind() == "pointer_declarator" {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                return self.get_function_name_text(&inner, source);
            }
        }

        // If it's already an identifier
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
        all_handlers: &HashSet<String>,
        macros: &Macros<'_>,
        violations: &mut Vec<RuleViolation>,
    ) {
        self.check_calls_in_handler(body, source, handler_name, all_handlers, macros, violations);
    }

    fn check_calls_in_handler(
        &self,
        node: &Node,
        source: &str,
        handler_name: &str,
        all_handlers: &HashSet<String>,
        macros: &Macros<'_>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                // A function-like macro isn't a call: the handler calls
                // whatever it expands to, so `UNUSED(sig)` (`((void)(sig))`)
                // calls nothing. Its arguments are call_expressions of their
                // own in this walk, so only the macro's own body is judged here.
                let is_unsafe =
                    |name: &str| self.is_unsafe_function(name, handler_name, all_handlers);
                let callees = callees_of(&function, &call, source, macros, &is_unsafe);
                for func_name in &callees {
                    let func_name = func_name.as_str();
                    if !self.is_unsafe_function(func_name, handler_name, all_handlers) {
                        continue;
                    }
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Signal handler '{}' calls '{}()' which is not async-signal-safe",
                            handler_name, func_name
                        ),
                        file_path: String::new(),
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        suggestion: Some(format!(
                            "Use only async-safe functions in signal handlers. Consider setting a volatile sig_atomic_t flag instead and performing '{}()' outside the handler.",
                            func_name
                        )),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check if a function is NOT async-signal-safe
    /// handler_name is the signal handler we're currently checking
    /// all_handlers is the set of all known handler functions (calling them directly is OK)
    fn is_unsafe_function(
        &self,
        func_name: &str,
        _handler_name: &str,
        all_handlers: &HashSet<String>,
    ) -> bool {
        // Special case: calling another signal handler function directly is OK
        // (it's just a normal function call, not going through signal mechanism)
        if all_handlers.contains(func_name) {
            return false;
        }

        // Signal-related functions that are problematic when called FROM a handler
        const SIGNAL_MANIPULATION_UNSAFE: &[&str] = &[
            "raise",       // Can cause nested signal issues
            "sigaction",   // Should not be modified in handler
            "sigprocmask", // Should not be modified in handler
            "sigpending",  // Not reliable in handler
            "sigsuspend",  // Would block in handler
        ];

        // Check if it's signal manipulation (these are normally async-safe but problematic in handlers)
        if SIGNAL_MANIPULATION_UNSAFE.contains(&func_name) {
            return true;
        }

        // List of SAFE functions (anything not in this list is generally unsafe)
        const ASYNC_SAFE_FUNCTIONS: &[&str] = &[
            // C Standard async-safe functions
            "abort",
            "_Exit",
            "quick_exit",
            "signal",
            // POSIX async-safe functions (partial list from common functions)
            "_exit",
            "accept",
            "access",
            "alarm",
            "bind",
            "cfgetispeed",
            "cfgetospeed",
            "cfsetispeed",
            "cfsetospeed",
            "chdir",
            "chmod",
            "chown",
            "clock_gettime",
            "close",
            "connect",
            "dup",
            "dup2",
            "execl",
            "execle",
            "execv",
            "execve",
            "execvp",
            "fchmod",
            "fchown",
            "fcntl",
            "fdatasync",
            "fork",
            "fstat",
            "fsync",
            "ftruncate",
            "getegid",
            "geteuid",
            "getgid",
            "getgroups",
            "getpeername",
            "getpgrp",
            "getpid",
            "getppid",
            "getsockname",
            "getsockopt",
            "getuid",
            "kill",
            "link",
            "listen",
            "lseek",
            "lstat",
            "mkdir",
            "mkfifo",
            "open",
            "pathconf",
            "pause",
            "pipe",
            "poll",
            "posix_trace_event",
            "pselect",
            "read",
            "readlink",
            "recv",
            "recvfrom",
            "recvmsg",
            "rename",
            "rmdir",
            "select",
            "sem_post",
            "send",
            "sendmsg",
            "sendto",
            "setgid",
            "setpgid",
            "setsid",
            "setsockopt",
            "setuid",
            "shutdown",
            "sigaddset",
            "sigdelset",
            "sigemptyset",
            "sigfillset",
            "sigismember",
            "sigpause",
            "sigqueue",
            "sigset",
            "sleep",
            "socket",
            "socketpair",
            "stat",
            "symlink",
            "sysconf",
            "tcdrain",
            "tcflow",
            "tcflush",
            "tcgetattr",
            "tcgetpgrp",
            "tcsendbreak",
            "tcsetattr",
            "tcsetpgrp",
            "time",
            "timer_getoverrun",
            "timer_gettime",
            "timer_settime",
            "times",
            "umask",
            "uname",
            "unlink",
            "utime",
            "wait",
            "waitpid",
            "write",
        ];

        !ASYNC_SAFE_FUNCTIONS.contains(&func_name)
    }
}

/// What a handler's calls are resolved through.
struct Macros<'p> {
    functions: HashMap<String, FunctionMacro>,
    aliases: HashMap<String, String>,
    /// Names this file declares or defines as functions.
    real_functions: HashSet<String>,
    project: Option<&'p ProjectContext>,
}

impl Macros<'_> {
    /// Whether `name` is a real function somewhere: then a macro of the
    /// same name is an alternative (another `#if` arm, ADR-0010), not the
    /// only thing the call can be.
    fn is_real_function(&self, name: &str) -> bool {
        self.real_functions.contains(name)
            || self
                .project
                // Not `is_known_function`: it holds function-like macro
                // names too, which is exactly what this must tell apart.
                .is_some_and(|p| {
                    p.get_function_summary(name).is_some() || p.is_header_declared(name)
                })
    }
}

/// The names to judge for `call`, each reported as unsafe on its own.
///
/// A name on the async-safe list is judged as written, whatever a header
/// maps it to (glibc's `#define signal __sysv_signal`). A real function by
/// the written name is judged as written too, since a macro of that name
/// is only one alternative (lua's `setsignal` is a sigaction wrapper in one
/// arm and `#define setsignal signal` in the other). Beyond that, the
/// macro is what the call is:
///
/// - an object-like alias (`#define xwrite write`) is safe when its target
///   is, and is otherwise reported by the name written;
/// - a function-like macro calls what its expansion calls, so `UNUSED(sig)`
///   (`((void)sig)`) calls nothing.
///
/// A macro whose invocation doesn't expand (arity mismatch, `#`/`##`,
/// variadic) is judged as written.
fn callees_of(
    function: &Node,
    call: &Node,
    source: &str,
    macros: &Macros<'_>,
    is_unsafe: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    let written = get_node_text(function, source).to_string();
    if function.kind() != "identifier" || !is_unsafe(&written) {
        return vec![written];
    }
    let mut out = Vec::new();
    if macros.is_real_function(&written) {
        out.push(written.clone());
    }
    let mut name = written.clone();
    let mut aliased = false;
    // Bounded: an alias cycle is not C, but must not hang the scan.
    for _ in 0..8 {
        match macros.aliases.get(&name) {
            Some(target) if *target != name => {
                name = target.clone();
                aliased = true;
                if !is_unsafe(&name) {
                    return out;
                }
            }
            _ => break,
        }
    }
    match macro_body_callees(&name, call, source, &macros.functions) {
        Some(callees) => out.extend(callees),
        None if aliased => out.push(written),
        None => out.push(name),
    }
    out.dedup();
    out
}

/// Names of every function this translation unit declares or defines.
fn functions_named_in(root: &Node, source: &str) -> HashSet<String> {
    query::find_descendants_of_kind(*root, "function_declarator")
        .into_iter()
        .filter_map(|d| d.child_by_field_name("declarator"))
        .filter(|d| d.kind() == "identifier")
        .map(|d| get_node_text(&d, source).to_string())
        .collect()
}

/// When `call` invokes the function-like macro `name`, the names its
/// replacement list calls, with the arguments left opaque (they are judged
/// where they are written). `None` when `name` isn't such a macro or the
/// invocation doesn't expand.
fn macro_body_callees(
    name: &str,
    call: &Node,
    source: &str,
    macros: &HashMap<String, FunctionMacro>,
) -> Option<Vec<String>> {
    let arity = macros.get(name)?.params.len();
    let args = call.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    let actual: Vec<String> = args
        .named_children(&mut cursor)
        .map(|a| get_node_text(&a, source).to_string())
        .collect();
    if actual.len() != arity {
        return None;
    }
    let opaque: Vec<String> = (0..arity).map(|i| format!("__sqc_arg{i}__")).collect();
    let expansion = macro_expand::expand_invocation(macros, name, &opaque)?;
    // A statement-shaped body (`do { ... } while (0)`) parses as one too.
    let snippet = format!("void __sqc_macro_body__(void) {{ {expansion}; }}");
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&crate::parser::c_language()).ok()?;
    let tree = parser.parse(&snippet, None)?;
    Some(
        query::find_descendants_of_kind(tree.root_node(), "call_expression")
            .into_iter()
            .filter_map(|c| c.child_by_field_name("function"))
            .map(|f| get_node_text(&f, &snippet).to_string())
            // A body calling its parameter (`#define CALL(f) f()`) calls
            // what the invocation passes.
            .map(|callee| match opaque.iter().position(|o| *o == callee) {
                Some(i) => actual[i].clone(),
                None => callee,
            })
            .collect(),
    )
}
