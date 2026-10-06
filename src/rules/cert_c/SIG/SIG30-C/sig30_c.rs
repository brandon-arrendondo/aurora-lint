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
use crate::analyze::check_macros::{self, MacroDefinition};
use crate::analyze::context::ProjectContext;
use crate::analyze::macro_expand::{self, FunctionMacro};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::signal_handlers::RegisteredHandlers;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
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
    fn reads_header_facts(&self) -> bool {
        true
    }

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
        let Some(macros) = Macros::new(node, source, project.as_ref()) else {
            return;
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
        let is_unsafe = |name: &str| self.is_unsafe_function(name, handler_name, all_handlers);
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(function) = call.child_by_field_name("function") else {
                continue;
            };
            // A macro isn't a call: the handler calls whatever it expands
            // to (see `Macros::reached`). Its arguments are call_expressions
            // of their own in this walk, so only the macro's body is judged
            // here.
            let written = get_node_text(&function, source).to_string();
            let callees = if function.kind() == "identifier" {
                let args = call_arguments(&call, source);
                macros.reached(&written, &args, &is_unsafe, &mut Vec::new())
            } else {
                vec![written.clone()]
            };
            for func_name in callees.iter().filter(|n| is_unsafe(n)) {
                let through = if *func_name == written {
                    String::new()
                } else {
                    format!(" (through macro '{written}')")
                };
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Signal handler '{}' calls '{}()'{} which is not async-signal-safe",
                        handler_name, func_name, through
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
    /// This file's `#define`s, every arm the file does not itself prove dead.
    local: HashMap<String, Vec<MacroDefinition>>,
    /// Names this file declares or defines as functions.
    real_functions: HashSet<String>,
    project: Option<&'p ProjectContext>,
    parser: RefCell<tree_sitter::Parser>,
}

/// How deep a chain of macros is followed. An alias cycle is not C, but must
/// not hang the scan.
const MAX_MACRO_DEPTH: usize = 8;

impl<'p> Macros<'p> {
    fn new(root: &Node, source: &str, project: Option<&'p ProjectContext>) -> Option<Self> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&crate::parser::c_language()).ok()?;
        Some(Self {
            local: check_macros::collect_macro_definitions(source),
            real_functions: functions_named_in(root, source),
            project,
            parser: RefCell::new(parser),
        })
    }

    /// Every live definition of `name`: this file's arms when it defines
    /// the name, else every arm any scanned file or header gives it.
    fn definitions(&self, name: &str) -> &[MacroDefinition] {
        self.local
            .get(name)
            .or_else(|| self.project.and_then(|p| p.macro_definitions.get(name)))
            .map_or(&[], Vec::as_slice)
    }

    /// Whether every definition of `name` is a system header's.
    fn is_implementation_macro(&self, name: &str) -> bool {
        !self.local.contains_key(name)
            && self
                .project
                .is_some_and(|p| p.macros_defined_outside_project.contains(name))
    }

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

    /// The callees a call written `name(args)` reaches, each judged on its
    /// own.
    ///
    /// A name no macro defines is the call. Otherwise every definition is an
    /// alternative, and the call reaches the union of what each arm calls
    /// (ADR-0010: an accusing rule uses any live definition), plus the name
    /// itself when a real function of that name is another alternative
    /// (lua's `setsignal` is a sigaction wrapper in one arm and `#define
    /// setsignal signal` in the other). So `UNUSED(sig)` (`((void)sig)` in
    /// every arm) calls nothing, and a `TRACE(x)` that is `((void)(x))`
    /// unless `DEBUG` selects `fprintf(...)` calls `fprintf`.
    ///
    /// A system header's definitions are the implementation's: a name on
    /// the async-safe list stays safe whatever it maps to (glibc's `#define
    /// signal __sysv_signal`), and anything else it reaches is reported by
    /// the name the code wrote, not an internal one (`__longjmp_chk`). A
    /// project's own macro is judged by what it expands to, a safe name
    /// included (ADR-0006).
    ///
    /// An arm that can't be expanded (variadic, `##`) is judged as written.
    fn reached(
        &self,
        name: &str,
        args: &[String],
        is_unsafe: &dyn Fn(&str) -> bool,
        stack: &mut Vec<String>,
    ) -> Vec<String> {
        let defs = self.definitions(name);
        if defs.is_empty() || stack.iter().any(|n| n == name) || stack.len() >= MAX_MACRO_DEPTH {
            return vec![name.to_string()];
        }
        let implementation = self.is_implementation_macro(name);
        if implementation && !is_unsafe(name) {
            return vec![name.to_string()];
        }
        let mut out = Vec::new();
        if self.is_real_function(name) {
            out.push(name.to_string());
        }
        stack.push(name.to_string());
        let mut expanded_any = false;
        for def in defs {
            let expansion = match def {
                MacroDefinition::Function { params, body } if params.len() == args.len() => {
                    let opaque = placeholders(args.len());
                    // One arm: the others are judged in their own turn.
                    let arm = FunctionMacro {
                        params: params.clone(),
                        body: body.clone(),
                        alternatives: Vec::new(),
                    };
                    let table = HashMap::from([(name.to_string(), arm)]);
                    macro_expand::expand_invocation(&table, name, &opaque)
                }
                // Another arm's arity: not what this invocation expands.
                MacroDefinition::Function { .. } => continue,
                // `NAME(args)` with `#define NAME body` is `body(args)`.
                MacroDefinition::Object { body } => {
                    Some(format!("{body}({})", placeholders(args.len()).join(", ")))
                }
                MacroDefinition::Opaque => None,
            };
            expanded_any = true;
            match expansion.and_then(|e| self.calls_in(&e, args)) {
                Some(calls) => {
                    for (callee, callee_args) in calls {
                        match callee {
                            Callee::Named(n) => {
                                out.extend(self.reached(&n, &callee_args, is_unsafe, stack))
                            }
                            Callee::Expression(text) => out.push(text),
                        }
                    }
                }
                None => out.push(name.to_string()),
            }
        }
        stack.pop();
        if !expanded_any {
            out.push(name.to_string());
        }
        if implementation {
            for reached in &mut out {
                if is_unsafe(reached) {
                    *reached = name.to_string();
                }
            }
        }
        let mut seen = HashSet::new();
        out.retain(|n| seen.insert(n.clone()));
        out
    }

    /// The calls in one arm's `expansion`, whose parameters were replaced by
    /// [`placeholders`], with `actual` (the invocation's own argument text)
    /// substituted back into each callee and its arguments. The arguments
    /// themselves are left opaque: they are judged where they are written.
    fn calls_in(&self, expansion: &str, actual: &[String]) -> Option<Vec<(Callee, Vec<String>)>> {
        // A statement-shaped body (`do { ... } while (0)`) parses as one too.
        let snippet = format!("void __sqc_macro_body__(void) {{ {expansion}; }}");
        let tree = self.parser.borrow_mut().parse(&snippet, None)?;
        let restore = |text: &str| {
            let mut text = text.to_string();
            for (i, a) in actual.iter().enumerate() {
                text = text.replace(&placeholder(i), a);
            }
            text
        };
        let calls = query::find_descendants_of_kind(tree.root_node(), "call_expression")
            .into_iter()
            .filter_map(|call| {
                let mut function = call.child_by_field_name("function")?;
                // `(f)(x)` calls `f`.
                while function.kind() == "parenthesized_expression" {
                    function = function.named_child(0)?;
                }
                let callee = restore(get_node_text(&function, &snippet));
                let args = call_arguments(&call, &snippet)
                    .iter()
                    .map(|a| restore(a))
                    .collect();
                // A parameter the invocation passes a name for
                // (`#define CALL(f) f()`) calls what that name is.
                let callee = if is_identifier(&callee) {
                    Callee::Named(callee)
                } else {
                    Callee::Expression(callee)
                };
                Some((callee, args))
            })
            .collect();
        Some(calls)
    }
}

/// What a call in a macro's expansion calls.
enum Callee {
    /// A name, which may itself be a macro.
    Named(String),
    /// A pointer or member expression, reported as written.
    Expression(String),
}

/// Stand-ins for a macro's arguments while its body is parsed on its own.
fn placeholder(i: usize) -> String {
    format!("__sqc_arg{i}__")
}

fn placeholders(n: usize) -> Vec<String> {
    (0..n).map(placeholder).collect()
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// The text of each argument of `call`.
fn call_arguments(call: &Node, source: &str) -> Vec<String> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .filter(|a| a.kind() != "comment")
        .map(|a| get_node_text(&a, source).to_string())
        .collect()
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
