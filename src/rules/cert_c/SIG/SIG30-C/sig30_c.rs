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
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Sig30C;

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

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "SIG30-C"
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
    /// Find all function names registered as signal handlers
    fn find_signal_handlers(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut handlers = HashSet::new();
        self.collect_handlers(node, source, &mut handlers);
        handlers
    }

    fn collect_handlers(&self, node: &Node, source: &str, handlers: &mut HashSet<String>) {
        // Look for signal(SIGXXX, handler_func) calls
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "signal" || func_name == "sigaction" {
                    // Get the handler function name (second argument for signal())
                    if let Some(args) = call.child_by_field_name("arguments") {
                        let arg_list = self.get_arguments(&args, source);

                        // For signal(sig, handler), handler is second arg
                        if func_name == "signal" && arg_list.len() >= 2 {
                            let handler_name = arg_list[1].trim();
                            // Skip SIG_IGN, SIG_DFL, SIG_ERR, NULL
                            if !handler_name.starts_with("SIG_")
                                && handler_name != "NULL"
                                && handler_name != "0"
                                && !handler_name.is_empty()
                            {
                                handlers.insert(handler_name.to_string());
                            }
                        }

                        // For sigaction, handler is in sa_sigaction field
                        if func_name == "sigaction" && arg_list.len() >= 2 {
                            // Extract handler from struct (this is simplified)
                            let second_arg = arg_list[1].trim();
                            if second_arg.starts_with("&") {
                                // Often &sa where sa.sa_handler = handler_func
                                // We'd need more complex parsing for this
                            }
                        }
                    }
                }
            }
        }
    }

    /// Get argument strings from an argument_list node
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

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        handlers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check if this is a function definition that's a signal handler
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(declarator) = func.child_by_field_name("declarator") {
                if let Some(func_name) = self.get_function_name_text(&declarator, source) {
                    if handlers.contains(&func_name) {
                        // This is a signal handler - check for unsafe calls
                        if let Some(body) = func.child_by_field_name("body") {
                            self.check_handler_body(
                                &body, source, &func_name, handlers, violations,
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
        violations: &mut Vec<RuleViolation>,
    ) {
        self.check_calls_in_handler(body, source, handler_name, all_handlers, violations);
    }

    fn check_calls_in_handler(
        &self,
        node: &Node,
        source: &str,
        handler_name: &str,
        all_handlers: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if self.is_unsafe_function(func_name, handler_name, all_handlers) {
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
