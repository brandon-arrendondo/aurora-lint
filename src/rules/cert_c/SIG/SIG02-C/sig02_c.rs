// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! SIG02-C: Avoid using signals to implement normal functionality
//!
//! CERT gives no checkable predicate for "normal functionality", so the rule
//! reports the one form its noncompliant example shows: the program sending
//! a signal to itself. That is `raise()`, `pthread_kill()` (a thread of this
//! process), or `kill()` aimed at `getpid()`, each resolved to the library
//! function rather than matched by spelling (ADR-0006), with a signal argument
//! that is one of the signals commonly used to carry ordinary work (SIGUSR1,
//! SIGALRM, SIGPIPE, ...) as a whole token. Registering a handler is not a
//! send: `signal(SIGPIPE, SIG_IGN)` installs none, and whether a registered
//! handler carries normal functionality is a design judgment. Unsafe calls
//! inside a handler belong to SIG30-C and SIG31-C.
//!
//! ## Non-compliant example:
//!
//! ```c
//! void notify_self(void) {
//!     raise(SIGUSR1);  /* The program signals itself to do ordinary work */
//! }
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! // Use proper synchronization primitives
//! pthread_mutex_t mutex;
//! pthread_cond_t cond;
//!
//! void thread_notify() {
//!     pthread_mutex_lock(&mutex);
//!     pthread_cond_signal(&cond);
//!     pthread_mutex_unlock(&mutex);
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::thread_api::{self, ProjectFunctions};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Default)]
pub struct Sig02C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

/// Signals commonly used to carry ordinary work rather than report an
/// abnormal event.
const NORMAL_USE_SIGNALS: &[&str] = &[
    "SIGUSR1",
    "SIGUSR2",
    "SIGALRM", // Timer/scheduling
    "SIGPIPE", // Connection handling
    "SIGURG",  // Out-of-band data
    "SIGVTALRM",
    "SIGPROF",
    "SIGIO",
    "SIGPOLL",
];

/// `expr` with any enclosing parentheses removed.
fn strip_parens<'a>(expr: Node<'a>) -> Node<'a> {
    let mut expr = expr;
    while expr.kind() == "parenthesized_expression" {
        match expr.named_child(0) {
            Some(inner) => expr = inner,
            None => break,
        }
    }
    expr
}

impl Sig02C {
    pub fn new() -> Self {
        Self::default()
    }

    /// True when `arg` is, as a whole token, one of [`NORMAL_USE_SIGNALS`]:
    /// `SIGIOT` is not `SIGIO`.
    fn is_normal_use_signal(arg: Node, source: &str) -> bool {
        let arg = strip_parens(arg);
        arg.kind() == "identifier" && NORMAL_USE_SIGNALS.contains(&get_node_text(&arg, source))
    }

    /// True when `arg` is a call of the library's `getpid()`: the process
    /// a `kill()` aimed at it signals is the caller's own.
    fn is_own_pid(arg: Node, source: &str, project: Option<&ProjectFunctions>) -> bool {
        let arg = strip_parens(arg);
        arg.kind() == "call_expression"
            && arg
                .child_by_field_name("arguments")
                .is_some_and(|a| a.named_child_count() == 0)
            && thread_api::library_call(&arg, source, project) == Some("getpid")
    }

    /// The severity and message for `call` when it is a send of a
    /// normal-use signal to the program's own process or thread, else `None`.
    fn own_process_send(
        &self,
        call: &Node,
        source: &str,
        project: Option<&ProjectFunctions>,
    ) -> Option<(Severity, &'static str)> {
        let callee = call.child_by_field_name("function")?;
        // The name first, since resolving the callee reads the whole file.
        let (name, signal_index, severity, message) = match get_node_text(&callee, source) {
            "raise" => ("raise", 0, Severity::Medium, "Use of raise() to send the program a signal for normal control flow instead of reporting an abnormal event."),
            "kill" => ("kill", 1, self.severity(), "Use of kill() to send the program's own process a signal for normal functionality instead of reporting an abnormal event."),
            "pthread_kill" => ("pthread_kill", 1, Severity::Medium, "Use of pthread_kill() to send a thread of this program a signal for normal inter-thread communication instead of reporting an abnormal event."),
            _ => return None,
        };
        if thread_api::library_call(call, source, project) != Some(name) {
            return None;
        }
        let args = call.child_by_field_name("arguments")?;
        if !Self::is_normal_use_signal(args.named_child(signal_index)?, source) {
            return None;
        }
        if name == "kill" && !Self::is_own_pid(args.named_child(0)?, source, project) {
            return None;
        }
        Some((severity, message))
    }

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let project = self.project.borrow();
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let Some((severity, message)) = self.own_process_send(&call, source, project.as_ref())
            else {
                continue;
            };
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity,
                message: message.to_string(),
                file_path: String::new(),
                line: call.start_position().row + 1,
                column: call.start_position().column + 1,
                suggestion: Some(
                    "Avoid using signals for normal program flow. Use function calls and return values within a thread, and condition variables, message queues or pipes between threads and processes."
                        .to_string(),
                ),
                ..Default::default()
            });
        }
    }
}

impl CertRule for Sig02C {
    fn rule_id(&self) -> &'static str {
        "SIG02-C"
    }

    fn description(&self) -> &'static str {
        "Avoid using signals to implement normal functionality"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "SIG02-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}
