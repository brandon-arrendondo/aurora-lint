// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! SIG01-C: Understand implementation-specific details regarding signal handler persistence
//!
//! The signal() function has implementation-defined behavior regarding signal handler
//! persistence. On some systems (e.g., many UNIX variants), signal handlers persist
//! after being called. On others (e.g., Windows), handlers are reset to default after
//! each signal delivery, requiring reinstallation.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void handler(int sig) {
//!     /* Handler logic */
//! }
//!
//! int main(void) {
//!     signal(SIGINT, handler);  // VIOLATION: Implementation-defined persistence
//!     while (1) { /* ... */ }
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! void handler(int sig) {
//!     /* Handler logic */
//! }
//!
//! int main(void) {
//!     struct sigaction sa;
//!     sa.sa_handler = handler;
//!     sa.sa_flags = 0;  // Explicit control over handler persistence
//!     sigemptyset(&sa.sa_mask);
//!     sigaction(SIGINT, &sa, NULL);  // OK: Well-defined behavior
//!     while (1) { /* ... */ }
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::signal_handlers::{RegisteredHandlers, RegistrationKind};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Sig01C {
    /// The prescan's context, so a handler declared only in a header is
    /// still identified (see `RegisteredHandlers::collect_in`).
    project: RefCell<Option<ProjectContext>>,
}

impl Sig01C {
    pub fn new() -> Self {
        Self {
            project: RefCell::new(None),
        }
    }
}

impl Default for Sig01C {
    fn default() -> Self {
        Self::new()
    }
}

impl CertRule for Sig01C {
    fn rule_id(&self) -> &'static str {
        "SIG01-C"
    }

    fn description(&self) -> &'static str {
        "Understand implementation-specific details regarding signal handler persistence"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "SIG01-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.clone());
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Sig01C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // A signal() call that installs a handler, by declaration: not
        // SIG_IGN/SIG_DFL, and not a saved disposition being restored.
        // A wrapper's signal() on its parameter installs the caller's
        // handler, so it counts too.
        let found = RegisteredHandlers::collect_in(node, source, self.project.borrow().as_ref());
        let sites: HashSet<(usize, usize)> = found
            .registrations
            .iter()
            .filter(|r| r.kind == RegistrationKind::Signal)
            .map(|r| (r.api_line, r.api_column))
            .chain(
                found
                    .caller_supplied
                    .iter()
                    .filter(|s| s.kind == RegistrationKind::Signal)
                    .map(|s| (s.api_line, s.api_column)),
            )
            .collect();
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let line = call.start_position().row + 1;
            let column = call.start_position().column + 1;
            if !sites.contains(&(line, column)) {
                continue;
            }
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Low,
                message: "Use of signal() has implementation-defined behavior regarding handler persistence. Consider using sigaction() for portable behavior.".to_string(),
                file_path: String::new(),
                line,
                column,
                suggestion: Some(
                    "Replace signal() with sigaction() to ensure consistent, well-defined behavior across platforms. sigaction() provides explicit control over handler persistence via the SA_RESETHAND flag.".to_string()
                ),
                ..Default::default()
            });
        }
    }
}
