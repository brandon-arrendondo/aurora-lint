// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON31-C: Do not destroy a mutex while it is locked
//!
//! This rule detects cases where a mutex is destroyed while it may still be locked
//! or in use by other threads. Destroying a mutex while it's locked causes undefined
//! behavior.
//!
//! ## The Problem:
//! Destroying a mutex while it's locked or potentially in use by other threads is dangerous:
//! 1. If a thread destroys a mutex while another thread holds the lock, undefined behavior occurs
//! 2. If a thread destroys a mutex while another thread is waiting on it, undefined behavior occurs
//! 3. Proper cleanup requires ensuring all threads are done using the mutex before destruction
//!
//! ## Examples:
//!
//! **Non-compliant (destroying mutex in thread function):**
//! ```c
//! int do_work(void *arg) {
//!   int *i = (int *)arg;
//!   if (*i < max_threads - 1) {
//!     mtx_lock(&lock);
//!     /* work */
//!     mtx_unlock(&lock);
//!   } else {
//!     mtx_destroy(&lock);  // VIOLATION: other threads might still be using it
//!   }
//!   return 0;
//! }
//! ```
//!
//! **Compliant (destroying mutex after thread joins):**
//! ```c
//! int do_work(void *dummy) {
//!   mtx_lock(&lock);
//!   /* work */
//!   mtx_unlock(&lock);
//!   return 0;
//! }
//!
//! int main(void) {
//!   for (size_t i = 0; i < max_threads; i++) {
//!     thrd_create(&threads[i], do_work, NULL);
//!   }
//!   for (size_t i = 0; i < max_threads; i++) {
//!     thrd_join(threads[i], 0);  // Wait for all threads to finish
//!   }
//!   mtx_destroy(&lock);  // SAFE: all threads have finished
//!   return 0;
//! }
//! ```
//!
//! ## Detection Strategy:
//! One analysis shared with POS48-C (`mutex_lifetime`), reading mutex calls
//! by their thread-API contract (C11, POSIX and any declared family) and each
//! mutex by declaration. A mutex destroy is reported when:
//! - the destroying function locked it and has not unlocked it on every path
//!   to the destroy; or
//! - a thread whose start routine (named in a thread creation in this file,
//!   by declaration) locks it may still run: the destroy is in a start
//!   routine and another thread locking the mutex may run beside it, or the
//!   destroying function created such a thread into a local handle and has
//!   not joined it.
//!
//! A destroy reached from a start routine through another call, and a start
//! routine defined in another file, are not seen.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::mutex_lifetime::{self, MutexHazard};
use crate::utility::cert_c::thread_api::ProjectFunctions;
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Default)]
pub struct Con31C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Con31C {
    fn rule_id(&self) -> &'static str {
        "CON31-C"
    }

    fn description(&self) -> &'static str {
        "Do not destroy a mutex while it is locked"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "CON31-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let project = self.project.borrow();
        let mut violations = Vec::new();
        for finding in mutex_lifetime::mutex_findings(node, source, project.as_ref()) {
            let mutex = &finding.mutex;
            let destroy = &finding.call.name;
            let (message, suggestion) = match &finding.hazard {
                MutexHazard::DestroyedWhileHeld { lock_line } => (
                    format!(
                        "Mutex '{mutex}' destroyed with {destroy}() while it is locked: \
                         this function locks it at line {lock_line} and does not unlock it \
                         on every path to the destroy."
                    ),
                    "Unlock the mutex before destroying it",
                ),
                MutexHazard::DestroyedWhileThreadsRun {
                    entry,
                    sibling: true,
                } => (
                    format!(
                        "Mutex '{mutex}' destroyed with {destroy}() in a thread start routine \
                         while other threads running {entry}(), which locks it, may still use it."
                    ),
                    "Destroy the mutex after every thread that uses it has been joined",
                ),
                MutexHazard::DestroyedWhileThreadsRun {
                    entry,
                    sibling: false,
                } => (
                    format!(
                        "Mutex '{mutex}' destroyed with {destroy}() while the thread running \
                         {entry}(), which locks it, may still run: it has not been joined."
                    ),
                    "Join the thread before destroying the mutex",
                ),
                MutexHazard::UsedAfterDestroy { .. } => continue,
            };
            let start = finding.node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                file_path: String::new(),
                line: start.row + 1,
                column: start.column + 1,
                message,
                suggestion: Some(suggestion.to_string()),
                ..Default::default()
            });
        }
        violations
    }
}
