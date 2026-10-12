// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! POS48-C: Do not unlock or destroy another thread's mutex
//!
//! Destroying a pthread mutex that another thread holds, or may still lock,
//! is undefined behavior; so is using one after it is destroyed.
//!
//! ## Detection Strategy:
//! One analysis shared with CON31-C (`mutex_lifetime`), reading the POSIX
//! family's mutex calls (`pthread_mutex_*`, `pthread_cond_*wait`) by their
//! contract and each mutex by declaration. Reported:
//! - a destroy of a mutex the destroying function locked and has not
//!   unlocked on every path to the destroy;
//! - a lock, unlock, condition wait or second destroy of a mutex the function
//!   destroyed on every path to it, with no initialization in between;
//! - a destroy while a thread whose start routine (named in a thread creation
//!   in this file, by declaration) locks the mutex may still run: the destroy
//!   is in a start routine and another thread locking the mutex may run beside
//!   it, or the destroying function created such a thread into a local handle
//!   and has not joined it.
//!
//! An unlock with no lock held on some path is not reported yet: it needs
//! the held-lock regions the analysis layer does not have.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::threads::ThreadOpKind;
use crate::utility::cert_c::mutex_lifetime::{self, MutexHazard};
use crate::utility::cert_c::thread_api::{Family, ProjectFunctions};
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Default)]
pub struct Pos48C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Pos48C {
    fn rule_id(&self) -> &'static str {
        "POS48-C"
    }
    fn description(&self) -> &'static str {
        "Do not unlock or destroy another thread's mutex"
    }
    fn severity(&self) -> Severity {
        Severity::High
    }
    fn cert_id(&self) -> &'static str {
        "POS48-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let project = self.project.borrow();
        let mut violations = Vec::new();
        for finding in mutex_lifetime::mutex_findings(node, source, project.as_ref()) {
            if finding.call.family != Family::Posix {
                continue;
            }
            let mutex = &finding.mutex;
            let name = &finding.call.name;
            let (message, suggestion) = match &finding.hazard {
                MutexHazard::DestroyedWhileHeld { lock_line } => (
                    format!(
                        "Mutex '{mutex}' destroyed with {name}() while it is locked: this \
                         function locks it at line {lock_line} and does not unlock it on \
                         every path to the destroy."
                    ),
                    "Unlock the mutex before destroying it".to_string(),
                ),
                MutexHazard::UsedAfterDestroy { destroy_line } => {
                    let init = finding
                        .call
                        .family
                        .function_of(ThreadOpKind::MutexInit)
                        .unwrap_or_else(|| "an initialization".to_string());
                    (
                        format!(
                            "Mutex '{mutex}' used by {name}() after it is destroyed at line \
                             {destroy_line}, with no {init}() in between."
                        ),
                        format!("Initialize the mutex again with {init}() before using it"),
                    )
                }
                MutexHazard::DestroyedWhileThreadsRun {
                    entry,
                    sibling: true,
                } => (
                    format!(
                        "Mutex '{mutex}' destroyed with {name}() in a thread start routine \
                         while other threads running {entry}(), which locks it, may still use it."
                    ),
                    "Destroy the mutex after every thread that uses it has been joined".to_string(),
                ),
                MutexHazard::DestroyedWhileThreadsRun {
                    entry,
                    sibling: false,
                } => (
                    format!(
                        "Mutex '{mutex}' destroyed with {name}() while the thread running \
                         {entry}(), which locks it, may still run: it has not been joined."
                    ),
                    "Join the thread before destroying the mutex".to_string(),
                ),
            };
            let start = finding.node.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                file_path: String::new(),
                line: start.row + 1,
                column: start.column + 1,
                message,
                suggestion: Some(suggestion),
                requires_manual_review: None,
            });
        }
        violations
    }
}
