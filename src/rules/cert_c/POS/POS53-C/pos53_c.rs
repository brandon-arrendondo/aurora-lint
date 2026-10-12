// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! POS53-C: Do not use more than one mutex for concurrent waiting operations on a condition variable
//!
//! This rule detects violations where the same condition variable is used with
//! different mutexes in pthread_cond_wait() or pthread_cond_timedwait() calls.
//!
//! ## Problem
//! Using multiple different mutexes with the same condition variable creates
//! undefined behavior. The POSIX standard states: "the effect of an attempt by
//! any thread to wait on that condition variable using a different mutex is undefined."
//!
//! ## Examples
//!
//! **Non-compliant:**
//! ```c
//! pthread_cond_t cv;
//! pthread_mutex_t mutex1, mutex2;
//!
//! void waiter1() {
//!     pthread_cond_wait(&cv, &mutex1);  // Using mutex1
//! }
//!
//! void waiter2() {
//!     pthread_cond_wait(&cv, &mutex2);  // Using mutex2 - VIOLATION!
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! pthread_cond_t cv;
//! pthread_mutex_t mutex1;
//!
//! void waiter1() {
//!     pthread_cond_wait(&cv, &mutex1);  // Using mutex1
//! }
//!
//! void waiter2() {
//!     pthread_cond_wait(&cv, &mutex1);  // Using same mutex1 - OK
//! }
//! ```
//!
//! ## Detection Strategy
//! - Find POSIX condition waits by their thread-API contract
//!   (`thread_api::thread_op`): `pthread_cond_wait()`,
//!   `pthread_cond_timedwait()` and `pthread_cond_clockwait()`, wherever the
//!   call names the library's function
//! - Identify the condition variable and the mutex by declaration and member
//!   path (`thread_api::sync_object`), not by the arguments' spelling: one
//!   mutex written `&m1` and `&(m1)` is one mutex, and a local condition
//!   variable is never merged with a same-named one elsewhere
//! - Report a condition variable whose waits in this file use more than one
//!   mutex
//!
//! The rule is POSIX's: the C11 `cnd_wait()` carries the same constraint
//! only by MISRA's reading, so a C11 or other family's wait is not read here.

use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::settings::threads::{Role, ThreadOpKind};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::thread_api::{self, Family, ProjectFunctions, SyncObject};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Default)]
pub struct Pos53C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

/// The waits on one condition variable: its spelling at the first wait,
/// that wait's position, and each distinct mutex with its spelling, in the
/// order first seen.
struct Waits {
    cond: String,
    first: (usize, usize),
    mutexes: Vec<(SyncObject, String)>,
}

impl CertRule for Pos53C {
    fn rule_id(&self) -> &'static str {
        "POS53-C"
    }

    fn cert_id(&self) -> &'static str {
        "POS53"
    }

    fn description(&self) -> &'static str {
        "Do not use more than one mutex for concurrent waiting operations on a condition variable"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let project = self.project.borrow();
        let mut order: Vec<SyncObject> = Vec::new();
        let mut waits: HashMap<SyncObject, Waits> = HashMap::new();
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(wait) = thread_api::thread_op_of_kind(
                &call_node,
                source,
                project.as_ref(),
                ThreadOpKind::CondWait,
            ) else {
                continue;
            };
            if wait.family != Family::Posix {
                continue;
            }
            let (Some(cond), Some(mutex)) = (wait.operand(Role::Cond), wait.operand(Role::Mutex))
            else {
                continue;
            };
            let (Some(cond_id), Some(mutex_id)) = (
                thread_api::sync_object(&cond, source),
                thread_api::sync_object(&mutex, source),
            ) else {
                continue;
            };
            let entry = waits.entry(cond_id.clone()).or_insert_with(|| {
                order.push(cond_id);
                let start = call_node.start_position();
                Waits {
                    cond: spelling(&cond, source),
                    first: (start.row, start.column),
                    mutexes: Vec::new(),
                }
            });
            if !entry.mutexes.iter().any(|(m, _)| *m == mutex_id) {
                entry.mutexes.push((mutex_id, spelling(&mutex, source)));
            }
        }

        let mut violations = Vec::new();
        for cond in order {
            let waits = &waits[&cond];
            if waits.mutexes.len() < 2 {
                continue;
            }
            let (row, column) = waits.first;
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Medium,
                message: format!(
                    "Condition variable '{}' is used with multiple different mutexes: {}. \
                     All threads waiting on a condition variable must use the same mutex.",
                    waits.cond,
                    waits
                        .mutexes
                        .iter()
                        .map(|(_, s)| format!("'{s}'"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                file_path: String::new(),
                line: row + 1,
                column: column + 1,
                suggestion: Some(
                    "Use the same mutex for every wait on this condition variable, or use separate condition variables for different mutexes."
                        .to_string(),
                ),
                ..Default::default()
            });
        }
        violations
    }
}

/// An operand as written, without surrounding whitespace.
fn spelling(node: &Node, source: &str) -> String {
    get_node_text(node, source).trim().to_string()
}
