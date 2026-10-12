// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON04-C: Join or detach threads even if their exit status is unimportant
//!
//! Threads must be properly cleaned up by either joining (thrd_join/pthread_join)
//! or detaching (thrd_detach/pthread_detach) to reclaim system resources.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int main(void) {
//!     thrd_t thr;
//!     thrd_create(&thr, func, NULL);  // VIOLATION: thread never joined/detached
//!     return 0;
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! int message_print(void *ptr) {
//!     // Thread detaches itself
//!     if (thrd_detach(thrd_current()) != thrd_success) {
//!         /* Handle error */
//!     }
//!     return 0;
//! }
//! ```

//!
//! ## Detection Strategy:
//! - Find thread creation, join, detach and self-handle calls by their
//!   thread-API contract (`thread_api::thread_op`): C11, POSIX and any
//!   declared family
//! - Identify each thread handle by declaration and member path
//!   (`thread_api::sync_object`): two functions' same-named locals are two
//!   handles, and a file-scope handle joined in another function is joined
//! - Report a created handle that this file never joins or detaches, unless
//!   the thread's start routine detaches itself (`thrd_detach(thrd_current())`
//!   and the like). A start routine this file defines counts only if it is
//!   the one that self-detaches; one it cannot name (a function pointer, or
//!   a function defined elsewhere) counts if any function here does

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::get_function_name;
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::threads::{Role, ThreadOpKind};
use crate::utility::cert_c::ast_utils::{find_containing_function, get_node_text};
use crate::utility::cert_c::thread_api::{self, Family, ProjectFunctions, SyncObject};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Default)]
pub struct Con04C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

/// One thread creation.
struct ThreadCreation {
    handle: SyncObject,
    spelling: String,
    entry: Option<String>,
    family: Family,
    line: usize,
    column: usize,
}

impl CertRule for Con04C {
    fn rule_id(&self) -> &'static str {
        "CON04-C"
    }

    fn description(&self) -> &'static str {
        "Join or detach threads even if their exit status is unimportant"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "CON04-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let project = self.project.borrow();
        let project = project.as_ref();

        let mut creations: Vec<ThreadCreation> = Vec::new();
        let mut released: HashSet<SyncObject> = HashSet::new();
        let mut self_detaching: HashSet<String> = HashSet::new();
        let mut defined: HashSet<String> = HashSet::new();

        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(name) = get_function_name(&func, source) {
                defined.insert(name.to_string());
            }
        }

        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(call) = thread_api::thread_op(&call_node, source, project) else {
                continue;
            };
            let Some(handle) = call.operand(Role::Handle) else {
                continue;
            };
            match call.kind() {
                ThreadOpKind::ThreadCreate => {
                    let Some(object) = thread_api::sync_object(&handle, source) else {
                        continue;
                    };
                    creations.push(ThreadCreation {
                        handle: object,
                        spelling: handle_spelling(&handle, source),
                        entry: call.entry_function(source),
                        family: call.family,
                        line: call_node.start_position().row + 1,
                        column: call_node.start_position().column + 1,
                    });
                }
                ThreadOpKind::ThreadDetach
                    if thread_api::is_own_thread(&handle, source, project) =>
                {
                    if let Some(name) = find_containing_function(&call_node)
                        .and_then(|f| get_function_name(&f, source))
                    {
                        self_detaching.insert(name.to_string());
                    }
                }
                ThreadOpKind::ThreadJoin | ThreadOpKind::ThreadDetach => {
                    if let Some(object) = thread_api::sync_object(&handle, source) {
                        released.insert(object);
                    }
                }
                _ => {}
            }
        }

        let mut violations = Vec::new();
        for creation in creations {
            if released.contains(&creation.handle) {
                continue;
            }
            let detaches_itself = match &creation.entry {
                Some(entry) if defined.contains(entry) => self_detaching.contains(entry),
                _ => !self_detaching.is_empty(),
            };
            if detaches_itself {
                continue;
            }
            let join = creation
                .family
                .function_of(ThreadOpKind::ThreadJoin)
                .unwrap_or_else(|| "a join".to_string());
            let detach = creation
                .family
                .function_of(ThreadOpKind::ThreadDetach)
                .unwrap_or_else(|| "a detach".to_string());
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message: format!(
                    "Thread '{}' created but never joined or detached. \
                     Call {join}() or {detach}() to reclaim resources.",
                    creation.spelling
                ),
                severity: self.severity(),
                line: creation.line,
                column: creation.column,
                file_path: String::new(),
                suggestion: Some(format!("Call {join}() or {detach}() on the thread")),
                requires_manual_review: None,
            });
        }
        violations
    }
}

/// The handle as the creation writes it, without `&` and the parentheses
/// and subscript around the variable: `&(thr[i])` is `thr`.
fn handle_spelling(handle: &Node, source: &str) -> String {
    let text = get_node_text(handle, source).trim();
    let text = text.strip_prefix('&').map_or(text, str::trim_start);
    let text = text.trim_start_matches('(').trim_end_matches(')');
    text.split('[').next().unwrap_or(text).trim().to_string()
}
