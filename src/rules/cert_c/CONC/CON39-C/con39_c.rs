// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON39-C: Do not join or detach a thread that was previously joined or detached
//!
//! This rule detects violations where:
//! 1. A thread detaches itself (thrd_detach(thrd_current())) and is later joined
//! 2. A thread is joined or detached multiple times
//!
//! Detected form: a thread whose start routine detaches itself
//! (`thrd_detach(thrd_current())`, `pthread_detach(pthread_self())`) and
//! whose handle is later joined.
//!
//! ## Detection Strategy:
//! - Find thread creation, join and detach calls and the self handle by
//!   their thread-API contract (`thread_api::thread_op`): C11, POSIX and any
//!   declared family
//! - The self-detaching functions are those this file defines that detach
//!   the calling thread's own handle (`thread_api::is_own_thread`)
//! - A creation starts its thread in the function its entry operand names,
//!   resolved by declaration (`ThreadCall::entry_function`), not by the
//!   arguments' text
//! - Report a creation whose start routine self-detaches when the same
//!   handle (`thread_api::sync_object`) is joined anywhere in the file
//!
//! A double join, or a detach then a join, of one handle in the creating
//! code is not detected: telling them from joins on exclusive paths needs
//! the control-flow graph.
//!
//! References:
//! - <https://wiki.sei.cmu.edu/confluence/display/c/CON39-C.+Do+not+join+or+detach+a+thread+that+was+previously+joined+or+detached>

use super::super::{CertRule, RuleViolation};
use crate::analyze::cfg::get_function_name;
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::threads::{Role, ThreadOpKind};
use crate::utility::cert_c::ast_utils::find_containing_function;
use crate::utility::cert_c::thread_api::{self, ProjectFunctions, SyncObject};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Default)]
pub struct Con39C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Con39C {
    fn rule_id(&self) -> &'static str {
        "CON39-C"
    }

    fn description(&self) -> &'static str {
        "Do not join or detach a thread that was previously joined or detached"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "CON39-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let project = self.project.borrow();
        let project = project.as_ref();

        let mut self_detaching: HashSet<String> = HashSet::new();
        let mut joined: HashSet<SyncObject> = HashSet::new();
        let mut creations = Vec::new();
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(call) = thread_api::thread_op(&call_node, source, project) else {
                continue;
            };
            let Some(handle) = call.operand(Role::Handle) else {
                continue;
            };
            match call.kind() {
                ThreadOpKind::ThreadDetach
                    if thread_api::is_own_thread(&handle, source, project) =>
                {
                    if let Some(name) = find_containing_function(&call_node)
                        .and_then(|f| get_function_name(&f, source))
                    {
                        self_detaching.insert(name.to_string());
                    }
                }
                ThreadOpKind::ThreadJoin => {
                    if let Some(object) = thread_api::sync_object(&handle, source) {
                        joined.insert(object);
                    }
                }
                ThreadOpKind::ThreadCreate => {
                    if let (Some(entry), Some(object)) = (
                        call.entry_function(source),
                        thread_api::sync_object(&handle, source),
                    ) {
                        creations.push((call_node, entry, object));
                    }
                }
                _ => {}
            }
        }

        let mut violations = Vec::new();
        for (call_node, entry, handle) in creations {
            if !self_detaching.contains(&entry) || !joined.contains(&handle) {
                continue;
            }
            let start_pos = call_node.start_position();
            violations.push(RuleViolation {
                rule_id: "CON39-C".to_string(),
                severity: Severity::Low,
                file_path: String::new(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                message: format!(
                    "Thread created with function '{entry}' that detaches itself, but is later joined, causing undefined behavior"
                ),
                suggestion: None,
                requires_manual_review: None,
            });
        }
        violations
    }
}
