// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON38-C: Preserve thread safety and liveness when using condition variables
//!
//! This rule detects use of `cnd_signal()` which can cause deadlock when multiple
//! threads wait on the same condition variable with different predicates. The safer
//! alternative is `cnd_broadcast()` which wakes all waiting threads.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! // Multiple threads wait on shared condition variable
//! void process_thread(int thread_id) {
//!   mtx_lock(&mutex);
//!   while (!ready[thread_id]) {
//!     cnd_wait(&cond, &mutex);  // Multiple threads wait on same condition
//!   }
//!   // ... process ...
//!   cnd_signal(&cond);  // WRONG: May wake wrong thread, causing deadlock
//!   mtx_unlock(&mutex);
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! void process_thread(int thread_id) {
//!   mtx_lock(&mutex);
//!   while (!ready[thread_id]) {
//!     cnd_wait(&cond, &mutex);
//!   }
//!   // ... process ...
//!   cnd_broadcast(&cond);  // Correct: Wakes all threads, ensures liveness
//!   mtx_unlock(&mutex);
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find condition-variable signals by their thread-API contract
//!   (`thread_api::thread_op`): C11 `cnd_signal()`, POSIX
//!   `pthread_cond_signal()` and any declared family's signal
//! - Report each one, recommending the same family's broadcast
//! - Note: Using a signal is only safe when each thread has its own unique
//!   condition variable, which is difficult to verify statically; a
//!   condition variable selected by subscript is taken as one per thread

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::threads::{Role, ThreadOpKind};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::thread_api::{self, ProjectFunctions, ThreadCall};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Default)]
pub struct Con38C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Con38C {
    fn rule_id(&self) -> &'static str {
        "CON38-C"
    }

    fn description(&self) -> &'static str {
        "Preserve thread safety and liveness when using condition variables"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "CON38-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Con38C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let project = self.project.borrow();
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(signal) = thread_api::thread_op_of_kind(
                &call_node,
                source,
                project.as_ref(),
                ThreadOpKind::CondSignal,
            ) {
                self.report_violation(&call_node, &signal, source, violations);
            }
        }
    }

    fn report_violation(
        &self,
        node: &Node,
        signal: &ThreadCall,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let line = node.start_position().row + 1;
        let column = node.start_position().column + 1;

        let (cond_var, is_array_access) = signal
            .operand(Role::Cond)
            .map(|cond| self.condition_variable(&cond, source))
            .unwrap_or_else(|| ("condition variable".to_string(), false));

        // Don't flag if the condition variable is accessed via array subscript
        // (indicates unique condition variable per thread, which is compliant)
        if is_array_access {
            return;
        }

        let broadcast = signal
            .family
            .function_of(ThreadOpKind::CondBroadcast)
            .map_or_else(|| "a broadcast".to_string(), |name| format!("{name}()"));
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "Use of {}() with '{}' may cause deadlock if multiple threads wait with different predicates",
                signal.name, cond_var
            ),
            file_path: String::new(),
            line,
            column,
            suggestion: Some(format!(
                "Consider using {broadcast} to wake all waiting threads and ensure liveness. \
                Alternatively, use unique condition variables per thread if signaling specific threads."
            )),
            ..Default::default()
        });
    }

    /// The condition variable's spelling (without a leading `&`) and whether
    /// it is selected by subscript.
    fn condition_variable(&self, cond: &Node, source: &str) -> (String, bool) {
        let is_array_access = cond.kind() == "subscript_expression"
            || query::find_first_descendant(*cond, |n| n.kind() == "subscript_expression")
                .is_some();
        let var_name = get_node_text(cond, source)
            .trim()
            .trim_start_matches('&')
            .to_string();
        (var_name, is_array_access)
    }
}
