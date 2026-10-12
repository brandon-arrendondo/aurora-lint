// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON01-C: Acquire and release synchronization primitives in the same module, at the same level of abstraction
//!
//! This rule detects functions that unlock mutexes they didn't lock themselves,
//! which breaks the acquire-release pairing and can lead to double-unlock errors.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int verify_balance(int amount) {
//!   if (account_balance - amount < MIN_BALANCE) {
//!     mtx_unlock(&mp);  // WRONG: unlocks mutex acquired elsewhere
//!     return -1;
//!   }
//!   return 0;
//! }
//!
//! void debit(int amount) {
//!   mtx_lock(&mp);
//!   if (verify_balance(amount) == -1) {
//!     mtx_unlock(&mp);  // Double unlock if balance check fails
//!     return;
//!   }
//!   account_balance -= amount;
//!   mtx_unlock(&mp);
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! static int verify_balance(int amount) {
//!   if (account_balance - amount < MIN_BALANCE) {
//!     return -1;  // Signal error without touching mutex
//!   }
//!   return 0;
//! }
//!
//! int debit(int amount) {
//!   if (mtx_lock(&mp) == thrd_error) return -1;
//!
//!   if (verify_balance(amount)) {
//!     mtx_unlock(&mp);
//!     return -1;
//!   }
//!
//!   account_balance -= amount;
//!   mtx_unlock(&mp);
//!   return 0;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find mutex lock and unlock calls by their thread-API contract
//!   (`thread_api::thread_op`): C11, POSIX and any declared family, with a
//!   timed or try lock counting as an acquire
//! - Identify the mutex by declaration and member path
//!   (`thread_api::sync_object`), not by the argument's spelling
//! - Report an unlock of a mutex the same function never locks

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::threads::{Role, ThreadOpKind};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::thread_api::{self, ProjectFunctions, SyncObject};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Default)]
pub struct Con01C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Con01C {
    fn rule_id(&self) -> &'static str {
        "CON01-C"
    }

    fn description(&self) -> &'static str {
        "Acquire and release synchronization primitives in the same module, at the same level of abstraction"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "CON01-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Find all function definitions
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function(&func_node, source, &mut violations);
        }

        violations
    }
}

impl Con01C {
    fn check_function(&self, func_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Get function name
        let func_name = if let Some(declarator) = func_node.child_by_field_name("declarator") {
            self.get_function_name(&declarator, source)
        } else {
            return;
        };

        // Get function body
        let body = if let Some(body_node) = func_node.child_by_field_name("body") {
            body_node
        } else {
            return;
        };

        // Track which mutexes are locked and unlocked in this function
        let mut locked_mutexes: HashSet<SyncObject> = HashSet::new();
        let mut unlocked_mutexes: Vec<(SyncObject, String, usize, usize)> = Vec::new();

        // Analyze the function body
        self.analyze_body(&body, source, &mut locked_mutexes, &mut unlocked_mutexes);

        // Check for unlocks without corresponding locks
        for (mutex, mutex_name, line, column) in unlocked_mutexes {
            if !locked_mutexes.contains(&mutex) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Function '{}' unlocks mutex '{}' without acquiring it in the same function. Acquire and release should occur at the same abstraction level.",
                        func_name,
                        mutex_name
                    ),
                    file_path: String::new(),
                    line,
                    column,
                    suggestion: Some(
                        "Ensure this function acquires the mutex before releasing it, or refactor so lock/unlock occur in the same function".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn get_function_name(&self, declarator: &Node, source: &str) -> String {
        // Navigate to the identifier
        if declarator.kind() == "function_declarator" {
            if let Some(inner_declarator) = declarator.child_by_field_name("declarator") {
                return get_node_text(&inner_declarator, source).to_string();
            }
        } else if declarator.kind() == "identifier" {
            return get_node_text(declarator, source).to_string();
        }

        // Try to find identifier in children
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if child.kind() == "identifier" {
                    return get_node_text(&child, source).to_string();
                }
                if child.kind() == "function_declarator" {
                    return self.get_function_name(&child, source);
                }
            }
        }

        "unknown".to_string()
    }

    fn analyze_body(
        &self,
        node: &Node,
        source: &str,
        locked_mutexes: &mut HashSet<SyncObject>,
        unlocked_mutexes: &mut Vec<(SyncObject, String, usize, usize)>,
    ) {
        let project = self.project.borrow();
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(call) = thread_api::thread_op(&call_node, source, project.as_ref()) else {
                continue;
            };
            let Some(operand) = call.operand(Role::Object) else {
                continue;
            };
            let Some(mutex) = thread_api::sync_object(&operand, source) else {
                continue;
            };
            match call.kind() {
                ThreadOpKind::MutexLock => {
                    locked_mutexes.insert(mutex);
                }
                ThreadOpKind::MutexUnlock => {
                    let spelling = get_node_text(&operand, source)
                        .trim()
                        .trim_start_matches('&')
                        .to_string();
                    let line = call_node.start_position().row + 1;
                    let column = call_node.start_position().column + 1;
                    unlocked_mutexes.push((mutex, spelling, line, column));
                }
                _ => {}
            }
        }
    }
}
