// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON36-C: Wrap functions that can spuriously wake up in a loop
//!
//! This rule detects a condition wait that can wake spuriously and is not
//! inside a loop: wrapped in an 'if' statement instead, or not guarded at
//! all. Such a wait can return without a signal, so the condition must be
//! re-checked after waking. The hazard is read API-neutrally
//! (`docs/design/thread-api-families.md`): C11's `cnd_wait()` and
//! `cnd_timedwait()`, POSIX's `pthread_cond_wait()` family, and any declared
//! wait whose contract says it can wake spuriously. A wait that cannot
//! (FreeRTOS has no condition variable) is not this hazard.
//!
//! A wait in no loop and no 'if' whose condition is reached through one of
//! the enclosing function's parameters is a wrapper: the loop that re-checks
//! belongs to its callers, which this rule does not follow, so it is not
//! reported.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! if (list.next == NULL) {
//!   if (thrd_success != cnd_wait(&condition, &lock)) {
//!     /* Handle error */
//!   }
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! while (list.next == NULL) {
//!   if (thrd_success != cnd_wait(&condition, &lock)) {
//!     /* Handle error */
//!   }
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find calls whose thread-API contract is a spuriously-waking condition
//!   wait (`thread_api::thread_op`)
//! - Report one with no enclosing loop in its function, unless it is a
//!   wrapper's (above)

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::threads::{Role, ThreadOpKind};
use crate::utility::cert_c::ast_utils::{
    get_node_text, resolve_identifier_binding, IdentifierBinding,
};
use crate::utility::cert_c::thread_api::{self, ProjectFunctions};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Default)]
pub struct Con36C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

/// Where a wait sits relative to the statements that could re-check it.
enum Placement {
    /// Inside a loop in its own function.
    InLoop,
    /// Under an 'if' and no loop.
    InIf,
    /// Under neither.
    Bare,
}

impl CertRule for Con36C {
    fn rule_id(&self) -> &'static str {
        "CON36-C"
    }

    fn description(&self) -> &'static str {
        "Wrap functions that can spuriously wake up in a loop"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "CON36-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for condition variable wait calls
        self.check_node(node, source, &mut violations);

        violations
    }
}

impl Con36C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_wait_call(&call, source, violations);
        }
    }

    fn check_wait_call(&self, call_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let project = self.project.borrow();
        let Some(wait) = thread_api::thread_op_of_kind(
            call_node,
            source,
            project.as_ref(),
            ThreadOpKind::CondWait,
        ) else {
            return;
        };
        if wait.op.spurious != Some(true) {
            return;
        }
        let func_name = &wait.name;
        let (message, suggestion) = match placement(call_node) {
            Placement::InLoop => return,
            Placement::InIf => (
                format!(
                    "Call to '{func_name}' is wrapped in an 'if' statement. Use 'while' loop to \
                     handle spurious wake-ups."
                ),
                "Replace the 'if' statement with a 'while' loop to re-check the condition after \
                 wake-up",
            ),
            Placement::Bare => {
                let wrapper = wait
                    .operand(Role::Cond)
                    .is_some_and(|cond| reaches_a_parameter(&cond, source));
                if wrapper {
                    return;
                }
                (
                    format!(
                        "Call to '{func_name}' is not inside a loop. It can wake without a \
                         signal, so wrap it in a 'while' loop that re-checks the condition."
                    ),
                    "Wait in a 'while' loop that re-checks the condition after wake-up",
                )
            }
        };
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Medium,
            message,
            file_path: String::new(),
            line: call_node.start_position().row + 1,
            column: call_node.start_position().column + 1,
            suggestion: Some(suggestion.to_string()),
            ..Default::default()
        });
    }
}

/// Where `node` sits in its function: in a loop, else under an 'if', else
/// neither.
fn placement(node: &Node) -> Placement {
    let mut current = node.parent();
    let mut found_if = false;
    while let Some(parent) = current {
        match parent.kind() {
            "if_statement" => found_if = true,
            "while_statement" | "do_statement" | "for_statement" => return Placement::InLoop,
            "function_definition" => break,
            _ => {}
        }
        current = parent.parent();
    }
    if found_if {
        Placement::InIf
    } else {
        Placement::Bare
    }
}

/// Whether the condition operand is reached through a parameter of the
/// enclosing function: `cond`, `&p->cond` or `&w.cond` where `cond`, `p` or
/// `w` is a parameter.
fn reaches_a_parameter(operand: &Node, source: &str) -> bool {
    let mut node = crate::analyze::init_state::strip_arg_casts(operand);
    loop {
        node = match node.kind() {
            "pointer_expression" | "field_expression" => match node.child_by_field_name("argument")
            {
                Some(inner) => crate::analyze::init_state::strip_arg_casts(&inner),
                None => return false,
            },
            "subscript_expression" => match node.child_by_field_name("argument") {
                Some(inner) => crate::analyze::init_state::strip_arg_casts(&inner),
                None => return false,
            },
            "identifier" => {
                let name = get_node_text(&node, source);
                return matches!(
                    resolve_identifier_binding(&node, name, source),
                    Some(IdentifierBinding::Parameter(_))
                );
            }
            _ => return false,
        };
    }
}
