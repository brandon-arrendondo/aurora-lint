// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON37-C: Do not call signal() in a multithreaded program
//!
//! The C Standard (C11 7.14.1.1 paragraph 7) states that the use of the signal()
//! function in a multithreaded program results in undefined behavior.
//!
//! ## Rationale:
//! - Mixing signals and threads causes undefined behavior in C11
//! - Signal handlers execute in an unpredictable thread context
//! - Race conditions and data corruption can occur
//! - POSIX implementations provide defined behavior but are still discouraged
//!
//! ## Detection Strategy:
//! - A file is multithreaded when it creates or joins a thread or initializes
//!   a mutex, read by thread-API contract (C11, POSIX and any declared
//!   family), or calls a Win32 thread-spawn function
//! - Report each call that reaches the standard `signal()` there (not a
//!   project's own function of that name)

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::threads::ThreadOpKind;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::thread_api::{self, ProjectFunctions};
use lang_parsing_substrate::query;
use std::cell::RefCell;

/// Win32 thread-spawn functions, which no thread-API family describes yet.
const WIN32_SPAWNS: &[&str] = &["CreateThread", "_beginthread", "_beginthreadex"];

#[derive(Default)]
pub struct Con37C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Con37C {
    fn rule_id(&self) -> &'static str {
        "CON37-C"
    }

    fn description(&self) -> &'static str {
        "Do not call signal() in a multithreaded program"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "CON37-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let project = self.project.borrow();
        let project = project.as_ref();
        let calls = query::find_descendants_of_kind(*node, "call_expression");
        let threaded = calls.iter().any(|call| {
            if let Some(op) = thread_api::thread_op(call, source, project) {
                return matches!(
                    op.kind(),
                    ThreadOpKind::ThreadCreate | ThreadOpKind::ThreadJoin | ThreadOpKind::MutexInit
                );
            }
            call.child_by_field_name("function")
                .is_some_and(|f| WIN32_SPAWNS.contains(&get_node_text(&f, source).trim()))
        });
        if !threaded {
            return Vec::new();
        }
        calls
            .iter()
            .filter(|call| thread_api::library_call(call, source, project) == Some("signal"))
            .map(|call| RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: "Calling signal() in a multithreaded program causes undefined behavior."
                    .to_string(),
                file_path: String::new(),
                line: call.start_position().row + 1,
                column: call.start_position().column + 1,
                suggestion: Some(
                    "Use sigaction() on POSIX systems or platform-specific thread-safe \
                     alternatives."
                        .to_string(),
                ),
                requires_manual_review: None,
            })
            .collect()
    }
}
