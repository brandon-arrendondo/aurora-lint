// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! POS52-C: Do not perform operations that can block while holding a POSIX lock
//!
//! Blocking operations (I/O, network calls) should not be performed while
//! holding a mutex.
//!
//! Detection: the analysis CON05-C shares (`blocking_under_lock`). A call
//! can block when it is a thread-API sleep or reaches a C or POSIX library
//! function that may block (stream, descriptor and socket I/O, waits), and
//! it is reported when a POSIX mutex is held on every path to it. A socket
//! call whose flags include `MSG_DONTWAIT` does not block (CERT's compliant
//! solution); acquiring another mutex is CON35-C's question (CERT's EX1).

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::utility::cert_c::blocking_under_lock;
use crate::utility::cert_c::thread_api::{Family, ProjectFunctions};
use std::cell::RefCell;

#[derive(Default)]
pub struct Pos52C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Pos52C {
    fn rule_id(&self) -> &'static str {
        "POS52-C"
    }

    fn description(&self) -> &'static str {
        "Do not perform operations that can block while holding a POSIX lock"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "POS52-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let project = self.project.borrow();
        blocking_under_lock::blocking_under_lock(node, source, project.as_ref())
            .into_iter()
            .filter_map(|call| {
                let held = call.held.iter().find(|h| h.family == Family::Posix)?;
                let start = call.node.start_position();
                Some(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    line: start.row + 1,
                    column: start.column + 1,
                    file_path: String::new(),
                    message: format!(
                        "Blocking function '{}' called while holding mutex '{}' (locked at line \
                         {}). This can cause deadlocks and poor performance.",
                        call.callee, held.mutex, held.line
                    ),
                    suggestion: Some(
                        "Perform blocking operations before acquiring or after releasing the \
                         mutex."
                            .to_string(),
                    ),
                    requires_manual_review: None,
                })
            })
            .collect()
    }
}
