// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON05-C: Do not perform operations that can block while holding a lock
//!
//! This rule detects blocking operations (I/O, network operations, etc.) that
//! occur between mutex lock and unlock calls. Blocking while holding a lock
//! can cause other threads waiting for the lock to also block, potentially
//! causing deadlock or performance degradation.
//!
//! Noncompliant pattern:
//!   mtx_lock(&mutex);
//!   fopen("file", "r");    // Blocking I/O while locked - VIOLATION
//!   mtx_unlock(&mutex);
//!
//! Detection: the analysis POS52-C shares (`blocking_under_lock`). A call
//! can block when it is a thread-API sleep or reaches a C or POSIX library
//! function that may block (stream, descriptor and socket I/O, waits), and
//! it is reported when a mutex of any thread-API family is held on every
//! path to it. Acquiring another mutex is CON35-C's question, not this
//! rule's; a socket call with `MSG_DONTWAIT` does not block.
//!
//! Compliant pattern:
//!   fopen("file", "r");    // I/O before acquiring lock
//!   mtx_lock(&mutex);
//!   // ... access shared data ...
//!   mtx_unlock(&mutex);

use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::blocking_under_lock;
use crate::utility::cert_c::thread_api::ProjectFunctions;
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Default)]
pub struct Con05C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Con05C {
    fn rule_id(&self) -> &'static str {
        "CON05-C"
    }

    fn description(&self) -> &'static str {
        "Do not perform operations that can block while holding a lock"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "CON05-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let project = self.project.borrow();
        blocking_under_lock::blocking_under_lock(node, source, project.as_ref())
            .into_iter()
            .filter_map(|call| {
                let held = call.held.first()?;
                let start = call.node.start_position();
                Some(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Blocking operation '{}()' called while holding mutex '{}' (locked at \
                         line {}). This can cause other threads to block unnecessarily",
                        call.callee, held.mutex, held.line
                    ),
                    file_path: String::new(),
                    line: start.row + 1,
                    column: start.column + 1,
                    suggestion: Some(
                        "Move blocking I/O operations outside the locked region. Perform I/O \
                         before acquiring the lock or after releasing it"
                            .to_string(),
                    ),
                    ..Default::default()
                })
            })
            .collect()
    }
}
