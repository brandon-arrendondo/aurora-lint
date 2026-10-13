// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CON33-C: Avoid race conditions when using library functions
//!
//! This rule detects usage of non-reentrant/non-thread-safe C standard library
//! functions that can cause race conditions in multithreaded programs.
//!
//! Functions like strtok(), asctime(), strerror(), rand(), etc. return pointers
//! to static/function-allocated memory or maintain per-process state, making them
//! unsafe for use across multiple threads without synchronization.
//!
//! A call is read as the library's only when its callee resolves to the
//! library function ([`thread_api::library_call`]): not when the project
//! defines a function or a macro of that name, or calls through an object
//! that happens to be named like one.

use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::thread_api::{self, ProjectFunctions};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Default)]
pub struct Con33C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Con33C {
    fn rule_id(&self) -> &'static str {
        "CON33-C"
    }

    fn description(&self) -> &'static str {
        "Avoid race conditions when using library functions"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "CON33-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Con33C {
    /// Check the AST for non-thread-safe library function calls
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let project = self.project.borrow();
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(callee) = call.child_by_field_name("function") else {
                continue;
            };
            // Check if it's a non-thread-safe library function: the table
            // first, since resolving the callee reads the whole file.
            let function_name = get_node_text(&callee, source);
            if let Some(remediation) = get_unsafe_function_remediation(function_name) {
                if thread_api::library_call(&call, source, project.as_ref()) == Some(function_name)
                {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        file_path: String::new(), // Filled by caller
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        severity: self.severity(),
                        message: format!(
                            "Call to non-thread-safe function '{}'. {}",
                            function_name, remediation
                        ),
                        suggestion: Some(remediation.to_string()),
                        ..Default::default()
                    });
                }
            }
        }
    }
}

/// Returns the remediation message for non-thread-safe functions
fn get_unsafe_function_remediation(function_name: &str) -> Option<&'static str> {
    match function_name {
        // Insecure temporary file creation (TOCTOU race)
        "mktemp" | "tmpnam" | "tempnam" => {
            Some("Use mkstemp() or tmpfile() instead. mktemp/tmpnam/tempnam are insecure due to TOCTOU race conditions between name generation and file creation")
        }

        // String tokenization
        "strtok" => {
            Some("Use strtok_r() (POSIX) which provides a thread-safe alternative with user-provided context")
        }

        // Error messages
        "strerror" => {
            Some("Use strerror_r() (POSIX) or strerror_s() (C11 Annex K) for thread-safe error reporting")
        }

        // Time functions
        "asctime" | "ctime" | "localtime" | "gmtime" => {
            Some("Use strftime() with localtime_r()/gmtime_r() (POSIX), or use thread-safe time conversion functions")
        }

        // Locale
        "setlocale" => {
            Some("Protect multithreaded access to locale-specific functions with a mutex")
        }

        // Atomic initialization
        "ATOMIC_VAR_INIT" | "atomic_init" => {
            Some("Do not attempt to initialize an atomic variable from multiple threads")
        }

        // Character conversion functions with static state
        "mbrtoc16" | "c16rtomb" | "mbrtoc32" | "c32rtomb" => {
            Some("Do not call with a null mbstate_t* argument in multithreaded contexts")
        }

        _ => None,
    }
}
