// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! POS50-C: Declare objects shared between POSIX threads with appropriate storage durations
//!
//! This rule detects passing the address of automatic (local) or thread-local storage variables
//! to pthread_create(), which can lead to undefined behavior when the thread outlives the
//! variable's lifetime.
//!
//! Violations:
//! - Passing the address of an automatic (local) or thread-local object to
//!   `pthread_create()`, however the thread is joined afterwards
//!
//! Compliant:
//! - Pass address of static/global variables
//! - Pass dynamically allocated memory
//! - Pass pointers with appropriate lifetimes
//!
//! ## Detection Strategy:
//! - Find POSIX thread creations by their thread-API contract
//!   (`thread_api::thread_op`), so a parameter or project function spelled
//!   `pthread_create` is not one
//! - Ask the analysis CON34-C shares (`thread_storage::passed_object`) what
//!   the argument names, by declaration
//! - Separately, a filesystem check followed by a use of the same name

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::threads::ThreadOpKind;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::thread_api::{self, Family, ProjectFunctions};
use crate::utility::cert_c::thread_storage::{self, SharedStorage};
use lang_parsing_substrate::query;
use std::cell::RefCell;

/// POS50-C: Declare objects shared between POSIX threads with appropriate storage durations
#[derive(Default)]
pub struct Pos50C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Pos50C {
    fn rule_id(&self) -> &'static str {
        "POS50-C"
    }

    fn description(&self) -> &'static str {
        "Declare objects shared between POSIX threads with appropriate storage durations"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "POS50-C"
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        self.check_toctou(node, source, &mut violations);
        violations
    }
}

impl Pos50C {
    /// Report each POSIX thread creation that hands its thread the address
    /// of an automatic or thread-local object.
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let project = self.project.borrow();
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            let Some(create) = thread_api::thread_op_of_kind(
                &n,
                source,
                project.as_ref(),
                ThreadOpKind::ThreadCreate,
            ) else {
                continue;
            };
            if create.family != Family::Posix {
                continue;
            }
            let Some(passed) = thread_storage::passed_object(&create, source) else {
                continue;
            };
            let storage = match passed.storage {
                SharedStorage::Automatic => "automatic",
                SharedStorage::ThreadLocal => "thread-local",
            };
            let position = n.start_position();
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                line: position.row + 1,
                column: position.column + 1,
                file_path: String::new(),
                message: format!(
                    "Passing address of {storage} storage '{}' to {}(). \
                     Another thread's access to it is implementation-defined, \
                     even when the thread is joined before it goes out of scope.",
                    passed.name, create.name
                ),
                suggestion: Some(
                    "Use static storage duration (global/static variables) or dynamically \
                     allocated memory for data shared between threads."
                        .to_string(),
                ),
                requires_manual_review: None,
            });
        }
    }

    // --- TOCTOU detection ---

    /// Check if a function name is a filesystem check function (check phase of TOCTOU)
    fn is_check_function(name: &str) -> bool {
        matches!(
            name,
            "stat" | "lstat" | "fstat" | "access" | "faccessat" | "euidaccess"
        )
    }

    /// Check if a function name is a filesystem use function (use phase of TOCTOU)
    fn is_use_function(name: &str) -> bool {
        matches!(
            name,
            "fopen"
                | "open"
                | "openat"
                | "creat"
                | "freopen"
                | "remove"
                | "unlink"
                | "rename"
                | "chmod"
                | "chown"
                | "truncate"
                | "mkdir"
                | "rmdir"
                | "link"
                | "symlink"
        )
    }

    /// Extract the path argument from a check or use function call.
    /// Returns the text of the first argument (which is the path for these functions).
    fn extract_path_arg<'a>(call_node: &Node<'a>, source: &'a str) -> Option<&'a str> {
        let args = call_node.child_by_field_name("arguments")?;
        let mut cursor = args.walk();
        for child in args.children(&mut cursor) {
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source));
                }
                return None; // Non-identifier first arg (e.g., string literal) — skip
            }
        }
        None
    }

    /// Walk all function definitions and check for TOCTOU patterns.
    fn check_toctou(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(body) = n.child_by_field_name("body") {
                self.check_toctou_in_body(&body, source, violations);
            }
        }
    }

    /// Collect all call_expression nodes in order from a function body,
    /// then look for check→use pairs on the same path variable.
    fn check_toctou_in_body(&self, body: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut calls: Vec<(String, String, usize, usize)> = Vec::new(); // (func_name, path_var, line, col)
        self.collect_calls_in_order(body, source, &mut calls);

        // Look for check→use pairs on the same path variable
        for i in 0..calls.len() {
            let (ref check_func, ref check_path, _, _) = calls[i];
            if !Self::is_check_function(check_func) {
                continue;
            }
            // Look for a subsequent use function on the same path
            for (use_func, use_path, use_line, use_col) in calls.iter().skip(i + 1) {
                if Self::is_use_function(use_func) && check_path == use_path {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        line: *use_line,
                        column: *use_col,
                        file_path: String::new(),
                        message: format!(
                            "TOCTOU race condition: {}() checks '{}' then {}() uses it. \
                             The file state may change between the check and use.",
                            check_func, check_path, use_func
                        ),
                        suggestion: Some(
                            "Use atomic file operations (e.g., open() with O_CREAT|O_EXCL) \
                             instead of separate check-then-use sequences."
                                .to_string(),
                        ),
                        requires_manual_review: None,
                    });
                    break; // Only flag first use after this check
                }
            }
        }
    }

    /// Collect function calls in source order from a subtree
    fn collect_calls_in_order(
        &self,
        node: &Node,
        source: &str,
        calls: &mut Vec<(String, String, usize, usize)>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);
                if Self::is_check_function(func_name) || Self::is_use_function(func_name) {
                    if let Some(path_var) = Self::extract_path_arg(&n, source) {
                        calls.push((
                            func_name.to_string(),
                            path_var.to_string(),
                            n.start_position().row + 1,
                            n.start_position().column + 1,
                        ));
                    }
                }
            }
        }
    }
}
