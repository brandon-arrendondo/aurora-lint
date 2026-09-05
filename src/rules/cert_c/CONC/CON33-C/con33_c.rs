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

use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Default)]
pub struct Con33C;

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

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "CON33-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Con33C {
    /// Check the AST for non-thread-safe library function calls
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function_node) = call.child_by_field_name("function") {
                let raw_name = get_node_text(&function_node, source);
                let function_name = raw_name.trim().to_lowercase();
                let function_name = function_name.as_str();

                // Check if it's a non-thread-safe library function
                if let Some(remediation) = get_unsafe_function_remediation(function_name) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        file_path: String::new(), // Filled by caller
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        severity: self.severity(),
                        message: format!(
                            "Call to non-thread-safe function '{}'. {}",
                            raw_name.trim(),
                            remediation
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
