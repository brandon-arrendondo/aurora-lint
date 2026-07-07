// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

//! MEM06-C: Ensure that sensitive data is not written out to disk
//!
//! This rule detects cases where sensitive data (memory allocated with malloc/calloc/realloc)
//! is not properly protected from being written to disk through core dumps or page swapping.
//!
//! Violations:
//! - Using malloc() to allocate sensitive data without memory locking (mlock/VirtualLock)
//! - Using malloc() without disabling core dumps (setrlimit RLIMIT_CORE)
//!
//! Compliant Solutions:
//! - POSIX: Use setrlimit(RLIMIT_CORE, &limit) to disable core dumps
//! - POSIX: Use mlock()/munlock() to lock memory pages
//! - Windows: Use VirtualAlloc() with VirtualLock()/VirtualUnlock()

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;

/// MEM06-C: Ensure that sensitive data is not written out to disk
pub struct Mem06C;

impl CertRule for Mem06C {
    fn rule_id(&self) -> &'static str {
        "MEM06-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that sensitive data is not written out to disk"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MEM06-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Mem06C {
    /// Recursively check AST nodes for MEM06-C violations
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for malloc/calloc/realloc calls
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                // Check if this is a malloc/calloc/realloc call
                if func_name == "malloc" || func_name == "calloc" || func_name == "realloc" {
                    // Check if there's proper memory protection in the same scope
                    if !self.has_memory_protection(&n, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            file_path: String::new(),
                            message: format!(
                                "Sensitive data allocated with {} may be written to disk. \
                                Use mlock() (POSIX) or VirtualLock() (Windows) to lock memory pages, \
                                or use setrlimit(RLIMIT_CORE, 0) to disable core dumps.",
                                func_name
                            ),
                            suggestion: Some(
                                "Consider using mlock()/munlock() to prevent memory from being \
                                swapped to disk, or use setrlimit() to disable core dumps."
                                    .to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Check if memory protection mechanisms are present in the code
    ///
    /// This checks for:
    /// - setrlimit(RLIMIT_CORE, ...) calls (POSIX core dump disable)
    /// - mlock()/munlock() calls (POSIX memory locking)
    /// - VirtualLock()/VirtualUnlock() calls (Windows memory locking)
    /// - VirtualAlloc() usage (Windows secure allocation)
    fn has_memory_protection(&self, node: &Node, source: &str) -> bool {
        // Walk up to find the containing function or translation unit
        let mut parent = node.parent();
        while let Some(p) = parent {
            if p.kind() == "function_definition" || p.kind() == "translation_unit" {
                // Search within this scope for memory protection calls
                return self.search_for_protection(&p, source);
            }
            parent = p.parent();
        }
        false
    }

    /// Search for memory protection function calls within a node's scope
    fn search_for_protection(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func_node) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func_node, source);
            let func_name_str = func_name.trim();

            // Check for memory protection functions
            match func_name_str {
                // POSIX memory locking
                "mlock" | "munlock" | "mlockall" | "munlockall" => true,
                // Windows memory locking
                "VirtualLock" | "VirtualUnlock" => true,
                // Windows secure allocation
                "VirtualAlloc" => true,
                // POSIX resource limits (core dump disable)
                "setrlimit" => self.is_rlimit_core_call(&n, source),
                _ => false,
            }
        })
        .is_some()
    }

    /// Check if a setrlimit call is specifically for RLIMIT_CORE
    fn is_rlimit_core_call(&self, node: &Node, source: &str) -> bool {
        // Look for RLIMIT_CORE in the arguments
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let text = get_node_text(&child, source);
            if text.contains("RLIMIT_CORE") {
                return true;
            }
        }
        false
    }
}
