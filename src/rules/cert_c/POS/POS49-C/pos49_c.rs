// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::ProjectContext;
use crate::manifest::Severity;
use crate::settings::threads::ThreadOpKind;
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::thread_api::{self, ProjectFunctions};
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::collections::HashSet;
use tree_sitter::Node;

#[derive(Default)]
pub struct Pos49C {
    /// The project's function definitions in every scanned file, for a
    /// library name the project defines itself.
    project: RefCell<Option<ProjectFunctions>>,
}

impl CertRule for Pos49C {
    fn rule_id(&self) -> &'static str {
        "POS49-C"
    }

    fn description(&self) -> &'static str {
        "Do not access shared bit-fields from multiple threads without mutex protection"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        self.rule_id()
    }

    fn set_project_context(&self, context: &ProjectContext) {
        *self.project.borrow_mut() = Some(context.function_summaries.clone());
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        // Collect actual bit-field names from struct declarations (AST-based)
        let bitfield_names = self.collect_bitfield_names(root, source);
        if bitfield_names.is_empty() {
            return Vec::new();
        }

        let mut violations = Vec::new();
        self.check_node(root, source, &bitfield_names, &mut violations);
        violations
    }
}

impl Pos49C {
    /// Walk the AST to find all field names declared with a bitfield_clause
    /// (e.g., `unsigned int flag1 : 1;` inside a struct).
    fn collect_bitfield_names<'a>(&self, node: &Node<'a>, source: &str) -> HashSet<String> {
        let mut names = HashSet::new();
        self.collect_bitfield_names_inner(node, source, &mut names);
        names
    }

    fn collect_bitfield_names_inner<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        names: &mut HashSet<String>,
    ) {
        if node.kind() == "field_declaration" {
            // Check if this field_declaration has a bitfield_clause child
            let mut has_bitfield = false;
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "bitfield_clause" {
                    has_bitfield = true;
                    break;
                }
            }
            if has_bitfield {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "field_identifier" {
                        let name = get_node_text(&child, source).trim().to_string();
                        if !name.is_empty() {
                            names.insert(name);
                        }
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_bitfield_names_inner(&child, source, names);
        }
    }

    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        bitfield_names: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() == "field_expression" {
            if let Some(field) = node.child_by_field_name("field") {
                let field_name = get_node_text(&field, source).trim().to_string();

                // Only flag if this field is a known bit-field from a struct in this file
                if bitfield_names.contains(&field_name) {
                    if let Some(parent) = node.parent() {
                        if matches!(parent.kind(), "assignment_expression" | "update_expression") {
                            if !self.is_within_critical_section(node, source) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    message: format!(
                                        "Bit-field '{}' may be accessed from multiple threads without mutex protection",
                                        field_name
                                    ),
                                    file_path: String::new(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    suggestion: Some(
                                        "Protect bit-field access with pthread_mutex_lock/unlock"
                                            .to_string(),
                                    ),
                                    requires_manual_review: Some(true),
                                });
                            }
                        }
                    }
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, bitfield_names, violations);
        }
    }

    /// Whether a block around `node` makes a lock call before it and an
    /// unlock call after it. Calls, not text: a comment naming a lock is not
    /// one.
    fn is_within_critical_section(&self, node: &Node, source: &str) -> bool {
        let at = node.start_byte();
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "compound_statement" {
                let calls = query::find_descendants_of_kind(parent, "call_expression");
                let has_lock_before = calls
                    .iter()
                    .any(|c| c.start_byte() < at && self.is_lock_call(c, source, true));
                let has_unlock_after = calls
                    .iter()
                    .any(|c| c.start_byte() > at && self.is_lock_call(c, source, false));
                if has_lock_before && has_unlock_after {
                    return true;
                }
            }
            current = parent.parent();
        }
        false
    }

    /// Whether `call` locks (`lock`) or unlocks a mutex: by its thread-API
    /// contract (C11, POSIX, declared families), or, for a callee no family
    /// describes, a project wrapper whose name ends in `mutex_lock` /
    /// `mutex_unlock`, or a Win32 critical section or slim reader/writer
    /// lock. The name is read only from a callee that resolves to a function
    /// (ADR-0006): a function pointer or `ops->mutex_lock` is not credited.
    fn is_lock_call(&self, call: &Node, source: &str, lock: bool) -> bool {
        let project = self.project.borrow();
        if let Some(op) = thread_api::thread_op(call, source, project.as_ref()) {
            let kind = if lock {
                ThreadOpKind::MutexLock
            } else {
                ThreadOpKind::MutexUnlock
            };
            return op.kind() == kind;
        }
        let Some(name) = thread_api::called_function(call, source) else {
            return false;
        };
        if lock {
            name.ends_with("mutex_lock")
                || name == "EnterCriticalSection"
                || name.starts_with("AcquireSRWLock")
        } else {
            name.ends_with("mutex_unlock")
                || name == "LeaveCriticalSection"
                || name.starts_with("ReleaseSRWLock")
        }
    }
}
