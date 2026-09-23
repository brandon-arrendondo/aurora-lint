// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Pos49C;

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

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        self.rule_id()
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

    fn is_within_critical_section(&self, node: &Node, source: &str) -> bool {
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "compound_statement" {
                let node_pos = node.start_byte();
                let before_text = &source[parent.start_byte()..node_pos];
                let after_text = &source[node_pos..parent.end_byte()];

                let has_lock_before = before_text.contains("pthread_mutex_lock")
                    || before_text.contains("mutex_lock")
                    || before_text.contains("EnterCriticalSection")
                    || before_text.contains("AcquireSRWLock");
                let has_unlock_after = after_text.contains("pthread_mutex_unlock")
                    || after_text.contains("mutex_unlock")
                    || after_text.contains("LeaveCriticalSection")
                    || after_text.contains("ReleaseSRWLock");

                if has_lock_before && has_unlock_after {
                    return true;
                }
            }
            current = parent.parent();
        }
        false
    }
}
