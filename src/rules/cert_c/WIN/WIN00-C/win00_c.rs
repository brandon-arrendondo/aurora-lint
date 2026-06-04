// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Ryan Urchick

//! WIN00-C: Be specific when dynamically loading libraries
//!
//! Using LoadLibrary() without specifying search paths can allow DLL hijacking attacks.

use tree_sitter::Node;

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;

pub struct Win00C;

impl CertRule for Win00C {
    fn rule_id(&self) -> &'static str {
        "WIN00-C"
    }

    fn description(&self) -> &'static str {
        "Be specific when dynamically loading libraries"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "WIN00-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Win00C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() == "call_expression" {
            if let Some(func_node) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);
                if func_name.trim() == "LoadLibrary" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        message:
                            "Using LoadLibrary() without specifying search paths enables DLL hijacking attacks. \
                            An attacker could place a malicious DLL on the search path."
                                .to_string(),
                        suggestion: Some(
                            "Use LoadLibraryEx() with explicit search flags like LOAD_LIBRARY_SEARCH_APPLICATION_DIR \
                            or LOAD_LIBRARY_SEARCH_SYSTEM32 to control DLL search paths.".to_string()
                        ),
                        requires_manual_review: None,
                    });
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, violations);
        }
    }
}
