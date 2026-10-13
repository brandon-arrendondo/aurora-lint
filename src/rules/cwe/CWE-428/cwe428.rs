// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! CWE-428: Unquoted search path or element
//!
//! Detects `CreateProcess*` handed a command line whose unquoted executable
//! path contains a space: Windows tries each space-separated prefix as a
//! program (`C:\Program.exe` before `C:\Program Files\App\app.exe`), so a
//! file planted at a prefix runs instead (path interception).
//!
//! The registry least-privilege check this rule once also carried is
//! CWE-272's (`src/rules/cwe/CWE-272/`).

use super::super::{CertRule, RuleViolation};
use crate::manifest::Severity;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

/// Functions that take a command line string that should have quoted paths.
/// (function_name, argument_index of lpCommandLine, 0-based)
const CREATE_PROCESS_FUNCTIONS: &[(&str, usize)] = &[
    ("CreateProcessA", 1),
    ("CreateProcessW", 1),
    ("CreateProcessAsUserA", 2),
    ("CreateProcessAsUserW", 2),
];

/// The CWE-428 checker.
pub struct Cwe428;

impl Cwe428 {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_call(&call, source, violations);
        }
    }

    fn check_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let func_name = match node.child_by_field_name("function") {
            Some(f) => get_node_text(&f, source).to_string(),
            None => return,
        };

        let args = match node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        for &(cp_func, arg_idx) in CREATE_PROCESS_FUNCTIONS {
            if func_name == cp_func {
                if let Some(arg) = self.get_nth_argument(&args, arg_idx) {
                    self.check_unquoted_path(&arg, source, &func_name, violations);
                }
                return;
            }
        }
    }

    /// Check if a CreateProcess command line argument has an unquoted path with spaces.
    fn check_unquoted_path(
        &self,
        arg: &Node,
        source: &str,
        func_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Only check string literals
        if arg.kind() != "string_literal" {
            return;
        }

        let text = get_node_text(arg, source);
        let content = text.trim_matches('"');

        // Skip NULL or empty
        if content.is_empty() || text == "NULL" || text == "0" {
            return;
        }

        // Check if path contains a space
        if !content.contains(' ') {
            return;
        }

        // Check if the path is properly quoted with escaped quotes
        // Good: "\"C:\\Program Files\\App\" arg1 arg2"
        // Bad:  "C:\\Program Files\\App arg1 arg2"
        if content.starts_with("\\\"") || content.starts_with("\"") {
            return; // Properly quoted
        }

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "Unquoted path with spaces in '{}' command line. \
                 This allows path interception attacks.",
                func_name
            ),
            file_path: String::new(),
            line: arg.start_position().row + 1,
            column: arg.start_position().column + 1,
            suggestion: Some(
                "Quote the executable path: \\\"C:\\\\Program Files\\\\App\\\" arg1 arg2"
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    fn get_nth_argument<'a>(&self, args: &Node<'a>, index: usize) -> Option<Node<'a>> {
        let mut count = 0;
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                let kind = child.kind();
                if kind != "(" && kind != ")" && kind != "," {
                    if count == index {
                        return Some(child);
                    }
                    count += 1;
                }
            }
        }
        None
    }
}

impl CertRule for Cwe428 {
    fn rule_id(&self) -> &'static str {
        "CWE-428"
    }

    fn description(&self) -> &'static str {
        "Quote an executable path containing a space in a CreateProcess command line"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn cert_id(&self) -> &'static str {
        "CWE-428"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}
