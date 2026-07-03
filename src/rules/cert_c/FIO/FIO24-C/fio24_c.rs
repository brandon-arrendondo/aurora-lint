//! FIO24-C: Do not open a file that is already open
//!
//! This rule detects:
//! 1. When the same file is opened multiple times without closing in between.
//! 2. When a file/handle/descriptor is closed multiple times (double close).
//!
//! Double-close is undefined behavior for FILE* (C11 7.21.3) and can cause
//! use-after-free for file descriptors and Windows handles.
//!
//! ## Detection Strategy:
//! - Track open/close calls for FILE*, POSIX fd, and Windows HANDLE
//! - Detect duplicate opens on the same filename while still open
//! - Detect duplicate close on the same variable without intervening reopen

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Fio24C;

/// Functions that open a resource (returning a handle/pointer/fd).
const OPEN_FUNCTIONS: &[&str] = &[
    "fopen",
    "freopen",
    "fdopen",
    "tmpfile",
    "open",
    "_open",
    "OPEN",
    "CreateFile",
    "CreateFileA",
    "CreateFileW",
    "CreateNamedPipe",
    "CreateNamedPipeA",
    "CreateNamedPipeW",
];

/// Functions that close a resource.
const CLOSE_FUNCTIONS: &[&str] = &[
    "fclose",
    "close",
    "_close",
    "CLOSE",
    "CLOSE_SOCKET",
    "closesocket",
    "CloseHandle",
];

impl CertRule for Fio24C {
    fn rule_id(&self) -> &'static str {
        "FIO24-C"
    }

    fn description(&self) -> &'static str {
        "Do not open a file that is already open"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "FIO24-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track open files: filename -> (variable_name, opening_location)
        let mut open_files: HashMap<String, Vec<(String, tree_sitter::Point)>> = HashMap::new();
        // Track file pointer variables: variable_name -> filename
        let mut file_pointers: HashMap<String, String> = HashMap::new();
        // Track closed variables for double-close detection: variable_name -> close_line
        let mut closed_vars: HashMap<String, usize> = HashMap::new();

        // Process each function body independently
        self.walk_functions(
            node,
            source,
            &mut violations,
            &mut open_files,
            &mut file_pointers,
            &mut closed_vars,
        );

        violations
    }
}

impl Fio24C {
    /// Walk top-level and process each function body with fresh close-tracking state.
    fn walk_functions(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        open_files: &mut HashMap<String, Vec<(String, tree_sitter::Point)>>,
        file_pointers: &mut HashMap<String, String>,
        _closed_vars: &mut HashMap<String, usize>,
    ) {
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            // Each function gets its own double-close tracking scope
            let mut fn_closed: HashMap<String, usize> = HashMap::new();
            if let Some(body) = func.child_by_field_name("body") {
                self.check_node(
                    &body,
                    source,
                    violations,
                    open_files,
                    file_pointers,
                    &mut fn_closed,
                );
            }
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        open_files: &mut HashMap<String, Vec<(String, tree_sitter::Point)>>,
        file_pointers: &mut HashMap<String, String>,
        closed_vars: &mut HashMap<String, usize>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_call_expression(
                &call,
                source,
                violations,
                open_files,
                file_pointers,
                closed_vars,
            );
        }
    }

    fn check_call_expression(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        open_files: &mut HashMap<String, Vec<(String, tree_sitter::Point)>>,
        file_pointers: &mut HashMap<String, String>,
        closed_vars: &mut HashMap<String, usize>,
    ) {
        if let Some(func) = node.child_by_field_name("function") {
            let func_name = get_node_text(&func, source).trim().to_string();

            if func_name == "fopen" {
                self.check_fopen_call(node, source, violations, open_files, file_pointers);
            }

            if is_open_function(&func_name) {
                // An open call assigned to a variable clears its "closed" state
                let var_name = self.get_assigned_variable(node, source);
                if !var_name.is_empty() {
                    closed_vars.remove(&var_name);
                }
            } else if is_close_function(&func_name) {
                self.check_close_call(
                    node,
                    source,
                    violations,
                    closed_vars,
                    file_pointers,
                    open_files,
                );
            }
        }
    }

    fn check_fopen_call(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        open_files: &mut HashMap<String, Vec<(String, tree_sitter::Point)>>,
        file_pointers: &mut HashMap<String, String>,
    ) {
        // Get the first argument (filename)
        if let Some(args) = node.child_by_field_name("arguments") {
            if let Some(first_arg) = self.get_first_argument(&args) {
                let filename = get_node_text(&first_arg, source).trim().to_string();

                // Check if this file is already open
                if let Some(existing_opens) = open_files.get(&filename) {
                    if !existing_opens.is_empty() {
                        // File is already open - report violation
                        let start_point = node.start_position();
                        let prev_open = &existing_opens[0];

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "File '{}' is opened again while still open (previously opened at line {}). Opening the same file multiple times is implementation-defined and can cause race conditions.",
                                filename,
                                prev_open.1.row + 1
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Pass the file pointer as a function argument instead of reopening the file. Alternatively, close the file before opening it again.".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }

                // Track this open - get the variable name from parent assignment if present
                let var_name = self.get_assigned_variable(node, source);
                let location = node.start_position();

                open_files
                    .entry(filename.clone())
                    .or_default()
                    .push((var_name.clone(), location));

                if !var_name.is_empty() {
                    file_pointers.insert(var_name, filename);
                }
            }
        }
    }

    /// Check for double-close: if this variable was already closed without
    /// intervening reopen, flag the duplicate close.
    fn check_close_call(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        closed_vars: &mut HashMap<String, usize>,
        file_pointers: &mut HashMap<String, String>,
        open_files: &mut HashMap<String, Vec<(String, tree_sitter::Point)>>,
    ) {
        if let Some(args) = node.child_by_field_name("arguments") {
            if let Some(first_arg) = self.get_first_argument(&args) {
                let var_name = get_node_text(&first_arg, source).trim().to_string();
                let close_line = node.start_position().row + 1;

                // Check for double close
                if let Some(prev_close_line) = closed_vars.get(&var_name) {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "Resource '{}' is closed again after already being closed at line {}. Double close is undefined behavior.",
                            var_name, prev_close_line
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Remove the duplicate close call, or set the variable to NULL/INVALID_HANDLE_VALUE/-1 after the first close to prevent double close.".to_string()
                        ),
                        ..Default::default()
                    });
                } else {
                    // Record that this variable has been closed
                    closed_vars.insert(var_name.clone(), close_line);
                }

                // Also update the fopen tracking (for duplicate-open detection)
                if let Some(filename) = file_pointers.get(&var_name) {
                    if let Some(opens) = open_files.get_mut(filename) {
                        opens.retain(|(var, _)| var != &var_name);
                        if opens.is_empty() {
                            open_files.remove(&filename.clone());
                        }
                    }
                    file_pointers.remove(&var_name);
                }
            }
        }
    }

    fn get_first_argument<'a>(&self, args_node: &'a Node<'a>) -> Option<Node<'a>> {
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    return Some(child);
                }
            }
        }
        None
    }

    fn get_assigned_variable(&self, node: &Node, source: &str) -> String {
        // Look for parent assignment or declaration
        if let Some(parent) = node.parent() {
            match parent.kind() {
                "init_declarator" => {
                    // Variable declaration: FILE *fp = fopen(...)
                    if let Some(declarator) = parent.child_by_field_name("declarator") {
                        return self
                            .extract_identifier(&declarator, source)
                            .unwrap_or_default();
                    }
                }
                "assignment_expression" => {
                    // Variable assignment: fp = fopen(...)
                    if let Some(left) = parent.child_by_field_name("left") {
                        return get_node_text(&left, source).trim().to_string();
                    }
                }
                _ => {}
            }
        }
        String::new()
    }

    fn extract_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).trim().to_string());
        }

        // Recursively search for identifier in declarator
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(id) = self.extract_identifier(&child, source) {
                    return Some(id);
                }
            }
        }
        None
    }
}

fn is_open_function(name: &str) -> bool {
    OPEN_FUNCTIONS.contains(&name)
}

fn is_close_function(name: &str) -> bool {
    CLOSE_FUNCTIONS.contains(&name)
}
