//! FIO22-C: Close files before spawning processes
//!
//! This rule detects when files are opened but not closed before spawning child processes
//! via system(), fork(), exec(), or similar functions.
//!
//! ## Key Issues:
//! - File descriptors inherited by child processes (security/access control issue)
//! - Resource exhaustion from unclosed file descriptors
//! - Data integrity risks from unflushed buffers
//! - Sensitive data exposure to spawned processes
//!
//! ## Detected Violations:
//! - fopen() followed by system() without intervening fclose()
//! - open() followed by fork()/exec() without close() or FD_CLOEXEC
//! - File still open in scope containing process spawn call
//!
//! ## Compliant Patterns:
//! - Closing files with fclose() before calling system()
//! - Using FD_CLOEXEC flag with fcntl() on file descriptors
//! - Using O_CLOEXEC flag with open() (Linux/POSIX)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Fio22C;

impl CertRule for Fio22C {
    fn rule_id(&self) -> &'static str {
        "FIO22-C"
    }

    fn description(&self) -> &'static str {
        "Close files before spawning processes"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "FIO22-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut checker = Fio22CChecker::new();
        checker.check_node(node, source, &mut violations);
        violations
    }
}

struct Fio22CChecker {
    /// Track open files: variable name -> line where opened
    open_files: HashMap<String, usize>,
}

impl Fio22CChecker {
    fn new() -> Self {
        Self {
            open_files: HashMap::new(),
        }
    }

    fn check_node(&mut self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        match node.kind() {
            "function_definition" => {
                // Process function body, tracking file open/close
                self.check_function_body(node, source, violations);
            }
            _ => {
                // Recursively check children
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.check_node(&child, source, violations);
                    }
                }
            }
        }
    }

    fn check_function_body(
        &mut self,
        func_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Reset state for each function
        self.open_files.clear();

        if let Some(body) = func_node.child_by_field_name("body") {
            self.check_compound_statement(&body, source, violations);
        }
    }

    fn check_compound_statement(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Process statements sequentially, tracking file operations
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.process_statement(&child, source, violations);
            }
        }
    }

    fn process_statement(
        &mut self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        match node.kind() {
            "expression_statement" | "declaration" => {
                // Check for file open operations
                if let Some(file_var) = self.find_file_open(node, source) {
                    let line = node.start_position().row + 1;
                    self.open_files.insert(file_var, line);
                }

                // Check for file close operations
                if let Some(file_var) = self.find_file_close(node, source) {
                    self.open_files.remove(&file_var);
                }

                // Check for FD_CLOEXEC flag being set
                if let Some(file_var) = self.find_cloexec_set(node, source) {
                    self.open_files.remove(&file_var);
                }

                // Check for process spawn operations
                if self.has_process_spawn(node, source) {
                    // Check if any files are still open
                    if !self.open_files.is_empty() {
                        let start_point = node.start_position();
                        let open_file_names: Vec<String> =
                            self.open_files.keys().cloned().collect();
                        violations.push(RuleViolation {
                            rule_id: "FIO22-C".to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Process spawned while file(s) still open: {} - files must be closed before spawning processes",
                                open_file_names.join(", ")
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Close all open files with fclose() before calling system(), fork(), or exec()".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
            "compound_statement" => {
                self.check_compound_statement(node, source, violations);
            }
            "if_statement" | "while_statement" | "for_statement" | "do_statement" => {
                // Check for FD_CLOEXEC being set in condition
                if let Some(file_var) = self.find_cloexec_set(node, source) {
                    self.open_files.remove(&file_var);
                }

                // Check if the condition contains a process spawn call
                if self.has_process_spawn(node, source) {
                    // Check if any files are still open
                    if !self.open_files.is_empty() {
                        let start_point = node.start_position();
                        let open_file_names: Vec<String> =
                            self.open_files.keys().cloned().collect();
                        violations.push(RuleViolation {
                            rule_id: "FIO22-C".to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Process spawned while file(s) still open: {} - files must be closed before spawning processes",
                                open_file_names.join(", ")
                            ),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Close all open files with fclose() before calling system(), fork(), or exec()".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }

                // Recursively check control flow statements
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        self.process_statement(&child, source, violations);
                    }
                }
            }
            _ => {}
        }
    }

    /// Check if this node contains a file open operation (fopen or open)
    fn find_file_open(&self, node: &Node, source: &str) -> Option<String> {
        // Look for patterns like: FILE *fp = fopen(...)
        if let Some(call) = self.find_call_expression(node, source) {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "fopen" || func_name == "open" {
                    // Check if O_CLOEXEC is used in the flags (only for open())
                    let call_text = get_node_text(&call, source);
                    if func_name == "open" && call_text.contains("O_CLOEXEC") {
                        // File will be closed on exec, no need to track
                        return None;
                    }
                    // Try to extract the variable name being assigned
                    return self.extract_assigned_variable(node, source);
                }
            }
        }
        None
    }

    /// Check if this node contains a file close operation (fclose or close)
    fn find_file_close(&self, node: &Node, source: &str) -> Option<String> {
        if let Some(call) = self.find_call_expression(node, source) {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "fclose" || func_name == "close" {
                    // Extract the argument (the file variable being closed)
                    if let Some(args) = call.child_by_field_name("arguments") {
                        for i in 0..args.child_count() {
                            if let Some(arg) = args.child(i) {
                                if arg.kind() == "identifier" {
                                    return Some(get_node_text(&arg, source).to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if this node sets FD_CLOEXEC on a file descriptor
    fn find_cloexec_set(&self, node: &Node, source: &str) -> Option<String> {
        // Look for fcntl(fd, F_SETFD, ... | FD_CLOEXEC) pattern
        if let Some(call) = self.find_call_expression(node, source) {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "fcntl" {
                    // Check if FD_CLOEXEC appears in the call
                    let call_text = get_node_text(&call, source);
                    if call_text.contains("FD_CLOEXEC") || call_text.contains("F_SETFD") {
                        // Extract the file descriptor argument (first arg)
                        if let Some(args) = call.child_by_field_name("arguments") {
                            for i in 0..args.child_count() {
                                if let Some(arg) = args.child(i) {
                                    if arg.kind() == "identifier" {
                                        return Some(get_node_text(&arg, source).to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Check if this node contains a process spawn call
    fn has_process_spawn(&self, node: &Node, source: &str) -> bool {
        if let Some(call) = self.find_call_expression(node, source) {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                return matches!(
                    func_name,
                    "system"
                        | "fork"
                        | "exec"
                        | "execl"
                        | "execle"
                        | "execlp"
                        | "execv"
                        | "execve"
                        | "execvp"
                        | "popen"
                );
            }
        }
        false
    }

    /// Find a call_expression in the AST subtree
    fn find_call_expression<'a>(&self, node: &Node<'a>, _source: &str) -> Option<Node<'a>> {
        query::find_first_descendant(*node, |n| n.kind() == "call_expression")
    }

    /// Extract the variable name being assigned in a declaration or assignment
    fn extract_assigned_variable(&self, node: &Node, source: &str) -> Option<String> {
        // For declarations: FILE *fp = fopen(...)
        if node.kind() == "declaration" {
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "init_declarator" {
                        if let Some(declarator) = child.child_by_field_name("declarator") {
                            return self.extract_identifier_from_declarator(&declarator, source);
                        }
                    }
                }
            }
        }

        // For assignments: fp = fopen(...)
        if let Some(assignment) = self.find_assignment_expression(node, source) {
            if let Some(left) = assignment.child_by_field_name("left") {
                if left.kind() == "identifier" {
                    return Some(get_node_text(&left, source).to_string());
                }
            }
        }

        None
    }

    /// Extract identifier from declarator (handles pointer declarators)
    fn extract_identifier_from_declarator(
        &self,
        declarator: &Node,
        source: &str,
    ) -> Option<String> {
        if declarator.kind() == "identifier" {
            return Some(get_node_text(declarator, source).to_string());
        }

        // Handle pointer_declarator: *fp
        if declarator.kind() == "pointer_declarator" {
            if let Some(inner) = declarator.child_by_field_name("declarator") {
                return self.extract_identifier_from_declarator(&inner, source);
            }
        }

        None
    }

    /// Find an assignment_expression in the AST subtree
    fn find_assignment_expression<'a>(&self, node: &Node<'a>, _source: &str) -> Option<Node<'a>> {
        query::find_first_descendant(*node, |n| n.kind() == "assignment_expression")
    }
}
