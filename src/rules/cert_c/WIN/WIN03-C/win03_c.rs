//! WIN03-C: Understand HANDLE inheritance
//!
//! This rule detects unsafe HANDLE inheritance patterns on Windows that can leak
//! sensitive resources or cause denial-of-service attacks by allowing child
//! processes to access parent process handles.
//!
//! ## Non-compliant example:
//!
//! ```c
//! // Handle inheritance enabled
//! HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, TRUE, TEXT("GlobalMutex"));
//!
//! // fopen() allows inheritance by default on Windows
//! FILE *fp = fopen("SomeFile.txt", "rw");
//! system("ChildProcess.exe");  // Child inherits all handles
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! // Explicitly disable inheritance
//! HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, TEXT("GlobalMutex"));
//!
//! // Use 'N' flag to disable inheritance
//! FILE *fp = fopen("SomeFile.txt", "rwN");
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{get_node_text, get_sanitized_node_text};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Win03C;

impl Win03C {
    pub fn new() -> Self {
        Self
    }

    /// Check for unsafe HANDLE inheritance patterns
    fn check_function_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if node.kind() != "call_expression" {
            return;
        }

        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            match function_name {
                "OpenMutex" => {
                    self.check_open_mutex_call(node, source, violations);
                }
                "fopen" => {
                    self.check_fopen_call(node, source, violations);
                }
                "_strtoui64" | "_strtoul" | "strtoul" | "_atoi64" => {
                    // Check if converting cmdLine to handle (dangerous pattern)
                    self.check_handle_from_cmdline(node, source, violations);
                }
                _ => {}
            }
        }
    }

    /// Check OpenMutex() calls for TRUE inheritance flag
    fn check_open_mutex_call(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(args_node) = node.child_by_field_name("arguments") {
            // Get second argument (inheritance flag)
            if let Some(second_arg) = self.get_nth_argument(&args_node, 1) {
                let arg_text = get_node_text(&second_arg, source).trim();

                // Check if it's TRUE (inheritance enabled)
                if arg_text == "TRUE" || arg_text == "1" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "OpenMutex() called with inheritance enabled (second parameter is {}). This allows child processes to inherit the mutex handle, potentially leaking sensitive resources.",
                            arg_text
                        ),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(
                            "Change the second parameter to FALSE to disable handle inheritance."
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Check fopen() calls for missing 'N' flag
    fn check_fopen_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(args_node) = node.child_by_field_name("arguments") {
            // Get second argument (mode string)
            if let Some(mode_arg) = self.get_nth_argument(&args_node, 1) {
                let mode_text = get_node_text(&mode_arg, source);

                // Check if it's a string literal containing mode
                if mode_arg.kind() == "string_literal" {
                    // Check if 'N' flag is present (disables inheritance on Windows)
                    if !mode_text.contains('N') {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "fopen() called without 'N' flag in mode string {}. On Windows, file handles are inheritable by default unless the 'N' flag is specified.",
                                mode_text
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Add 'N' flag to the mode string (e.g., \"rwN\") to disable handle inheritance on Windows."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check if a string-to-integer conversion is being used to receive a handle via command line
    /// This is a dangerous pattern for handle inheritance UNLESS the handle is validated
    fn check_handle_from_cmdline(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(args_node) = node.child_by_field_name("arguments") {
            // Get first argument
            if let Some(first_arg) = self.get_nth_argument(&args_node, 0) {
                let arg_text = get_node_text(&first_arg, source).trim();

                // Check if parsing cmdLine, lpCmdLine, or similar command line variables
                if arg_text.contains("cmdLine")
                    || arg_text.contains("CmdLine")
                    || arg_text.contains("lpCmdLine")
                    || arg_text.contains("CommandLine")
                {
                    // Check if result is being cast to HANDLE
                    if let Some(parent) = node.parent() {
                        let parent_text = get_node_text(&parent, source);
                        if parent_text.contains("HANDLE") {
                            // Check if DuplicateHandle is used in the same scope to validate
                            // Finding the containing function/scope
                            let scope = self.find_containing_scope(node);
                            if let Some(scope) = scope {
                                // Sanitized so a comment/string literal in
                                // the scope can't spoof DuplicateHandle usage
                                // and silently suppress a genuine violation.
                                let scope_text = get_sanitized_node_text(&scope, source);
                                // If DuplicateHandle is used, this is the compliant pattern
                                if scope_text.contains("DuplicateHandle") {
                                    return; // Compliant - handle is being validated
                                }
                            }

                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: "Converting command line argument to HANDLE without validation. Receiving handles via command line is insecure - it exposes handles to other processes and allows handle hijacking.".to_string(),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(
                                    "Validate the handle using DuplicateHandle() to ensure it's a valid handle with appropriate access rights, or use proper IPC mechanisms."
                                        .to_string(),
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Find the containing function or scope for a node
    fn find_containing_scope<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition"
                || parent.kind() == "compound_statement"
                || parent.kind() == "translation_unit"
            {
                return Some(parent);
            }
            current = parent;
        }
        None
    }

    /// Get the Nth argument from an argument list node (0-indexed)
    fn get_nth_argument<'a>(&self, args_node: &Node<'a>, index: usize) -> Option<Node<'a>> {
        let mut arg_count = 0;

        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                // Skip '(' and ')' and ',' tokens
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    if arg_count == index {
                        return Some(child);
                    }
                    arg_count += 1;
                }
            }
        }

        None
    }
}

impl CertRule for Win03C {
    fn rule_id(&self) -> &'static str {
        "WIN03-C"
    }

    fn description(&self) -> &'static str {
        "Understand HANDLE inheritance"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "WIN03-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Win03C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for unsafe handle inheritance patterns
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_function_call(&call, source, violations);
        }
    }
}
