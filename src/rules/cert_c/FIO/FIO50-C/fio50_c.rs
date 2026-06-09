// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! FIO50-C: Do not alternately input and output from a file stream without an intervening positioning call
//!
//! This rule detects alternating input and output operations on file streams
//! without proper positioning calls, which causes undefined behavior in C.
//!
//! ## C Standard Requirements (ISO/IEC 9899:1999, §7.19.5.3¶6):
//! - Output cannot be directly followed by input without:
//!   - `fflush()` call, OR
//!   - A file positioning function (`fseek`, `fsetpos`, `rewind`)
//! - Input cannot be directly followed by output without:
//!   - A file positioning function, UNLESS
//!   - The input operation encountered end-of-file
//!
//! ## Violations:
//!
//! **Noncompliant Code Example (Output then Input):**
//! ```c
//! FILE *file = fopen("data.txt", "r+");
//! fprintf(file, "Output");
//! fscanf(file, "%s", buffer);  // VIOLATION: No positioning call between output and input
//! ```
//!
//! **Noncompliant Code Example (Input then Output):**
//! ```c
//! FILE *file = fopen("data.txt", "r+");
//! fscanf(file, "%s", buffer);
//! fprintf(file, "Output");  // VIOLATION: No positioning call between input and output
//! ```
//!
//! ## Compliant Solutions:
//!
//! **Compliant Solution (Output then Input with fflush):**
//! ```c
//! FILE *file = fopen("data.txt", "r+");
//! fprintf(file, "Output");
//! fflush(file);  // Positioning call
//! fscanf(file, "%s", buffer);
//! ```
//!
//! **Compliant Solution (Input then Output with fseek):**
//! ```c
//! FILE *file = fopen("data.txt", "r+");
//! fscanf(file, "%s", buffer);
//! fseek(file, 0, SEEK_CUR);  // Positioning call
//! fprintf(file, "Output");
//! ```
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/cplusplus/FIO50-CPP

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Fio50C;

#[derive(Clone, Debug, PartialEq)]
enum OperationType {
    Input,
    Output,
    Positioning,
}

#[derive(Clone, Debug)]
struct FileOperation {
    op_type: OperationType,
    file_var: String,
    line: usize,
    column: usize,
}

impl Fio50C {
    pub fn new() -> Self {
        Fio50C
    }

    /// Check if function is a file input operation
    fn is_input_function(&self, name: &str) -> bool {
        matches!(
            name,
            "fread" | "fgets" | "fscanf" | "getc" | "fgetc" | "fgetwc" | "fgetws" | "vfscanf"
        )
    }

    /// Check if function is a file output operation
    fn is_output_function(&self, name: &str) -> bool {
        matches!(
            name,
            "fwrite" | "fputs" | "fprintf" | "putc" | "fputc" | "fputwc" | "fputws" | "vfprintf"
        )
    }

    /// Check if function is a positioning operation
    fn is_positioning_function(&self, name: &str) -> bool {
        matches!(name, "fflush" | "fseek" | "fsetpos" | "rewind")
    }

    /// Extract the first argument (FILE* variable) from function call
    fn get_file_argument(&self, arguments: &Node, source: &str) -> Option<String> {
        let mut cursor = arguments.walk();
        for child in arguments.children(&mut cursor) {
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                return Some(get_node_text(&child, source).to_string());
            }
        }
        None
    }

    /// Analyze function definition or translation unit for I/O violations
    fn analyze_scope(&self, scope_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let mut file_operations: HashMap<String, Vec<FileOperation>> = HashMap::new();

        // Collect all file operations in this scope
        self.collect_file_operations(scope_node, source, &mut file_operations);

        // Detect violations in operation sequences
        for ops in file_operations.values() {
            self.detect_alternation_violations(ops, violations);
        }
    }

    /// Check if this is a C++ stream input operation (operator>>)
    fn is_cpp_input_operator(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "binary_expression" {
            if let Some(operator_node) = node.child_by_field_name("operator") {
                let operator = get_node_text(&operator_node, source);
                if operator == ">>" {
                    // Get the left operand (the stream object)
                    if let Some(left) = node.child_by_field_name("left") {
                        return Some(get_node_text(&left, source).to_string());
                    }
                }
            }
        }
        None
    }

    /// Check if this is a C++ stream output operation (operator<<)
    fn is_cpp_output_operator(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "binary_expression" {
            if let Some(operator_node) = node.child_by_field_name("operator") {
                let operator = get_node_text(&operator_node, source);
                if operator == "<<" {
                    // Get the left operand (the stream object)
                    if let Some(left) = node.child_by_field_name("left") {
                        return Some(get_node_text(&left, source).to_string());
                    }
                }
            }
        }
        None
    }

    /// Check if this is a C++ positioning call (seekg, seekp, etc.)
    fn is_cpp_positioning_call(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_text = get_node_text(&function, source);
                // Check for method calls like file.seekg()
                if func_text.contains(".seekg")
                    || func_text.contains(".seekp")
                    || func_text.contains("->seekg")
                    || func_text.contains("->seekp")
                {
                    // Extract the stream object name before the dot or arrow
                    if let Some(dot_pos) = func_text.find('.') {
                        return Some(func_text[..dot_pos].to_string());
                    } else if let Some(arrow_pos) = func_text.find("->") {
                        return Some(func_text[..arrow_pos].to_string());
                    }
                }
            }
        }
        None
    }

    /// Recursively collect file operations (both C and C++ styles)
    fn collect_file_operations(
        &self,
        node: &Node,
        source: &str,
        file_operations: &mut HashMap<String, Vec<FileOperation>>,
    ) {
        // C-style function calls
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                let op_type = if self.is_input_function(func_name) {
                    Some(OperationType::Input)
                } else if self.is_output_function(func_name) {
                    Some(OperationType::Output)
                } else if self.is_positioning_function(func_name) {
                    Some(OperationType::Positioning)
                } else {
                    None
                };

                if let Some(op_type) = op_type {
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        if let Some(file_var) = self.get_file_argument(&arguments, source) {
                            let operation = FileOperation {
                                op_type,
                                file_var: file_var.clone(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                            };

                            file_operations.entry(file_var).or_default().push(operation);
                        }
                    }
                }
            }

            // Check for C++ positioning calls
            if let Some(stream_var) = self.is_cpp_positioning_call(node, source) {
                let operation = FileOperation {
                    op_type: OperationType::Positioning,
                    file_var: stream_var.clone(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                };

                file_operations
                    .entry(stream_var)
                    .or_default()
                    .push(operation);
            }
        }

        // C++ stream operators (<< and >>)
        if node.kind() == "binary_expression" {
            // Check for input operator (>>)
            if let Some(stream_var) = self.is_cpp_input_operator(node, source) {
                let operation = FileOperation {
                    op_type: OperationType::Input,
                    file_var: stream_var.clone(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                };

                file_operations
                    .entry(stream_var)
                    .or_default()
                    .push(operation);
            }

            // Check for output operator (<<)
            if let Some(stream_var) = self.is_cpp_output_operator(node, source) {
                let operation = FileOperation {
                    op_type: OperationType::Output,
                    file_var: stream_var.clone(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                };

                file_operations
                    .entry(stream_var)
                    .or_default()
                    .push(operation);
            }
        }

        // Recursively process children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.collect_file_operations(&child, source, file_operations);
        }
    }

    /// Detect violations in a sequence of file operations
    fn detect_alternation_violations(
        &self,
        operations: &[FileOperation],
        violations: &mut Vec<RuleViolation>,
    ) {
        for i in 0..operations.len().saturating_sub(1) {
            let current = &operations[i];
            let next = &operations[i + 1];

            // Skip if there's a positioning call in between
            if next.op_type == OperationType::Positioning {
                continue;
            }

            // Check for output followed by input without positioning
            if current.op_type == OperationType::Output && next.op_type == OperationType::Input {
                // Check if there's a positioning call between current and next
                let has_positioning = operations
                    .iter()
                    .skip(i + 1)
                    .take_while(|op| op.line < next.line)
                    .any(|op| op.op_type == OperationType::Positioning);

                if !has_positioning {
                    violations.push(RuleViolation {
                        rule_id: "FIO50-C".to_string(),
                        severity: Severity::Low,
                        line: next.line,
                        column: next.column,
                        message: format!(
                            "Input operation on file stream '{}' follows output without intervening positioning call (fflush, fseek, fsetpos, or rewind)",
                            next.file_var
                        ),
                        file_path: String::new(),
                        suggestion: Some(
                            "Insert fflush() or a positioning function (fseek, fsetpos, rewind) between output and input operations".to_string(),
                        ),
                        requires_manual_review: Some(false),
                    });
                }
            }

            // Check for input followed by output without positioning
            if current.op_type == OperationType::Input && next.op_type == OperationType::Output {
                // Check if there's a positioning call between current and next
                let has_positioning = operations
                    .iter()
                    .skip(i + 1)
                    .take_while(|op| op.line < next.line)
                    .any(|op| op.op_type == OperationType::Positioning);

                if !has_positioning {
                    violations.push(RuleViolation {
                        rule_id: "FIO50-C".to_string(),
                        severity: Severity::Low,
                        line: next.line,
                        column: next.column,
                        message: format!(
                            "Output operation on file stream '{}' follows input without intervening positioning call (fseek, fsetpos, or rewind)",
                            next.file_var
                        ),
                        file_path: String::new(),
                        suggestion: Some(
                            "Insert a positioning function (fseek, fsetpos, rewind) between input and output operations, unless input encountered EOF".to_string(),
                        ),
                        requires_manual_review: Some(false),
                    });
                }
            }
        }
    }

    /// Recursively traverse AST
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Analyze at function scope
        if node.kind() == "function_definition" {
            self.analyze_scope(node, source, violations);
        }

        // Also analyze global scope
        if node.kind() == "translation_unit" {
            self.analyze_scope(node, source, violations);
        }

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.traverse(&child, source, violations);
        }
    }
}

impl CertRule for Fio50C {
    fn rule_id(&self) -> &'static str {
        "FIO50-C"
    }

    fn description(&self) -> &'static str {
        "Do not alternately input and output from a file stream without an intervening positioning call"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn cert_id(&self) -> &'static str {
        "FIO50-C"
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.traverse(root, source, &mut violations);
        violations
    }
}
