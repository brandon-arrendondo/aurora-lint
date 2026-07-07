// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! FIO09-C: Be careful with binary data when transferring data across systems
//!
//! This rule detects binary data transfers using fread() and fwrite() with structures
//! or multi-byte data types, which can cause portability issues across heterogeneous systems.
//!
//! Common violations include:
//! - Using fread() to read binary data directly into a struct
//! - Using fwrite() to write struct data in binary format
//! - Assumptions about memory layout portability
//!
//! ## Portability Concerns:
//! - Structure padding differences
//! - Floating-point model variations
//! - Number of bits per byte
//! - Endianness differences
//! - Other platform-specific binary format incompatibilities
//!
//! ## Violations:
//!
//! **Noncompliant Code Example:**
//! ```c
//! struct myData {
//!   char c;
//!   long l;
//! };
//!
//! FILE *file;
//! struct myData data;
//!
//! if (fread(&data, sizeof(struct myData), 1, file) < sizeof(struct myData)) {
//!   /* Handle error */
//! }
//! ```
//!
//! ## Compliant Solutions:
//!
//! **Use text-based format:**
//! ```c
//! if (fgets(buf, 1, file) == NULL) {
//!   /* Handle error */
//! }
//! data.c = buf[0];
//!
//! if (fgets(buf, sizeof(buf), file) == NULL) {
//!   /* Handle Error */
//! }
//! data.l = strtol(buf, &end_ptr, 10);
//! ```
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/FIO09-C.+Be+careful+with+binary+data+when+transferring+data+across+systems

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Fio09C;

impl Fio09C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Fio09C
    }

    /// Check if a node represents a pointer to a struct type
    #[allow(dead_code)]
    fn is_struct_pointer(&self, node: &Node, source: &str) -> bool {
        let text = get_node_text(node, source);

        // Check for address-of operator on a struct variable
        // Pattern: &struct_var or &data
        if let Some(_child) = node.child_by_field_name("argument") {
            // Check if the argument is a pointer_expression (&...)
            if node.kind() == "pointer_expression" {
                return true; // Any pointer could be a struct
            }
        }

        // Check for explicit struct type casts or identifiers
        text.contains("struct ") ||
        node.kind() == "pointer_expression" ||
        // Check for identifiers that might be struct pointers
        (node.kind() == "identifier" && !text.starts_with('"'))
    }

    /// Check if this is a binary read/write of potentially structured data
    fn is_binary_io_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() != "call_expression" {
            return false;
        }

        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source);
            func_name == "fread" || func_name == "fwrite"
        } else {
            false
        }
    }

    /// Get the first argument from a function call
    fn get_first_argument<'a>(&self, arguments: &'a Node) -> Option<Node<'a>> {
        let mut cursor = arguments.walk();
        Self::find_non_punctuation(arguments.children(&mut cursor))
    }

    fn find_non_punctuation<'a>(iter: impl Iterator<Item = Node<'a>>) -> Option<Node<'a>> {
        iter.into_iter()
            .find(|child| child.kind() != "(" && child.kind() != ")" && child.kind() != ",")
    }

    /// Check for fread() or fwrite() calls with struct pointers
    fn check_binary_io(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if !self.is_binary_io_call(node, source) {
            return;
        }

        // Get function name for error message
        let func_name = if let Some(function) = node.child_by_field_name("function") {
            get_node_text(&function, source).to_string()
        } else {
            return;
        };

        // Get the arguments
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // First argument to fread/fwrite is the data buffer
            if let Some(first_arg) = self.get_first_argument(&arguments) {
                let arg_text = get_node_text(&first_arg, source);

                // Check if the first argument is a pointer to struct or complex type
                // Common patterns:
                // - &data (where data is a struct)
                // - &struct_name
                // - pointer_expression nodes
                // - identifiers (could be struct pointers)

                let is_suspicious = first_arg.kind() == "pointer_expression" ||  // &something
                    arg_text.contains("struct ") ||               // explicit struct reference
                    (first_arg.kind() == "identifier" &&
                     // Check if it's being used with sizeof in other arguments
                     self.has_sizeof_struct_in_args(&arguments, source));

                if is_suspicious {
                    violations.push(RuleViolation {
                        rule_id: "FIO09-C".to_string(),
                        severity: Severity::Medium,
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        message: format!(
                            "{}() used for binary I/O with potentially structured data; portability issues may arise from differences in structure padding, endianness, or floating-point representation",
                            func_name
                        ),
                        file_path: String::new(),
                        suggestion: Some(
                            "Use text-based format (e.g., fgets/fprintf) or a specialized serialization library to ensure portability across systems".to_string(),
                        ),
                        requires_manual_review: Some(false),
                    });
                }
            }
        }
    }

    /// Check if sizeof(struct ...) appears in the arguments
    fn has_sizeof_struct_in_args(&self, arguments: &Node, source: &str) -> bool {
        let mut cursor = arguments.walk();
        for child in arguments.children(&mut cursor) {
            if child.kind() == "sizeof_expression" {
                let sizeof_text = get_node_text(&child, source);
                if sizeof_text.contains("struct ") {
                    return true;
                }
            }
        }
        false
    }

    /// Recursively traverse AST
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_binary_io(&call, source, violations);
        }
    }
}

impl CertRule for Fio09C {
    fn rule_id(&self) -> &'static str {
        "FIO09-C"
    }

    fn description(&self) -> &'static str {
        "Be careful with binary data when transferring data across systems"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "FIO09-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.traverse(root, source, violations);
    }
}
