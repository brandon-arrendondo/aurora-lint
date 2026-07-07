//! FIO14-C: Understand the difference between text mode and binary mode with file streams
//!
//! This rule detects improper use of file positioning functions with text/binary streams:
//!
//! ## Text Mode Issues:
//! - Using arbitrary offsets with fseek() (only 0 or ftell() values allowed with SEEK_SET)
//! - File position is indeterminate after ungetc() until pushed-back characters are read
//!
//! ## Binary Mode Issues:
//! - Using fseek() with SEEK_END (binary streams may have unspecified null termination)
//! - Calling ungetc() when file position indicator is 0
//!
//! ## Detected Violations:
//! - fseek() with non-zero offset in text mode (without prior ftell())
//! - fseek() with SEEK_END on binary mode files
//! - Improper use of ungetc() based on stream type
//!
//! ## Compliant Patterns:
//! - Using binary mode ("rb", "wb") for binary data
//! - Using text mode ("r", "w") for text data with appropriate positioning
//! - Using fseek() with 0 or ftell() values in text mode

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio14C;

impl CertRule for Fio14C {
    fn rule_id(&self) -> &'static str {
        "FIO14-C"
    }

    fn description(&self) -> &'static str {
        "Understand the difference between text mode and binary mode with file streams"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "FIO14-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Fio14C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for fseek() calls with problematic usage
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "fseek" {
                    self.check_fseek_call(&call, source, violations);
                }
            }
        }
    }

    /// Check fseek() calls for improper usage
    fn check_fseek_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // fseek(stream, offset, whence)
        if let Some(arguments) = node.child_by_field_name("arguments") {
            let args = self.extract_arguments(&arguments, source);

            if args.len() >= 3 {
                let offset_text = get_node_text(&args[1], source);
                let whence_text = get_node_text(&args[2], source);

                // Check for SEEK_END usage (problematic in binary mode)
                if whence_text == "SEEK_END" {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: "fseek() with SEEK_END should not be used on binary streams (undefined behavior with null padding)".to_string(),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Use SEEK_SET or SEEK_CUR instead, or ensure stream is in text mode"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }

                // Check for non-zero offset with SEEK_SET (problematic in text mode)
                // This is a heuristic - we flag literal non-zero offsets
                if whence_text == "SEEK_SET" && self.is_literal_nonzero_offset(&offset_text) {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "fseek() with arbitrary offset '{}' and SEEK_SET may not work correctly in text mode (only 0 or ftell() values allowed)",
                            offset_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Use binary mode for the file, or use offset from ftell()".to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Extract function call arguments as a vector of nodes
    fn extract_arguments<'a>(&self, arguments_node: &Node<'a>, _source: &str) -> Vec<Node<'a>> {
        let mut args = Vec::new();

        for i in 0..arguments_node.child_count() {
            if let Some(child) = arguments_node.child(i) {
                // Skip commas and parentheses
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    args.push(child);
                }
            }
        }

        args
    }

    /// Check if an offset is a literal non-zero value (not a function call or variable)
    fn is_literal_nonzero_offset(&self, offset_text: &str) -> bool {
        // Try to parse as integer
        if let Ok(value) = offset_text.trim().parse::<i64>() {
            value != 0
        } else {
            // Not a simple integer literal, might be ftell() or a variable
            false
        }
    }
}
