//! FIO08-C: Take care when calling remove() on an open file
//!
//! Calling remove() on an open file is implementation-defined behavior.
//! Files should be closed before removal, or use unlink() instead.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! file = fopen(file_name, "w+");
//! remove(file_name);  // File still open!
//! fclose(file);
//! ```
//!
//! **Compliant:**
//! ```c
//! file = fopen(file_name, "w+");
//! fclose(file);
//! remove(file_name);  // File closed first
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Fio08C;

impl CertRule for Fio08C {
    fn rule_id(&self) -> &'static str {
        "FIO08-C"
    }

    fn description(&self) -> &'static str {
        "Take care when calling remove() on an open file"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO08-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let mut open_files: HashSet<String> = HashSet::new();

        self.analyze_file_operations(node, source, &mut open_files, &mut violations);
        violations
    }
}

impl Fio08C {
    /// Analyze file operations to detect remove() on open files
    fn analyze_file_operations(
        &self,
        node: &Node,
        source: &str,
        open_files: &mut HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Iterate in document order (important for tracking state)
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                match func_name {
                    "fopen" | "fopen_s" | "freopen" => {
                        // Track opened file
                        if let Some(args) = call.child_by_field_name("arguments") {
                            if let Some(filename) = self.get_first_arg(&args, source) {
                                open_files.insert(filename);
                            }
                        }
                    }
                    "fclose" => {
                        // File closed - would need to track file handle, simplified here
                        // For now, just note that fclose was called
                    }
                    "remove" => {
                        // Check if removing an open file
                        if let Some(args) = call.child_by_field_name("arguments") {
                            if let Some(filename) = self.get_first_arg(&args, source) {
                                if open_files.contains(&filename) {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        message: format!(
                                            "Calling remove() on '{}' which may still be open. \
                                             This is implementation-defined behavior.",
                                            filename
                                        ),
                                        severity: self.severity(),
                                        line: call.start_position().row + 1,
                                        column: call.start_position().column + 1,
                                        file_path: String::new(),
                                        suggestion: Some(
                                            "Close the file with fclose() before calling remove(), \
                                             or use unlink() for POSIX systems"
                                                .to_string(),
                                        ),
                                        requires_manual_review: None,
                                    });
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Get first argument from argument list
    fn get_first_arg(&self, args: &Node, source: &str) -> Option<String> {
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }
}
