//! ERR04-C: Choose an appropriate termination strategy
//!
//! This recommendation detects use of `abort()` or `_Exit()` after file I/O operations.
//! These functions do not guarantee proper cleanup of buffered data or file descriptors.
//! When file operations have occurred, prefer `exit()` or returning from `main()` for
//! proper resource cleanup.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! #include <stdlib.h>
//! #include <stdio.h>
//!
//! int write_data(void) {
//!   FILE *f = fopen("hello.txt", "w");
//!   fprintf(f, "Hello, World\n");
//!   abort();  // WRONG: Data might not be written!
//!   return 0;
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! #include <stdlib.h>
//! #include <stdio.h>
//!
//! int write_data(void) {
//!   FILE *f = fopen("hello.txt", "w");
//!   fprintf(f, "Hello, World\n");
//!   exit(EXIT_FAILURE);  // Correct: Writes data and closes f
//!   return 0;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find all `abort()` or `_Exit()` calls
//! - Check if the containing function has any file I/O operations
//! - Report violations recommending `exit()` or return from `main()`

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Err04C;

impl CertRule for Err04C {
    fn rule_id(&self) -> &'static str {
        "ERR04-C"
    }

    fn description(&self) -> &'static str {
        "Choose an appropriate termination strategy"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "ERR04-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Err04C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for call expressions that might be abort() or _Exit()
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = call.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                if self.is_unsafe_termination(&func_name) {
                    // Check if there are file I/O operations in the same function
                    if let Some(function_def) = self.find_containing_function(&call) {
                        if self.has_file_io_operations(&function_def, source) {
                            self.report_violation(&call, &func_name, source, violations);
                        }
                    }
                }
            }
        }
    }

    fn is_unsafe_termination(&self, func_name: &str) -> bool {
        matches!(func_name.trim(), "abort" | "_Exit")
    }

    fn find_containing_function<'a>(&self, node: &'a Node) -> Option<Node<'a>> {
        let mut current = Some(*node);

        while let Some(n) = current {
            if n.kind() == "function_definition" {
                return Some(n);
            }
            current = n.parent();
        }

        None
    }

    fn has_file_io_operations(&self, function_node: &Node, source: &str) -> bool {
        // Recursively search for file I/O function calls
        self.contains_file_io_call(function_node, source)
    }

    fn contains_file_io_call(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func_node) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func_node, source);
            self.is_file_io_function(&func_name)
        })
        .is_some()
    }

    fn is_file_io_function(&self, name: &str) -> bool {
        matches!(
            name.trim(),
            "fopen"
                | "fclose"
                | "fprintf"
                | "fwrite"
                | "fputs"
                | "fputc"
                | "fread"
                | "fgets"
                | "fgetc"
                | "fscanf"
                | "fseek"
                | "ftell"
                | "freopen"
                | "fflush"
                | "setvbuf"
                | "ungetc"
                | "feof"
                | "ferror"
                | "clearerr"
                | "rewind"
                | "fsetpos"
                | "fgetpos"
        )
    }

    fn report_violation(
        &self,
        node: &Node,
        func_name: &str,
        _source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let line = node.start_position().row + 1;
        let column = node.start_position().column + 1;

        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: format!(
                "Use of {}() after file I/O may leave files in inconsistent state",
                func_name
            ),
            file_path: String::new(),
            line,
            column,
            suggestion: Some(
                "Use exit() or return from main() instead to ensure proper file cleanup. \
                These functions flush buffered data and close file descriptors properly."
                    .to_string(),
            ),
            ..Default::default()
        });
    }
}
