//! FIO19-C: Do not use fseek() and ftell() to compute the size of a regular file
//!
//! Using fseek() to seek to the end of a file and ftell() to compute the file size
//! is problematic because:
//! - For binary files: fseek() to end is not guaranteed to work correctly on all systems
//! - For text files: ftell() returns unspecified information, not suitable for size calculations
//!
//! ## Rationale:
//! - fseek(file, 0, SEEK_END) is not meaningfully supported for binary streams
//! - ftell() for text streams contains unspecified information
//! - Can lead to incorrect memory allocation and buffer overflows
//!
//! ## Examples:
//!
//! **Non-compliant (using fseek/ftell for file size):**
//! ```c
//! fseek(fp, 0, SEEK_END);
//! long size = ftell(fp);
//! ```
//!
//! **Compliant (using fstat):**
//! ```c
//! struct stat st;
//! fstat(fileno(fp), &st);
//! off_t size = st.st_size;
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio19C;

impl CertRule for Fio19C {
    fn rule_id(&self) -> &'static str {
        "FIO19-C"
    }

    fn description(&self) -> &'static str {
        "Do not use fseek() and ftell() to compute the size of a regular file"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO19-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Fio19C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for fseek() calls
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func, source).trim();

                if func_name == "fseek" {
                    // Check if fseek uses SEEK_END
                    if self.fseek_uses_seek_end(&n, source) {
                        // Get the file pointer argument (first argument)
                        if let Some(file_ptr) = self.get_first_argument(&n) {
                            let file_ptr_text = get_node_text(&file_ptr, source);

                            // Check if there's a ftell() call on the same file pointer nearby
                            if self.has_ftell_nearby(&n, file_ptr_text.trim(), source) {
                                let line = n.start_position().row + 1;
                                let column = n.start_position().column + 1;

                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    message:
                                        "Using fseek()/ftell() to compute file size - use fstat() or platform-specific APIs instead"
                                            .to_string(),
                                    file_path: String::new(),
                                    line,
                                    column,
                                    suggestion: Some(
                                        "Use fstat() with fileno() to get file size reliably"
                                            .to_string(),
                                    ),
                                    requires_manual_review: None,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Check if fseek call uses SEEK_END as the third argument
    fn fseek_uses_seek_end(&self, fseek_node: &Node, source: &str) -> bool {
        if let Some(args) = fseek_node.child_by_field_name("arguments") {
            let mut arg_count = 0;
            let mut cursor = args.walk();
            for child in args.children(&mut cursor) {
                // Skip separators and parentheses
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    arg_count += 1;
                    if arg_count == 3 {
                        // Third argument (whence parameter)
                        let arg_text = get_node_text(&child, source).trim();
                        return arg_text == "SEEK_END" || arg_text == "2";
                    }
                }
            }
        }
        false
    }

    /// Get the first argument from a function call (file pointer)
    fn get_first_argument<'a>(&self, call_node: &Node<'a>) -> Option<Node<'a>> {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            let mut cursor = args.walk();
            for child in args.children(&mut cursor) {
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Check if there's a ftell() call on the same file pointer nearby
    fn has_ftell_nearby(&self, fseek_node: &Node, file_ptr: &str, source: &str) -> bool {
        // Get the containing function, compound statement, or translation unit
        let mut current = fseek_node.parent();
        let mut scope: Option<Node> = None;

        while let Some(node) = current {
            if matches!(
                node.kind(),
                "compound_statement" | "function_definition" | "translation_unit"
            ) {
                scope = Some(node);
                break;
            }
            current = node.parent();
        }

        let scope_node = match scope {
            Some(s) => s,
            None => return false,
        };

        // Search for ftell() calls in the same scope
        self.find_ftell_on_file_ptr(&scope_node, file_ptr, source)
    }

    /// Recursively search for ftell() calls on the specified file pointer
    fn find_ftell_on_file_ptr(&self, node: &Node, file_ptr: &str, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func) = n.child_by_field_name("function") else {
                return false;
            };
            if func.utf8_text(source.as_bytes()).unwrap_or("").trim() != "ftell" {
                return false;
            }
            // Check if ftell uses the same file pointer
            let Some(first_arg) = self.get_first_argument(&n) else {
                return false;
            };
            get_node_text(&first_arg, source).trim() == file_ptr
        })
        .is_some()
    }
}
