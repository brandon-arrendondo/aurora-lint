//! WIN30-C: Properly pair allocation and deallocation functions
//!
//! Windows provides several memory allocation APIs that must be paired with
//! their corresponding deallocation functions. Mispairing causes memory
//! corruption or out-of-bounds access.
//!
//! ## Non-compliant example:
//!
//! ```c
//! // FormatMessage allocates with LocalAlloc
//! FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER, ...);
//! GlobalFree(buf);  // WRONG - should be LocalFree
//!
//! // malloc must pair with free, not LocalFree
//! char *p = malloc(100);
//! LocalFree(p);  // WRONG - should be free
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! // Use LocalFree for FormatMessage allocations
//! FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER, ...);
//! LocalFree(buf);  // Correct
//!
//! // Use free for malloc
//! char *p = malloc(100);
//! free(p);  // Correct
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Win30C;

impl Win30C {
    pub fn new() -> Self {
        Self
    }

    fn contains_format_message_alloc(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function_node) = n.child_by_field_name("function") else {
                return false;
            };
            let function_name = get_node_text(&function_node, source);
            if function_name != "FormatMessage" {
                return false;
            }
            let Some(args_node) = n.child_by_field_name("arguments") else {
                return false;
            };
            let Some(first_arg) = self.get_first_argument(&args_node) else {
                return false;
            };
            let arg_text = get_node_text(&first_arg, source);
            arg_text.contains("FORMAT_MESSAGE_ALLOCATE_BUFFER")
        })
        .is_some()
    }

    fn contains_global_free(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function_node) = n.child_by_field_name("function") else {
                return false;
            };
            get_node_text(&function_node, source) == "GlobalFree"
        })
        .is_some()
    }

    fn report_global_free_violation(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function_node) = call.child_by_field_name("function") {
                let function_name = get_node_text(&function_node, source);
                if function_name == "GlobalFree" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: "Using GlobalFree() for buffer allocated by FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER). Use LocalFree() instead.".to_string(),
                        file_path: String::new(),
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        suggestion: Some(
                            "Change GlobalFree() to LocalFree(). Per Microsoft documentation, buffers allocated by FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER) must be freed with LocalFree().".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    /// Get the first argument from an argument list node
    fn get_first_argument<'a>(&self, args_node: &Node<'a>) -> Option<Node<'a>> {
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    return Some(child);
                }
            }
        }
        None
    }
}

impl CertRule for Win30C {
    fn rule_id(&self) -> &'static str {
        "WIN30-C"
    }

    fn description(&self) -> &'static str {
        "Properly pair allocation and deallocation functions"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "WIN30-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // Fast path: skip files that don't contain both patterns
        if !source.contains("FormatMessage")
            || !source.contains("FORMAT_MESSAGE_ALLOCATE_BUFFER")
            || !source.contains("GlobalFree")
        {
            return Vec::new();
        }

        // Single O(N) pass: check the entire file once for the mismatch pattern
        let mut violations = Vec::new();
        if self.contains_format_message_alloc(node, source) {
            if self.contains_global_free(node, source) {
                self.report_global_free_violation(node, source, &mut violations);
            }
        }
        violations
    }
}
