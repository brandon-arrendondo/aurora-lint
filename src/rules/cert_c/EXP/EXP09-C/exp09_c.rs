//! EXP09-C: Use sizeof to determine the size of a type or variable
//!
//! Do not hard code the size of a type into an application. Because of alignment,
//! padding, and differences in basic types (e.g., 32-bit versus 64-bit pointers),
//! the size of most types can vary between compilers and versions.
//!
//! ## Examples:
//!
//! **Non-compliant (hardcoded size):**
//! ```c
//! int **matrix = (int **)calloc(100, 4);  // Hardcoded 4 bytes
//! ```
//!
//! **Compliant (using sizeof):**
//! ```c
//! int **matrix = (int **)calloc(100, sizeof(*matrix));
//! ```
//!
//! ## Detection Strategy:
//! - Detect calls to memory allocation functions (malloc, calloc, realloc)
//! - Check if size arguments are numeric literals
//! - Flag hardcoded numeric sizes as violations
//! - Suggest using sizeof() instead

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp09C;

impl CertRule for Exp09C {
    fn rule_id(&self) -> &'static str {
        "EXP09-C"
    }

    fn description(&self) -> &'static str {
        "Use sizeof to determine the size of a type or variable"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP09-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Exp09C {
    /// Recursively check nodes for hardcoded sizes in allocation functions
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call_node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if self.is_memory_allocation_function(&func_name) {
                    self.check_allocation_call(&call_node, source, &func_name, violations);
                }
            }
        }
    }

    /// Check if a function is a memory allocation function
    fn is_memory_allocation_function(&self, name: &str) -> bool {
        matches!(name, "malloc" | "calloc" | "realloc")
    }

    /// Check allocation function call for hardcoded sizes
    fn check_allocation_call(
        &self,
        node: &Node,
        source: &str,
        func_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            let args = self.extract_arguments(&arguments, source);

            // For calloc(count, size), check the size argument (second parameter)
            // For malloc(size) and realloc(ptr, size), check the size argument
            let size_arg_index = if func_name == "calloc" || func_name == "realloc" {
                1
            } else {
                0
            };

            if let Some(size_arg) = args.get(size_arg_index) {
                if self.is_numeric_literal(size_arg, source) {
                    let literal_value = get_node_text(size_arg, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        message: format!(
                            "Hardcoded size '{}' used in {}(). Use sizeof() to determine type sizes instead of hardcoding them.",
                            literal_value, func_name
                        ),
                        severity: self.severity(),
                        line: size_arg.start_position().row + 1,
                        column: size_arg.start_position().column + 1,
                        file_path: String::new(),
                        suggestion: Some(format!(
                            "Replace '{}' with sizeof(type) or sizeof(variable) for portability",
                            literal_value
                        )),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    /// Extract arguments from argument list
    fn extract_arguments<'a>(&self, arguments: &Node<'a>, _source: &str) -> Vec<Node<'a>> {
        let mut args = Vec::new();
        let mut cursor = arguments.walk();

        for child in arguments.children(&mut cursor) {
            // Skip parentheses and commas, collect actual argument expressions
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                args.push(child);
            }
        }

        args
    }

    /// Check if a node is a numeric literal
    fn is_numeric_literal(&self, node: &Node, source: &str) -> bool {
        // Check for number_literal node type
        if node.kind() == "number_literal" {
            return true;
        }

        // Also check text content for numeric patterns
        let text = get_node_text(node, source);
        text.chars().all(|c| c.is_ascii_digit())
    }
}
