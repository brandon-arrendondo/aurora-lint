//! POS34-C: Do not call putenv() with a pointer to an automatic variable as the argument
//!
//! The POSIX `putenv()` function stores a pointer to the string argument in the environment,
//! rather than copying it. If the argument is a pointer to automatic (stack-allocated) storage,
//! the memory will be reclaimed when the function returns, leaving a dangling pointer in the
//! environment. This leads to undefined behavior and potential security vulnerabilities.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int func(const char *var) {
//!     char env[1024];  // Automatic storage
//!     snprintf(env, sizeof(env), "TEST=%s", var);
//!     return putenv(env);  // Dangling pointer after function returns
//! }
//! ```
//!
//! **Compliant (Static storage):**
//! ```c
//! int func(const char *var) {
//!     static char env[1024];  // Static storage persists
//!     snprintf(env, sizeof(env), "TEST=%s", var);
//!     return putenv(env);  // Safe: static variable persists
//! }
//! ```
//!
//! **Compliant (Heap allocation):**
//! ```c
//! int func(const char *var) {
//!     char *env = malloc(len);  // Heap allocation persists
//!     snprintf(env, len, "TEST=%s", var);
//!     putenv(env);  // Safe: heap memory persists (don't free!)
//!     return 0;
//! }
//! ```
//!
//! **Preferred (Use setenv):**
//! ```c
//! int func(const char *var) {
//!     return setenv("TEST", var, 1);  // Handles memory management
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pos34C;

impl CertRule for Pos34C {
    fn rule_id(&self) -> &'static str {
        "POS34-C"
    }

    fn description(&self) -> &'static str {
        "Do not call putenv() with a pointer to an automatic variable as the argument"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS34-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_putenv_calls(node, source, violations);
    }
}

impl Pos34C {
    fn check_putenv_calls(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            let node = &node;
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "putenv" {
                    // Check the argument passed to putenv
                    if let Some(arguments) = node.child_by_field_name("arguments") {
                        if let Some(arg) = self.get_first_argument(&arguments) {
                            let arg_text = get_node_text(&arg, source);

                            // Check if it's a local automatic variable
                            if self.is_automatic_variable(&arg, source, node) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    message: format!(
                                        "putenv() called with pointer to automatic variable '{}'. \
                                         The argument to putenv() must point to memory with static \
                                         storage duration (static variable or heap allocation). \
                                         Automatic variables are destroyed when the function returns, \
                                         leaving a dangling pointer in the environment.",
                                        arg_text
                                    ),
                                    severity: self.severity(),
                                    line: node.start_position().row + 1,
                                    column: node.start_position().column + 1,
                                    file_path: String::new(),
                                    suggestion: Some(
                                        "Use 'static char env[...]' or malloc(), or prefer setenv() \
                                         which handles memory management automatically"
                                            .to_string(),
                                    ),
                                    requires_manual_review: Some(true),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    /// Get the first argument from an argument list
    fn get_first_argument<'a>(&self, arguments: &Node<'a>) -> Option<Node<'a>> {
        for i in 0..arguments.child_count() {
            if let Some(child) = arguments.child(i) {
                // Skip the parentheses and commas
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Check if a variable is automatic (not static, not from malloc)
    fn is_automatic_variable(&self, arg: &Node, source: &str, call_node: &Node) -> bool {
        let arg_text = get_node_text(arg, source);

        // If argument is not an identifier, it might be a cast or other expression
        // For simplicity, we'll check if the text contains an identifier pattern
        let var_name = if arg.kind() == "identifier" {
            arg_text
        } else if arg.kind() == "cast_expression" {
            // Handle cast like (char *)env
            if let Some(value) = arg.child_by_field_name("value") {
                get_node_text(&value, source)
            } else {
                return false;
            }
        } else {
            // For other expressions, extract identifier if present
            arg_text
        };

        // Check if this variable is declared locally in the containing function
        if let Some(function) = self.find_containing_function(call_node) {
            if let Some(declaration) = self.find_variable_declaration(&function, &var_name, source)
            {
                // Check if the declaration has 'static' storage class
                if self.is_static_declaration(&declaration, source) {
                    return false; // Static variable, not automatic
                }

                // Check if the variable is initialized with malloc/calloc/realloc
                if self.is_heap_allocated(&declaration, source) {
                    return false; // Heap allocated pointer, not automatic
                }

                // Check if it's an array declaration (not a pointer)
                // Arrays are automatic storage, pointers can point anywhere
                if self.is_array_declaration(&declaration, source) {
                    return true; // Array is automatic storage
                }

                // For pointer variables not initialized with malloc, need more analysis
                // If it's a pointer type (char *), we can't be sure where it points
                // Conservatively assume pointers are not automatic unless we know otherwise
                if self.is_pointer_declaration(&declaration, source) {
                    return false; // Pointer could point to heap/static, conservatively safe
                }

                // If it's neither an array nor a pointer, it's likely automatic
                return true;
            }
        }

        // If we can't find the declaration, conservatively assume it's not automatic
        false
    }

    /// Find the containing function node
    fn find_containing_function<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = Some(*node);
        while let Some(node) = current {
            if node.kind() == "function_definition" {
                return Some(node);
            }
            current = node.parent();
        }
        None
    }

    /// Find a variable declaration within a function
    fn find_variable_declaration<'a>(
        &self,
        function: &Node<'a>,
        var_name: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        self.search_declaration(function, var_name, source)
    }

    fn search_declaration<'a>(
        &self,
        node: &Node<'a>,
        var_name: &str,
        source: &str,
    ) -> Option<Node<'a>> {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "declaration" {
                return false;
            }
            if let Some(declarator) = n.child_by_field_name("declarator") {
                let decl_text = get_node_text(&declarator, source);
                return decl_text.contains(var_name);
            }
            false
        })
    }

    /// Check if a declaration is static
    fn is_static_declaration(&self, declaration: &Node, source: &str) -> bool {
        let decl_text = get_node_text(declaration, source);
        decl_text.contains("static")
    }

    /// Check if a variable is heap allocated (initialized with malloc/calloc/realloc)
    fn is_heap_allocated(&self, declaration: &Node, source: &str) -> bool {
        let decl_text = get_node_text(declaration, source);
        decl_text.contains("malloc")
            || decl_text.contains("calloc")
            || decl_text.contains("realloc")
    }

    /// Check if a declaration is an array (e.g., char env[1024])
    fn is_array_declaration(&self, declaration: &Node, source: &str) -> bool {
        let decl_text = get_node_text(declaration, source);
        // Simple heuristic: check for square brackets
        decl_text.contains('[') && decl_text.contains(']')
    }

    /// Check if a declaration is a pointer (e.g., char *env)
    fn is_pointer_declaration(&self, declaration: &Node, source: &str) -> bool {
        let decl_text = get_node_text(declaration, source);
        // Simple heuristic: check for pointer declaration
        // This is simplified and may need refinement
        decl_text.contains('*') && !decl_text.contains('[')
    }
}
