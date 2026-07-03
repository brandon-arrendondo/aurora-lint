//! MSC39-C: Do not call va_arg() on a va_list that has an indeterminate value
//!
//! This rule addresses undefined behavior that occurs when a va_list is used after
//! being passed to a function that calls va_arg() on it. According to the C Standard
//! (7.16, paragraph 3), if a function invokes va_arg with a va_list parameter, the
//! representation of that va_list in the calling function becomes indeterminate.
//!
//! ## Non-compliant examples:
//!
//! **Function that modifies caller's va_list:**
//! ```c
//! int contains_zero(size_t count, va_list ap) {  // Takes va_list by value
//!     for (size_t i = 1; i < count; ++i) {
//!         if (va_arg(ap, double) == 0.0) {  // Modifies va_list
//!             return 1;
//!         }
//!     }
//!     return 0;
//! }
//!
//! int print_reciprocals(size_t count, ...) {
//!     va_list ap;
//!     va_start(ap, count);
//!
//!     if (contains_zero(count, ap)) {  // Passes va_list
//!         va_end(ap);
//!         return 1;
//!     }
//!
//!     // ap now has indeterminate value - undefined behavior!
//!     for (size_t i = 0; i < count; ++i) {
//!         printf("%f ", 1.0 / va_arg(ap, double));
//!     }
//!
//!     va_end(ap);
//!     return 0;
//! }
//! ```
//!
//! ## Compliant solutions:
//!
//! **Use va_list pointer and va_copy:**
//! ```c
//! int contains_zero(size_t count, va_list *ap) {  // Takes pointer
//!     va_list ap1;
//!     va_copy(ap1, *ap);  // Create a copy
//!     for (size_t i = 1; i < count; ++i) {
//!         if (va_arg(ap1, double) == 0.0) {
//!             va_end(ap1);
//!             return 1;
//!         }
//!     }
//!     va_end(ap1);
//!     return 0;
//! }
//!
//! int print_reciprocals(size_t count, ...) {
//!     va_list ap;
//!     va_start(ap, count);
//!
//!     if (contains_zero(count, &ap)) {  // Pass address
//!         va_end(ap);
//!         return 1;
//!     }
//!
//!     // ap still has determinate value - safe!
//!     for (size_t i = 0; i < count; ++i) {
//!         printf("%f ", 1.0 / va_arg(ap, double));
//!     }
//!
//!     va_end(ap);
//!     return 0;
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Msc39C;

impl Msc39C {
    pub fn new() -> Self {
        Self
    }

    /// Check if a type is va_list (by value, not pointer)
    fn is_va_list_type(&self, type_node: &Node, source: &str) -> bool {
        let type_text = get_node_text(type_node, source);
        // Check for va_list but not va_list* (pointer)
        type_text.contains("va_list") && !type_text.contains('*')
    }

    /// Check if a type is va_list pointer
    #[allow(dead_code)]
    fn is_va_list_pointer(&self, type_node: &Node, source: &str) -> bool {
        let type_text = get_node_text(type_node, source);
        type_text.contains("va_list") && type_text.contains('*')
    }

    /// Extract parameter name from parameter declaration
    fn get_parameter_name(&self, param: &Node, source: &str) -> Option<String> {
        if let Some(declarator) = param.child_by_field_name("declarator") {
            return self.extract_identifier(&declarator, source);
        }
        None
    }

    /// Extract identifier from declarator
    fn extract_identifier(&self, node: &Node, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" => Some(get_node_text(node, source).trim().to_string()),
            "pointer_declarator" | "array_declarator" | "function_declarator" => {
                if let Some(decl) = node.child_by_field_name("declarator") {
                    return self.extract_identifier(&decl, source);
                }
                None
            }
            _ => {
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "identifier" {
                            return Some(get_node_text(&child, source).trim().to_string());
                        }
                    }
                }
                None
            }
        }
    }

    /// Check if function body contains va_arg calls on a specific parameter
    fn has_va_arg_on_param(&self, body: &Node, param_name: &str, source: &str) -> bool {
        query::find_first_descendant(*body, |node| {
            if node.kind() != "call_expression" {
                return false;
            }
            let Some(function_node) = node.child_by_field_name("function") else {
                return false;
            };
            let function_name = get_node_text(&function_node, source).trim().to_string();
            if function_name != "va_arg" {
                return false;
            }
            // Check if the first argument is the parameter
            let Some(arguments) = node.child_by_field_name("arguments") else {
                return false;
            };
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if arg.kind() == "identifier" {
                        // Only check first argument
                        let arg_text = get_node_text(&arg, source).trim();
                        return arg_text == param_name;
                    }
                }
            }
            false
        })
        .is_some()
    }

    /// Check function definitions for va_list parameters that are used with va_arg
    fn check_function_definition(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "function_definition" {
            return;
        }

        // Get function declarator
        let declarator = match node.child_by_field_name("declarator") {
            Some(d) => d,
            None => return,
        };

        // Find parameter list
        let params_node = self.find_parameters(&declarator);
        if params_node.is_none() {
            return;
        }
        let params_node = params_node.unwrap();

        // Get function body
        let body = match node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // Check each parameter
        for i in 0..params_node.child_count() {
            if let Some(param) = params_node.child(i) {
                if param.kind() == "parameter_declaration" {
                    // Check if parameter is va_list (by value)
                    if let Some(type_node) = param.child_by_field_name("type") {
                        if self.is_va_list_type(&type_node, source) {
                            // Get parameter name
                            if let Some(param_name) = self.get_parameter_name(&param, source) {
                                // Check if function calls va_arg on this parameter
                                if self.has_va_arg_on_param(&body, &param_name, source) {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: self.severity(),
                                        message: format!(
                                            "Function takes 'va_list {}' by value and calls va_arg() on it. This makes the caller's va_list indeterminate after the function returns.",
                                            param_name
                                        ),
                                        file_path: String::new(),
                                        line: param.start_position().row + 1,
                                        column: param.start_position().column + 1,
                                        suggestion: Some(
                                            format!("Change parameter '{}' to 'va_list *{}' and use va_copy() to create a local copy before calling va_arg().", param_name, param_name)
                                        ),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Find parameter list in function declarator
    fn find_parameters<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        if node.kind() == "parameter_list" {
            return Some(*node);
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(params) = self.find_parameters(&child) {
                    return Some(params);
                }
            }
        }
        None
    }
}

impl CertRule for Msc39C {
    fn rule_id(&self) -> &'static str {
        "MSC39-C"
    }

    fn description(&self) -> &'static str {
        "Do not call va_arg() on a va_list that has an indeterminate value"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MSC39-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Msc39C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check function definitions
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function_definition(&func, source, violations);
        }
    }
}
