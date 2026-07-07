//! STR06-C: Do not assume that strtok() leaves the parse string unchanged
//!
//! The strtok() function modifies its input string by replacing delimiters with
//! null bytes, making the original string unsafe to use. This rule detects unsafe
//! usage patterns.
//!
//! ## Non-compliant example:
//!
//! ```c
//! char *path = getenv("PATH");
//! char *token = strtok(path, ":");  // Modifies environment variable!
//! printf("PATH: %s\n", path);        // PATH is now corrupted
//!
//! // Or using string literal
//! char *tok = strtok("a:b:c", ":");  // Undefined behavior!
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! char *path = getenv("PATH");
//! char *path_copy = malloc(strlen(path) + 1);
//! strcpy(path_copy, path);
//! char *token = strtok(path_copy, ":");  // Modifies copy only
//! free(path_copy);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Str06C;

impl Str06C {
    pub fn new() -> Self {
        Self
    }

    /// Get the first argument from an argument list node
    fn get_first_argument<'a>(&self, args_node: &Node<'a>) -> Option<Node<'a>> {
        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                // Skip '(' and ')' and ',' tokens
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Check if a node is a string literal
    fn is_string_literal(&self, node: &Node) -> bool {
        matches!(node.kind(), "string_literal" | "concatenated_string")
    }

    /// Check if a node is a getenv() call
    fn is_getenv_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                let function_name = get_node_text(&function_node, source);
                return function_name == "getenv";
            }
        }
        false
    }

    /// Check if a node looks like a function call (heuristic)
    fn looks_like_function_call(&self, node: &Node) -> bool {
        node.kind() == "call_expression"
    }
}

impl CertRule for Str06C {
    fn rule_id(&self) -> &'static str {
        "STR06-C"
    }

    fn description(&self) -> &'static str {
        "Do not assume that strtok() leaves the parse string unchanged"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "STR06-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Str06C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // First pass: collect variables assigned from getenv()
        let getenv_vars = self.collect_getenv_vars(node, source);

        // Second pass: check strtok calls
        self.check_strtok_calls_recursive(node, source, violations, &getenv_vars);
    }

    fn collect_getenv_vars(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut vars = HashSet::new();
        self.collect_getenv_vars_recursive(node, source, &mut vars);
        vars
    }

    fn collect_getenv_vars_recursive(&self, node: &Node, source: &str, vars: &mut HashSet<String>) {
        for node in query::find_descendants(*node, |_| true) {
            let node = &node;
            // Check for declarations: char *path = getenv("PATH");
            if node.kind() == "declaration" {
                if let Some(init_decl) = node.child_by_field_name("declarator") {
                    self.check_declarator_for_getenv(&init_decl, source, vars);
                }
                // Also check init_declarator children
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "init_declarator" {
                            self.check_declarator_for_getenv(&child, source, vars);
                        }
                    }
                }
            }

            // Check for assignments: path = getenv("PATH");
            if node.kind() == "assignment_expression" {
                if let Some(left) = node.child_by_field_name("left") {
                    if let Some(right) = node.child_by_field_name("right") {
                        if self.is_getenv_call(&right, source) {
                            let var_name = get_node_text(&left, source);
                            vars.insert(var_name.to_string());
                        }
                    }
                }
            }
        }
    }

    fn check_declarator_for_getenv(&self, node: &Node, source: &str, vars: &mut HashSet<String>) {
        // Look for init_declarator with getenv() as value
        if node.kind() == "init_declarator" {
            let mut var_name = None;
            let mut has_getenv = false;

            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    if child.kind() == "pointer_declarator" || child.kind() == "identifier" {
                        var_name = Some(self.extract_identifier(&child, source));
                    }
                    if self.is_getenv_call(&child, source) {
                        has_getenv = true;
                    }
                }
            }

            if has_getenv {
                if let Some(name) = var_name {
                    vars.insert(name);
                }
            }
        }
    }

    fn extract_identifier(&self, node: &Node, source: &str) -> String {
        if node.kind() == "identifier" {
            return get_node_text(node, source).to_string();
        }
        // For pointer_declarator, recurse to find identifier
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                let result = self.extract_identifier(&child, source);
                if !result.is_empty() {
                    return result;
                }
            }
        }
        String::new()
    }

    fn check_strtok_calls_recursive(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        getenv_vars: &HashSet<String>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_strtok_call_with_vars(&n, source, violations, getenv_vars);
        }
    }

    fn check_strtok_call_with_vars(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        getenv_vars: &HashSet<String>,
    ) {
        if node.kind() != "call_expression" {
            return;
        }

        if let Some(function_node) = node.child_by_field_name("function") {
            let function_name = get_node_text(&function_node, source);

            if function_name == "strtok" {
                self.check_strtok_argument_with_vars(node, source, violations, getenv_vars);
            }
        }
    }

    fn check_strtok_argument_with_vars(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        getenv_vars: &HashSet<String>,
    ) {
        if let Some(args_node) = node.child_by_field_name("arguments") {
            // Get first argument
            if let Some(first_arg) = self.get_first_argument(&args_node) {
                let arg_text = get_node_text(&first_arg, source);

                // Check for string literal (definitely wrong)
                if self.is_string_literal(&first_arg) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: "Passing string literal to strtok() is undefined behavior. strtok() modifies its input by replacing delimiters with null bytes, and string literals are immutable.".to_string(),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(
                            "Create a mutable copy of the string before passing to strtok()."
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                    return;
                }

                // Check for getenv() call (definitely wrong)
                if self.is_getenv_call(&first_arg, source) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: "Passing getenv() result to strtok() modifies the environment variable. strtok() replaces delimiters with null bytes, corrupting the environment string.".to_string(),
                        file_path: String::new(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        suggestion: Some(
                            "Create a mutable copy using malloc() and strcpy() before passing to strtok()."
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                    return;
                }

                // Check for variable assigned from getenv()
                if first_arg.kind() == "identifier" {
                    let var_name = arg_text.trim();
                    if getenv_vars.contains(var_name) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!(
                                "Variable '{}' was assigned from getenv() and passed to strtok(). strtok() modifies its input, corrupting the environment string.",
                                var_name
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "Create a mutable copy using malloc() and strcpy() before passing to strtok()."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                        return;
                    }
                }

                // General warning for non-NULL first argument
                // (NULL is used for subsequent calls to continue tokenization)
                if arg_text.trim() != "NULL" && arg_text.trim() != "0" {
                    // Check if it looks like a function call (heuristic)
                    if self.looks_like_function_call(&first_arg) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Low,
                            message: format!(
                                "Passing function return value '{}' to strtok(). Ensure this is a mutable copy, not a pointer to static/const data. strtok() modifies its input by replacing delimiters with null bytes.",
                                arg_text.trim()
                            ),
                            file_path: String::new(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            suggestion: Some(
                                "If the string source is immutable or shared, create a mutable copy before passing to strtok()."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
}
