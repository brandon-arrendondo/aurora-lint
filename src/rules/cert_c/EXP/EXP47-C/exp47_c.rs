// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 BISSELL Homecare, Inc.

//! EXP47-C: Do not call va_arg with an argument of the incorrect type
//!
//! This rule detects when va_arg is called with a type that doesn't match
//! the type of the actual argument after default argument promotions.
//! Common violations include using va_arg with char, short, or float types
//! which undergo promotion to int/unsigned int or double when passed.
//!
//! CERT C reference:
//! https://wiki.sei.cmu.edu/confluence/display/c/EXP47-C.+Do+not+call+va_arg+with+an+argument+of+the+incorrect+type

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

#[derive(Debug)]
pub struct Exp47C;

/// Information about a variadic function
#[derive(Debug, Clone)]
struct VariadicFuncInfo {
    /// Number of fixed parameters (before ...)
    fixed_param_count: usize,
    /// Number of va_arg calls in the function body
    va_arg_count: usize,
}

impl Exp47C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Exp47C
    }

    /// Check if a type undergoes default argument promotion
    /// Types that promote:
    /// - char, signed char, unsigned char -> int
    /// - short, unsigned short -> int (or unsigned int if larger)
    /// - float -> double
    fn is_promoted_type(&self, type_text: &str) -> Option<&'static str> {
        let trimmed = type_text.trim();

        // Check for char types (promote to int)
        if trimmed == "char"
            || trimmed == "signed char"
            || trimmed == "unsigned char"
            || trimmed.ends_with(" char")
        {
            return Some("int");
        }

        // Check for short types (promote to int or unsigned int)
        if trimmed == "short"
            || trimmed == "short int"
            || trimmed == "signed short"
            || trimmed == "signed short int"
        {
            return Some("int");
        }

        if trimmed == "unsigned short" || trimmed == "unsigned short int" {
            return Some("int or unsigned int");
        }

        // Check for float (promotes to double)
        if trimmed == "float" {
            return Some("double");
        }

        None
    }

    /// Extract the type argument from a va_arg call
    fn extract_va_arg_type<'a>(&self, node: &'a Node, source: &'a str) -> Option<String> {
        // va_arg is typically a macro call_expression
        // Looking for: va_arg(ap, type)
        if node.kind() != "call_expression" {
            return None;
        }

        // Check if this is a va_arg call
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source).trim().to_string();
            if func_name != "va_arg" {
                return None;
            }
        } else {
            return None;
        }

        // Get the arguments
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // arguments is an argument_list node
            let mut cursor = arguments.walk();
            let mut arg_count = 0;

            for child in arguments.children(&mut cursor) {
                // Skip the parentheses and commas
                if child.kind() == "(" || child.kind() == ")" || child.kind() == "," {
                    continue;
                }

                arg_count += 1;

                // The second argument is the type (might be a type_descriptor node)
                if arg_count == 2 {
                    let type_text = get_node_text(&child, source).trim().to_string();
                    return Some(type_text);
                }
            }
        }

        // Also check for generic_expression or other macro expansion patterns
        // va_arg may expand to different AST structures
        let node_text = get_node_text(node, source);
        if node_text.contains("va_arg") {
            // Try to extract the type from the text directly
            // Pattern: va_arg(something, type)
            if let Some(start) = node_text.find(',') {
                let after_comma = &node_text[start + 1..];
                if let Some(end) = after_comma.rfind(')') {
                    let type_text = after_comma[..end].trim().to_string();
                    if !type_text.is_empty() {
                        return Some(type_text);
                    }
                }
            }
        }

        None
    }

    /// Check a va_arg call for incorrect type usage
    fn check_va_arg_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(type_text) = self.extract_va_arg_type(node, source) {
            if let Some(correct_type) = self.is_promoted_type(&type_text) {
                violations.push(RuleViolation {
                    rule_id: "EXP47-C".to_string(),
                    severity: Severity::Medium,
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: format!(
                        "va_arg called with type '{}' which undergoes default argument promotion; use '{}' instead",
                        type_text, correct_type
                    ),
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Change va_arg type to '{}' and cast the result if needed: ({})va_arg(ap, {})",
                        correct_type, type_text, correct_type
                    )),
                    requires_manual_review: Some(false),
                });
            }
        }
    }

    /// Recursively traverse AST
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            // Check if this is a call expression (potential va_arg call)
            if n.kind() == "call_expression" {
                self.check_va_arg_call(&n, source, violations);
            }

            // Also check for va_arg pattern in text for any node type
            // (va_arg may be expanded by macros or parsed differently)
            let node_text = get_node_text(&n, source);
            if node_text.contains("va_arg(") && n.kind() != "call_expression" {
                // Try text-based detection as fallback
                self.check_va_arg_text(&n, &node_text, violations);
            }
        }
    }

    /// Check for va_arg with incorrect type using text-based analysis
    fn check_va_arg_text(&self, node: &Node, text: &str, violations: &mut Vec<RuleViolation>) {
        // Find all va_arg( patterns in the text
        let mut start_pos = 0;
        while let Some(pos) = text[start_pos..].find("va_arg(") {
            let absolute_pos = start_pos + pos;
            let after_va_arg = &text[absolute_pos + 7..]; // Skip "va_arg("

            // Find the comma separating arguments
            if let Some(comma_pos) = after_va_arg.find(',') {
                let after_comma = &after_va_arg[comma_pos + 1..];
                // Find the closing paren
                if let Some(paren_pos) = after_comma.find(')') {
                    let type_text = after_comma[..paren_pos].trim();

                    if let Some(correct_type) = self.is_promoted_type(type_text) {
                        violations.push(RuleViolation {
                            rule_id: "EXP47-C".to_string(),
                            severity: Severity::Medium,
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            message: format!(
                                "va_arg called with type '{}' which undergoes default argument promotion; use '{}' instead",
                                type_text, correct_type
                            ),
                            file_path: String::new(),
                            suggestion: Some(format!(
                                "Change va_arg type to '{}' and cast the result if needed: ({})va_arg(ap, {})",
                                correct_type, type_text, correct_type
                            )),
                            requires_manual_review: Some(false),
                        });
                    }
                }
            }
            start_pos = absolute_pos + 7;
        }
    }

    /// Collect information about variadic functions defined in the source
    fn collect_variadic_functions(
        &self,
        node: &Node,
        source: &str,
        funcs: &mut HashMap<String, VariadicFuncInfo>,
    ) {
        for n in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(declarator) = n.child_by_field_name("declarator") {
                // Check if this is a variadic function
                let decl_text = get_node_text(&declarator, source);
                if decl_text.contains("...") {
                    // Extract function name
                    if let Some(func_name) = self.extract_function_name(&declarator, source) {
                        // Count fixed parameters
                        let fixed_params = self.count_fixed_params(&declarator, source);
                        // Count UNCONDITIONAL va_arg calls in body
                        let va_arg_count = if let Some(body) = n.child_by_field_name("body") {
                            self.count_unconditional_va_arg_calls(&body, source)
                        } else {
                            0
                        };

                        funcs.insert(
                            func_name,
                            VariadicFuncInfo {
                                fixed_param_count: fixed_params,
                                va_arg_count,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Extract function name from declarator
    fn extract_function_name(&self, declarator: &Node, source: &str) -> Option<String> {
        if declarator.kind() == "function_declarator" {
            if let Some(name_node) = declarator.child_by_field_name("declarator") {
                return Some(get_node_text(&name_node, source).trim().to_string());
            }
        }
        // Try children
        let mut cursor = declarator.walk();
        for child in declarator.children(&mut cursor) {
            if let Some(name) = self.extract_function_name(&child, source) {
                return Some(name);
            }
        }
        None
    }

    /// Count fixed parameters (non-variadic)
    fn count_fixed_params(&self, declarator: &Node, source: &str) -> usize {
        let text = get_node_text(declarator, source);
        // Find the parameter list
        // Pattern: func(param1, param2, ...) or func(...)
        if let Some(start) = text.find('(') {
            if let Some(ellipsis_pos) = text.find("...") {
                let params_text = &text[start + 1..ellipsis_pos];
                // Remove trailing comma and whitespace
                let params_text = params_text.trim().trim_end_matches(',').trim();
                if params_text.is_empty() {
                    return 0;
                }
                // Number of fixed params = number of commas + 1
                // e.g., "size_t num_vargs" has 0 commas -> 1 param
                // e.g., "const char *cp, size_t n" has 1 comma -> 2 params
                return params_text.matches(',').count() + 1;
            }
        }
        0
    }

    /// Count UNCONDITIONAL va_arg calls in a function body
    /// Only counts va_arg calls that are not nested inside if/while/for/switch statements
    fn count_unconditional_va_arg_calls(&self, body: &Node, source: &str) -> usize {
        let mut count = 0;
        self.count_va_arg_at_depth(body, source, 0, &mut count);
        count
    }

    /// Recursively count va_arg calls, only counting those at conditional depth 0
    fn count_va_arg_at_depth(
        &self,
        node: &Node,
        source: &str,
        conditional_depth: usize,
        count: &mut usize,
    ) {
        // Check if this node contains a va_arg call (AST-based detection)
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim().to_string();
                if func_name == "va_arg" && conditional_depth == 0 {
                    *count += 1;
                    return; // Found a va_arg, don't recurse into its children
                }
            }
        }

        // Text-based fallback for macro expansion cases - only for leaf-ish nodes
        // Only check if this specific statement/expression contains va_arg and has no
        // conditional children (to avoid double counting)
        if conditional_depth == 0
            && matches!(
                node.kind(),
                "expression_statement" | "declaration" | "init_declarator"
            )
        {
            let node_text = get_node_text(node, source);
            if node_text.contains("va_arg(") && !self.has_conditional_children(node) {
                *count += node_text.matches("va_arg(").count();
                return; // Don't recurse further
            }
        }

        // Increase depth when entering conditional structures
        let new_depth = if matches!(
            node.kind(),
            "if_statement"
                | "while_statement"
                | "for_statement"
                | "switch_statement"
                | "do_statement"
        ) {
            conditional_depth + 1
        } else {
            conditional_depth
        };

        // Recurse into children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.count_va_arg_at_depth(&child, source, new_depth, count);
        }
    }

    /// Check if a node has any conditional statement children
    fn has_conditional_children(&self, node: &Node) -> bool {
        query::find_first_descendant(*node, |n| {
            matches!(
                n.kind(),
                "if_statement"
                    | "while_statement"
                    | "for_statement"
                    | "switch_statement"
                    | "do_statement"
            )
        })
        .is_some()
    }

    /// Check calls to variadic functions
    fn check_variadic_calls(
        &self,
        node: &Node,
        source: &str,
        funcs: &HashMap<String, VariadicFuncInfo>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = n.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim().to_string();

                if let Some(info) = funcs.get(&func_name) {
                    // Count actual arguments passed
                    let actual_args = if let Some(args) = n.child_by_field_name("arguments") {
                        self.count_arguments(&args)
                    } else {
                        0
                    };

                    // Check if enough variadic arguments are passed
                    let variadic_args_passed = actual_args.saturating_sub(info.fixed_param_count);
                    if variadic_args_passed < info.va_arg_count {
                        violations.push(RuleViolation {
                            rule_id: "EXP47-C".to_string(),
                            severity: Severity::Medium,
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            message: format!(
                                "Call to variadic function '{}' passes {} variadic argument(s) but function uses va_arg {} time(s)",
                                func_name, variadic_args_passed, info.va_arg_count
                            ),
                            file_path: String::new(),
                            suggestion: Some(format!(
                                "Pass at least {} variadic argument(s) to match va_arg usage in '{}'",
                                info.va_arg_count, func_name
                            )),
                            requires_manual_review: Some(false),
                        });
                    }
                }
            }
        }
    }

    /// Count arguments in an argument list
    fn count_arguments(&self, args: &Node) -> usize {
        let mut count = 0;
        let mut cursor = args.walk();
        for child in args.children(&mut cursor) {
            // Skip parentheses and commas
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                count += 1;
            }
        }
        count
    }
}

impl CertRule for Exp47C {
    fn rule_id(&self) -> &'static str {
        "EXP47-C"
    }

    fn description(&self) -> &'static str {
        "Do not call va_arg with an argument of the incorrect type"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "EXP47-C"
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First, collect information about variadic functions defined in the source
        let mut variadic_funcs = HashMap::new();
        self.collect_variadic_functions(root, source, &mut variadic_funcs);

        // Check for incorrect va_arg type usage
        self.traverse(root, source, &mut violations);

        // Check calls to variadic functions for insufficient arguments
        self.check_variadic_calls(root, source, &variadic_funcs, &mut violations);

        violations
    }
}
