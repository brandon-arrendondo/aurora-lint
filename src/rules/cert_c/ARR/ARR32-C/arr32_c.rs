use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{get_sanitized_node_text, is_likely_macro_constant};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Arr32C;

impl CertRule for Arr32C {
    fn rule_id(&self) -> &'static str {
        "ARR32-C"
    }

    fn description(&self) -> &'static str {
        "Ensure size arguments for variable length arrays are in a valid range"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "ARR32-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        for n in
            query::find_descendants_of_kinds(*node, &["array_declarator", "parameter_declaration"])
        {
            match n.kind() {
                // Look for variable length array declarations (LOCAL declarations, not function parameters)
                "array_declarator" => {
                    // Skip if this is a function parameter (handled separately below)
                    if is_function_parameter(&n) {
                        // Don't check function parameters here - they're handled in the parameter_declaration check
                    } else if let Some(size_node) = n.child_by_field_name("size") {
                        let start_point = n.start_position();

                        // Check if this is a VLA (size is not a constant)
                        if is_variable_length_array(&size_node, source) {
                            let size_text = &source[size_node.start_byte()..size_node.end_byte()];

                            // Check for obvious violations
                            if is_problematic_vla_size(&size_node, source) {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "Variable length array with potentially unsafe size '{}'. Ensure size is validated to be positive and within reasonable bounds.",
                                        size_text
                                    ),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some("Add bounds checking: if (size == 0 || size > MAX_ARRAY) { /* handle error */ }".to_string()),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
                // Look for function parameters that might be used as VLA sizes
                // Note: VLA parameters are safe if the caller validates the size.
                // We only flag VLA parameters that have suspicious patterns (like expressions).
                // We DON'T flag simple VLA parameters like array[n] or matrix[rows][cols]
                // because these are considered acceptable if the caller validates before calling.
                "parameter_declaration" => {
                    if let Some(declarator) = n.child_by_field_name("declarator") {
                        if declarator.kind() == "array_declarator" {
                            if let Some(size_node) = declarator.child_by_field_name("size") {
                                let size_text =
                                    &source[size_node.start_byte()..size_node.end_byte()];

                                // Only flag if the size is a complex expression (not just a simple parameter)
                                // Simple parameters like array[n] are acceptable VLA parameters
                                // if the caller validates n before calling
                                if is_problematic_vla_parameter(&size_node, source) {
                                    let start_point = n.start_position();
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::Medium,
                                        message: format!(
                                            "Function parameter VLA size '{}' uses complex expression. Ensure callers validate the size.",
                                            size_text
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some("Validate the size parameter before using it for VLA declaration".to_string()),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        violations
    }
}

fn is_variable_length_array(size_node: &Node, source: &str) -> bool {
    // A VLA has a size that is not a compile-time constant
    // Simple heuristic: if it's an identifier or expression (not a number literal)
    match size_node.kind() {
        "identifier" => {
            // ALL_CAPS identifiers are conventionally preprocessor constants, not VLAs
            let name = &source[size_node.start_byte()..size_node.end_byte()];
            !is_likely_macro_constant(name)
        }
        "binary_expression" => {
            // Check if all leaf identifiers are macro constants.
            // `MACRO_A * MACRO_B` is a compile-time constant expression.
            !is_all_constant_expression(size_node, source)
        }
        "call_expression" => true,
        "number_literal" => false,
        _ => {
            // Check if it contains any identifiers (making it non-constant)
            contains_identifier(size_node, source)
        }
    }
}

fn is_problematic_vla_size(size_node: &Node, source: &str) -> bool {
    let size_text = &source[size_node.start_byte()..size_node.end_byte()];

    // Check for obvious problematic patterns
    if size_text == "0" {
        return true;
    }

    // Check for identifiers without obvious bounds checking context
    if size_node.kind() == "identifier" {
        // Look for nearby bounds checking
        return !has_nearby_bounds_check(size_node, source);
    }

    // Check for expressions that might overflow
    if size_node.kind() == "binary_expression" {
        let operator = get_binary_operator(size_node, source);
        if operator == "*" || operator == "+" {
            // Potential for overflow
            return true;
        }
    }

    false
}

#[allow(dead_code)]
fn is_identifier_node(node: &Node) -> bool {
    node.kind() == "identifier"
}

fn contains_identifier(node: &Node, _source: &str) -> bool {
    if node.kind() == "identifier" {
        return true;
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if contains_identifier(&child, _source) {
                return true;
            }
        }
    }

    false
}

/// Check if a VLA parameter size is problematic
/// Simple parameter references (like array[n]) are acceptable VLA parameters
/// Complex expressions are potentially problematic
fn is_problematic_vla_parameter(size_node: &Node, _source: &str) -> bool {
    match size_node.kind() {
        // Simple identifiers are OK for VLA parameters (e.g., array[n])
        "identifier" => false,
        // Complex expressions in VLA parameters are problematic
        "binary_expression" | "call_expression" | "unary_expression" => true,
        _ => false,
    }
}

/// Check if an array_declarator is part of a function parameter
fn is_function_parameter(array_decl: &Node) -> bool {
    let mut current = array_decl.parent();
    while let Some(parent) = current {
        if parent.kind() == "parameter_declaration" {
            return true;
        }
        // Stop searching if we hit a function definition or declaration
        if parent.kind() == "function_definition" || parent.kind() == "declaration" {
            return false;
        }
        current = parent.parent();
    }
    false
}

fn has_nearby_bounds_check(node: &Node, source: &str) -> bool {
    // Get the variable name being used as VLA size
    let var_name = &source[node.start_byte()..node.end_byte()];

    // Find the enclosing function to search for validation
    let function_node = find_enclosing_function(node);
    if let Some(func) = function_node {
        // Get all statements in the function before the VLA declaration
        let vla_line = node.start_position().row;
        let func_body = find_function_body(&func);

        if let Some(body) = func_body {
            // Search for bounds checking patterns in statements before the VLA
            return has_prior_validation(&body, source, var_name, vla_line);
        }
    }

    // Fallback: check immediate context (grandparent), sanitized so a
    // comment/string literal can't spoof a bounds-check pattern and
    // silently suppress a genuine violation.
    if let Some(parent) = node.parent() {
        if let Some(grandparent) = parent.parent() {
            let context = get_sanitized_node_text(&grandparent, source);

            // Look for common bounds checking patterns
            return context.contains("if")
                && (context.contains("== 0")
                    || context.contains("> ")
                    || context.contains("< ")
                    || context.contains("MAX_")
                    || context.contains("SIZE_MAX"));
        }
    }
    false
}

/// Find the enclosing function definition for a node
fn find_enclosing_function<'a>(node: &'a Node) -> Option<Node<'a>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind() == "function_definition" {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

/// Find the compound_statement (body) of a function
fn find_function_body<'a>(func_node: &'a Node) -> Option<Node<'a>> {
    for i in 0..func_node.child_count() {
        if let Some(child) = func_node.child(i) {
            if child.kind() == "compound_statement" {
                return Some(child);
            }
        }
    }
    None
}

/// Check if there's validation for a variable before a given line
fn has_prior_validation(body_node: &Node, source: &str, var_name: &str, vla_line: usize) -> bool {
    // Search through statements in the function body
    for i in 0..body_node.child_count() {
        if let Some(stmt) = body_node.child(i) {
            let stmt_line = stmt.start_position().row;

            // Only check statements BEFORE the VLA declaration
            if stmt_line >= vla_line {
                break;
            }

            // Check if this statement validates the variable
            if stmt.kind() == "if_statement" {
                // Sanitized so a comment/string literal inside the if-block
                // can't spoof a validation pattern and silently suppress a
                // genuine VLA-size violation.
                let stmt_text = get_sanitized_node_text(&stmt, source);

                // Look for validation patterns involving the variable
                if stmt_text.contains(var_name) {
                    // Pattern 1: Direct bounds checking (size < MAX, size == 0, etc.)
                    if stmt_text.contains("== 0")
                        || stmt_text.contains("!= 0")
                        || stmt_text.contains("> ")
                        || stmt_text.contains("< ")
                        || stmt_text.contains(">=")
                        || stmt_text.contains("<=")
                        || stmt_text.contains("MAX_")
                        || stmt_text.contains("SIZE_MAX")
                    {
                        return true;
                    }

                    // Pattern 2: Function call validation (e.g., if (!is_safe_size(var)))
                    // Look for patterns like: if (!func_name(var, ...)) { return/break; }
                    if (stmt_text.contains("!") || stmt_text.contains("== false"))
                        && stmt_text.contains("(")
                    {
                        // Check if the if-statement body contains return/break (early exit pattern)
                        if stmt_text.contains("return") || stmt_text.contains("break") {
                            return true;
                        }
                    }

                    // Pattern 3: Positive function call validation (e.g., if (is_valid(var)))
                    // with proper handling in else or subsequent code
                    if stmt_text.contains("(") && !stmt_text.contains("!") {
                        // This is a positive check - assume it's validation if it's checking the variable
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Check if an expression tree consists entirely of compile-time constants:
/// numeric literals, ALL_CAPS macro identifiers, sizeof, and arithmetic operators.
fn is_all_constant_expression(node: &Node, source: &str) -> bool {
    match node.kind() {
        "number_literal" => true,
        "identifier" => {
            let name = &source[node.start_byte()..node.end_byte()];
            is_likely_macro_constant(name)
        }
        "binary_expression" | "parenthesized_expression" => {
            // All children must be constant
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    match child.kind() {
                        // Operators and parens are fine
                        "+" | "-" | "*" | "/" | "%" | "<<" | ">>" | "&" | "|" | "^" | "(" | ")" => {
                        }
                        _ => {
                            if !is_all_constant_expression(&child, source) {
                                return false;
                            }
                        }
                    }
                }
            }
            true
        }
        "sizeof_expression" => true,
        _ => false,
    }
}

fn get_binary_operator<'a>(node: &Node, source: &'a str) -> &'a str {
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            let child_text = &source[child.start_byte()..child.end_byte()];
            if child_text == "*" || child_text == "+" || child_text == "-" || child_text == "/" {
                return child_text;
            }
        }
    }
    ""
}
