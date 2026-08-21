// DCL11-C: Understand the type issues associated with variadic functions
//
// This rule detects type mismatches between printf-style format specifiers
// and the actual argument types, which can lead to undefined behavior.
//
// Detection strategy:
// 1. Find printf-family function calls (printf, fprintf, sprintf, etc.)
// 2. Parse the format string to extract format specifiers
// 3. Match format specifiers against actual argument types
// 4. Flag violations when types don't match (e.g., %s with int, %d with long long)

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::call_roles;
use tree_sitter::Node;

pub struct Dcl11C;

impl Dcl11C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Dcl11C
    }

    /// Check a node and all its descendants for violations
    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for printf-family function calls
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);

                // Check if this is a printf-family function
                if self.is_printf_family(func_name) {
                    self.check_printf_call(node, source, func_name, violations);
                }
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, violations);
            }
        }
    }

    /// Check if function name is a printf-family function
    fn is_printf_family(&self, name: &str) -> bool {
        call_roles::is_printf_family(name)
    }

    /// Check a printf-family function call for type mismatches
    fn check_printf_call<'a>(
        &self,
        call_node: &Node<'a>,
        source: &'a str,
        func_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            let arg_nodes = self.extract_arguments(&args, source);

            if arg_nodes.is_empty() {
                return;
            }

            // First argument should be format string (except for fprintf which has file first)
            let format_idx = if func_name.starts_with('f') && func_name != "fwprintf" {
                1
            } else {
                0
            };

            if arg_nodes.len() <= format_idx {
                return;
            }

            // Try to extract format string
            if let Some(format_str) = self.extract_format_string(&arg_nodes[format_idx], source) {
                // Parse format specifiers
                let specifiers = self.parse_format_specifiers(&format_str);

                // Get actual argument types
                let actual_args = &arg_nodes[format_idx + 1..];

                // Check if argument count matches
                if specifiers.len() != actual_args.len() {
                    // Argument count mismatch - likely swapped or missing args
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        line: call_node.start_position().row + 1,
                        column: call_node.start_position().column + 1,
                        message: format!(
                            "Format string expects {} arguments but {} provided - possible type mismatch",
                            specifiers.len(), actual_args.len()
                        ),
                        severity: self.severity(),
                        file_path: String::new(),
                        suggestion: Some("Ensure format specifiers match the number and types of arguments".to_string()),
                        requires_manual_review: None,
                    });
                    return;
                }

                // Check each argument against its format specifier
                for (idx, (spec, arg)) in specifiers.iter().zip(actual_args.iter()).enumerate() {
                    if let Some(expected_type) = self.format_spec_to_type(spec) {
                        let actual_type = self.infer_argument_type(arg, source);

                        if !self.types_compatible(&expected_type, &actual_type) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                line: arg.start_position().row + 1,
                                column: arg.start_position().column + 1,
                                message: format!(
                                    "Type mismatch in variadic function call: format specifier '{}' expects {} but argument {} is {}",
                                    spec, expected_type, idx + 1, actual_type
                                ),
                                severity: self.severity(),
                                file_path: String::new(),
                                suggestion: Some(format!(
                                    "Use correct format specifier for {} or cast argument to {}",
                                    actual_type, expected_type
                                )),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Extract arguments from argument list
    fn extract_arguments<'a>(&self, args_node: &Node<'a>, _source: &'a str) -> Vec<Node<'a>> {
        let mut args = Vec::new();

        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    args.push(child);
                }
            }
        }

        args
    }

    /// Try to extract format string literal
    fn extract_format_string<'a>(&self, node: &Node<'a>, source: &'a str) -> Option<String> {
        let text = get_node_text(node, source);

        // Check if it's a string literal
        if text.starts_with('"') && text.ends_with('"') {
            // Remove quotes and unescape
            let content = &text[1..text.len() - 1];
            return Some(content.to_string());
        }

        None
    }

    /// Parse format specifiers from format string
    fn parse_format_specifiers(&self, format: &str) -> Vec<String> {
        let mut specs = Vec::new();
        let mut chars = format.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '%' {
                if let Some(&next) = chars.peek() {
                    if next == '%' {
                        // Escaped %
                        chars.next();
                        continue;
                    }

                    // Parse format specifier
                    let mut spec = String::from("%");

                    // Skip flags (-, +, space, #, 0)
                    while let Some(&c) = chars.peek() {
                        if matches!(c, '-' | '+' | ' ' | '#' | '0') {
                            spec.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    // Skip width
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_digit() || c == '*' {
                            spec.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    // Skip precision
                    if let Some(&'.') = chars.peek() {
                        spec.push('.');
                        chars.next();
                        while let Some(&c) = chars.peek() {
                            if c.is_ascii_digit() || c == '*' {
                                spec.push(c);
                                chars.next();
                            } else {
                                break;
                            }
                        }
                    }

                    // Length modifier (hh, h, l, ll, L, z, t, j)
                    let mut length_mod = String::new();
                    if let Some(&c) = chars.peek() {
                        if matches!(c, 'h' | 'l' | 'L' | 'z' | 't' | 'j') {
                            length_mod.push(c);
                            spec.push(c);
                            chars.next();

                            // Check for double (hh, ll)
                            if (c == 'h' || c == 'l') && chars.peek() == Some(&c) {
                                length_mod.push(c);
                                spec.push(c);
                                chars.next();
                            }
                        }
                    }

                    // Conversion specifier
                    if let Some(c) = chars.next() {
                        spec.push(c);
                        specs.push(spec);
                    }
                }
            }
        }

        specs
    }

    /// Convert format specifier to expected type
    fn format_spec_to_type(&self, spec: &str) -> Option<String> {
        // Extract the conversion character and length modifier
        let last_char = spec.chars().last()?;

        match last_char {
            'd' | 'i' => {
                if spec.contains("ll") {
                    Some("long long".to_string())
                } else if spec.contains('l') {
                    Some("long".to_string())
                } else if spec.contains("hh") {
                    Some("signed char".to_string())
                } else if spec.contains('h') {
                    Some("short".to_string())
                } else {
                    Some("int".to_string())
                }
            }
            'u' | 'o' | 'x' | 'X' => {
                if spec.contains("ll") {
                    Some("unsigned long long".to_string())
                } else if spec.contains('l') {
                    Some("unsigned long".to_string())
                } else {
                    Some("unsigned int".to_string())
                }
            }
            's' => Some("char*".to_string()),
            'c' => Some("int".to_string()), // char is promoted to int
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' => {
                if spec.contains('L') {
                    Some("long double".to_string())
                } else {
                    Some("double".to_string())
                }
            }
            'p' => Some("void*".to_string()),
            'n' => Some("int*".to_string()),
            _ => None,
        }
    }

    /// Infer argument type from AST node
    fn infer_argument_type<'a>(&self, node: &Node<'a>, source: &'a str) -> String {
        let text = get_node_text(node, source);

        // Check for NULL literal
        if text == "NULL" || text == "0" {
            return "NULL".to_string();
        }

        // Check for string literals
        if text.starts_with('"') {
            return "char*".to_string();
        }

        // Check for character literals
        if text.starts_with('\'') {
            return "int".to_string(); // char promoted to int
        }

        // Check for integer literals
        if text.chars().next().is_some_and(|c| c.is_ascii_digit()) {
            if text.contains("LL") || text.contains("ll") {
                return "long long".to_string();
            } else if text.contains('L') || text.contains('l') {
                return "long".to_string();
            }
            return "int".to_string();
        }

        // Check for floating point literals (only if starts with digit or contains decimal point)
        if text.starts_with(|c: char| c.is_ascii_digit()) || text.starts_with('.') {
            if text.contains('.') || text.contains('e') || text.contains('E') {
                if text.ends_with('f') || text.ends_with('F') {
                    return "float".to_string(); // will be promoted to double
                }
                return "double".to_string();
            }
        }

        // For identifiers, try to find their declaration
        if node.kind() == "identifier" {
            // Check if this variable is initialized to NULL
            if let Some(init_value) = self.find_variable_initializer(&text, node, source) {
                if init_value == "NULL" || init_value == "0" {
                    return "NULL".to_string();
                }
            }

            if let Some(var_type) = self.find_variable_type(&text, node, source) {
                return var_type;
            }
        }

        // Try to infer from variable type (would need type tracking)
        // For now, look for type hints in variable names
        if text.contains("msg") || text.contains("str") || text.contains("name") {
            return "char*".to_string();
        }

        "unknown".to_string()
    }

    /// Find variable type by searching for its declaration
    fn find_variable_type<'a>(
        &self,
        var_name: &str,
        current_node: &Node<'a>,
        source: &'a str,
    ) -> Option<String> {
        // Start from root and search for declaration
        let mut node = *current_node;
        while let Some(parent) = node.parent() {
            node = parent;
        }

        // Now search down from root for declarations
        self.search_for_declaration(&node, var_name, source)
    }

    /// Find variable initializer value (e.g., NULL check)
    fn find_variable_initializer<'a>(
        &self,
        var_name: &str,
        current_node: &Node<'a>,
        source: &'a str,
    ) -> Option<String> {
        // Start from root and search for declaration
        let mut node = *current_node;
        while let Some(parent) = node.parent() {
            node = parent;
        }

        // Search for declaration with initializer
        self.search_for_initializer(&node, var_name, source)
    }

    /// Recursively search for variable initializer
    fn search_for_initializer<'a>(
        &self,
        node: &Node<'a>,
        var_name: &str,
        source: &'a str,
    ) -> Option<String> {
        // Check if this is a declaration node
        if node.kind() == "declaration" {
            // Look for declarator with matching identifier
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(identifier) = self.find_identifier_in_declarator(&declarator, source) {
                    if identifier == var_name {
                        // Found the declaration! Check for initializer
                        for i in 0..declarator.child_count() {
                            if let Some(child) = declarator.child(i) {
                                if child.kind() == "=" {
                                    // Next child should be the initializer
                                    if let Some(init) = declarator.child(i + 1) {
                                        let init_text =
                                            get_node_text(&init, source).trim().to_string();
                                        return Some(init_text);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(init) = self.search_for_initializer(&child, var_name, source) {
                    return Some(init);
                }
            }
        }

        None
    }

    /// Recursively search for variable declaration
    fn search_for_declaration<'a>(
        &self,
        node: &Node<'a>,
        var_name: &str,
        source: &'a str,
    ) -> Option<String> {
        // Check if this is a declaration node
        if node.kind() == "declaration" {
            // Look for declarator with matching identifier
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(identifier) = self.find_identifier_in_declarator(&declarator, source) {
                    if identifier == var_name {
                        // Found the declaration! Extract type
                        if let Some(type_node) = node.child_by_field_name("type") {
                            let type_text = get_node_text(&type_node, source);
                            return Some(self.normalize_type(&type_text));
                        }
                    }
                }
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(type_str) = self.search_for_declaration(&child, var_name, source) {
                    return Some(type_str);
                }
            }
        }

        None
    }

    /// Find identifier in declarator (handling pointers, arrays, etc.)
    fn find_identifier_in_declarator<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
    ) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }

        // Handle pointer declarator, array declarator, etc.
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
                if let Some(id) = self.find_identifier_in_declarator(&child, source) {
                    return Some(id);
                }
            }
        }

        None
    }

    /// Normalize type string (handle const, pointers, arrays)
    fn normalize_type(&self, type_text: &str) -> String {
        let cleaned = type_text
            .trim()
            .replace("const ", "")
            .replace("volatile ", "")
            .replace("static ", "")
            .replace("register ", "");

        // Handle pointer types first
        if cleaned.contains('*') {
            if cleaned.contains("char") {
                return "char*".to_string();
            }
            return "void*".to_string();
        }

        // Handle array types - arrays decay to pointers when passed to functions
        // Check if it's char type (arrays decay to char*)
        if cleaned.contains("char") {
            return "char*".to_string();
        }

        // Return the base type
        cleaned.trim().to_string()
    }

    /// Check if types are compatible
    fn types_compatible(&self, expected: &str, actual: &str) -> bool {
        if expected == actual {
            return true;
        }

        // NULL is risky for %s - should use explicit check (incompatible)
        if actual == "NULL" && expected.ends_with('*') {
            return false;
        }

        // "unknown" type means we couldn't infer - assume compatible to avoid false positives
        if actual == "unknown" {
            return true;
        }

        // Allow implicit conversions
        match (expected, actual) {
            ("double", "float") => true,
            ("int", "short") => true,
            ("int", "signed char") => true,
            ("long", "int") => false,       // Size mismatch
            ("long long", "int") => false,  // Size mismatch
            ("long long", "long") => false, // Size mismatch
            _ => false,
        }
    }
}

impl CertRule for Dcl11C {
    fn rule_id(&self) -> &'static str {
        "DCL11-C"
    }

    fn description(&self) -> &'static str {
        "Understand the type issues associated with variadic functions"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL11-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}
