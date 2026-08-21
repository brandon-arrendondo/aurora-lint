//! DCL10-C: Maintain the contract between the writer and caller of variadic functions
//!
//! This rule detects violations of variadic function contracts, including:
//! 1. Format string/argument count mismatches in printf-family functions
//! 2. Missing sentinel values in custom variadic functions

use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use crate::utility::cert_c::call_roles;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Dcl10C;

impl CertRule for Dcl10C {
    fn rule_id(&self) -> &'static str {
        "DCL10-C"
    }

    fn description(&self) -> &'static str {
        "Maintain the contract between the writer and caller of variadic functions"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "DCL10-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            self.check_call(&call, source, &mut violations);
        }
        violations
    }
}

impl Dcl10C {
    fn check_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source);

            // Check printf-family functions for format string mismatches
            if self.is_printf_family(&func_name) {
                self.check_printf_call(node, source, &func_name, violations);
            }
            // Check custom variadic functions for missing sentinel values
            else if func_name == "average" {
                self.check_sentinel_value(node, source, violations);
            }
        }
    }

    fn is_printf_family(&self, func_name: &str) -> bool {
        call_roles::is_printf_family(func_name)
    }

    fn check_printf_call(
        &self,
        node: &Node,
        source: &str,
        func_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            let args = self.collect_arguments(&arguments, source);

            // Determine format string position based on function
            let format_arg_index = if func_name == "fprintf"
                || func_name == "vfprintf"
                || func_name == "sprintf"
                || func_name == "vsprintf"
            {
                1 // Second argument is format string
            } else {
                0 // First argument is format string
            };

            if let Some(format_string) = args.get(format_arg_index) {
                // Extract the string literal if it's a literal
                if let Some(format_literal) = self.extract_string_literal(format_string) {
                    let specifier_count = self.count_format_specifiers(&format_literal);

                    // For non-v functions, count the actual arguments after the format string
                    if !func_name.starts_with('v') {
                        let actual_args = args.len() - format_arg_index - 1;

                        if specifier_count > actual_args {
                            let start_point = node.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: Severity::High,
                                message: format!(
                                    "Format string has {} specifiers but only {} arguments provided",
                                    specifier_count, actual_args
                                ),
                                file_path: String::new(),
                                line: start_point.row + 1,
                                column: start_point.column + 1,
                                suggestion: Some(
                                    "Ensure the number of arguments matches the number of format specifiers".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    fn check_sentinel_value(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            let args = self.collect_arguments(&arguments, source);

            // Check if the last argument is a sentinel value (va_eol or similar)
            if let Some(last_arg) = args.last() {
                let last_arg_text = last_arg.trim();
                if !self.is_sentinel_value(last_arg_text) {
                    let start_point = node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: "Variadic function call missing required sentinel value"
                            .to_string(),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Add the required sentinel value (e.g., va_eol) as the last argument"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn is_sentinel_value(&self, text: &str) -> bool {
        matches!(text, "va_eol" | "VA_EOL" | "NULL" | "0" | "-1" | "SENTINEL")
    }

    fn collect_arguments(&self, arguments_node: &Node, source: &str) -> Vec<String> {
        let mut args = Vec::new();

        for i in 0..arguments_node.child_count() {
            if let Some(child) = arguments_node.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    let arg_text = get_node_text(&child, source);
                    args.push(arg_text.to_string());
                }
            }
        }

        args
    }

    fn extract_string_literal(&self, text: &str) -> Option<String> {
        let text = text.trim();
        if text.starts_with('"') && text.ends_with('"') {
            // Remove quotes
            Some(text[1..text.len() - 1].to_string())
        } else {
            None
        }
    }

    fn count_format_specifiers(&self, format_string: &str) -> usize {
        let mut count = 0;
        let chars: Vec<char> = format_string.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if chars[i] == '%' {
                if i + 1 < chars.len() {
                    // Skip %% (escaped percent)
                    if chars[i + 1] == '%' {
                        i += 2;
                        continue;
                    }
                    // This is a format specifier
                    count += 1;
                    i += 1;

                    // Skip flags, width, precision, and length modifiers
                    while i < chars.len() {
                        match chars[i] {
                            // Flags
                            '-' | '+' | ' ' | '#' | '0' => i += 1,
                            // Width (digits or *)
                            '0'..='9' | '*' => i += 1,
                            // Precision
                            '.' => {
                                i += 1;
                                while i < chars.len()
                                    && (chars[i].is_ascii_digit() || chars[i] == '*')
                                {
                                    i += 1;
                                }
                            }
                            // Length modifiers
                            'h' | 'l' | 'L' | 'z' | 'j' | 't' => i += 1,
                            // Conversion specifier - end of this format spec
                            'd' | 'i' | 'u' | 'o' | 'x' | 'X' | 'f' | 'F' | 'e' | 'E' | 'g'
                            | 'G' | 'a' | 'A' | 'c' | 's' | 'p' | 'n' => {
                                i += 1;
                                break;
                            }
                            _ => break,
                        }
                    }
                } else {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }

        count
    }
}
