use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Int05C;

impl CertRule for Int05C {
    fn rule_id(&self) -> &'static str {
        "INT05-C"
    }

    fn description(&self) -> &'static str {
        "Do not use input functions to convert character data if they cannot handle all possible inputs"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT05-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Int05C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for scanf/fscanf/sscanf calls with integer format specifiers
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);

                if self.is_scanf_function(&func_name) {
                    // Check if this scanf call uses integer conversion specifiers
                    if self.has_integer_conversion(&n, source) {
                        // Check if there's an errno check nearby
                        if !self.has_errno_check_after_call(&n, source) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                message: format!(
                                    "Input function '{}' used for integer conversion without errno check for ERANGE",
                                    func_name.trim()
                                ),
                                severity: self.severity(),
                                line: n.start_position().row + 1,
                                column: n.start_position().column + 1,
                                file_path: String::new(),
                                suggestion: Some(
                                    "Either use fgets() + strtol/strtoll() for safe conversion, or check errno for ERANGE after scanf".to_string()
                                ),
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check if function is a scanf family function
    fn is_scanf_function(&self, func_name: &str) -> bool {
        matches!(
            func_name.trim(),
            "scanf" | "fscanf" | "sscanf" | "vscanf" | "vfscanf" | "vsscanf"
        )
    }

    /// Check if scanf call uses integer conversion specifiers
    fn has_integer_conversion(&self, call_node: &Node, source: &str) -> bool {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            // Find format string (first or second argument depending on function)
            let format_string = self.find_format_string(args, source);

            if let Some(fmt_str) = format_string {
                // Check for integer conversion specifiers: %d, %i, %ld, %lld, %u, %lu, %llu, etc.
                return self.contains_integer_specifiers(&fmt_str);
            }
        }
        false
    }

    /// Find format string in argument list
    fn find_format_string(&self, args_node: Node, source: &str) -> Option<String> {
        let mut first_string_arg: Option<String> = None;

        for i in 0..args_node.child_count() {
            if let Some(child) = args_node.child(i) {
                if child.kind() != "," && child.kind() != "(" && child.kind() != ")" {
                    let text = get_node_text(&child, source);
                    if text.starts_with('"') {
                        if first_string_arg.is_none() {
                            first_string_arg = Some(text.to_string());
                        } else {
                            // For fprintf/fscanf, skip the file pointer and use second string
                            return Some(text.to_string());
                        }
                    }
                }
            }
        }

        first_string_arg
    }

    /// Check if format string contains integer conversion specifiers
    fn contains_integer_specifiers(&self, format_str: &str) -> bool {
        // Parse format string for %d, %i, %ld, %lld, %u, %lu, %llu, etc.
        let chars: Vec<char> = format_str.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if chars[i] == '%' && i + 1 < chars.len() {
                if chars[i + 1] == '%' {
                    i += 2; // Skip %%
                    continue;
                }

                i += 1; // Move past %

                // Skip flags and width
                while i < chars.len()
                    && (chars[i].is_ascii_digit()
                        || chars[i] == '*'
                        || chars[i] == '-'
                        || chars[i] == '+'
                        || chars[i] == ' '
                        || chars[i] == '#'
                        || chars[i] == '0')
                {
                    i += 1;
                }

                // Check for length modifiers (l, ll, h, hh, etc.)
                if i < chars.len() && chars[i] == 'l' {
                    i += 1;
                    if i < chars.len() && chars[i] == 'l' {
                        i += 1;
                    }
                } else if i < chars.len() && chars[i] == 'h' {
                    i += 1;
                    if i < chars.len() && chars[i] == 'h' {
                        i += 1;
                    }
                } else if i < chars.len() && matches!(chars[i], 'L' | 'j' | 'z' | 't') {
                    i += 1;
                }

                // Check conversion specifier
                if i < chars.len() && matches!(chars[i], 'd' | 'i' | 'o' | 'u' | 'x' | 'X') {
                    // Found integer conversion specifier
                    // All integer conversions are subject to this rule
                    return true;
                }

                i += 1;
            } else {
                i += 1;
            }
        }

        false
    }

    /// Check if there's an errno check for ERANGE after the scanf call
    fn has_errno_check_after_call(&self, call_node: &Node, source: &str) -> bool {
        // Find the containing scope (compound statement, function, etc.)
        let mut current = call_node.parent();
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

        if let Some(scope_node) = scope {
            // Look for errno checks after this call
            return self.find_errno_check_in_scope(
                &scope_node,
                call_node.start_position().row,
                source,
            );
        }

        false
    }

    /// Find errno check in scope after the scanf call
    fn find_errno_check_in_scope(&self, scope: &Node, after_line: usize, source: &str) -> bool {
        // Any binary_expression/if_statement descendant starting at/after
        // after_line is a candidate — descendants can never start earlier
        // than their parent, so this flat filter is equivalent to the
        // depth-first walk that only descended into later-starting children.
        query::find_descendants_of_kinds(*scope, &["binary_expression", "if_statement"])
            .into_iter()
            .filter(|n| n.start_position().row >= after_line)
            .any(|n| self.is_errno_check(&n, source))
    }

    /// Check if node is an errno check (specifically for ERANGE)
    fn is_errno_check(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "binary_expression" {
            let text = get_node_text(node, source);
            // Check for patterns like "errno == ERANGE" or "ERANGE == errno"
            if (text.contains("errno") && text.contains("ERANGE"))
                || (text.contains("ERANGE") && text.contains("errno"))
            {
                return true;
            }
        }

        // Also check if statement conditions
        if node.kind() == "if_statement" {
            if let Some(condition) = node.child_by_field_name("condition") {
                let text = get_node_text(&condition, source);
                if (text.contains("errno") && text.contains("ERANGE"))
                    || (text.contains("ERANGE") && text.contains("errno"))
                {
                    return true;
                }
            }
        }

        false
    }
}
