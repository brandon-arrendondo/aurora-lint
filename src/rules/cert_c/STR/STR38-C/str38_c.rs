//! STR38-C: Do not confuse narrow and wide character strings and functions
//!
//! Don't use narrow string functions (strlen, strcpy, etc.) on wide strings (wchar_t*),
//! and don't use wide string functions (wcslen, wcscpy, etc.) on narrow strings (char*).
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! wchar_t wide_str[] = L"hello";
//! strlen(wide_str);  // VIOLATION: strlen on wchar_t
//! ```
//!
//! **Compliant:**
//! ```c
//! wchar_t wide_str[] = L"hello";
//! wcslen(wide_str);  // OK: wcslen on wchar_t
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Str38C;

// Narrow string functions (work on char*)
const NARROW_FUNCTIONS: &[&str] = &[
    "strlen", "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp", "strchr", "strstr",
    "strdup", "sprintf", "snprintf", "sscanf",
];

// Wide string functions (work on wchar_t*)
const WIDE_FUNCTIONS: &[&str] = &[
    "wcslen", "wcscpy", "wcsncpy", "wcscat", "wcsncat", "wcscmp", "wcsncmp", "wcschr", "wcsstr",
    "wcsdup", "swprintf", "swscanf",
];

impl CertRule for Str38C {
    fn rule_id(&self) -> &'static str {
        "STR38-C"
    }

    fn description(&self) -> &'static str {
        "Do not confuse narrow and wide character strings and functions"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "STR38-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        for node in query::find_descendants(*node, |_| true) {
            if node.kind() == "function_definition" || node.kind() == "translation_unit" {
                let scope = if node.kind() == "function_definition" {
                    node.child_by_field_name("body")
                } else {
                    Some(node)
                };

                if let Some(scope_node) = scope {
                    // Track variable types
                    let mut var_types: HashMap<String, VarType> = HashMap::new();
                    self.collect_var_types(&scope_node, source, &mut var_types);

                    // Check function calls
                    self.check_calls(&scope_node, source, &var_types, &mut violations);
                }
            }
        }

        violations
    }
}

#[derive(Clone, Copy)]
enum VarType {
    Wide,   // wchar_t
    Narrow, // char
}

impl Str38C {
    fn collect_var_types(&self, node: &Node, source: &str, types: &mut HashMap<String, VarType>) {
        for node in query::find_descendants_of_kind(*node, "declaration") {
            let node = &node;
            // Look for wchar_t or char declarations
            let decl_text = get_node_text(node, source);

            if decl_text.contains("wchar_t") {
                // Extract variable names
                if let Some(var_name) = self.extract_var_name(node, source) {
                    types.insert(var_name, VarType::Wide);
                }
            } else if decl_text.contains("char") && !decl_text.contains("wchar_t") {
                if let Some(var_name) = self.extract_var_name(node, source) {
                    types.insert(var_name, VarType::Narrow);
                }
            }
        }
    }

    fn extract_var_name(&self, decl: &Node, source: &str) -> Option<String> {
        // Find init_declarator or declarator
        for i in 0..decl.child_count() {
            if let Some(child) = decl.child(i) {
                if child.kind() == "init_declarator" {
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        return self.get_identifier(&declarator, source);
                    }
                } else if child.kind() == "array_declarator"
                    || child.kind() == "pointer_declarator"
                    || child.kind() == "identifier"
                {
                    if let Some(name) = self.get_identifier(&child, source) {
                        return Some(name);
                    }
                }
            }
        }
        None
    }

    fn get_identifier(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }

        // Recurse to find identifier
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(id) = self.get_identifier(&child, source) {
                    return Some(id);
                }
            }
        }
        None
    }

    fn check_calls(
        &self,
        node: &Node,
        source: &str,
        types: &HashMap<String, VarType>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            let node = &node;
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // Check if it's a narrow or wide function
                let is_narrow = NARROW_FUNCTIONS.contains(&func_name);
                let is_wide = WIDE_FUNCTIONS.contains(&func_name);

                if is_narrow || is_wide {
                    // Get first argument
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let arg_text = self.get_first_arg_text(&args, source);
                        if let Some(arg_text) = arg_text {
                            // Check if argument is a variable we know the type of
                            for (var_name, var_type) in types {
                                if arg_text.contains(var_name) {
                                    let mismatch = match (is_narrow, var_type) {
                                        (true, VarType::Wide) => true,    // narrow func on wide var
                                        (false, VarType::Narrow) => true, // wide func on narrow var (is_wide must be true)
                                        _ => false,
                                    };

                                    if mismatch {
                                        let expected = if is_narrow { "wide" } else { "narrow" };
                                        let actual = if matches!(var_type, VarType::Wide) {
                                            "wide"
                                        } else {
                                            "narrow"
                                        };

                                        violations.push(RuleViolation {
                                            rule_id: self.rule_id().to_string(),
                                            severity: Severity::High,
                                            message: format!(
                                                "{} string function '{}' used on {} string variable '{}' - type mismatch",
                                                if is_narrow { "Narrow" } else { "Wide" },
                                                func_name,
                                                actual,
                                                var_name
                                            ),
                                            file_path: String::new(),
                                            line: node.start_position().row + 1,
                                            column: node.start_position().column + 1,
                                            suggestion: Some(format!(
                                                "Use {} string function instead (e.g., {})",
                                                expected,
                                                if is_narrow { "wcs* functions" } else { "str* functions" }
                                            )),
                                            ..Default::default()
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn get_first_arg_text(&self, args: &Node, source: &str) -> Option<String> {
        for i in 0..args.child_count() {
            if let Some(child) = args.child(i) {
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }
}
