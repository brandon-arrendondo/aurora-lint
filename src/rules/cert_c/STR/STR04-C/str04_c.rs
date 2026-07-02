use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct STR04C;

impl CertRule for STR04C {
    fn rule_id(&self) -> &'static str {
        "STR04-C"
    }

    fn cert_id(&self) -> &'static str {
        "STR04"
    }

    fn description(&self) -> &'static str {
        "Use plain char for characters in the basic character set"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl STR04C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            // Check declarations for signed/unsigned char arrays with string literals
            if n.kind() == "declaration" {
                if let Some(violation) = self.check_string_declaration(&n, source) {
                    violations.push(violation);
                }
            }

            // Check function calls with signed/unsigned char arguments (e.g., strlen)
            if n.kind() == "call_expression" {
                violations.extend(self.check_string_function_call(&n, source));
            }
        }
    }

    fn check_string_function_call(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Get function name
        let mut cursor = node.walk();
        let mut function_name = String::new();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" {
                function_name = get_node_text(&child, source).to_string();
                break;
            }
        }

        // Check if it's a string function
        if !self.is_string_function(&function_name) {
            return violations;
        }

        // Check arguments
        for child in node.children(&mut cursor) {
            if child.kind() == "argument_list" {
                let mut arg_cursor = child.walk();
                for arg in child.children(&mut arg_cursor) {
                    if arg.kind() == "identifier" {
                        // Look up the variable's declaration type
                        if let Some(var_type) = self.find_variable_type(&arg, source) {
                            if var_type.contains("signed char")
                                || var_type.contains("unsigned char")
                            {
                                let start = arg.start_position();
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    file_path: String::new(),
                                    message: format!(
                                        "Passing '{}' to string function '{}'. Use plain 'char' for basic character set strings.",
                                        var_type, function_name
                                    ),
                                    line: start.row + 1,
                                    column: start.column + 1,
                                    severity: self.severity(),
                                    suggestion: Some("Change variable type to plain 'char' instead of signed/unsigned char".to_string()),
                                    requires_manual_review: Some(false),
                                });
                            }
                        }
                    }
                }
            }
        }

        violations
    }

    fn is_string_function(&self, name: &str) -> bool {
        matches!(
            name,
            "strlen"
                | "strcpy"
                | "strncpy"
                | "strcat"
                | "strncat"
                | "strcmp"
                | "strncmp"
                | "strchr"
                | "strrchr"
                | "strstr"
                | "strtok"
                | "strspn"
                | "strcspn"
                | "strpbrk"
                | "memcpy"
                | "memmove"
                | "memcmp"
                | "memset"
                | "memchr"
        )
    }

    fn find_variable_type(&self, identifier_node: &Node, source: &str) -> Option<String> {
        let var_name = get_node_text(identifier_node, source);

        // Walk up to translation_unit
        let mut current = identifier_node.parent();
        while let Some(parent) = current {
            if parent.kind() == "translation_unit" {
                // Search for declaration of this variable
                let mut cursor = parent.walk();
                for child in parent.children(&mut cursor) {
                    if child.kind() == "declaration" {
                        if let Some(var_type) =
                            self.extract_var_type_if_matches(&child, var_name, source)
                        {
                            return Some(var_type);
                        }
                    }
                }
                break;
            }
            current = parent.parent();
        }

        None
    }

    fn extract_var_type_if_matches(
        &self,
        decl_node: &Node,
        target_name: &str,
        source: &str,
    ) -> Option<String> {
        let mut cursor = decl_node.walk();
        let mut type_text = String::new();
        let mut found_name = false;

        for child in decl_node.children(&mut cursor) {
            match child.kind() {
                "type_qualifier" | "primitive_type" | "sized_type_specifier" => {
                    let text = get_node_text(&child, source);
                    type_text.push_str(text);
                    type_text.push(' ');
                }
                "init_declarator" | "array_declarator"
                    // Check if this declarator contains our target variable
                    if self.contains_identifier(&child, target_name, source) => {
                        found_name = true;
                    }
                _ => {}
            }
        }

        if found_name && !type_text.is_empty() {
            return Some(type_text.trim().to_string());
        }

        None
    }

    fn contains_identifier(&self, node: &Node, target: &str, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            n.kind() == "identifier" && get_node_text(&n, source) == target
        })
        .is_some()
    }

    fn check_string_declaration(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        let mut cursor = node.walk();
        let mut type_text = String::new();
        let mut has_string_evidence = false;

        for child in node.children(&mut cursor) {
            match child.kind() {
                "type_qualifier" => {
                    // Capture type qualifiers like "signed" or "unsigned"
                    let text = get_node_text(&child, source);
                    type_text.push_str(text);
                    type_text.push(' ');
                }
                "sized_type_specifier" => {
                    // sized_type_specifier contains "signed char" or "unsigned char"
                    type_text = get_node_text(&child, source).to_string();
                }
                "primitive_type" => {
                    let text = get_node_text(&child, source);
                    if text == "char" {
                        if type_text.is_empty() {
                            // Plain char is OK
                            return None;
                        }
                        // Append "char" to type (e.g., "signed char")
                        type_text.push_str(text);
                    }
                }
                "init_declarator" => {
                    // Has initialization - only flag if initialized with string literal
                    let mut init_cursor = child.walk();
                    for init_child in child.children(&mut init_cursor) {
                        if init_child.kind() == "string_literal"
                            || init_child.kind() == "concatenated_string"
                        {
                            has_string_evidence = true;
                        } else if init_child.kind() == "initializer_list" {
                            let mut list_cursor = init_child.walk();
                            for list_item in init_child.children(&mut list_cursor) {
                                if list_item.kind() == "string_literal" {
                                    has_string_evidence = true;
                                }
                            }
                        }
                    }
                }
                // Bare array_declarator without string literal init is likely a binary
                // buffer (e.g., unsigned char cert_buf[2048]) — not a string violation
                "array_declarator" => {}
                _ => {}
            }
        }

        // Only flag signed/unsigned char with string literal evidence
        if has_string_evidence
            && (type_text.contains("signed") || type_text.contains("unsigned"))
            && type_text.contains("char")
        {
            let start = node.start_position();
            return Some(RuleViolation {
                rule_id: self.rule_id().to_string(),
                file_path: String::new(),
                message: format!(
                    "Using '{}' for basic character set strings. Use plain 'char' instead.",
                    type_text.trim()
                ),
                line: start.row + 1,
                column: start.column + 1,
                severity: self.severity(),
                suggestion: Some("Change to plain 'char' for string declarations".to_string()),
                requires_manual_review: Some(false),
            });
        }

        None
    }
}
