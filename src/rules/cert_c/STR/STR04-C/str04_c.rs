// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use crate::manifest::Severity;
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declarator};
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

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
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
                        if let Some(var_type) = self.char_string_type(&arg, source) {
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

        violations
    }

    /// The narrow string functions. The `mem*` functions take bytes, not
    /// strings, so an `unsigned char` buffer passed to one is not reported.
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
        )
    }

    /// The character type of a `signed char` or `unsigned char` string the
    /// argument `ident` names: its declaration, resolved by scope, declares
    /// it an array of or a pointer to one of them. A plain `unsigned char`
    /// value (`strchr`'s `int` argument) is not a string, nor is an array of
    /// pointers.
    fn char_string_type(&self, ident: &Node, source: &str) -> Option<String> {
        let name = get_node_text(ident, source);
        let (decl, declarator) = resolve_identifier_declarator(ident, name, source)?;
        let base = get_node_text(&decl.child_by_field_name("type")?, source)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if base != "signed char" && base != "unsigned char" {
            return None;
        }
        let mut levels = 0;
        let mut d = declarator;
        loop {
            match d.kind() {
                "pointer_declarator" | "array_declarator" => levels += 1,
                "parenthesized_declarator" => {}
                "function_declarator" => return None,
                _ => break,
            }
            match d
                .child_by_field_name("declarator")
                .or_else(|| d.named_child(0))
            {
                Some(inner) if inner.id() != d.id() => d = inner,
                _ => break,
            }
        }
        (levels == 1).then_some(base)
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
