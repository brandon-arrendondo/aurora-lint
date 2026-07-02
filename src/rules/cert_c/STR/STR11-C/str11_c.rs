//! STR11-C: Do not specify the bound of a character array initialized with a string literal
//!
//! This rule detects when a character array is declared with an explicit bound that doesn't
//! provide enough space for the null terminator of its string literal initializer.
//!
//! ## Problem
//! When you declare a character array with an explicit bound matching the character count
//! of a string literal, there's no room for the null terminator. This creates arrays that
//! are not properly null-terminated strings, leading to potential vulnerabilities.
//!
//! ## Examples
//!
//! **Non-compliant:**
//! ```c
//! const char s[3] = "abc";  // VIOLATION: 3 elements but "abc" needs 4 (including '\0')
//! char str[5] = "hello";    // VIOLATION: 5 elements but "hello" needs 6
//! ```
//!
//! **Compliant:**
//! ```c
//! const char s[] = "abc";      // OK: compiler sizes to 4 elements
//! char str[10] = "hello";      // OK: 10 > 6, sufficient space
//! char s[3] = {'a', 'b', 'c'}; // OK: explicit element notation (not a string)
//! ```
//!
//! ## Detection Strategy
//! - Find character array declarations (char or const char)
//! - Check if they have an explicit array size bound
//! - Check if they're initialized with a string literal (not explicit element notation)
//! - Calculate if bound is too small: bound <= string_length (needs bound > string_length)
//! - Report violation if insufficient space for null terminator

use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Str11C;

impl CertRule for Str11C {
    fn rule_id(&self) -> &'static str {
        "STR11-C"
    }

    fn cert_id(&self) -> &'static str {
        "STR11"
    }

    fn description(&self) -> &'static str {
        "Do not specify the bound of a character array initialized with a string literal"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_declarations(node, source, &mut violations);
        violations
    }
}

impl Str11C {
    fn check_declarations(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "declaration") {
            self.check_declaration_node(&n, source, violations);
        }
    }

    fn check_declaration_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the type specifier to check if it's a char type
        if let Some(type_node) = node.child_by_field_name("type") {
            let type_text = get_node_text(&type_node, source).trim();

            // Check if it's a character type (char or const char)
            if !type_text.contains("char") {
                return;
            }

            // Check each declarator in the declaration
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "init_declarator" {
                    self.check_init_declarator(&child, source, violations);
                }
            }
        }
    }

    fn check_init_declarator(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the declarator (which may be an array_declarator)
        if let Some(declarator) = node.child_by_field_name("declarator") {
            // Check if this is an array declarator with explicit size
            if declarator.kind() == "array_declarator" {
                // Get the array size
                if let Some(size_node) = declarator.child_by_field_name("size") {
                    let size_text = get_node_text(&size_node, source).trim();

                    // Try to parse the size as an integer
                    if let Ok(array_size) = size_text.parse::<usize>() {
                        // Get the initializer value
                        if let Some(value) = node.child_by_field_name("value") {
                            // Check if it's a string literal (not an initializer_list)
                            if value.kind() == "string_literal" {
                                let literal_text = get_node_text(&value, source).trim();

                                // Calculate string length (excluding quotes)
                                let string_length = self.get_string_literal_length(literal_text);

                                // Check if array size is too small
                                // Array needs to be > string_length to hold null terminator
                                if array_size <= string_length {
                                    let start_point = node.start_position();

                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: Severity::Low,
                                        message: format!(
                                            "Character array bound [{}] is too small for string literal {} (needs {} for null terminator). \
                                            Omit the array bound to let the compiler allocate sufficient storage.",
                                            array_size,
                                            literal_text,
                                            string_length + 1
                                        ),
                                        file_path: String::new(),
                                        line: start_point.row + 1,
                                        column: start_point.column + 1,
                                        suggestion: Some(
                                            "Remove the array bound (use []) to let the compiler automatically size the array, \
                                            or specify a bound larger than the string length to accommodate the null terminator."
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
        }
    }

    fn get_string_literal_length(&self, literal: &str) -> usize {
        // Remove surrounding quotes
        let content = literal.trim_matches('"');

        // Count actual characters, handling escape sequences
        let mut length = 0;
        let mut chars = content.chars();

        while let Some(ch) = chars.next() {
            if ch == '\\' {
                // Handle escape sequence
                if let Some(next_ch) = chars.next() {
                    match next_ch {
                        'n' | 't' | 'r' | '\\' | '"' | '\'' | '0' => {
                            // Single character escape sequences
                            length += 1;
                        }
                        'x' => {
                            // Hex escape: \xHH
                            chars.next(); // Skip first hex digit
                            chars.next(); // Skip second hex digit
                            length += 1;
                        }
                        _ => {
                            // Other escape sequences count as one character
                            length += 1;
                        }
                    }
                }
            } else {
                length += 1;
            }
        }

        length
    }
}
