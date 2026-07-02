//! STR32-C: Do not pass a non-null-terminated character sequence to a library function that expects a string
//!
//! This rule detects when character sequences that may not be null-terminated are passed
//! to library functions that expect properly terminated strings.
//!
//! ## Problem
//! Many library functions (strlen, strcpy, strcat, printf with %s, etc.) expect null-terminated
//! strings. Passing a character array that lacks a null terminator causes undefined behavior,
//! often leading to buffer overflows or information disclosure.
//!
//! ## Examples
//!
//! **Non-compliant:**
//! ```c
//! char c_str[3] = "abc";      // No space for '\0'
//! printf("%s\n", c_str);      // VIOLATION: c_str not null-terminated
//!
//! strncpy(buf, src, sizeof(buf));
//! int len = strlen(buf);      // VIOLATION: strncpy may not null-terminate
//! ```
//!
//! **Compliant:**
//! ```c
//! char c_str[] = "abc";       // Compiler adds space for '\0'
//! printf("%s\n", c_str);      // OK
//!
//! strncpy(buf, src, sizeof(buf) - 1);
//! buf[sizeof(buf) - 1] = '\0';
//! int len = strlen(buf);      // OK: explicitly null-terminated
//! ```
//!
//! ## Detection Strategy
//! - Track character arrays that may not be null-terminated:
//!   1. Arrays with bounds exactly matching string literal length (STR11-C overlap)
//!   2. Arrays that are targets of strncpy() calls (may not null-terminate)
//! - Detect uses of these arrays with string functions requiring null termination
//! - Report violations when potentially non-null-terminated arrays are used unsafely

use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Str32C;

impl CertRule for Str32C {
    fn rule_id(&self) -> &'static str {
        "STR32-C"
    }

    fn cert_id(&self) -> &'static str {
        "STR32"
    }

    fn description(&self) -> &'static str {
        "Do not pass a non-null-terminated character sequence to a library function that expects a string"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track potentially non-null-terminated arrays
        let mut unsafe_arrays: HashSet<String> = HashSet::new();
        let mut array_locations: HashMap<String, (usize, usize)> = HashMap::new();

        // Pass 1: Find arrays that may not be null-terminated
        self.find_unsafe_arrays(node, source, &mut unsafe_arrays, &mut array_locations);

        // Pass 2: Find explicit null-termination assignments and mark arrays as safe
        self.find_explicit_null_termination(node, source, &mut unsafe_arrays, &array_locations);

        // Pass 3: Find uses of these arrays with string functions
        self.check_unsafe_usage(
            node,
            source,
            &unsafe_arrays,
            &array_locations,
            &mut violations,
        );

        violations
    }
}

impl Str32C {
    fn find_unsafe_arrays(
        &self,
        node: &Node,
        source: &str,
        unsafe_arrays: &mut HashSet<String>,
        array_locations: &mut HashMap<String, (usize, usize)>,
    ) {
        for n in query::find_descendants(*node, |_| true) {
            // Check for character array declarations with insufficient bounds
            if n.kind() == "declaration" {
                self.check_declaration_for_unsafe_array(&n, source, unsafe_arrays, array_locations);
            }

            // Check for strncpy() calls that may not null-terminate
            if n.kind() == "call_expression" {
                self.check_strncpy_call(&n, source, unsafe_arrays, array_locations);
                self.check_realloc_call(&n, source, unsafe_arrays, array_locations);
            }
        }
    }

    fn check_declaration_for_unsafe_array(
        &self,
        node: &Node,
        source: &str,
        unsafe_arrays: &mut HashSet<String>,
        array_locations: &mut HashMap<String, (usize, usize)>,
    ) {
        // Check if it's a character type
        if let Some(type_node) = node.child_by_field_name("type") {
            let type_text = get_node_text(&type_node, source).trim();
            if !type_text.contains("char") {
                return;
            }

            // Check each declarator
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "init_declarator" {
                    if let Some(declarator) = child.child_by_field_name("declarator") {
                        if declarator.kind() == "array_declarator" {
                            // Get array name and size
                            if let Some(name_node) = declarator.child_by_field_name("declarator") {
                                let array_name = get_node_text(&name_node, source).trim();

                                if let Some(size_node) = declarator.child_by_field_name("size") {
                                    let size_text = get_node_text(&size_node, source).trim();

                                    if let Ok(array_size) = size_text.parse::<usize>() {
                                        // Check if initialized with string literal
                                        if let Some(value) = child.child_by_field_name("value") {
                                            if value.kind() == "string_literal" {
                                                let literal_text =
                                                    get_node_text(&value, source).trim();
                                                let string_length =
                                                    self.get_string_literal_length(literal_text);

                                                // Array is unsafe if size <= string length (no room for '\0')
                                                if array_size <= string_length {
                                                    unsafe_arrays.insert(array_name.to_string());
                                                    let start_point = node.start_position();
                                                    array_locations.insert(
                                                        array_name.to_string(),
                                                        (start_point.row, start_point.column),
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_strncpy_call(
        &self,
        node: &Node,
        source: &str,
        unsafe_arrays: &mut HashSet<String>,
        array_locations: &mut HashMap<String, (usize, usize)>,
    ) {
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source).trim();

            if func_name == "strncpy" {
                // Extract destination argument
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    let args = self.extract_arguments(&arguments, source);

                    if !args.is_empty() {
                        let dest_text = get_node_text(&args[0], source).trim();
                        // Mark destination as potentially non-null-terminated
                        unsafe_arrays.insert(dest_text.to_string());
                        let start_point = node.start_position();
                        array_locations
                            .insert(dest_text.to_string(), (start_point.row, start_point.column));
                    }
                }
            }
        }
    }

    fn check_realloc_call(
        &self,
        node: &Node,
        source: &str,
        unsafe_arrays: &mut HashSet<String>,
        array_locations: &mut HashMap<String, (usize, usize)>,
    ) {
        if let Some(function) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function, source).trim();

            if func_name == "realloc" {
                // Look for the first argument (pointer being reallocated)
                if let Some(arguments) = node.child_by_field_name("arguments") {
                    let args = self.extract_arguments(&arguments, source);

                    if !args.is_empty() {
                        let ptr_text = get_node_text(&args[0], source).trim();
                        // Mark pointer as potentially non-null-terminated after realloc
                        unsafe_arrays.insert(ptr_text.to_string());
                        let start_point = node.start_position();
                        array_locations
                            .insert(ptr_text.to_string(), (start_point.row, start_point.column));
                    }
                }
            }
        }
    }

    fn find_explicit_null_termination(
        &self,
        node: &Node,
        source: &str,
        unsafe_arrays: &mut HashSet<String>,
        array_locations: &HashMap<String, (usize, usize)>,
    ) {
        // Look for assignments like: array[index] = '\0' or array[index] = L'\0'
        for n in query::find_descendants_of_kind(*node, "assignment_expression") {
            if let Some(left) = n.child_by_field_name("left") {
                if left.kind() == "subscript_expression" {
                    // Get the array name from subscript expression
                    if let Some(array_node) = left.child_by_field_name("argument") {
                        let array_name = get_node_text(&array_node, source).trim();

                        // Check if right side is '\0', L'\0', or 0
                        if let Some(right) = n.child_by_field_name("right") {
                            let right_text = get_node_text(&right, source).trim();
                            if right_text == "'\\0'" || right_text == "L'\\0'" || right_text == "0"
                            {
                                // Check if this null-termination happens AFTER the array was marked unsafe
                                let null_term_line = n.start_position().row;

                                if let Some(&(unsafe_line, _)) = array_locations.get(array_name) {
                                    // Only remove from unsafe if null-termination is AFTER the unsafe operation
                                    if null_term_line > unsafe_line {
                                        unsafe_arrays.remove(array_name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn check_unsafe_usage(
        &self,
        node: &Node,
        source: &str,
        unsafe_arrays: &HashSet<String>,
        _array_locations: &HashMap<String, (usize, usize)>,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = n.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim();

                // Check if this is a string function that requires null termination
                if self.is_string_function(func_name) {
                    if let Some(arguments) = n.child_by_field_name("arguments") {
                        let args = self.extract_arguments(&arguments, source);

                        // Check each argument against unsafe arrays
                        for arg in &args {
                            let arg_text = get_node_text(arg, source).trim();

                            // Check if this argument is one of our unsafe arrays
                            if unsafe_arrays.contains(arg_text) {
                                let start_point = n.start_position();

                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: Severity::High,
                                    message: format!(
                                        "Character array '{}' may not be null-terminated but is passed to '{}()' which expects a null-terminated string. \
                                        This can cause buffer overflows or information disclosure.",
                                        arg_text, func_name
                                    ),
                                    file_path: String::new(),
                                    line: start_point.row + 1,
                                    column: start_point.column + 1,
                                    suggestion: Some(
                                        format!(
                                            "Ensure '{}' is properly null-terminated before passing to '{}()'. \
                                            For strncpy(), explicitly add a null terminator. For array declarations, \
                                            ensure the bound is large enough to include the null terminator.",
                                            arg_text, func_name
                                        )
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

    fn is_string_function(&self, func_name: &str) -> bool {
        matches!(
            func_name,
            // Regular string functions (char*)
            "strlen"
                | "strcpy"
                | "strcat"
                | "strcmp"
                | "strncmp"
                | "strstr"
                | "strchr"
                | "strrchr"
                | "strspn"
                | "strcspn"
                | "strpbrk"
                | "strtok"
                | "printf"
                | "fprintf"
                | "sprintf"
                | "snprintf"
                | "puts"
                | "fputs"
                // Wide character string functions (wchar_t*)
                | "wcslen"
                | "wcscpy"
                | "wcscat"
                | "wcscmp"
                | "wcsncmp"
                | "wcsstr"
                | "wcschr"
                | "wcsrchr"
                | "wcsspn"
                | "wcscspn"
                | "wcspbrk"
                | "wcstok"
                | "wprintf"
                | "fwprintf"
                | "swprintf"
        )
    }

    fn extract_arguments<'a>(&self, arguments: &'a Node, _source: &str) -> Vec<Node<'a>> {
        let mut args = Vec::new();
        let mut cursor = arguments.walk();

        for child in arguments.children(&mut cursor) {
            // Skip parentheses and commas
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                args.push(child);
            }
        }

        args
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
                            length += 1;
                        }
                        'x' => {
                            // Hex escape: \xHH
                            chars.next(); // Skip first hex digit
                            chars.next(); // Skip second hex digit
                            length += 1;
                        }
                        _ => {
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
