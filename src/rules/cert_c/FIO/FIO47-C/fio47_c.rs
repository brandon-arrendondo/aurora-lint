//! FIO47-C: Use valid format strings
//!
//! The formatted output functions (fprintf(), printf(), sprintf(), snprintf(), etc.)
//! convert, format, and print their arguments under control of a format string.
//! Invalid format strings can lead to undefined behavior, memory corruption, or
//! abnormal program termination.
//!
//! ## Common Mistakes:
//! - Incorrect argument count for the format string
//! - Invalid conversion specifiers
//! - Incompatible flag-specifier combinations
//! - Incompatible length modifier-specifier combinations
//! - Type mismatches between arguments and conversion specifiers
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! const char *error_msg = "Resource not available";
//! int error_type = 3;
//! printf("Error (type %s): %d\n", error_type, error_msg);
//! // %s expects pointer, gets int; %d expects int, gets pointer
//! ```
//!
//! **Compliant:**
//! ```c
//! const char *error_msg = "Resource not available";
//! int error_type = 3;
//! printf("Error (type %d): %s\n", error_type, error_msg);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Fio47C;

/// Track inferred type category for variables
#[derive(Debug, Clone, PartialEq)]
enum TypeCategory {
    Integer,
    Pointer, // Includes char* and const char*
    Float,
    Unknown,
}

impl Fio47C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }

    /// List of printf-family functions that take format strings
    const PRINTF_FUNCTIONS: &'static [&'static str] = &[
        "printf",
        "fprintf",
        "sprintf",
        "snprintf",
        "vprintf",
        "vfprintf",
        "vsprintf",
        "vsnprintf",
        "dprintf",
        "vdprintf",
    ];

    /// List of scanf-family functions that take format strings
    const SCANF_FUNCTIONS: &'static [&'static str] =
        &["scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf"];

    /// Check if a function name is a printf-family function
    fn is_printf_family(&self, name: &str) -> bool {
        Self::PRINTF_FUNCTIONS.contains(&name)
    }

    /// Check if a function name is a scanf-family function
    fn is_scanf_family(&self, name: &str) -> bool {
        Self::SCANF_FUNCTIONS.contains(&name)
    }

    /// Check if a function name is a format string function
    fn is_format_function(&self, name: &str) -> bool {
        self.is_printf_family(name) || self.is_scanf_family(name)
    }

    /// Extract format string from a call expression
    /// Returns the format string if it's a string literal, None otherwise
    fn extract_format_string<'a>(
        &self,
        call_node: &Node,
        source: &'a str,
        function_name: &str,
    ) -> Option<&'a str> {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            // Determine format string argument index based on function
            let format_arg_index = match function_name {
                // Functions where format is at index 0 (first arg)
                "printf" | "scanf" | "vprintf" | "vscanf" => 0,
                // Functions where format is at index 1 (second arg - after FILE* or buffer)
                "fprintf" | "fscanf" | "sprintf" | "sscanf" | "vfprintf" | "vfscanf"
                | "vsprintf" | "vsscanf" | "dprintf" | "vdprintf" => 1,
                // Functions where format is at index 2 (third arg - after buffer and size)
                "snprintf" | "vsnprintf" => 2,
                // Default to index 0
                _ => 0,
            };

            let mut arg_count = 0;
            for i in 0..args.child_count() {
                if let Some(child) = args.child(i) {
                    // Skip commas, parentheses, and comments
                    if child.kind() == ","
                        || child.kind() == "comment"
                        || child.kind() == "("
                        || child.kind() == ")"
                    {
                        continue;
                    }

                    if arg_count == format_arg_index {
                        // Check if this is a string literal
                        if child.kind() == "string_literal" {
                            let text = get_node_text(&child, source);
                            // Remove quotes
                            if text.len() >= 2 {
                                return Some(&text[1..text.len() - 1]);
                            }
                        } else if child.kind() == "concatenated_string" {
                            // Handle concatenated string literals
                            let text = get_node_text(&child, source);
                            return Some(text);
                        }
                        // If format string is not a literal, we can't validate it
                        return None;
                    }
                    arg_count += 1;
                }
            }
        }
        None
    }

    /// Count the number of format specifiers in a format string
    /// Returns (specifier_count, errors)
    fn count_format_specifiers(&self, format_string: &str) -> (usize, Vec<String>) {
        let mut count = 0;
        let mut errors = Vec::new();
        let mut chars = format_string.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '%' {
                if let Some(&next) = chars.peek() {
                    if next == '%' {
                        // %% is an escaped percent sign, not a format specifier
                        chars.next();
                        continue;
                    }

                    // This is a format specifier, parse it
                    if let Some(error) = self.parse_format_specifier(&mut chars, format_string) {
                        errors.push(error);
                    }
                    count += 1;
                }
            }
        }

        (count, errors)
    }

    /// Parse a single format specifier and validate it
    /// Returns Some(error) if the format specifier is invalid
    fn parse_format_specifier(
        &self,
        chars: &mut std::iter::Peekable<std::str::Chars>,
        _format_string: &str,
    ) -> Option<String> {
        let mut flags = String::new();
        let mut length_modifier = String::new();

        // Parse flags: -, +, space, #, 0, '
        while let Some(&ch) = chars.peek() {
            match ch {
                '-' | '+' | ' ' | '#' | '0' | '\'' => {
                    flags.push(ch);
                    chars.next();
                }
                _ => break,
            }
        }

        // Parse width
        while let Some(&ch) = chars.peek() {
            if ch.is_ascii_digit() || ch == '*' {
                chars.next();
            } else {
                break;
            }
        }

        // Parse precision
        if let Some(&'.') = chars.peek() {
            chars.next();
            while let Some(&ch) = chars.peek() {
                if ch.is_ascii_digit() || ch == '*' {
                    chars.next();
                } else {
                    break;
                }
            }
        }

        // Parse length modifier: hh, h, l, ll, j, z, t, L
        if let Some(&ch) = chars.peek() {
            match ch {
                'h' => {
                    chars.next();
                    if let Some(&'h') = chars.peek() {
                        chars.next();
                        length_modifier = "hh".to_string();
                    } else {
                        length_modifier = "h".to_string();
                    }
                }
                'l' => {
                    chars.next();
                    if let Some(&'l') = chars.peek() {
                        chars.next();
                        length_modifier = "ll".to_string();
                    } else {
                        length_modifier = "l".to_string();
                    }
                }
                'j' | 'z' | 't' | 'L' => {
                    length_modifier.push(ch);
                    chars.next();
                }
                _ => {}
            }
        }

        // Parse conversion specifier
        if let Some(specifier) = chars.next() {
            // Validate conversion specifier
            if !self.is_valid_conversion_specifier(specifier) {
                return Some(format!("Invalid conversion specifier: %{}", specifier));
            }

            // Validate flag combinations
            if let Some(error) =
                self.validate_flag_combinations(&flags, specifier, &length_modifier)
            {
                return Some(error);
            }

            // Validate length modifier combinations
            if let Some(error) = self.validate_length_modifier(specifier, &length_modifier) {
                return Some(error);
            }
        } else {
            return Some("Incomplete format specifier".to_string());
        }

        None
    }

    /// Check if a character is a valid conversion specifier
    fn is_valid_conversion_specifier(&self, ch: char) -> bool {
        matches!(
            ch,
            'd' | 'i'
                | 'o'
                | 'u'
                | 'x'
                | 'X'
                | 'f'
                | 'F'
                | 'e'
                | 'E'
                | 'g'
                | 'G'
                | 'a'
                | 'A'
                | 'c'
                | 's'
                | 'p'
                | 'n'
                | '%'
        )
    }

    /// Validate flag combinations with conversion specifiers
    fn validate_flag_combinations(
        &self,
        flags: &str,
        specifier: char,
        _length_modifier: &str,
    ) -> Option<String> {
        // # flag with %c, %s, %d, %i, %u is invalid per C standard
        if flags.contains('#') && matches!(specifier, 'c' | 's' | 'd' | 'i' | 'u') {
            return Some(format!(
                "Invalid combination: # flag with %{} specifier",
                specifier
            ));
        }

        None
    }

    /// Validate length modifier combinations with conversion specifiers
    fn validate_length_modifier(&self, specifier: char, length_modifier: &str) -> Option<String> {
        if length_modifier.is_empty() {
            return None;
        }

        // Float specifiers (f, e, g, a, F, E, G, A) are invalid with h, hh, ll.
        // Note: "l" with float IS valid in C99+ printf (no effect, but not UB).
        // "L" with float is valid (long double).
        if matches!(specifier, 'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A')
            && matches!(length_modifier, "h" | "hh" | "ll")
        {
            return Some(format!(
                "Invalid combination: {} length modifier with %{} specifier",
                length_modifier, specifier
            ));
        }

        // %s and %c should not have length modifiers (except 'l' for wide chars)
        if matches!(specifier, 's' | 'c')
            && !matches!(length_modifier, "l")
            && !length_modifier.is_empty()
        {
            return Some(format!(
                "Invalid combination: {} length modifier with %{} specifier",
                length_modifier, specifier
            ));
        }

        // %n should not have any length modifiers
        if specifier == 'n' && !length_modifier.is_empty() {
            return Some(format!(
                "Invalid combination: {} length modifier with %n specifier",
                length_modifier
            ));
        }

        None
    }

    /// Count actual arguments passed to the function (excluding format string)
    fn count_arguments(&self, call_node: &Node, function_name: &str) -> usize {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            let mut count: usize = 0;
            for i in 0..args.child_count() {
                if let Some(child) = args.child(i) {
                    // Skip commas, parentheses, and comments
                    if child.kind() == ","
                        || child.kind() == "comment"
                        || child.kind() == "("
                        || child.kind() == ")"
                    {
                        continue;
                    }
                    count += 1;
                }
            }

            // Subtract non-data arguments (everything up to and including format string).
            // Must match format_arg_index logic in extract_format_string.
            let skip_count = match function_name {
                "snprintf" | "vsnprintf" => 3,
                "fprintf" | "fscanf" | "sprintf" | "sscanf" | "dprintf" | "vdprintf"
                | "vfprintf" | "vfscanf" | "vsprintf" | "vsscanf" => 2,
                _ => 1,
            };
            count = count.saturating_sub(skip_count);

            count
        } else {
            0
        }
    }

    /// Get expected type category for a format specifier.
    ///
    /// `is_scanf` distinguishes scanf-family calls (where every conversion
    /// writes through a pointer argument, e.g. `sscanf(s, "%d", &var)`)
    /// from printf-family calls (where numeric/char conversions take the
    /// value by value, e.g. `printf("%d", var)`).
    fn get_expected_type(&self, specifier: char, is_scanf: bool) -> TypeCategory {
        if is_scanf {
            return match specifier {
                // Every scanf-family conversion (including %s, %[, %n) writes
                // through a pointer argument.
                'd' | 'i' | 'o' | 'u' | 'x' | 'X' | 'c' | 'f' | 'F' | 'e' | 'E' | 'g' | 'G'
                | 'a' | 'A' | 's' | 'p' | 'n' | '[' => TypeCategory::Pointer,
                _ => TypeCategory::Unknown,
            };
        }

        match specifier {
            'd' | 'i' | 'o' | 'u' | 'x' | 'X' | 'c' => TypeCategory::Integer,
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' => TypeCategory::Float,
            's' | 'p' => TypeCategory::Pointer,
            _ => TypeCategory::Unknown,
        }
    }

    /// Collect variable types from the function body
    fn collect_variable_types(
        &self,
        func_node: &Node,
        source: &str,
    ) -> HashMap<String, TypeCategory> {
        let mut types = HashMap::new();
        self.collect_types_recursive(func_node, source, &mut types);
        types
    }

    fn collect_types_recursive(
        &self,
        node: &Node,
        source: &str,
        types: &mut HashMap<String, TypeCategory>,
    ) {
        for decl in query::find_descendants_of_kind(*node, "declaration") {
            self.process_declaration(&decl, source, types);
        }
    }

    fn process_declaration(
        &self,
        node: &Node,
        source: &str,
        types: &mut HashMap<String, TypeCategory>,
    ) {
        // Simplified approach: analyze the full declaration text to determine types
        let decl_text = get_node_text(node, source);

        // Check if this is a pointer type declaration (contains *)
        let is_pointer = decl_text.contains('*');

        // Extract base type category
        let type_category = if decl_text.contains("float") || decl_text.contains("double") {
            TypeCategory::Float
        } else if decl_text.contains("int")
            || decl_text.contains("char")
            || decl_text.contains("short")
            || decl_text.contains("long")
            || decl_text.contains("size_t")
        {
            TypeCategory::Integer
        } else {
            TypeCategory::Unknown
        };

        // The final type depends on whether it's a pointer
        let final_type = if is_pointer {
            TypeCategory::Pointer
        } else {
            type_category
        };

        // Find all identifier names in this declaration
        self.find_and_register_identifiers(node, source, types, &final_type);
    }

    fn find_and_register_identifiers(
        &self,
        node: &Node,
        source: &str,
        types: &mut HashMap<String, TypeCategory>,
        var_type: &TypeCategory,
    ) {
        // Check if this node is an identifier that's part of a declarator
        for id in query::find_descendants_of_kind(*node, "identifier") {
            // Make sure it's a variable declaration, not a type name or function name
            if let Some(parent) = id.parent() {
                let parent_kind = parent.kind();
                if parent_kind == "pointer_declarator"
                    || parent_kind == "init_declarator"
                    || parent_kind == "declarator"
                    || parent_kind == "array_declarator"
                {
                    let var_name = get_node_text(&id, source).to_string();
                    types.insert(var_name, var_type.clone());
                }
            }
        }
    }

    #[allow(dead_code)]
    fn process_init_declarator(
        &self,
        node: &Node,
        source: &str,
        types: &mut HashMap<String, TypeCategory>,
        base_type: &TypeCategory,
        is_pointer: bool,
    ) {
        if let Some(declarator) = node.child_by_field_name("declarator") {
            let (var_name, decl_is_pointer) = self.extract_declarator_info(&declarator, source);

            let final_type = if is_pointer || decl_is_pointer {
                TypeCategory::Pointer
            } else {
                base_type.clone()
            };

            if !var_name.is_empty() {
                types.insert(var_name, final_type);
            }
        }
    }

    fn extract_declarator_info(&self, node: &Node, source: &str) -> (String, bool) {
        match node.kind() {
            "identifier" => (get_node_text(node, source).to_string(), false),
            "pointer_declarator" => {
                // Get the identifier inside the pointer declarator
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "identifier" {
                            return (get_node_text(&child, source).to_string(), true);
                        }
                    }
                }
                (String::new(), true)
            }
            _ => {
                // Try to find an identifier child
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        let (name, is_ptr) = self.extract_declarator_info(&child, source);
                        if !name.is_empty() {
                            return (name, is_ptr);
                        }
                    }
                }
                (String::new(), false)
            }
        }
    }

    /// Infer type from an expression node
    fn infer_expression_type(
        &self,
        node: &Node,
        source: &str,
        var_types: &HashMap<String, TypeCategory>,
    ) -> TypeCategory {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, source);
                var_types
                    .get(name)
                    .cloned()
                    .unwrap_or(TypeCategory::Unknown)
            }
            "number_literal" => {
                let text = get_node_text(node, source);
                if text.contains('.') || text.contains('e') || text.contains('E') {
                    TypeCategory::Float
                } else {
                    TypeCategory::Integer
                }
            }
            "string_literal" => TypeCategory::Pointer,
            "char_literal" => TypeCategory::Integer,
            "unary_expression" => {
                // Check for address-of operator
                if let Some(operator) = node.child_by_field_name("operator") {
                    let op = get_node_text(&operator, source);
                    if op == "&" {
                        return TypeCategory::Pointer;
                    }
                }
                TypeCategory::Unknown
            }
            _ => TypeCategory::Unknown,
        }
    }

    /// Extract format specifier characters from format string
    fn extract_format_specifiers(&self, format_string: &str) -> Vec<char> {
        let mut specifiers = Vec::new();
        let mut chars = format_string.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '%' {
                if let Some(&next) = chars.peek() {
                    if next == '%' {
                        chars.next();
                        continue;
                    }

                    // Skip flags, width, precision, length modifier
                    while let Some(&c) = chars.peek() {
                        if matches!(c, '-' | '+' | ' ' | '#' | '0' | '\'' | '.' | '*')
                            || c.is_ascii_digit()
                        {
                            chars.next();
                        } else if matches!(c, 'h' | 'l' | 'j' | 'z' | 't' | 'L') {
                            chars.next();
                            // Handle hh and ll
                            if let Some(&next) = chars.peek() {
                                if (c == 'h' && next == 'h') || (c == 'l' && next == 'l') {
                                    chars.next();
                                }
                            }
                        } else {
                            break;
                        }
                    }

                    // Get the conversion specifier
                    if let Some(specifier) = chars.next() {
                        if specifier != '%' {
                            specifiers.push(specifier);
                        }
                    }
                }
            }
        }

        specifiers
    }

    /// Get the data arguments from a printf call (excluding format string and FILE*)
    fn get_data_arguments<'a>(&self, call_node: &'a Node, function_name: &str) -> Vec<Node<'a>> {
        let mut args = Vec::new();

        if let Some(arguments) = call_node.child_by_field_name("arguments") {
            let skip_count =
                if function_name.starts_with('f') && !function_name.starts_with("fopen") {
                    2 // Skip FILE* and format string
                } else {
                    1 // Skip format string only
                };

            let mut arg_idx = 0;
            for i in 0..arguments.child_count() {
                if let Some(child) = arguments.child(i) {
                    // Skip commas, parentheses, and comments
                    if child.kind() == ","
                        || child.kind() == "comment"
                        || child.kind() == "("
                        || child.kind() == ")"
                    {
                        continue;
                    }
                    if arg_idx >= skip_count {
                        args.push(child);
                    }
                    arg_idx += 1;
                }
            }
        }

        args
    }
}

impl CertRule for Fio47C {
    fn rule_id(&self) -> &'static str {
        "FIO47-C"
    }

    fn description(&self) -> &'static str {
        "Use valid format strings"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "FIO47-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Collect variable types from the entire translation unit first
        let var_types = self.collect_variable_types(node, source);

        self.check_node(node, source, &mut violations, &var_types);
        violations
    }
}

impl Fio47C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, TypeCategory>,
    ) {
        // Check for call expressions
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let function_name = get_node_text(&function, source);

                if self.is_format_function(function_name) {
                    self.check_format_call(&call, source, function_name, violations, var_types);
                }
            }
        }
    }

    fn check_format_call(
        &self,
        call_node: &Node,
        source: &str,
        function_name: &str,
        violations: &mut Vec<RuleViolation>,
        var_types: &HashMap<String, TypeCategory>,
    ) {
        // Extract format string if it's a literal
        if let Some(format_string) = self.extract_format_string(call_node, source, function_name) {
            // Count format specifiers and validate format string
            let (specifier_count, format_errors) = self.count_format_specifiers(format_string);
            let has_format_errors = !format_errors.is_empty();

            // Report format string syntax errors
            for error in format_errors {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!("Invalid format string in {}(): {}", function_name, error),
                    file_path: String::new(),
                    line: call_node.start_position().row + 1,
                    column: call_node.start_position().column + 1,
                    suggestion: Some(
                        "Review format string syntax according to C standard".to_string(),
                    ),
                    ..Default::default()
                });
            }

            // Count actual arguments
            let arg_count = self.count_arguments(call_node, function_name);

            // Check if argument count matches specifier count
            // Note: This is a simplified check - it doesn't account for * width/precision
            // which consume additional arguments
            if specifier_count != arg_count && !has_format_errors {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Argument count mismatch in {}(): format string expects {} arguments but {} provided",
                        function_name, specifier_count, arg_count
                    ),
                    file_path: String::new(),
                    line: call_node.start_position().row + 1,
                    column: call_node.start_position().column + 1,
                    suggestion: Some(
                        "Ensure the number of arguments matches format specifiers".to_string()
                    ),
                    ..Default::default()
                });
            }

            // Check argument types against format specifiers
            let specifiers = self.extract_format_specifiers(format_string);
            let data_args = self.get_data_arguments(call_node, function_name);
            let is_scanf = self.is_scanf_family(function_name);

            for (i, (specifier, arg)) in specifiers.iter().zip(data_args.iter()).enumerate() {
                let expected_type = self.get_expected_type(*specifier, is_scanf);
                let actual_type = self.infer_expression_type(arg, source, var_types);

                // Only flag clear mismatches (not Unknown types)
                if expected_type != TypeCategory::Unknown
                    && actual_type != TypeCategory::Unknown
                    && expected_type != actual_type
                {
                    let arg_text = get_node_text(arg, source);
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Type mismatch in {}(): format specifier '%{}' expects {:?} but argument {} ('{}') is {:?}",
                            function_name, specifier, expected_type, i + 1, arg_text, actual_type
                        ),
                        file_path: String::new(),
                        line: call_node.start_position().row + 1,
                        column: call_node.start_position().column + 1,
                        suggestion: Some(
                            "Ensure format specifiers match argument types".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
        // If format string is not a literal, we cannot validate it statically
        // This is acceptable - we only check what we can analyze
    }
}
