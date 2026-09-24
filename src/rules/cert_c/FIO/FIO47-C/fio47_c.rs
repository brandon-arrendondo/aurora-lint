// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

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
use crate::utility::cert_c::ast_utils::{get_node_text, resolve_identifier_declared_type};
use crate::utility::cert_c::call_roles;
use crate::utility::cert_c::format_slots;
use lang_parsing_substrate::query;
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

/// Category of a resolved declared type (`resolve_identifier_declared_type`'s
/// spelling: the declaration's type field, ` *` appended for a pointer or
/// array). Read by whole token, so a typedef such as `pointer_t` is not an
/// integer because it contains "int"; an alias this cannot name is Unknown.
fn classify_declared_type(ty: &str) -> TypeCategory {
    if ty.ends_with('*') {
        return TypeCategory::Pointer;
    }
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let tokens: Vec<&str> = ty
        .split(|c: char| !is_ident(c))
        .filter(|t| !t.is_empty())
        .collect();
    if tokens.iter().any(|t| matches!(*t, "float" | "double")) {
        return TypeCategory::Float;
    }
    let is_integer = |t: &str| {
        matches!(
            t,
            "int"
                | "char"
                | "short"
                | "long"
                | "signed"
                | "unsigned"
                | "_Bool"
                | "bool"
                | "size_t"
                | "ssize_t"
                | "ptrdiff_t"
                | "wchar_t"
                | "intptr_t"
                | "uintptr_t"
                | "intmax_t"
                | "uintmax_t"
        ) || {
            // <stdint.h> exact/least/fast-width names: int32_t, uint_least8_t, ...
            let rest = t.strip_prefix('u').unwrap_or(t);
            rest.strip_prefix("int")
                .and_then(|r| r.strip_suffix("_t"))
                .map(|r| {
                    r.strip_prefix("_least")
                        .or(r.strip_prefix("_fast"))
                        .unwrap_or(r)
                })
                .is_some_and(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_digit()))
        }
    };
    if tokens.iter().any(|t| is_integer(t)) {
        TypeCategory::Integer
    } else {
        TypeCategory::Unknown
    }
}

impl Fio47C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }

    /// Check if a function name is a scanf-family function
    fn is_scanf_family(&self, name: &str) -> bool {
        call_roles::is_scanf_family(name)
    }

    /// Check if a function name is a format string function
    fn is_format_function(&self, name: &str) -> bool {
        call_roles::is_format_function(name)
    }

    /// Extract format string from a call expression
    /// Returns the format string if it's a string literal, None otherwise.
    /// A `concatenated_string` is joined into the text the compiler sees; one
    /// that splices a macro (`"%" PRIu16 "\n"`) is not validated, since the
    /// macro's expansion carries part of the conversion.
    fn extract_format_string(
        &self,
        call_node: &Node,
        source: &str,
        function_name: &str,
    ) -> Option<String> {
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
                        // If format string is not a literal, we can't validate it
                        return format_slots::string_literal_text(&child, source);
                    }
                    arg_count += 1;
                }
            }
        }
        None
    }

    /// Count the arguments a format string consumes
    /// Returns (argument_count, errors). A printf `*` width or precision
    /// consumes an `int` of its own before the conversion's argument; a scanf
    /// `%*` suppresses the assignment, so that conversion consumes none.
    fn count_format_specifiers(&self, format_string: &str, is_scanf: bool) -> (usize, Vec<String>) {
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
                    let (slots, error) = self.parse_format_specifier(&mut chars, is_scanf);
                    if let Some(error) = error {
                        errors.push(error);
                    }
                    count += slots;
                }
            }
        }

        (count, errors)
    }

    /// Parse a single format specifier and validate it
    /// Returns (arguments consumed, Some(error) if the specifier is invalid)
    fn parse_format_specifier(
        &self,
        chars: &mut std::iter::Peekable<std::str::Chars>,
        is_scanf: bool,
    ) -> (usize, Option<String>) {
        let mut flags = String::new();
        let mut length_modifier = String::new();
        let mut stars = 0usize;

        // scanf's assignment-suppression `*` comes first and consumes nothing
        let suppressed = is_scanf && chars.peek() == Some(&'*');
        if suppressed {
            chars.next();
        }
        let slots = |stars: usize| match (suppressed, is_scanf) {
            (true, _) => 0,
            (false, true) => 1,
            (false, false) => stars + 1,
        };

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
                stars += usize::from(ch == '*');
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
                    stars += usize::from(ch == '*');
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
                return (
                    slots(stars),
                    Some(format!("Invalid conversion specifier: %{}", specifier)),
                );
            }

            // Validate flag combinations
            if let Some(error) =
                self.validate_flag_combinations(&flags, specifier, &length_modifier)
            {
                return (slots(stars), Some(error));
            }

            // Validate length modifier combinations
            if let Some(error) = self.validate_length_modifier(specifier, &length_modifier) {
                return (slots(stars), Some(error));
            }
        } else {
            return (
                slots(stars),
                Some("Incomplete format specifier".to_string()),
            );
        }

        (slots(stars), None)
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

    /// Number of leading call arguments that are not format-string data
    /// (everything up to and including the format string itself): the
    /// buffer and size for `snprintf`/`vsnprintf`, the `FILE*`/buffer for
    /// the rest of the `f`/`s`/`v`-prefixed family, or just the format
    /// string for plain `printf`/`scanf`. Must match `format_arg_index` in
    /// `extract_format_string` (skip_count is always format_arg_index + 1).
    /// Shared by `count_arguments` and `get_data_arguments` so the two can't
    /// diverge — they used to, and the divergence shifted every zipped
    /// specifier/argument pair for `snprintf`/`vsnprintf` (and most of the
    /// `s`/`v`-prefixed variants) by up to 2 positions, misattributing
    /// mismatches to the buffer, size, or even the format string literal
    /// itself.
    fn data_arg_skip_count(&self, function_name: &str) -> usize {
        match function_name {
            "snprintf" | "vsnprintf" => 3,
            "fprintf" | "fscanf" | "sprintf" | "sscanf" | "dprintf" | "vdprintf" | "vfprintf"
            | "vfscanf" | "vsprintf" | "vsscanf" => 2,
            _ => 1,
        }
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

            count.saturating_sub(self.data_arg_skip_count(function_name))
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
            // A `*` width or precision takes an `int`
            '*' | 'd' | 'i' | 'o' | 'u' | 'x' | 'X' | 'c' => TypeCategory::Integer,
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' => TypeCategory::Float,
            's' | 'p' => TypeCategory::Pointer,
            _ => TypeCategory::Unknown,
        }
    }

    /// Infer type from an expression node
    ///
    /// An identifier is typed from the declaration it resolves to at this
    /// occurrence (ADR-0006), never from a name-keyed map or a declaration's
    /// raw text: the text can carry a comment (parse recovery writes one in
    /// place of an attribute macro such as `UNUSED`) whose `*` is not a
    /// pointer. An occurrence that resolves to nothing stays Unknown.
    fn infer_expression_type(&self, node: &Node, source: &str) -> TypeCategory {
        match node.kind() {
            "identifier" => {
                let name = get_node_text(node, source);
                resolve_identifier_declared_type(node, name, source)
                    .map(|ty| classify_declared_type(&ty))
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

    /// Extract one entry per consumed argument from a format string: the
    /// conversion specifier, preceded by a `*` for each printf `*` width or
    /// precision, each paired with its directive exactly as written (`%lx`,
    /// `%-*s`), so a message quotes what the source says. A `*` slot shares
    /// its directive's text. A suppressed scanf conversion (`%*d`) consumes
    /// no argument and contributes nothing.
    fn extract_format_specifiers(
        &self,
        format_string: &str,
        is_scanf: bool,
    ) -> Vec<(char, String)> {
        let mut specifiers = Vec::new();
        let mut chars = format_string.char_indices().peekable();

        while let Some((start, ch)) = chars.next() {
            if ch == '%' {
                if let Some(&(_, next)) = chars.peek() {
                    if next == '%' {
                        chars.next();
                        continue;
                    }

                    let suppressed = is_scanf && next == '*';
                    let mut stars = 0usize;
                    if suppressed {
                        chars.next();
                    }

                    // Skip flags, width, precision, length modifier
                    while let Some(&(_, c)) = chars.peek() {
                        if matches!(c, '-' | '+' | ' ' | '#' | '0' | '\'' | '.' | '*')
                            || c.is_ascii_digit()
                        {
                            stars += usize::from(c == '*' && !is_scanf);
                            chars.next();
                        } else if matches!(c, 'h' | 'l' | 'j' | 'z' | 't' | 'L') {
                            chars.next();
                            // Handle hh and ll
                            if let Some(&(_, next)) = chars.peek() {
                                if (c == 'h' && next == 'h') || (c == 'l' && next == 'l') {
                                    chars.next();
                                }
                            }
                        } else {
                            break;
                        }
                    }

                    // Get the conversion specifier
                    if let Some((at, specifier)) = chars.next() {
                        if specifier != '%' && !suppressed {
                            let end = at + specifier.len_utf8();
                            let directive = format_string[start..end].to_string();
                            specifiers.extend(std::iter::repeat_n(('*', directive.clone()), stars));
                            specifiers.push((specifier, directive));
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
            let skip_count = self.data_arg_skip_count(function_name);

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
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Fio47C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for call expressions
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let function_name = get_node_text(&function, source);

                if self.is_format_function(function_name) {
                    self.check_format_call(&call, source, function_name, violations);
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
    ) {
        // Extract format string if it's a literal
        if let Some(format_string) = self.extract_format_string(call_node, source, function_name) {
            // Count format specifiers and validate format string
            let (specifier_count, format_errors) =
                self.count_format_specifiers(&format_string, self.is_scanf_family(function_name));
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
            let is_scanf = self.is_scanf_family(function_name);
            let specifiers = self.extract_format_specifiers(&format_string, is_scanf);
            let data_args = self.get_data_arguments(call_node, function_name);

            for (i, ((specifier, directive), arg)) in
                specifiers.iter().zip(data_args.iter()).enumerate()
            {
                let expected_type = self.get_expected_type(*specifier, is_scanf);
                let actual_type = self.infer_expression_type(arg, source);

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
                            "Type mismatch in {}(): format specifier '{}'{} expects {:?} but argument {} ('{}') is {:?}",
                            function_name,
                            directive,
                            if *specifier == '*' { " (its '*')" } else { "" },
                            expected_type,
                            i + 1,
                            arg_text,
                            actual_type
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
