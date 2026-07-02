//! STR37-C: Arguments to character-handling functions must be representable as an unsigned char
//!
//! This rule detects when arguments to character-handling functions from <ctype.h> are not
//! properly cast to unsigned char, which can cause undefined behavior when char is signed.
//!
//! ## Problem
//! Character-handling functions (isalpha, isdigit, toupper, tolower, etc.) require arguments
//! that are representable as unsigned char (0-255) or EOF. On systems where char is signed,
//! dereferencing a char pointer may yield negative values, causing undefined behavior.
//!
//! ## Examples
//!
//! **Non-compliant:**
//! ```c
//! const char *s = "hello";
//! if (isspace(*s)) {           // VIOLATION: *s may be negative
//!     // ...
//! }
//!
//! char c = getchar();
//! if (isalpha(c)) {            // VIOLATION: c may be negative
//!     // ...
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! const char *s = "hello";
//! if (isspace((unsigned char)*s)) {  // OK: cast to unsigned char
//!     // ...
//! }
//!
//! char c = getchar();
//! if (isalpha((unsigned char)c)) {   // OK: cast to unsigned char
//!     // ...
//! }
//! ```
//!
//! ## Detection Strategy
//! - Find calls to character-handling functions (isalpha, isdigit, toupper, etc.)
//! - Check if arguments are properly cast to unsigned char
//! - Report violations when cast is missing

use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Str37C;

impl CertRule for Str37C {
    fn rule_id(&self) -> &'static str {
        "STR37-C"
    }

    fn cert_id(&self) -> &'static str {
        "STR37"
    }

    fn description(&self) -> &'static str {
        "Arguments to character-handling functions must be representable as an unsigned char"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_ctype_calls(node, source, &mut violations);
        violations
    }
}

impl Str37C {
    fn check_ctype_calls(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = n.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim();

                // Check if this is a character-handling function from <ctype.h>
                if self.is_ctype_function(func_name) {
                    if let Some(arguments) = n.child_by_field_name("arguments") {
                        self.check_arguments(&arguments, source, func_name, violations);
                    }
                }
            }
        }
    }

    fn check_arguments(
        &self,
        arguments: &Node,
        source: &str,
        func_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        let args = self.extract_arguments(arguments, source);

        for arg in args {
            // Check if argument has explicit cast to unsigned char
            if !self.has_unsigned_char_cast(&arg, source) {
                // Check if argument is potentially unsafe (dereferenced pointer or char variable)
                if self.is_potentially_unsafe_argument(&arg, source) {
                    let start_point = arg.start_position();

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "Argument to '{}()' is not cast to unsigned char. \
                            This can cause undefined behavior if the argument has a negative value.",
                            func_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(format!(
                            "Cast the argument to unsigned char: '{}((unsigned char)...)'",
                            func_name
                        )),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn is_ctype_function(&self, func_name: &str) -> bool {
        matches!(
            func_name,
            // Character classification functions
            "isalnum"
                | "isalpha"
                | "isascii"
                | "isblank"
                | "iscntrl"
                | "isdigit"
                | "isgraph"
                | "islower"
                | "isprint"
                | "ispunct"
                | "isspace"
                | "isupper"
                | "isxdigit"
                // Character conversion functions
                | "toascii"
                | "toupper"
                | "tolower"
        )
    }

    fn has_unsigned_char_cast(&self, arg: &Node, source: &str) -> bool {
        // Check if argument is a cast_expression to unsigned char
        if arg.kind() == "cast_expression" {
            if let Some(type_node) = arg.child_by_field_name("type") {
                let type_text = get_node_text(&type_node, source).trim();
                // Check for various forms of unsigned char cast
                if type_text == "unsigned char"
                    || type_text == "unsignedchar"
                    || type_text == "(unsigned char)"
                    || type_text.contains("unsigned char")
                {
                    return true;
                }
            }
        }

        false
    }

    fn is_potentially_unsafe_argument(&self, arg: &Node, source: &str) -> bool {
        let arg_kind = arg.kind();

        // Pointer dereference is potentially unsafe
        if arg_kind == "pointer_expression" {
            return true;
        }

        // Array subscript is potentially unsafe (similar to pointer dereference)
        if arg_kind == "subscript_expression" {
            return true;
        }

        // Identifier could be a char variable (potentially unsafe)
        if arg_kind == "identifier" {
            return true;
        }

        // Cast expressions should be checked recursively
        if arg_kind == "cast_expression" {
            // If it's already an unsigned char cast, it's safe
            if self.has_unsigned_char_cast(arg, source) {
                return false;
            }
            // Otherwise check the value being cast
            if let Some(value) = arg.child_by_field_name("value") {
                return self.is_potentially_unsafe_argument(&value, source);
            }
        }

        // Parenthesized expressions should be checked recursively
        if arg_kind == "parenthesized_expression" {
            let mut cursor = arg.walk();
            for child in arg.children(&mut cursor) {
                if child.kind() != "(" && child.kind() != ")" {
                    return self.is_potentially_unsafe_argument(&child, source);
                }
            }
        }

        // Integer literals are safe (they're already in valid range or will be caught at compile time)
        if arg_kind == "number_literal" || arg_kind == "char_literal" {
            return false;
        }

        // If we're not sure, be conservative and flag it
        true
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
}
