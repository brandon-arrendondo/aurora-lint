//! DCL06-C: Use meaningful symbolic constants to represent literal values
//!
//! Magic numbers (literal values) obscure code intent and create maintenance risks.
//! Use named symbolic constants (enums, const, macros) instead of embedding literals.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! char buffer[256];
//! fgets(buffer, 256, stdin);  // Magic number repeated
//!
//! if (age >= 18) { ... }       // Unclear meaning
//! ```
//!
//! **Compliant:**
//! ```c
//! enum { BUFFER_SIZE = 256 };
//! char buffer[BUFFER_SIZE];
//! fgets(buffer, sizeof(buffer), stdin);
//!
//! enum { ADULT_AGE = 18 };
//! if (age >= ADULT_AGE) { ... }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Dcl06C;

/// Tracks literal occurrences for duplicate detection
#[derive(Debug, Clone)]
struct LiteralInfo {
    value: String,
    line: usize,
    column: usize,
    context: String,
}

impl CertRule for Dcl06C {
    fn rule_id(&self) -> &'static str {
        "DCL06-C"
    }

    fn description(&self) -> &'static str {
        "Use meaningful symbolic constants to represent literal values"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL06-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track literal occurrences to detect magic numbers
        let mut literal_occurrences: HashMap<String, Vec<LiteralInfo>> = HashMap::new();
        let mut array_sizes: Vec<LiteralInfo> = Vec::new();

        self.analyze_literals(node, source, &mut literal_occurrences, &mut array_sizes);

        // Check for sizeof usage on arrays
        let sizeof_arrays = self.find_sizeof_usages(node, source);

        // Check for magic numbers (single or repeated occurrences)
        for (literal_value, occurrences) in &literal_occurrences {
            // Skip common acceptable values
            if self.is_acceptable_literal(literal_value) {
                continue;
            }

            // Flag any occurrence of non-trivial literal
            let first = &occurrences[0];
            let message = if occurrences.len() >= 2 {
                format!(
                    "Magic number '{}' appears {} times. Consider using a symbolic constant.",
                    literal_value,
                    occurrences.len()
                )
            } else if literal_value.starts_with('"') {
                format!(
                    "String literal {} should use a symbolic constant.",
                    literal_value
                )
            } else {
                format!(
                    "Magic number '{}' should use a symbolic constant.",
                    literal_value
                )
            };

            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                message,
                severity: self.severity(),
                line: first.line,
                column: first.column,
                file_path: String::new(),
                suggestion: Some(format!(
                    "Define a constant: enum {{ CONSTANT_NAME = {} }};",
                    literal_value
                )),
                requires_manual_review: None,
            });
        }

        // Check for magic numbers in array declarations
        // Only flag if sizeof() is not used on that array
        for array_size in &array_sizes {
            if !self.is_acceptable_literal(&array_size.value) {
                // context contains the array name
                let array_name = &array_size.context;

                // Don't flag if sizeof is used on this array
                if !array_name.is_empty() && sizeof_arrays.contains(array_name) {
                    continue;
                }

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: format!(
                        "Array size '{}' should use a symbolic constant instead of magic number.",
                        array_size.value
                    ),
                    severity: self.severity(),
                    line: array_size.line,
                    column: array_size.column,
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Define a constant: enum {{ ARRAY_SIZE = {} }};",
                        array_size.value
                    )),
                    requires_manual_review: None,
                });
            }
        }

        violations
    }
}

impl Dcl06C {
    /// Analyze AST for literal values
    fn analyze_literals(
        &self,
        node: &Node,
        source: &str,
        occurrences: &mut HashMap<String, Vec<LiteralInfo>>,
        array_sizes: &mut Vec<LiteralInfo>,
    ) {
        for n in query::find_descendants_of_kinds(*node, &["array_declarator", "number_literal"]) {
            match n.kind() {
                // Check for array declarator with numeric size
                "array_declarator" => {
                    if let Some(size_node) = self.find_array_size(&n) {
                        if size_node.kind() == "number_literal" {
                            let value = get_node_text(&size_node, source).to_string();
                            // Extract array name to check for sizeof usage
                            let array_name = self.extract_array_name(&n, source);
                            array_sizes.push(LiteralInfo {
                                value,
                                line: size_node.start_position().row + 1,
                                column: size_node.start_position().column + 1,
                                context: array_name.unwrap_or_default(),
                            });
                        }
                    }
                }
                // Track number literals in various contexts
                "number_literal" => {
                    let value = get_node_text(&n, source).to_string();

                    // Determine context
                    let context = self.get_literal_context(&n);
                    let operator = self.get_binary_operator(&n, source);

                    // Only track literals in suspicious contexts
                    if self.is_suspicious_context(&context)
                        && !self.is_well_known_idiom(&value, &operator)
                    {
                        let info = LiteralInfo {
                            value: value.clone(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            context,
                        };

                        occurrences.entry(value).or_default().push(info);
                    }
                }
                _ => {}
            }
        }

        // Note: String literals are generally acceptable in context (error messages, etc.)
        // so we don't flag them to avoid false positives
    }

    /// Extract array name from array declarator
    fn extract_array_name(&self, array_decl: &Node, source: &str) -> Option<String> {
        // Look for identifier in the declarator
        for i in 0..array_decl.child_count() {
            if let Some(child) = array_decl.child(i) {
                if child.kind() == "identifier" {
                    return Some(get_node_text(&child, source).to_string());
                }
            }
        }
        None
    }

    /// Find the size expression in an array declarator
    fn find_array_size<'a>(&self, array_decl: &'a Node<'a>) -> Option<Node<'a>> {
        // Array declarator structure: declarator '[' size? ']'
        for i in 0..array_decl.child_count() {
            if let Some(child) = array_decl.child(i) {
                // Skip declarator and brackets
                if child.kind() != "[" && child.kind() != "]" {
                    // This could be the declarator (identifier) or the size
                    if child.kind() == "number_literal"
                        || child.kind() == "identifier"
                        || child.kind() == "binary_expression"
                    {
                        // If it's a number literal, this is the size
                        if child.kind() == "number_literal" {
                            return Some(child);
                        }
                    }
                }
            }
        }
        // Check for nested structure
        for i in 0..array_decl.child_count() {
            if let Some(child) = array_decl.child(i) {
                if child.kind() == "number_literal" {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Get the context where a literal appears
    fn get_literal_context(&self, node: &Node) -> String {
        if let Some(parent) = node.parent() {
            match parent.kind() {
                "binary_expression" => "comparison".to_string(),
                "call_expression" => "function_argument".to_string(),
                "argument_list" => "function_argument".to_string(),
                "assignment_expression" => "assignment".to_string(),
                "init_declarator" => "initialization".to_string(),
                "array_declarator" => "array_size".to_string(),
                "for_statement" => "loop".to_string(),
                "while_statement" => "loop".to_string(),
                _ => "other".to_string(),
            }
        } else {
            "unknown".to_string()
        }
    }

    /// Check if context is suspicious for magic numbers
    fn is_suspicious_context(&self, context: &str) -> bool {
        matches!(context, "comparison" | "function_argument")
    }

    /// If `node` is a direct operand of a `binary_expression`, return the text of
    /// that expression's operator (e.g. "<<", "&", "*", "<="). Empty string otherwise.
    fn get_binary_operator(&self, node: &Node, source: &str) -> String {
        node.parent()
            .filter(|p| p.kind() == "binary_expression")
            .and_then(|p| p.child_by_field_name("operator"))
            .map(|op| get_node_text(&op, source).to_string())
            .unwrap_or_default()
    }

    /// Narrow, context-gated exemptions for well-known numeric idioms that don't
    /// obscure intent even though they're "magic numbers" in the literal sense.
    /// Each exemption is gated on BOTH the literal's normalized value AND the
    /// specific operator it's an operand of, so these values are still flagged
    /// everywhere else (e.g. `8` in an unrelated comparison is not exempted).
    fn is_well_known_idiom(&self, value: &str, operator: &str) -> bool {
        let normalized = Self::normalize_int_literal(value);

        match normalized.as_str() {
            // Byte-shift widths: standard byte-packing/unpacking idiom, e.g.
            // `(a << 24) | (b << 16) | (c << 8) | d` for IPv4 octet packing.
            "8" | "16" | "24" => operator == "<<" || operator == ">>",
            // 0xff as a byte mask: `x & 0xff`, `(x >> 8) & 0xff`, etc.
            "255" => operator == "&",
            // 1024 / KB-MB conversion factor: `size / 1024`, `n * 1024 * 1024UL`.
            "1024" => operator == "*" || operator == "/",
            // 65535: well-known max TCP port / max uint16, in a bounds check.
            "65535" => matches!(operator, "<" | "<=" | ">" | ">=" | "==" | "!="),
            _ => false,
        }
    }

    /// Normalize an integer literal's text to its decimal value for comparison
    /// against well-known idiom constants, stripping unsigned/long suffixes and
    /// resolving hex form (e.g. "0xff", "0XFF", "255UL" all normalize to "255").
    fn normalize_int_literal(value: &str) -> String {
        let trimmed = value.trim();
        let stripped = trimmed.trim_end_matches(['u', 'U', 'l', 'L']);

        if let Some(hex) = stripped
            .strip_prefix("0x")
            .or_else(|| stripped.strip_prefix("0X"))
        {
            if let Ok(n) = u64::from_str_radix(hex, 16) {
                return n.to_string();
            }
        }

        stripped.to_string()
    }

    /// Check if a literal value is acceptable (common non-magic values)
    fn is_acceptable_literal(&self, value: &str) -> bool {
        let trimmed = value.trim();

        // Handle negative numbers
        if let Some(positive) = trimmed.strip_prefix('-') {
            return self.is_acceptable_literal(positive);
        }

        // Strip float/unsigned suffixes: 0.0f, 1.0F, 0u, 0U, 0L, 0UL, etc.
        let stripped = trimmed.trim_end_matches(['f', 'F', 'u', 'U', 'l', 'L']);

        // Accept zero in any float form: 0.0, 0.0f, 0.0F
        if stripped == "0.0" || stripped == "0." || stripped == ".0" {
            return true;
        }

        // Accept small float literals: 1.0f, 2.0f, etc.
        if let Some(int_part) = stripped.strip_suffix(".0") {
            if self.is_acceptable_integer(int_part) {
                return true;
            }
        }

        self.is_acceptable_integer(stripped)
    }

    fn is_acceptable_integer(&self, value: &str) -> bool {
        // Common acceptable values: 0-10 and hex equivalents
        matches!(
            value,
            "0" | "1"
                | "2"
                | "3"
                | "4"
                | "5"
                | "6"
                | "7"
                | "8"
                | "9"
                | "10"
                | "0x0"
                | "0x1"
                | "0x2"
        )
    }

    /// Find all sizeof() usages and return the variable names
    fn find_sizeof_usages(&self, node: &Node, source: &str) -> HashSet<String> {
        query::find_descendants_of_kind(*node, "sizeof_expression")
            .into_iter()
            .filter_map(|n| {
                // Look for the argument to sizeof
                let text = get_node_text(&n, source);
                // Extract identifier from sizeof(identifier)
                let start = text.find('(')?;
                let end = text.rfind(')')?;
                let inner = text[start + 1..end].trim();
                // Could be an identifier
                if !inner.is_empty() && !inner.contains(' ') {
                    Some(inner.to_string())
                } else {
                    None
                }
            })
            .collect()
    }
}
