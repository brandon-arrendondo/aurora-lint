use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Dcl18C;

impl CertRule for Dcl18C {
    fn rule_id(&self) -> &'static str {
        "DCL18-C"
    }

    fn description(&self) -> &'static str {
        "Do not begin integer constants with 0 when specifying a decimal value"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL18-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Recursively check for octal literals
        violations.extend(self.check_node(*node, source));

        violations
    }
}

impl Dcl18C {
    /// Recursively check nodes for integer literals that appear to be unintended octals
    fn check_node(&self, node: Node, source: &str) -> Vec<RuleViolation> {
        query::find_descendants_of_kind(node, "number_literal")
            .into_iter()
            .filter_map(|n| self.check_number_literal(n, source))
            .collect()
    }

    /// Check if a number_literal is an unintended octal constant
    fn check_number_literal(&self, literal_node: Node, source: &str) -> Option<RuleViolation> {
        let literal_text = get_node_text(&literal_node, source);

        // Check if this is an octal literal (starts with 0 but is not a special case)
        if self.is_unintended_octal(&literal_text) {
            let decimal_value = self.parse_octal_as_decimal(&literal_text);

            let message = format!(
                "Integer constant '{}' begins with 0, making it octal (base-8). This evaluates to {} in decimal. \
                If you intended decimal {}, remove the leading 0. \
                If you intended octal, consider using explicit base notation for clarity",
                literal_text,
                self.octal_to_decimal(&literal_text),
                decimal_value
            );

            let suggestion = format!(
                "Remove leading 0: use '{}' for decimal, or keep '{}' if octal was intended",
                decimal_value, literal_text
            );

            return Some(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message,
                file_path: String::new(),
                line: literal_node.start_position().row + 1,
                column: literal_node.start_position().column + 1,
                suggestion: Some(suggestion),
                ..Default::default()
            });
        }

        None
    }

    /// Check if a literal string represents an unintended octal constant
    fn is_unintended_octal(&self, literal: &str) -> bool {
        // Must start with '0'
        if !literal.starts_with('0') {
            return false;
        }

        // Filter out legitimate cases:
        // - Just "0" (zero)
        if literal == "0" {
            return false;
        }

        // - Hexadecimal (0x or 0X)
        if literal.starts_with("0x") || literal.starts_with("0X") {
            return false;
        }

        // - Binary (0b or 0B) - C23 extension
        if literal.starts_with("0b") || literal.starts_with("0B") {
            return false;
        }

        // - Floating point (0.something or 0e/0E for scientific notation)
        if literal.contains('.') || literal.contains('e') || literal.contains('E') {
            return false;
        }

        // - Zero with type suffix (0U, 0u, 0L, 0l, 0UL, 0ul, 0LL, 0ULL, etc.)
        //   "0U" is unsigned zero, "0L" is long zero — never octal confusion.
        let stripped = literal.trim_end_matches(['u', 'U', 'l', 'L']);
        if stripped == "0" {
            return false;
        }

        // Check if it has more digits after the leading 0
        // This catches cases like "0042", "0123", etc.
        if literal.len() > 1 {
            // Make sure the characters after '0' are digits (octal digits 0-7)
            // This is an octal literal
            return true;
        }

        false
    }

    /// Parse octal literal text as if it were decimal (what programmer likely intended)
    fn parse_octal_as_decimal(&self, literal: &str) -> String {
        // Remove leading zeros and return the numeric part
        literal.trim_start_matches('0').to_string()
    }

    /// Convert octal literal to its decimal value
    fn octal_to_decimal(&self, literal: &str) -> i64 {
        // Parse as octal (base-8)
        i64::from_str_radix(literal.trim_start_matches("0o").trim_start_matches('0'), 8)
            .unwrap_or(0)
    }
}
