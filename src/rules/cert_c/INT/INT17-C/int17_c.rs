//! INT17-C: Define integer constants in an implementation-independent manner
//!
//! Integer constants, especially hexadecimal ones, should not assume specific bit-widths
//! as this creates implementation-dependent code that may fail on platforms with different
//! integer sizes.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! const unsigned long mask = 0xFFFFFFFF;  // Assumes 32-bit unsigned long
//! unsigned long flipbits(unsigned long x) {
//!     return x ^ mask;  // Won't work correctly on 64-bit systems
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! const unsigned long mask = -1;  // All bits set regardless of size
//! unsigned long flipbits(unsigned long x) {
//!     return x ^ mask;
//! }
//!
//! // Or for MSB:
//! const unsigned long msb = ~(ULONG_MAX >> 1);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Int17C;

impl CertRule for Int17C {
    fn rule_id(&self) -> &'static str {
        "INT17-C"
    }

    fn description(&self) -> &'static str {
        "Define integer constants in an implementation-independent manner"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "INT17-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.traverse(node, source, &mut violations);
        violations
    }
}

impl Int17C {
    /// Traverse the AST looking for implementation-dependent hex constants
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "number_literal") {
            let literal_text = get_node_text(&n, source);

            // Check if it's a problematic hex constant
            if self.is_implementation_dependent_constant(literal_text) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: format!(
                        "Hex constant '{}' assumes specific bit-width and is implementation-dependent. \
                         Use -1 for all bits set, or shift expressions like ~(ULONG_MAX >> 1) for MSB.",
                        literal_text
                    ),
                    severity: self.severity(),
                    line: n.start_position().row + 1,
                    column: n.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(
                        "Use -1 for all bits set (unsigned), or macros from <limits.h> for portable values"
                            .to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Check if a hex constant is implementation-dependent
    fn is_implementation_dependent_constant(&self, literal: &str) -> bool {
        // Normalize to lowercase and remove common suffixes
        let normalized = literal
            .to_lowercase()
            .trim_end_matches('u')
            .trim_end_matches('l')
            .trim_end_matches("ul")
            .trim_end_matches("lu")
            .trim_end_matches("ll")
            .trim_end_matches("ull")
            .trim_end_matches("llu")
            .to_string();

        // Check for hexadecimal constants that assume specific bit-widths
        if !normalized.starts_with("0x") && !normalized.starts_with("0X") {
            return false;
        }

        let hex_part = &normalized[2..];
        if hex_part.is_empty() {
            return false;
        }

        // Parse the hex value to check magnitude.
        // Constants that fit within 16 bits (≤ 0xFFFF, value ≤ 65535) are portable
        // across all C implementations — they're byte/word masks, not platform
        // assumptions. Only flag constants > 16 bits where the programmer may be
        // assuming a specific `int` or `long` width.
        if let Ok(val) = u64::from_str_radix(hex_part, 16) {
            if val <= 0xFFFF {
                return false; // Portable small constant — not implementation-dependent
            }
        }

        // 32-bit and larger patterns that assume specific widths:
        if hex_part.len() >= 4 {
            // All F's (any length > 4 hex digits) — "all bits set" assumption
            if hex_part.chars().all(|c| c == 'f') {
                return true;
            }
            // MSB patterns: 8 followed by zeros
            if hex_part.starts_with('8') && hex_part.chars().skip(1).all(|c| c == '0') {
                return true;
            }
            // Max positive patterns: 7 followed by F's
            if hex_part.starts_with('7') && hex_part.chars().skip(1).all(|c| c == 'f') {
                return true;
            }
        }

        false
    }
}
