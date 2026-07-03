//! INT35-C: Use correct integer precisions
//!
//! Integer types have both size and precision. Size is the number of bytes (`sizeof`),
//! but precision is the number of bits used for value representation (excluding sign
//! and padding bits). Using `sizeof(type) * CHAR_BIT` incorrectly assumes precision
//! equals size when padding bits may exist.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! #include <limits.h>
//! unsigned int pow2(unsigned int exp) {
//!     if (exp >= sizeof(unsigned int) * CHAR_BIT) {  // Wrong: assumes no padding bits
//!         /* Handle error */
//!     }
//!     return 1 << exp;
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! #include <limits.h>
//! // Using popcount to determine actual precision
//! #define PRECISION(umax_value) popcount(umax_value)
//!
//! unsigned int pow2(unsigned int exp) {
//!     if (exp >= PRECISION(UINT_MAX)) {  // Correct: uses actual precision
//!         /* Handle error */
//!     }
//!     return 1 << exp;
//! }
//!
//! // Or in C23:
//! unsigned int pow2(unsigned int exp) {
//!     if (exp >= UINT_WIDTH) {  // Correct: uses WIDTH macro
//!         /* Handle error */
//!     }
//!     return 1 << exp;
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Int35C;

impl CertRule for Int35C {
    fn rule_id(&self) -> &'static str {
        "INT35-C"
    }

    fn description(&self) -> &'static str {
        "Use correct integer precisions"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "INT35-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.traverse(node, source, &mut violations);
        violations
    }
}

impl Int35C {
    /// Traverse the AST looking for sizeof * CHAR_BIT pattern
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for node in query::find_descendants_of_kind(*node, "binary_expression") {
            let Some(operator) = node.child_by_field_name("operator") else {
                continue;
            };
            let op_text = get_node_text(&operator, source);

            // Check for multiplication operator
            if op_text != "*" {
                continue;
            }
            // Get left and right operands
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                continue;
            };
            let left_text = get_node_text(&left, source);
            let right_text = get_node_text(&right, source);

            // Check for pattern: sizeof(...) * CHAR_BIT or CHAR_BIT * sizeof(...)
            let has_sizeof_char_bit = (self.is_sizeof_expression(left_text)
                && self.is_char_bit(right_text))
                || (self.is_char_bit(left_text) && self.is_sizeof_expression(right_text));

            if has_sizeof_char_bit {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: "Using 'sizeof(...) * CHAR_BIT' to determine integer precision \
                         is incorrect when padding bits exist. Use PRECISION() macro, \
                         popcount(), or C23 *_WIDTH macros instead."
                        .to_string(),
                    severity: self.severity(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(
                        "Use popcount(TYPE_MAX) for actual precision, or *_WIDTH macros in C23"
                            .to_string(),
                    ),
                    requires_manual_review: None,
                });
            }
        }
    }

    /// Check if expression is a sizeof expression
    fn is_sizeof_expression(&self, expr: &str) -> bool {
        let trimmed = expr.trim();
        trimmed.starts_with("sizeof") || trimmed.contains("sizeof(") || trimmed.contains("sizeof ")
    }

    /// Check if expression is CHAR_BIT
    fn is_char_bit(&self, expr: &str) -> bool {
        let trimmed = expr.trim();
        trimmed == "CHAR_BIT"
            || trimmed == "(CHAR_BIT)"
            || trimmed.ends_with("CHAR_BIT")
            || trimmed.contains("CHAR_BIT")
    }
}
