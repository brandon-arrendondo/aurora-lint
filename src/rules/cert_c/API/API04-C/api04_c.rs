//! API04-C: Provide a consistent and usable error-checking mechanism
//!
//! Functions should provide consistent and usable error-checking mechanisms.
//! Complex or inconsistent interfaces are sometimes ignored by programmers,
//! resulting in code that is not properly error checked.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! // strlcpy has inconsistent error checking - returns length, awkward comparison
//! if (strlcpy(dest, src, sizeof(dest)) >= sizeof(dest)) {
//!     // Handle error
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! // strcpy_m provides consistent error checking - returns errno_t
//! errno_t result = strcpy_m(dest, src);
//! if (result != 0) {
//!     // Handle error
//! }
//! ```

use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Api04C;

impl CertRule for Api04C {
    fn rule_id(&self) -> &'static str {
        "API04-C"
    }

    fn description(&self) -> &'static str {
        "Provide a consistent and usable error-checking mechanism"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "API04-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        // Check for strlcpy() and strlcat() function calls
        // These functions have inconsistent error-checking mechanisms
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                if func_name == "strlcpy" || func_name == "strlcat" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: format!(
                            "Use of '{}' function with inconsistent error-checking mechanism",
                            func_name
                        ),
                        file_path: String::new(),
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        suggestion: Some(
                            "Consider using functions with clearer return values like strcpy_s() or strcpy_m() \
                            that return errno_t for consistent error checking"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
        violations
    }
}
