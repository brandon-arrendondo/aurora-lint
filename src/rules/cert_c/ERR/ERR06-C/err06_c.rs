//! ERR06-C: Understand the termination behavior of assert() and abort()
//!
//! The assert() macro calls abort(), which means cleanup functions registered
//! with atexit() are not called. When cleanup handlers are registered, use
//! explicit error checking instead of assert().
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! if (atexit(cleanup) != 0) { /* Handle error */ }
//! // ...
//! assert(condition);  // Bypasses atexit cleanup if assertion fails
//! ```
//!
//! **Compliant:**
//! ```c
//! if (atexit(cleanup) != 0) { /* Handle error */ }
//! // ...
//! if (!condition) {
//!     exit(EXIT_FAILURE);  // Calls atexit cleanup handlers
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Err06C;

impl CertRule for Err06C {
    fn rule_id(&self) -> &'static str {
        "ERR06-C"
    }

    fn description(&self) -> &'static str {
        "Understand the termination behavior of assert() and abort()"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "ERR06-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check if atexit is used anywhere in the file
        let has_atexit = self.find_atexit_calls(node, source);

        if has_atexit {
            // Find all assert() calls and flag them
            self.find_assert_calls(node, source, &mut violations);
        }

        violations
    }
}

impl Err06C {
    /// Check if atexit() or at_quick_exit() is called anywhere in the tree
    fn find_atexit_calls(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(function) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&function, source);
            func_name == "atexit" || func_name == "at_quick_exit"
        })
        .is_some()
    }

    /// Find all assert() calls and create violations
    fn find_assert_calls(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "assert" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        message: "assert() used when atexit() cleanup handlers are registered. \
                                 assert() calls abort() which bypasses atexit cleanup."
                            .to_string(),
                        severity: self.severity(),
                        line: call.start_position().row + 1,
                        column: call.start_position().column + 1,
                        file_path: String::new(),
                        suggestion: Some(
                            "Replace assert() with explicit error checking: \
                             if (!condition) { exit(EXIT_FAILURE); }"
                                .to_string(),
                        ),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }
}
