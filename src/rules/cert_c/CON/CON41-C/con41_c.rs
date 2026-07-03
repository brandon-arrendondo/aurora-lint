//! CON41-C: Wrap functions that can fail spuriously in a loop
//!
//! Atomic compare-exchange weak functions can fail spuriously and must be wrapped
//! in a loop to handle these failures correctly.
//!
//! ## Affected Functions:
//! - `atomic_compare_exchange_weak()`
//! - `atomic_compare_exchange_weak_explicit()`
//!
//! ## Rationale:
//! Per C Standard 7.17.7.4 paragraph 5 [ISO/IEC 9899:2024]:
//! - A weak compare-and-exchange operation may fail spuriously
//! - This makes them faster on some platforms (Alpha, ARM, MIPS, PowerPC)
//! - These architectures implement compare-and-exchange using load-linked/store-conditional
//! - To recover from spurious failures, a loop must be used
//!
//! ## Examples:
//!
//! **Non-compliant (no loop):**
//! ```c
//! _Bool flag = 0;
//! if (atomic_compare_exchange_weak(&flag, &expected, 1)) {
//!     // May fail spuriously!
//! }
//! ```
//!
//! **Compliant (in loop):**
//! ```c
//! _Bool flag = 0;
//! while (!atomic_compare_exchange_weak(&flag, &expected, 1)) {
//!     // Retry on spurious failure
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find calls to atomic_compare_exchange_weak() and atomic_compare_exchange_weak_explicit()
//! - Check if they are within a loop (while, for, do-while)
//! - Flag violations if not in a loop

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Con41C;

impl CertRule for Con41C {
    fn rule_id(&self) -> &'static str {
        "CON41-C"
    }

    fn description(&self) -> &'static str {
        "Wrap functions that can fail spuriously in a loop"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON41-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Con41C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for call expressions
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = call.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);

                // Check if this is an atomic compare-exchange weak function
                if matches!(
                    func_name,
                    "atomic_compare_exchange_weak" | "atomic_compare_exchange_weak_explicit"
                ) {
                    // Check if the call is within a loop
                    if !self.is_in_loop(&call) {
                        let line = call.start_position().row + 1;
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Function '{}' can fail spuriously and must be wrapped in a loop (C11 7.17.7.4)",
                                func_name
                            ),
                            file_path: String::new(),
                            line,
                            column: 0,
                            suggestion: Some(
                                format!("Wrap {} in a while/for/do-while loop to handle spurious failures", func_name)
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check if a node is within a loop structure
    fn is_in_loop(&self, node: &Node) -> bool {
        let mut current = node.parent();

        while let Some(parent) = current {
            match parent.kind() {
                "while_statement" | "for_statement" | "do_statement" => {
                    return true;
                }
                "function_definition" => {
                    // Stop at function boundary
                    return false;
                }
                _ => {
                    current = parent.parent();
                }
            }
        }

        false
    }
}
