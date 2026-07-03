//! CON09-C: Avoid the ABA problem when using lock-free algorithms
//!
//! This rule detects potential ABA problems when using atomic compare-exchange operations
//! without proper synchronization mechanisms like mutexes or hazard pointers.
//!
//! ## The ABA Problem:
//! The ABA problem occurs in lock-free algorithms when:
//! 1. Thread 1 reads a value A from shared memory
//! 2. Thread 1 is preempted
//! 3. Thread 2 changes the value from A to B, then back to A
//! 4. Thread 1 resumes and performs a compare-and-swap, which succeeds because the value is still A
//! 5. Thread 1 incorrectly assumes nothing changed, leading to data corruption
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void func(void) {
//!   size_t index;
//!   int value;
//!   find_max_element(array, &index, &value);  // Time window for ABA
//!   if (!atomic_compare_exchange_strong(array[index], &value, 0)) {
//!     /* Handle error */
//!   }
//! }
//! ```
//!
//! **Compliant (using mutex):**
//! ```c
//! void func(void) {
//!   size_t index;
//!   int value;
//!   mtx_lock(&array_mutex);  // Protect entire operation
//!   find_max_element(array, &index, &value);
//!   if (!atomic_compare_exchange_strong(array[index], &value, 0)) {
//!     /* Handle error */
//!   }
//!   mtx_unlock(&array_mutex);
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Detect atomic compare-exchange operations (atomic_compare_exchange_strong, atomic_compare_exchange_weak, CAS)
//! - Check if the function contains proper synchronization (mutex lock/unlock)
//! - Flag cases where CAS is used without mutex protection

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Con09C;

impl CertRule for Con09C {
    fn rule_id(&self) -> &'static str {
        "CON09-C"
    }

    fn description(&self) -> &'static str {
        "Avoid the ABA problem when using lock-free algorithms"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "CON09-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Find all function definitions
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function(&func_node, source, &mut violations);
        }

        violations
    }
}

impl Con09C {
    fn check_function(&self, func_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Get function body
        let body = if let Some(body_node) = func_node.child_by_field_name("body") {
            body_node
        } else {
            return;
        };

        // Check if function has mutex protection
        let has_mutex_lock = self.has_mutex_lock(&body, source);

        // Find all compare-exchange operations and report violations immediately
        self.find_and_check_cas_operations(&body, source, has_mutex_lock, violations);
    }

    fn has_mutex_lock(&self, node: &Node, source: &str) -> bool {
        // Look for mutex lock function calls
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func_node) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func_node, source);
            self.is_lock_function(&func_name)
        })
        .is_some()
    }

    fn find_and_check_cas_operations(
        &self,
        node: &Node,
        source: &str,
        has_mutex_lock: bool,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for compare-exchange function calls
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = call_node.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);
                if self.is_cas_function(&func_name) && !has_mutex_lock {
                    let start_point = call_node.start_position();
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "Atomic compare-and-swap operation '{}' used without mutex protection, which may lead to ABA problem",
                            func_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Protect compare-and-swap operations with a mutex, or use hazard pointers to prevent the ABA problem".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn is_lock_function(&self, func_name: &str) -> bool {
        matches!(
            func_name.trim(),
            "mtx_lock"
                | "pthread_mutex_lock"
                | "mtx_trylock"
                | "pthread_mutex_trylock"
                | "mtx_timedlock"
                | "pthread_mutex_timedlock"
        )
    }

    fn is_cas_function(&self, func_name: &str) -> bool {
        let trimmed = func_name.trim();
        trimmed.starts_with("atomic_compare_exchange")
            || trimmed == "CAS"
            || trimmed == "__sync_bool_compare_and_swap"
            || trimmed == "__sync_val_compare_and_swap"
    }
}
