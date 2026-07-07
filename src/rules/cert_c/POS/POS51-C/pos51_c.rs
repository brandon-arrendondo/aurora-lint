//! POS51-C: Avoid deadlock with POSIX threads by locking in predefined order
//!
//! This rule addresses deadlock conditions that can occur when multiple threads
//! acquire locks in inconsistent orders. Deadlock requires all four conditions:
//! 1. Mutual exclusion
//! 2. Hold and wait
//! 3. No preemption
//! 4. Circular wait
//!
//! ## Non-compliant examples:
//!
//! **Locks acquired in argument order (variable between threads):**
//! ```c
//! void transfer(bank_account *from, bank_account *to, int amount) {
//!     pthread_mutex_lock(&(from->balance_mutex));
//!     pthread_mutex_lock(&(to->balance_mutex));
//!     // Transfer logic
//!     pthread_mutex_unlock(&(to->balance_mutex));
//!     pthread_mutex_unlock(&(from->balance_mutex));
//! }
//! ```
//!
//! ## Compliant solutions:
//!
//! **Conditional ordering based on unique IDs:**
//! ```c
//! void transfer(bank_account *from, bank_account *to, int amount) {
//!     if (from->id == to->id) {
//!         return; // Same account
//!     }
//!     if (from->id < to->id) {
//!         pthread_mutex_lock(&(from->balance_mutex));
//!         pthread_mutex_lock(&(to->balance_mutex));
//!     } else {
//!         pthread_mutex_lock(&(to->balance_mutex));
//!         pthread_mutex_lock(&(from->balance_mutex));
//!     }
//!     // Transfer logic
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pos51C;

impl Pos51C {
    pub fn new() -> Self {
        Self
    }

    /// Check if a node is a pthread_mutex_lock() call
    fn is_mutex_lock_call(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "call_expression" {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim();
                return func_name == "pthread_mutex_lock";
            }
        }
        false
    }

    /// Extract the mutex argument from pthread_mutex_lock() call
    fn get_mutex_argument(&self, node: &Node, source: &str) -> Option<String> {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if arg.kind() != "," && arg.kind() != "(" && arg.kind() != ")" {
                        return Some(get_node_text(&arg, source).trim().to_string());
                    }
                }
            }
        }
        None
    }

    /// Collect all pthread_mutex_lock() calls in a compound statement
    fn collect_mutex_locks<'a>(&self, node: &Node<'a>, source: &str) -> Vec<(Node<'a>, String)> {
        query::find_descendants(*node, |n| self.is_mutex_lock_call(&n, source))
            .into_iter()
            .filter_map(|n| self.get_mutex_argument(&n, source).map(|arg| (n, arg)))
            .collect()
    }

    /// Check if a node contains conditional statements that order locks based on comparison
    /// The condition should compare the lock arguments (e.g., from->id < to->id)
    fn contains_conditional_ordering(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "if_statement" {
                return false;
            }
            // Check if the condition involves a comparison that could be lock ordering
            let Some(condition) = n.child_by_field_name("condition") else {
                return false;
            };
            let cond_text = get_node_text(&condition, source);
            // Look for comparison patterns like "->id <" or "->id >" or address comparisons
            if (cond_text.contains("->id") || cond_text.contains(".id"))
                && (cond_text.contains('<') || cond_text.contains('>'))
            {
                return true;
            }
            // Also check for address comparisons (comparing pointers directly)
            if cond_text.contains('<') || cond_text.contains('>') {
                // Check if both sides of the comparison are pointer variables
                if self.is_pointer_comparison(&condition, source) {
                    return true;
                }
            }
            false
        })
        .is_some()
    }

    /// Check if the condition is a pointer comparison (used for lock ordering)
    fn is_pointer_comparison(&self, node: &Node, source: &str) -> bool {
        if node.kind() == "binary_expression" {
            let _text = get_node_text(node, source);
            // Simple heuristic: if both sides are identifiers and operator is < or >
            if let Some(op) = node.child_by_field_name("operator") {
                let op_text = get_node_text(&op, source);
                if op_text == "<" || op_text == ">" {
                    // Check if left and right are identifiers (pointer variables)
                    if let Some(left) = node.child_by_field_name("left") {
                        if let Some(right) = node.child_by_field_name("right") {
                            let left_text = get_node_text(&left, source);
                            let right_text = get_node_text(&right, source);
                            // Both should be simple identifiers (pointer vars)
                            if !left_text.contains('(')
                                && !right_text.contains('(')
                                && !left_text.chars().all(|c| c.is_ascii_digit())
                                && !right_text.chars().all(|c| c.is_ascii_digit())
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Check for multiple sequential mutex locks without conditional ordering
    fn check_function_for_deadlock(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if node.kind() != "function_definition" {
            return;
        }

        if let Some(body) = node.child_by_field_name("body") {
            // Collect all mutex lock calls in the function body
            let locks = self.collect_mutex_locks(&body, source);

            // If there are multiple locks, check for potential deadlock
            if locks.len() >= 2 {
                // Check if there's conditional ordering logic
                let has_conditional = self.contains_conditional_ordering(&body, source);

                // If multiple locks without conditional ordering, report violation
                if !has_conditional {
                    // Check if locks use different variables (not hardcoded)
                    let uses_variables = locks.iter().any(|(_, mutex_arg)| {
                        // Check if argument contains struct field access or pointer dereferencing
                        mutex_arg.contains("->") || mutex_arg.contains('.')
                    });

                    if uses_variables {
                        // Report violation at the location of the first lock
                        if let Some((first_lock, _)) = locks.first() {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Potential deadlock: multiple pthread_mutex_lock() calls ({} locks) without predefined ordering. Locks may be acquired in inconsistent order across threads.",
                                    locks.len()
                                ),
                                file_path: String::new(),
                                line: first_lock.start_position().row + 1,
                                column: first_lock.start_position().column + 1,
                                suggestion: Some(
                                    "Acquire locks in a predefined order (e.g., based on unique resource IDs). Use conditional statements to ensure consistent lock ordering: if (res1->id < res2->id) { lock(res1); lock(res2); } else { lock(res2); lock(res1); }".to_string()
                                ),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }
}

impl CertRule for Pos51C {
    fn rule_id(&self) -> &'static str {
        "POS51-C"
    }

    fn description(&self) -> &'static str {
        "Avoid deadlock with POSIX threads by locking in predefined order"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "POS51-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}

impl Pos51C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check for deadlock patterns in function definitions
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function_for_deadlock(&func, source, violations);
        }
    }
}
