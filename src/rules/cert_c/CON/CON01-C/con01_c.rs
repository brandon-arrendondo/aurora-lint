//! CON01-C: Acquire and release synchronization primitives in the same module, at the same level of abstraction
//!
//! This rule detects functions that unlock mutexes they didn't lock themselves,
//! which breaks the acquire-release pairing and can lead to double-unlock errors.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int verify_balance(int amount) {
//!   if (account_balance - amount < MIN_BALANCE) {
//!     mtx_unlock(&mp);  // WRONG: unlocks mutex acquired elsewhere
//!     return -1;
//!   }
//!   return 0;
//! }
//!
//! void debit(int amount) {
//!   mtx_lock(&mp);
//!   if (verify_balance(amount) == -1) {
//!     mtx_unlock(&mp);  // Double unlock if balance check fails
//!     return;
//!   }
//!   account_balance -= amount;
//!   mtx_unlock(&mp);
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! static int verify_balance(int amount) {
//!   if (account_balance - amount < MIN_BALANCE) {
//!     return -1;  // Signal error without touching mutex
//!   }
//!   return 0;
//! }
//!
//! int debit(int amount) {
//!   if (mtx_lock(&mp) == thrd_error) return -1;
//!
//!   if (verify_balance(amount)) {
//!     mtx_unlock(&mp);
//!     return -1;
//!   }
//!
//!   account_balance -= amount;
//!   mtx_unlock(&mp);
//!   return 0;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Track mutex lock/unlock calls within each function
//! - Detect functions that unlock mutexes they didn't lock
//! - Report violations when unlock is called without corresponding lock

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Con01C;

impl CertRule for Con01C {
    fn rule_id(&self) -> &'static str {
        "CON01-C"
    }

    fn description(&self) -> &'static str {
        "Acquire and release synchronization primitives in the same module, at the same level of abstraction"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON01-C"
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

impl Con01C {
    fn check_function(&self, func_node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Get function name
        let func_name = if let Some(declarator) = func_node.child_by_field_name("declarator") {
            self.get_function_name(&declarator, source)
        } else {
            return;
        };

        // Get function body
        let body = if let Some(body_node) = func_node.child_by_field_name("body") {
            body_node
        } else {
            return;
        };

        // Track which mutexes are locked and unlocked in this function
        let mut locked_mutexes: HashSet<String> = HashSet::new();
        let mut unlocked_mutexes: Vec<(String, usize, usize)> = Vec::new();

        // Analyze the function body
        self.analyze_body(&body, source, &mut locked_mutexes, &mut unlocked_mutexes);

        // Check for unlocks without corresponding locks
        for (mutex_name, line, column) in unlocked_mutexes {
            if !locked_mutexes.contains(&mutex_name) {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::High,
                    message: format!(
                        "Function '{}' unlocks mutex '{}' without acquiring it in the same function. Acquire and release should occur at the same abstraction level.",
                        func_name,
                        mutex_name
                    ),
                    file_path: String::new(),
                    line,
                    column,
                    suggestion: Some(
                        "Ensure this function acquires the mutex before releasing it, or refactor so lock/unlock occur in the same function".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn get_function_name(&self, declarator: &Node, source: &str) -> String {
        // Navigate to the identifier
        if declarator.kind() == "function_declarator" {
            if let Some(inner_declarator) = declarator.child_by_field_name("declarator") {
                return get_node_text(&inner_declarator, source).to_string();
            }
        } else if declarator.kind() == "identifier" {
            return get_node_text(declarator, source).to_string();
        }

        // Try to find identifier in children
        for i in 0..declarator.child_count() {
            if let Some(child) = declarator.child(i) {
                if child.kind() == "identifier" {
                    return get_node_text(&child, source).to_string();
                }
                if child.kind() == "function_declarator" {
                    return self.get_function_name(&child, source);
                }
            }
        }

        "unknown".to_string()
    }

    fn analyze_body(
        &self,
        node: &Node,
        source: &str,
        locked_mutexes: &mut HashSet<String>,
        unlocked_mutexes: &mut Vec<(String, usize, usize)>,
    ) {
        // Look for function calls
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = call_node.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                // Check if it's a lock function
                if self.is_lock_function(&func_name) {
                    if let Some(mutex_name) = self.get_mutex_argument(&call_node, source) {
                        locked_mutexes.insert(mutex_name);
                    }
                }
                // Check if it's an unlock function
                else if self.is_unlock_function(&func_name) {
                    if let Some(mutex_name) = self.get_mutex_argument(&call_node, source) {
                        let line = call_node.start_position().row + 1;
                        let column = call_node.start_position().column + 1;
                        unlocked_mutexes.push((mutex_name, line, column));
                    }
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

    fn is_unlock_function(&self, func_name: &str) -> bool {
        matches!(func_name.trim(), "mtx_unlock" | "pthread_mutex_unlock")
    }

    fn get_mutex_argument(&self, call_node: &Node, source: &str) -> Option<String> {
        // Get the arguments node
        if let Some(args_node) = call_node.child_by_field_name("arguments") {
            // Get the first argument (the mutex)
            for i in 0..args_node.child_count() {
                if let Some(child) = args_node.child(i) {
                    if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                        let arg_text = get_node_text(&child, source);
                        // Extract the mutex variable name (handle &mp, mp, etc.)
                        let mutex_name = arg_text.trim().trim_start_matches('&').to_string();
                        return Some(mutex_name);
                    }
                }
            }
        }
        None
    }
}
