//! CON08-C: Do not assume that a group of calls to independently atomic methods is atomic
//!
//! A consistent locking policy guarantees that multiple threads cannot simultaneously
//! access or modify shared data. When two or more operations must be performed as a
//! single atomic operation, a consistent locking policy must be implemented using some
//! form of locking, such as a mutex.
//!
//! When presented with a set of operations where each is guaranteed to be atomic, it is
//! tempting to assume that a single operation consisting of individually-atomic operations
//! is guaranteed to be collectively atomic without additional locking. A grouping of calls
//! to such methods requires additional synchronization for the group.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! // Each method is atomic with its own mutex lock
//! void set_values(int new_a, int new_b) {
//!   mtx_lock(&lock);
//!   a = new_a; b = new_b;
//!   mtx_unlock(&lock);
//! }
//!
//! int get_sum(void) {
//!   mtx_lock(&lock);
//!   int sum = a + b;
//!   mtx_unlock(&lock);
//!   return sum;
//! }
//!
//! // This function calls multiple atomic methods but isn't atomic as a whole
//! void multiply_monomials(int x1, int x2) {
//!   set_values(x1, x2);  // Atomic
//!   printf("= x^2 + %dx + %d\n", get_sum(), get_product());  // Race condition!
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! // Wrap the group of calls with a single mutex lock
//! void multiply_monomials(int x1, int x2) {
//!   mtx_lock(&lock);  // Lock the entire group
//!   set_values(x1, x2);
//!   int sum = get_sum();
//!   int product = get_product();
//!   mtx_unlock(&lock);
//!
//!   printf("= x^2 + %dx + %d\n", sum, product);
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find functions that call multiple other functions
//! - Check if called functions use mutex locks (indicating they're atomic)
//! - Check if the calling function also uses mutex locks to wrap the calls
//! - If calling function doesn't wrap the calls in a mutex, flag as violation

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Con08C;

impl CertRule for Con08C {
    fn rule_id(&self) -> &'static str {
        "CON08-C"
    }

    fn description(&self) -> &'static str {
        "Do not assume that a group of calls to independently atomic methods is atomic"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "CON08-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: identify functions that use mutex locks (atomic functions)
        let atomic_functions = self.collect_atomic_functions(node, source);

        // Second pass: check for functions that call multiple atomic functions
        // without wrapping them in a mutex
        self.check_node(node, source, &atomic_functions, &mut violations);

        violations
    }
}

impl Con08C {
    /// Collect all function names that use mutex locks (atomic functions)
    fn collect_atomic_functions(&self, node: &Node, source: &str) -> HashSet<String> {
        let mut atomic_funcs = HashSet::new();
        self.find_atomic_functions(node, source, &mut atomic_funcs);
        atomic_funcs
    }

    fn find_atomic_functions(&self, node: &Node, source: &str, atomic_funcs: &mut HashSet<String>) {
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            if let Some(func_name) = self.get_function_name(&func_node, source) {
                // Check if this function uses mutex locks
                if self.uses_mutex_lock(&func_node, source) {
                    atomic_funcs.insert(func_name);
                }
            }
        }
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        atomic_functions: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for function definitions
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function_for_grouped_atomic_calls(
                &func_node,
                source,
                atomic_functions,
                violations,
            );
        }
    }

    fn check_function_for_grouped_atomic_calls(
        &self,
        function_node: &Node,
        source: &str,
        atomic_functions: &HashSet<String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        let func_name = self
            .get_function_name(function_node, source)
            .unwrap_or_else(|| "<unknown>".to_string());

        // Skip if this is already an atomic function (it's okay for atomic functions to exist)
        if atomic_functions.contains(&func_name) {
            return;
        }

        // Skip initialization functions that initialize mutexes
        if func_name.to_lowercase().contains("init") && func_name.to_lowercase().contains("mutex") {
            return;
        }

        // Skip main function
        if func_name == "main" {
            return;
        }

        // Get function body
        let body = match function_node.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // Find all function calls in the body (not just atomic ones)
        let all_function_calls = self.find_all_function_calls(&body, source);

        // Filter out known safe calls (printf, thread functions, etc.)
        let relevant_calls: Vec<String> = all_function_calls
            .into_iter()
            .filter(|name| !self.is_safe_function(name))
            .collect();

        // If function calls multiple other functions, check patterns
        if relevant_calls.len() >= 2 {
            // Check if the function uses mutex locks to wrap the calls
            let has_mutex = self.uses_mutex_lock(&body, source);

            // Check if any of the called functions are atomic
            let atomic_calls: Vec<&String> = relevant_calls
                .iter()
                .filter(|name| atomic_functions.contains(*name))
                .collect();

            // Only flag when calling multiple atomic functions without wrapping
            // them in a mutex. Do NOT flag ordinary multi-function calls.
            if !has_mutex && atomic_calls.len() >= 2 {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: Severity::Low,
                    message: format!(
                        "Function '{}' calls multiple methods ({}) without wrapping them in a mutex lock",
                        func_name,
                        relevant_calls.join(", ")
                    ),
                    file_path: String::new(),
                    line: function_node.start_position().row + 1,
                    column: function_node.start_position().column + 1,
                    suggestion: Some(
                        "Wrap the group of method calls with a single mutex lock to ensure the sequence is atomic".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    fn is_safe_function(&self, name: &str) -> bool {
        matches!(
            name,
            "printf"
                | "fprintf"
                | "sprintf"
                | "snprintf"
                | "thrd_create"
                | "thrd_join"
                | "thrd_detach"
                | "mtx_init"
                | "mtx_destroy"
        )
    }

    fn find_all_function_calls(&self, node: &Node, source: &str) -> Vec<String> {
        let mut calls = Vec::new();
        self.collect_all_function_calls(node, source, &mut calls);
        calls.sort();
        calls.dedup();
        calls
    }

    fn collect_all_function_calls(&self, node: &Node, source: &str, calls: &mut Vec<String>) {
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = call_node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source).to_string();
                calls.push(func_name);
            }
        }
    }

    /// Extract function name from a function_definition node.
    /// Handles both direct function_declarator children and pointer return types
    /// where function_declarator is nested inside pointer_declarator.
    fn get_function_name(&self, function_node: &Node, source: &str) -> Option<String> {
        for i in 0..function_node.child_count() {
            if let Some(child) = function_node.child(i) {
                if child.kind() == "function_declarator" {
                    if let Some(name) = self.get_identifier_name(&child, source) {
                        return Some(name);
                    }
                }
                // Handle pointer return types: type *func_name(...)
                // tree-sitter wraps as: pointer_declarator -> function_declarator
                if child.kind() == "pointer_declarator" {
                    if let Some(name) = self.find_function_name_in_declarator(&child, source) {
                        return Some(name);
                    }
                }
            }
        }
        None
    }

    /// Recursively search a declarator node for a function_declarator and extract its name.
    fn find_function_name_in_declarator(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "function_declarator" {
            return self.get_identifier_name(node, source);
        }
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.find_function_name_in_declarator(&child, source) {
                    return Some(name);
                }
            }
        }
        None
    }

    fn get_identifier_name(&self, node: &Node, source: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(get_node_text(node, source).to_string());
        }

        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if let Some(name) = self.get_identifier_name(&child, source) {
                    return Some(name);
                }
            }
        }

        None
    }

    fn uses_mutex_lock(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            let Some(func) = n.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func, source);
            matches!(
                func_name,
                "mtx_lock" | "mtx_unlock" | "pthread_mutex_lock" | "pthread_mutex_unlock"
            )
        })
        .is_some()
    }
}
