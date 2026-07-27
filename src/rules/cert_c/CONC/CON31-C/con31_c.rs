//! CON31-C: Do not destroy a mutex while it is locked
//!
//! This rule detects cases where a mutex is destroyed while it may still be locked
//! or in use by other threads. Destroying a mutex while it's locked causes undefined
//! behavior.
//!
//! ## The Problem:
//! Destroying a mutex while it's locked or potentially in use by other threads is dangerous:
//! 1. If a thread destroys a mutex while another thread holds the lock, undefined behavior occurs
//! 2. If a thread destroys a mutex while another thread is waiting on it, undefined behavior occurs
//! 3. Proper cleanup requires ensuring all threads are done using the mutex before destruction
//!
//! ## Examples:
//!
//! **Non-compliant (destroying mutex in thread function):**
//! ```c
//! int do_work(void *arg) {
//!   int *i = (int *)arg;
//!   if (*i < max_threads - 1) {
//!     mtx_lock(&lock);
//!     /* work */
//!     mtx_unlock(&lock);
//!   } else {
//!     mtx_destroy(&lock);  // VIOLATION: other threads might still be using it
//!   }
//!   return 0;
//! }
//! ```
//!
//! **Compliant (destroying mutex after thread joins):**
//! ```c
//! int do_work(void *dummy) {
//!   mtx_lock(&lock);
//!   /* work */
//!   mtx_unlock(&lock);
//!   return 0;
//! }
//!
//! int main(void) {
//!   for (size_t i = 0; i < max_threads; i++) {
//!     thrd_create(&threads[i], do_work, NULL);
//!   }
//!   for (size_t i = 0; i < max_threads; i++) {
//!     thrd_join(threads[i], 0);  // Wait for all threads to finish
//!   }
//!   mtx_destroy(&lock);  // SAFE: all threads have finished
//!   return 0;
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Detect mutex destroy functions: mtx_destroy, pthread_mutex_destroy
//! - Check if the destroy call is in a thread function (function passed to thrd_create/pthread_create)
//! - Flag destroy calls in thread functions as violations
//! - Allow destroy calls in main() or after thread joins

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{find_containing_function, get_node_text};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Con31C;

impl Con31C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Con31C
    }

    fn is_mutex_destroy_function(func_name: &str) -> bool {
        matches!(
            func_name,
            "mtx_destroy" | "pthread_mutex_destroy" | "DeleteCriticalSection"
        )
    }

    fn is_thread_function(&self, node: &Node, source: &str) -> bool {
        // Check if this function is used as a thread function argument
        // by looking for references in thrd_create or pthread_create calls

        if let Some(func_node) = find_containing_function(node) {
            let func_name_node = func_node.child_by_field_name("declarator");
            if let Some(func_name_node) = func_name_node {
                let func_name = get_node_text(&func_name_node, source);

                // If function name is "main", it's not a thread function
                if func_name.contains("main") {
                    return false;
                }

                // Check if this function name appears as an argument to thrd_create or pthread_create
                // For simplicity in this implementation, we'll flag any non-main function
                // as potentially being a thread function if it destroys a mutex
                // This is conservative but safe
                return !func_name.contains("main");
            }
        }

        false
    }

    fn check_function(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for call in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = call.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                if Self::is_mutex_destroy_function(&func_name) {
                    // Check if we're in a thread function context
                    if self.is_thread_function(&call, source) {
                        let start = call.start_position();
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            file_path: String::new(),
                            line: start.row + 1,
                            column: start.column + 1,
                            message: format!(
                                "Mutex destroyed in thread function with '{}()'. \
                                Destroying a mutex while other threads may still be using it causes undefined behavior. \
                                Destroy mutexes only after all threads have finished (e.g., after thread joins in main()).",
                                func_name
                            ),
                            suggestion: Some(
                                "Move mutex destruction to main() after all thread joins complete".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
}

impl CertRule for Con31C {
    fn rule_id(&self) -> &'static str {
        "CON31-C"
    }

    fn description(&self) -> &'static str {
        "Do not destroy a mutex while it is locked"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "CON31-C"
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_function(root, source, violations);
    }
}
