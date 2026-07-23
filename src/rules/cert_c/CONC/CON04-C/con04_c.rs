//! CON04-C: Join or detach threads even if their exit status is unimportant
//!
//! Threads must be properly cleaned up by either joining (thrd_join/pthread_join)
//! or detaching (thrd_detach/pthread_detach) to reclaim system resources.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int main(void) {
//!     thrd_t thr;
//!     thrd_create(&thr, func, NULL);  // VIOLATION: thread never joined/detached
//!     return 0;
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! int message_print(void *ptr) {
//!     // Thread detaches itself
//!     if (thrd_detach(thrd_current()) != thrd_success) {
//!         /* Handle error */
//!     }
//!     return 0;
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Con04C;

/// Tracks thread creation information
#[derive(Debug, Clone)]
struct ThreadCreation {
    variable_name: String,
    line: usize,
    column: usize,
}

impl CertRule for Con04C {
    fn rule_id(&self) -> &'static str {
        "CON04-C"
    }

    fn description(&self) -> &'static str {
        "Join or detach threads even if their exit status is unimportant"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "CON04-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Find all thread creations and join/detach operations
        let mut thread_creations: HashMap<String, Vec<ThreadCreation>> = HashMap::new();
        let mut joined_or_detached: HashSet<String> = HashSet::new();
        let mut detach_current_found = false;

        self.analyze_thread_operations(
            node,
            source,
            &mut thread_creations,
            &mut joined_or_detached,
            &mut detach_current_found,
        );

        // Check for violations: threads created but not joined or detached
        for (var_name, creations) in &thread_creations {
            // If thrd_detach(thrd_current()) is found, assume threads self-detach
            if !detach_current_found && !joined_or_detached.contains(var_name) {
                // Report violation for each creation of this thread variable
                for creation in creations {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        message: format!(
                            "Thread '{}' created but never joined or detached. \
                             Call thrd_join() or thrd_detach() to reclaim resources.",
                            creation.variable_name
                        ),
                        severity: self.severity(),
                        line: creation.line,
                        column: creation.column,
                        file_path: String::new(),
                        suggestion: Some(
                            "Call thrd_join() or thrd_detach() on the thread".to_string(),
                        ),
                        requires_manual_review: None,
                    });
                }
            }
        }

        violations
    }
}

impl Con04C {
    /// Analyze the AST for thread operations
    fn analyze_thread_operations(
        &self,
        node: &Node,
        source: &str,
        creations: &mut HashMap<String, Vec<ThreadCreation>>,
        joined_or_detached: &mut HashSet<String>,
        detach_current_found: &mut bool,
    ) {
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call_node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // Check for thread creation
                if self.is_thread_create_function(func_name) {
                    if let Some(thread_var) = self.extract_thread_variable(&call_node, source) {
                        let creation = ThreadCreation {
                            variable_name: thread_var.clone(),
                            line: call_node.start_position().row + 1,
                            column: call_node.start_position().column + 1,
                        };
                        creations.entry(thread_var).or_default().push(creation);
                    }
                }

                // Check for thread join
                if self.is_thread_join_function(func_name) {
                    if let Some(thread_var) = self.extract_thread_argument(&call_node, source) {
                        joined_or_detached.insert(thread_var);
                    }
                }

                // Check for thread detach
                if self.is_thread_detach_function(func_name) {
                    if let Some(arg) = self.extract_thread_argument(&call_node, source) {
                        if arg == "thrd_current()" || arg.contains("thrd_current") {
                            // Thread detaches itself - this is valid pattern
                            *detach_current_found = true;
                        } else {
                            joined_or_detached.insert(arg);
                        }
                    }
                }

                // Check for pthread_detach(pthread_self())
                if func_name == "pthread_detach" {
                    if let Some(args) = call_node.child_by_field_name("arguments") {
                        let args_text = get_node_text(&args, source);
                        if args_text.contains("pthread_self") {
                            *detach_current_found = true;
                        }
                    }
                }
            }
        }
    }

    /// Check if function name is a thread creation function
    fn is_thread_create_function(&self, name: &str) -> bool {
        matches!(name, "thrd_create" | "pthread_create")
    }

    /// Check if function name is a thread join function
    fn is_thread_join_function(&self, name: &str) -> bool {
        matches!(name, "thrd_join" | "pthread_join")
    }

    /// Check if function name is a thread detach function
    fn is_thread_detach_function(&self, name: &str) -> bool {
        matches!(name, "thrd_detach" | "pthread_detach")
    }

    /// Extract the thread variable name from a thrd_create/pthread_create call
    /// For thrd_create(&thr, func, arg) - first argument is the thread
    /// For pthread_create(&thr, attr, func, arg) - first argument is the thread
    fn extract_thread_variable(&self, call_node: &Node, source: &str) -> Option<String> {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            // Get first argument
            for i in 0..args.child_count() {
                if let Some(child) = args.child(i) {
                    let kind = child.kind();
                    if kind != "," && kind != "(" && kind != ")" {
                        let arg_text = get_node_text(&child, source).trim().to_string();

                        // Handle &var or &var[i]
                        if let Some(var_name) = arg_text.strip_prefix('&').map(str::trim_start) {
                            // Handle array indexing: &thr[i] -> thr
                            if let Some(bracket_pos) = var_name.find('[') {
                                return Some(var_name[..bracket_pos].to_string());
                            }
                            // Handle parentheses: &(thr[i]) -> thr
                            let clean_name = var_name.trim_start_matches('(').trim_end_matches(')');
                            if let Some(bracket_pos) = clean_name.find('[') {
                                return Some(clean_name[..bracket_pos].to_string());
                            }
                            return Some(clean_name.to_string());
                        }

                        return Some(arg_text);
                    }
                }
            }
        }
        None
    }

    /// Extract thread variable from join/detach call
    /// For thrd_join(thr, res) - first argument
    /// For thrd_detach(thr) - first argument
    /// For pthread_join(thr, res) - first argument
    /// For pthread_detach(thr) - first argument
    fn extract_thread_argument(&self, call_node: &Node, source: &str) -> Option<String> {
        if let Some(args) = call_node.child_by_field_name("arguments") {
            // Get first argument
            for i in 0..args.child_count() {
                if let Some(child) = args.child(i) {
                    let kind = child.kind();
                    if kind != "," && kind != "(" && kind != ")" {
                        let arg_text = get_node_text(&child, source).trim().to_string();

                        // Handle array indexing: thr[i] -> thr
                        if let Some(bracket_pos) = arg_text.find('[') {
                            return Some(arg_text[..bracket_pos].to_string());
                        }

                        return Some(arg_text);
                    }
                }
            }
        }
        None
    }
}
