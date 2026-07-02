//! POS53-C: Do not use more than one mutex for concurrent waiting operations on a condition variable
//!
//! This rule detects violations where the same condition variable is used with
//! different mutexes in pthread_cond_wait() or pthread_cond_timedwait() calls.
//!
//! ## Problem
//! Using multiple different mutexes with the same condition variable creates
//! undefined behavior. The POSIX standard states: "the effect of an attempt by
//! any thread to wait on that condition variable using a different mutex is undefined."
//!
//! ## Examples
//!
//! **Non-compliant:**
//! ```c
//! pthread_cond_t cv;
//! pthread_mutex_t mutex1, mutex2;
//!
//! void waiter1() {
//!     pthread_cond_wait(&cv, &mutex1);  // Using mutex1
//! }
//!
//! void waiter2() {
//!     pthread_cond_wait(&cv, &mutex2);  // Using mutex2 - VIOLATION!
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! pthread_cond_t cv;
//! pthread_mutex_t mutex1;
//!
//! void waiter1() {
//!     pthread_cond_wait(&cv, &mutex1);  // Using mutex1
//! }
//!
//! void waiter2() {
//!     pthread_cond_wait(&cv, &mutex1);  // Using same mutex1 - OK
//! }
//! ```
//!
//! ## Detection Strategy
//! - Track all pthread_cond_wait() and pthread_cond_timedwait() calls
//! - For each call, extract condition variable (arg 0) and mutex (arg 1)
//! - Build a map: condition_variable → set of mutexes
//! - Report violation if any condition variable has more than one mutex

use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

pub struct Pos53C;

impl CertRule for Pos53C {
    fn rule_id(&self) -> &'static str {
        "POS53-C"
    }

    fn cert_id(&self) -> &'static str {
        "POS53"
    }

    fn description(&self) -> &'static str {
        "Do not use more than one mutex for concurrent waiting operations on a condition variable"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Collect all pthread_cond_wait and pthread_cond_timedwait calls
        let mut cond_var_to_mutexes: HashMap<String, HashSet<String>> = HashMap::new();
        let mut cond_var_locations: HashMap<String, Vec<(usize, usize)>> = HashMap::new();

        self.collect_cond_wait_calls(
            node,
            source,
            &mut cond_var_to_mutexes,
            &mut cond_var_locations,
        );

        // Check for condition variables used with multiple mutexes
        for (cond_var, mutexes) in &cond_var_to_mutexes {
            if mutexes.len() > 1 {
                // Found a violation - same condition variable with multiple mutexes
                if let Some(locations) = cond_var_locations.get(cond_var) {
                    if let Some(&(row, column)) = locations.first() {
                        let mutex_list: Vec<&String> = mutexes.iter().collect();

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Condition variable '{}' is used with multiple different mutexes: {}. \
                                All threads waiting on a condition variable must use the same mutex.",
                                cond_var,
                                mutex_list
                                    .iter()
                                    .map(|s| format!("'{}'", s))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ),
                            file_path: String::new(),
                            line: row + 1,
                            column: column + 1,
                            suggestion: Some(
                                "Use the same mutex for all pthread_cond_wait() and pthread_cond_timedwait() calls on this condition variable, or use separate condition variables for different mutexes."
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }

        violations
    }
}

impl Pos53C {
    fn collect_cond_wait_calls(
        &self,
        node: &Node,
        source: &str,
        cond_var_to_mutexes: &mut HashMap<String, HashSet<String>>,
        cond_var_locations: &mut HashMap<String, Vec<(usize, usize)>>,
    ) {
        // Check if this is a call_expression
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = n.child_by_field_name("function") {
                let func_name = get_node_text(&function, source).trim();

                // Check if it's pthread_cond_wait or pthread_cond_timedwait
                if func_name == "pthread_cond_wait" || func_name == "pthread_cond_timedwait" {
                    // Extract arguments
                    if let Some(arguments) = n.child_by_field_name("arguments") {
                        let args = self.extract_arguments(&arguments, source);

                        // We need at least 2 arguments (condition_var, mutex)
                        if args.len() >= 2 {
                            let cond_var = get_node_text(&args[0], source).trim().to_string();
                            let mutex = get_node_text(&args[1], source).trim().to_string();

                            // Track this combination
                            cond_var_to_mutexes
                                .entry(cond_var.clone())
                                .or_default()
                                .insert(mutex);

                            // Track location for violation reporting
                            let start_point = n.start_position();
                            cond_var_locations
                                .entry(cond_var)
                                .or_default()
                                .push((start_point.row, start_point.column));
                        }
                    }
                }
            }
        }
    }

    fn extract_arguments<'a>(&self, arguments: &'a Node, _source: &str) -> Vec<Node<'a>> {
        let mut args = Vec::new();
        let mut cursor = arguments.walk();

        for child in arguments.children(&mut cursor) {
            // Skip parentheses and commas
            if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                args.push(child);
            }
        }

        args
    }
}
