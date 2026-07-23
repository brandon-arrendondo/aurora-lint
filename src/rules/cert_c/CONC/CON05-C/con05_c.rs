//! CON05-C: Do not perform operations that can block while holding a lock
//!
//! This rule detects blocking operations (I/O, network operations, etc.) that
//! occur between mutex lock and unlock calls. Blocking while holding a lock
//! can cause other threads waiting for the lock to also block, potentially
//! causing deadlock or performance degradation.
//!
//! Noncompliant pattern:
//!   mtx_lock(&mutex);
//!   fopen("file", "r");    // Blocking I/O while locked - VIOLATION
//!   mtx_unlock(&mutex);
//!
//! Compliant pattern:
//!   fopen("file", "r");    // I/O before acquiring lock
//!   mtx_lock(&mutex);
//!   // ... access shared data ...
//!   mtx_unlock(&mutex);

use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use std::collections::HashSet;
use tree_sitter::Node;

pub struct Con05C;

impl CertRule for Con05C {
    fn rule_id(&self) -> &'static str {
        "CON05-C"
    }

    fn description(&self) -> &'static str {
        "Do not perform operations that can block while holding a lock"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for func_node in query::find_descendants_of_kind(*node, "function_definition") {
            self.analyze_function_body(&func_node, source, &mut violations);
        }
        violations
    }
}

impl Con05C {
    fn analyze_function_body(
        &self,
        function_node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(body) = function_node.child_by_field_name("body") {
            let mut locked_regions = Vec::new();
            self.find_locked_regions(&body, source, &mut locked_regions);

            // Check each locked region for blocking operations
            for (lock_call, unlock_call) in locked_regions {
                self.check_for_blocking_ops_in_region(
                    &body,
                    source,
                    &lock_call,
                    &unlock_call,
                    violations,
                );
            }
        }
    }

    fn find_locked_regions<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        regions: &mut Vec<(Node<'a>, Node<'a>)>,
    ) {
        // Find pairs of mtx_lock/mtx_unlock or pthread_mutex_lock/pthread_mutex_unlock
        let mut locks = Vec::new();
        let mut unlocks = Vec::new();

        self.collect_lock_unlock_calls(node, source, &mut locks, &mut unlocks);

        // Simple pairing: match locks with subsequent unlocks
        let mut used_unlocks = HashSet::new();
        for lock in &locks {
            for unlock in &unlocks {
                if used_unlocks.contains(&unlock.id()) {
                    continue;
                }
                // Check if unlock comes after lock
                if unlock.start_byte() > lock.start_byte() {
                    regions.push((*lock, *unlock));
                    used_unlocks.insert(unlock.id());
                    break;
                }
            }
        }
    }

    fn collect_lock_unlock_calls<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        locks: &mut Vec<Node<'a>>,
        unlocks: &mut Vec<Node<'a>>,
    ) {
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call_node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if func_name == "mtx_lock" || func_name == "pthread_mutex_lock" {
                    locks.push(call_node);
                } else if func_name == "mtx_unlock" || func_name == "pthread_mutex_unlock" {
                    unlocks.push(call_node);
                }
            }
        }
    }

    fn check_for_blocking_ops_in_region(
        &self,
        body: &Node,
        source: &str,
        lock_call: &Node,
        unlock_call: &Node,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Find all call expressions between lock and unlock
        let mut calls_in_region = Vec::new();
        self.collect_calls_in_region(
            body,
            source,
            lock_call.start_byte(),
            unlock_call.start_byte(),
            &mut calls_in_region,
        );

        // Check if any are blocking operations
        for call in calls_in_region {
            if let Some(function) = call.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);
                if self.is_blocking_operation(&func_name) {
                    let start_point = call.start_position();
                    let call_text = get_node_text(&call, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Blocking operation '{}' called while holding a lock. This can cause other threads to block unnecessarily",
                            call_text
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Move blocking I/O operations outside the locked region. Perform I/O before acquiring the lock or after releasing it".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }

    fn collect_calls_in_region<'a>(
        &self,
        node: &Node<'a>,
        source: &str,
        lock_start: usize,
        unlock_start: usize,
        calls: &mut Vec<Node<'a>>,
    ) {
        // Only collect calls that are strictly between lock and unlock
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            let call_start = call_node.start_byte();
            if call_start > lock_start && call_start < unlock_start {
                // Exclude the unlock call itself
                if let Some(function) = call_node.child_by_field_name("function") {
                    let func_name = get_node_text(&function, source);
                    if func_name != "mtx_unlock" && func_name != "pthread_mutex_unlock" {
                        calls.push(call_node);
                    }
                }
            }
        }
    }

    fn is_blocking_operation(&self, func_name: &str) -> bool {
        // List of functions that can block
        matches!(
            func_name,
            // File I/O
            "fopen"
                | "fclose"
                | "fread"
                | "fwrite"
                | "fprintf"
                | "fscanf"
                | "fgets"
                | "fputs"
                | "fflush"
                | "open"
                | "close"
                | "read"
                | "write"
                // Console I/O
                | "printf"
                | "scanf"
                | "puts"
                | "gets"
                | "getchar"
                | "putchar"
                // Network I/O
                | "send"
                | "recv"
                | "sendto"
                | "recvfrom"
                | "connect"
                | "accept"
                | "listen"
                // Other blocking operations
                | "sleep"
                | "usleep"
                | "nanosleep"
                | "thrd_sleep"
        )
    }
}
