//! MSC32-C: Properly seed pseudorandom number generators
//!
//! This rule detects calls to random number generation functions (rand, random)
//! without a prior call to seed functions (srand, srandom) in the same function scope.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! void func(void) {
//!     printf("%d\n", rand());  // VIOLATION: rand() called without srand()
//! }
//! ```
//!
//! **Compliant:**
//! ```c
//! void func(void) {
//!     srand(time(NULL));       // OK: srand() called before rand()
//!     printf("%d\n", rand());
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find function definitions
//! - Track calls to seed functions (srand, srandom)
//! - Track calls to RNG functions (rand, random, rand_r)
//! - Report violations if RNG called without prior seed

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Msc32C;

impl CertRule for Msc32C {
    fn rule_id(&self) -> &'static str {
        "MSC32-C"
    }

    fn description(&self) -> &'static str {
        "Properly seed pseudorandom number generators"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MSC32-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Msc32C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Check function definitions
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            self.check_function(&func, source, violations);
        }
    }

    fn check_function(&self, func: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Get function body
        let body = match func.child_by_field_name("body") {
            Some(b) => b,
            None => return,
        };

        // Track whether we've seen a seed call
        let mut has_seed = false;

        // Track all function calls in order
        let mut calls = Vec::new();
        self.collect_calls(&body, source, &mut calls);

        // Check each call
        for call in &calls {
            if self.is_seed_function(&call.func_name) {
                has_seed = true;
            } else if self.is_rng_function(&call.func_name) {
                if !has_seed {
                    // RNG called without prior seed
                    self.report_violation_at(call.line, call.column, &call.func_name, violations);
                }
            }
        }
    }

    fn collect_calls(&self, node: &Node, source: &str, calls: &mut Vec<FunctionCall>) {
        for call_node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = call_node.child_by_field_name("function") {
                let func_name = &source[function.start_byte()..function.end_byte()];
                calls.push(FunctionCall {
                    line: call_node.start_position().row + 1,
                    column: call_node.start_position().column + 1,
                    func_name: func_name.to_string(),
                });
            }
        }
    }

    fn is_seed_function(&self, name: &str) -> bool {
        matches!(name, "srand" | "srandom" | "seed_r")
    }

    fn is_rng_function(&self, name: &str) -> bool {
        matches!(name, "rand" | "random" | "rand_r")
    }

    fn report_violation_at(
        &self,
        line: usize,
        column: usize,
        func_name: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        violations.push(RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: Severity::Medium,
            message: format!(
                "Pseudorandom number generator '{}()' called without proper seeding - will produce predictable sequences",
                func_name
            ),
            file_path: String::new(),
            line,
            column,
            suggestion: Some(format!(
                "Call srand() or srandom() with a non-deterministic seed (e.g., from time() or /dev/urandom) before calling {}()",
                func_name
            )),
            ..Default::default()
        });
    }
}

struct FunctionCall {
    line: usize,
    column: usize,
    func_name: String,
}
