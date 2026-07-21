//! MEM11-C: Do not assume infinite heap space
//!
//! Memory is fundamentally limited. Programs that continuously allocate memory
//! without bounds can exhaust the heap, leading to undefined behavior and crashes.
//! This is particularly problematic in:
//! 1. Long-running servers that accumulate data
//! 2. Loops with user-controlled iteration counts
//! 3. Unbounded data structure growth (linked lists, trees, etc.)
//!
//! While static analysis cannot perfectly detect heap exhaustion (as it depends on
//! runtime environment), we can identify common anti-patterns like memory allocation
//! in loops without upper bound checks.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! do {
//!     fgets(new_name, MAX_LENGTH, stdin);
//!     if (strcmp(new_name, "quit") != 0) {
//!         namelist_t new_entry = malloc(sizeof(struct namelist_s)); // Unbounded allocation
//!         if (new_entry == NULL) { /* Handle error */ }
//!         // ... add to list ...
//!     }
//! } while (strcmp(new_name, "quit") != 0);
//! ```
//!
//! **Compliant:**
//! ```c
//! // Use database or file storage instead of accumulating in memory
//! // Or implement a maximum size limit:
//! int count = 0;
//! do {
//!     if (count >= MAX_ENTRIES) {
//!         /* Refuse to add more entries */
//!         break;
//!     }
//!     // ... allocate and add entry ...
//!     count++;
//! } while (...);
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::{get_node_text, get_sanitized_node_text};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Mem11C;

impl CertRule for Mem11C {
    fn rule_id(&self) -> &'static str {
        "MEM11-C"
    }

    fn description(&self) -> &'static str {
        "Do not assume infinite heap space"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MEM11-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_unbounded_allocations(node, source, violations);
    }
}

impl Mem11C {
    fn check_unbounded_allocations(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for loop statements
        for loop_node in query::find_descendants_of_kinds(
            *node,
            &["while_statement", "do_statement", "for_statement"],
        ) {
            // Check if this loop contains memory allocations
            if self.contains_memory_allocation(&loop_node, source)
                // Check if there's a bound check (like a counter)
                && !self.has_bound_check(&loop_node, source)
            {
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    message: "Memory allocation in loop without upper bound check. \
                             Unbounded memory allocation can exhaust heap space. \
                             Consider using databases, file storage, or implementing \
                             a maximum size limit for data structures."
                        .to_string(),
                    severity: self.severity(),
                    line: loop_node.start_position().row + 1,
                    column: loop_node.start_position().column + 1,
                    file_path: String::new(),
                    suggestion: Some(
                        "Add a counter to limit iterations or use persistent storage \
                         (database/file) instead of accumulating unbounded data in memory"
                            .to_string(),
                    ),
                    requires_manual_review: Some(true),
                });
            }
        }
    }

    /// Check if a node contains memory allocation calls (malloc, calloc, realloc)
    fn contains_memory_allocation(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "call_expression" {
                return false;
            }
            match n.child_by_field_name("function") {
                Some(function) => {
                    let func_name = get_node_text(&function, source);
                    func_name == "malloc" || func_name == "calloc" || func_name == "realloc"
                }
                None => false,
            }
        })
        .is_some()
    }

    /// Check if there's a bound check in the loop (heuristic: look for counter variables)
    /// This is a simplified heuristic - we look for common patterns like:
    /// - Counter increment with comparison (count++; if (count >= MAX))
    /// - Loop counter with break based on limit
    /// - Loop condition checking against a limit
    fn has_bound_check(&self, node: &Node, source: &str) -> bool {
        // Look for specific patterns that indicate iteration bounds:
        // 1. Counter variable being incremented (count++, i++, etc.)
        // 2. Break statement with counter comparison
        // 3. Conditional with counter >= or > a limit

        if self.has_counter_with_limit(node, source) {
            return true;
        }

        false
    }

    /// Check if there's a counter variable being incremented with a limit check
    fn has_counter_with_limit(&self, node: &Node, source: &str) -> bool {
        let mut has_increment = false;
        let mut has_comparison = false;

        // Recursively search for increment and comparison patterns
        self.search_counter_patterns(node, source, &mut has_increment, &mut has_comparison);

        // Both increment and comparison must be present
        has_increment && has_comparison
    }

    fn search_counter_patterns(
        &self,
        node: &Node,
        source: &str,
        has_increment: &mut bool,
        has_comparison: &mut bool,
    ) {
        for n in query::find_descendants_of_kinds(
            *node,
            &[
                "update_expression",
                "assignment_expression",
                "binary_expression",
                "if_statement",
            ],
        ) {
            // Sanitized so a string literal argument (e.g. inside a strcmp()
            // condition) can't spoof a bound-check pattern and silently
            // suppress a genuine unbounded-allocation violation.
            let node_text = get_sanitized_node_text(&n, source);

            // Check for increment patterns (count++, ++count, count += 1, i++, etc.)
            if n.kind() == "update_expression" {
                // count++, ++count
                *has_increment = true;
            } else if n.kind() == "assignment_expression" {
                // count += 1, count = count + 1
                if node_text.contains("+=")
                    || node_text.contains("= ") && node_text.contains(" + 1")
                {
                    *has_increment = true;
                }
            }

            // Check for comparison patterns in conditions
            if n.kind() == "binary_expression" {
                if let Some(operator) = n.child_by_field_name("operator") {
                    let op = get_node_text(&operator, source);
                    if op == ">=" || op == ">" || op == "<" || op == "<=" {
                        // Check if this is comparing a variable to something
                        // (not just any comparison, but one that looks like a limit)
                        if node_text.contains("count")
                            || node_text.contains("limit")
                            || (node_text.contains("MAX") && node_text.contains(">="))
                            || (node_text.contains("MAX") && node_text.contains(">"))
                        {
                            *has_comparison = true;
                        }
                    }
                }
            }

            // Check for break statements with conditions
            if n.kind() == "if_statement" {
                if let Some(body) = n.child_by_field_name("consequence") {
                    let body_text = get_sanitized_node_text(&body, source);
                    if body_text.contains("break") {
                        // This is a conditional break, check if condition has comparison
                        if let Some(condition) = n.child_by_field_name("condition") {
                            let cond_text = get_sanitized_node_text(&condition, source);
                            if cond_text.contains(">=")
                                || cond_text.contains(">")
                                || cond_text.contains("MAX")
                                || cond_text.contains("limit")
                            {
                                *has_comparison = true;
                            }
                        }
                    }
                }
            }
        }
    }
}
