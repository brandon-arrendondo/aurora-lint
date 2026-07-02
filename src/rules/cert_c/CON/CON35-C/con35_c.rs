use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Con35C;

impl CertRule for Con35C {
    fn rule_id(&self) -> &'static str {
        "CON35-C"
    }

    fn description(&self) -> &'static str {
        "Avoid deadlock by locking in a predefined order"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "CON35-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Track functions that lock multiple mutexes
        violations.extend(self.check_multiple_locks(*node, source));

        violations
    }
}

impl Con35C {
    /// Check for functions that lock multiple mutexes without using ordered locking
    fn check_multiple_locks(&self, node: Node, source: &str) -> Vec<RuleViolation> {
        query::find_descendants_of_kind(node, "function_definition")
            .into_iter()
            .filter_map(|func| self.analyze_function(func, source))
            .collect()
    }

    /// Analyze a single function for potential deadlock patterns
    fn analyze_function(&self, func_node: Node, source: &str) -> Option<RuleViolation> {
        let func_name = self.get_function_name(func_node, source);

        // Find all mtx_lock calls in this function
        let lock_calls = self.find_lock_calls(func_node, source);

        if lock_calls.len() < 2 {
            // No deadlock risk if there are fewer than 2 locks
            return None;
        }

        // Check if the function has any ordering mechanism
        let has_ordering = self.has_ordering_mechanism(func_node, source, &lock_calls);

        if !has_ordering {
            // Found a potential deadlock: multiple locks without ordering
            let first_lock = &lock_calls[0];
            let violation_msg = format!(
                "Function '{}' locks multiple mutexes without a predefined locking order. Found {} lock operations. This can lead to deadlock if different threads lock these mutexes in different orders",
                func_name.unwrap_or_else(|| "<unknown>".to_string()),
                lock_calls.len()
            );

            return Some(RuleViolation {
                rule_id: self.rule_id().to_string(),
                file_path: "".to_string(),
                severity: self.severity(),
                line: first_lock.start_position().row + 1,
                column: first_lock.start_position().column + 1,
                message: violation_msg,
                suggestion: Some("Implement a predefined locking order (e.g., by comparing mutex IDs before locking)".to_string()),
                requires_manual_review: Some(false),
            });
        }

        None
    }

    /// Get the name of a function from its definition node
    fn get_function_name(&self, func_node: Node, source: &str) -> Option<String> {
        let mut cursor = func_node.walk();
        for child in func_node.children(&mut cursor) {
            if child.kind() == "function_declarator" {
                let mut decl_cursor = child.walk();
                for decl_child in child.children(&mut decl_cursor) {
                    if decl_child.kind() == "identifier" {
                        return Some(get_node_text(&decl_child, source).to_string());
                    }
                }
            }
        }
        None
    }

    /// Find all mtx_lock calls within a function
    fn find_lock_calls<'a>(&self, func_node: Node<'a>, source: &str) -> Vec<Node<'a>> {
        query::find_descendants(func_node, |node| {
            if node.kind() != "call_expression" {
                return false;
            }
            let Some(func_name_node) = node.child_by_field_name("function") else {
                return false;
            };
            let func_name = get_node_text(&func_name_node, source);
            func_name == "mtx_lock" || func_name == "pthread_mutex_lock"
        })
    }

    /// Check if a function has a locking order mechanism
    fn has_ordering_mechanism(&self, func_node: Node, source: &str, lock_calls: &[Node]) -> bool {
        // Look for common ordering patterns:
        // 1. Comparison before locking (e.g., if (a->id < b->id))
        // 2. Pointer comparison to determine order
        // 3. Sorting or ordering of lock targets before locking
        // 4. Using helper variables like "first" and "second" for ordered locking

        // Check for conditional assignment of lock order
        if self.has_conditional_lock_order(func_node, source, lock_calls) {
            return true;
        }

        // Check for comparisons involving mutex-containing objects
        if self.has_comparison_based_ordering(func_node, source) {
            return true;
        }

        false
    }

    /// Check for conditional lock ordering (e.g., first/second mutex pattern)
    fn has_conditional_lock_order(
        &self,
        _func_node: Node,
        source: &str,
        lock_calls: &[Node],
    ) -> bool {
        // Look for patterns like:
        // if (condition) { first = &a; second = &b; } else { first = &b; second = &a; }
        // followed by mtx_lock(first); mtx_lock(second);

        // Check if lock calls use variables that might be set conditionally
        for lock_call in lock_calls {
            if let Some(args_node) = lock_call.child_by_field_name("arguments") {
                let arg_text = get_node_text(&args_node, source);
                // Common ordered locking variable names
                if arg_text.contains("first")
                    || arg_text.contains("second")
                    || arg_text.contains("lock1")
                    || arg_text.contains("lock2")
                    || arg_text.contains("ordered")
                {
                    // Found evidence of ordered locking via variable naming
                    return true;
                }
            }
        }

        false
    }

    /// Check for comparison-based ordering in the function
    fn has_comparison_based_ordering(&self, func_node: Node, source: &str) -> bool {
        // Look for comparison operations involving id, address, or similar fields
        self.has_comparison_recursive(func_node, source)
    }

    fn has_comparison_recursive(&self, node: Node, source: &str) -> bool {
        query::find_first_descendant(node, |n| {
            if n.kind() == "binary_expression" {
                let operator = n.child(1).map(|c| get_node_text(&c, source));
                if let Some(op) = operator {
                    if op == "<" || op == ">" || op == "<=" || op == ">=" {
                        // Check if the comparison involves id fields or similar
                        let full_text = get_node_text(&n, source);
                        if full_text.contains("->id") || full_text.contains(".id") {
                            return true;
                        }
                    }
                }
            }

            // Also check for if statements that might contain ordering logic
            if n.kind() == "if_statement" {
                if let Some(condition) = n.child_by_field_name("condition") {
                    let condition_text = get_node_text(&condition, source);
                    if (condition_text.contains("->id") || condition_text.contains(".id"))
                        && (condition_text.contains('<') || condition_text.contains('>'))
                    {
                        return true;
                    }
                }
            }

            false
        })
        .is_some()
    }
}
