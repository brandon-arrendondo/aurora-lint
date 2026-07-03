//! MEM04-C: Beware of zero-length allocations
//!
//! When the requested size is 0, the behavior of malloc(), calloc(), and realloc() is
//! implementation-defined. The C Standard states that if the size requested is zero,
//! either a null pointer is returned OR the behavior is as if a non-zero size were
//! requested - but the behavior of reading/writing is undefined.
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! int *list = malloc(size);  // No check if size == 0
//! // Undefined behavior if size is 0
//!
//! p2 = realloc(p, 0);  // Passing 0 to realloc
//!
//! data = calloc(num, 0);  // Passing 0 as element size
//! ```
//!
//! **Compliant:**
//! ```c
//! if (size == 0) {
//!     /* Handle error */
//! }
//! int *list = malloc(size);
//!
//! if (nsize != 0) {
//!     p2 = realloc(p, nsize);
//! } else {
//!     p2 = NULL;
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Mem04C;

impl CertRule for Mem04C {
    fn rule_id(&self) -> &'static str {
        "MEM04-C"
    }

    fn description(&self) -> &'static str {
        "Beware of zero-length allocations"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "MEM04-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.traverse(node, source, &mut violations);
        violations
    }
}

impl Mem04C {
    /// Recursively traverse the AST looking for allocation function calls with zero size
    fn traverse(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = node.child_by_field_name("function") {
                let func_name = get_node_text(&function, source);

                // Check for malloc, calloc, realloc calls
                if func_name == "malloc" {
                    self.check_malloc_call(&node, source, violations);
                } else if func_name == "calloc" {
                    self.check_calloc_call(&node, source, violations);
                } else if func_name == "realloc" {
                    self.check_realloc_call(&node, source, violations);
                }
            }
        }
    }

    /// Check malloc(size) calls for potential zero-length allocation
    fn check_malloc_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // Get the argument (malloc takes one argument)
            let args = self.extract_arguments(&arguments);

            if args.len() == 1 {
                let size_arg = &args[0];
                let size_text = get_node_text(size_arg, source);

                if self.is_potentially_zero(&size_text) {
                    // Check if there's a preceding zero validation
                    if !self.has_preceding_zero_check(node, &size_text, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "malloc() called with potentially zero size argument: '{}' without prior zero check. \
                                 Zero-length allocations have implementation-defined behavior.",
                                size_text
                            ),
                            severity: self.severity(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Check that size argument is non-zero before calling malloc()".to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Check calloc(num, size) calls for potential zero-length allocation
    fn check_calloc_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            let args = self.extract_arguments(&arguments);

            if args.len() == 2 {
                let num_arg = &args[0];
                let size_arg = &args[1];

                let num_text = get_node_text(num_arg, source);
                let size_text = get_node_text(size_arg, source);

                // Check if either argument is potentially zero without validation
                let num_needs_check = self.is_potentially_zero(&num_text)
                    && !self.has_preceding_zero_check(node, &num_text, source);
                let size_needs_check = self.is_potentially_zero(&size_text)
                    && !self.has_preceding_zero_check(node, &size_text, source);

                if num_needs_check || size_needs_check {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        message: format!(
                            "calloc() called with potentially zero argument(s) without prior check: num='{}', size='{}'. \
                             Zero-length allocations have implementation-defined behavior.",
                            num_text, size_text
                        ),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        suggestion: Some(
                            "Check that both arguments are non-zero before calling calloc()".to_string(),
                        ),
                        requires_manual_review: None,
                    });
                }
            }
        }
    }

    /// Check realloc(ptr, size) calls for potential zero-length allocation
    fn check_realloc_call(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        if let Some(arguments) = node.child_by_field_name("arguments") {
            let args = self.extract_arguments(&arguments);

            if args.len() == 2 {
                let size_arg = &args[1]; // Second argument is the size
                let size_text = get_node_text(size_arg, source);

                if self.is_potentially_zero(&size_text) {
                    // Check if there's a preceding zero validation
                    if !self.has_preceding_zero_check(node, &size_text, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            message: format!(
                                "realloc() called with potentially zero size argument: '{}' without prior check. \
                                 This is implementation-defined and may cause memory leaks.",
                                size_text
                            ),
                            severity: self.severity(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column + 1,
                            file_path: String::new(),
                            suggestion: Some(
                                "Check that size argument is non-zero before calling realloc()".to_string(),
                            ),
                            requires_manual_review: None,
                        });
                    }
                }
            }
        }
    }

    /// Extract individual arguments from argument_list node
    fn extract_arguments<'a>(&self, arguments: &Node<'a>) -> Vec<Node<'a>> {
        let mut args = Vec::new();

        for i in 0..arguments.child_count() {
            if let Some(child) = arguments.child(i) {
                // Skip punctuation like '(' ')' ','
                if child.kind() != "(" && child.kind() != ")" && child.kind() != "," {
                    args.push(child);
                }
            }
        }

        args
    }

    /// Check if an expression is potentially zero
    ///
    /// This conservatively flags expressions that might be zero, including:
    /// - Literal zero
    /// - Variables/identifiers (which might be zero)
    /// - Complex expressions (which we can't easily verify)
    ///
    /// Only obvious non-zero constants are considered safe.
    fn is_potentially_zero(&self, expr: &str) -> bool {
        let trimmed = expr.trim();

        // Check for literal zero
        if trimmed == "0" {
            return true;
        }

        // Check for NULL (which is often defined as 0 or ((void*)0))
        if trimmed == "NULL" {
            return true;
        }

        // Check if it's a non-zero numeric literal (e.g., "1", "42", "100")
        if let Ok(value) = trimmed.parse::<i64>() {
            return value == 0;
        }

        // sizeof(T) always evaluates to a non-zero value for any complete type
        if trimmed.contains("sizeof") {
            return false;
        }

        // If it's not a literal number, it could be a variable, expression, or macro.
        // Conservatively flag as potentially zero since we can't verify
        // whether they've been validated without data flow analysis.
        true
    }

    /// Check if there's a preceding validation that checks the variable against zero
    ///
    /// This looks for patterns like:
    /// - if (size == 0) { ... }
    /// - if (size != 0) { ... }
    /// - if (!size) { ... }
    /// - if (size) { ... }
    ///
    /// This is a simplified check - it looks for if-statements in the source before
    /// the allocation call that mention the variable name.
    fn has_preceding_zero_check(&self, node: &Node, var_name: &str, source: &str) -> bool {
        // Get the line number of the allocation call
        let alloc_line = node.start_position().row;

        // Get all the source code before this line
        let lines: Vec<&str> = source.lines().collect();
        if alloc_line >= lines.len() {
            return false;
        }

        // Look at previous lines for validation patterns
        // We'll look back up to 50 lines (reasonable scope for local validation)
        let start_line = alloc_line.saturating_sub(50);

        for line in lines.iter().take(alloc_line).skip(start_line) {
            // Check if this line contains an if-statement with the variable
            if line.trim_start().starts_with("if") && line.contains(var_name) {
                // Check for common zero-check patterns
                if line.contains("== 0")
                    || line.contains("!= 0")
                    || line.contains(&format!("!{}", var_name))
                    || (line.contains(&format!("if ({})", var_name))
                        || line.contains(&format!("if({})", var_name)))
                {
                    return true;
                }
            }
        }

        false
    }
}
