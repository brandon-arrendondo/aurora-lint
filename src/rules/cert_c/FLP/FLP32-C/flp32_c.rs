//! FLP32-C: Prevent or detect domain and range errors in math functions
//!
//! Math functions can produce domain errors, range errors, or pole errors:
//! - Domain error: input argument outside the function's defined domain (e.g., sqrt(-1))
//! - Range error: result cannot be represented due to extreme magnitude (e.g., pow(10, 1e6))
//! - Pole error: function approaches infinity (e.g., log(0))
//!
//! ## Rationale:
//! - Domain and range errors can lead to undefined behavior or incorrect results
//! - Programs should check for these errors using errno or return value checks
//! - Critical for numerical stability and correctness
//!
//! ## Examples:
//!
//! **Non-compliant (no error checking):**
//! ```c
//! double result = sqrt(x);
//! // No check for domain error (x < 0) or NaN result
//! ```
//!
//! **Compliant (with error checking):**
//! ```c
//! errno = 0;
//! double result = sqrt(x);
//! if (errno != 0 || isnan(result)) {
//!     /* Handle error */
//! }
//! ```
//!
//! ## Detection Strategy:
//! - Find calls to math.h functions
//! - Check if errno is checked or cleared nearby
//! - Check if return value is validated (isnan, isinf, isfinite)
//! - Report if no error handling is present

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Flp32C;

impl CertRule for Flp32C {
    fn rule_id(&self) -> &'static str {
        "FLP32-C"
    }

    fn description(&self) -> &'static str {
        "Prevent or detect domain and range errors in math functions"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "FLP32-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Flp32C {
    /// List of math.h functions that can produce domain/range/pole errors
    const MATH_FUNCTIONS: &'static [&'static str] = &[
        "sqrt",
        "sqrtf",
        "sqrtl",
        "pow",
        "powf",
        "powl",
        "log",
        "logf",
        "logl",
        "log10",
        "log10f",
        "log10l",
        "log2",
        "log2f",
        "log2l",
        "exp",
        "expf",
        "expl",
        "exp2",
        "exp2f",
        "exp2l",
        "asin",
        "asinf",
        "asinl",
        "acos",
        "acosf",
        "acosl",
        "atan",
        "atanf",
        "atanl",
        "atan2",
        "atan2f",
        "atan2l",
        "sinh",
        "sinhf",
        "sinhl",
        "cosh",
        "coshf",
        "coshl",
        "tanh",
        "tanhf",
        "tanhl",
        "asinh",
        "asinhf",
        "asinhl",
        "acosh",
        "acoshf",
        "acoshl",
        "atanh",
        "atanhf",
        "atanhl",
        "hypot",
        "hypotf",
        "hypotl",
        "fmod",
        "fmodf",
        "fmodl",
        "remainder",
        "remainderf",
        "remainderl",
        "remquo",
        "remquof",
        "remquol",
    ];

    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for call expressions
        for node in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = get_node_text(&func, source);

                // Check if it's a math function
                if Self::MATH_FUNCTIONS.contains(&func_name) {
                    // Check if there's error checking nearby
                    if !self.has_error_checking(&node, source) {
                        let line = node.start_position().row + 1;

                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: Severity::Medium,
                            message: format!(
                                "Call to {}() without checking for domain/range errors",
                                func_name
                            ),
                            file_path: String::new(),
                            line,
                            column: 0,
                            suggestion: Some(
                                "Check errno or use isnan()/isinf() to detect math errors"
                                    .to_string(),
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check if there's error checking near the math function call.
    /// Searches a limited window (5 statements before and after) for errno/isnan/etc.,
    /// rather than the entire containing scope.
    fn has_error_checking(&self, call_node: &Node, source: &str) -> bool {
        // Find the statement containing this call
        let stmt_node = match self.find_containing_statement(call_node) {
            Some(s) => s,
            None => return false,
        };

        // Find the compound_statement containing the statement
        let compound_node = {
            let mut parent = stmt_node.parent();
            loop {
                match parent {
                    Some(p) if p.kind() == "compound_statement" => break p,
                    Some(p) => parent = p.parent(),
                    None => return false,
                }
            }
        };

        let stmt_start_byte = stmt_node.start_byte();
        let stmt_end_byte = stmt_node.end_byte();
        const MAX_SEARCH: usize = 5;

        // Collect statement indices and find the call's position
        let mut statement_indices: Vec<usize> = Vec::new();
        let mut call_stmt_idx: Option<usize> = None;
        let mut cursor = compound_node.walk();
        for (i, child) in compound_node.children(&mut cursor).enumerate() {
            if child.start_byte() >= stmt_start_byte && child.end_byte() <= stmt_end_byte {
                call_stmt_idx = Some(statement_indices.len());
            }
            statement_indices.push(i);
        }

        let call_pos = match call_stmt_idx {
            Some(p) => p,
            None => return false,
        };

        // Search backward (up to 5 statements before)
        let start = call_pos.saturating_sub(MAX_SEARCH);
        for &idx in &statement_indices[start..call_pos] {
            if let Some(child) = compound_node.child(idx) {
                if self.node_contains_errno_or_error_check(&child, source) {
                    return true;
                }
            }
        }

        // Search forward (up to 5 statements after)
        let end = std::cmp::min(call_pos + 1 + MAX_SEARCH, statement_indices.len());
        for &idx in &statement_indices[(call_pos + 1)..end] {
            if let Some(child) = compound_node.child(idx) {
                if self.node_contains_errno_or_error_check(&child, source) {
                    return true;
                }
            }
        }

        false
    }

    /// Find the statement node containing a given node
    fn find_containing_statement<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = node.parent();
        while let Some(p) = current {
            if matches!(
                p.kind(),
                "expression_statement"
                    | "declaration"
                    | "if_statement"
                    | "while_statement"
                    | "for_statement"
                    | "return_statement"
            ) {
                return Some(p);
            }
            current = p.parent();
        }
        None
    }

    /// Recursively check if a node contains errno usage or error-checking function calls
    fn node_contains_errno_or_error_check(&self, node: &Node, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() == "identifier" {
                let text = get_node_text(&n, source);
                if text == "errno" {
                    return true;
                }
            }

            if n.kind() == "call_expression" {
                if let Some(func) = n.child_by_field_name("function") {
                    let func_name = get_node_text(&func, source);
                    if matches!(
                        func_name,
                        "isnan"
                            | "isinf"
                            | "isfinite"
                            | "fpclassify"
                            | "isnormal"
                            | "signbit"
                            | "fetestexcept"
                            | "feclearexcept"
                            | "isless"
                            | "islessequal"
                            | "isgreater"
                            | "isgreaterequal"
                            | "islessgreater"
                            | "isunordered"
                    ) {
                        return true;
                    }
                }
            }

            false
        })
        .is_some()
    }
}
