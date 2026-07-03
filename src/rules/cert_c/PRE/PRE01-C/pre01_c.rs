//! PRE01-C: Use parentheses within macros around parameter names
//!
//! This rule addresses operator precedence issues in macro expansions.
//! Without parentheses around each parameter reference, complex expressions
//! passed as arguments can cause unexpected behavior due to operator precedence.
//!
//! ## Non-compliant example:
//!
//! ```c
//! #define CUBE(I) (I * I * I)
//! int result = 81 / CUBE(2 + 1);  // Expands to 81 / (2 + 1 * 2 + 1 * 2 + 1) = 11 (wrong!)
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! #define CUBE(I) ( (I) * (I) * (I) )
//! int result = 81 / CUBE(2 + 1);  // Expands to 81 / ( (2 + 1) * (2 + 1) * (2 + 1) ) = 3 (correct!)
//! ```
//!
//! ## Exceptions:
//!
//! 1. **Function call arguments**: Parameters already in comma-separated lists don't need parentheses:
//!    ```c
//!    #define FOO(a, b) bar(a, b)  // OK - commas have lower precedence
//!    ```
//!
//! 2. **Token concatenation (##) and stringification (#)**: These operators require un-parenthesized identifiers:
//!    ```c
//!    #define JOIN(a, b) (a ## b)  // OK - ## requires raw identifier
//!    #define SHOW(a) printf(#a " = %d\n", a)  // OK - # requires raw identifier
//!    ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre01C;

impl Pre01C {
    pub fn new() -> Self {
        Self
    }

    /// Extract parameter names from a macro definition
    fn extract_parameters(&self, node: &Node, source: &str) -> Vec<String> {
        let mut params = Vec::new();

        if let Some(params_node) = node.child_by_field_name("parameters") {
            for i in 0..params_node.child_count() {
                if let Some(child) = params_node.child(i) {
                    if child.kind() == "identifier" {
                        let param_name = get_node_text(&child, source).trim().to_string();
                        params.push(param_name);
                    }
                }
            }
        }

        params
    }

    /// Check if a parameter reference is surrounded by parentheses
    fn is_parenthesized(&self, param_start: usize, param_end: usize, text: &str) -> bool {
        // Check if there's a '(' before and ')' after
        let before = &text[..param_start];
        let after = &text[param_end..];

        // Find the last non-whitespace character before the parameter
        let has_open_paren = before.trim_end().ends_with('(');

        // Find the first non-whitespace character after the parameter
        let has_close_paren = after.trim_start().starts_with(')');

        has_open_paren && has_close_paren
    }

    /// Check if a parameter is used with ## (token concatenation) operator
    fn is_token_concatenation(&self, param_start: usize, param_end: usize, text: &str) -> bool {
        let before = &text[..param_start];
        let after = &text[param_end..];

        // Check for ## before or after the parameter
        before.trim_end().ends_with("##") || after.trim_start().starts_with("##")
    }

    /// Check if a parameter is used with # (stringification) operator
    fn is_stringification(&self, param_start: usize, text: &str) -> bool {
        let before = &text[..param_start];

        // Check for # immediately before the parameter (with possible whitespace)
        let trimmed = before.trim_end();
        if trimmed.ends_with('#') {
            // Make sure it's not ## (that's token concatenation)
            return !trimmed.ends_with("##");
        }
        false
    }

    /// Check if a parameter is in a function call argument list
    /// This is detected by checking if the parameter is between commas or between '(' and ','
    fn is_in_function_args(&self, param_start: usize, param_end: usize, text: &str) -> bool {
        // Look backward for opening parenthesis and forward for comma or closing parenthesis
        let before = &text[..param_start];
        let after = &text[param_end..];

        // Check if we're in a pattern like: func(..., param, ...) or func(param, ...)
        // This is a simplified heuristic: if there's a balanced '(' before and we're followed by ',' or ')'

        // Count parentheses depth before this parameter
        let mut depth = 0;
        let mut last_was_open = false;
        for c in before.chars().rev() {
            if c == ')' {
                depth += 1;
            } else if c == '(' {
                if depth == 0 {
                    last_was_open = true;
                    break;
                }
                depth -= 1;
            }
        }

        // Check if after the parameter there's a comma or closing paren
        let trimmed_after = after.trim_start();
        let has_comma_or_close = trimmed_after.starts_with(',') || trimmed_after.starts_with(')');

        last_was_open && has_comma_or_close
    }

    /// Check a function-like macro definition for unparenthesized parameters
    fn check_function_macro(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Only check function-like macros (preproc_function_def)
        if node.kind() != "preproc_function_def" {
            return;
        }

        // Extract parameter names
        let params = self.extract_parameters(node, source);
        if params.is_empty() {
            return; // No parameters to check
        }

        // Get the replacement text (value)
        let value_node = match node.child_by_field_name("value") {
            Some(v) => v,
            None => return, // No replacement text
        };

        let value_text = get_node_text(&value_node, source);

        // Check each parameter reference in the replacement text
        for param in &params {
            // Find all occurrences of this parameter
            let mut start_pos = 0;
            while let Some(pos) = value_text[start_pos..].find(param.as_str()) {
                let absolute_pos = start_pos + pos;
                let param_end = absolute_pos + param.len();

                // Check if this is a complete identifier match (not part of another identifier)
                let before_char = if absolute_pos > 0 {
                    value_text.chars().nth(absolute_pos - 1)
                } else {
                    None
                };
                let after_char = value_text.chars().nth(param_end);

                let is_complete_match = (before_char.is_none()
                    || !before_char.unwrap().is_alphanumeric() && before_char.unwrap() != '_')
                    && (after_char.is_none()
                        || !after_char.unwrap().is_alphanumeric() && after_char.unwrap() != '_');

                if is_complete_match {
                    // Check for exceptions
                    let is_concat =
                        self.is_token_concatenation(absolute_pos, param_end, &value_text);
                    let is_stringify = self.is_stringification(absolute_pos, &value_text);
                    let is_func_arg =
                        self.is_in_function_args(absolute_pos, param_end, &value_text);

                    if !is_concat && !is_stringify && !is_func_arg {
                        // Check if it's parenthesized
                        if !self.is_parenthesized(absolute_pos, param_end, &value_text) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Macro parameter '{}' is not parenthesized in replacement text. This can cause operator precedence issues.",
                                    param
                                ),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(format!(
                                    "Wrap parameter '{}' in parentheses: ({}) instead of {}",
                                    param, param, param
                                )),
                                ..Default::default()
                            });
                            break; // Only report once per parameter per macro
                        }
                    }
                }

                start_pos = param_end;
            }
        }
    }
}

impl CertRule for Pre01C {
    fn rule_id(&self) -> &'static str {
        "PRE01-C"
    }

    fn description(&self) -> &'static str {
        "Use parentheses within macros around parameter names"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "PRE01-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for macro_node in query::find_descendants_of_kind(*node, "preproc_function_def") {
            self.check_function_macro(&macro_node, source, &mut violations);
        }
        violations
    }
}
