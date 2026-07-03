//! PRE05-C: Understand macro replacement when concatenating tokens or performing stringification
//!
//! This rule requires understanding how the C preprocessor handles the `##` (token
//! concatenation) and `#` (stringification) operators. When these operators are used
//! directly on macro parameters, the parameters are NOT expanded before the operation.
//! To get proper macro expansion, an additional level of indirection is required.
//!
//! ## Examples:
//!
//! **Non-compliant (single-level macro with ##):**
//! ```c
//! #define JOIN(x, y) x ## y
//! // Problem: x and y are not expanded before concatenation
//! ```
//!
//! **Non-compliant (single-level macro with #):**
//! ```c
//! #define str(s) #s
//! #define foo 4
//! str(foo)  // Produces "foo", not "4"
//! ```
//!
//! **Compliant (two-level indirection for ##):**
//! ```c
//! #define JOIN(x, y) JOIN_AGAIN(x, y)
//! #define JOIN_AGAIN(x, y) x ## y
//! // Now x and y are expanded before concatenation
//! ```
//!
//! **Compliant (two-level indirection for #):**
//! ```c
//! #define xstr(s) str(s)
//! #define str(s) #s
//! #define foo 4
//! xstr(foo)  // Produces "4"
//! ```
//!
//! ## Detection Strategy:
//! - Find preprocessor function definitions (macros with parameters)
//! - Check if macro body contains `##` or `#` operators
//! - If operators are used directly (not via another macro call), report violation

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre05C;

impl CertRule for Pre05C {
    fn rule_id(&self) -> &'static str {
        "PRE05-C"
    }

    fn description(&self) -> &'static str {
        "Understand macro replacement when concatenating tokens or performing stringification"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "PRE05-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // First pass: collect all macro names that are called by other macros
        let called_macros = self.find_called_macros(node, source);

        // Second pass: check each macro definition
        self.check_node(node, source, &mut violations, &called_macros);
        violations
    }
}

impl Pre05C {
    fn find_called_macros(&self, node: &Node, source: &str) -> Vec<String> {
        let mut called = Vec::new();
        for macro_node in query::find_descendants_of_kind(*node, "preproc_function_def") {
            // Get the macro body (value field)
            if let Some(value_node) = macro_node.child_by_field_name("value") {
                let value_text = &source[value_node.start_byte()..value_node.end_byte()];
                // Look for potential macro calls (identifier followed by parentheses)
                // This is a simple heuristic: find words that look like function calls
                for word in value_text.split(|c: char| !c.is_alphanumeric() && c != '_') {
                    if !word.is_empty() && !called.contains(&word.to_string()) {
                        called.push(word.to_string());
                    }
                }
            }
        }
        called
    }

    fn check_node(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        called_macros: &[String],
    ) {
        // Look for preprocessor function definitions (macros with parameters)
        for macro_node in query::find_descendants_of_kind(*node, "preproc_function_def") {
            self.check_macro_definition(&macro_node, source, violations, called_macros);
        }
    }

    fn check_macro_definition(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
        called_macros: &[String],
    ) {
        let macro_text = &source[node.start_byte()..node.end_byte()];

        // Check for token concatenation (##) or stringification (#) operators
        if macro_text.contains("##") || self.contains_stringification(macro_text) {
            // Get the macro name for better error messages
            let macro_name = self.extract_macro_name(node, source);

            // Skip inner helper macros (those with naming patterns suggesting they're implementation details)
            // These are typically the inner level in two-level indirection patterns
            if self.is_likely_helper_macro(&macro_name) {
                return;
            }

            // Check if this macro is called by a wrapper macro that doesn't use ##/#
            // (proper two-level indirection pattern)
            if self.has_proper_wrapper(node, source, &macro_name, called_macros) {
                return;
            }

            // Determine which operator is present
            let operator = if macro_text.contains("##") { "##" } else { "#" };
            let operation = if operator == "##" {
                "token concatenation"
            } else {
                "stringification"
            };

            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: Severity::Low,
                message: format!(
                    "Macro '{}' uses {} operator ({}) which prevents parameter expansion - consider using two-level macro indirection for proper expansion",
                    macro_name, operation, operator
                ),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some(format!(
                    "Use two-level indirection: define a wrapper macro that calls another macro with {}, allowing parameters to expand first",
                    operator
                )),
                ..Default::default()
            });
        }
    }

    /// Check if macro contains stringification operator (#)
    /// We need to distinguish # (stringification) from ## (concatenation) and #include
    fn contains_stringification(&self, macro_text: &str) -> bool {
        // Look for # that is not part of ## and not part of #include/#define etc
        let chars: Vec<char> = macro_text.chars().collect();
        for i in 0..chars.len() {
            if chars[i] == '#' {
                // Skip if it's the # from #define
                if i == 0 {
                    continue;
                }
                // Skip if it's part of ##
                if i + 1 < chars.len() && chars[i + 1] == '#' {
                    continue;
                }
                if i > 0 && chars[i - 1] == '#' {
                    continue;
                }
                // Found a standalone # (stringification operator)
                return true;
            }
        }
        false
    }

    /// Extract macro name from the definition node
    fn extract_macro_name(&self, node: &Node, source: &str) -> String {
        if let Some(name_node) = node.child_by_field_name("name") {
            source[name_node.start_byte()..name_node.end_byte()].to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// Check if macro name suggests it's a helper/implementation macro
    /// Helper macros are the inner level in two-level indirection patterns
    fn is_likely_helper_macro(&self, name: &str) -> bool {
        let upper = name.to_uppercase();

        // Common suffixes for helper macros
        upper.ends_with("_AGAIN")
            || upper.ends_with("_IMPL")
            || upper.ends_with("_INTERNAL")
            || upper.ends_with("_HELPER")
            || upper.ends_with("_INNER")
            || upper.ends_with("_")
    }

    /// Check if this macro has a proper wrapper that doesn't use ##/#
    /// This indicates correct two-level indirection pattern
    fn has_proper_wrapper(
        &self,
        _node: &Node,
        source: &str,
        macro_name: &str,
        _called_macros: &[String],
    ) -> bool {
        // Look through all macro definitions in the source
        // Check if there's a macro that:
        // 1. Calls this macro
        // 2. Doesn't use ## or # directly
        // 3. Has the same or similar name (e.g., JOIN wrapping JOIN_AGAIN)

        // Simple heuristic: look for a wrapper pattern like:
        // #define WRAPPER(...) INNER_MACRO(...)
        // where INNER_MACRO uses ## and WRAPPER doesn't

        let lines: Vec<&str> = source.lines().collect();
        for line in &lines {
            let trimmed = line.trim();
            if !trimmed.starts_with("#define") {
                continue;
            }

            // Skip if this line is the macro itself
            if trimmed.contains(&format!("#define {}", macro_name))
                || trimmed.contains(&format!("#define {}(", macro_name))
            {
                continue;
            }

            // Check if this is a macro that calls our target macro
            if trimmed.contains(macro_name) && trimmed.contains('(') {
                // This macro references our target - check if it uses ## or #
                if !trimmed.contains("##") && !self.line_contains_stringification(trimmed) {
                    // Found a wrapper macro that doesn't use ##/#
                    // This is proper two-level indirection
                    return true;
                }
            }
        }

        false
    }

    /// Check if a line contains stringification operator
    fn line_contains_stringification(&self, line: &str) -> bool {
        let chars: Vec<char> = line.chars().collect();
        for i in 0..chars.len() {
            if chars[i] == '#' {
                // Skip if it's the # from #define
                if i == 0 {
                    continue;
                }
                // Skip if it's part of ##
                if i + 1 < chars.len() && chars[i + 1] == '#' {
                    continue;
                }
                if i > 0 && chars[i - 1] == '#' {
                    continue;
                }
                return true;
            }
        }
        false
    }
}
