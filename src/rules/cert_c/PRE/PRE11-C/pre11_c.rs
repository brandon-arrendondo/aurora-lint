//! PRE11-C: Do not conclude macro definitions with a semicolon
//!
//! This rule prevents macro definitions from ending with a semicolon, which can
//! cause unexpected behavior when the macro is expanded. Trailing semicolons in
//! macros can create null statements or interfere with control flow.
//!
//! ## Non-compliant example:
//!
//! ```c
//! #define FOR_LOOP(n) for(i=0; i<(n); i++);  // Trailing semicolon
//! #define INCREMOD(x, max) ((x) = ((x) + 1) % (max));  // Trailing semicolon
//!
//! FOR_LOOP(10) {  // Loop body never executes (null statement from semicolon)
//!     doSomething();
//! }
//! ```
//!
//! ## Compliant solution:
//!
//! ```c
//! #define FOR_LOOP(n) for(i=0; i<(n); i++)  // No trailing semicolon
//! #define INCREMOD(x, max) ((x) = ((x) + 1) % (max))  // No trailing semicolon
//!
//! FOR_LOOP(10) {  // Works correctly
//!     doSomething();
//! }
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre11C;

impl Pre11C {
    pub fn new() -> Self {
        Self
    }

    /// Check if a macro definition ends with a semicolon
    fn check_macro_definition(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Check both object-like and function-like macros
        let is_macro = node.kind() == "preproc_def" || node.kind() == "preproc_function_def";
        if !is_macro {
            return;
        }

        // Get the value/replacement text
        let value_node = match node.child_by_field_name("value") {
            Some(v) => v,
            None => return, // No replacement text
        };

        let value_text = get_node_text(&value_node, source);
        let trimmed = value_text.trim_end();

        // Check if the macro definition ends with a semicolon
        if trimmed.ends_with(';') {
            // Get the macro name for better error message
            let macro_name = if let Some(name_node) = node.child_by_field_name("name") {
                get_node_text(&name_node, source)
            } else {
                "(unknown)"
            };

            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                message: format!(
                    "Macro '{}' definition ends with a semicolon. This can cause unexpected behavior when the macro is used.",
                    macro_name
                ),
                file_path: String::new(),
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
                suggestion: Some(
                    "Remove the trailing semicolon from the macro definition. The semicolon should be added by the macro user, not in the definition.".to_string()
                ),
                ..Default::default()
            });
        }
    }
}

impl CertRule for Pre11C {
    fn rule_id(&self) -> &'static str {
        "PRE11-C"
    }

    fn description(&self) -> &'static str {
        "Do not conclude macro definitions with a semicolon"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "PRE11-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        for macro_node in
            query::find_descendants_of_kinds(*node, &["preproc_def", "preproc_function_def"])
        {
            self.check_macro_definition(&macro_node, source, &mut violations);
        }
        violations
    }
}
