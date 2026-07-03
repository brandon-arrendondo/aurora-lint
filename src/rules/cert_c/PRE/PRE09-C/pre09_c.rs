//! PRE09-C: Do not replace secure functions with less secure functions through macro definitions
//!
//! Don't use #define to replace secure standard library functions (like vsnprintf)
//! with less secure versions (like vsprintf).
//!
//! ## Examples:
//!
//! **Non-compliant:**
//! ```c
//! #define vsnprintf(buf, size, fmt, list) vsprintf(buf, fmt, list)
//! ```
//!
//! **Compliant:**
//! ```c
//! #ifndef __USE_ISOC11
//!   #include "my_stdio.h"  // Conditional inclusion, not macro replacement
//! #endif
//! ```

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Pre09C;

// List of secure functions that should not be replaced
const SECURE_FUNCTIONS: &[&str] = &[
    "vsnprintf",
    "snprintf",
    "vsnprintf_s",
    "snprintf_s",
    "strncpy_s",
    "strncat_s",
    "memcpy_s",
    "memmove_s",
];

impl CertRule for Pre09C {
    fn rule_id(&self) -> &'static str {
        "PRE09-C"
    }

    fn description(&self) -> &'static str {
        "Do not replace secure functions with less secure functions through macro definitions"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "PRE09-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Pre09C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for #define directives
        for macro_node in query::find_descendants_of_kind(*node, "preproc_function_def") {
            if let Some(name_node) = macro_node.child_by_field_name("name") {
                let macro_name = get_node_text(&name_node, source);

                // Check if it's replacing a secure function
                if SECURE_FUNCTIONS.contains(&macro_name) {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::High,
                        message: format!(
                            "Macro definition replaces secure function '{}' - may introduce vulnerabilities",
                            macro_name
                        ),
                        file_path: String::new(),
                        line: macro_node.start_position().row + 1,
                        column: macro_node.start_position().column + 1,
                        suggestion: Some(
                            "Use conditional compilation (#ifndef) or wrapper functions instead of macro replacement".to_string()
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }
}
