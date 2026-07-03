//! API10-C: APIs should have security options enabled by default
//!
//! APIs with security-related options should be secure by default. This prevents
//! developers from unknowingly using insecure configurations. This rule detects
//! APIs that require explicit opt-in for security features (insecure by default)
//! rather than requiring explicit opt-out (secure by default).
//!
//! Noncompliant pattern:
//!   - TLS_VALIDATE_HOST     (must enable validation)
//!   - TLS_DISABLE_V1_0      (must disable old protocol)
//!
//! Compliant pattern:
//!   - TLS_DISABLE_HOST_VALIDATION  (must disable validation, secure by default)
//!   - TLS_ENABLE_V1_0              (must enable old protocol, secure by default)

use crate::manifest::{RuleCategory, Severity};
use crate::rules::{CertRule, RuleViolation};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Api10C;

impl CertRule for Api10C {
    fn rule_id(&self) -> &'static str {
        "API10-C"
    }

    fn description(&self) -> &'static str {
        "APIs should have security options enabled by default"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "API10-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        // Check for insecure-by-default #define patterns
        for def in query::find_descendants_of_kind(*node, "preproc_def") {
            self.check_define(&def, source, &mut violations);
        }
        violations
    }
}

impl Api10C {
    fn check_define(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Get the macro name
        if let Some(name_node) = node.child_by_field_name("name") {
            let macro_name = get_node_text(&name_node, source);

            // Check for insecure-by-default patterns (security requires opt-in)
            let insecure_patterns = [
                "TLS_VALIDATE_HOST", // Must enable validation (insecure by default)
                "TLS_DISABLE_V1_0",  // Must disable old TLS (insecure by default)
                "TLS_DISABLE_V1_1",  // Must disable old TLS (insecure by default)
                "VALIDATE_",         // Generic validation opt-in pattern
                "ENABLE_SECURITY",   // Generic security opt-in pattern
                "DISABLE_INSECURE",  // Generic insecure opt-out pattern
            ];

            for pattern in &insecure_patterns {
                if macro_name.contains(pattern) {
                    let start_point = node.start_position();
                    let _define_text = get_node_text(node, source);

                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: Severity::Medium,
                        message: format!(
                            "API option '{}' requires explicit opt-in for security (insecure by default). \
                             Security features should be enabled by default, requiring explicit opt-out.",
                            macro_name
                        ),
                        file_path: String::new(),
                        line: start_point.row + 1,
                        column: start_point.column + 1,
                        suggestion: Some(
                            "Rename to require explicit opt-out of security (e.g., 'DISABLE_HOST_VALIDATION' \
                             instead of 'VALIDATE_HOST', 'ENABLE_V1_0' instead of 'DISABLE_V1_0')"
                                .to_string(),
                        ),
                        ..Default::default()
                    });

                    break; // Only report once per define
                }
            }
        }
    }
}
