// DCL16-C: Use "L," not "l," to indicate a long value
//
// This rule detects integer literals that use lowercase 'l' suffix instead
// of uppercase 'L', which can be confused with the digit '1'.
//
// Detection strategy:
// 1. Find all number literals in the code
// 2. Check if they end with lowercase 'l' or 'll'
// 3. Flag violations and suggest using uppercase 'L' or 'LL'

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use tree_sitter::Node;

pub struct Dcl16C;

impl Dcl16C {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Dcl16C
    }

    /// Check a node and all its descendants for violations
    fn check_node<'a>(
        &self,
        node: &Node<'a>,
        source: &'a str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for number literals
        if node.kind() == "number_literal" {
            let text = get_node_text(node, source);

            // Check for lowercase 'l' or 'll' suffix
            if self.has_lowercase_long_suffix(text) {
                let suggested = self.fix_lowercase_suffix(text);

                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    line: node.start_position().row + 1,
                    column: node.start_position().column + 1,
                    message: format!(
                        "Integer literal '{}' uses lowercase 'l' suffix which can be confused with digit '1'",
                        text
                    ),
                    severity: self.severity(),
                    file_path: String::new(),
                    suggestion: Some(format!(
                        "Use uppercase 'L': {}",
                        suggested
                    )),
                    requires_manual_review: None,
                });
            }
        }

        // Recurse into children
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.check_node(&child, source, violations);
            }
        }
    }

    /// Check if number has lowercase 'l' or 'll' suffix
    fn has_lowercase_long_suffix(&self, text: &str) -> bool {
        // Remove any unsigned suffix first
        let text = text.trim_end_matches('u').trim_end_matches('U');

        // Check for lowercase 'l' or 'll' at the end
        text.ends_with("ll") || (text.ends_with('l') && !text.ends_with('L'))
    }

    /// Fix lowercase suffix to uppercase
    fn fix_lowercase_suffix(&self, text: &str) -> String {
        let mut result = text.to_string();

        // Handle unsigned suffix
        let has_u_suffix = result.ends_with('u') || result.ends_with('U');
        let u_suffix = if has_u_suffix {
            let suffix = result.chars().last().unwrap();
            result.pop();
            Some(suffix)
        } else {
            None
        };

        // Replace lowercase 'l' with 'L'
        if result.ends_with("ll") {
            result = result[..result.len() - 2].to_string() + "LL";
        } else if result.ends_with('l') {
            result = result[..result.len() - 1].to_string() + "L";
        }

        // Restore unsigned suffix
        if let Some(u) = u_suffix {
            result.push(u);
        }

        result
    }
}

impl CertRule for Dcl16C {
    fn rule_id(&self) -> &'static str {
        "DCL16-C"
    }

    fn description(&self) -> &'static str {
        "Use \"L,\" not \"l,\" to indicate a long value"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "DCL16-C"
    }

    fn scan(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(node, source, violations);
    }
}
