use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Msc33C;

impl CertRule for Msc33C {
    fn rule_id(&self) -> &'static str {
        "MSC33-C"
    }

    fn description(&self) -> &'static str {
        "Do not pass invalid data to the asctime() function"
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "MSC33-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(node, source, &mut violations);
        violations
    }
}

impl Msc33C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(function) = n.child_by_field_name("function") {
                let func_name = ast_utils::get_node_text(&function, source);

                if func_name == "asctime" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: "Call to asctime() function without validation. \
                             The asctime() function can overflow if passed invalid data"
                            .to_string(),
                        file_path: String::new(),
                        line: n.start_position().row + 1,
                        column: n.start_position().column + 1,
                        suggestion: Some(
                            "Use strftime() instead, which is safer and provides better error handling"
                                .to_string(),
                        ),
                        ..Default::default()
                    });
                }
            }
        }
    }
}
