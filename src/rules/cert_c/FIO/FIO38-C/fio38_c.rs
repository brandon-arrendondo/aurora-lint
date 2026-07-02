use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio38C;

impl CertRule for Fio38C {
    fn rule_id(&self) -> &'static str {
        "FIO38-C"
    }

    fn description(&self) -> &'static str {
        "Do not copy a FILE object"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        self.rule_id()
    }

    fn check(&self, root: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        self.check_node(root, source, &mut violations);
        violations
    }
}

impl Fio38C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for memcpy/assignment of FILE objects
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                if func_name == "memcpy" || func_name == "memmove" {
                    // Check if copying a FILE object
                    if let Some(args) = n.child_by_field_name("arguments") {
                        let args_text = get_node_text(&args, source);
                        if args_text.contains("sizeof(FILE)") {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: "Copying FILE object using memcpy/memmove; FILE objects should not be copied".to_string(),
                                file_path: String::new(),
                                line: n.start_position().row + 1,
                                column: n.start_position().column + 1,
                                suggestion: None,
                                requires_manual_review: None,
                            });
                        }
                    }
                }
            }
        }
    }
}
