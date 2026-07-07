use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio15C;

impl CertRule for Fio15C {
    fn rule_id(&self) -> &'static str {
        "FIO15-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that file operations are performed in a secure directory"
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

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        self.check_node(root, source, violations);
    }
}

impl Fio15C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for fopen calls with paths in potentially insecure directories
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);
                if func_name == "fopen" {
                    if let Some(args) = n.child_by_field_name("arguments") {
                        if let Some(first_arg) = args.named_child(0) {
                            let path = get_node_text(&first_arg, source);
                            // Check for operations in /tmp or other world-writable directories
                            if path.contains("/tmp") && !self.has_security_check_before(&n, source)
                            {
                                violations.push(RuleViolation {
                                    rule_id: self.rule_id().to_string(),
                                    severity: self.severity(),
                                    message: format!(
                                        "File operation in potentially insecure directory {}",
                                        path
                                    ),
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

    fn has_security_check_before(&self, _node: &Node, source: &str) -> bool {
        // Simple heuristic: check if source contains security-related function calls
        source.contains("is_secure_directory") || source.contains("stat(")
    }
}
