use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio32C;

impl CertRule for Fio32C {
    fn rule_id(&self) -> &'static str {
        "FIO32-C"
    }

    fn description(&self) -> &'static str {
        "Do not perform operations on devices that are only appropriate for files"
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

impl Fio32C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for file operations that are inappropriate for devices
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                // Check for operations like fseek, ftell on device files
                if func_name == "fseek" || func_name == "ftell" || func_name == "rewind" {
                    // Check if the file being operated on is a device file
                    if self.operates_on_device_file(&n, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: format!("{}() operation on device file; this operation is only appropriate for regular files", func_name),
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

    fn operates_on_device_file(&self, _node: &Node, source: &str) -> bool {
        // Simple heuristic: check for /dev/ paths without S_ISREG check
        source.contains("/dev/") && !source.contains("S_ISREG")
    }
}
