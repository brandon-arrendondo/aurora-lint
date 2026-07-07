use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use tree_sitter::Node;

pub struct Fio51C;

impl CertRule for Fio51C {
    fn rule_id(&self) -> &'static str {
        "FIO51-C"
    }

    fn description(&self) -> &'static str {
        "Close files when they are no longer needed"
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

impl Fio51C {
    fn check_node<'a>(&self, node: &Node<'a>, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for fopen calls without corresponding fclose
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                let func_name = &source[func.start_byte()..func.end_byte()];

                if func_name == "fopen" {
                    // Get the function containing this fopen
                    if let Some(containing_func) = self.get_containing_function(node) {
                        // Check if there's a corresponding fclose
                        if !self.has_fclose_in_function(&containing_func, source) {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: "File opened with fopen() but not closed with fclose()"
                                    .to_string(),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(
                                    "Call fclose() before function returns".to_string(),
                                ),
                                requires_manual_review: Some(true),
                            });
                        }
                    }
                }
            }
        }

        // Recursively check child nodes
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, violations);
        }
    }

    fn get_containing_function<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = *node;
        while let Some(parent) = current.parent() {
            if parent.kind() == "function_definition" {
                return Some(parent);
            }
            current = parent;
        }
        None
    }

    fn has_fclose_in_function(&self, func_node: &Node, source: &str) -> bool {
        let text = &source[func_node.start_byte()..func_node.end_byte()];
        text.contains("fclose")
    }
}
