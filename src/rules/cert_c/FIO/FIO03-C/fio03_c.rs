use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio03C;

impl CertRule for Fio03C {
    fn rule_id(&self) -> &'static str {
        "FIO03-C"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &'static str {
        "Do not make assumptions about fopen() and file creation"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "FIO03-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        query::find_descendants_of_kind(*node, "call_expression")
            .into_iter()
            .flat_map(|call| self.check_fopen_call(call, source))
            .collect()
    }
}

impl Fio03C {
    fn check_fopen_call(&self, node: Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for fopen() calls with "w" or "w+" mode that may incorrectly assume file creation
        if let Some(function_node) = node.child_by_field_name("function") {
            let func_name = get_node_text(&function_node, source);

            if func_name == "fopen" {
                if let Some(args_node) = node.child_by_field_name("arguments") {
                    // Look for string literals in arguments that represent write mode without 'x'
                    for i in 0..args_node.child_count() {
                        if let Some(arg) = args_node.child(i) {
                            if arg.kind() == "string_literal" {
                                let mode_text = get_node_text(&arg, source);
                                let mode_value = mode_text.trim().trim_matches('"');

                                // Check for write modes without exclusive creation flag
                                let is_unsafe_write_mode = (mode_value == "w"
                                    || mode_value == "w+"
                                    || mode_value == "wb"
                                    || mode_value == "w+b"
                                    || mode_value == "wb+")
                                    && !mode_value.contains('x');

                                if is_unsafe_write_mode {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: self.severity(),
                                        message: format!(
                                            "fopen() with mode {} does not guarantee exclusive file creation. Use \"wx\" or \"w+x\" mode for exclusive creation.",
                                            mode_text
                                        ),
                                        file_path: String::new(),
                                        line: node.start_position().row + 1,
                                        column: node.start_position().column + 1,
                                        suggestion: Some("Use fopen() with \"wx\" or \"w+x\" mode for C11, or use open() with O_CREAT|O_EXCL for POSIX".to_string()),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        violations
    }
}
