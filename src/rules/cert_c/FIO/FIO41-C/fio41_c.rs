use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Fio41C;

impl CertRule for Fio41C {
    fn rule_id(&self) -> &'static str {
        "FIO41-C"
    }

    fn description(&self) -> &'static str {
        "Do not call getc(), putc(), getwc(), or putwc() with a stream argument that has side effects"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
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

impl Fio41C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                if func_name == "getc"
                    || func_name == "putc"
                    || func_name == "getwc"
                    || func_name == "putwc"
                {
                    // Check if the stream argument is a function call (has side effects)
                    if let Some(args) = n.child_by_field_name("arguments") {
                        // Look for stream argument
                        let mut cursor = args.walk();
                        for arg in args.named_children(&mut cursor) {
                            if arg.kind() == "call_expression" {
                                let arg_text = get_node_text(&arg, source);
                                if arg_text.contains("get_stream") || arg_text.contains("()") {
                                    violations.push(RuleViolation {
                                        rule_id: self.rule_id().to_string(),
                                        severity: self.severity(),
                                        message: format!("{}() called with stream argument that has side effects", func_name),
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
    }
}
