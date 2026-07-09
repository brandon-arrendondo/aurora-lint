use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Sig34C;

impl CertRule for Sig34C {
    fn rule_id(&self) -> &'static str {
        "SIG34-C"
    }

    fn description(&self) -> &'static str {
        "Do not call signal() from within interruptible signal handlers"
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
        self.find_signal_handlers(root, source, violations);
    }
}

impl Sig34C {
    fn find_signal_handlers(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        // Look for function definitions matching the signal-handler signature:
        // exactly one parameter of type `int` (e.g. `void handler(int sig)`).
        for func in query::find_descendants_of_kind(*node, "function_definition") {
            if self.has_signal_handler_signature(&func, source) {
                if let Some(body) = func.child_by_field_name("body") {
                    self.check_for_signal_calls(&body, source, violations);
                }
            }
        }
    }

    fn has_signal_handler_signature(&self, func: &Node, source: &str) -> bool {
        let declarator = match func.child_by_field_name("declarator") {
            Some(d) => d,
            None => return false,
        };
        let params: Vec<Node> =
            query::find_descendants_of_kind(declarator, "parameter_declaration");
        if params.len() != 1 {
            return false;
        }
        match params[0].child_by_field_name("type") {
            Some(ty) => get_node_text(&ty, source).trim() == "int",
            None => false,
        }
    }

    fn check_for_signal_calls(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);
                if func_name == "signal" {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        message: "signal() called from within signal handler; this is not safe"
                            .to_string(),
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
