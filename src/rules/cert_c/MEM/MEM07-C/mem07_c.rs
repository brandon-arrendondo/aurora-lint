use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Mem07C;

impl CertRule for Mem07C {
    fn rule_id(&self) -> &'static str {
        "MEM07-C"
    }

    fn description(&self) -> &'static str {
        "Ensure that the arguments to calloc(), when multiplied, do not wrap"
    }

    fn severity(&self) -> Severity {
        Severity::High
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

impl Mem07C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "call_expression") {
            if let Some(func_node) = n.child_by_field_name("function") {
                let func_name = get_node_text(&func_node, source);

                if func_name == "calloc" {
                    // Check if there's overflow checking before this calloc
                    if !self.has_overflow_check_before(&n, source) {
                        violations.push(RuleViolation {
                            rule_id: self.rule_id().to_string(),
                            severity: self.severity(),
                            message: "calloc() arguments may wrap when multiplied; check for overflow before allocation".to_string(),
                            file_path: String::new(),
                            line: n.start_position().row + 1,
                            column: n.start_position().column + 1,
                            suggestion: Some(
                                "Add overflow check: if (num_elements > SIZE_MAX/element_size) { /* handle error */ }".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    fn has_overflow_check_before(&self, calloc_node: &Node, source: &str) -> bool {
        // Check the entire source for SIZE_MAX overflow checks before this calloc
        let calloc_start = calloc_node.start_byte();
        let before_calloc = &source[..calloc_start];

        // Look for SIZE_MAX division pattern before the calloc
        if before_calloc.contains("SIZE_MAX") && before_calloc.contains("/") {
            return true;
        }

        // Also check for UINT_MAX or ULONG_MAX patterns
        if (before_calloc.contains("UINT_MAX") || before_calloc.contains("ULONG_MAX"))
            && before_calloc.contains("/")
        {
            return true;
        }

        false
    }
}
