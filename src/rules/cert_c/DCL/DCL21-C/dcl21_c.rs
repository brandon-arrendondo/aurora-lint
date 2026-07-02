use crate::manifest::{RuleCategory, Severity};
use crate::prelude::RuleViolation;
use crate::rules::cert_c::CertRule;
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct DCL21C;

impl CertRule for DCL21C {
    fn rule_id(&self) -> &'static str {
        "DCL21-C"
    }

    fn cert_id(&self) -> &'static str {
        "DCL21"
    }

    fn description(&self) -> &'static str {
        "Understand the storage of compound literals"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Recursively check all nodes
        self.check_node(node, source, &mut violations);

        violations
    }
}

impl DCL21C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants_of_kind(*node, "pointer_expression") {
            // Look for & operator (pointer_expression with &)
            let text = get_node_text(&n, source);
            if text.starts_with('&') {
                // Check if the operand is a cast or type initialization (compound literal pattern)
                let mut cursor = n.walk();
                for child in n.children(&mut cursor) {
                    if child.kind() == "cast_expression"
                        || child.kind() == "compound_literal_expression"
                    {
                        // Check if inside a loop
                        if self.is_inside_loop(&n) {
                            let start = n.start_position();
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                file_path: String::new(),
                                message: "Address of compound literal taken inside a loop. Compound literals have automatic storage duration that ends at the end of the enclosing block, potentially creating dangling pointers.".to_string(),
                                line: start.row + 1,
                                column: start.column + 1,
                                severity: self.severity(),
                                suggestion: Some("Avoid taking the address of compound literals. Use a regular variable or array instead.".to_string()),
                                requires_manual_review: Some(false),
                            });
                        }
                    }
                }
            }
        }
    }
    fn is_inside_loop(&self, node: &Node) -> bool {
        let mut current = node.parent();
        while let Some(parent) = current {
            match parent.kind() {
                "for_statement" | "while_statement" | "do_statement" => return true,
                _ => current = parent.parent(),
            }
        }
        false
    }
}
