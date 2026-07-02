use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp19C;

impl CertRule for Exp19C {
    fn rule_id(&self) -> &'static str {
        "EXP19-C"
    }

    fn description(&self) -> &'static str {
        "Use braces for the body of an if, for, or while statement"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Recommendation
    }

    fn cert_id(&self) -> &'static str {
        "EXP19-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Recursively check for control flow statements without braces
        violations.extend(self.check_node(*node, source));

        violations
    }
}

impl Exp19C {
    /// Recursively check nodes for control flow statements without compound statement bodies
    fn check_node(&self, node: Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        for n in query::find_descendants(node, |_| true) {
            // Check if this is a control flow statement that needs braces
            match n.kind() {
                "if_statement" => {
                    if let Some(violation) = self.check_if_statement(n, source) {
                        violations.push(violation);
                    }
                }
                "for_statement" => {
                    if let Some(violation) = self.check_for_statement(n, source) {
                        violations.push(violation);
                    }
                }
                "while_statement" => {
                    if let Some(violation) = self.check_while_statement(n, source) {
                        violations.push(violation);
                    }
                }
                "do_statement" => {
                    if let Some(violation) = self.check_do_statement(n, source) {
                        violations.push(violation);
                    }
                }
                _ => {}
            }
        }

        violations
    }

    /// Check if an if_statement has braces around its body
    fn check_if_statement(&self, if_node: Node, _source: &str) -> Option<RuleViolation> {
        // Get the consequence (then-branch) of the if statement
        if let Some(consequence) = if_node.child_by_field_name("consequence") {
            // If the consequence is not a compound_statement (braced block), it's a violation
            if consequence.kind() != "compound_statement" {
                return Some(self.create_violation(
                    if_node,
                    "if",
                    "if statement body should be enclosed in braces {}",
                ));
            }
        }

        // Check the else-branch if it exists
        if let Some(alternative) = if_node.child_by_field_name("alternative") {
            // Skip checking if the alternative is another if_statement (else if)
            // We'll check that if_statement separately in recursion
            if alternative.kind() == "if_statement" {
                return None; // else-if chain, will be checked recursively
            }

            // The alternative can be wrapped in an else_clause node in tree-sitter-c
            // We need to check the actual body inside it
            let body_to_check = if alternative.kind() == "else_clause" {
                // Find the actual statement inside the else_clause
                let mut body = None;
                let mut cursor = alternative.walk();
                for child in alternative.children(&mut cursor) {
                    // Skip the "else" keyword, look for the actual statement
                    if child.kind() != "else" {
                        body = Some(child);
                        break;
                    }
                }
                body
            } else {
                Some(alternative)
            };

            if let Some(body) = body_to_check {
                // Skip if it's an if_statement (else if case inside else_clause)
                if body.kind() == "if_statement" {
                    return None;
                }
                // Check if the body is a compound_statement (braced block)
                if body.kind() != "compound_statement" {
                    return Some(self.create_violation(
                        if_node,
                        "else",
                        "else statement body should be enclosed in braces {}",
                    ));
                }
            }
        }

        None
    }

    /// Check if a for_statement has braces around its body
    fn check_for_statement(&self, for_node: Node, _source: &str) -> Option<RuleViolation> {
        if let Some(body) = for_node.child_by_field_name("body") {
            if body.kind() != "compound_statement" {
                return Some(self.create_violation(
                    for_node,
                    "for",
                    "for statement body should be enclosed in braces {}",
                ));
            }
        }

        None
    }

    /// Check if a while_statement has braces around its body
    fn check_while_statement(&self, while_node: Node, _source: &str) -> Option<RuleViolation> {
        if let Some(body) = while_node.child_by_field_name("body") {
            if body.kind() != "compound_statement" {
                return Some(self.create_violation(
                    while_node,
                    "while",
                    "while statement body should be enclosed in braces {}",
                ));
            }
        }

        None
    }

    /// Check if a do_statement has braces around its body
    fn check_do_statement(&self, do_node: Node, _source: &str) -> Option<RuleViolation> {
        if let Some(body) = do_node.child_by_field_name("body") {
            if body.kind() != "compound_statement" {
                return Some(self.create_violation(
                    do_node,
                    "do-while",
                    "do-while statement body should be enclosed in braces {}",
                ));
            }
        }

        None
    }

    /// Create a rule violation for a control flow statement without braces
    fn create_violation(
        &self,
        statement_node: Node,
        statement_type: &str,
        message: &str,
    ) -> RuleViolation {
        let suggestion = format!(
            "Add braces around the {} statement body: {} {{ /* body */ }}",
            statement_type, statement_type
        );

        RuleViolation {
            rule_id: self.rule_id().to_string(),
            severity: self.severity(),
            message: message.to_string(),
            file_path: String::new(),
            line: statement_node.start_position().row + 1,
            column: statement_node.start_position().column + 1,
            suggestion: Some(suggestion),
            ..Default::default()
        }
    }
}
