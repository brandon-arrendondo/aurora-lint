use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils::get_node_text;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Flp07C;

impl CertRule for Flp07C {
    fn rule_id(&self) -> &'static str {
        "FLP07-C"
    }

    fn description(&self) -> &'static str {
        "Cast the return value of floating-point functions to the expected type to avoid implicit conversion issues"
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

impl Flp07C {
    fn check_node(&self, node: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        for n in query::find_descendants(*node, |_| true) {
            // Look for assignments where RHS is a function call returning float
            // but LHS is a different floating-point type (like long double)
            if n.kind() == "assignment_expression" {
                if let Some(violation) = self.check_float_assignment_expr(&n, source) {
                    violations.push(violation);
                }
            } else if n.kind() == "init_declarator" {
                if let Some(violation) = self.check_float_init(&n, source) {
                    violations.push(violation);
                }
            }
        }
    }

    fn check_float_assignment_expr(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // For assignment_expression: var = expr
        if let Some(left) = node.child_by_field_name("left") {
            if let Some(right) = node.child_by_field_name("right") {
                let var_name = get_node_text(&left, source);

                // Check if right side is a function call (without cast)
                if let Some(call) = self.find_call_expression(&right) {
                    if !self.has_explicit_cast(&right, source) {
                        // Look for the variable declaration to determine its type
                        if self.is_long_double_variable(node, &var_name, source) {
                            let line = node.start_position().row + 1;
                            let column = node.start_position().column + 1;
                            let call_text = get_node_text(&call, source);

                            return Some(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Function call '{}' assigned to 'long double' variable '{}' without explicit cast",
                                    call_text, var_name
                                ),
                                file_path: String::new(),
                                line,
                                column,
                                suggestion: Some("Cast the function return value to the expected type".to_string()),
                                requires_manual_review: Some(true),
                            });
                        }
                    }
                }
            }
        }
        None
    }

    fn is_long_double_variable(&self, node: &Node, var_name: &str, source: &str) -> bool {
        // Walk up to find the function, then look for declaration
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.kind() == "function_definition" {
                // Found the function, now look for variable declaration
                if let Some(body) = parent.child_by_field_name("body") {
                    return self.find_long_double_decl(&body, var_name, source);
                }
                break;
            }
            current = parent.parent();
        }
        false
    }

    fn find_long_double_decl(&self, node: &Node, var_name: &str, source: &str) -> bool {
        query::find_first_descendant(*node, |n| {
            if n.kind() != "declaration" {
                return false;
            }
            let Some(type_node) = n.child_by_field_name("type") else {
                return false;
            };
            let type_text = get_node_text(&type_node, source);
            if !(type_text.contains("long") && type_text.contains("double")) {
                return false;
            }
            // Check if this declaration includes our variable
            get_node_text(&n, source).contains(var_name)
        })
        .is_some()
    }

    fn check_float_init(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // For init_declarator: type var = expr
        if node.kind() == "init_declarator" {
            if let Some(declarator) = node.child_by_field_name("declarator") {
                if let Some(value) = node.child_by_field_name("value") {
                    // Get the declared type
                    if let Some(parent) = node.parent() {
                        if parent.kind() == "declaration" {
                            if let Some(type_node) = parent.child_by_field_name("type") {
                                let declared_type = get_node_text(&type_node, source);

                                // Check if this is a long double assignment
                                if declared_type.contains("long")
                                    && declared_type.contains("double")
                                {
                                    // Check if value is a function call that returns float
                                    if let Some(call) = self.find_call_expression(&value) {
                                        if !self.has_explicit_cast(&value, source) {
                                            let line = node.start_position().row + 1;
                                            let column = node.start_position().column + 1;
                                            let var_name = get_node_text(&declarator, source);
                                            let call_text = get_node_text(&call, source);

                                            return Some(RuleViolation {
                                                rule_id: self.rule_id().to_string(),
                                                severity: self.severity(),
                                                message: format!(
                                                    "Function call '{}' assigned to 'long double' variable '{}' without explicit cast",
                                                    call_text, var_name
                                                ),
                                                file_path: String::new(),
                                                line,
                                                column,
                                                suggestion: Some("Cast the function return value to the expected type".to_string()),
                                                requires_manual_review: Some(true),
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

        None
    }

    fn find_call_expression<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        query::find_first_descendant(*node, |n| n.kind() == "call_expression")
    }

    fn has_explicit_cast(&self, node: &Node, source: &str) -> bool {
        // Check if there's a cast_expression wrapping the function call
        self.check_for_cast(node, source)
    }

    fn check_for_cast(&self, node: &Node, _source: &str) -> bool {
        if node.kind() == "cast_expression" {
            return true;
        }

        // Check parent for cast
        if let Some(parent) = node.parent() {
            if parent.kind() == "cast_expression" {
                return true;
            }
        }

        false
    }
}
