use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp32C;

impl CertRule for Exp32C {
    fn rule_id(&self) -> &'static str {
        "EXP32-C"
    }

    fn description(&self) -> &'static str {
        "Do not access a volatile object through a nonvolatile reference"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP32-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();

        // Check for assignment expressions that might violate volatile rules
        for assign_node in query::find_descendants_of_kind(*node, "assignment_expression") {
            self.check_volatile_assignment(&assign_node, source, &mut violations);
        }

        violations
    }
}

impl Exp32C {
    /// Check if an assignment violates volatile qualifier rules
    fn check_volatile_assignment(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) {
            let left_text = ast_utils::get_node_text(&left, source);
            let right_text = ast_utils::get_node_text(&right, source);

            // Check for pointer assignment where types mismatch in volatile qualifier
            // Pattern: volatile_ptr_to_ptr = &non_volatile_ptr
            // Example: ipp = &ip where ipp is volatile int ** and ip is int *

            // Check if left side looks like a pointer-to-pointer to volatile
            // and right side is taking address of a non-volatile pointer
            if right_text.starts_with('&')
                || right_text.starts_with("(int**)")
                || right_text.starts_with("(int **)")
            {
                // Try to find the declaration of the left side variable to check its type
                let left_var = left_text.trim();

                // Search backwards for declaration
                if let Some(func) = ast_utils::find_containing_function(&node) {
                    if let Some(body) = func.child_by_field_name("body") {
                        let left_is_volatile_ptr_ptr =
                            self.is_volatile_pointer_to_pointer(left_var, &body, source);

                        // Extract the variable being addressed on the right
                        let right_var = right_text
                            .trim_start_matches('&')
                            .trim_start_matches('(')
                            .trim();
                        let right_var = if let Some(idx) = right_var.find(')') {
                            right_var[..idx].trim()
                        } else {
                            right_var
                        };

                        // Check if the right side pointer is non-volatile
                        let right_is_nonvolatile_ptr =
                            self.is_non_volatile_pointer(right_var, &body, source);

                        if left_is_volatile_ptr_ptr && right_is_nonvolatile_ptr {
                            violations.push(RuleViolation {
                                rule_id: self.rule_id().to_string(),
                                severity: self.severity(),
                                message: format!(
                                    "Assignment of non-volatile pointer '{}' to volatile pointer-to-pointer '{}'. This may allow accessing volatile object through non-volatile reference.",
                                    right_var, left_var
                                ),
                                file_path: String::new(),
                                line: node.start_position().row + 1,
                                column: node.start_position().column + 1,
                                suggestion: Some(format!("Declare '{}' as volatile", right_var)),
                                ..Default::default()
                            });
                        }
                    }
                }
            }
        }
    }

    /// Check if a variable is declared as volatile pointer-to-pointer
    fn is_volatile_pointer_to_pointer(&self, var_name: &str, scope: &Node, source: &str) -> bool {
        self.find_declaration_type(var_name, scope, source)
            .map(|decl| decl.contains("volatile") && decl.matches("*").count() >= 2)
            .unwrap_or(false)
    }

    /// Check if a variable is declared as a non-volatile pointer
    fn is_non_volatile_pointer(&self, var_name: &str, scope: &Node, source: &str) -> bool {
        self.find_declaration_type(var_name, scope, source)
            .map(|decl| !decl.contains("volatile") && decl.contains('*'))
            .unwrap_or(false)
    }

    /// Find the declaration of a variable and return its type string
    fn find_declaration_type(&self, var_name: &str, scope: &Node, source: &str) -> Option<String> {
        // Walk through the scope looking for declarations
        for i in 0..scope.named_child_count() {
            if let Some(child) = scope.named_child(i) {
                if child.kind() == "declaration" {
                    let decl_text = ast_utils::get_node_text(&child, source);

                    // Check if this declaration contains the exact variable name
                    // Match patterns ending with the variable name followed by ; or = or space
                    // e.g., "*ip;" or "*ip " or "**ipp;" but not "*ip" within "**ipp"
                    let pattern_semi = format!("{};", var_name);
                    let pattern_space = format!("{} ", var_name);
                    let pattern_eq = format!("{} =", var_name);

                    if decl_text.contains(&pattern_semi)
                        || decl_text.contains(&pattern_space)
                        || decl_text.contains(&pattern_eq)
                    {
                        return Some(decl_text.to_string());
                    }
                }

                // Recursively search in nested scopes
                if child.kind() == "compound_statement" {
                    if let Some(result) = self.find_declaration_type(var_name, &child, source) {
                        return Some(result);
                    }
                }
            }
        }

        None
    }
}
