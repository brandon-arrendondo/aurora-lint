use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use tree_sitter::Node;

pub struct Exp35C;

impl CertRule for Exp35C {
    fn rule_id(&self) -> &'static str {
        "EXP35-C"
    }

    fn description(&self) -> &'static str {
        "Do not modify objects with temporary lifetime"
    }

    fn severity(&self) -> Severity {
        Severity::Low
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }

    fn cert_id(&self) -> &'static str {
        "EXP35-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // Compute once — avoids O(N × source_len) if done inside the recursion.
        let has_c11_guard = source.contains("__STDC_VERSION__") && source.contains("201112L");
        let mut violations = Vec::new();
        self.check_node(node, source, has_c11_guard, &mut violations);
        violations
    }
}

impl Exp35C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        has_c11_guard: bool,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in query::find_descendants_of_kinds(
            *node,
            &[
                "unary_expression",
                "init_declarator",
                "assignment_expression",
                "call_expression",
            ],
        ) {
            match n.kind() {
                "unary_expression" => {
                    self.check_unary_expression(&n, source, violations);
                }
                "init_declarator" | "assignment_expression" => {
                    self.check_pointer_assignment(&n, source, violations);
                }
                "call_expression" if !has_c11_guard => {
                    self.check_c99_temporary_access(&n, source, violations);
                }
                _ => {}
            }
        }
    }
}

impl Exp35C {
    /// Check for C99-specific violations: accessing array members from temporaries
    /// In C99, accessing arrays from temporaries across sequence points is undefined
    /// In C11+, this is allowed (temporary lifetime extends to end of full expression)
    fn check_c99_temporary_access(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for function calls (like printf) that have arguments accessing temporary arrays
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // Check each argument
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if self.contains_temporary_array_access(&arg, source) {
                        let start_point = arg.start_position();
                        violations.push(RuleViolation {
                            rule_id: "EXP35-C".to_string(),
                            severity: Severity::Low,
                            message: "Accessing array member of temporary object (C99 violation)".to_string(),
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Store the returned struct/union in a local variable before accessing array members, or use C11+ where this is allowed".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check for unary operations on temporary array members
    /// Pattern: ++function_call().array[0] or &function_call().array
    fn check_unary_expression(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = node.child(0) {
            let op_text = ast_utils::get_node_text(&operator, source);

            // Check for modification operators (++, --) or address-of (&)
            if matches!(op_text, "++" | "--" | "&") {
                if let Some(argument) = node.child_by_field_name("argument") {
                    // Check if modifying/taking address of a temporary's array member
                    // Use contains_temporary_array_access to check deeply nested patterns
                    if self.contains_temporary_array_access(&argument, source) {
                        let start_point = node.start_position();
                        let message = if op_text == "&" {
                            "Taking address of array member from temporary object".to_string()
                        } else {
                            format!(
                                "Modifying array element of temporary object with '{}' operator",
                                op_text
                            )
                        };

                        violations.push(RuleViolation {
                            rule_id: "EXP35-C".to_string(),
                            severity: Severity::Low,
                            message,
                            file_path: String::new(),
                            line: start_point.row + 1,
                            column: start_point.column + 1,
                            suggestion: Some(
                                "Store the returned struct/union in a local variable before modifying array members".to_string()
                            ),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    /// Check for pointer assignments to temporary array members
    /// Pattern: int *ptr = function_call().array;
    fn check_pointer_assignment(
        &self,
        node: &Node,
        source: &str,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Get the right-hand side value
        let value_node = if node.kind() == "init_declarator" {
            node.child_by_field_name("value")
        } else if node.kind() == "assignment_expression" {
            node.child_by_field_name("right")
        } else {
            None
        };

        if let Some(value) = value_node {
            // Check if assigning a temporary's array member to a pointer
            if self.is_temporary_array_access(&value, source) {
                let start_point = value.start_position();
                violations.push(RuleViolation {
                    rule_id: "EXP35-C".to_string(),
                    severity: Severity::Low,
                    message: "Assigning pointer to array member of temporary object".to_string(),
                    file_path: String::new(),
                    line: start_point.row + 1,
                    column: start_point.column + 1,
                    suggestion: Some(
                        "Store the returned struct/union in a local variable before taking pointers to array members".to_string()
                    ),
                    ..Default::default()
                });
            }
        }
    }

    /// Check if a field_expression uses arrow (->) vs dot (.) operator.
    /// Arrow means the function returned a pointer to a persistent object,
    /// not a temporary struct value.
    fn uses_arrow_operator(&self, field_expr: &Node, source: &str) -> bool {
        for i in 0..field_expr.child_count() {
            if let Some(child) = field_expr.child(i) {
                let text = ast_utils::get_node_text(&child, source);
                if text == "->" {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a node represents accessing an array member from a temporary
    fn is_temporary_array_access(&self, node: &Node, source: &str) -> bool {
        match node.kind() {
            "field_expression" => {
                // Check if the argument is a call expression
                // Pattern: func().array — temporary struct member access
                // Skip: func()->field — function returns pointer, not temporary
                if let Some(argument) = node.child_by_field_name("argument") {
                    if argument.kind() == "call_expression" {
                        return !self.uses_arrow_operator(node, source);
                    }
                }
            }
            "subscript_expression" => {
                // Check if subscripting a field from a call expression
                // Pattern: func().array[index]
                if let Some(array) = node.child(0) {
                    if array.kind() == "field_expression" {
                        if let Some(argument) = array.child_by_field_name("argument") {
                            if argument.kind() == "call_expression" {
                                return !self.uses_arrow_operator(&array, source);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        false
    }

    /// Check if a node or its ancestors represent accessing an array member from a temporary
    fn contains_temporary_array_access(&self, node: &Node, _source: &str) -> bool {
        query::find_first_descendant(*node, |n| self.is_temporary_array_access(&n, _source))
            .is_some()
    }
}
