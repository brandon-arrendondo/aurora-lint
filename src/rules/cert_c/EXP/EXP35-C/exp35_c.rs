// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::VisibleTypes;
use crate::manifest::Severity;
use crate::settings::{AnalysisSettings, IntFacts};
use crate::utility::cert_c::ast_utils;
use crate::utility::cert_c::expr_type::{self, CType, TypeEnv};
use lang_parsing_substrate::query;
use std::cell::{Cell, RefCell};
use tree_sitter::Node;

#[derive(Default)]
pub struct Exp35C {
    /// The struct fields this file sees, so a member of a call's result is
    /// typed by its declaration: only an array member is one whose address
    /// outlives the temporary.
    visible: RefCell<VisibleTypes>,
    /// The integer data model the settings credit, for typing.
    data_model: Cell<IntFacts>,
}

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

    fn cert_id(&self) -> &'static str {
        "EXP35-C"
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn set_analysis_settings(&self, settings: &std::sync::Arc<AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // Compute once — avoids O(N × source_len) if done inside the recursion.
        let has_c11_guard = source.contains("__STDC_VERSION__") && source.contains("201112L");
        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible, self.data_model.get()).in_tree(*node);
        let mut violations = Vec::new();
        self.check_node(node, source, &env, has_c11_guard, &mut violations);
        violations
    }
}

impl Exp35C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        env: &TypeEnv,
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
                    self.check_unary_expression(&n, source, env, violations);
                }
                "init_declarator" | "assignment_expression" => {
                    self.check_pointer_assignment(&n, source, env, violations);
                }
                "call_expression" if !has_c11_guard => {
                    self.check_c99_temporary_access(&n, source, env, violations);
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
        env: &TypeEnv,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Look for function calls (like printf) that have arguments accessing temporary arrays
        if let Some(arguments) = node.child_by_field_name("arguments") {
            // Check each argument
            for i in 0..arguments.child_count() {
                if let Some(arg) = arguments.child(i) {
                    if self.contains_temporary_array_access(&arg, source, env) {
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
        env: &TypeEnv,
        violations: &mut Vec<RuleViolation>,
    ) {
        if let Some(operator) = node.child(0) {
            let op_text = ast_utils::get_node_text(&operator, source);

            // Check for modification operators (++, --) or address-of (&)
            if matches!(op_text, "++" | "--" | "&") {
                if let Some(argument) = node.child_by_field_name("argument") {
                    // Check if modifying/taking address of a temporary's array member
                    // Use contains_temporary_array_access to check deeply nested patterns
                    if self.contains_temporary_array_access(&argument, source, env) {
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
        env: &TypeEnv,
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
            if self.is_temporary_array_access(&value, source, env) {
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

    /// `f().a` with `a` an array member of the struct `f` returns: the one
    /// member of a temporary whose address, by decay, outlives it. The
    /// member is typed by its declaration (ADR-0006); a scalar member, an
    /// element `f().a[i]` (a value), and a member whose type is not in reach
    /// are not reported.
    fn is_temporary_array_access(&self, node: &Node, source: &str, env: &TypeEnv) -> bool {
        node.kind() == "field_expression"
            && node
                .child_by_field_name("argument")
                .is_some_and(|argument| argument.kind() == "call_expression")
            && !self.uses_arrow_operator(node, source)
            && matches!(
                expr_type::expr_type(node, source, env),
                Some(CType::Array(_))
            )
    }

    /// Whether `node` or anything under it is such a member access. An
    /// element of the member that is only read, `use(f().a[i])`, is a copy
    /// taken before the call and keeps no pointer into the temporary; one
    /// that is modified or whose address is taken does.
    fn contains_temporary_array_access(&self, node: &Node, source: &str, env: &TypeEnv) -> bool {
        query::find_first_descendant(*node, |n| {
            self.is_temporary_array_access(&n, source, env) && !is_element_read(&n, source)
        })
        .is_some()
    }
}

/// Whether the member `field` is subscripted, `f().a[i]`, and the element is
/// only read: not the operand of `++`/`--` or `&`, and not assigned to.
fn is_element_read(field: &Node, source: &str) -> bool {
    let Some(subscript) = field
        .parent()
        .filter(|p| p.kind() == "subscript_expression")
        .filter(|p| {
            p.child_by_field_name("argument")
                .is_some_and(|a| a.id() == field.id())
        })
    else {
        return false;
    };
    let mut operand = subscript;
    let mut user = subscript.parent();
    while let Some(p) = user.filter(|p| p.kind() == "parenthesized_expression") {
        operand = p;
        user = p.parent();
    }
    let Some(user) = user else {
        return true;
    };
    match user.kind() {
        "update_expression" => false,
        "pointer_expression" => user
            .child_by_field_name("operator")
            .is_none_or(|op| ast_utils::get_node_text(&op, source) != "&"),
        "assignment_expression" => user
            .child_by_field_name("left")
            .is_none_or(|left| left.id() != operand.id()),
        _ => true,
    }
}
