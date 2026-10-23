// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::VisibleTypes;
use crate::analyze::side_effects::designates_object;
use crate::manifest::Severity;
use crate::settings::{AnalysisSettings, IntFacts};
use crate::utility::cert_c::ast_utils::{self, get_node_text};
use crate::utility::cert_c::expr_type::{self, CType, FloatKind, TypeEnv};
use lang_parsing_substrate::query;
use std::cell::{Cell, RefCell};
use tree_sitter::Node;

#[derive(Default)]
pub struct Flp07C {
    /// The typedefs and struct fields this file sees, so the target and the
    /// callee's return are typed by their declarations.
    visible: RefCell<VisibleTypes>,
    /// The integer data model the settings credit, for typing.
    data_model: Cell<IntFacts>,
}

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

    fn cert_id(&self) -> &'static str {
        self.rule_id()
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn set_analysis_settings(&self, settings: &std::sync::Arc<AnalysisSettings>) {
        self.data_model.set(settings.facts);
    }

    fn scan(&self, root: &Node, source: &str, violations: &mut Vec<RuleViolation>) {
        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible, self.data_model.get()).in_tree(*root);
        self.check_node(root, source, &env, violations);
    }
}

impl Flp07C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        env: &TypeEnv,
        violations: &mut Vec<RuleViolation>,
    ) {
        for n in
            query::find_descendants_of_kinds(*node, &["assignment_expression", "init_declarator"])
        {
            // A `long double` target, typed by the declaration its name
            // resolves to (ADR-0006), and the value it is given.
            let (target, value) = if n.kind() == "assignment_expression" {
                let (Some(left), Some(right)) = (
                    n.child_by_field_name("left"),
                    n.child_by_field_name("right"),
                ) else {
                    continue;
                };
                let long_double = expr_type::expr_type(&left, source, env)
                    == Some(CType::Float(FloatKind::LongDouble));
                (long_double.then(|| get_node_text(&left, source)), right)
            } else {
                let (Some(decl), Some(declarator), Some(value)) = (
                    n.parent().filter(|p| p.kind() == "declaration"),
                    n.child_by_field_name("declarator"),
                    n.child_by_field_name("value"),
                ) else {
                    continue;
                };
                let long_double = expr_type::declarator_type(&decl, &n, source, env)
                    == Some(CType::Float(FloatKind::LongDouble));
                (
                    long_double.then(|| get_node_text(&declarator, source)),
                    value,
                )
            };
            let Some(var_name) = target else {
                continue;
            };
            if value.kind() == "cast_expression" {
                continue;
            }
            if let Some(call) = self.floating_call(&value, node, source, env) {
                let call_text = get_node_text(&call, source);
                violations.push(RuleViolation {
                    rule_id: self.rule_id().to_string(),
                    severity: self.severity(),
                    message: format!(
                        "Function call '{}' assigned to 'long double' variable '{}' without explicit cast",
                        call_text, var_name
                    ),
                    file_path: String::new(),
                    line: n.start_position().row + 1,
                    column: n.start_position().column + 1,
                    suggestion: Some("Cast the function return value to the expected type".to_string()),
                    requires_manual_review: Some(true),
                });
            }
        }
    }

    /// A call in `value` whose result is the value's own, not an argument of
    /// another call, and whose callee is declared to return a floating type
    /// other than `long double`, which reaches the target with no conversion.
    /// A callee this file defines with a cast on every return already gives
    /// the type it names, as CERT's compliant solution within the function
    /// does. A callee whose return type is not in reach is not reported.
    fn floating_call<'a>(
        &self,
        value: &Node<'a>,
        root: &Node,
        source: &str,
        env: &TypeEnv,
    ) -> Option<Node<'a>> {
        let mut pending = vec![*value];
        while let Some(n) = pending.pop() {
            if n.kind() == "call_expression" {
                if expr_type::expr_type(&n, source, env)
                    .is_some_and(|t| t.is_float() && t != CType::Float(FloatKind::LongDouble))
                    && !self.every_return_cast(&n, root, source)
                {
                    return Some(n);
                }
                continue;
            }
            for i in (0..n.named_child_count()).rev() {
                if let Some(child) = n.named_child(i) {
                    pending.push(child);
                }
            }
        }
        None
    }

    /// Whether `call` names a function this file defines, and every
    /// definition of it returns only cast expressions.
    fn every_return_cast(&self, call: &Node, root: &Node, source: &str) -> bool {
        let Some(callee) = call
            .child_by_field_name("function")
            .filter(|c| c.kind() == "identifier")
        else {
            return false;
        };
        if designates_object(&callee, source) {
            return false;
        }
        let name = get_node_text(&callee, source);
        let definitions: Vec<Node> = query::find_descendants_of_kind(*root, "function_definition")
            .into_iter()
            .filter(|f| {
                f.child_by_field_name("declarator")
                    .is_some_and(|d| ast_utils::get_identifier_from_declarator(&d, source) == name)
            })
            .collect();
        !definitions.is_empty()
            && definitions.iter().all(|f| {
                let returns = query::find_descendants_of_kind(*f, "return_statement");
                !returns.is_empty()
                    && returns.iter().all(|r| {
                        r.named_child(0)
                            .is_some_and(|e| e.kind() == "cast_expression")
                    })
            })
    }
}
