// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::analyze::context::VisibleTypes;
use crate::manifest::Severity;
use crate::utility::cert_c::expr_type::{self, TypeEnv};
use std::cell::RefCell;
use tree_sitter::Node;

#[derive(Default)]
pub struct Flp06C {
    /// The typedefs and struct fields this file sees, so a target declared
    /// `real` (a typedef of double) and an operand declared `u32` are typed by
    /// their declarations.
    visible: RefCell<VisibleTypes>,
}

impl CertRule for Flp06C {
    fn rule_id(&self) -> &'static str {
        "FLP06-C"
    }
    fn description(&self) -> &'static str {
        "TODO"
    }
    fn severity(&self) -> Severity {
        Severity::Medium
    }
    fn cert_id(&self) -> &'static str {
        "FLP06-C"
    }

    fn set_visible_types(&self, types: &VisibleTypes) {
        *self.visible.borrow_mut() = types.clone();
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let visible = self.visible.borrow();
        let env = TypeEnv::visible(&visible);
        let mut violations = Vec::new();
        for decl in lang_parsing_substrate::query::find_descendants_of_kind(*node, "declaration") {
            self.check_declaration(&decl, source, &env, &mut violations);
        }
        violations
    }
}

impl Flp06C {
    /// `double d = a * b;` with integer `a` and `b`: the arithmetic happens in
    /// an integer type and only the result is converted.
    ///
    /// The target is the declaration's first `init_declarator`, typed by its
    /// own declarator: a floating object, not a pointer to one, and not an int
    /// whose name happens to contain `float`. The initializer must be a
    /// top-level `+ - * /` whose type is an integer type: both operands typed
    /// integer by their declarations (expr_type), so a float-returning call,
    /// a float operand, `->` in an argument, index arithmetic inside a
    /// subscript read, a unary minus on a literal and a brace initializer are
    /// not integer arithmetic implicitly converted to float.
    ///
    /// On unknown (None), for the target or either operand, no finding: this
    /// check accuses, and an unknown type must not raise one.
    fn check_declaration(
        &self,
        decl: &Node,
        source: &str,
        env: &TypeEnv,
        violations: &mut Vec<RuleViolation>,
    ) {
        let Some(init) = first_init_declarator(decl) else {
            return;
        };
        let target_is_float =
            expr_type::declarator_type(decl, &init, source, env).is_some_and(|t| t.is_float());
        if !target_is_float {
            return;
        }
        let is_integer_arith = init
            .child_by_field_name("value")
            .is_some_and(|v| is_integer_arithmetic(&v, source, env));
        if is_integer_arith {
            violations.push(RuleViolation {
                rule_id: self.rule_id().to_string(),
                severity: self.severity(),
                line: decl.start_position().row + 1,
                column: decl.start_position().column + 1,
                file_path: String::new(),
                message: "Floating point variable initialized with integer arithmetic; use floating-point literals or explicit conversion".to_string(),
                suggestion: Some("Use floating-point literals (e.g., 7.0) or explicit casts (e.g., (double)x)".to_string()),
                requires_manual_review: None,
            });
        }
    }
}

fn first_init_declarator<'a>(decl: &Node<'a>) -> Option<Node<'a>> {
    let mut cursor = decl.walk();
    let found = decl
        .children(&mut cursor)
        .find(|c| c.kind() == "init_declarator");
    found
}

fn is_integer_arithmetic(node: &Node, source: &str, env: &TypeEnv) -> bool {
    let inner = unwrap_parens(node);
    if inner.kind() != "binary_expression" {
        return false;
    }
    let is_arith_op = inner
        .child_by_field_name("operator")
        .map(|op| {
            matches!(
                &source[op.start_byte()..op.end_byte()],
                "+" | "-" | "*" | "/"
            )
        })
        .unwrap_or(false);
    if !is_arith_op {
        return false;
    }
    expr_type::expr_type(&inner, source, env).is_some_and(|t| t.is_integer())
}

fn unwrap_parens<'a>(node: &Node<'a>) -> Node<'a> {
    let mut n = *node;
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => break,
        }
    }
    n
}
