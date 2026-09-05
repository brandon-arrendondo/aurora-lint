// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

use super::super::{CertRule, RuleViolation};
use crate::manifest::{RuleCategory, Severity};
use crate::utility::cert_c::float_typing;
use std::collections::HashMap;
use tree_sitter::Node;

pub struct Flp06C;

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
    fn category(&self) -> RuleCategory {
        RuleCategory::Rule
    }
    fn cert_id(&self) -> &'static str {
        "FLP06-C"
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        let mut violations = Vec::new();
        let type_map = HashMap::new();
        self.check_node(node, source, &type_map, &mut violations);
        violations
    }
}

impl Flp06C {
    fn check_node(
        &self,
        node: &Node,
        source: &str,
        type_map: &HashMap<String, String>,
        violations: &mut Vec<RuleViolation>,
    ) {
        // Build a fresh param/local type map at each function boundary so
        // operand types can be resolved (see the float-operand suppression
        // below). Outside any function the map is empty.
        if node.kind() == "function_definition" {
            let fn_type_map = float_typing::collect_variable_types(node, source);
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                self.check_node(&child, source, &fn_type_map, violations);
            }
            return;
        }

        // Look for declarations: float/double var = expression;
        if node.kind() == "declaration" {
            let decl_text = node.utf8_text(source.as_bytes()).unwrap_or("");

            // Must be a float or double declaration with an initializer.
            if (decl_text.contains("float") || decl_text.contains("double"))
                && decl_text.contains(" = ")
            {
                // Fire only when the initializer's value is genuine integer
                // arithmetic: a top-level `+ - * /` binary expression whose
                // operands are all provably integer. Driving off the AST
                // (rather than the old text `contains('+-*/')`) excludes the
                // residual FP sub-classes that scan picked up — the `->` arrow
                // in call arguments, integer index arithmetic inside a subscript
                // *read*, unary minus on a literal, and brace initializers — and
                // float-returning calls or float operands (task 230/237), none
                // of which are integer arithmetic implicitly converted to float.
                let is_integer_arith = initializer_value_node(node)
                    .map(|v| is_integer_arithmetic(&v, source, type_map))
                    .unwrap_or(false);

                if is_integer_arith {
                    violations.push(RuleViolation {
                        rule_id: self.rule_id().to_string(),
                        severity: self.severity(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                        file_path: String::new(),
                        message: "Floating point variable initialized with integer arithmetic; use floating-point literals or explicit conversion".to_string(),
                        suggestion: Some("Use floating-point literals (e.g., 7.0) or explicit casts (e.g., (double)x)".to_string()),
                        requires_manual_review: None,
                    });
                }
            }
        }

        // Recursively check children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.check_node(&child, source, type_map, violations);
        }
    }
}

/// Return the initializer expression (`value`) of the first `init_declarator`
/// in a `declaration` node, if present.
fn initializer_value_node<'a>(decl: &Node<'a>) -> Option<Node<'a>> {
    let mut cursor = decl.walk();
    for child in decl.children(&mut cursor) {
        if child.kind() == "init_declarator" {
            return child.child_by_field_name("value");
        }
    }
    None
}

/// True if `node` (after unwrapping parentheses) is *integer* arithmetic: a
/// `+ - * /` binary expression all of whose operands are provably integer.
///
/// Requiring provably-integer operands (rather than merely "no float operand")
/// keeps the rule conservative: a float-typed operand, a float-returning call
/// (`sinf`/`cosf`), an unresolved identifier, or a struct-field access all make
/// the expression not-provably-integer, so it is not reported. This is the
/// integer-then-implicitly-converted-to-float pattern FLP06-C targets.
fn is_integer_arithmetic(node: &Node, source: &str, type_map: &HashMap<String, String>) -> bool {
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
    float_typing::expr_is_definitely_integer(&inner, source, type_map)
}

/// Peel away `( … )` wrappers to reach the underlying expression.
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
