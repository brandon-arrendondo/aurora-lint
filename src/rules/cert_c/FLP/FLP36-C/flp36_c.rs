// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025-2026 BISSELL Homecare, Inc.

//! FLP36-C: Preserve precision when converting integral values to floating-point type
//!
//! This rule detects conversions from integer types to floating-point types that may
//! lose precision because the floating-point type cannot represent all integer values.
//!
//! VIOLATIONS:
//! - float approx = long_value;      // long to float may lose precision
//! - float f = int64_value;          // int64_t to float may lose precision
//!
//! COMPLIANT:
//! - double approx = long_value;     // double has sufficient precision
//! - With precision assertion checking before conversion

use super::super::{CertRule, RuleViolation};
use crate::analyze::const_eval;
use crate::manifest::Severity;
use crate::settings::AnalysisSettings;
use crate::utility::cert_c::ast_utils;
use lang_parsing_substrate::query;
use std::cell::RefCell;
use std::sync::Arc;
use tree_sitter::Node;

#[derive(Default)]
pub struct Flp36C {
    /// The run's policy and environment settings: whether an
    /// NDEBUG-strippable assert counts as a precision check
    /// (`assert_is_guard`).
    settings: RefCell<Arc<AnalysisSettings>>,
}

impl CertRule for Flp36C {
    fn rule_id(&self) -> &'static str {
        "FLP36-C"
    }

    fn description(&self) -> &'static str {
        "Preserve precision when converting integral values to floating-point type"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn cert_id(&self) -> &'static str {
        "FLP36-C"
    }

    fn set_analysis_settings(&self, settings: &Arc<AnalysisSettings>) {
        *self.settings.borrow_mut() = Arc::clone(settings);
    }

    fn check(&self, node: &Node, source: &str) -> Vec<RuleViolation> {
        // Check for assignments/declarations that might lose precision
        query::find_descendants_of_kinds(*node, &["assignment_expression", "init_declarator"])
            .into_iter()
            .filter_map(|n| self.check_int_to_float_conversion(&n, source))
            .collect()
    }
}

impl Flp36C {
    /// Check if an assignment/declaration converts int to float without precision check
    fn check_int_to_float_conversion(&self, node: &Node, source: &str) -> Option<RuleViolation> {
        // Check if there's precision checking in the function
        if self.has_precision_checking(node, source) {
            return None;
        }

        // Check if this is actually a long -> float conversion
        if !self.is_long_to_float_conversion(node, source) {
            return None;
        }

        // If no precision checking, report as potential violation
        let start_point = node.start_position();

        Some(RuleViolation {
            rule_id: "FLP36-C".to_string(),
            severity: Severity::Medium,
            message: "Potential precision loss in integer to floating-point conversion".to_string(),
            file_path: String::new(),
            line: start_point.row + 1,
            column: start_point.column + 1,
            suggestion: Some(
                "Ensure target floating-point type has sufficient precision (use assert with PRECISION macro or use double instead of float)".to_string()
            ),
            requires_manual_review: None,
        })
    }

    /// Check if this is a long -> float conversion
    fn is_long_to_float_conversion(&self, node: &Node, source: &str) -> bool {
        // Get the declaration context
        if node.kind() == "init_declarator" {
            if let Some(parent) = node.parent() {
                let decl_text = ast_utils::get_node_text(&parent, source);
                // Check if target is float (not double)
                if decl_text.contains("float") && !decl_text.contains("double") {
                    // Check if source is a long variable
                    if let Some(value) = node.child_by_field_name("value") {
                        let value_text = ast_utils::get_node_text(&value, source);
                        // Look for the long variable in scope
                        if self.is_long_variable(node, &value_text, source) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if a variable name refers to a long type variable
    fn is_long_variable(&self, node: &Node, var_name: &str, source: &str) -> bool {
        let var_name = var_name.trim();
        // Sanitized (comments/string/char literals blanked) so a comment or
        // string literal mentioning "long" and the variable name elsewhere
        // in the file can't spoof a false "is long" match — this only
        // affects whether the violation is TRIGGERED, but a spurious trigger
        // is still an incorrect finding worth preventing.
        let mut root = *node;
        while let Some(p) = root.parent() {
            root = p;
        }
        let sanitized_source = ast_utils::get_sanitized_node_text(&root, source);
        // Search source for declaration of this variable as long
        for line in sanitized_source.lines() {
            if (line.contains("long int") || (line.contains("long") && !line.contains("double")))
                && line.contains(var_name)
            {
                return true;
            }
        }
        false
    }

    /// Check if there's precision validation in the function
    fn has_precision_checking(&self, node: &Node, source: &str) -> bool {
        // Find the containing function body
        let function_body = self.get_containing_function_body(node);
        let body = match function_body {
            Some(b) => b,
            None => return false,
        };

        // Sanitized so a comment/string literal in the function can't spoof
        // a precision-check pattern and silently suppress a genuine
        // precision-loss violation.
        let body_text = ast_utils::get_sanitized_node_text(&body, source);

        // Look for precision checking patterns
        if body_text.contains("PRECISION") {
            return true;
        }

        if body_text.contains("DBL_MANT_DIG") || body_text.contains("FLT_MANT_DIG") {
            return true;
        }

        // An `assert(x <= LONG_MAX ...)` counts only when the policy credits
        // an NDEBUG-strippable assert (`assert_is_guard`); the strict policy
        // reads the release configuration, where it checks nothing
        // (ADR-0010 D5).
        if self.settings.borrow().flag("assert_is_guard")
            && body_text.contains("assert")
            && body_text.contains("LONG_MAX")
        {
            return true;
        }

        // An assert over constants alone checks the platform, whatever the
        // build: CERT's own compliant solution is one
        // (`flp36_constant_assert_is_guard`).
        if self
            .settings
            .borrow()
            .flag("flp36_constant_assert_is_guard")
            && has_constant_assert(&body, source)
        {
            return true;
        }

        // Using double instead of float is compliant
        if body_text.contains("double") && !body_text.contains("float") {
            return true;
        }

        false
    }

    /// Get the containing function body
    fn get_containing_function_body<'a>(&self, node: &Node<'a>) -> Option<Node<'a>> {
        let mut current = node.parent();

        while let Some(n) = current {
            if n.kind() == "compound_statement" {
                if let Some(parent) = n.parent() {
                    if parent.kind() == "function_definition" {
                        return Some(n);
                    }
                }
            }
            current = n.parent();
        }

        None
    }
}

/// Whether `body` holds an `assert` whose condition only compares
/// compile-time constants, in [`const_eval::is_compile_time_constant_expr`]'s
/// sense: the same value in every build for one target.
fn has_constant_assert(body: &Node, source: &str) -> bool {
    let mut stack = vec![*body];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression"
            && node.child_by_field_name("function").is_some_and(|f| {
                f.kind() == "identifier" && ast_utils::get_node_text(&f, source) == "assert"
            })
            && node
                .child_by_field_name("arguments")
                .and_then(|args| args.named_child(0))
                .is_some_and(|cond| is_constant_condition(&cond, source))
        {
            return true;
        }
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }
    false
}

/// A comparison or logical combination whose operands are all compile-time
/// constants, or a constant itself.
fn is_constant_condition(node: &Node, source: &str) -> bool {
    match node.kind() {
        "parenthesized_expression" => node
            .named_child(0)
            .is_some_and(|inner| is_constant_condition(&inner, source)),
        "unary_expression"
            if ast_utils::get_node_text(node, source)
                .trim_start()
                .starts_with('!') =>
        {
            node.child_by_field_name("argument")
                .is_some_and(|arg| is_constant_condition(&arg, source))
        }
        "binary_expression"
            if matches!(
                ast_utils::get_binary_operator(node, source).unwrap_or_default(),
                "<" | "<=" | ">" | ">=" | "==" | "!=" | "&&" | "||"
            ) =>
        {
            match (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                (Some(l), Some(r)) => {
                    is_constant_condition(&l, source) && is_constant_condition(&r, source)
                }
                _ => false,
            }
        }
        _ => const_eval::is_compile_time_constant_expr(
            node,
            source,
            &const_eval::MacroConstantMap::new(),
            const_eval::ConstantNameSets::none(),
        ),
    }
}
